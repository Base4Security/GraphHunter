//! Export commands: subgraph → CSV/JSON, hunt results → CSV/JSON, and
//! IoC feed → STIX 2.1 / MISP CSV / KQL / Sigma / Sentinel Watchlist.
//!
//! Format-specific builders (`build_stix21`, `build_misp_csv`, …) are
//! pure functions kept private. `format_ioc_feed` is the public
//! dispatch helper the HTTP layer and any future transport reuse.

use std::collections::{HashMap, HashSet};

use graph_hunter_canonical::{ProvenanceCtx, triple_to_ocsf};
use graph_hunter_core::export::{
    ExportSubgraphEdge, ExportSubgraphNode, export_hunt_results_csv, export_hunt_results_json,
    export_subgraph_csv, export_subgraph_json,
};

use crate::dto::export::{
    ExportHuntResultsRequest, ExportIocsRequest, ExportOcsfRequest, ExportSubgraphRequest,
};
use crate::{ApiError, ApiResult, GraphHunterApi};

impl GraphHunterApi {
    /// Build a subgraph from the given node IDs and export as CSV or JSON.
    pub fn export_subgraph(&self, req: ExportSubgraphRequest) -> ApiResult<String> {
        let nodes = req.nodes;
        let format = req.format;
        self.with_graph_read(req.session.as_ref(), |graph| {
            let id_set: HashSet<&str> = nodes.iter().map(|s| s.as_str()).collect();

            struct OwnedNode {
                id: String,
                entity_type: String,
                score: f64,
            }
            struct OwnedEdge {
                source: String,
                target: String,
                rel_type: String,
                timestamp: i64,
            }

            let owned_nodes: Vec<OwnedNode> = nodes
                .iter()
                .filter_map(|id| graph.get_entity(id))
                .map(|e| OwnedNode {
                    id: e.id.clone(),
                    entity_type: format!("{}", e.entity_type),
                    score: e.score,
                })
                .collect();

            const MAX_EDGES: usize = 10_000;
            let mut owned_edges: Vec<OwnedEdge> = Vec::new();
            // Dedup by (source, target, rel_type, timestamp): guards against
            // duplicate IDs in input AND re-played events in the graph.
            let mut seen: HashSet<(String, String, String, i64)> = HashSet::new();
            let mut visited_sources: HashSet<&str> = HashSet::new();
            'outer: for source_id in &nodes {
                if !visited_sources.insert(source_id.as_str()) {
                    continue;
                }
                for compact in graph.get_compact_relations(source_id) {
                    if owned_edges.len() >= MAX_EDGES {
                        break 'outer;
                    }
                    let dest_str = graph.interner.resolve(compact.dest_sid);
                    if !id_set.contains(dest_str) {
                        continue;
                    }
                    let src = graph.interner.resolve(compact.source_sid).to_string();
                    let dst = dest_str.to_string();
                    let rel = graph.resolve_rel_type_name(&compact);
                    let key = (src.clone(), dst.clone(), rel.clone(), compact.timestamp);
                    if !seen.insert(key) {
                        continue;
                    }
                    owned_edges.push(OwnedEdge {
                        source: src,
                        target: dst,
                        rel_type: rel,
                        timestamp: compact.timestamp,
                    });
                }
            }

            let export_nodes: Vec<ExportSubgraphNode<'_>> = owned_nodes
                .iter()
                .map(|n| ExportSubgraphNode {
                    id: &n.id,
                    entity_type: &n.entity_type,
                    score: n.score,
                })
                .collect();
            let export_edges: Vec<ExportSubgraphEdge<'_>> = owned_edges
                .iter()
                .map(|e| ExportSubgraphEdge {
                    source: &e.source,
                    target: &e.target,
                    rel_type: &e.rel_type,
                    timestamp: e.timestamp,
                })
                .collect();

            let mut buf = Vec::new();
            match format.as_str() {
                "csv" => export_subgraph_csv(&export_nodes, &export_edges, &mut buf)
                    .map_err(|e| ApiError::Io(e.to_string()))?,
                "json" => export_subgraph_json(&export_nodes, &export_edges, &mut buf)
                    .map_err(|e| ApiError::Io(e.to_string()))?,
                other => {
                    return Err(ApiError::InvalidInput(format!(
                        "unsupported format: {other}. Use 'csv' or 'json'."
                    )));
                }
            }
            String::from_utf8(buf).map_err(|e| ApiError::Internal(format!("utf-8: {e}")))
        })
    }

    /// Export the cached hunt results as CSV or JSON. `aggregate=true`
    /// collapses identical paths (DedupMode::ByPath).
    pub fn export_hunt_results(&self, req: ExportHuntResultsRequest) -> ApiResult<String> {
        // Snapshot the cache before acquiring the graph lock — keep
        // critical sections small.
        let cache = {
            let guard = self
                .inner
                .hunt_cache
                .read()
                .map_err(|e| ApiError::Internal(format!("hunt cache poisoned: {e}")))?;
            if guard.is_empty() {
                return Err(ApiError::InvalidState(
                    "no hunt results to export. Run a hunt first.".into(),
                ));
            }
            guard.clone()
        };

        let dedup_mode = if req.aggregate.unwrap_or(false) {
            graph_hunter_core::DedupMode::ByPath
        } else {
            graph_hunter_core::DedupMode::None
        };
        let page = req.page.unwrap_or(0);
        let page_size = req.page_size.unwrap_or(cache.len());
        let format = req.format;

        let scored = self.with_graph_read(req.session.as_ref(), |graph| {
            let (page_scored, _) =
                graph.score_and_paginate_paths(&cache, page, page_size, None, dedup_mode);
            Ok(page_scored)
        })?;

        let mut buf = Vec::new();
        match format.as_str() {
            "csv" => export_hunt_results_csv(&scored, &mut buf)
                .map_err(|e| ApiError::Io(e.to_string()))?,
            "json" => export_hunt_results_json(&scored, &mut buf)
                .map_err(|e| ApiError::Io(e.to_string()))?,
            other => {
                return Err(ApiError::InvalidInput(format!(
                    "unsupported format: {other}. Use 'csv' or 'json'."
                )));
            }
        }
        String::from_utf8(buf).map_err(|e| ApiError::Internal(format!("utf-8: {e}")))
    }

    /// Export every triple in the session — or one dataset — as OCSF v1.4
    /// events, each carrying the Graph Hunter Provenance Extension. The
    /// projection is deterministic and total: shapes outside the shipping
    /// subset land in `OcsfEvent::Other` with a diagnostic reason.
    ///
    /// `format = "json"` emits a single JSON array; `"ndjson"` emits one
    /// event per line for streaming sinks. Provenance bytes (raw event
    /// SHA-256) are empty at export time — the raw bytes are not retained
    /// after ingest; M5 will plug in a proper cold-store lookup.
    pub fn export_ocsf(&self, req: ExportOcsfRequest) -> ApiResult<String> {
        match req.format.as_str() {
            "json" | "ndjson" => {}
            other => {
                return Err(ApiError::InvalidInput(format!(
                    "unsupported format: {other}. Use 'json' or 'ndjson'."
                )));
            }
        }

        let dataset_filter = req.dataset_id.clone();
        // 2026-05-06: bound the response size. The JS string limit
        // (~536 MB) was the actual ceiling for an MCP caller, and
        // a real Sentinel session of 1M+ events blew through it.
        // Default cap of 10k keeps the rendered string < 50 MB
        // safely; analysts who need more page through with `offset`.
        const DEFAULT_PAGE_SIZE: usize = 10_000;
        const MAX_PAGE_SIZE: usize = 200_000;
        let page_size = req
            .page_size
            .unwrap_or(DEFAULT_PAGE_SIZE)
            .min(MAX_PAGE_SIZE);
        let offset = req.offset.unwrap_or(0);

        // Build a per-dataset mapping_hash table from FieldConfig before
        // touching the graph. Datasets without a FieldConfig stay on the
        // builtin-parser path; datasets with one get a real
        // `vrl-v{N}:{sha256(vrl_source)}` stamp.
        let session = self.resolve_session(req.session.as_ref())?;
        let vrl_by_dataset: HashMap<String, graph_hunter_vrl::VrlProgram> = {
            let infos = session
                .datasets
                .read()
                .map_err(|e| ApiError::Internal(format!("session datasets lock poisoned: {e}")))?;
            infos
                .iter()
                .filter_map(|d| {
                    d.field_config
                        .as_ref()
                        .map(|cfg| (d.id.clone(), graph_hunter_vrl::field_config_to_vrl(cfg)))
                })
                .collect()
        };

        self.with_graph_read(req.session.as_ref(), |graph| {
            let (entities, relations) = graph.to_snapshot();
            let entity_by_id: HashMap<String, &graph_hunter_core::entity::Entity> =
                entities.iter().map(|e| (e.id.clone(), e)).collect();

            // First pass: count the total match set so the meta
            // envelope is honest about `has_more`. Skipping the
            // dataset filter twice would double-iterate; we live
            // with one extra pass here because it's a vector of
            // refs and the inner work (provenance + serialize) only
            // runs on the page slice below.
            let mut total: usize = 0;
            for relation in &relations {
                if let Some(ds) = &dataset_filter {
                    match relation.dataset_id.as_deref() {
                        Some(rds) if rds == ds => {}
                        _ => continue,
                    }
                }
                if entity_by_id.contains_key(&relation.source_id)
                    && entity_by_id.contains_key(&relation.dest_id)
                {
                    total += 1;
                }
            }

            let mut events: Vec<serde_json::Value> = Vec::new();
            let mut produced: usize = 0;
            let mut skipped: usize = 0;
            for relation in &relations {
                if events.len() >= page_size {
                    break;
                }
                if let Some(ds) = &dataset_filter {
                    match relation.dataset_id.as_deref() {
                        Some(rds) if rds == ds => {}
                        _ => continue,
                    }
                }
                let (Some(source), Some(dest)) = (
                    entity_by_id.get(&relation.source_id),
                    entity_by_id.get(&relation.dest_id),
                ) else {
                    continue;
                };
                if skipped < offset {
                    skipped += 1;
                    continue;
                }
                let prov = provenance_for_relation(relation, &dataset_filter, &vrl_by_dataset);
                let event = triple_to_ocsf(source, relation, dest, &prov);
                let value = serde_json::to_value(&event)
                    .map_err(|e| ApiError::Internal(format!("ocsf serialize: {e}")))?;
                events.push(value);
                produced += 1;
            }
            let has_more = offset + produced < total;

            let rendered = match req.format.as_str() {
                "ndjson" => {
                    // Lead with a `_meta` JSON line so a streaming
                    // consumer (jq, splunk forwarder, etc.) can
                    // skip-comment it cheaply but still know to
                    // page when `has_more = true`.
                    let meta = serde_json::json!({
                        "_meta": {
                            "offset": offset,
                            "page_size": page_size,
                            "returned": produced,
                            "total_in_session": total,
                            "has_more": has_more,
                        }
                    });
                    let mut out = String::new();
                    out.push_str(
                        &serde_json::to_string(&meta)
                            .map_err(|e| ApiError::Internal(format!("ndjson meta: {e}")))?,
                    );
                    out.push('\n');
                    for v in &events {
                        out.push_str(
                            &serde_json::to_string(v)
                                .map_err(|e| ApiError::Internal(format!("ndjson: {e}")))?,
                        );
                        out.push('\n');
                    }
                    out
                }
                _ => {
                    let envelope = serde_json::json!({
                        "events": events,
                        "_meta": {
                            "offset": offset,
                            "page_size": page_size,
                            "returned": produced,
                            "total_in_session": total,
                            "has_more": has_more,
                        }
                    });
                    serde_json::to_string(&envelope)
                        .map_err(|e| ApiError::Internal(format!("json array: {e}")))?
                }
            };
            Ok(rendered)
        })
    }

    /// Export the session's tagged entities as a consumable IoC feed.
    ///
    /// Supported formats: `stix21`, `misp_csv`, `kql_ioc_set`,
    /// `sigma_stub`, `sentinel_watchlist`. `tag_prefix` defaults to
    /// `"ioc:"`; pass `""` to include every tag.
    pub fn export_iocs(&self, req: ExportIocsRequest) -> ApiResult<String> {
        let prefix = req.tag_prefix.unwrap_or_else(|| "ioc:".to_string());

        let session = self.resolve_session(req.session.as_ref())?;
        let items: Vec<IocItem> = {
            let tags = session
                .tags
                .read()
                .map_err(|e| ApiError::Internal(format!("tags lock poisoned: {e}")))?;
            let graph = session
                .graph
                .read()
                .map_err(|e| ApiError::Internal(format!("graph lock poisoned: {e}")))?;
            let mut out = Vec::new();
            for t in tags.iter() {
                if !prefix.is_empty() && !t.tag.starts_with(&prefix) {
                    continue;
                }
                let etype = graph
                    .get_entity(&t.node_id)
                    .map(|e| format!("{}", e.entity_type))
                    .unwrap_or_else(|| "Unknown".to_string());
                out.push((t.node_id.clone(), etype, t.tag.clone(), t.reason.clone()));
            }
            out
        };

        let rendered = format_ioc_feed(&req.format, &items);
        if rendered.is_empty() {
            return Err(ApiError::InvalidInput(format!(
                "unsupported IoC format: {}. Use 'stix21', 'misp_csv', 'kql_ioc_set', 'sigma_stub', or 'sentinel_watchlist'.",
                req.format
            )));
        }
        Ok(rendered)
    }
}

/// Builds a Provenance Extension context for a relation at export time.
/// The raw event bytes are not retained after ingest, so `raw_event_sha256`
/// is empty until M5 wires in cold-store lookup. `parser_name` is best-
/// effort: we read it from relation metadata if the ingestion path
/// stamped it, otherwise fall back to `"unknown"`.
fn provenance_for_relation(
    relation: &graph_hunter_core::relation::Relation,
    dataset_override: &Option<String>,
    vrl_by_dataset: &HashMap<String, graph_hunter_vrl::VrlProgram>,
) -> ProvenanceCtx {
    let dataset_id = dataset_override
        .clone()
        .or_else(|| relation.dataset_id.as_deref().map(|s| s.to_string()))
        .unwrap_or_else(|| "unknown".to_string());

    // If the dataset that produced this relation has a FieldConfig, the
    // VRL compiler has already given us a stable mapping_hash — stamp
    // it. Otherwise fall back to the legacy builtin-parser identity so
    // hand-written parsers still emit a non-empty hash.
    if let Some(program) = vrl_by_dataset.get(&dataset_id) {
        return ProvenanceCtx::for_vrl(
            program.provenance_id(),
            program.mapping_version,
            program.source.as_bytes(),
            dataset_id,
            &[],
            1.0,
        );
    }

    let parser_name = relation
        .metadata
        .get("parser_name")
        .cloned()
        .unwrap_or_else(|| "unknown".to_string());
    ProvenanceCtx::for_builtin_parser(parser_name, dataset_id, &[])
}

/// Type alias that matches the legacy shape `(node_id, entity_type, tag,
/// reason)` accepted by the IoC format helpers. Kept as a tuple (not a
/// struct) to preserve the existing `format_ioc_feed` contract used by
/// the HTTP transport.
type IocItem = (String, String, String, Option<String>);

/// Public dispatcher used by the HTTP layer's bulk-export helpers.
///
/// 2026-05-06: dedupe `items` by `(node_id, entity_type)` before
/// dispatching. Previously a node carrying multiple tags produced one
/// `IocItem` per tag — every format then emitted duplicate
/// indicators (the same IP appearing twice in `kql_ioc_set`, the
/// same STIX `indicator--…` UUID-collision pair, etc.). Merge the
/// tags into a comma-separated label and concatenate the non-empty
/// reasons so no signal is lost.
pub fn format_ioc_feed(format: &str, items: &[IocItem]) -> String {
    let deduped = dedupe_items(items);
    match format {
        "stix21" => build_stix21(&deduped),
        "misp_csv" => build_misp_csv(&deduped),
        "kql_ioc_set" => build_kql_ioc_set(&deduped),
        "sigma_stub" => build_sigma_stub(&deduped),
        "sentinel_watchlist" => build_sentinel_watchlist_csv(&deduped),
        _ => String::new(),
    }
}

/// Collapse multiple tags on the same `(node_id, entity_type)` into a
/// single `IocItem`. Tags joined with `,` (Sigma + STIX-friendly),
/// reasons concatenated with ` | ` so analyst notes from each tag are
/// preserved. Order is stable: first-seen wins, subsequent occurrences
/// merge in arrival order.
fn dedupe_items(items: &[IocItem]) -> Vec<IocItem> {
    use std::collections::HashMap;
    let mut order: Vec<(String, String)> = Vec::with_capacity(items.len());
    let mut acc: HashMap<(String, String), (Vec<String>, Vec<String>)> = HashMap::new();
    for (node_id, etype, tag, reason) in items {
        let key = (node_id.clone(), etype.clone());
        let entry = acc.entry(key.clone()).or_insert_with(|| {
            order.push(key.clone());
            (Vec::new(), Vec::new())
        });
        if !entry.0.iter().any(|t| t == tag) {
            entry.0.push(tag.clone());
        }
        if let Some(r) = reason.as_ref().filter(|s| !s.trim().is_empty()) {
            if !entry.1.iter().any(|x| x == r) {
                entry.1.push(r.clone());
            }
        }
    }
    order
        .into_iter()
        .map(|key| {
            let (node_id, etype) = key.clone();
            let (tags, reasons) = acc.remove(&key).unwrap_or_default();
            let merged_tag = tags.join(",");
            let merged_reason = if reasons.is_empty() {
                None
            } else {
                Some(reasons.join(" | "))
            };
            (node_id, etype, merged_tag, merged_reason)
        })
        .collect()
}

/// CSV body ready for the Azure Sentinel Watchlist REST API. First
/// column holds the indexable value (`itemsSearchKey`).
pub fn build_sentinel_watchlist_csv(items: &[IocItem]) -> String {
    let mut out = String::from("ioc_value,ioc_type,tag,reason\n");
    for (node_id, entity_type, tag, reason) in items {
        let value = node_id.replace('"', "\"\"");
        let ioc_type = match entity_type.as_str() {
            "IP" => "ipv4",
            "Domain" => "domain",
            "URL" => "url",
            "File" => "filename",
            "User" => "account",
            _ => "other",
        };
        let reason_escaped = reason.clone().unwrap_or_default().replace('"', "\"\"");
        out.push_str(&format!(
            "\"{}\",{},{},\"{}\"\n",
            value, ioc_type, tag, reason_escaped
        ));
    }
    out
}

fn build_stix21(items: &[IocItem]) -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let created = iso_now().unwrap_or_else(|_| "1970-01-01T00:00:00Z".to_string());
    let bundle_id = format!(
        "bundle--gh-{:x}",
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0)
    );
    let mut objects: Vec<serde_json::Value> = Vec::with_capacity(items.len());
    for (node_id, entity_type, tag, reason) in items {
        let pattern = stix_pattern_for(entity_type, node_id);
        // 2026-05-06 (N2 fix): `tag` is a comma-joined string after
        // `dedupe_items` collapses multiple tags on the same node.
        // STIX 2.1 § 4.1 defines `labels` as `list of string`, so a
        // single CSV entry like `["ioc:suspicious,ioc:malicious"]`
        // breaks schema validators. Split back into separate labels.
        let labels: Vec<&str> = tag
            .split(',')
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .collect();
        let indicator = serde_json::json!({
            "type": "indicator",
            "spec_version": "2.1",
            "id": format!("indicator--{}", uuid_from_node(node_id, tag)),
            "created": created,
            "modified": created,
            "name": format!("{entity_type}: {node_id}"),
            "description": reason.clone().unwrap_or_default(),
            "labels": labels,
            "pattern": pattern,
            "pattern_type": "stix",
            "valid_from": created,
        });
        objects.push(indicator);
    }
    let bundle = serde_json::json!({
        "type": "bundle",
        "id": bundle_id,
        "objects": objects,
    });
    serde_json::to_string_pretty(&bundle).unwrap_or_else(|_| "{}".to_string())
}

fn stix_pattern_for(entity_type: &str, node_id: &str) -> String {
    let quoted = node_id.replace('\\', "\\\\").replace('\'', "\\'");
    match entity_type {
        "IP" => format!("[ipv4-addr:value = '{quoted}']"),
        "Domain" => format!("[domain-name:value = '{quoted}']"),
        "URL" => format!("[url:value = '{quoted}']"),
        "File" => format!("[file:name = '{quoted}']"),
        "Host" => format!("[x-gh:host = '{quoted}']"),
        "User" => format!("[user-account:user_id = '{quoted}']"),
        _ => format!("[x-gh:{} = '{quoted}']", entity_type.to_ascii_lowercase()),
    }
}

fn uuid_from_node(node_id: &str, tag: &str) -> String {
    // FNV-1a 64-bit: deterministic so repeated exports of the same tag
    // produce stable STIX IDs (useful for diffing IoC feeds).
    let mut hash: u64 = 0xcbf2_9ce4_8422_2325;
    for b in node_id
        .bytes()
        .chain(b"|".iter().copied())
        .chain(tag.bytes())
    {
        hash ^= b as u64;
        hash = hash.wrapping_mul(0x100_0000_01b3);
    }
    format!(
        "{:08x}-{:04x}-{:04x}-{:04x}-{:012x}",
        (hash >> 32) as u32,
        (hash >> 16) as u16 & 0xffff,
        (hash as u16) & 0xffff,
        (hash >> 48) as u16 & 0xffff,
        hash & 0xffff_ffff_ffff,
    )
}

fn build_misp_csv(items: &[IocItem]) -> String {
    let mut out = String::from("value,type,category,comment\n");
    for (node_id, entity_type, _tag, reason) in items {
        let (typ, cat) = match entity_type.as_str() {
            "IP" => ("ip-dst", "Network activity"),
            "Domain" => ("domain", "Network activity"),
            "URL" => ("url", "Network activity"),
            "File" => ("filename", "Artifacts dropped"),
            "User" => ("target-user", "Targeting data"),
            _ => ("other", "External analysis"),
        };
        let comment = reason.clone().unwrap_or_default().replace('"', "\"\"");
        out.push_str(&format!(
            "\"{}\",{},{},\"{}\"\n",
            node_id.replace('"', "\"\""),
            typ,
            cat,
            comment,
        ));
    }
    out
}

fn build_kql_ioc_set(items: &[IocItem]) -> String {
    let mut ips = Vec::new();
    let mut domains = Vec::new();
    let mut files = Vec::new();
    let mut processes = Vec::new();
    let mut hashes = Vec::new();
    for (node_id, entity_type, _, _) in items {
        let escaped = node_id.replace('"', "\\\"");
        match entity_type.as_str() {
            "IP" => ips.push(escaped),
            "Domain" => domains.push(escaped),
            "File" => files.push(escaped),
            // Process IoCs (e.g. cnd.exe) used to drop on the floor
            // here — Sentinel `DeviceProcessEvents.FileName` is the
            // standard match field, so emit them under a dedicated
            // `IoC_Processes` datatable for paste-into-hunt.
            "Process" => processes.push(escaped),
            "Hash" => hashes.push(escaped),
            _ => {}
        }
    }
    let mut out = String::new();
    out.push_str("// Generated by Graph Hunter — paste into an Azure Sentinel hunting query.\n");
    let push_table = |out: &mut String, name: &str, col: &str, vals: &[String]| {
        if vals.is_empty() {
            return;
        }
        out.push_str(&format!("let {name} = datatable({col}:string)[\n"));
        out.push_str(
            &vals
                .iter()
                .map(|v| format!("  \"{v}\""))
                .collect::<Vec<_>>()
                .join(",\n"),
        );
        out.push_str("\n];\n");
    };
    push_table(&mut out, "IoC_IPs", "ip", &ips);
    push_table(&mut out, "IoC_Domains", "domain", &domains);
    push_table(&mut out, "IoC_Files", "filename", &files);
    push_table(&mut out, "IoC_Processes", "process_name", &processes);
    push_table(&mut out, "IoC_Hashes", "hash", &hashes);
    if out.lines().count() <= 1 {
        out.push_str(
            "// (no IoCs of IP/Domain/File/Process/Hash type in the current tag set)\n",
        );
    }
    out
}

fn build_sigma_stub(items: &[IocItem]) -> String {
    let ips: Vec<&str> = items
        .iter()
        .filter(|(_, t, _, _)| t == "IP")
        .map(|(id, _, _, _)| id.as_str())
        .collect();
    let domains: Vec<&str> = items
        .iter()
        .filter(|(_, t, _, _)| t == "Domain")
        .map(|(id, _, _, _)| id.as_str())
        .collect();

    // Deterministic UUID derived from the IoC set — replaces the
    // 2026-04 hardcoded 00000000-… literal that caused collisions
    // when multiple Sigma stubs were imported into the same SIEM.
    // Stable across re-exports of the same IoCs (good for diffing
    // rule versions) but distinct between disjoint sets.
    let rule_id = sigma_rule_uuid(&ips, &domains);

    let mut out = String::new();
    out.push_str("title: Graph Hunter IoC stub\n");
    out.push_str(&format!("id: {rule_id}\n"));
    out.push_str("status: experimental\n");
    out.push_str(
        "description: Auto-generated from Graph Hunter IoC tag set. Replace logsource + attach timeframe before production use.\n",
    );
    out.push_str("logsource:\n  category: network_connection\n");
    out.push_str("detection:\n");
    if !ips.is_empty() {
        out.push_str("  dst_ip:\n    DestinationIp:\n");
        for ip in &ips {
            out.push_str(&format!("      - '{ip}'\n"));
        }
    }
    if !domains.is_empty() {
        out.push_str("  dst_domain:\n    DestinationHostname:\n");
        for d in &domains {
            out.push_str(&format!("      - '{d}'\n"));
        }
    }
    let parts: Vec<&str> = ["dst_ip", "dst_domain"]
        .iter()
        .copied()
        .filter(|k| match *k {
            "dst_ip" => !ips.is_empty(),
            "dst_domain" => !domains.is_empty(),
            _ => false,
        })
        .collect();
    out.push_str(&format!(
        "  condition: {}\n",
        if parts.is_empty() {
            "selection".to_string()
        } else {
            parts.join(" or ")
        }
    ));
    out.push_str("level: medium\n");
    out
}

/// Deterministic UUIDv5-style identifier derived from the sorted IP +
/// domain set. Gives the same rule_id for repeated exports of an
/// equivalent IoC set, but a different one when the set changes.
/// Hash function reuses the FNV-1a 64-bit recipe from
/// `uuid_from_node` — not a real RFC-4122 UUID but a 36-char id that
/// looks right in a Sigma `id:` field and is stable per-set.
fn sigma_rule_uuid(ips: &[&str], domains: &[&str]) -> String {
    let mut sorted_ips: Vec<&str> = ips.to_vec();
    sorted_ips.sort_unstable();
    let mut sorted_domains: Vec<&str> = domains.to_vec();
    sorted_domains.sort_unstable();

    let mut hash: u64 = 0xcbf2_9ce4_8422_2325;
    for ip in &sorted_ips {
        for b in ip.bytes() {
            hash ^= b as u64;
            hash = hash.wrapping_mul(0x100_0000_01b3);
        }
        hash ^= b'\n' as u64;
        hash = hash.wrapping_mul(0x100_0000_01b3);
    }
    hash ^= b'|' as u64;
    hash = hash.wrapping_mul(0x100_0000_01b3);
    for d in &sorted_domains {
        for b in d.bytes() {
            hash ^= b as u64;
            hash = hash.wrapping_mul(0x100_0000_01b3);
        }
        hash ^= b'\n' as u64;
        hash = hash.wrapping_mul(0x100_0000_01b3);
    }
    // Fan out to a second 64-bit half so we have 128 bits of state to
    // populate the UUID layout — without dragging a real hash crate
    // in.
    let mut second: u64 = 0x84222325cbf29ce4;
    for ip in &sorted_ips {
        for b in ip.bytes() {
            second = second.rotate_left(5) ^ (b as u64);
        }
    }
    for d in &sorted_domains {
        for b in d.bytes() {
            second = second.rotate_left(5) ^ (b as u64);
        }
    }
    if sorted_ips.is_empty() && sorted_domains.is_empty() {
        // Fallback: empty IoC set still gets a recognizable, distinct
        // id so two empty stubs imported simultaneously don't collide.
        // 2026-05-06: empty IoC set used to emit a string that
        // looked like a UUID but contained letters in hex slots
        // (`empty…`), which broke `sigmac` and any consumer
        // validating the field as a real UUID. Use the canonical nil
        // UUID instead — sigmac accepts it, and downstream tooling
        // can treat it as "no IoCs supplied".
        return "00000000-0000-0000-0000-000000000000".to_string();
    }
    format!(
        "{:08x}-{:04x}-{:04x}-{:04x}-{:012x}",
        (hash >> 32) as u32,
        (hash >> 16) as u16 & 0xffff,
        (hash as u16) & 0xffff,
        (second >> 48) as u16 & 0xffff,
        second & 0xffff_ffff_ffff,
    )
}

/// Best-effort ISO-8601 timestamp without pulling `chrono` in. Moved
/// from the Tauri command crate; the civil-from-days math is Howard
/// Hinnant's, unchanged.
fn iso_now() -> Result<String, ()> {
    use std::time::{SystemTime, UNIX_EPOCH};
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| ())?
        .as_secs();
    let days = (secs / 86_400) as i64;
    let (y, m, d) = civil_from_days(days);
    let secs_of_day = (secs % 86_400) as u32;
    let h = secs_of_day / 3600;
    let mi = (secs_of_day % 3600) / 60;
    let s = secs_of_day % 60;
    Ok(format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z",
        y, m, d, h, mi, s
    ))
}

fn civil_from_days(z: i64) -> (i32, u32, u32) {
    let z = z + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = (z - era * 146_097) as u64;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    let year = y + if m <= 2 { 1 } else { 0 };
    (year as i32, m, d)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_items() -> Vec<IocItem> {
        vec![
            (
                "1.2.3.4".into(),
                "IP".into(),
                "ioc:malicious".into(),
                Some("password spraying".into()),
            ),
            (
                "evil.com".into(),
                "Domain".into(),
                "ioc:malicious".into(),
                None,
            ),
            (
                "attacker".into(),
                "User".into(),
                "ioc:malicious".into(),
                Some("has \"quotes\" in reason".into()),
            ),
        ]
    }

    #[test]
    fn sentinel_watchlist_csv_shape_and_mapping() {
        let out = build_sentinel_watchlist_csv(&sample_items());
        assert!(out.starts_with("ioc_value,ioc_type,tag,reason\n"));
        assert!(out.contains("\"1.2.3.4\",ipv4,ioc:malicious,"));
        assert!(out.contains("\"evil.com\",domain,ioc:malicious,"));
        assert!(out.contains("\"attacker\",account,ioc:malicious,"));
    }

    #[test]
    fn sentinel_watchlist_csv_escapes_quotes() {
        let out = build_sentinel_watchlist_csv(&sample_items());
        assert!(out.contains("\"has \"\"quotes\"\" in reason\""));
    }

    #[test]
    fn stix21_has_bundle_and_indicators() {
        let out = build_stix21(&sample_items());
        assert!(out.contains("\"type\": \"bundle\""));
        assert!(out.contains("\"type\": \"indicator\""));
        assert!(out.contains("ipv4-addr:value"));
    }

    #[test]
    fn stix21_splits_csv_labels() {
        // 2026-05-06 (N2 fix): when dedupe collapses two tags into a
        // single comma-joined `IocItem.tag`, the STIX exporter must
        // emit them as separate strings, not as one CSV element.
        let items = vec![(
            "1.2.3.4".to_string(),
            "IP".to_string(),
            "ioc:suspicious,ioc:malicious".to_string(),
            None,
        )];
        let out = build_stix21(&items);
        let parsed: serde_json::Value = serde_json::from_str(&out).unwrap();
        let labels = parsed["objects"][0]["labels"].as_array().unwrap();
        assert_eq!(labels.len(), 2);
        assert_eq!(labels[0], "ioc:suspicious");
        assert_eq!(labels[1], "ioc:malicious");
    }

    #[test]
    fn format_ioc_feed_unknown_is_empty() {
        assert_eq!(format_ioc_feed("not-a-format", &sample_items()), "");
    }
}
