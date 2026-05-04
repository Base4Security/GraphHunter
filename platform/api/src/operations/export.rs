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
                    let rel = format!("{}", compact.rel_type());
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

            let mut events: Vec<serde_json::Value> = Vec::new();
            for relation in &relations {
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
                let prov = provenance_for_relation(relation, &dataset_filter, &vrl_by_dataset);
                let event = triple_to_ocsf(source, relation, dest, &prov);
                let value = serde_json::to_value(&event)
                    .map_err(|e| ApiError::Internal(format!("ocsf serialize: {e}")))?;
                events.push(value);
            }

            let rendered = match req.format.as_str() {
                "ndjson" => {
                    let mut out = String::new();
                    for v in &events {
                        out.push_str(
                            &serde_json::to_string(v)
                                .map_err(|e| ApiError::Internal(format!("ndjson: {e}")))?,
                        );
                        out.push('\n');
                    }
                    out
                }
                _ => serde_json::to_string(&events)
                    .map_err(|e| ApiError::Internal(format!("json array: {e}")))?,
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
pub fn format_ioc_feed(format: &str, items: &[IocItem]) -> String {
    match format {
        "stix21" => build_stix21(items),
        "misp_csv" => build_misp_csv(items),
        "kql_ioc_set" => build_kql_ioc_set(items),
        "sigma_stub" => build_sigma_stub(items),
        "sentinel_watchlist" => build_sentinel_watchlist_csv(items),
        _ => String::new(),
    }
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
        let indicator = serde_json::json!({
            "type": "indicator",
            "spec_version": "2.1",
            "id": format!("indicator--{}", uuid_from_node(node_id, tag)),
            "created": created,
            "modified": created,
            "name": format!("{entity_type}: {node_id}"),
            "description": reason.clone().unwrap_or_default(),
            "labels": [tag],
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
    for (node_id, entity_type, _, _) in items {
        let escaped = node_id.replace('"', "\\\"");
        match entity_type.as_str() {
            "IP" => ips.push(escaped),
            "Domain" => domains.push(escaped),
            "File" => files.push(escaped),
            _ => {}
        }
    }
    let mut out = String::new();
    out.push_str("// Generated by Graph Hunter — paste into an Azure Sentinel hunting query.\n");
    if !ips.is_empty() {
        out.push_str("let IoC_IPs = datatable(ip:string)[\n");
        out.push_str(
            &ips.iter()
                .map(|ip| format!("  \"{ip}\""))
                .collect::<Vec<_>>()
                .join(",\n"),
        );
        out.push_str("\n];\n");
    }
    if !domains.is_empty() {
        out.push_str("let IoC_Domains = datatable(domain:string)[\n");
        out.push_str(
            &domains
                .iter()
                .map(|d| format!("  \"{d}\""))
                .collect::<Vec<_>>()
                .join(",\n"),
        );
        out.push_str("\n];\n");
    }
    if !files.is_empty() {
        out.push_str("let IoC_Files = datatable(filename:string)[\n");
        out.push_str(
            &files
                .iter()
                .map(|f| format!("  \"{f}\""))
                .collect::<Vec<_>>()
                .join(",\n"),
        );
        out.push_str("\n];\n");
    }
    if out.lines().count() <= 1 {
        out.push_str("// (no IoCs of IP/Domain/File type in the current tag set)\n");
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

    let mut out = String::new();
    out.push_str("title: Graph Hunter IoC stub\n");
    out.push_str("id: 00000000-0000-0000-0000-000000000000\n");
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
    fn format_ioc_feed_unknown_is_empty() {
        assert_eq!(format_ioc_feed("not-a-format", &sample_items()), "");
    }
}
