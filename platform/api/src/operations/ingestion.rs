//! Ingestion commands: preview + load_data + ingest_siem +
//! load_data_with_config + load_data_streaming.
//!
//! `load_data_streaming` was lifted out of the Tauri command layer in
//! F2.16 so the full ingestion pipeline (sync + background) lives in
//! one place. Tauri's `cmd_load_data_streaming` is now a thin
//! delegator that forwards to [`GraphHunterApi::load_data_streaming`];
//! all event emission routes through the canonical [`EventEmitter`].

use std::collections::{HashMap, HashSet};
use std::io::BufReader;
use std::sync::Arc;

use graph_hunter_core::drift::DriftSnapshot;
use graph_hunter_core::{
    ConfigurableParser, EntityType, FieldConfig, FieldMapping, FieldRole, GenericParser,
    GraphHunter, LogParser,
};
use graph_hunter_parsers::extract_fields_header;
use uuid::Uuid;

use crate::dto::ingestion::{
    DetectedField, IngestComplete, IngestError, IngestJobStarted, IngestSiemRequest,
    LoadDataRequest, LoadDataStreamingRequest, LoadDataWithConfigRequest, LoadResult,
    PcapPreviewRequest, PcapPreviewResult, PreviewIngestRequest, PreviewIngestResult,
};
use crate::events::events::{INGEST_COMPLETE, INGEST_ERROR, INGEST_PROGRESS};
use crate::evtx::{
    evtx_preview_sample, evtx_to_sysmon_ndjson, file_looks_like_evtx, path_is_evtx,
};
use crate::format_registry::{make_parser_for_format, resolve_format, rich_preview_for_format};
use crate::scoring::{run_full_scoring, run_scoring_adaptive};
use crate::state::{DatasetInfo, Session, SessionPhase};
use crate::util::now_secs;
use crate::{ApiError, ApiResult, EventEmitter, GraphHunterApi};

/// After a failed streaming ingest, unblock hunts when the graph still has data.
fn restore_huntable_phase_after_ingest_failure(session: &Session) {
    let has_graph = session
        .graph
        .read()
        .map(|g| g.entity_count() > 0)
        .unwrap_or(false);
    session.set_phase(if has_graph {
        SessionPhase::Ready
    } else {
        SessionPhase::Loading
    });
}

fn note_post_finalize_appends(session: &Session, new_relations: usize) {
    session.note_post_finalize_appends(new_relations as u64, now_secs());
}

// ── Constants for load_data_streaming (lifted from Tauri commands) ─────
/// Number of lines per batch during streaming line-based ingestion.
const BATCH_LINES: usize = 50_000;
/// Read-buffer capacity for streaming ingestion (8 MB).
const BUF_CAPACITY: usize = 8 * 1024 * 1024;
/// Size of the peek buffer used for format detection at the start of a file.
const PEEK_BUF_SIZE: usize = 8192;
/// Maximum entities pre-allocated based on file size heuristics.
const MAX_PREALLOC_ENTITIES: usize = 2_000_000;
/// Maximum relations pre-allocated based on file size heuristics.
const MAX_PREALLOC_RELATIONS: usize = 4_000_000;
/// Available physical memory (MB) below which ingestion stops to prevent a crash.
/// Only consulted on Windows via `GlobalMemoryStatusEx`; gated to avoid a
/// dead-code warning on Linux/macOS where the check is skipped.
#[cfg(target_os = "windows")]
const CRITICAL_MEMORY_MB: u64 = 256;

const LARGE_FILE_THRESHOLD: u64 = 10 * 1024 * 1024;
const PREVIEW_READ_SIZE: usize = 64 * 1024;
const EVTX_PREVIEW_SAMPLE_SIZE: usize = 1000;

/// Rewrites a [`FieldConfig`] that was likely saved before canonical-Skip
/// semantics were fixed. When a mapping targets a canonical field whose
/// entity-type is `"Skip"` (timestamp, action, outcome, severity, message,
/// protocol, ports, command_line) and asks for `Ignore` or `Node`, we force
/// the role to `Metadata` and drop the entity_type override.
///
/// Why: a persisted `TIME → Ignore` mapping tanks `temporal_heatmap`,
/// `temporal_novelty`, and `diff_hunts` because GenericParser::normalize
/// can no longer recover the event time. A persisted `SEVERITY → Node`
/// mapping explodes the graph with one Severity entity per row. Both were
/// the default behavior before the Phase A defaults fix; this sanitizer
/// upgrades old configs to the new semantics without asking the user to
/// re-preview manually.
fn sanitize_field_config(config: &mut FieldConfig) -> usize {
    let mut fixed = 0;
    for m in config.mappings.iter_mut() {
        let canonical = match GenericParser::canonical_field(&m.raw_name) {
            Some(c) => c,
            None => continue,
        };
        if GenericParser::canonical_to_entity_type(canonical) != "Skip" {
            continue;
        }
        match m.role {
            FieldRole::Metadata => {}
            FieldRole::Ignore | FieldRole::Node => {
                m.role = FieldRole::Metadata;
                m.entity_type = None;
                fixed += 1;
            }
        }
    }
    fixed
}

/// Build a `FieldConfig` from the same heuristic the Preview UI shows,
/// so a one-shot `load_data` call (no analyst override) gets the value-
/// based + multilingual entity-type suggestions instead of falling back
/// to plain `GenericParser` which only matches canonical English field
/// names.
///
/// Returns `None` for formats that already have a dedicated parser
/// (`iis`, `fortianalyzer`) — those handle field mapping themselves.
pub fn auto_field_config_for(format_name: &str, contents: &str) -> Option<FieldConfig> {
    let supports_configurable = matches!(
        format_name,
        "csv" | "generic" | "sysmon" | "sentinel" | "cognito"
    );
    if !supports_configurable {
        return None;
    }
    let fields = crate::format_registry::rich_preview_for_format(format_name, contents);
    if fields.is_empty() {
        return None;
    }
    let mappings: Vec<FieldMapping> = fields
        .into_iter()
        .map(|fi| {
            // Same precedence as preview_ingest: heuristic > timestamp >
            // canonical default > raw name.
            let is_timestamp = fi.canonical_target.as_deref() == Some("timestamp");
            let canonical_default = fi.canonical_target.as_deref().and_then(|ct| {
                let et = GenericParser::canonical_to_entity_type(ct);
                if et == "Skip" {
                    None
                } else {
                    Some(et.to_string())
                }
            });
            // 2026-05-06 (#11 fix): the previous fallback was
            // `fi.raw_name.clone()`, which silently promoted any
            // unrecognized field to a Node typed by its own field
            // name. That wrongly turned numeric/categorical metadata
            // (`bytes`, `action`, `count`, `priority`) into entities
            // of types like `bytes` or `action`. When neither the
            // value-regex heuristic nor a canonical mapping has an
            // opinion, default to Metadata so the analyst can opt in
            // explicitly instead of opt out after seeing junk nodes.
            let suggested = match (fi.suggested_entity_type.clone(), canonical_default) {
                (Some(t), _) => t,
                (None, _) if is_timestamp => "Skip".to_string(),
                (None, Some(canonical)) => canonical,
                (None, None) => "Skip".to_string(),
            };
            let (role, entity_type) = if suggested == "Skip" {
                (FieldRole::Metadata, None)
            } else {
                (FieldRole::Node, Some(suggested))
            };
            FieldMapping {
                raw_name: fi.raw_name,
                role,
                entity_type,
                timestamp_format: None,
                locale: None,
            }
        })
        .collect();
    Some(FieldConfig { mappings })
}

/// Normalize a User entity id for fuzzy duplicate detection: lowercase,
/// strip dots / spaces / underscores / dashes. `diegostaino`, `diego.staino`
/// and `Diego Staino` all collapse to `diegostaino`.
fn normalize_user_id(id: &str) -> String {
    id.chars()
        .filter(|c| !c.is_whitespace() && *c != '.' && *c != '_' && *c != '-')
        .flat_map(char::to_lowercase)
        .collect()
}

/// Walks the graph looking for two structural ingest pitfalls and emits
/// human-readable warnings. Read-only — never mutates the graph. Used to
/// make symptoms like "30 users + 1 backend IP" or "diegostaino vs Diego
/// Staino" explicit in `LoadResult.warnings` instead of forcing the
/// analyst to discover them by eye.
///
/// Two checks:
/// - **Shared-infrastructure IP**: an IP entity with fan-in from ≥5
///   distinct User entities (typical of SaaS/proxy backends like Zoho).
/// - **Likely-duplicate user identities**: User ids that collapse to the
///   same `normalize_user_id` form (login vs display name).
pub fn compute_ingest_warnings(graph: &GraphHunter) -> Vec<String> {
    let mut warnings = Vec::new();

    // ── shared-infra IP: an IP touched by many distinct users ──
    const SHARED_IP_USER_THRESHOLD: usize = 5;
    let mut ip_to_users: HashMap<&str, HashSet<&str>> = HashMap::new();
    for entity in graph.entities.values() {
        if !matches!(entity.entity_type, EntityType::User) {
            continue;
        }
        let user_id = entity.id.as_str();
        for compact in graph.get_compact_relations(user_id) {
            let dest_str = graph.interner.resolve(compact.dest_sid);
            if let Some(dest_entity) = graph.get_entity(dest_str) {
                if matches!(dest_entity.entity_type, EntityType::IP) {
                    ip_to_users
                        .entry(dest_entity.id.as_str())
                        .or_default()
                        .insert(user_id);
                }
            }
        }
    }
    let mut shared_ips: Vec<(&str, usize)> = ip_to_users
        .iter()
        .filter(|(_, users)| users.len() >= SHARED_IP_USER_THRESHOLD)
        .map(|(ip, users)| (*ip, users.len()))
        .collect();
    shared_ips.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(b.0)));
    for (ip, count) in shared_ips.iter().take(3) {
        warnings.push(format!(
            "IP {ip} received connections from {count} distinct users — likely shared infrastructure (proxy/SaaS backend). Score this IP as low-signal."
        ));
    }

    // ── likely-duplicate user identities ──
    let mut buckets: HashMap<String, Vec<&str>> = HashMap::new();
    for entity in graph.entities.values() {
        if !matches!(entity.entity_type, EntityType::User) {
            continue;
        }
        let norm = normalize_user_id(&entity.id);
        if norm.is_empty() {
            continue;
        }
        buckets.entry(norm).or_default().push(entity.id.as_str());
    }
    let mut dup_groups: Vec<Vec<&str>> =
        buckets.into_values().filter(|ids| ids.len() >= 2).collect();
    dup_groups.sort_by(|a, b| b.len().cmp(&a.len()).then(a[0].cmp(b[0])));
    for group in dup_groups.iter().take(5) {
        let mut sample = group.to_vec();
        sample.sort();
        let preview = sample
            .iter()
            .take(3)
            .copied()
            .collect::<Vec<_>>()
            .join(" ≈ ");
        warnings.push(format!(
            "Likely duplicate user identities ({} variants): {}{}",
            group.len(),
            preview,
            if group.len() > 3 { " …" } else { "" }
        ));
    }

    warnings
}

impl GraphHunterApi {
    /// Detect a file's format + propose a field → entity type mapping.
    /// Stateless — reads from disk, doesn't touch any session.
    pub fn preview_ingest(&self, req: PreviewIngestRequest) -> ApiResult<PreviewIngestResult> {
        let use_evtx = req.format.to_lowercase() == "evtx"
            || path_is_evtx(&req.path)
            || (req.format.to_lowercase() == "auto" && file_looks_like_evtx(&req.path));
        let (contents, resolved) = if use_evtx {
            let contents =
                evtx_preview_sample(&req.path, EVTX_PREVIEW_SAMPLE_SIZE).map_err(ApiError::Io)?;
            (contents, "sysmon".to_string())
        } else {
            let file_size = std::fs::metadata(&req.path).map(|m| m.len()).unwrap_or(0);
            let contents = if file_size > LARGE_FILE_THRESHOLD {
                let mut file = std::fs::File::open(&req.path)
                    .map_err(|e| ApiError::Io(format!("open '{}': {e}", req.path)))?;
                let mut buf = vec![0u8; PREVIEW_READ_SIZE];
                let n = std::io::Read::read(&mut file, &mut buf)
                    .map_err(|e| ApiError::Io(format!("read: {e}")))?;
                String::from_utf8_lossy(&buf[..n]).to_string()
            } else {
                std::fs::read_to_string(&req.path)
                    .map_err(|e| ApiError::Io(format!("read '{}': {e}", req.path)))?
            };
            let resolved = resolve_format(&contents, &req.format);
            (contents, resolved)
        };
        let detected_fields: Vec<DetectedField> = rich_preview_for_format(&resolved, &contents)
            .into_iter()
            .map(|fi| {
                // Default precedence:
                //   1. heuristic match (suggest_entity_type) wins — its
                //      source ("name"/"values") is preserved from core.
                //   2. timestamp canonical → Skip (timestamps are edge metadata)
                //   3. any other canonical field → its canonical entity type
                //      (so EVENT_BY → User, IP_ADDRESS → IP even when the
                //      name-heuristic stays silent — this avoids defaulting
                //      to raw_name, which would diverge from the canonical
                //      default and trigger the override-strip path)
                //   4. truly unknown column → raw column name as a custom
                //      entity type so the data is preserved in the graph
                let is_timestamp = fi.canonical_target.as_deref() == Some("timestamp");
                let canonical_default = fi.canonical_target.as_deref().and_then(|ct| {
                    let et = graph_hunter_core::GenericParser::canonical_to_entity_type(ct);
                    if et == "Skip" {
                        None
                    } else {
                        Some(et.to_string())
                    }
                });
                let (suggested_entity_type, suggestion_source) = match (
                    fi.suggested_entity_type.clone(),
                    fi.suggestion_source.clone(),
                    canonical_default,
                ) {
                    (Some(t), src, _) => (t, src),
                    (None, _, _) if is_timestamp => {
                        ("Skip".to_string(), Some("canonical".to_string()))
                    }
                    (None, _, Some(canonical)) => (canonical, Some("canonical".to_string())),
                    (None, _, None) => (fi.raw_name.clone(), Some("default".to_string())),
                };
                DetectedField {
                    field_name: fi.raw_name,
                    suggested_entity_type,
                    canonical_target: fi.canonical_target,
                    occurrence_count: fi.occurrence_count,
                    sample_values: fi.sample_values,
                    suggestion_source,
                }
            })
            .collect();
        Ok(PreviewIngestResult {
            format: resolved,
            detected_fields,
        })
    }

    /// PCAP / PCAPNG preview. Reads up to 10K packets and returns a
    /// non-tabular summary (top src/dst IPs, top dst ports, protocol
    /// mix, time span). Stateless — touches no session. Frontend
    /// dispatches by extension; the regular [`Self::preview_ingest`]
    /// path would corrupt the binary file via `read_to_string`.
    pub fn pcap_preview(&self, req: PcapPreviewRequest) -> ApiResult<PcapPreviewResult> {
        crate::pcap_preview::pcap_preview_sample(&req.path).map_err(ApiError::Io)
    }

    /// Read a file from disk, parse it, insert triples into the
    /// resolved session's graph, and run full scoring. Synchronous;
    /// callers in async contexts should `spawn_blocking`.
    pub fn load_data(&self, req: LoadDataRequest) -> ApiResult<LoadResult> {
        let use_evtx = req.format.to_lowercase() == "evtx"
            || path_is_evtx(&req.path)
            || (req.format.to_lowercase() == "auto" && file_looks_like_evtx(&req.path));
        let (contents, format_for_parser) = if use_evtx {
            let contents = evtx_to_sysmon_ndjson(&req.path).map_err(ApiError::Io)?;
            (contents, "generic".to_string())
        } else {
            let contents = std::fs::read_to_string(&req.path)
                .map_err(|e| ApiError::Io(format!("read '{}': {e}", req.path)))?;
            (contents, req.format)
        };

        let session = self.resolve_session(req.session.as_ref())?;

        let dataset_id = Uuid::new_v4().to_string();
        let name = std::path::Path::new(&req.path)
            .file_name()
            .and_then(|p| p.to_str())
            .unwrap_or("ingest")
            .to_string();

        let resolved_format = resolve_format(&contents, &format_for_parser);
        // Auto-build a FieldConfig from the same heuristic the Preview UI
        // uses, so one-shot ingest matches the field coverage the analyst
        // sees in the customization panel (multilingual aliases + value-
        // based regex inference). Falls back to the format's native parser
        // when the format isn't `ConfigurableParser`-compatible.
        let auto_config = auto_field_config_for(&resolved_format, &contents);

        {
            let mut datasets = session
                .datasets
                .write()
                .map_err(|e| ApiError::Internal(format!("datasets lock poisoned: {e}")))?;
            datasets.push(DatasetInfo {
                id: dataset_id.clone(),
                name,
                path: Some(req.path.clone()),
                created_at: now_secs(),
                entity_count: 0,
                relation_count: 0,
                // Persist the auto-built config so DatasetCard's "Schema
                // used" view shows the same mappings the parser actually
                // applied — the analyst can then tweak from a real baseline
                // instead of the empty default.
                field_config: auto_config.clone(),
                ingest_stats: None,
            });
        }
        let resume_phase = resume_phase_after_finalize(session.phase());
        session.set_phase(crate::state::SessionPhase::Finalizing);
        let _phase_guard = FinalizePhaseGuard { session: Arc::clone(&session), resume: resume_phase };
        let (new_entities, new_relations, ingest_stats, used_auto_config) = {
            let mut graph = session
                .graph
                .write()
                .map_err(|e| ApiError::Internal(format!("graph lock poisoned: {e}")))?;
            let (events, stats, used_auto) = if let Some(cfg) = auto_config.clone() {
                let parser = ConfigurableParser::new(cfg);
                let (e, s) = parser.parse_raw_with_stats(&contents);
                (e, s, true)
            } else {
                let parser =
                    make_parser_for_format(&resolved_format).map_err(ApiError::InvalidInput)?;
                let (e, s) = parser.parse_raw_with_stats(&contents);
                (e, s, false)
            };
            self.record_parse_skips(dataset_id.as_str(), None, &stats);
            let (ne, nr) = graph
                .insert_raw_events(events, Some(dataset_id.as_str()))
                .map_err(|e| ApiError::Internal(e.to_string()))?;
            run_full_scoring(&mut graph);
            // An empty ParseStats (rows_seen == 0) means the parser didn't
            // report real stats — treat as "unknown".
            let stats = if stats.rows_seen == 0 {
                None
            } else {
                Some(stats)
            };
            if let Some(s) = stats.as_ref() {
                if let Some(d) = s.drift.as_ref() {
                    self.record_drift(dataset_id.as_str(), d);
                }
            }
            (ne, nr, stats, used_auto)
        };
        // Record post-finalize appends only after the graph write guard is
        // released: note_post_finalize_appends re-acquires graph.read(), and
        // a read-while-write on the same thread self-deadlocks the RwLock.
        // no-ops here: phase is Finalizing at this point (the FinalizePhaseGuard has
        // not dropped yet), so the Ready->LiveTail transition is skipped. Sync batch
        // ingest intentionally never enters LiveTail anyway (Track O owns that).
        note_post_finalize_appends(&session, new_relations);
        let _ = used_auto_config; // reserved for future telemetry (which path served the ingest)

        {
            let mut datasets = session
                .datasets
                .write()
                .map_err(|e| ApiError::Internal(format!("datasets lock poisoned: {e}")))?;
            if let Some(last) = datasets.last_mut() {
                last.entity_count = new_entities;
                last.relation_count = new_relations;
                last.ingest_stats = ingest_stats.clone();
            }
        }

        let (total_entities, total_relations, warnings) = {
            let graph = session
                .graph
                .read()
                .map_err(|e| ApiError::Internal(format!("graph lock poisoned: {e}")))?;
            (
                graph.entity_count(),
                graph.relation_count(),
                compute_ingest_warnings(&graph),
            )
        };

        let zero_triples = ingest_stats
            .as_ref()
            .map(|s| s.rows_seen > 0 && s.rows_with_triples == 0)
            .unwrap_or(false);
        Ok(LoadResult {
            new_entities,
            new_relations,
            total_entities,
            total_relations,
            zero_triples,
            ingest_stats,
            warnings,
        })
    }

    /// SIEM ingest (Sentinel or Elastic): fetch via CLI helper then
    /// ingest into the resolved session's graph. Async because the
    /// network fetch runs in a `spawn_blocking` task.
    pub async fn ingest_siem(&self, req: IngestSiemRequest) -> ApiResult<LoadResult> {
        let source = req
            .params
            .get("source")
            .and_then(|v| v.as_str())
            .ok_or_else(|| {
                ApiError::InvalidInput("missing param: source (sentinel | elastic)".into())
            })?;

        let data = match source {
            "sentinel" => {
                let workspace_id = req
                    .params
                    .get("workspace_id")
                    .and_then(|v| v.as_str())
                    .ok_or_else(|| ApiError::InvalidInput("missing param: workspace_id".into()))?
                    .to_string();
                let query = req
                    .params
                    .get("query")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string();
                let auth = match (
                    req.params.get("azure_tenant_id").and_then(|v| v.as_str()),
                    req.params.get("azure_client_id").and_then(|v| v.as_str()),
                    req.params
                        .get("azure_client_secret")
                        .and_then(|v| v.as_str()),
                ) {
                    (Some(t), Some(c), Some(s)) => Some(graph_hunter_siem::SentinelAuth {
                        tenant_id: t.to_string(),
                        client_id: c.to_string(),
                        client_secret: s.to_string(),
                    }),
                    _ => None,
                };
                let res = tokio::task::spawn_blocking(move || {
                    graph_hunter_siem::run_sentinel_query(&workspace_id, &query, auth)
                })
                .await
                .map_err(|e| ApiError::Internal(format!("task join error: {e}")))?
                .map_err(|e| ApiError::Upstream {
                    service: "sentinel".into(),
                    message: e,
                })?;
                res.data
            }
            "elastic" => {
                let url = req
                    .params
                    .get("url")
                    .and_then(|v| v.as_str())
                    .ok_or_else(|| ApiError::InvalidInput("missing param: url".into()))?
                    .to_string();
                let index = req
                    .params
                    .get("index")
                    .and_then(|v| v.as_str())
                    .unwrap_or("_all")
                    .to_string();
                let query = req
                    .params
                    .get("query")
                    .and_then(|v| v.as_str())
                    .unwrap_or("{}")
                    .to_string();
                let size = req
                    .params
                    .get("size")
                    .and_then(|v| v.as_u64())
                    .map(|n| n as u32);
                let auth = match (
                    req.params.get("elastic_api_key").and_then(|v| v.as_str()),
                    req.params.get("elastic_user").and_then(|v| v.as_str()),
                    req.params.get("elastic_password").and_then(|v| v.as_str()),
                ) {
                    (Some(k), _, _) if !k.is_empty() => Some(graph_hunter_siem::ElasticAuth {
                        api_key: Some(k.to_string()),
                        user: None,
                        password: None,
                    }),
                    (_, Some(u), p) if !u.is_empty() => Some(graph_hunter_siem::ElasticAuth {
                        api_key: None,
                        user: Some(u.to_string()),
                        password: p.map(|s| s.to_string()),
                    }),
                    _ => None,
                };
                let res = tokio::task::spawn_blocking(move || {
                    graph_hunter_siem::run_elastic_query(&url, &index, &query, size, None, auth)
                })
                .await
                .map_err(|e| ApiError::Internal(format!("task join error: {e}")))?
                .map_err(|e| ApiError::Upstream {
                    service: "elastic".into(),
                    message: e.to_string(),
                })?;
                res.data
            }
            other => {
                return Err(ApiError::InvalidInput(format!(
                    "unsupported source: '{other}'. Use 'sentinel' or 'elastic'."
                )));
            }
        };

        let session = self.resolve_session(req.session.as_ref())?;

        let dataset_id = Uuid::new_v4().to_string();
        let name = match source {
            "sentinel" => "Sentinel ingest",
            _ => "Elasticsearch ingest",
        }
        .to_string();

        {
            let mut datasets = session
                .datasets
                .write()
                .map_err(|e| ApiError::Internal(format!("datasets lock poisoned: {e}")))?;
            datasets.push(DatasetInfo {
                id: dataset_id.clone(),
                name,
                path: None,
                created_at: now_secs(),
                entity_count: 0,
                relation_count: 0,
                field_config: None,
                ingest_stats: None,
            });
        }

        let resume_phase = resume_phase_after_finalize(session.phase());
        session.set_phase(crate::state::SessionPhase::Finalizing);
        let _phase_guard = FinalizePhaseGuard { session: Arc::clone(&session), resume: resume_phase };
        let (new_entities, new_relations) = {
            let mut graph = session
                .graph
                .write()
                .map_err(|e| ApiError::Internal(format!("graph lock poisoned: {e}")))?;
            let parser = make_parser_for_format("sentinel").map_err(ApiError::InvalidInput)?;
            // RawIngestEvent path — see evtx.rs for the rationale.
            let events = parser.parse_raw(&data);
            let (e, r) = graph
                .insert_raw_events(events, Some(dataset_id.as_str()))
                .map_err(|e| ApiError::Internal(e.to_string()))?;
            run_full_scoring(&mut graph);
            (e, r)
        };
        // Record post-finalize appends after the write guard is dropped
        // (calling while holding the graph write lock self-deadlocks the RwLock).
        // no-ops here: phase is Finalizing at this point (the FinalizePhaseGuard has
        // not dropped yet), so the Ready->LiveTail transition is skipped. Sync batch
        // ingest intentionally never enters LiveTail anyway (Track O owns that).
        note_post_finalize_appends(&session, new_relations);

        {
            let mut datasets = session
                .datasets
                .write()
                .map_err(|e| ApiError::Internal(format!("datasets lock poisoned: {e}")))?;
            if let Some(last) = datasets.last_mut() {
                last.entity_count = new_entities;
                last.relation_count = new_relations;
            }
        }

        let (total_entities, total_relations, warnings) = {
            let graph = session
                .graph
                .read()
                .map_err(|e| ApiError::Internal(format!("graph lock poisoned: {e}")))?;
            (
                graph.entity_count(),
                graph.relation_count(),
                compute_ingest_warnings(&graph),
            )
        };

        Ok(LoadResult {
            new_entities,
            new_relations,
            total_entities,
            total_relations,
            zero_triples: false,
            ingest_stats: None,
            warnings,
        })
    }

    /// Load data with an explicit [`FieldConfig`] (user-supplied field
    /// mapping). Replaces `cmd_load_data_with_config` from the Tauri
    /// `graph_ops` module. Synchronous — spawn_blocking at the
    /// caller.
    pub fn load_data_with_config(&self, req: LoadDataWithConfigRequest) -> ApiResult<LoadResult> {
        // Auto-upgrade stale mappings (TIME→Ignore, SEVERITY→Node, etc.)
        // so canonical-Skip fields always land as Metadata regardless of
        // what the persisted FieldConfig said.
        let mut req = req;
        let _upgraded = sanitize_field_config(&mut req.config);

        // Same EVTX-detection path as load_data.
        let use_evtx = path_is_evtx(&req.path) || file_looks_like_evtx(&req.path);
        let contents = if use_evtx {
            evtx_to_sysmon_ndjson(&req.path).map_err(ApiError::Io)?
        } else {
            std::fs::read_to_string(&req.path)
                .map_err(|e| ApiError::Io(format!("read '{}': {e}", req.path)))?
        };

        let session = self.resolve_session(req.session.as_ref())?;

        let dataset_id = Uuid::new_v4().to_string();
        let name = std::path::Path::new(&req.path)
            .file_name()
            .and_then(|p| p.to_str())
            .unwrap_or("ingest")
            .to_string();
        {
            let mut datasets = session
                .datasets
                .write()
                .map_err(|e| ApiError::Internal(format!("datasets lock poisoned: {e}")))?;
            datasets.push(DatasetInfo {
                id: dataset_id.clone(),
                name,
                path: Some(req.path.clone()),
                created_at: now_secs(),
                entity_count: 0,
                relation_count: 0,
                field_config: Some(req.config.clone()),
                ingest_stats: None,
            });
        }

        let resume_phase = resume_phase_after_finalize(session.phase());
        session.set_phase(crate::state::SessionPhase::Finalizing);
        let _phase_guard = FinalizePhaseGuard { session: Arc::clone(&session), resume: resume_phase };
        let (new_entities, new_relations, ingest_stats) = {
            let mut graph = session
                .graph
                .write()
                .map_err(|e| ApiError::Internal(format!("graph lock poisoned: {e}")))?;
            let out = if use_evtx {
                let (ne, nr) = graph
                    .ingest_logs(&contents, &GenericParser, None)
                    .map_err(|e| ApiError::Internal(e.to_string()))?;
                (ne, nr, None)
            } else {
                let parser = ConfigurableParser::new(req.config.clone());
                let (events, stats) = parser.parse_raw_with_stats(&contents);
                self.record_parse_skips(dataset_id.as_str(), None, &stats);
                let (ne, nr) = graph
                    .insert_raw_events(events, Some(dataset_id.as_str()))
                    .map_err(|e| ApiError::Internal(e.to_string()))?;
                (ne, nr, Some(stats))
            };
            run_full_scoring(&mut graph);
            out
        };
        // Record post-finalize appends after the write guard is dropped
        // (calling while holding the graph write lock self-deadlocks the RwLock).
        // no-ops here: phase is Finalizing at this point (the FinalizePhaseGuard has
        // not dropped yet), so the Ready->LiveTail transition is skipped. Sync batch
        // ingest intentionally never enters LiveTail anyway (Track O owns that).
        note_post_finalize_appends(&session, new_relations);

        {
            let mut datasets = session
                .datasets
                .write()
                .map_err(|e| ApiError::Internal(format!("datasets lock poisoned: {e}")))?;
            if let Some(last) = datasets.last_mut() {
                last.entity_count = new_entities;
                last.relation_count = new_relations;
                last.ingest_stats = ingest_stats.clone();
            }
        }

        if let Some(s) = ingest_stats.as_ref() {
            if let Some(d) = s.drift.as_ref() {
                self.record_drift(dataset_id.as_str(), d);
            }
        }

        let (total_entities, total_relations, warnings) = {
            let graph = session
                .graph
                .read()
                .map_err(|e| ApiError::Internal(format!("graph lock poisoned: {e}")))?;
            (
                graph.entity_count(),
                graph.relation_count(),
                compute_ingest_warnings(&graph),
            )
        };

        let zero_triples = ingest_stats
            .as_ref()
            .map(|s| s.rows_seen > 0 && s.rows_with_triples == 0)
            .unwrap_or(false);
        Ok(LoadResult {
            new_entities,
            new_relations,
            total_entities,
            total_relations,
            zero_triples,
            ingest_stats,
            warnings,
        })
    }

    /// Starts a background streaming ingestion and returns the
    /// `job_id` / `dataset_id` synchronously. Progress is emitted via
    /// `ingest-progress`, completion via `ingest-complete`, failure via
    /// `ingest-error` — all through the API's canonical
    /// [`EventEmitter`], which each transport (Tauri / HTTP / tests)
    /// binds to its own sink.
    ///
    /// Moved from `apps/tauri/src-tauri/src/commands/ingestion.rs` in
    /// F2.16. The previous Tauri command is now a thin delegator so
    /// every path through ingestion — preview, one-shot, streaming,
    /// explicit-config — shares the same business-logic surface.
    pub fn load_data_streaming(
        &self,
        req: LoadDataStreamingRequest,
    ) -> ApiResult<IngestJobStarted> {
        // Validate format before any work so callers fail fast.
        // Tabular formats stay hardcoded (they flow through
        // `format_registry`); stateful ingestors (EVTX, PCAP, …) come
        // from the `ingestors` module registry so adding one there
        // automatically accepts its name + aliases here.
        let pre_check = req.format.to_lowercase();
        const TABULAR_FORMATS: &[&str] = &[
            "auto",
            "sysmon",
            "sentinel",
            "cognito",
            "generic",
            "csv",
            "iis",
            "iis_w3c",
            "w3c",
            "fortianalyzer",
            "faz",
            "forti",
            "xml",
        ];
        if !TABULAR_FORMATS.contains(&pre_check.as_str())
            && !crate::ingestors::is_known_streaming_format(&pre_check)
        {
            return Err(ApiError::InvalidInput(format!(
                "Unsupported format: '{}'. Use 'auto', 'evtx', 'pcap', 'sysmon', 'sentinel', 'cognito', 'generic', 'csv', 'iis', or 'fortianalyzer'.",
                req.format
            )));
        }

        let session = self.resolve_session(req.session.as_ref())?;
        let job_id = Uuid::new_v4().to_string();
        let dataset_id = Uuid::new_v4().to_string();

        let file_name = std::path::Path::new(&req.path)
            .file_name()
            .and_then(|p| p.to_str())
            .unwrap_or("ingest")
            .to_string();

        // Register the dataset synchronously so the caller sees the
        // record the moment `IngestJobStarted` returns, matching the
        // old Tauri behavior.
        {
            let mut datasets = session
                .datasets
                .write()
                .map_err(|e| ApiError::Internal(format!("datasets lock poisoned: {e}")))?;
            datasets.push(DatasetInfo {
                id: dataset_id.clone(),
                name: file_name,
                path: Some(req.path.clone()),
                created_at: now_secs(),
                entity_count: 0,
                relation_count: 0,
                field_config: req.config.clone(),
                ingest_stats: None,
            });
        }

        let result_to_return = IngestJobStarted {
            job_id: job_id.clone(),
            dataset_id: dataset_id.clone(),
        };

        // Clones for the background task. `GraphHunterApi` is cheap to
        // clone (it wraps `Arc<ApiState>`), and `emitter`/`session` are
        // already Arc handles.
        let bg_job_id = job_id.clone();
        let bg_dataset_id = dataset_id.clone();
        let bg_path = req.path.clone();
        let bg_format = req.format.clone();
        let bg_config = req.config.clone();
        let bg_date_from = req.date_from.clone();
        let bg_date_to = req.date_to.clone();
        let bg_session = Arc::clone(&session);
        let bg_emitter: Arc<dyn EventEmitter> = Arc::clone(self.emitter());
        let bg_api: GraphHunterApi = self.clone();

        // Fire-and-forget: the caller is sync and we don't await the
        // handle, so a plain OS thread works and doesn't require a Tokio
        // runtime in scope. `spawn_blocking` here panicked when Tauri
        // invoked this op from a sync `#[command]` on the WebView2
        // callback thread (F2.16 regression).
        std::thread::spawn(move || {
            let panic_emitter = Arc::clone(&bg_emitter);
            let panic_job_id = bg_job_id.clone();
            let panic_dataset_id = bg_dataset_id.clone();
            let panic_session = Arc::clone(&bg_session);

            let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(move || {
                bg_session.set_phase(SessionPhase::Loading);

                const MAX_INGEST_LINES: usize = usize::MAX;

                // Date-range filter for line-based formats (IIS, CSV). Lines
                // whose first 10 bytes parse as an ISO date outside
                // `[date_from, date_to]` are skipped before parsing. Byte
                // comparison works because `YYYY-MM-DD` sorts
                // lexicographically.
                let date_from_bytes: Option<Vec<u8>> =
                    bg_date_from.as_ref().map(|s| s.as_bytes().to_vec());
                let date_to_bytes: Option<Vec<u8>> =
                    bg_date_to.as_ref().map(|s| s.as_bytes().to_vec());
                tracing::info!(
                    "INGEST: date_from={:?}, date_to={:?}",
                    bg_date_from,
                    bg_date_to
                );

                // 1. Stateful binary / state-carrying-text formats go
                //    through the `ingestors` registry. EVTX and PCAP
                //    used to be two hard-coded `if`-branches here;
                //    they're now `StreamingIngestor` impls in
                //    `crate::ingestors`. Future PRs add Zeek,
                //    Suricata, NetFlow, live capture by registering
                //    new ingestors — no edit to this dispatch.
                if let Some(ingestor) =
                    crate::ingestors::resolve_ingestor(&bg_path, &bg_format)
                {
                    let result = ingestor.ingest(crate::ingestors::IngestContext {
                        path: &bg_path,
                        session: &bg_session,
                        dataset_id: &bg_dataset_id,
                        emitter: &bg_emitter,
                        job_id: &bg_job_id,
                        date_from: bg_date_from.as_deref(),
                        date_to: bg_date_to.as_deref(),
                        config: bg_config.as_ref(),
                    });

                    match result {
                        Ok((total_new_entities, total_new_relations)) => {
                            bg_emitter.emit(
                                INGEST_PROGRESS,
                                serde_json::json!({
                                    "phase": "scoring",
                                    "bytes_read": 0u64,
                                    "bytes_total": 0u64,
                                    "entities": total_new_entities,
                                    "relations": total_new_relations,
                                }),
                            );

                            if let Ok(mut graph) = bg_session.graph.write() {
                                graph.compute_composite_score_hunt_default();
                                graph.finalize_anomaly_scorer();
                            }

                            {
                                let mut datasets = match bg_session.datasets.write() {
                                    Ok(d) => d,
                                    Err(_) => return,
                                };
                                if let Some(ds) =
                                    datasets.iter_mut().find(|d| d.id == bg_dataset_id)
                                {
                                    ds.entity_count = total_new_entities;
                                    ds.relation_count = total_new_relations;
                                }
                            }

                            let (total_entities, total_relations, warnings) = {
                                let graph = match bg_session.graph.read() {
                                    Ok(g) => g,
                                    Err(_) => return,
                                };
                                let warnings = compute_ingest_warnings(&graph);
                                (graph.entity_count(), graph.relation_count(), warnings)
                            };

                            bg_emitter.emit(
                                INGEST_COMPLETE,
                                serde_json::to_value(&IngestComplete {
                                    job_id: bg_job_id,
                                    dataset_id: bg_dataset_id,
                                    result: LoadResult {
                                        new_entities: total_new_entities,
                                        new_relations: total_new_relations,
                                        total_entities,
                                        total_relations,
                                        zero_triples: total_new_entities == 0
                                            && total_new_relations == 0,
                                        ingest_stats: None,
                                        warnings,
                                    },
                                })
                                .unwrap_or_default(),
                            );
                        }
                        Err(e) => {
                            bg_emitter.emit(
                                INGEST_ERROR,
                                serde_json::to_value(&IngestError {
                                    job_id: bg_job_id,
                                    dataset_id: bg_dataset_id,
                                    error: e,
                                })
                                .unwrap_or_default(),
                            );
                        }
                    }
                    return;
                }

                // 2. Open file and get size for progress reporting
                let file = match std::fs::File::open(&bg_path) {
                    Ok(f) => f,
                    Err(e) => {
                        bg_emitter.emit(
                            INGEST_ERROR,
                            serde_json::to_value(&IngestError {
                                job_id: bg_job_id,
                                dataset_id: bg_dataset_id,
                                error: format!("Failed to open file '{}': {}", bg_path, e),
                            })
                            .unwrap_or_default(),
                        );
                        return;
                    }
                };
                let bytes_total = file.metadata().map(|m| m.len()).unwrap_or(0);

                // 3. Read first 8KB for format detection
                let mut reader = BufReader::with_capacity(BUF_CAPACITY, file);
                let peek_buf = {
                    let mut peek_bytes = [0u8; PEEK_BUF_SIZE];
                    let n = std::io::Read::read(&mut reader, &mut peek_bytes).unwrap_or(0);
                    String::from_utf8_lossy(&peek_bytes[..n]).to_string()
                };
                let resolved = resolve_format(&peek_buf, &bg_format);

                let trimmed_peek = peek_buf.trim_start();
                let is_line_based = trimmed_peek.starts_with('{')
                    || matches!(resolved.as_str(), "iis" | "iis_w3c" | "w3c")
                    || (resolved == "cognito" && !trimmed_peek.starts_with('['));

                let iis_fields_header = if matches!(resolved.as_str(), "iis" | "iis_w3c" | "w3c") {
                    extract_fields_header(&peek_buf)
                } else {
                    None
                };

                // Auto-build a FieldConfig from the same preview heuristics the
                // customization panel uses, so one-shot ingest doesn't silently
                // fall back to plain GenericParser for formats that benefit
                // from field-based entity-type suggestions.
                //
                // The LLM-as-compiler dispatcher used to fire here when
                // `GRAPHHUNTER_LLM_INGEST=1`, but Phi-3 inference on a CPU
                // dev profile took 9 minutes per call — unusable as a hot-
                // path silent step. Phase G demoted the dispatcher to an
                // explicit "Probar mapeo IA" button on `DatasetCard`, which
                // calls `cmd_request_llm_proposal` after a 0-triple ingest.
                // The hot path stays heuristic-only and instant.
                let auto_config = if bg_config.is_none() {
                    auto_field_config_for(&resolved, &peek_buf)
                } else {
                    None
                };
                let effective_config: Option<FieldConfig> =
                    bg_config.clone().or(auto_config.clone());
                let parser: Box<dyn LogParser + Send + Sync> = if let Some(cfg) = &effective_config
                {
                    Box::new(ConfigurableParser::new(cfg.clone()))
                } else {
                    match make_parser_for_format(&resolved) {
                        Ok(p) => p,
                        Err(e) => {
                            bg_emitter.emit(
                                INGEST_ERROR,
                                serde_json::to_value(&IngestError {
                                    job_id: bg_job_id,
                                    dataset_id: bg_dataset_id,
                                    error: e,
                                })
                                .unwrap_or_default(),
                            );
                            return;
                        }
                    }
                };

                // Persist the effective config into DatasetInfo so the UI's
                // "Schema used" panel reflects what was actually applied.
                if let Some(cfg) = &auto_config {
                    if let Ok(mut datasets) = bg_session.datasets.write() {
                        if let Some(ds) = datasets.iter_mut().find(|d| d.id == bg_dataset_id) {
                            ds.field_config = Some(cfg.clone());
                        }
                    }
                }

                // Pre-allocate graph capacity based on file-size heuristics.
                {
                    let estimated_entities =
                        ((bytes_total / 400) as usize).min(MAX_PREALLOC_ENTITIES);
                    let estimated_relations =
                        ((bytes_total / 200) as usize).min(MAX_PREALLOC_RELATIONS);
                    if let Ok(mut graph) = bg_session.graph.write() {
                        graph.reserve(estimated_entities, estimated_relations);
                    }
                }

                tracing::info!(
                    "INGEST: format={}, is_line_based={}, file_size={}",
                    resolved,
                    is_line_based,
                    bytes_total
                );
                let ingest_result: Result<(usize, usize, Option<DriftSnapshot>), String> =
                    (|| -> Result<(usize, usize, Option<DriftSnapshot>), String> {
                        if is_line_based {
                            // ── Line-based streaming path (NDJSON / IIS / CSV): mmap + line-batch parsing ──
                            bg_emitter.emit(
                                INGEST_PROGRESS,
                                serde_json::json!({
                                    "phase": "reading",
                                    "bytes_read": 0u64,
                                    "bytes_total": bytes_total,
                                    "entities": 0,
                                    "relations": 0,
                                }),
                            );

                            let file2 = std::fs::File::open(&bg_path).map_err(|e| {
                                format!("Failed to re-open file '{}': {}", bg_path, e)
                            })?;
                            let mmap = unsafe { memmap2::Mmap::map(&file2) }.map_err(|e| {
                                tracing::error!("INGEST: Failed to mmap: {}", e);
                                format!("Failed to mmap file '{}': {}", bg_path, e)
                            })?;
                            graph_hunter_core::mmap_advise::try_hugepages(&mmap);
                            tracing::info!("INGEST: mmap OK, {} bytes", mmap.len());

                            let raw = &mmap[..];

                            let mut total_new_entities = 0usize;
                            let mut total_new_relations = 0usize;
                            let mut lines_in_batch = 0usize;
                            let mut batch_start = 0usize;
                            let mut stopped_early = false;
                            let mut drift_accum: Option<DriftSnapshot> = None;

                            let mut last_fields_header: Option<String> = iis_fields_header.clone();

                            let mut total_lines = 0usize;
                            let mut search_offset = 0usize;
                            while let Some(rel_pos) = memchr::memchr(b'\n', &raw[search_offset..]) {
                                let pos = search_offset + rel_pos;
                                search_offset = pos + 1;

                                total_lines += 1;
                                if total_lines > MAX_INGEST_LINES {
                                    tracing::warn!(
                                        "INGEST: reached max ingest limit of {} lines, stopping",
                                        MAX_INGEST_LINES
                                    );
                                    stopped_early = true;
                                    break;
                                }

                                if date_from_bytes.is_some() || date_to_bytes.is_some() {
                                    let line_start = if pos > 0 && batch_start < pos {
                                        raw[batch_start..pos]
                                            .iter()
                                            .rposition(|&b| b == b'\n')
                                            .map(|p| batch_start + p + 1)
                                            .unwrap_or(batch_start)
                                    } else {
                                        batch_start
                                    };
                                    let first_byte = raw.get(line_start).copied().unwrap_or(b'#');
                                    if first_byte.is_ascii_digit() && pos >= line_start + 10 {
                                        let line_date = &raw[line_start..line_start + 10];
                                        if let Some(ref from) = date_from_bytes {
                                            if line_date < from.as_slice() {
                                                continue;
                                            }
                                        }
                                        if let Some(ref to) = date_to_bytes {
                                            if line_date > to.as_slice() {
                                                continue;
                                            }
                                        }
                                    }
                                }

                                if last_fields_header.is_some() || iis_fields_header.is_some() {
                                    let line_start = if pos > 0 {
                                        let search_from = batch_start.max(pos.saturating_sub(512));
                                        memchr::memrchr(b'\n', &raw[search_from..pos])
                                            .map(|p| search_from + p + 1)
                                            .unwrap_or(batch_start)
                                    } else {
                                        0
                                    };
                                    if pos > line_start + 8
                                        && &raw[line_start
                                            ..line_start.min(raw.len()).max(line_start + 8)]
                                            == b"#Fields:"
                                    {
                                        let line_bytes = &raw[line_start..pos];
                                        let line_str = String::from_utf8_lossy(line_bytes);
                                        last_fields_header = Some(line_str.trim().to_string());
                                    }
                                }

                                lines_in_batch += 1;

                                if lines_in_batch >= BATCH_LINES {
                                    let batch_bytes = &raw[batch_start..pos + 1];
                                    let batch_str = String::from_utf8_lossy(batch_bytes);

                                    let parse_input: String = if let Some(ref hdr) =
                                        last_fields_header
                                    {
                                        if memchr::memmem::find(batch_bytes, b"#Fields:").is_none()
                                        {
                                            format!("{}\n{}", hdr, batch_str)
                                        } else {
                                            batch_str.into_owned()
                                        }
                                    } else {
                                        batch_str.into_owned()
                                    };

                                    let sub_chunks: Vec<&str> = {
                                        let num_chunks = rayon::current_num_threads().max(1);
                                        let lines: Vec<&str> = parse_input.lines().collect();
                                        let chunk_size = (lines.len() / num_chunks).max(1);
                                        lines
                                            .chunks(chunk_size)
                                            .map(|chunk| {
                                                let first = chunk[0].as_ptr() as usize
                                                    - parse_input.as_ptr() as usize;
                                                let last = chunk.last().unwrap();
                                                let end = last.as_ptr() as usize + last.len()
                                                    - parse_input.as_ptr() as usize;
                                                &parse_input[first..end]
                                            })
                                            .collect()
                                    };

                                    // parse_raw_with_stats: native typed-fast-path on
                                    // SysmonJsonParser/SentinelJsonParser captures the
                                    // parser-side allocation savings; other parsers fall
                                    // through to the default lift-from-parse_with_stats.
                                    // Stats fidelity trade-off documented on the trait
                                    // method: drift / per_field_occurrence / skip_reasons
                                    // are empty in the native typed paths.
                                    let events: Vec<graph_hunter_core::RawIngestEvent> =
                                        if sub_chunks.len() > 1 {
                                            use rayon::prelude::*;
                                            let per_chunk: Vec<(Vec<_>, _)> = sub_chunks
                                                .par_iter()
                                                .map(|chunk| parser.parse_raw_with_stats(chunk))
                                                .collect();
                                            let mut flattened: Vec<_> = Vec::new();
                                            for (e, s) in per_chunk {
                                                flattened.extend(e);
                                                if let Some(d) = s.drift {
                                                    drift_accum
                                                        .get_or_insert_with(DriftSnapshot::default)
                                                        .merge(&d);
                                                }
                                            }
                                            flattened
                                        } else {
                                            let (e, s) = parser.parse_raw_with_stats(&parse_input);
                                            if let Some(d) = s.drift {
                                                drift_accum
                                                    .get_or_insert_with(DriftSnapshot::default)
                                                    .merge(&d);
                                            }
                                            e
                                        };
                                    let (ne, nr) = {
                                        let mut graph = bg_session
                                            .graph
                                            .write()
                                            .map_err(|e| format!("Lock poisoned: {}", e))?;
                                        graph
                                            .insert_raw_events(events, Some(&bg_dataset_id))
                                            .map_err(|e| e.to_string())?
                                    };
                                    note_post_finalize_appends(&bg_session, nr);
                                    total_new_entities += ne;
                                    total_new_relations += nr;

                                    let bytes_read = (pos + 1) as u64;
                                    bg_emitter.emit(
                                        INGEST_PROGRESS,
                                        serde_json::json!({
                                            "phase": "parsing",
                                            "bytes_read": bytes_read,
                                            "bytes_total": bytes_total,
                                            "entities": total_new_entities,
                                            "relations": total_new_relations,
                                        }),
                                    );

                                    // Last-resort OOM guard: edges spill to disk but entities/interner
                                    // stay in RAM. Stop only if physical RAM is critically low.
                                    if total_new_relations % (BATCH_LINES * 20) < BATCH_LINES {
                                        #[cfg(target_os = "windows")]
                                        {
                                            use std::mem::MaybeUninit;
                                            #[repr(C)]
                                            struct MEMORYSTATUSEX {
                                                dw_length: u32,
                                                dw_memory_load: u32,
                                                ull_total_phys: u64,
                                                ull_avail_phys: u64,
                                                ull_total_page_file: u64,
                                                ull_avail_page_file: u64,
                                                ull_total_virtual: u64,
                                                ull_avail_virtual: u64,
                                                ull_avail_extended_virtual: u64,
                                            }
                                            unsafe extern "system" {
                                                fn GlobalMemoryStatusEx(
                                                    lp_buffer: *mut MEMORYSTATUSEX,
                                                ) -> i32;
                                            }
                                            let mut mem_info =
                                                MaybeUninit::<MEMORYSTATUSEX>::zeroed();
                                            unsafe {
                                                let p = mem_info.as_mut_ptr();
                                                (*p).dw_length =
                                                    std::mem::size_of::<MEMORYSTATUSEX>() as u32;
                                                if GlobalMemoryStatusEx(p) != 0 {
                                                    let avail_mb =
                                                        (*p).ull_avail_phys / (1024 * 1024);
                                                    if avail_mb < CRITICAL_MEMORY_MB {
                                                        tracing::warn!(
                                                            "INGEST: Critically low memory ({} MB free), stopping to prevent crash",
                                                            avail_mb
                                                        );
                                                        stopped_early = true;
                                                        break;
                                                    }
                                                }
                                            }
                                        }
                                    }

                                    batch_start = pos + 1;
                                    lines_in_batch = 0;
                                }
                            }

                            // Final batch (remaining lines after last newline).
                            // Skip when we stopped early — the remaining data could
                            // be gigabytes and would OOM.
                            if !stopped_early && batch_start < raw.len() {
                                let batch_bytes = &raw[batch_start..];
                                let batch_str = String::from_utf8_lossy(batch_bytes);
                                if !batch_str.trim().is_empty() {
                                    let (events, final_stats) =
                                        if let Some(ref hdr) = last_fields_header {
                                            if !batch_str.contains("#Fields:") {
                                                let with_header = format!("{}\n{}", hdr, batch_str);
                                                parser.parse_raw_with_stats(&with_header)
                                            } else {
                                                parser.parse_raw_with_stats(&batch_str)
                                            }
                                        } else {
                                            parser.parse_raw_with_stats(&batch_str)
                                        };
                                    if let Some(d) = final_stats.drift {
                                        drift_accum
                                            .get_or_insert_with(DriftSnapshot::default)
                                            .merge(&d);
                                    }
                                    let (ne, nr) = {
                                        let mut graph = bg_session
                                            .graph
                                            .write()
                                            .map_err(|e| format!("Lock poisoned: {}", e))?;
                                        graph
                                            .insert_raw_events(events, Some(&bg_dataset_id))
                                            .map_err(|e| e.to_string())?
                                    };
                                    note_post_finalize_appends(&bg_session, nr);
                                    total_new_entities += ne;
                                    total_new_relations += nr;
                                }
                            }

                            Ok((total_new_entities, total_new_relations, drift_accum))
                        } else {
                            // ── JSON array / small file: memory-mapped parse + insert ──
                            let file = std::fs::File::open(&bg_path)
                                .map_err(|e| format!("Failed to open file '{}': {}", bg_path, e))?;
                            let mmap = unsafe { memmap2::Mmap::map(&file) }
                                .map_err(|e| format!("Failed to mmap file '{}': {}", bg_path, e))?;
                            graph_hunter_core::mmap_advise::try_hugepages(&mmap);
                            let contents = std::str::from_utf8(&mmap)
                                .map_err(|e| format!("File is not valid UTF-8: {}", e))?;

                            bg_emitter.emit(
                                INGEST_PROGRESS,
                                serde_json::json!({
                                    "phase": "parsing",
                                    "bytes_read": bytes_total,
                                    "bytes_total": bytes_total,
                                    "entities": 0,
                                    "relations": 0,
                                }),
                            );

                            tracing::info!(
                                "INGEST: parsing {} bytes as {}",
                                contents.len(),
                                resolved
                            );
                            let (events, stats) = parser.parse_raw_with_stats(contents);
                            tracing::info!("INGEST: parsed {} events", events.len());

                            let (ne, nr) = {
                                let mut graph = bg_session
                                    .graph
                                    .write()
                                    .map_err(|e| format!("Lock poisoned: {}", e))?;
                                graph
                                    .insert_raw_events(events, Some(&bg_dataset_id))
                                    .map_err(|e| e.to_string())?
                            };
                            // Guard dropped above before noting appends —
                            // note_post_finalize_appends re-locks graph.read()
                            // and would self-deadlock under a held write guard.
                            note_post_finalize_appends(&bg_session, nr);
                            tracing::info!("INGEST: inserted ({}, {})", ne, nr);
                            Ok((ne, nr, stats.drift))
                        }
                    })();

                match ingest_result {
                    Ok((new_entities, new_relations, drift)) => {
                        if let Some(ref d) = drift {
                            bg_api.record_drift(&bg_dataset_id, d);
                        }
                        bg_emitter.emit(
                            INGEST_PROGRESS,
                            serde_json::json!({
                                "phase": "scoring",
                                "bytes_read": bytes_total,
                                "bytes_total": bytes_total,
                                "entities": new_entities,
                                "relations": new_relations,
                            }),
                        );

                        bg_session.set_phase(crate::state::SessionPhase::Finalizing);

                        {
                            let mut graph = match bg_session.graph.write() {
                                Ok(g) => g,
                                Err(e) => {
                                    bg_session.set_phase(SessionPhase::Ready);
                                    bg_emitter.emit(
                                        INGEST_ERROR,
                                        serde_json::to_value(&IngestError {
                                            job_id: bg_job_id,
                                            dataset_id: bg_dataset_id,
                                            error: format!("Lock poisoned during scoring: {}", e),
                                        })
                                        .unwrap_or_default(),
                                    );
                                    return;
                                }
                            };
                            if let Err(e) = run_scoring_adaptive(&mut graph) {
                                tracing::warn!("INGEST: scoring failed: {}", e);
                            }
                        }

                        if let Ok(mut datasets) = bg_session.datasets.write() {
                            if let Some(ds) = datasets.iter_mut().find(|d| d.id == bg_dataset_id) {
                                ds.entity_count = new_entities;
                                ds.relation_count = new_relations;
                            }
                        }

                        let (total_entities, total_relations, warnings) = bg_session
                            .graph
                            .read()
                            .map(|g| {
                                let warnings = compute_ingest_warnings(&g);
                                (g.entity_count(), g.relation_count(), warnings)
                            })
                            .unwrap_or((0, 0, Vec::new()));

                        bg_session.set_phase(crate::state::SessionPhase::Ready);

                        bg_emitter.emit(
                            INGEST_COMPLETE,
                            serde_json::to_value(&IngestComplete {
                                job_id: bg_job_id,
                                dataset_id: bg_dataset_id,
                                result: LoadResult {
                                    new_entities,
                                    new_relations,
                                    total_entities,
                                    total_relations,
                                    zero_triples: new_entities == 0 && new_relations == 0,
                                    ingest_stats: None,
                                    warnings,
                                },
                            })
                            .unwrap_or_default(),
                        );
                    }
                    Err(e) => {
                        restore_huntable_phase_after_ingest_failure(&bg_session);
                        bg_emitter.emit(
                            INGEST_ERROR,
                            serde_json::to_value(&IngestError {
                                job_id: bg_job_id,
                                dataset_id: bg_dataset_id,
                                error: e,
                            })
                            .unwrap_or_default(),
                        );
                    }
                }
            })); // end catch_unwind

            if let Err(panic_info) = result {
                restore_huntable_phase_after_ingest_failure(&panic_session);
                let msg = if let Some(s) = panic_info.downcast_ref::<&str>() {
                    s.to_string()
                } else if let Some(s) = panic_info.downcast_ref::<String>() {
                    s.clone()
                } else {
                    "Unknown panic during ingestion".to_string()
                };
                panic_emitter.emit(
                    INGEST_ERROR,
                    serde_json::to_value(&IngestError {
                        job_id: panic_job_id,
                        dataset_id: panic_dataset_id,
                        error: format!("Internal error: {}", msg),
                    })
                    .unwrap_or_default(),
                );
            }
        });

        Ok(result_to_return)
    }
}

// Keep LogParser in scope so `parser.parse(...)` resolves. Used only to
// satisfy the trait call — not called directly here.
#[allow(dead_code)]
fn _ensure_logparser_imported() {
    let _: Option<&dyn LogParser> = None;
}

// Keep Arc reachable for clippy when the signatures need it.
#[allow(dead_code)]
fn _ensure_arc_imported() -> Option<Arc<u8>> {
    None
}

/// Determines which phase to restore after a synchronous ingest re-finalizes.
/// If the session was in LiveTail (live streaming active), we must not clobber
/// that — restore LiveTail. For any other entry phase, restore Ready.
fn resume_phase_after_finalize(
    prior: crate::state::SessionPhase,
) -> crate::state::SessionPhase {
    match prior {
        crate::state::SessionPhase::LiveTail => crate::state::SessionPhase::LiveTail,
        _ => crate::state::SessionPhase::Ready,
    }
}

/// RAII guard that restores the session phase on scope exit (success, `?`-error,
/// or panic unwind), so a failed or short-circuited sync ingest can never strand
/// the session in `Finalizing` (which would silently reject all future hunts with
/// a 409 and leave the session unrecoverable without a restart).
///
/// Usage: set the session to `Finalizing` first, then immediately construct this
/// guard with the phase to resume. On any exit path — normal return, early `?`,
/// or panic — `Drop` fires and calls `session.set_phase(resume)`.
///
/// Stores an `Arc<Session>` rather than a borrow to sidestep lifetime entanglement
/// with the caller's `Arc<Session>` local and to make the guard `Send`-compatible
/// for future async use. The clone is a single atomic ref-count bump.
struct FinalizePhaseGuard {
    session: Arc<Session>,
    resume: crate::state::SessionPhase,
}

impl Drop for FinalizePhaseGuard {
    fn drop(&mut self) {
        self.session.set_phase(self.resume);
    }
}

#[cfg(test)]
mod resume_phase_tests {
    use super::*;

    #[test]
    fn resume_phase_preserves_live_tail_else_ready() {
        use crate::state::SessionPhase::*;
        assert_eq!(resume_phase_after_finalize(LiveTail), LiveTail);
        assert_eq!(resume_phase_after_finalize(Ready), Ready);
        assert_eq!(resume_phase_after_finalize(Loading), Ready);
        assert_eq!(resume_phase_after_finalize(Finalizing), Ready);
    }

    /// Proves that `FinalizePhaseGuard` restores the session phase on ANY exit
    /// path — including an early return that bypasses the happy-path tail.
    ///
    /// This is the regression guard for the C5 bug: before the RAII fix, an
    /// early `?`-return between `set_phase(Finalizing)` and the trailing
    /// `set_phase(resume_phase)` would strand the session in `Finalizing`
    /// forever, silently rejecting all subsequent hunts with a 409.
    #[test]
    fn finalize_guard_restores_phase_on_early_exit() {
        use crate::state::SessionPhase;

        let session = Arc::new(Session::new("guard-test", "guard-test", GraphHunter::new(), 0));
        session.set_phase(SessionPhase::Ready);

        // Simulate the ingest preamble: set Finalizing, create the guard.
        let resume = resume_phase_after_finalize(session.phase());
        session.set_phase(SessionPhase::Finalizing);
        assert_eq!(session.phase(), SessionPhase::Finalizing);

        // Enter a block that creates the guard and then "early-exits" without
        // reaching a normal success path. The closure returns an Err, which
        // causes the guard to be dropped when the block scope ends.
        let result: Result<(), &str> = (|| {
            let _guard = FinalizePhaseGuard { session: Arc::clone(&session), resume };
            // Simulate a mid-ingest error that would have `?`-returned in
            // the real load_data / ingest_siem / load_data_with_config.
            return Err("simulated lock-poisoned error");
            #[allow(unreachable_code)]
            Ok(())
        })();

        assert!(result.is_err(), "closure must return Err to simulate early exit");
        // The critical assertion: the session must NOT be stranded in Finalizing.
        assert_ne!(
            session.phase(),
            SessionPhase::Finalizing,
            "session must not be stranded in Finalizing after early exit"
        );
        assert_eq!(
            session.phase(),
            SessionPhase::Ready,
            "guard must restore Ready when entry phase was Ready"
        );
    }
}

#[cfg(test)]
mod sanitize_tests {
    use super::*;
    use graph_hunter_core::FieldMapping;

    fn mk(raw: &str, role: FieldRole, entity: Option<&str>) -> FieldMapping {
        FieldMapping {
            raw_name: raw.to_string(),
            role,
            entity_type: entity.map(|s| s.to_string()),
            timestamp_format: None,
            locale: None,
        }
    }

    #[test]
    fn time_ignore_upgrades_to_metadata() {
        let mut cfg = FieldConfig {
            mappings: vec![mk("TIME", FieldRole::Ignore, None)],
        };
        let fixed = sanitize_field_config(&mut cfg);
        assert_eq!(fixed, 1);
        assert!(matches!(cfg.mappings[0].role, FieldRole::Metadata));
    }

    #[test]
    fn severity_node_demoted_to_metadata() {
        let mut cfg = FieldConfig {
            mappings: vec![mk("severity", FieldRole::Node, Some("Severity"))],
        };
        let fixed = sanitize_field_config(&mut cfg);
        assert_eq!(fixed, 1);
        assert!(matches!(cfg.mappings[0].role, FieldRole::Metadata));
        assert!(cfg.mappings[0].entity_type.is_none());
    }

    #[test]
    fn non_skip_canonical_untouched() {
        let mut cfg = FieldConfig {
            mappings: vec![mk("user", FieldRole::Node, Some("User"))],
        };
        let fixed = sanitize_field_config(&mut cfg);
        assert_eq!(fixed, 0);
        assert!(matches!(cfg.mappings[0].role, FieldRole::Node));
    }

    #[test]
    fn non_canonical_field_untouched() {
        let mut cfg = FieldConfig {
            mappings: vec![mk("custom_column", FieldRole::Ignore, None)],
        };
        let fixed = sanitize_field_config(&mut cfg);
        assert_eq!(fixed, 0);
        assert!(matches!(cfg.mappings[0].role, FieldRole::Ignore));
    }
}
