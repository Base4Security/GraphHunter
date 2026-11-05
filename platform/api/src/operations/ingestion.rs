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

use graph_hunter_canonical::ProvenanceCtx;
use graph_hunter_core::drift::DriftSnapshot;
use graph_hunter_core::{
    ConfigurableParser, EntityType, FieldConfig, FieldMapping, FieldRole, GenericParser,
    GraphHunter, LogParser,
};
use graph_hunter_parsers::{extract_fields_header, haproxy_iso_date};
use uuid::Uuid;

use crate::dto::ingestion::{
    DetectedField, IngestComplete, IngestError, IngestJobStarted, IngestSiemRequest,
    LoadDataRequest, LoadDataStreamingRequest, LoadDataWithConfigRequest, LoadResult,
    PcapPreviewRequest, PcapPreviewResult, PreviewIngestRequest, PreviewIngestResult,
};
use crate::events::events::{INGEST_COMPLETE, INGEST_ERROR, INGEST_PROGRESS};
use crate::evtx::{evtx_preview_sample, evtx_to_sysmon_ndjson, file_looks_like_evtx, path_is_evtx};
use crate::format_registry::{make_parser_for_format, resolve_format, rich_preview_for_format};
use crate::paths::PathPolicy;
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

/// Record a failed `ingest_siem` pull against the per-source breaker
/// (GRAPHHUNTER_SOURCE_COVERAGE gated; no-op with the flag off). Called at
/// every fetch-failure exit point (task join error and upstream query
/// error, for both Sentinel and Elastic) so PROBE-EVERY-CALL holds: this
/// one-shot pull never skips on `is_open` (see `record_siem_outcome`'s doc
/// comment), it only ever attempts and records the outcome. `window_end_ts`
/// is `now` — a failed pull has no parsed events to derive a watermark from.
fn record_siem_failure(session: &Session, source_id: &str) {
    if !crate::coverage::source_coverage_enabled() {
        return;
    }
    if let Ok(mut sc) = session.source_coverage.write() {
        crate::coverage::record_siem_outcome(
            &mut sc,
            source_id,
            false,
            now_secs(),
            SIEM_BREAKER_MAX_FAILURES,
        );
    }
}

/// Best-effort append of a journal batch for one ingest call, shared by
/// `load_data` and `load_data_with_config`. Resolves the on-disk journal
/// directory as a sibling of the session data dir (`<data_dir>/GraphHunter/
/// journal`) — mirrors how the DLQ store lives outside any single
/// `Session`, since `Session` itself carries no directory of its own.
/// Any failure along the way (dir resolution, store open, append) only
/// `tracing::warn!`s: the journal is additive and must never abort
/// ingestion (design spec §9, steps 4-9 run before the graph insert at
/// step 9, but a journaling failure is not an ingest failure).
///
/// A no-op returning `None` when `GRAPHHUNTER_JOURNAL` is off. Otherwise
/// returns each event's idempotency key when `GRAPHHUNTER_GRAPHDELTA` is
/// also on — the keys `insert_journaled` dedups on — and `None` when the
/// batch should be inserted directly. Keys are produced even if the journal
/// directory can't be opened, matching the old per-envelope apply path,
/// which never depended on the write succeeding.
fn journal_batch_best_effort(
    dataset_id: &str,
    source_kind: &str,
    parser_name: &str,
    events: &[graph_hunter_core::parser::RawIngestEvent],
    skipped_samples: &[(String, String)],
) -> Option<Vec<u64>> {
    if !crate::journal::journal_enabled() {
        return None;
    }
    let store = match dirs::data_dir() {
        Some(d) => {
            match crate::journal::JournalStore::open(d.join("GraphHunter").join("journal")) {
                Ok(s) => Some(s),
                Err(e) => {
                    tracing::warn!(target: "journal", error = %e, "journal open failed; continuing");
                    None
                }
            }
        }
        None => {
            tracing::warn!(
                target: "journal",
                "could not resolve app data directory; journal append skipped"
            );
            None
        }
    };
    let now_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0);
    let (keys, err) = crate::journal::journal_batch_keyed(
        store.as_ref(),
        dataset_id,
        source_kind,
        dataset_id,
        parser_name,
        events,
        skipped_samples,
        now_ms,
    );
    if let Some(e) = err {
        tracing::warn!(target: "journal", error = %e, "journal append failed; continuing");
    }
    crate::journal::graphdelta_enabled().then_some(keys)
}

/// Graph insert for a batch that went through `journal_batch_best_effort`:
/// idempotent on event identity when it returned keys (GRAPHHUNTER_GRAPHDELTA,
/// so a crash-and-reingest cannot duplicate edges), direct otherwise.
fn insert_journaled(
    graph: &mut GraphHunter,
    events: Vec<graph_hunter_core::parser::RawIngestEvent>,
    keys: Option<Vec<u64>>,
    dataset_id: Option<&str>,
) -> Result<(usize, usize), graph_hunter_core::GraphError> {
    match keys {
        Some(keys) => graph.insert_raw_events_idempotent(events, &keys, dataset_id),
        None => graph.insert_raw_events(events, dataset_id),
    }
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
/// Only reachable on Windows, where `memory_snapshot_mb` reads
/// `GlobalMemoryStatusEx`; elsewhere that returns `None` and the guard never
/// fires, but the comparison still compiles, so the constant is not gated.
const CRITICAL_MEMORY_MB: u64 = 256;

/// Growth in this process's own working set, since the ingest began, above
/// which the ingest is treated as the *cause* of the machine's memory
/// pressure.
///
/// The guard needs both readings. A machine low on RAM says nothing about
/// who is responsible, and aborting on that alone discards the operator's
/// data to make room for someone else's browser tab. Measured on a 15 GB
/// HTTP access log, an ingest's resident set *falls* while it runs — edges
/// spill to disk and parsed batches are freed, so at 1.1M relations RSS had
/// dropped from 585 MB to 391 MB and free RAM had risen — while the machine
/// idled only 150-300 MB above the critical line. Availability alone was
/// therefore firing on ambient pressure, never on this ingest.
/// Share of total physical RAM this ingest's own commit must have grown by
/// before it is considered the cause of the machine's pressure. A fraction
/// rather than a constant so the same build behaves sanely on a 16 GB
/// laptop and a 256 GB server. Measured: a 2 GB HTTP log ingests with about
/// 1.6 GB of commit growth — 10% of a 16 GB machine — and the curve
/// flattens from there, so half of RAM is far above anything a healthy
/// ingest reaches and still well under the point of no return.
const SELF_GROWTH_CRITICAL_FRACTION: u64 = 2; // total_phys / 2

/// `(free physical RAM, this process's private commit, total physical RAM)`
/// in MB.
///
/// `None` when the platform offers no cheap reading; callers must then let
/// the ingest proceed rather than abort on a measurement they do not have.
#[cfg(target_os = "windows")]
fn memory_snapshot_mb() -> Option<(u64, u64, u64)> {
    use std::mem::MaybeUninit;

    #[repr(C)]
    struct MemoryStatusEx {
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

    #[repr(C)]
    struct ProcessMemoryCounters {
        cb: u32,
        page_fault_count: u32,
        peak_working_set_size: usize,
        working_set_size: usize,
        quota_peak_paged_pool_usage: usize,
        quota_paged_pool_usage: usize,
        quota_peak_non_paged_pool_usage: usize,
        quota_non_paged_pool_usage: usize,
        pagefile_usage: usize,
        peak_pagefile_usage: usize,
    }

    unsafe extern "system" {
        fn GlobalMemoryStatusEx(lp_buffer: *mut MemoryStatusEx) -> i32;
        fn K32GetProcessMemoryInfo(
            process: isize,
            counters: *mut ProcessMemoryCounters,
            cb: u32,
        ) -> i32;
        fn GetCurrentProcess() -> isize;
    }

    unsafe {
        let mut status = MaybeUninit::<MemoryStatusEx>::zeroed();
        let sp = status.as_mut_ptr();
        (*sp).dw_length = std::mem::size_of::<MemoryStatusEx>() as u32;
        if GlobalMemoryStatusEx(sp) == 0 {
            return None;
        }
        let avail_mb = (*sp).ull_avail_phys / (1024 * 1024);
        let total_phys_mb = (*sp).ull_total_phys / (1024 * 1024);

        let mut counters = MaybeUninit::<ProcessMemoryCounters>::zeroed();
        let cp = counters.as_mut_ptr();
        (*cp).cb = std::mem::size_of::<ProcessMemoryCounters>() as u32;
        if K32GetProcessMemoryInfo(GetCurrentProcess(), cp, (*cp).cb) == 0 {
            return None;
        }
        // `pagefile_usage` is private commit: memory this process actually
        // demands. `working_set_size` would also count the resident pages of
        // the mmap'd input, which are file-backed and reclaimable — on a
        // 2 GB log that inflated the reading by ~1.4 GB and made the ingest
        // look like the culprit for its own input file.
        let commit_mb = ((*cp).pagefile_usage / (1024 * 1024)) as u64;

        Some((avail_mb, commit_mb, total_phys_mb))
    }
}

#[cfg(not(target_os = "windows"))]
fn memory_snapshot_mb() -> Option<(u64, u64, u64)> {
    None
}

const LARGE_FILE_THRESHOLD: u64 = 10 * 1024 * 1024;
const PREVIEW_READ_SIZE: usize = 64 * 1024;
const EVTX_PREVIEW_SAMPLE_SIZE: usize = 1000;
/// Upper bound for the whole-file (non-line-delimited) ingest branch. That
/// branch parses the entire file at once and peaks near 8× the input size
/// in transient `Vec<ParsedTriple>` + `Vec<RawIngestEvent>`, so a file past
/// this size is rejected with a clear error instead of aborting the process
/// on a multi-GB allocation. Line-delimited formats are unaffected — they
/// stream in batches and never hit this branch.
const WHOLE_FILE_PARSE_LIMIT: u64 = 512 * 1024 * 1024;

/// Consecutive-failure threshold before `ingest_siem`'s per-source breaker
/// opens (a reporting signal only — see `record_siem_outcome`'s doc comment
/// for why a one-shot pull must never skip on `is_open`).
const SIEM_BREAKER_MAX_FAILURES: u32 = 5;

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
            // 2026-07-24 (MDE node-explosion fix): the canonical Skip
            // verdict outranks the name-heuristic suggestion. Ports,
            // command lines, timestamps, actions and severities are
            // structural metadata — the heuristic used to promote them
            // anyway ("Remote Port" → IP, "Process Command Line" →
            // Process), minting one junk node per unique value: a 13K-row
            // MDE timeline export produced 26K entities and a ~7-minute
            // "hung" ingest in the UI.
            let canonical_skip = fi
                .canonical_target
                .as_deref()
                .map(|ct| GenericParser::canonical_to_entity_type(ct) == "Skip")
                .unwrap_or(false);
            let mut suggested = if canonical_skip {
                "Skip".to_string()
            } else {
                match (fi.suggested_entity_type.clone(), canonical_default) {
                    (Some(t), _) => t,
                    (None, _) if is_timestamp => "Skip".to_string(),
                    (None, Some(canonical)) => canonical,
                    (None, None) => "Skip".to_string(),
                }
            };
            // Same fix, value tier: a name-heuristic match on a
            // timestamp-valued column ("Process Creation Time" → Process)
            // would create one entity per timestamp value. Only the
            // name tier can make this mistake — the value tier already
            // classifies timestamps as non-entities.
            if suggested != "Skip"
                && fi.suggestion_source.as_deref() == Some("name")
                && graph_hunter_core::field_preview::values_look_like_timestamps(&fi.sample_values)
            {
                suggested = "Skip".to_string();
            }
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
            if let Some(dest_entity) = graph.get_entity(dest_str)
                && matches!(dest_entity.entity_type, EntityType::IP)
            {
                ip_to_users
                    .entry(dest_entity.id.as_str())
                    .or_default()
                    .insert(user_id);
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
    pub fn preview_ingest(
        &self,
        req: PreviewIngestRequest,
        policy: &PathPolicy,
    ) -> ApiResult<PreviewIngestResult> {
        let checked = policy.resolve(&req.path)?;
        let path = checked.as_path().to_string_lossy().to_string();
        let use_evtx = req.format.to_lowercase() == "evtx"
            || path_is_evtx(&path)
            || (req.format.to_lowercase() == "auto" && file_looks_like_evtx(&path));
        let (contents, resolved) = if use_evtx {
            let contents =
                evtx_preview_sample(&path, EVTX_PREVIEW_SAMPLE_SIZE).map_err(ApiError::Io)?;
            (contents, "sysmon".to_string())
        } else {
            let file_size = std::fs::metadata(&path).map(|m| m.len()).unwrap_or(0);
            let contents = if file_size > LARGE_FILE_THRESHOLD {
                let mut file = std::fs::File::open(&path)
                    .map_err(|e| ApiError::Io(format!("open '{}': {e}", checked.display_hint())))?;
                let mut buf = vec![0u8; PREVIEW_READ_SIZE];
                let n = std::io::Read::read(&mut file, &mut buf)
                    .map_err(|e| ApiError::Io(format!("read: {e}")))?;
                String::from_utf8_lossy(&buf[..n]).to_string()
            } else {
                std::fs::read_to_string(&path)
                    .map_err(|e| ApiError::Io(format!("read '{}': {e}", checked.display_hint())))?
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

    /// Snapshot of one background ingest job.
    ///
    /// `NotFound` covers three cases a client cannot distinguish and does
    /// not need to: never existed, evicted from the bounded store, or the
    /// process restarted (which also killed the detached ingest thread).
    pub fn ingest_job_status(
        &self,
        job_id: &str,
    ) -> ApiResult<crate::dto::ingestion::IngestJobSnapshot> {
        self.inner
            .ingest_jobs
            .get(job_id)
            .ok_or_else(|| ApiError::NotFound(format!("unknown job_id: {job_id}")))
    }

    /// Recent ingest jobs, most recently updated first. Lets a client
    /// find a job it lost the id for, or spot one stalled by a restart.
    pub fn list_ingest_jobs(
        &self,
        limit: Option<usize>,
    ) -> Vec<crate::dto::ingestion::IngestJobSnapshot> {
        self.inner.ingest_jobs.list(limit.unwrap_or(32).min(64))
    }

    /// PCAP / PCAPNG preview. Reads up to 10K packets and returns a
    /// non-tabular summary (top src/dst IPs, top dst ports, protocol
    /// mix, time span). Stateless — touches no session. Frontend
    /// dispatches by extension; the regular [`Self::preview_ingest`]
    /// path would corrupt the binary file via `read_to_string`.
    pub fn pcap_preview(
        &self,
        req: PcapPreviewRequest,
        policy: &PathPolicy,
    ) -> ApiResult<PcapPreviewResult> {
        let resolved = policy.resolve(&req.path)?;
        crate::pcap_preview::pcap_preview_sample(&resolved.as_path().to_string_lossy())
            .map_err(ApiError::Io)
    }

    /// Read a file from disk, parse it, insert triples into the
    /// resolved session's graph, and run full scoring. Synchronous;
    /// callers in async contexts should `spawn_blocking`.
    /// Note: the file is read *before* the session is resolved, so a
    /// caller with no session still pays a full read and then gets a 400.
    /// Left in this order deliberately — swapping it changes the
    /// failure-attribution ordering the DLQ comment below depends on. The
    /// cost is bounded by [`PathPolicy`]'s size cap.
    pub fn load_data(&self, req: LoadDataRequest, policy: &PathPolicy) -> ApiResult<LoadResult> {
        let resolved = policy.resolve(&req.path)?;
        let path = resolved.as_path().to_string_lossy().to_string();
        let use_evtx = req.format.to_lowercase() == "evtx"
            || path_is_evtx(&path)
            || (req.format.to_lowercase() == "auto" && file_looks_like_evtx(&path));
        let (contents, format_for_parser) = if use_evtx {
            let contents = evtx_to_sysmon_ndjson(&path).map_err(ApiError::Io)?;
            (contents, "generic".to_string())
        } else {
            // `display_hint` is the caller's own string: echoing the
            // canonical absolute path alongside the OS error would be an
            // existence oracle for paths outside the allowed root.
            let contents = std::fs::read_to_string(&path)
                .map_err(|e| ApiError::Io(format!("read '{}': {e}", resolved.display_hint())))?;
            (contents, req.format)
        };

        let session = self.resolve_session(req.session.as_ref())?;

        let dataset_id = Uuid::new_v4().to_string();
        let name = std::path::Path::new(&path)
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
                // The resolved path, not the caller's string: this is the
                // provenance record of what was actually read, and DLQ
                // replay re-opens it later.
                path: Some(path.clone()),
                created_at: now_secs(),
                entity_count: 0,
                relation_count: 0,
                // Persist the auto-built config so DatasetCard's "Schema
                // used" view shows the same mappings the parser actually
                // applied — the analyst can then tweak from a real baseline
                // instead of the empty default.
                field_config: auto_config.clone(),
                ingest_stats: None,
                // Frozen at ingest, mirrors `journaled_parser_name` below:
                // "configurable" when the auto-built config drove the parse,
                // else the resolved format name. Known now (before parsing
                // even runs) since `auto_config.is_some()` already decided
                // which parser will be used.
                parser: Some(if auto_config.is_some() {
                    "configurable".to_string()
                } else {
                    resolved_format.clone()
                }),
                // FROZEN mapping identity, set once here at ingest and never
                // touched again — see `DatasetInfo::mapping_hash`. Computed
                // from the auto-built config directly, independent of the
                // `field_config` field above (which a later mapping-review
                // promotion may overwrite for display purposes).
                mapping_hash: auto_config
                    .as_ref()
                    .map(ProvenanceCtx::mapping_hash_for_config),
            });
        }
        let resume_phase = resume_phase_after_finalize(session.phase());
        session.set_phase(crate::state::SessionPhase::Finalizing);
        let _phase_guard = FinalizePhaseGuard {
            session: Arc::clone(&session),
            resume: resume_phase,
        };
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
            // `used_auto` tells us which parser actually produced `events`:
            // when an auto-built FieldConfig drove a ConfigurableParser,
            // journal/apply that identity instead of the raw format name, so
            // the frozen provenance reflects the real producer (matches the
            // `load_data_with_config` branch below, which always used
            // "configurable").
            let journaled_parser_name = if used_auto {
                "configurable"
            } else {
                resolved_format.as_str()
            };
            // Journal step (4-5 of the 12-step order): must run BEFORE the
            // graph insert below so a crash in between is replayable. Gated
            // behind GRAPHHUNTER_JOURNAL (default off = no-op); failures only
            // warn, never abort ingestion — journaling is additive.
            let journal_keys = journal_batch_best_effort(
                &dataset_id,
                "file",
                journaled_parser_name,
                &events,
                &stats.skipped_samples,
            );
            let (ne, nr) = {
                insert_journaled(&mut graph, events, journal_keys, Some(dataset_id.as_str()))
                    .map_err(|e| ApiError::Internal(e.to_string()))?
            };
            run_full_scoring(&mut graph);
            // An empty ParseStats (rows_seen == 0) means the parser didn't
            // report real stats — treat as "unknown".
            let stats = if stats.rows_seen == 0 {
                None
            } else {
                Some(stats)
            };
            if let Some(s) = stats.as_ref()
                && let Some(d) = s.drift.as_ref()
            {
                self.record_drift(dataset_id.as_str(), d);
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
            stopped_early: false,
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

        // Resolved up front (not after the network fetch below) so a fetch
        // failure still has a session to record the per-source breaker
        // failure against — PROBE-EVERY-CALL (see `record_siem_failure`):
        // every `ingest_siem` call, success or failure, is a probe.
        let session = self.resolve_session(req.session.as_ref())?;

        let (data, source_id) = match source {
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
                let source_id = format!("sentinel:{workspace_id}");
                let res = tokio::task::spawn_blocking(move || {
                    graph_hunter_siem::run_sentinel_query(&workspace_id, &query, auth)
                })
                .await
                .map_err(|e| ApiError::Internal(format!("task join error: {e}")))
                .inspect_err(|_| record_siem_failure(&session, &source_id))?
                .map_err(|e| ApiError::Upstream {
                    service: "sentinel".into(),
                    message: e,
                })
                .inspect_err(|_| record_siem_failure(&session, &source_id))?;
                (res.data, source_id)
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
                let source_id = format!("elastic:{url}");
                let res = tokio::task::spawn_blocking(move || {
                    graph_hunter_siem::run_elastic_query(&url, &index, &query, size, None, auth)
                })
                .await
                .map_err(|e| ApiError::Internal(format!("task join error: {e}")))
                .inspect_err(|_| record_siem_failure(&session, &source_id))?
                .map_err(|e| ApiError::Upstream {
                    service: "elastic".into(),
                    message: e.to_string(),
                })
                .inspect_err(|_| record_siem_failure(&session, &source_id))?;
                (res.data, source_id)
            }
            other => {
                return Err(ApiError::InvalidInput(format!(
                    "unsupported source: '{other}'. Use 'sentinel' or 'elastic'."
                )));
            }
        };

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
                // `make_parser_for_format("sentinel")` below is hardcoded
                // regardless of `source` (see the comment at that call) —
                // "sentinel" is the real frozen parser identity for both
                // the Sentinel and Elastic branches of this op today.
                parser: Some("sentinel".to_string()),
                // No FieldConfig on this path — builtin identity via
                // `parser` above (`builtin:sentinel`) is the frozen
                // mapping identity for this dataset.
                mapping_hash: None,
            });
        }

        let resume_phase = resume_phase_after_finalize(session.phase());
        session.set_phase(crate::state::SessionPhase::Finalizing);
        let _phase_guard = FinalizePhaseGuard {
            session: Arc::clone(&session),
            resume: resume_phase,
        };
        let (new_entities, new_relations, stats, window_end_ts) = {
            let mut graph = session
                .graph
                .write()
                .map_err(|e| ApiError::Internal(format!("graph lock poisoned: {e}")))?;
            let parser = make_parser_for_format("sentinel").map_err(ApiError::InvalidInput)?;
            // RawIngestEvent path — see evtx.rs for the rationale.
            let (events, stats) = parser.parse_raw_with_stats(&data);
            // Coverage window end: the max event timestamp this pull actually
            // covered, or `now` when the pull returned zero events (an empty
            // result is still a covered window, not a blind one).
            let window_end_ts = events
                .iter()
                .map(|e| e.timestamp)
                .max()
                .unwrap_or_else(now_secs);
            // Journal step (4-5 of the 12-step order): must run BEFORE the
            // graph insert below so a crash in between is replayable. Gated
            // behind GRAPHHUNTER_JOURNAL (default off = no-op); failures only
            // warn, never abort ingestion — mirrors the load_data branch.
            // `ingest_siem` is the live Sentinel/Elastic pull path, so wiring
            // this closes the honesty gap: without it the edge-multiplicity
            // dedup only ever applied to file-based ingest, never to the
            // declared "live sync path". `parse_raw_with_stats` (not
            // `parse_raw`) so real skipped samples are journaled alongside
            // the events instead of the previous empty-slice stand-in.
            // `parser_name` is "sentinel" literal (not `source`) because
            // `make_parser_for_format` above is hardcoded to "sentinel"
            // regardless of source — that reflects the actual parser that
            // produced `events`.
            let journal_keys = journal_batch_best_effort(
                &dataset_id,
                "siem",
                "sentinel",
                &events,
                &stats.skipped_samples,
            );
            let (e, r) = {
                insert_journaled(&mut graph, events, journal_keys, Some(dataset_id.as_str()))
                    .map_err(|e| ApiError::Internal(e.to_string()))?
            };
            run_full_scoring(&mut graph);
            (e, r, stats, window_end_ts)
        };
        // The pull (and its parse/insert) reached here without error: record
        // it as covered. PROBE-EVERY-CALL — this also recovers the breaker
        // if prior calls had opened it (see `record_siem_outcome`'s doc
        // comment on why a one-shot pull must never skip on `is_open`).
        if crate::coverage::source_coverage_enabled() {
            let mut sc = session
                .source_coverage
                .write()
                .map_err(|e| ApiError::Internal(format!("source_coverage lock poisoned: {e}")))?;
            crate::coverage::record_siem_outcome(
                &mut sc,
                &source_id,
                true,
                window_end_ts,
                SIEM_BREAKER_MAX_FAILURES,
            );
        }
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

        let zero_triples = stats.rows_seen > 0 && stats.rows_with_triples == 0;
        Ok(LoadResult {
            new_entities,
            new_relations,
            total_entities,
            total_relations,
            zero_triples,
            ingest_stats: Some(stats),
            warnings,
            stopped_early: false,
        })
    }

    /// Load data with an explicit [`FieldConfig`] (user-supplied field
    /// mapping). Replaces `cmd_load_data_with_config` from the Tauri
    /// `graph_ops` module. Synchronous — spawn_blocking at the
    /// caller.
    pub fn load_data_with_config(
        &self,
        req: LoadDataWithConfigRequest,
        policy: &PathPolicy,
    ) -> ApiResult<LoadResult> {
        // Auto-upgrade stale mappings (TIME→Ignore, SEVERITY→Node, etc.)
        // so canonical-Skip fields always land as Metadata regardless of
        // what the persisted FieldConfig said.
        let mut req = req;
        let _upgraded = sanitize_field_config(&mut req.config);

        let resolved = policy.resolve(&req.path)?;
        let path = resolved.as_path().to_string_lossy().to_string();

        // Same EVTX-detection path as load_data.
        let use_evtx = path_is_evtx(&path) || file_looks_like_evtx(&path);
        let contents = if use_evtx {
            evtx_to_sysmon_ndjson(&path).map_err(ApiError::Io)?
        } else {
            std::fs::read_to_string(&path)
                .map_err(|e| ApiError::Io(format!("read '{}': {e}", resolved.display_hint())))?
        };

        let session = self.resolve_session(req.session.as_ref())?;

        let dataset_id = Uuid::new_v4().to_string();
        let name = std::path::Path::new(&path)
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
                // Unused by export's provenance identity when `mapping_hash`
                // is `Some` (always true on this path) — left unset.
                parser: None,
                // FROZEN mapping identity, set once here at ingest and never
                // touched again — see `DatasetInfo::mapping_hash`. A later
                // mapping-review promotion may overwrite `field_config`
                // above for display, but this hash is what export actually
                // stamps into `provenance.mapping_hash`.
                mapping_hash: Some(ProvenanceCtx::mapping_hash_for_config(&req.config)),
            });
        }

        let resume_phase = resume_phase_after_finalize(session.phase());
        session.set_phase(crate::state::SessionPhase::Finalizing);
        let _phase_guard = FinalizePhaseGuard {
            session: Arc::clone(&session),
            resume: resume_phase,
        };
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
                // Journal step (4-5 of the 12-step order): must run BEFORE
                // the graph insert below. Gated behind GRAPHHUNTER_JOURNAL
                // (default off = no-op); failures only warn, never abort
                // ingestion — journaling is additive.
                let journal_keys = journal_batch_best_effort(
                    &dataset_id,
                    "file",
                    "configurable",
                    &events,
                    &stats.skipped_samples,
                );
                let (ne, nr) = {
                    insert_journaled(&mut graph, events, journal_keys, Some(dataset_id.as_str()))
                        .map_err(|e| ApiError::Internal(e.to_string()))?
                };
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

        if let Some(s) = ingest_stats.as_ref()
            && let Some(d) = s.drift.as_ref()
        {
            self.record_drift(dataset_id.as_str(), d);
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
            stopped_early: false,
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
        policy: &PathPolicy,
    ) -> ApiResult<IngestJobStarted> {
        // Containment first: the background thread mmaps this path, and
        // by then there is no caller left to return an error to.
        let checked = policy.resolve(&req.path)?;
        let mut req = req;
        req.path = checked.as_path().to_string_lossy().to_string();

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
            "haproxy",
            "hap",
            "haproxy_http",
            "fortigate",
            "fgt",
            "fortios",
            "fortianalyzer",
            "faz",
            "forti",
            "xml",
        ];
        if !TABULAR_FORMATS.contains(&pre_check.as_str())
            && !crate::ingestors::is_known_streaming_format(&pre_check)
        {
            return Err(ApiError::InvalidInput(format!(
                "Unsupported format: '{}'. Use 'auto', 'evtx', 'pcap', 'sysmon', 'sentinel', 'cognito', 'generic', 'csv', 'iis', 'haproxy', 'fortigate', or 'fortianalyzer'.",
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
                // The resolved format isn't known yet at this point (only
                // determined in the background task below, from a content
                // peek); patched in once that happens.
                parser: None,
                // FROZEN mapping identity, set once here at ingest and
                // never touched again — see `DatasetInfo::mapping_hash`.
                // Only known now if the caller supplied an explicit config
                // upfront; the heuristic auto-config case (no explicit
                // config) is frozen later, in the background task below,
                // BEFORE any event is parsed under it — still "at ingest",
                // never a post-ingest mutation.
                mapping_hash: req
                    .config
                    .as_ref()
                    .map(ProvenanceCtx::mapping_hash_for_config),
            });
        }

        let result_to_return = IngestJobStarted {
            job_id: job_id.clone(),
            dataset_id: dataset_id.clone(),
        };

        // Register before returning, so a client that polls
        // `/ingest/status` the instant it receives the job_id finds it
        // rather than a spurious 404.
        self.inner.ingest_jobs.register(&job_id, &dataset_id);

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
        // Wrap, don't replace: the scoped emitter tees the ingest
        // lifecycle into the job store *and* forwards every event to the
        // process emitter, so the desktop webview keeps receiving exactly
        // what it did before. Per-job because `ingest-progress` payloads
        // carry no job_id — a single global recorder could not attribute
        // events when two ingests run at once. Since this same handle is
        // what `IngestContext.emitter` carries, every progress site is
        // captured (including the EVTX / Zeek / PCAP registry ingestors)
        // without editing a single emit call.
        let bg_emitter: Arc<dyn EventEmitter> = Arc::new(crate::jobs::JobScopedEmitter::new(
            job_id.clone(),
            self.inner.ingest_jobs.clone(),
            Arc::clone(self.emitter()),
        ));
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
                if let Some(ingestor) = crate::ingestors::resolve_ingestor(&bg_path, &bg_format) {
                    // Freeze the resolved ingestor identity onto the
                    // dataset BEFORE any event is parsed under it — this
                    // registry branch (EVTX/PCAP/Zeek/Suricata/Netflow)
                    // used to `return` without ever setting `ds.parser`,
                    // leaving these datasets stamped `builtin:unknown` at
                    // export instead of e.g. `builtin:evtx`. Mirrors the
                    // `ds.parser = Some(resolved.clone())` patch below for
                    // the tabular path.
                    if let Ok(mut datasets) = bg_session.datasets.write()
                        && let Some(ds) = datasets.iter_mut().find(|d| d.id == bg_dataset_id)
                    {
                        ds.parser = Some(ingestor.name().to_string());
                    }
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
                                        stopped_early: false,
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
                // How this format may be cut into batches is declared by the
                // registry next to its parser (`FormatDescriptor::stream`),
                // not decided here.
                //
                // This used to be a hard-coded allowlist of format names. It
                // fell behind the registry: `csv` was never in it, so every
                // CSV larger than WHOLE_FILE_PARSE_LIMIT was rejected with
                // "this format isn't line-delimited so it can't be streamed"
                // — by an error message that, in the same breath, suggested
                // converting the file to CSV. A list that has to be updated
                // by hand every time a format is added will drift again, so
                // the fact now lives with the format.
                let stream_mode = crate::format_registry::stream_mode_for(&resolved, trimmed_peek);
                // Headed formats (CSV/TSV) repeat their column header into
                // every batch — see `table_header` below.
                let is_headed = crate::format_registry::format_is_headed(&resolved);
                let is_line_based = stream_mode.is_streamable();

                // The date-range filter below probes byte 0 for an ISO date.
                // HAProxy lines start with the client `ip:port` and carry the
                // date in a bracketed `DD/Mon/YYYY` second token, so the probe
                // never matched and the range was silently ignored. Resolved
                // once here rather than per line — this loop runs tens of
                // millions of times on the logs that motivated the fix.
                let is_haproxy = resolved == "haproxy";

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
                // Also freeze the resolved parser/format name now that it's
                // known (it wasn't yet at the synchronous push above) —
                // export's builtin-parser provenance identity reads this
                // for datasets that end up with no `field_config`.
                if let Ok(mut datasets) = bg_session.datasets.write()
                    && let Some(ds) = datasets.iter_mut().find(|d| d.id == bg_dataset_id)
                {
                    if let Some(cfg) = &auto_config {
                        ds.field_config = Some(cfg.clone());
                        // FROZEN mapping identity, set once here
                        // (still before any event is parsed under this
                        // dataset — see `DatasetInfo::mapping_hash`)
                        // and never touched again after this point.
                        ds.mapping_hash = Some(ProvenanceCtx::mapping_hash_for_config(cfg));
                    }
                    ds.parser = Some(resolved.clone());
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
                // (new entities, new relations, drift, truncation as (byte offset, avail MB, growth MB)).
                type IngestOutcome = (usize, usize, Option<DriftSnapshot>, Option<(u64, u64, u64)>);
                let ingest_result: Result<IngestOutcome, String> =
                    (|| -> Result<IngestOutcome, String> {
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
                            // Set past the header record below, once known.
                            let mut batch_start: usize;
                            let mut stopped_early = false;
                            // Baseline for the self-growth half of the OOM
                            // guard: only growth *since this ingest started*
                            // can be attributed to it.
                            let commit_baseline_mb = memory_snapshot_mb()
                                .map(|(_, commit, _)| commit)
                                .unwrap_or(0);
                            // Set when the guard fires, so the truncation can
                            // be reported instead of inferred from a bool.
                            let mut truncated_at: Option<(usize, u64, u64)> = None;
                            let mut drift_accum: Option<DriftSnapshot> = None;

                            let mut last_fields_header: Option<String> = iis_fields_header.clone();

                            // Column header of a headed format (CSV/TSV),
                            // taken from the first record and repeated into
                            // every batch — batch 1 included, which is why
                            // the scan below starts AFTER the header record.
                            //
                            // Without this, a batch hands the parser a
                            // headerless block: it takes the first *data* row
                            // as the column names and every subsequent row
                            // maps onto the wrong fields. Nothing errors —
                            // the ingest just lands as near-zero triples,
                            // which is the failure mode that is hardest to
                            // notice on a multi-GB file. Batch 1 used to rely
                            // on carrying the header verbatim, but it is then
                            // split across rayon workers and only the first
                            // sub-chunk saw it: on a 1M-row Auth0 CSV the
                            // first batch yielded 19k events instead of 230k.
                            let (table_header, header_end): (Option<String>, usize) = if is_headed {
                                let mut hs = crate::record_scan::RecordScanner::new(stream_mode);
                                match hs.next_record_end(raw, 0) {
                                    Some(end) => (
                                        Some(
                                            String::from_utf8_lossy(&raw[..end])
                                                .trim_end_matches('\r')
                                                .to_string(),
                                        ),
                                        end + 1,
                                    ),
                                    None => (None, 0),
                                }
                            } else {
                                (None, 0)
                            };
                            batch_start = header_end;

                            // Record boundaries honour the format's stream
                            // mode: for `Quoted` a newline inside a quoted
                            // value does not end a record, so a multi-line
                            // FortiWeb attack payload stays one record
                            // instead of being shredded into fragments.
                            let mut scanner = crate::record_scan::RecordScanner::new(stream_mode);

                            let mut search_offset = header_end;
                            while let Some(pos) = scanner.next_record_end(raw, search_offset) {
                                search_offset = pos + 1;

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
                                    // Two date shapes: ISO at byte 0 (IIS, CSV)
                                    // and HAProxy's bracketed `DD/Mon/YYYY`,
                                    // normalized to ISO so the same byte
                                    // comparison works. A line we cannot date
                                    // is left IN, never dropped: guessing here
                                    // would silently shrink the ingest, which
                                    // is the failure mode this filter already
                                    // had for HAProxy.
                                    let line_date: Option<[u8; 10]> = if is_haproxy {
                                        haproxy_iso_date(&raw[line_start..pos])
                                    } else {
                                        let first_byte =
                                            raw.get(line_start).copied().unwrap_or(b'#');
                                        if first_byte.is_ascii_digit() && pos >= line_start + 10 {
                                            raw[line_start..line_start + 10].try_into().ok()
                                        } else {
                                            None
                                        }
                                    };

                                    if let Some(ref d) = line_date {
                                        if let Some(ref from) = date_from_bytes
                                            && d.as_slice() < from.as_slice()
                                        {
                                            continue;
                                        }
                                        if let Some(ref to) = date_to_bytes
                                            && d.as_slice() > to.as_slice()
                                        {
                                            continue;
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

                                    // The header this batch must carry, if
                                    // any. Two sources, never both: IIS reads
                                    // a `#Fields:` directive that can recur
                                    // mid-file, a headed tabular format
                                    // repeats its first row.
                                    let header_for_batch: Option<&str> = if let Some(ref hdr) =
                                        last_fields_header
                                    {
                                        if memchr::memmem::find(batch_bytes, b"#Fields:").is_none()
                                        {
                                            Some(hdr.as_str())
                                        } else {
                                            None
                                        }
                                    } else if batch_start > 0 {
                                        table_header.as_deref()
                                    } else {
                                        None
                                    };

                                    // Sub-chunks are cut at record
                                    // boundaries, not at every newline: the
                                    // `lines()` split this replaced could
                                    // hand one worker the first half of a
                                    // multi-line quoted value and the next
                                    // worker the rest.
                                    //
                                    // The header goes on EVERY chunk, not
                                    // just the first. Each chunk is parsed by
                                    // an independent `parse_raw_with_stats`
                                    // call, so a header that reached only
                                    // chunk 0 left the other workers mapping
                                    // columns by position against the wrong
                                    // names.
                                    let num_chunks = rayon::current_num_threads().max(1);
                                    let sub_chunks: Vec<std::borrow::Cow<'_, str>> =
                                        crate::record_scan::split_records(
                                            &batch_str,
                                            stream_mode,
                                            num_chunks,
                                        )
                                        .into_iter()
                                        .map(|c| match header_for_batch {
                                            Some(h) => {
                                                std::borrow::Cow::Owned(format!("{}\n{}", h, c))
                                            }
                                            None => std::borrow::Cow::Borrowed(c),
                                        })
                                        .collect();

                                    // parse_raw_with_stats: native typed-fast-path on
                                    // SysmonJsonParser/SentinelJsonParser captures the
                                    // parser-side allocation savings; other parsers fall
                                    // through to the default lift-from-parse_with_stats.
                                    // Stats fidelity trade-off documented on the trait
                                    // method: drift / per_field_occurrence / skip_reasons
                                    // are empty in the native typed paths.
                                    // Skip samples for THIS batch only (not
                                    // carried across iterations, unlike
                                    // `drift_accum` which aggregates over the
                                    // whole file) — capped at SKIP_SAMPLE_CAP
                                    // so a batch made of many skip-heavy
                                    // sub-chunks doesn't blow past the same
                                    // bound the non-parallel parsers enforce.
                                    let mut skipped_accum: Vec<(String, String)> = Vec::new();
                                    let events: Vec<graph_hunter_core::RawIngestEvent> =
                                        if sub_chunks.len() > 1 {
                                            use rayon::prelude::*;
                                            let per_chunk: Vec<(Vec<_>, _)> = sub_chunks
                                                .par_iter()
                                                .map(|chunk| {
                                                    parser.parse_raw_with_stats(chunk.as_ref())
                                                })
                                                .collect();
                                            let mut flattened: Vec<_> = Vec::new();
                                            for (e, s) in per_chunk {
                                                flattened.extend(e);
                                                if let Some(d) = s.drift {
                                                    drift_accum
                                                        .get_or_insert_with(DriftSnapshot::default)
                                                        .merge(&d);
                                                }
                                                if skipped_accum.len()
                                                    < graph_hunter_core::parser::SKIP_SAMPLE_CAP
                                                {
                                                    let remaining =
                                                        graph_hunter_core::parser::SKIP_SAMPLE_CAP
                                                            - skipped_accum.len();
                                                    skipped_accum.extend(
                                                        s.skipped_samples
                                                            .into_iter()
                                                            .take(remaining),
                                                    );
                                                }
                                            }
                                            flattened
                                        } else {
                                            let (e, s) =
                                                parser.parse_raw_with_stats(sub_chunks[0].as_ref());
                                            if let Some(d) = s.drift {
                                                drift_accum
                                                    .get_or_insert_with(DriftSnapshot::default)
                                                    .merge(&d);
                                            }
                                            skipped_accum = s.skipped_samples;
                                            skipped_accum.truncate(
                                                graph_hunter_core::parser::SKIP_SAMPLE_CAP,
                                            );
                                            e
                                        };
                                    // Journal step: must run BEFORE the graph
                                    // insert below so a crash in between is
                                    // replayable. Gated behind GRAPHHUNTER_JOURNAL
                                    // (default off = no-op); failures only warn,
                                    // never abort ingestion — mirrors load_data.
                                    // The parallel-chunk path above now merges
                                    // `skipped_samples` from every sub-chunk
                                    // (capped at SKIP_SAMPLE_CAP) alongside
                                    // `drift`, so real skip samples for this
                                    // batch's `events` are journaled instead
                                    // of an empty slice.
                                    let journal_keys = journal_batch_best_effort(
                                        &bg_dataset_id,
                                        "file_stream",
                                        resolved.as_str(),
                                        &events,
                                        &skipped_accum,
                                    );
                                    let (ne, nr) = {
                                        let mut graph = bg_session
                                            .graph
                                            .write()
                                            .map_err(|e| format!("Lock poisoned: {}", e))?;
                                        insert_journaled(
                                            &mut graph,
                                            events,
                                            journal_keys,
                                            Some(&bg_dataset_id),
                                        )
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

                                    // Last-resort OOM guard: edges spill to disk but
                                    // entities/interner stay in RAM. Stops only when the
                                    // machine is critically low AND this ingest is what
                                    // filled it — see `SELF_GROWTH_CRITICAL_MB` for why
                                    // availability alone is the wrong test.
                                    if total_new_relations % (BATCH_LINES * 20) < BATCH_LINES
                                        && let Some((avail_mb, commit_mb, total_mb)) =
                                            memory_snapshot_mb()
                                    {
                                        let self_growth_mb =
                                            commit_mb.saturating_sub(commit_baseline_mb);
                                        if avail_mb < CRITICAL_MEMORY_MB
                                            && self_growth_mb
                                                > total_mb / SELF_GROWTH_CRITICAL_FRACTION
                                        {
                                            tracing::warn!(
                                                "INGEST: stopping at byte {} of {} — {} MB free and this ingest grew {} MB",
                                                pos + 1,
                                                bytes_total,
                                                avail_mb,
                                                self_growth_mb
                                            );
                                            truncated_at =
                                                Some((pos + 1, avail_mb, self_growth_mb));
                                            stopped_early = true;
                                            break;
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
                                    // Same header rule as the batch loop
                                    // above — the remainder is a batch like
                                    // any other, and a headed format's last
                                    // partial batch is exactly where a
                                    // missing header goes unnoticed.
                                    let header_for_batch: Option<&str> =
                                        if let Some(ref hdr) = last_fields_header {
                                            if !batch_str.contains("#Fields:") {
                                                Some(hdr.as_str())
                                            } else {
                                                None
                                            }
                                        } else if batch_start > 0 {
                                            table_header.as_deref()
                                        } else {
                                            None
                                        };
                                    let (events, final_stats) = match header_for_batch {
                                        Some(h) => {
                                            let with_header = format!("{}\n{}", h, batch_str);
                                            parser.parse_raw_with_stats(&with_header)
                                        }
                                        None => parser.parse_raw_with_stats(&batch_str),
                                    };
                                    if let Some(d) = final_stats.drift {
                                        drift_accum
                                            .get_or_insert_with(DriftSnapshot::default)
                                            .merge(&d);
                                    }
                                    // Journal step: must run BEFORE the graph
                                    // insert below so a crash in between is
                                    // replayable. Gated behind GRAPHHUNTER_JOURNAL
                                    // (default off = no-op); failures only warn,
                                    // never abort ingestion — mirrors load_data.
                                    // Unlike the batch-loop site above, this
                                    // final-remainder parse keeps `final_stats`
                                    // in scope, so its real `skipped_samples`
                                    // are journaled alongside `events`.
                                    let journal_keys = journal_batch_best_effort(
                                        &bg_dataset_id,
                                        "file_stream",
                                        resolved.as_str(),
                                        &events,
                                        &final_stats.skipped_samples,
                                    );
                                    let (ne, nr) = {
                                        let mut graph = bg_session
                                            .graph
                                            .write()
                                            .map_err(|e| format!("Lock poisoned: {}", e))?;
                                        insert_journaled(
                                            &mut graph,
                                            events,
                                            journal_keys,
                                            Some(&bg_dataset_id),
                                        )
                                        .map_err(|e| e.to_string())?
                                    };
                                    note_post_finalize_appends(&bg_session, nr);
                                    total_new_entities += ne;
                                    total_new_relations += nr;
                                }
                            }

                            // A desync means the input's quoting is not
                            // trustworthy (a producer emitting unescaped
                            // quotes inside a quoted value). The scan
                            // recovered, but records were merged on the
                            // way — say so, rather than leaving a silent
                            // shortfall for someone to find later.
                            if scanner.resyncs() > 0 {
                                tracing::warn!(
                                    "INGEST: {} quote-state resync(s) in '{}' ({}) — the file                                      contains unescaped quotes inside quoted values, so some                                      records were merged before the scan recovered",
                                    scanner.resyncs(),
                                    bg_path,
                                    resolved
                                );
                            }

                            let _ = stopped_early;
                            Ok((
                                total_new_entities,
                                total_new_relations,
                                drift_accum,
                                truncated_at.map(|(b, a, g)| (b as u64, a, g)),
                            ))
                        } else {
                            // ── JSON array / small file: memory-mapped parse + insert ──
                            //
                            // This branch parses the WHOLE file in one
                            // `parse_raw_with_stats(contents)` call, which
                            // materializes a `Vec<ParsedTriple>` (448 B/event)
                            // and a `Vec<RawIngestEvent>` (272 B/event) for
                            // every event at once. At ~12 M events/GB that
                            // peaks near 8 GB per GB of input — a multi-GB
                            // file aborts the process with
                            // `memory allocation of N bytes failed`. Line-
                            // delimited formats avoid this via the streaming
                            // branch above; JSON-array formats can't be line-
                            // split, so guard by size and fail loudly with an
                            // actionable message instead of crashing.
                            if bytes_total > WHOLE_FILE_PARSE_LIMIT {
                                return Err(format!(
                                    "File '{}' ({} MB, format '{}') is too large for the whole-file ingest path \
                                     (limit {} MB). '{2}' is parsed as a single document (a JSON array or an XML \
                                     report), so it has no record boundary to stream on. Split the file, or export \
                                     it as one record per line (NDJSON instead of a JSON array). Line-delimited and \
                                     quoted-CSV formats stream regardless of size and never reach this check.",
                                    bg_path,
                                    bytes_total / (1024 * 1024),
                                    resolved,
                                    WHOLE_FILE_PARSE_LIMIT / (1024 * 1024),
                                ));
                            }
                            let file = std::fs::File::open(&bg_path)
                                .map_err(|e| format!("Failed to open file '{}': {}", bg_path, e))?;
                            let mmap = unsafe { memmap2::Mmap::map(&file) }
                                .map_err(|e| format!("Failed to mmap file '{}': {}", bg_path, e))?;
                            graph_hunter_core::mmap_advise::try_hugepages(&mmap);
                            let contents = std::str::from_utf8(&mmap)
                                .map_err(|e| format!("File is not valid UTF-8: {}", e))?;

                            // Honest 0%: this branch parses the whole file in
                            // ONE call with no mid-parse events, so reporting
                            // `bytes_read: bytes_total` here (as this used to)
                            // painted a full, frozen bar for the entire parse —
                            // users read that as a hang. 0% + "parsing" at
                            // least states the truth: working, size known,
                            // progress unknowable until the call returns.
                            bg_emitter.emit(
                                INGEST_PROGRESS,
                                serde_json::json!({
                                    "phase": "parsing",
                                    "bytes_read": 0u64,
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

                            // Parse done → bar jumps to 100% and the phase
                            // flips to "inserting". `relations` carries the
                            // parsed raw-event count (≈ relations about to be
                            // inserted) so the label shows real output volume
                            // while the graph insert runs.
                            bg_emitter.emit(
                                INGEST_PROGRESS,
                                serde_json::json!({
                                    "phase": "inserting",
                                    "bytes_read": bytes_total,
                                    "bytes_total": bytes_total,
                                    "entities": 0,
                                    "relations": events.len(),
                                }),
                            );

                            // Journal step: must run BEFORE the graph insert
                            // below so a crash in between is replayable. Gated
                            // behind GRAPHHUNTER_JOURNAL (default off = no-op);
                            // failures only warn, never abort ingestion —
                            // mirrors load_data. `stats` is in scope here (this
                            // is the whole-file parse path), so its real
                            // `skipped_samples` are journaled alongside `events`.
                            let journal_keys = journal_batch_best_effort(
                                &bg_dataset_id,
                                "file_stream",
                                resolved.as_str(),
                                &events,
                                &stats.skipped_samples,
                            );
                            let (ne, nr) = {
                                let mut graph = bg_session
                                    .graph
                                    .write()
                                    .map_err(|e| format!("Lock poisoned: {}", e))?;
                                insert_journaled(
                                    &mut graph,
                                    events,
                                    journal_keys,
                                    Some(&bg_dataset_id),
                                )
                                .map_err(|e| e.to_string())?
                            };
                            // Guard dropped above before noting appends —
                            // note_post_finalize_appends re-locks graph.read()
                            // and would self-deadlock under a held write guard.
                            note_post_finalize_appends(&bg_session, nr);
                            tracing::info!("INGEST: inserted ({}, {})", ne, nr);
                            // Whole-file parse path always consumes the entire
                            // input in one pass — there is no early-stop guard
                            // here (only the line-based streaming branch above
                            // can bail on the Windows critical-memory check).
                            // The whole-file branch reads everything or fails; it
                            // never truncates, so there is nothing to report.
                            Ok((ne, nr, stats.drift, None))
                        }
                    })();

                match ingest_result {
                    Ok((new_entities, new_relations, drift, truncation)) => {
                        let stopped_early = truncation.is_some();
                        if let Some(ref d) = drift {
                            bg_api.record_drift(&bg_dataset_id, d);
                        }
                        // completeness_flag (design spec §17): fold this
                        // ingest's stopped_early signal into the session's
                        // running coverage state so a later `run_hunt`
                        // marks its answer `possibly_incomplete`. Monotonic
                        // — see `IngestCoverage::observe`. Only this
                        // streaming path currently computes a real
                        // stopped_early (the Windows critical-memory
                        // early-bail); the other ingest entry points
                        // (`load_data`, `ingest_siem`,
                        // `load_data_with_config`, the ingestor-registry
                        // branch above) always report `stopped_early:
                        // false` today, so wiring `observe()` there would
                        // be a no-op — left for follow-up if/when those
                        // paths grow a real early-stop condition.
                        if let Ok(mut ic) = bg_session.ingest_coverage.write() {
                            ic.observe(stopped_early, false);
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

                        if let Ok(mut datasets) = bg_session.datasets.write()
                            && let Some(ds) = datasets.iter_mut().find(|d| d.id == bg_dataset_id)
                        {
                            ds.entity_count = new_entities;
                            ds.relation_count = new_relations;
                        }

                        let (total_entities, total_relations, mut warnings) = bg_session
                            .graph
                            .read()
                            .map(|g| {
                                let warnings = compute_ingest_warnings(&g);
                                (g.entity_count(), g.relation_count(), warnings)
                            })
                            .unwrap_or((0, 0, Vec::new()));

                        // A truncated ingest is a partial graph, and a partial
                        // graph answers hunts wrongly without ever looking
                        // wrong. `stopped_early` alone is a flag someone has to
                        // think to check; say plainly what was dropped and
                        // where, at the top of the warnings the UI already
                        // shows.
                        if let Some((byte, avail_mb, growth_mb)) = truncation {
                            let pct = if bytes_total > 0 {
                                (byte as f64 / bytes_total as f64) * 100.0
                            } else {
                                0.0
                            };
                            warnings.insert(
                                0,
                                format!(
                                    "INGESTA PARCIAL: se detuvo en el byte {} de {} ({:.1}% del archivo)                                      por memoria baja ({} MB libres, esta ingesta creció {} MB).                                      El resto del archivo NO se ingirió y el grafo está incompleto.                                      Liberá memoria y reingerí, o acotá con un rango de fechas.",
                                    byte, bytes_total, pct, avail_mb, growth_mb
                                ),
                            );
                        }

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
                                    stopped_early,
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
fn resume_phase_after_finalize(prior: crate::state::SessionPhase) -> crate::state::SessionPhase {
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

        let session = Arc::new(Session::new(
            "guard-test",
            "guard-test",
            GraphHunter::new(),
            0,
        ));
        session.set_phase(SessionPhase::Ready);

        // Simulate the ingest preamble: set Finalizing, create the guard.
        let resume = resume_phase_after_finalize(session.phase());
        session.set_phase(SessionPhase::Finalizing);
        assert_eq!(session.phase(), SessionPhase::Finalizing);

        // Enter a block that creates the guard and then "early-exits" without
        // reaching a normal success path. The closure returns an Err, which
        // causes the guard to be dropped when the block scope ends.
        let result: Result<(), &str> = (|| {
            let _guard = FinalizePhaseGuard {
                session: Arc::clone(&session),
                resume,
            };
            // Simulate a mid-ingest error that would have `?`-returned in
            // the real load_data / ingest_siem / load_data_with_config.
            return Err("simulated lock-poisoned error");
            #[allow(unreachable_code)]
            Ok(())
        })();

        assert!(
            result.is_err(),
            "closure must return Err to simulate early exit"
        );
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
