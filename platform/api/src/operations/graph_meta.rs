//! `/graph/summary` and `/graph/overlap` operation implementations.
//!
//! Task 1 (hardcoded skeleton): both methods return empty / zero data so the
//! route and DTO wiring can be tested end-to-end before live data is plumbed
//! in.
//!
//! Task 2 (real data): wires in:
//! - `active_datasets` — from the current session's `DatasetInfo` list.
//! - `active_hunts`    — from the shared hunt cache (`Vec<Vec<Arc<str>>>`).
//!                       The cache holds raw path lists with no per-hunt
//!                       metadata (params, timestamp, TTL); those are Task 3+
//!                       concerns. A non-empty cache is surfaced as one
//!                       `ActiveHunt` entry whose `result_size` is the path
//!                       count. All metadata fields default to placeholder
//!                       values until a richer cache structure is introduced.
//! - `sources`         — the registered log format names (sysmon, sentinel,
//!                       cognito, fortigate, iis, haproxy, fortianalyzer,
//!                       generic, csv). Per-source ingest timestamps and row
//!                       counts require session-level tracking not yet built;
//!                       `last_ingest` and `rows_lifetime` default to their
//!                       zero/None values (Task 3).
//! - `totals`          — node + edge counts from the session graph's
//!                       `entity_count()` / `relation_count()` /
//!                       `entity_type_counts()`. Zero when no session is
//!                       loaded (graceful degradation).
//!
//! Task 4: 30s TTL cache on `get_graph_meta_summary`. The public method is
//! now a cache-or-compute facade; the computation lives in the private
//! `compute_graph_meta_summary`. A `_flush_summary_cache_for_test()` helper
//! keeps tests hermetic.
//!
//! Task 5: `RecentPivotsBuffer` — a process-global ring buffer (size 20)
//! that holds the most-recently-seeded/expanded pivot entities, newest-first.
//! `get_graph_meta_summary` includes a snapshot of the buffer.
//!
//! Task 6: `RECENT_PIVOTS.push(...)` is wired into `sentinel.rs` (seed) and
//! `sentinel.rs` / graph_ops (expand). See those modules for call sites.

use std::collections::BTreeMap;
use std::collections::VecDeque;
use std::sync::{LazyLock, Mutex};
use std::time::{Duration, Instant};

use crate::dto::v1::graph_meta::{
    ActiveHunt, FoundEntity, GraphSummary, GraphTotals, OverlapRequest, OverlapResponse,
    RecentPivot, SourceState, GRAPH_META_SCHEMA_VERSION, OVERLAP_MAX_ENTITIES,
};
use crate::error::ApiError;
use crate::{ApiResult, GraphHunterApi};

/// Canonical list of log source names known to the format registry.
///
/// Mirrors the `name` fields in `format_registry::FORMAT_REGISTRY`.
/// Kept here as a local constant to avoid exposing the private static
/// from `format_registry` (which is an implementation detail of the
/// ingest pipeline, not a public API). Update this list when a new
/// format is added to `FORMAT_REGISTRY`.
///
/// NOTE(Task 3): once per-source ingest audit data exists, replace this
/// constant list with a runtime query against the registry + session state.
const REGISTERED_SOURCE_NAMES: &[&str] = &[
    "sysmon",
    "sentinel",
    "cognito",
    "fortigate",
    "iis",
    "haproxy",
    "fortianalyzer",
    "generic",
    "csv",
];

// ── Task 4: 30s TTL summary cache ───────────────────────────────────────────

const SUMMARY_TTL: Duration = Duration::from_secs(30);

static SUMMARY_CACHE: LazyLock<Mutex<Option<(Instant, GraphSummary)>>> =
    LazyLock::new(|| Mutex::new(None));

// ── Task 5: recent-pivots ring buffer ───────────────────────────────────────

/// An in-memory ring buffer of the most recently seeded/expanded pivot
/// entities, capped at `capacity` entries and ordered newest-first.
///
/// Thread-safe: all access is guarded by an internal `Mutex`. The buffer
/// is backed by a `VecDeque` so both push-to-front and pop-from-back are
/// O(1).
pub struct RecentPivotsBuffer {
    inner: Mutex<VecDeque<RecentPivot>>,
    capacity: usize,
}

impl RecentPivotsBuffer {
    /// Create a new buffer capped at `cap` entries.
    pub fn with_capacity(cap: usize) -> Self {
        Self {
            inner: Mutex::new(VecDeque::with_capacity(cap)),
            capacity: cap,
        }
    }

    /// Push a new pivot to the front (newest-first). Drops the oldest
    /// entry when the buffer is already at capacity.
    pub fn push(&self, p: RecentPivot) {
        let mut q = self.inner.lock().unwrap();
        if q.len() == self.capacity {
            q.pop_back();
        }
        q.push_front(p);
    }

    /// Return a cloned snapshot of the buffer, newest-first.
    pub fn snapshot(&self) -> Vec<RecentPivot> {
        self.inner.lock().unwrap().iter().cloned().collect()
    }

    /// Mark an existing pivot entry as expanded and record the hop degree.
    /// Looks up the entry by `entity` value; no-op if the entity is not
    /// currently in the buffer (e.g. it was evicted).
    pub fn mark_expanded(&self, entity: &str, degree: u32) {
        let mut q = self.inner.lock().unwrap();
        if let Some(p) = q.iter_mut().find(|p| p.entity == entity) {
            p.expanded = true;
            p.degree = degree;
        }
    }
}

/// Process-global ring buffer for the 20 most recent pivots.
/// Populated by `sentinel.rs` (`seed_from_ioc_with`) and by the expand
/// path in `graph_ops.rs` / `sentinel.rs`.
pub static RECENT_PIVOTS: LazyLock<RecentPivotsBuffer> =
    LazyLock::new(|| RecentPivotsBuffer::with_capacity(20));

// ── Test-only flush helpers ──────────────────────────────────────────────────

/// A process-global mutex used by tests that need to flush the summary
/// cache and pivot buffer atomically — without a race window between the
/// flush and the subsequent `get_graph_meta_summary` call. Tests that
/// call `get_graph_meta_summary` and depend on specific cached state must
/// hold this lock for the entire flush-call sequence.
///
/// Example usage in tests that need isolation:
/// ```ignore
/// use graph_hunter_api::operations::graph_meta::{
///     _GRAPH_META_TEST_MUTEX, _flush_summary_cache_for_test, _flush_recent_pivots_for_test,
/// };
/// let _guard = _GRAPH_META_TEST_MUTEX.lock().unwrap();
/// _flush_summary_cache_for_test();
/// _flush_recent_pivots_for_test();
/// // ... call get_graph_meta_summary here ...
/// ```
///
/// Note: this serialises only the tests that hold the guard. Tests that
/// do NOT call `get_graph_meta_summary` (or do not care about cache state)
/// do not need to acquire it.
// Exposed `pub` (not gated on `#[cfg(test)]`) so that integration tests
// living in `tests/` — which compile against the public crate — can
// serialise themselves against the global SUMMARY_CACHE / RECENT_PIVOTS.
// The leading underscore in the names is the convention for "test-only,
// do not call from production paths". The cost of carrying these in
// release builds is a few hundred bytes for a no-op-in-production helper.
pub static _GRAPH_META_TEST_MUTEX: LazyLock<Mutex<()>> =
    LazyLock::new(|| Mutex::new(()));

/// Flush the `SUMMARY_CACHE` so that the next call to
/// `get_graph_meta_summary` recomputes from scratch. Test-only by
/// convention. Hold `_GRAPH_META_TEST_MUTEX` for the duration when you
/// need to prevent cross-test cache pollution.
pub fn _flush_summary_cache_for_test() {
    *SUMMARY_CACHE.lock().unwrap() = None;
}

/// Flush the `RECENT_PIVOTS` ring buffer. Test-only by convention.
/// Hold `_GRAPH_META_TEST_MUTEX` for the duration when you need to
/// prevent cross-test pivot-list pollution.
pub fn _flush_recent_pivots_for_test() {
    let mut q = RECENT_PIVOTS.inner.lock().unwrap();
    q.clear();
}

// ── API implementation ───────────────────────────────────────────────────────

impl GraphHunterApi {
    /// Returns a `GraphSummary` snapshot for the `/graph/summary` endpoint.
    ///
    /// Named `get_graph_meta_summary` to avoid collision with the existing
    /// `get_graph_summary` in `operations/geoip.rs` which returns a different
    /// DTO (`GraphSummaryWithCapabilities`). The two serve different callers:
    /// the new endpoint feeds the MCP `graph://summary` resource and the
    /// frontend badge; the existing one answers the `/graph_summary` legacy
    /// route used by the Tauri UI panel.
    ///
    /// Graceful degradation: when no session is loaded (e.g. fresh API,
    /// tests that don't create a session), the session-bound fields
    /// (`active_datasets`, `totals`) are empty/zero rather than an error.
    /// `sources` is always populated from the static format registry.
    ///
    /// Task 4: wraps `compute_graph_meta_summary` in a 30-second TTL cache.
    /// The cache is process-global (`SUMMARY_CACHE`). Use
    /// `_flush_summary_cache_for_test()` in tests to avoid cross-test
    /// pollution.
    pub fn get_graph_meta_summary(&self) -> ApiResult<GraphSummary> {
        // ── Consult cache ───────────────────────────────────────────────
        {
            let guard = SUMMARY_CACHE.lock().unwrap();
            if let Some((t, cached)) = guard.as_ref() {
                if t.elapsed() < SUMMARY_TTL {
                    return Ok(cached.clone());
                }
            }
        }
        // ── Cache miss: compute and store ───────────────────────────────
        let fresh = self.compute_graph_meta_summary()?;
        *SUMMARY_CACHE.lock().unwrap() = Some((Instant::now(), fresh.clone()));
        Ok(fresh)
    }

    /// Inner computation for `get_graph_meta_summary`. Never reads the
    /// cache — always produces a fresh snapshot from current state.
    fn compute_graph_meta_summary(&self) -> ApiResult<GraphSummary> {
        // ── Sources (from registered format names) ─────────────────────
        // NOTE(Task 3): per-source last_ingest timestamps and row counts
        // require a session-level ingest audit log that doesn't exist yet.
        // Until then, surface the format names only.
        let sources: Vec<SourceState> = REGISTERED_SOURCE_NAMES
            .iter()
            .map(|&name| SourceState {
                name: name.to_string(),
                last_ingest: None,
                rows_lifetime: 0,
            })
            .collect();

        // ── Session-bound state (graceful degradation when no session) ──
        let maybe_session = self.sessions().current_session();

        let (nodes, edges, by_type, active_datasets) = match &maybe_session {
            Some(session) => {
                // Graph counters.
                let (n, e, bt) = session
                    .graph
                    .read()
                    .map(|g| {
                        let n = g.entity_count() as u64;
                        let e = g.relation_count() as u64;
                        let bt: BTreeMap<String, u64> = g
                            .entity_type_counts()
                            .into_iter()
                            .map(|(k, v)| (k, v as u64))
                            .collect();
                        (n, e, bt)
                    })
                    .unwrap_or((0, 0, BTreeMap::new()));

                // Dataset IDs from the session metadata.
                let ds: Vec<String> = session
                    .datasets
                    .read()
                    .map(|d| d.iter().map(|info| info.id.clone()).collect())
                    .unwrap_or_default();

                (n, e, bt, ds)
            }
            None => (0, 0, BTreeMap::new(), vec![]),
        };

        // ── Hunt cache ──────────────────────────────────────────────────
        // The current hunt cache (`Arc<RwLock<Vec<Vec<Arc<str>>>>>`) stores
        // raw path vectors with no per-hunt metadata (no params string, no
        // timestamp, no TTL). Task 3 will introduce a richer cache entry
        // type. For now: a non-empty cache is surfaced as one ActiveHunt
        // whose result_size is the total path count.
        //
        // NOTE(Task 3): replace this block with real per-entry iteration
        // once `HuntCacheEntry { params, computed_at, paths, ttl }` lands.
        //
        // NOTE on `computed_at`: this field currently reflects the READ
        // time (i.e. when `/graph/summary` is computed), NOT the time the
        // hunt was actually computed. When per-hunt cache entries land
        // (Task 3+), `computed_at` should be sourced from the cache entry's
        // own timestamp so the analyst sees when the hunt ran, not when the
        // summary was polled.
        //
        // NOTE on `result_size` semantics: currently records the total path
        // count across the single collapsed cache entry. When the cache
        // evolves to per-key entries (Task 3+), `result_size` will need
        // recalibration — each entry will report its own path count rather
        // than an aggregate across all hunts.
        let active_hunts: Vec<ActiveHunt> = {
            let cache = self
                .inner
                .hunt_cache
                .read()
                .map(|g| g.len())
                .unwrap_or(0);
            if cache > 0 {
                vec![ActiveHunt {
                    cache_key: "current".to_string(),
                    params_summary: "(last hunt)".to_string(),
                    result_size: cache as u64,
                    computed_at: chrono::Utc::now().to_rfc3339(),
                    ttl_seconds_remaining: 0, // NOTE(Task 3): no TTL tracked yet
                }]
            } else {
                vec![]
            }
        };

        // ── Recent pivots (Task 5: ring buffer snapshot) ────────────────
        let recent_pivots = RECENT_PIVOTS.snapshot();

        Ok(GraphSummary {
            schema_version: GRAPH_META_SCHEMA_VERSION,
            as_of: chrono::Utc::now().to_rfc3339(),
            totals: GraphTotals { nodes, edges, by_type },
            sources,
            active_datasets,
            active_hunts,
            recent_pivots,
            graph_empty: nodes == 0,
        })
    }

    /// Look up a batch of entities against the current session graph.
    ///
    /// Powers the MCP `sentinel_query` overlap nudge: given the entity-like
    /// values extracted from a KQL result, returns which are already in
    /// the graph and their total degree.
    ///
    /// Capped at [`OVERLAP_MAX_ENTITIES`]; above the cap returns
    /// `PayloadTooLarge` (HTTP 413). Sessions: when no session is loaded
    /// every entity reports as missing — that's the correct "graph is
    /// empty" answer for the nudge composer.
    ///
    /// `top_neighbor` is `None` in v1 to keep p99 bounded; the MCP nudge
    /// composer uses only `degree` today.
    pub fn post_graph_overlap(&self, req: OverlapRequest) -> ApiResult<OverlapResponse> {
        if req.entities.len() > OVERLAP_MAX_ENTITIES {
            return Err(ApiError::PayloadTooLarge(format!(
                "entities ({} > {})",
                req.entities.len(),
                OVERLAP_MAX_ENTITIES
            )));
        }

        let mut found: Vec<FoundEntity> = Vec::new();
        let mut missing: Vec<String> = Vec::new();

        match self.sessions().current_session() {
            Some(session) => {
                let graph = session
                    .graph
                    .read()
                    .map_err(|e| ApiError::Internal(format!("graph lock poisoned: {e}")))?;
                for e in &req.entities {
                    match graph.get_entity(&e.value) {
                        Some(_) => {
                            let out_d = graph.get_compact_relations(&e.value).len();
                            let in_d = graph
                                .interner
                                .get(&e.value)
                                .and_then(|sid| graph.reverse_adj.get(&sid))
                                .map(|v| v.len())
                                .unwrap_or(0);
                            let degree = (out_d + in_d) as u32;
                            found.push(FoundEntity {
                                entity: e.value.clone(),
                                kind: e.kind.clone(),
                                degree,
                                top_neighbor: None,
                            });
                        }
                        None => missing.push(e.value.clone()),
                    }
                }
            }
            None => {
                for e in &req.entities {
                    missing.push(e.value.clone());
                }
            }
        }

        Ok(OverlapResponse {
            schema_version: GRAPH_META_SCHEMA_VERSION,
            found,
            missing,
        })
    }
}

// ── Unit tests ────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state::Session;
    use crate::state::session_types::DatasetInfo;
    use graph_hunter_core::GraphHunter;
    use std::sync::Arc;

    /// Helper: build an API with one Ready session that contains a named dataset.
    fn api_with_dataset(session_id: &str, dataset_id: &str) -> GraphHunterApi {
        let api = GraphHunterApi::new_noop();
        let session = Arc::new(Session::new(session_id, "test session", GraphHunter::new(), 0));
        // Push a DatasetInfo directly so we don't need a real file on disk.
        session
            .datasets
            .write()
            .unwrap()
            .push(DatasetInfo {
                id: dataset_id.to_string(),
                name: dataset_id.to_string(),
                path: None,
                created_at: 0,
                entity_count: 0,
                relation_count: 0,
                field_config: None,
                ingest_stats: None,
            });
        api.sessions().insert(session);
        api.sessions().set_current(Some(session_id.to_string()));
        api
    }

    // ── Task 1/2 tests (unchanged assertions, now with cache flush) ──────
    // NOTE: tests that call `get_graph_meta_summary` acquire
    // `_GRAPH_META_TEST_MUTEX` to serialise the flush+call pair and prevent
    // concurrent tests from polluting the process-global SUMMARY_CACHE.

    #[test]
    fn get_graph_meta_summary_returns_schema_version_1() {
        let _g = _GRAPH_META_TEST_MUTEX.lock().unwrap();
        _flush_summary_cache_for_test();
        _flush_recent_pivots_for_test();
        let api = GraphHunterApi::new_noop();
        let summary = api.get_graph_meta_summary().expect("get_graph_meta_summary");
        assert_eq!(summary.schema_version, GRAPH_META_SCHEMA_VERSION);
    }

    #[test]
    fn get_graph_meta_summary_as_of_is_non_empty_rfc3339() {
        let _g = _GRAPH_META_TEST_MUTEX.lock().unwrap();
        _flush_summary_cache_for_test();
        _flush_recent_pivots_for_test();
        let api = GraphHunterApi::new_noop();
        let summary = api.get_graph_meta_summary().expect("get_graph_meta_summary");
        assert!(
            !summary.as_of.is_empty(),
            "as_of must be a non-empty RFC 3339 string"
        );
        // Confirm chrono can parse its own output.
        chrono::DateTime::parse_from_rfc3339(&summary.as_of)
            .expect("as_of must parse as RFC 3339");
    }

    #[test]
    fn get_graph_meta_summary_no_session_has_zero_totals_and_empty_datasets() {
        let _g = _GRAPH_META_TEST_MUTEX.lock().unwrap();
        _flush_summary_cache_for_test();
        _flush_recent_pivots_for_test();
        // Fresh API with no session — graceful degradation path.
        let api = GraphHunterApi::new_noop();
        let summary = api.get_graph_meta_summary().expect("get_graph_meta_summary");
        assert_eq!(summary.totals.nodes, 0);
        assert_eq!(summary.totals.edges, 0);
        assert!(summary.totals.by_type.is_empty());
        assert!(summary.active_datasets.is_empty());
        assert!(summary.active_hunts.is_empty());
        assert!(summary.recent_pivots.is_empty());
        assert!(summary.graph_empty);
    }

    #[test]
    fn get_graph_meta_summary_serializes_stable_shape() {
        let _g = _GRAPH_META_TEST_MUTEX.lock().unwrap();
        _flush_summary_cache_for_test();
        _flush_recent_pivots_for_test();
        let api = GraphHunterApi::new_noop();
        let summary = api.get_graph_meta_summary().expect("get_graph_meta_summary");
        let v = serde_json::to_value(&summary).expect("serialize");
        assert_eq!(v["schema_version"], 1);
        assert!(v["as_of"].is_string());
        assert!(v["totals"]["nodes"].is_u64());
        assert!(v["totals"]["edges"].is_u64());
        assert!(v["totals"]["by_type"].is_object());
        assert!(v["sources"].is_array());
        assert!(v["active_datasets"].is_array());
        assert!(v["active_hunts"].is_array());
        assert!(v["recent_pivots"].is_array());
        assert!(v["graph_empty"].is_boolean());
    }

    #[test]
    fn get_graph_meta_summary_sources_include_format_registry_names() {
        let _g = _GRAPH_META_TEST_MUTEX.lock().unwrap();
        _flush_summary_cache_for_test();
        _flush_recent_pivots_for_test();
        let api = GraphHunterApi::new_noop();
        let summary = api.get_graph_meta_summary().expect("get_graph_meta_summary");
        // The static FORMAT_REGISTRY is always present regardless of session state.
        assert!(!summary.sources.is_empty(), "sources must list registered formats");
        let names: Vec<&str> = summary.sources.iter().map(|s| s.name.as_str()).collect();
        assert!(names.contains(&"sysmon"), "sysmon must be in sources");
        assert!(names.contains(&"sentinel"), "sentinel must be in sources");
        assert!(names.contains(&"csv"), "csv must be in sources");
    }

    #[test]
    fn get_graph_meta_summary_lists_active_datasets() {
        let _g = _GRAPH_META_TEST_MUTEX.lock().unwrap();
        _flush_summary_cache_for_test();
        _flush_recent_pivots_for_test();
        let api = api_with_dataset("s1", "ator-evtx-snapshot");
        let summary = api.get_graph_meta_summary().expect("get_graph_meta_summary");
        assert!(
            summary.active_datasets.contains(&"ator-evtx-snapshot".to_string()),
            "active_datasets must include the registered dataset id"
        );
    }

    #[test]
    fn get_graph_meta_summary_hunt_cache_non_empty_yields_active_hunt() {
        let _g = _GRAPH_META_TEST_MUTEX.lock().unwrap();
        _flush_summary_cache_for_test();
        _flush_recent_pivots_for_test();
        let api = GraphHunterApi::new_noop();
        // Seed the hunt cache with a few fake paths.
        {
            let handle = api.hunt_cache_handle();
            let mut cache = handle.write().unwrap();
            *cache = vec![
                vec![Arc::from("u1"), Arc::from("h1")],
                vec![Arc::from("u2"), Arc::from("h2")],
            ];
        }
        let summary = api.get_graph_meta_summary().expect("get_graph_meta_summary");
        assert!(
            !summary.active_hunts.is_empty(),
            "hunt cache should expose entries in active_hunts"
        );
        assert_eq!(
            summary.active_hunts[0].result_size,
            2,
            "result_size must equal the number of paths in the cache"
        );
    }

    #[test]
    fn get_graph_meta_summary_empty_hunt_cache_yields_no_active_hunts() {
        let _g = _GRAPH_META_TEST_MUTEX.lock().unwrap();
        _flush_summary_cache_for_test();
        _flush_recent_pivots_for_test();
        let api = GraphHunterApi::new_noop();
        let summary = api.get_graph_meta_summary().expect("get_graph_meta_summary");
        assert!(
            summary.active_hunts.is_empty(),
            "empty hunt cache must produce empty active_hunts"
        );
    }

    // ── Task 4: cache tests ──────────────────────────────────────────────

    #[test]
    fn graph_summary_caches_within_30s_window() {
        let _g = _GRAPH_META_TEST_MUTEX.lock().unwrap();
        _flush_summary_cache_for_test();
        _flush_recent_pivots_for_test();

        let api = GraphHunterApi::new_noop();
        let t1 = api.get_graph_meta_summary().expect("first call");

        // Mutate state that would change the next computation: insert a
        // session with a dataset. While holding the global mutex no other
        // test can flush the cache between these two calls.
        let session = Arc::new(Session::new("s1", "test", GraphHunter::new(), 0));
        session.datasets.write().unwrap().push(DatasetInfo {
            id: "ds1".into(),
            name: "ds1".into(),
            path: None,
            created_at: 0,
            entity_count: 0,
            relation_count: 0,
            field_config: None,
            ingest_stats: None,
        });
        api.sessions().insert(session);
        api.sessions().set_current(Some("s1".into()));

        let t2 = api.get_graph_meta_summary().expect("second call");

        assert_eq!(t1.as_of, t2.as_of, "cached responses must share as_of");
        assert!(
            t2.active_datasets.is_empty(),
            "cached response should still show empty active_datasets even though state changed; got {:?}",
            t2.active_datasets
        );
    }

    // ── Task 5: ring buffer tests ────────────────────────────────────────

    #[test]
    fn recent_pivots_ring_drops_oldest_at_capacity() {
        // Local buffer — no global state involved, no mutex needed.
        let buf = RecentPivotsBuffer::with_capacity(3);
        for i in 0..5 {
            buf.push(RecentPivot {
                entity: format!("ip-{}", i),
                kind: "IP".into(),
                added_at: chrono::Utc::now().to_rfc3339(),
                expanded: false,
                degree: 0,
            });
        }
        let snap = buf.snapshot();
        assert_eq!(snap.len(), 3, "capacity must cap the buffer");
        assert_eq!(snap[0].entity, "ip-4", "newest-first ordering");
        assert_eq!(snap[2].entity, "ip-2", "oldest in window is at the tail");
    }

    #[test]
    fn recent_pivots_mark_expanded_updates_entry() {
        let buf = RecentPivotsBuffer::with_capacity(5);
        buf.push(RecentPivot {
            entity: "10.0.0.1".into(),
            kind: "IP".into(),
            added_at: chrono::Utc::now().to_rfc3339(),
            expanded: false,
            degree: 0,
        });
        buf.mark_expanded("10.0.0.1", 7);
        let snap = buf.snapshot();
        assert!(snap[0].expanded, "mark_expanded must set expanded=true");
        assert_eq!(snap[0].degree, 7, "mark_expanded must record degree");
    }

    #[test]
    fn recent_pivots_mark_expanded_noop_for_unknown_entity() {
        let buf = RecentPivotsBuffer::with_capacity(5);
        // Should not panic even when the entity is absent.
        buf.mark_expanded("unknown", 3);
    }

    #[test]
    fn summary_includes_recent_pivots_snapshot() {
        let _g = _GRAPH_META_TEST_MUTEX.lock().unwrap();
        _flush_summary_cache_for_test();
        _flush_recent_pivots_for_test();

        RECENT_PIVOTS.push(RecentPivot {
            entity: "192.168.1.1".into(),
            kind: "IP".into(),
            added_at: chrono::Utc::now().to_rfc3339(),
            expanded: false,
            degree: 0,
        });

        let api = GraphHunterApi::new_noop();
        let summary = api.get_graph_meta_summary().expect("summary");
        let found = summary.recent_pivots.iter().any(|p| p.entity == "192.168.1.1");
        assert!(found, "summary.recent_pivots must include the pushed pivot");
    }

    // ── Task 7: /graph/overlap tests ───────────────────────────────────

    use crate::dto::v1::graph_meta::EntityRef;

    #[test]
    fn overlap_no_session_returns_all_missing() {
        let api = GraphHunterApi::new_noop();
        let resp = api
            .post_graph_overlap(OverlapRequest {
                schema_version: 1,
                entities: vec![
                    EntityRef { kind: "IP".into(), value: "1.2.3.4".into() },
                    EntityRef { kind: "User".into(), value: "alice@corp".into() },
                ],
            })
            .expect("overlap must succeed");
        assert_eq!(resp.schema_version, 1);
        assert!(resp.found.is_empty(), "no session ⇒ nothing found");
        assert_eq!(resp.missing.len(), 2);
        assert!(resp.missing.contains(&"1.2.3.4".to_string()));
        assert!(resp.missing.contains(&"alice@corp".to_string()));
    }

    #[test]
    fn overlap_rejects_above_500_entities_with_413() {
        let api = GraphHunterApi::new_noop();
        let entities: Vec<EntityRef> = (0..501)
            .map(|i| EntityRef {
                kind: "IP".into(),
                value: format!("10.0.{}.{}", i / 256, i % 256),
            })
            .collect();
        let err = api
            .post_graph_overlap(OverlapRequest { schema_version: 1, entities })
            .expect_err("must reject above cap");
        assert_eq!(err.status_code(), 413, "PayloadTooLarge ⇒ HTTP 413");
    }

    // ── Task 8: schema_version drift guard ────────────────────────────
    //
    // Bumping GRAPH_META_SCHEMA_VERSION is a coordinated change across the
    // Rust DTO, the TypeScript zod schema, and the shared golden fixture
    // (Task 16). This test pins the constant at the Rust side so the
    // change forces a deliberate update — bare integer assertion, not
    // `GRAPH_META_SCHEMA_VERSION == GRAPH_META_SCHEMA_VERSION`.
    #[test]
    fn schema_version_is_pinned_at_one_until_deliberately_bumped() {
        assert_eq!(
            GRAPH_META_SCHEMA_VERSION, 1,
            "bumping requires coordinated update of zod schema + golden fixture"
        );

        // Defense in depth: both response payloads must carry the same
        // version. Catches a buggy refactor that hardcodes a literal
        // instead of using the constant.
        let api = GraphHunterApi::new_noop();
        let _g = _GRAPH_META_TEST_MUTEX.lock().unwrap();
        _flush_summary_cache_for_test();
        let summary = api.get_graph_meta_summary().expect("summary");
        assert_eq!(summary.schema_version, 1);
        let overlap = api
            .post_graph_overlap(OverlapRequest { schema_version: 1, entities: vec![] })
            .expect("overlap");
        assert_eq!(overlap.schema_version, 1);
    }

    #[test]
    fn overlap_finds_entity_in_session_graph() {
        use graph_hunter_core::{Entity, EntityType};

        let _g = _GRAPH_META_TEST_MUTEX.lock().unwrap();

        let api = GraphHunterApi::new_noop();
        let session = Arc::new(Session::new("s1", "test", GraphHunter::new(), 0));
        session
            .graph
            .write()
            .unwrap()
            .add_entity(Entity::new("203.0.113.42", EntityType::IP))
            .expect("add_entity");
        api.sessions().insert(session);
        api.sessions().set_current(Some("s1".into()));

        let resp = api
            .post_graph_overlap(OverlapRequest {
                schema_version: 1,
                entities: vec![
                    EntityRef { kind: "IP".into(), value: "203.0.113.42".into() },
                    EntityRef { kind: "IP".into(), value: "8.8.8.8".into() },
                ],
            })
            .expect("overlap");
        assert_eq!(resp.found.len(), 1, "exactly one entity present");
        assert_eq!(resp.found[0].entity, "203.0.113.42");
        assert_eq!(resp.found[0].degree, 0, "no relations ⇒ degree 0");
        assert!(resp.found[0].top_neighbor.is_none(), "top_neighbor deferred in v1");
        assert_eq!(resp.missing, vec!["8.8.8.8".to_string()]);
    }
}
