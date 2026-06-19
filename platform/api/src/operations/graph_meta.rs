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
//! `recent_pivots` remains `vec![]` — that ring buffer lands in Task 6.

use std::collections::BTreeMap;

use crate::dto::v1::graph_meta::{
    ActiveHunt, GraphSummary, GraphTotals, SourceState, GRAPH_META_SCHEMA_VERSION,
};
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
    pub fn get_graph_meta_summary(&self) -> ApiResult<GraphSummary> {
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

        Ok(GraphSummary {
            schema_version: GRAPH_META_SCHEMA_VERSION,
            as_of: chrono::Utc::now().to_rfc3339(),
            totals: GraphTotals { nodes, edges, by_type },
            sources,
            active_datasets,
            active_hunts,
            recent_pivots: vec![], // NOTE(Task 6): pivot ring buffer
            graph_empty: nodes == 0,
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

    #[test]
    fn get_graph_meta_summary_returns_schema_version_1() {
        let api = GraphHunterApi::new_noop();
        let summary = api.get_graph_meta_summary().expect("get_graph_meta_summary");
        assert_eq!(summary.schema_version, GRAPH_META_SCHEMA_VERSION);
    }

    #[test]
    fn get_graph_meta_summary_as_of_is_non_empty_rfc3339() {
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
        let api = api_with_dataset("s1", "ator-evtx-snapshot");
        let summary = api.get_graph_meta_summary().expect("get_graph_meta_summary");
        assert!(
            summary.active_datasets.contains(&"ator-evtx-snapshot".to_string()),
            "active_datasets must include the registered dataset id"
        );
    }

    #[test]
    fn get_graph_meta_summary_hunt_cache_non_empty_yields_active_hunt() {
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
        let api = GraphHunterApi::new_noop();
        let summary = api.get_graph_meta_summary().expect("get_graph_meta_summary");
        assert!(
            summary.active_hunts.is_empty(),
            "empty hunt cache must produce empty active_hunts"
        );
    }
}
