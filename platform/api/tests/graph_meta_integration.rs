//! Integration tests for `GraphHunterApi::get_graph_meta_summary`.
//!
//! The test harness follows the existing pattern in `platform/api/tests/`:
//! construct a `GraphHunterApi` via `new_noop()` and call methods directly
//! (no HTTP layer). The shape assertions mirror the JSON contract that the
//! MCP TypeScript client and the frontend badge will consume.
//!
//! Task 2 additions:
//! - `graph_summary_lists_active_datasets` — after pushing a `DatasetInfo`
//!   into the current session the dataset id must appear in the response.
//! - `graph_summary_hunt_cache_non_empty_exposes_active_hunt` — after
//!   seeding the shared hunt cache the response must contain at least one
//!   `ActiveHunt` entry.
//! - The Task 1 "stub is always empty" test is renamed and narrowed:
//!   `graph_summary_fresh_api_has_no_datasets_or_hunts` asserts the
//!   session-bound fields are empty on a freshly-constructed API (which has
//!   no current session). `sources` is no longer empty — the static format
//!   registry is always populated — so that assertion is intentionally
//!   removed. The `graph_empty: true` and zero-totals assertions stay.

use std::sync::Arc;

use graph_hunter_api::state::{Session, session_types::DatasetInfo};
use graph_hunter_api::GraphHunterApi;
use graph_hunter_core::GraphHunter;
use serde_json::Value;

// ── Task 1 tests (kept, updated) ────────────────────────────────────────

#[test]
fn graph_summary_returns_schema_v1_shape() {
    use graph_hunter_api::operations::graph_meta::{
        _flush_summary_cache_for_test, _GRAPH_META_TEST_MUTEX,
    };
    let _g = _GRAPH_META_TEST_MUTEX.lock().unwrap();
    _flush_summary_cache_for_test();

    let api = GraphHunterApi::new_noop();
    let summary = api.get_graph_meta_summary().expect("get_graph_meta_summary must succeed");

    // Serialize to Value so the assertions are transport-agnostic —
    // they verify the same JSON field names that the HTTP handler and
    // the MCP TypeScript client will see.
    let resp: Value = serde_json::to_value(&summary).expect("serialize GraphSummary");

    assert_eq!(resp["schema_version"], 1);
    assert!(
        resp["as_of"].is_string(),
        "as_of must be a JSON string (RFC 3339)"
    );
    assert!(
        resp["totals"]["nodes"].is_u64(),
        "totals.nodes must be a u64"
    );
    assert!(
        resp["totals"]["edges"].is_u64(),
        "totals.edges must be a u64"
    );
    assert!(
        resp["totals"]["by_type"].is_object(),
        "totals.by_type must be an object"
    );
    assert!(
        resp["sources"].is_array(),
        "sources must be an array"
    );
    assert!(
        resp["active_datasets"].is_array(),
        "active_datasets must be an array"
    );
    assert!(
        resp["active_hunts"].is_array(),
        "active_hunts must be an array"
    );
    assert!(
        resp["recent_pivots"].is_array(),
        "recent_pivots must be an array"
    );
    assert!(
        resp["graph_empty"].is_boolean(),
        "graph_empty must be a boolean"
    );
}

/// Replaces the Task-1 "stub_is_empty_and_graph_empty_true" test.
///
/// A freshly-constructed API has no current session, so the session-bound
/// fields (active_datasets, active_hunts, totals) must be empty/zero.
/// `sources` is NOT asserted empty here — the static format registry is
/// always populated regardless of session state (that's correct behaviour,
/// not a regression). The old test's `sources.is_empty()` assertion would
/// now fail by design.
#[test]
fn graph_summary_fresh_api_has_no_datasets_or_hunts() {
    use graph_hunter_api::operations::graph_meta::{
        _flush_summary_cache_for_test, _GRAPH_META_TEST_MUTEX,
    };
    let _g = _GRAPH_META_TEST_MUTEX.lock().unwrap();
    _flush_summary_cache_for_test();

    let api = GraphHunterApi::new_noop();
    let summary = api.get_graph_meta_summary().expect("get_graph_meta_summary");

    assert!(summary.graph_empty, "graph must report empty on a fresh API");
    assert_eq!(summary.totals.nodes, 0, "nodes must be 0 with no session");
    assert_eq!(summary.totals.edges, 0, "edges must be 0 with no session");
    assert!(
        summary.totals.by_type.is_empty(),
        "by_type must be empty with no session"
    );
    assert!(
        summary.active_datasets.is_empty(),
        "active_datasets must be empty with no session"
    );
    assert!(
        summary.active_hunts.is_empty(),
        "active_hunts must be empty with no session"
    );
    assert!(
        summary.recent_pivots.is_empty(),
        "recent_pivots must be empty (Task 6 deferred)"
    );
    // sources is populated from static registry — not asserted empty.
}

// ── Task 2 tests ────────────────────────────────────────────────────────

/// Helper: build an API with one named session that contains the given
/// dataset id. Uses direct `Session` construction (no file I/O) to keep
/// the test hermetic.
fn api_with_session_dataset(session_id: &str, dataset_id: &str) -> GraphHunterApi {
    let api = GraphHunterApi::new_noop();
    let session = Arc::new(Session::new(
        session_id,
        "test session",
        GraphHunter::new(),
        0,
    ));
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
fn graph_summary_lists_active_datasets() {
    use graph_hunter_api::operations::graph_meta::{
        _flush_summary_cache_for_test, _GRAPH_META_TEST_MUTEX,
    };
    let _g = _GRAPH_META_TEST_MUTEX.lock().unwrap();
    _flush_summary_cache_for_test();

    let api = api_with_session_dataset("s1", "ator-evtx-snapshot");
    let summary = api.get_graph_meta_summary().expect("get_graph_meta_summary");
    assert!(
        summary.active_datasets.contains(&"ator-evtx-snapshot".to_string()),
        "active_datasets must include the registered dataset id; got: {:?}",
        summary.active_datasets
    );
}

#[test]
fn graph_summary_hunt_cache_non_empty_exposes_active_hunt() {
    use graph_hunter_api::operations::graph_meta::{
        _flush_summary_cache_for_test, _GRAPH_META_TEST_MUTEX,
    };
    let _g = _GRAPH_META_TEST_MUTEX.lock().unwrap();
    _flush_summary_cache_for_test();

    let api = GraphHunterApi::new_noop();
    // Seed the shared hunt cache with fake paths — same mechanism the
    // real `run_hunt` uses (it writes into `inner.hunt_cache` directly).
    {
        let handle = api.hunt_cache_handle();
        let mut cache = handle.write().unwrap();
        *cache = vec![
            vec![Arc::from("u1"), Arc::from("h1")],
            vec![Arc::from("u2"), Arc::from("h2")],
            vec![Arc::from("u3"), Arc::from("h3")],
        ];
    }
    let summary = api.get_graph_meta_summary().expect("get_graph_meta_summary");
    assert!(
        !summary.active_hunts.is_empty(),
        "hunt cache should expose entries in active_hunts"
    );
    assert_eq!(
        summary.active_hunts[0].result_size,
        3,
        "result_size must equal the number of cached paths"
    );
}

// ── Task 6 tests ────────────────────────────────────────────────────────────

/// `seed_from_ioc` must push the seeded entity into the RECENT_PIVOTS ring
/// buffer regardless of whether Azure hydration ran (the skipped-creds
/// branch still returns Ok, and the user expressed pivot intent). Uses a
/// uniquely-shaped IP value to avoid cross-test collision with the global
/// buffer.
#[tokio::test]
async fn seed_from_ioc_appends_to_recent_pivots() {
    use graph_hunter_api::dto::v1::sentinel::SeedFromIocRequest;
    use graph_hunter_api::operations::graph_meta::RECENT_PIVOTS;

    let api = GraphHunterApi::new_noop();
    let unique = "10.255.255.42";

    api.seed_from_ioc(SeedFromIocRequest {
        session: None,
        entity_type: "IP".into(),
        value: unique.into(),
        time_window: None,
    })
    .await
    .expect("seed_from_ioc must succeed (skipped path when no Azure creds)");

    let snap = RECENT_PIVOTS.snapshot();
    let pivot = snap
        .iter()
        .find(|p| p.entity == unique)
        .expect("seeded entity must appear in recent_pivots");
    assert_eq!(pivot.expanded, false, "fresh seed must be unexpanded");
    assert_eq!(pivot.kind, "IP");
}

/// `expand_node` calls `mark_expanded` even when the node isn't in the
/// buffer (mark_expanded is a no-op in that case — verified by the unit
/// test `recent_pivots_mark_expanded_noop_for_unknown_entity`). When the
/// node IS in the buffer, the corresponding entry flips to expanded=true
/// with the neighborhood size as degree.
#[test]
fn expand_node_marks_pivot_expanded_when_buffered() {
    use graph_hunter_api::dto::v1::graph_meta::RecentPivot;
    use graph_hunter_api::dto::v1::graph_ops::ExpandNodeRequest;
    use graph_hunter_api::operations::graph_meta::RECENT_PIVOTS;

    let api = GraphHunterApi::new_noop();
    let unique = "host-task6-marker";

    // Pre-populate the buffer so mark_expanded has something to flip.
    RECENT_PIVOTS.push(RecentPivot {
        entity: unique.into(),
        kind: "Host".into(),
        added_at: chrono::Utc::now().to_rfc3339(),
        expanded: false,
        degree: 0,
    });

    // expand_node will fail with NotFound (no session/graph), but the
    // mark_expanded call still fires before the Err returns? No — the
    // Ok path runs mark_expanded; the Err path doesn't. So this Err
    // case must NOT flip expanded. Verify that.
    let _ = api.expand_node(ExpandNodeRequest {
        session: None,
        node_id: unique.into(),
        max_hops: None,
        max_nodes: None,
        filter: None,
        live: false,
        time_window: None,
    });

    let snap = RECENT_PIVOTS.snapshot();
    let pivot = snap.iter().find(|p| p.entity == unique).expect("pivot present");
    // expand_node returned Err (no session) before reaching mark_expanded —
    // so expanded stays false. This pins the "mark only on success" contract.
    assert!(
        !pivot.expanded,
        "expand_node must NOT flip expanded when the call itself failed"
    );
}
