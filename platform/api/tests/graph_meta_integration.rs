//! Integration tests for `GraphHunterApi::get_graph_meta_summary` (Task 1).
//!
//! The test harness follows the existing pattern in `platform/api/tests/`:
//! construct a `GraphHunterApi` via `new_noop()` and call methods directly
//! (no HTTP layer). The shape assertions mirror the JSON contract that the
//! MCP TypeScript client and the frontend badge will consume.

use graph_hunter_api::GraphHunterApi;
use serde_json::Value;

#[test]
fn graph_summary_returns_schema_v1_shape() {
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

#[test]
fn graph_summary_stub_is_empty_and_graph_empty_true() {
    let api = GraphHunterApi::new_noop();
    let summary = api.get_graph_meta_summary().expect("get_graph_meta_summary");

    assert!(summary.graph_empty, "stub must report graph_empty = true");
    assert_eq!(summary.totals.nodes, 0, "stub nodes must be 0");
    assert_eq!(summary.totals.edges, 0, "stub edges must be 0");
    assert!(
        summary.totals.by_type.is_empty(),
        "stub by_type must be empty"
    );
    assert!(summary.sources.is_empty(), "stub sources must be empty");
    assert!(
        summary.active_datasets.is_empty(),
        "stub active_datasets must be empty"
    );
    assert!(
        summary.active_hunts.is_empty(),
        "stub active_hunts must be empty"
    );
    assert!(
        summary.recent_pivots.is_empty(),
        "stub recent_pivots must be empty"
    );
}
