//! Cross-side schema_version drift guard.
//!
//! Pinned against the shared fixture at
//! `platform/mcp/tests/fixtures/summary.v1.golden.json` so the Rust DTO
//! and the TypeScript zod schema cannot drift without breaking one of
//! the two halves of this golden test pair.
//!
//! Bumping GRAPH_META_SCHEMA_VERSION requires updating:
//!   1. The constant in platform/api/src/dto/v1/graph_meta.rs
//!   2. The zod literal in platform/mcp/src/lib/graph-state-client.ts
//!   3. The fixture at platform/mcp/tests/fixtures/summary.v1.golden.json
//! In that order, with the corresponding migration plan documented.

use graph_hunter_api::dto::v1::graph_meta::GraphSummary;
use std::path::PathBuf;

fn golden_path() -> PathBuf {
    // CARGO_MANIFEST_DIR = platform/api at test compile time.
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("mcp")
        .join("tests")
        .join("fixtures")
        .join("summary.v1.golden.json")
}

#[test]
fn serde_accepts_the_shared_v1_golden_fixture() {
    let path = golden_path();
    let raw = std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("fixture must exist at {path:?}: {e}"));
    let parsed: GraphSummary =
        serde_json::from_str(&raw).expect("serde must accept the v1 golden fixture");
    assert_eq!(parsed.schema_version, 1);
    assert!(parsed.graph_empty);
    assert_eq!(parsed.totals.nodes, 0);
    assert_eq!(parsed.totals.edges, 0);
    assert!(parsed.totals.by_type.is_empty());
    assert!(parsed.sources.is_empty());
    assert!(parsed.active_datasets.is_empty());
    assert!(parsed.active_hunts.is_empty());
    assert!(parsed.recent_pivots.is_empty());
}
