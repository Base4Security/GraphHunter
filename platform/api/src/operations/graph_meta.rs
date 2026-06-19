//! `/graph/summary` and `/graph/overlap` operation implementations.
//!
//! Task 1 (hardcoded skeleton): both methods return empty / zero data so the
//! route and DTO wiring can be tested end-to-end before live data is plumbed
//! in. Later tasks will replace the stub bodies with real graph counters,
//! recent-pivot ring buffer reads, and hunt-cache inspection.

use std::collections::BTreeMap;

use crate::dto::v1::graph_meta::{
    GraphSummary, GraphTotals, GRAPH_META_SCHEMA_VERSION,
};
use crate::{ApiResult, GraphHunterApi};

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
    /// **Task 1 stub:** all counters are zero and all lists are empty.
    /// Subsequent tasks wire in real data from `self.inner.*`.
    pub fn get_graph_meta_summary(&self) -> ApiResult<GraphSummary> {
        Ok(GraphSummary {
            schema_version: GRAPH_META_SCHEMA_VERSION,
            as_of: chrono::Utc::now().to_rfc3339(),
            totals: GraphTotals {
                nodes: 0,
                edges: 0,
                by_type: BTreeMap::new(),
            },
            sources: vec![],
            active_datasets: vec![],
            active_hunts: vec![],
            recent_pivots: vec![],
            graph_empty: true,
        })
    }
}

// ── Unit tests ────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

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
    fn get_graph_meta_summary_stub_has_zero_totals_and_empty_lists() {
        let api = GraphHunterApi::new_noop();
        let summary = api.get_graph_meta_summary().expect("get_graph_meta_summary");
        assert_eq!(summary.totals.nodes, 0);
        assert_eq!(summary.totals.edges, 0);
        assert!(summary.totals.by_type.is_empty());
        assert!(summary.sources.is_empty());
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
}
