//! F4.9 — `/v1/schema` producer.
//!
//! Returns a static list of endpoint metadata. The list is hand-coded
//! rather than derived so that "renaming a route" is an explicit,
//! reviewable change in a single file — exactly the signal MCP
//! contract tests key on.
//!
//! Invariant: every path used by a tool in `platform/mcp/src/tools/`
//! MUST appear in the list returned by `get_schema`. The MCP
//! contract suite (`platform/mcp/tests/contract/schema.test.ts`)
//! enforces this at CI time.

use crate::GraphHunterApi;
use crate::dto::schema::{EndpointMeta, HttpMethod, SchemaResponse, Stability};

/// Bump when the schema response **shape** breaks. Additive endpoint
/// additions do NOT bump this.
const SCHEMA_CONTRACT_VERSION: &str = "1.0.0";

impl GraphHunterApi {
    pub fn get_schema(&self) -> SchemaResponse {
        SchemaResponse {
            version: SCHEMA_CONTRACT_VERSION.to_string(),
            endpoints: known_endpoints(),
        }
    }
}

/// Stable list — append-only. Removing an entry is a breaking change.
fn known_endpoints() -> Vec<EndpointMeta> {
    fn ep(path: &str, method: HttpMethod, description: &str, heavy: bool) -> EndpointMeta {
        EndpointMeta {
            path: path.to_string(),
            method,
            description: description.to_string(),
            heavy,
            stability: Stability::Stable,
        }
    }

    use HttpMethod::{Get, Post};
    vec![
        // --- Self-describing + navigation ----------------------------
        ep(
            "/v1/schema",
            Get,
            "Return the list of stable endpoints + contract version.",
            false,
        ),
        ep(
            "/health",
            Get,
            "Process health + GNN model status probe.",
            false,
        ),
        ep(
            "/entity_types",
            Get,
            "Entity types present in the current session's graph.",
            false,
        ),
        ep(
            "/search",
            Get,
            "Substring search over entity IDs and metadata.",
            false,
        ),
        ep(
            "/expand",
            Get,
            "Expand a node to its 1..N-hop neighborhood.",
            true,
        ),
        ep(
            "/node_details",
            Get,
            "Full per-node details: scores, degrees, neighbors.",
            true,
        ),
        ep(
            "/subgraph",
            Post,
            "Fetch the subgraph (nodes + edges) for a list of node IDs.",
            true,
        ),
        ep(
            "/events_for_node",
            Get,
            "Every edge/event touching a node.",
            true,
        ),
        ep(
            "/relation_schema",
            Get,
            "Observed (rel_type, source_type, target_type) triples + metadata keys.",
            false,
        ),
        ep(
            "/events_paginated",
            Get,
            "Paginated, sortable edges for a node.",
            true,
        ),
        ep(
            "/expand_grouped",
            Get,
            "Neighborhood with grouped edges for high-degree nodes.",
            true,
        ),
        // --- Hunting -------------------------------------------------
        ep(
            "/run_hunt",
            Post,
            "Execute a DSL hypothesis over the loaded graph.",
            true,
        ),
        ep(
            "/hunt_results",
            Get,
            "One page of the most recent run_hunt output.",
            false,
        ),
        ep(
            "/parse_dsl",
            Post,
            "Validate a DSL pattern without executing it.",
            false,
        ),
        ep(
            "/diff_hunts",
            Post,
            "Compare hunt output at two time bounds.",
            true,
        ),
        ep(
            "/export_hunt_results",
            Post,
            "Serialize hunt paths as JSON or CSV text.",
            true,
        ),
        ep(
            "/save_hypothesis_as_sigma",
            Post,
            "Convert a DSL hypothesis to a Sigma rule YAML.",
            true,
        ),
        // --- Scoring -------------------------------------------------
        ep(
            "/enable_anomaly_scoring",
            Post,
            "Turn on anomaly-based scoring for subsequent hunts.",
            false,
        ),
        ep(
            "/compute_scores",
            Post,
            "Recompute centrality / PageRank / betweenness over the graph.",
            true,
        ),
        ep(
            "/explain_score",
            Get,
            "4-dimension anomaly breakdown + percentiles + peers for a node.",
            false,
        ),
        // --- Graph views --------------------------------------------
        ep(
            "/graph_summary",
            Get,
            "Session-wide counts, type mix, time range, top anomalies.",
            false,
        ),
        ep(
            "/entity_type_counts",
            Get,
            "Per-type entity counts for the loaded graph.",
            false,
        ),
        ep(
            "/temporal_heatmap",
            Get,
            "Bucketed activity volumes per relation type.",
            true,
        ),
        ep(
            "/subnet_analysis",
            Get,
            "Group IP entities by /24 subnet with aggregates.",
            true,
        ),
        // --- Catalogs ------------------------------------------------
        ep(
            "/catalog",
            Get,
            "Pre-built ATT&CK hypothesis catalog.",
            false,
        ),
        ep(
            "/catalog/status",
            Get,
            "Catalog entries annotated with per-entry compatibility.",
            false,
        ),
        ep(
            "/catalog/diagnostics",
            Get,
            "Catalog loader diagnostics from startup.",
            false,
        ),
        ep(
            "/datasets",
            Get,
            "Ingested datasets in the current session.",
            false,
        ),
        // --- Notes / path nodes / tags ------------------------------
        ep(
            "/notes",
            Post,
            "Append an analyst note to the session.",
            false,
        ),
        ep(
            "/notes/list",
            Get,
            "List every note in the current session.",
            false,
        ),
        ep(
            "/path_nodes",
            Get,
            "List pinned investigation waypoints.",
            false,
        ),
        ep(
            "/tag",
            Post,
            "Apply a tag (e.g. `ioc:malicious`) to an entity.",
            false,
        ),
        ep("/untag", Post, "Remove a previously applied tag.", false),
        ep(
            "/tags",
            Get,
            "List tagged entities (with optional prefix filter).",
            false,
        ),
        // --- Export --------------------------------------------------
        ep(
            "/export_subgraph",
            Post,
            "Export a subgraph as JSON or CSV text.",
            true,
        ),
        ep(
            "/export_ocsf",
            Post,
            "Export session triples as OCSF v1.4 + Provenance Extension events.",
            true,
        ),
        ep(
            "/export_iocs",
            Post,
            "Emit session tags as a STIX / MISP / KQL / Sigma feed.",
            true,
        ),
        // --- Data quality -------------------------------------------
        ep(
            "/check_invariants",
            Post,
            "Run P1..P4 first-order invariants + treewidth estimate.",
            true,
        ),
        ep(
            "/schema_drift_detect",
            Post,
            "Per-field drift signals + recommended action.",
            false,
        ),
        ep(
            "/mapping_regression_test",
            Post,
            "Replay a dataset through a candidate VRL and diff.",
            true,
        ),
        ep(
            "/invariant_check_hypothetical",
            Post,
            "Invariant suite over a synthetic graph from candidate VRL.",
            true,
        ),
        ep(
            "/list_dead_letters",
            Post,
            "Paginate rows rejected by the ingest pipeline.",
            false,
        ),
        ep(
            "/reingest_dead_letter",
            Post,
            "Retry DLQ entries with the current FieldConfig.",
            true,
        ),
        ep(
            "/purge_dead_letters",
            Post,
            "Bulk-remove DLQ entries by filter.",
            false,
        ),
        // --- Agentic slow-lane --------------------------------------
        ep(
            "/ingest_negotiate",
            Post,
            "Propose a FieldConfig for a raw log sample.",
            true,
        ),
        ep(
            "/canonical_map",
            Post,
            "Map a FieldConfig onto an OCSF category + provenance stamp.",
            false,
        ),
        ep(
            "/parser_generate",
            Post,
            "Compile a FieldConfig to a deterministic VRL program.",
            true,
        ),
        ep(
            "/agentic_review_list",
            Post,
            "List MappingDrafts in the review queue.",
            false,
        ),
        ep(
            "/agentic_review_approve",
            Post,
            "Approve a pending MappingDraft.",
            false,
        ),
        ep(
            "/agentic_review_reject",
            Post,
            "Reject a pending MappingDraft with a reason.",
            false,
        ),
        ep(
            "/publish_mapping",
            Post,
            "Force-publish a draft to the shared mapping library.",
            false,
        ),
        ep(
            "/fetch_shared_mappings",
            Post,
            "List published mappings from the shared library.",
            false,
        ),
        // --- Integrations -------------------------------------------
        ep(
            "/enrich_ip",
            Post,
            "GeoIP enrichment for a public IP address.",
            false,
        ),
        ep(
            "/file_ticket",
            Post,
            "Create a Jira / ServiceNow ticket with hunt context.",
            true,
        ),
        ep(
            "/publish_iocs_to_sentinel",
            Post,
            "Publish tagged IoCs as an Azure Sentinel Watchlist.",
            true,
        ),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn schema_lists_expected_endpoints() {
        let api = GraphHunterApi::new_noop();
        let s = api.get_schema();
        assert_eq!(s.version, SCHEMA_CONTRACT_VERSION);
        let paths: Vec<&str> = s.endpoints.iter().map(|e| e.path.as_str()).collect();
        assert!(paths.contains(&"/health"), "health must be registered");
        assert!(
            paths.contains(&"/entity_types"),
            "entity_types must be registered"
        );
        assert!(
            paths.contains(&"/v1/schema"),
            "schema endpoint is self-describing"
        );
        assert!(paths.contains(&"/run_hunt"), "hunting must be registered");
        assert!(paths.contains(&"/export_ocsf"), "export must be registered");
        assert!(
            paths.contains(&"/check_invariants"),
            "data-quality must be registered"
        );
    }

    #[test]
    fn schema_serializes_method_uppercase_and_stability_lowercase() {
        let api = GraphHunterApi::new_noop();
        let s = api.get_schema();
        let v = serde_json::to_value(&s).unwrap();
        let first = &v["endpoints"][0];
        let method = first["method"].as_str().unwrap();
        assert!(method == "GET" || method == "POST");
        assert_eq!(first["stability"], "stable");
    }

    #[test]
    fn schema_omits_heavy_when_false() {
        let api = GraphHunterApi::new_noop();
        let s = api.get_schema();
        let v = serde_json::to_value(&s).unwrap();
        // At least one entry is non-heavy (e.g. /health). Non-heavy entries
        // should hide the field entirely rather than emit `"heavy": false`.
        let health = v["endpoints"]
            .as_array()
            .unwrap()
            .iter()
            .find(|ep| ep["path"] == "/health")
            .expect("health endpoint present");
        assert!(
            health.get("heavy").is_none(),
            "heavy=false should be omitted: {health}"
        );
    }

    #[test]
    fn schema_surfaces_heavy_flag_when_true() {
        let api = GraphHunterApi::new_noop();
        let s = api.get_schema();
        let v = serde_json::to_value(&s).unwrap();
        let run_hunt = v["endpoints"]
            .as_array()
            .unwrap()
            .iter()
            .find(|ep| ep["path"] == "/run_hunt")
            .expect("/run_hunt present");
        assert_eq!(run_hunt["heavy"], true);
    }

    #[test]
    fn schema_has_no_duplicate_paths() {
        let api = GraphHunterApi::new_noop();
        let s = api.get_schema();
        let mut paths: Vec<&str> = s.endpoints.iter().map(|e| e.path.as_str()).collect();
        paths.sort();
        let len_before = paths.len();
        paths.dedup();
        assert_eq!(
            paths.len(),
            len_before,
            "duplicate paths found in schema list"
        );
    }
}
