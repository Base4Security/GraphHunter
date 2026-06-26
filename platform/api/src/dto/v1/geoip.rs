//! DTOs for GeoIP enrichment + runtime capabilities.

use crate::state::SessionHandle;
use graph_hunter_core::geoip::GeoIpResult;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnrichIpRequest {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session: Option<SessionHandle>,
    pub ip: String,
}

pub type EnrichIpResponse = GeoIpResult;

/// Report of which on-demand enrichment backends are available to the
/// current process. Surfaced alongside `ApiTestResult` and in
/// `get_graph_summary` so the UI (and MCP clients) can tell the analyst
/// up front that e.g. GeoIP is off and they should rely on dataset
/// metadata instead of calling `enrich_ip` only to be told mid-hunt
/// that the provider is missing.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Capabilities {
    pub geoip: bool,
    pub asn: bool,
    pub threat_intel: bool,
}

/// Result of pinging the local HTTP API + reporting capabilities.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiTestResult {
    pub ok: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub status: Option<u16>,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub body: Option<String>,
    #[serde(default)]
    pub capabilities: Capabilities,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct GraphSummaryRequest {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session: Option<SessionHandle>,
}

/// Active state of the session graph, derived from its entity/relation
/// counts. Surfaced alongside the raw counts so clients can report
/// "empty / partial / populated" as an explicit signal rather than
/// inferring it — the graph-first design principle that an empty graph
/// should actively say so (and how to populate it).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GraphState {
    Empty,
    Partial,
    Populated,
}

impl GraphState {
    /// Classify a graph by its counts, returning the state plus an
    /// analyst-facing advisory. Only empty/partial graphs get an advisory
    /// — a populated graph needs no nudge. Shared by `get_graph_summary`
    /// and `/health` so both report the same state from one set of
    /// thresholds.
    pub fn classify(entity_count: usize, relation_count: usize) -> (GraphState, Option<String>) {
        // A seed/cold-start typically lands a handful of entities; below this
        // (or with no edges at all) the graph isn't yet worth traversing.
        const PARTIAL_MAX_ENTITIES: usize = 10;
        if entity_count == 0 {
            return (
                GraphState::Empty,
                Some(
                    "Graph is empty — run sentinel_seed (cold-start from an IoC) or \
                     sentinel_schema (discover which tables/fields are worth building) to begin. \
                     Raw KQL bypasses GraphHunter's correlated, persistent graph."
                        .to_string(),
                ),
            );
        }
        if relation_count == 0 || entity_count < PARTIAL_MAX_ENTITIES {
            return (
                GraphState::Partial,
                Some(
                    "Graph is sparsely populated (seed-sized) — expand it with node_expand / \
                     node_enrich before hunting so paths and anomalies have structure to \
                     traverse."
                        .to_string(),
                ),
            );
        }
        (GraphState::Populated, None)
    }
}

/// `GraphSummary` wrapped with the on-demand enrichment capabilities
/// of this process. Flatten keeps the response backwards-compatible
/// with clients that only consumed the original fields.
#[derive(Debug, Clone, Serialize)]
pub struct GraphSummaryWithCapabilities {
    #[serde(flatten)]
    pub summary: graph_hunter_core::GraphSummary,
    pub capabilities: Capabilities,
    /// Active graph state derived from the summary counts. See
    /// [`GraphState::classify`].
    pub graph_state: GraphState,
    /// Advisory nudge for empty/partial graphs; omitted when populated.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub advisory: Option<String>,
    /// The most recent `graph_build` for this session (§5), or `null` when the
    /// graph has not been materialized via a proposal.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_build: Option<crate::dto::sentinel::BuildRecord>,
}
