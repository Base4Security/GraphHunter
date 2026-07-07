//! DTOs for graph operation commands (reads, runs, etc.).
//!
//! Fase 1 migrates the simpler read-only ops first. Hunt and ingest
//! operations land in Fase 2.

use std::collections::HashMap;

use crate::state::SessionHandle;
use serde::{Deserialize, Serialize};

// ── Subgraph wire shape ─────────────────────────────────────────────────

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SubgraphNode {
    pub id: String,
    pub entity_type: String,
    pub score: f64,
    pub metadata: HashMap<String, String>,
    /// Per analyst feedback (2026-04-10): for IP entities carry a pre-
    /// computed Private/Public/Loopback/… classification so the UI never
    /// has to re-parse IPs per render. `None` for non-IP entities.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ip_class: Option<String>,
}

impl SubgraphNode {
    pub fn new(
        id: String,
        entity_type: String,
        score: f64,
        metadata: HashMap<String, String>,
    ) -> Self {
        let ip_class = crate::util::ip_class_for(&entity_type, &id);
        Self {
            id,
            entity_type,
            score,
            metadata,
            ip_class,
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SubgraphEdge {
    pub source: String,
    pub target: String,
    pub rel_type: String,
    pub timestamp: i64,
    pub metadata: HashMap<String, String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dataset_id: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Subgraph {
    pub nodes: Vec<SubgraphNode>,
    pub edges: Vec<SubgraphEdge>,
    /// 2026-05-06: pagination envelope. `total_edges` is the full
    /// count induced by `node_ids` before the page cap; `has_more`
    /// tells the caller whether `offset + page_size` is enough to
    /// see the rest. Older clients that ignore these fields keep
    /// working — the semantics of the legacy default cap (5 000) is
    /// preserved when `page_size` is omitted.
    #[serde(default)]
    pub total_edges: usize,
    #[serde(default)]
    pub returned_edges: usize,
    #[serde(default)]
    pub offset: usize,
    #[serde(default)]
    pub page_size: usize,
    #[serde(default)]
    pub has_more: bool,
}

impl Default for Subgraph {
    /// Empty subgraph with zeroed pagination envelope. Lets callers and
    /// tests build instances with `Subgraph { nodes, edges, ..Default::default() }`
    /// when they don't care about the pagination metadata (RH-P1-013).
    fn default() -> Self {
        Self {
            nodes: Vec::new(),
            edges: Vec::new(),
            total_edges: 0,
            returned_edges: 0,
            offset: 0,
            page_size: 0,
            has_more: false,
        }
    }
}

/// Paginated events response for the Event View panel.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PaginatedEvents {
    pub events: Vec<SubgraphEdge>,
    pub total_count: usize,
    pub page: usize,
    pub page_size: usize,
}

/// Filter struct received from the frontend for neighborhood expansion.
/// `Deserialize` only — this is pure input, never rendered.
#[derive(Debug, Clone, Deserialize, Serialize, Default)]
pub struct ExpandFilter {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub entity_types: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub relation_types: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub time_start: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub time_end: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub min_score: Option<f64>,
}

// ── Request DTOs ────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EventsForNodeRequest {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session: Option<SessionHandle>,
    pub node_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EventsPaginatedRequest {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session: Option<SessionHandle>,
    pub node_id: String,
    pub page: usize,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub page_size: Option<usize>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sort_by: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SubgraphRequest {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session: Option<SessionHandle>,
    pub node_ids: Vec<String>,
    /// Cap on returned edges. `None` keeps the legacy 5 000 default;
    /// hard ceiling of 50 000 to keep responses bounded.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub page_size: Option<usize>,
    /// Number of edges to skip before starting the page.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub offset: Option<usize>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SearchEntitiesRequest {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session: Option<SessionHandle>,
    pub query: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub type_filter: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub limit: Option<usize>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExpandNodeRequest {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session: Option<SessionHandle>,
    pub node_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_hops: Option<usize>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_nodes: Option<usize>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub filter: Option<ExpandFilter>,
    /// When true, hydrate the target node from Sentinel before expanding
    /// (Enfoque A). Ignored on non-Sentinel sessions (soft no-op).
    #[serde(default)]
    pub live: bool,
    /// Time window for the hydration KQL. Defaults to 24h when absent.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub time_window: Option<crate::dto::v1::sentinel::TimeWindow>,
}

// ── Graph-cycle analysis: neighbors (§4.5) + paths (§4.4) ──────────────

/// An entity referenced by `{class, value}` (design doc §4.4/§4.5). Only
/// `value` is used to resolve the node (it is the graph id); `class` is
/// advisory context from the caller.
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
pub struct EntityRef {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub class: Option<String>,
    pub value: String,
}

/// `graph_neighbors` input (§4.5).
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
pub struct GraphNeighborsRequest {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session: Option<SessionHandle>,
    pub entity: EntityRef,
    /// Neighborhood expansion degree (hops). Default 1.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub degree: Option<usize>,
    /// Restrict to these edge (relation) types.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub edge_filter: Option<Vec<String>>,
    /// Cap neighbors returned (default 100).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_nodes: Option<usize>,
}

#[derive(Debug, Clone, Serialize)]
pub struct NeighborsCenter {
    pub class: String,
    pub value: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct NeighborRef {
    pub class: String,
    pub value: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct NeighborItem {
    pub edge: String,
    pub node: NeighborRef,
    #[serde(skip_serializing_if = "HashMap::is_empty")]
    pub attributes: HashMap<String, String>,
}

/// `graph_neighbors` output (§4.5): the central entity's attributes plus its
/// directly-connected entities and the edge metadata to each.
#[derive(Debug, Clone, Serialize)]
pub struct GraphNeighborsResult {
    pub entity: NeighborsCenter,
    #[serde(skip_serializing_if = "HashMap::is_empty")]
    pub attributes: HashMap<String, String>,
    pub neighbors: Vec<NeighborItem>,
}

/// `graph_path` input (§4.4).
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
pub struct GraphPathRequest {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session: Option<SessionHandle>,
    pub from_entity: EntityRef,
    /// Destination; when omitted, returns all outbound paths up to `max_depth`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub to_entity: Option<EntityRef>,
    /// Maximum hop depth (default 4).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_depth: Option<usize>,
    /// Restrict traversal to these edge (relation) types.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub edge_filter: Option<Vec<String>>,
    /// Cap on paths returned (default 50).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_paths: Option<usize>,
}

#[derive(Debug, Clone, Serialize)]
pub struct PathNode {
    pub class: String,
    pub value: String,
    /// Country (or country code) when the node carries geoip enrichment.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub geoip: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct PathHopDto {
    /// Relation type taken into `node`; absent on the origin hop.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub edge: Option<String>,
    pub node: PathNode,
}

#[derive(Debug, Clone, Serialize)]
pub struct PathDto {
    /// Hop count (edges) — `hops.len() - 1`.
    pub length: usize,
    pub hops: Vec<PathHopDto>,
}

/// `graph_path` output (§4.4).
#[derive(Debug, Clone, Serialize)]
pub struct GraphPathResult {
    pub paths: Vec<PathDto>,
}

/// `graph_anomaly` input (§4.6).
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
pub struct GraphAnomalyRequest {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session: Option<SessionHandle>,
    /// `degree` | `betweenness` | `isolation` | `all` (default `all`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub metric: Option<String>,
    /// Restrict analysis to one node class (also scopes the z-score baseline).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub node_class: Option<String>,
    /// Number of anomalies to return (default 20).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub top_n: Option<usize>,
}

#[derive(Debug, Clone, Serialize)]
pub struct AnomalyItem {
    pub entity: NeighborRef,
    pub metric: String,
    pub observation: String,
    pub z_score: f64,
}

/// `graph_anomaly` output (§4.6).
#[derive(Debug, Clone, Serialize)]
pub struct GraphAnomalyResult {
    pub anomalies: Vec<AnomalyItem>,
}

/// Node and edge counts for the resolved session's graph.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GraphStats {
    pub entity_count: usize,
    pub relation_count: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PreviewFieldsRequest {
    pub path: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sample_size: Option<usize>,
}

/// Runtime capability info not tied to any session (SIMD ISA, build
/// features). Served from `runtime_info()` — replaces the ad-hoc
/// `cmd_get_simd_isa` and future `cmd_test_http_api` payloads.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuntimeInfo {
    pub simd_isa: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ComputeScoresRequest {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session: Option<SessionHandle>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct HeavyEdgesRequest {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session: Option<SessionHandle>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub top_n: Option<usize>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub min_count: Option<usize>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rel_type: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ChannelBehaviorRequest {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session: Option<SessionHandle>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub top_n: Option<usize>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub min_count: Option<usize>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub window_secs: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rel_type: Option<String>,
    /// "beacon" (default) | "resets" | "volume"
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sort_by: Option<String>,
}
