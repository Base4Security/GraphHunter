//! DTOs for `/graph/summary` and `/graph/overlap` endpoints.
//!
//! All types carry `schema_version: u32 = GRAPH_META_SCHEMA_VERSION` so
//! clients can detect when the shape changes without relying on HTTP headers
//! or content-negotiation.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// Increment this constant when the [`GraphSummary`] shape changes in a
/// breaking way. Clients gate their parsing on this value.
pub const GRAPH_META_SCHEMA_VERSION: u32 = 1;

/// Top-level response for `GET /graph/summary`.
///
/// Returned by [`crate::GraphHunterApi::get_graph_meta_summary`]. Designed to be
/// cheap to compute: totals come from in-memory counters, not a full graph
/// scan.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct GraphSummary {
    /// Protocol version — always [`GRAPH_META_SCHEMA_VERSION`] (currently 1).
    pub schema_version: u32,
    /// RFC 3339 timestamp of when this snapshot was computed.
    pub as_of: String,
    /// Node and edge counts.
    pub totals: GraphTotals,
    /// One entry per data source the API knows about.
    pub sources: Vec<SourceState>,
    /// Dataset IDs that are loaded into the current session.
    pub active_datasets: Vec<String>,
    /// Hunt results that are still cached.
    pub active_hunts: Vec<ActiveHunt>,
    /// Most-recently-expanded pivot entities (ring buffer, up to 20).
    pub recent_pivots: Vec<RecentPivot>,
    /// Convenience flag — `true` when the graph has no nodes.
    pub graph_empty: bool,
}

/// Aggregate node + edge counts for the current session graph.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct GraphTotals {
    /// Total node count across all entity types.
    pub nodes: u64,
    /// Total edge count across all relation types.
    pub edges: u64,
    /// Per-entity-type breakdown. Keys are the `EntityType` display name
    /// (e.g. `"IP"`, `"User"`, `"Domain"`).
    pub by_type: BTreeMap<String, u64>,
}

/// State for a single named data source (log format / ingest channel).
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct SourceState {
    /// Human-readable name for the source (e.g. `"Sentinel"`, `"EVTX"`).
    pub name: String,
    /// RFC 3339 timestamp of the last successful ingest, or `None` if the
    /// source has never been ingested in this session.
    pub last_ingest: Option<String>,
    /// Cumulative row count across all ingests for this source in the
    /// current session.
    pub rows_lifetime: u64,
}

/// A hunt result that is still resident in the cache.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct ActiveHunt {
    /// Cache key used by `get_hunt_page` to paginate this result.
    pub cache_key: String,
    /// Human-readable summary of the hunt parameters.
    pub params_summary: String,
    /// Number of paths in this hunt result.
    pub result_size: u64,
    /// RFC 3339 timestamp when the hunt was computed.
    pub computed_at: String,
    /// Seconds until this entry is evicted from the cache.
    pub ttl_seconds_remaining: u64,
}

// ── /graph/overlap DTOs ────────────────────────────────────────────────────

/// Request body for `POST /graph/overlap`. Capped at 500 entities per
/// request (enforced server-side; returns HTTP 413 above the cap).
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct OverlapRequest {
    /// Protocol version — must equal [`GRAPH_META_SCHEMA_VERSION`].
    pub schema_version: u32,
    /// Entities to look up in the current session graph.
    pub entities: Vec<EntityRef>,
}

/// Hard cap on entities per `/graph/overlap` request. Above this the
/// endpoint responds with HTTP 413. The MCP client mirrors this cap.
pub const OVERLAP_MAX_ENTITIES: usize = 500;

/// A typed reference to an entity for lookup. `kind` is informational —
/// the graph engine indexes by string ID, not by entity type.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct EntityRef {
    /// Entity type tag (e.g. `"IP"`, `"User"`, `"Domain"`, `"Host"`).
    #[serde(rename = "type")]
    pub kind: String,
    /// Entity value as it appears in the graph (e.g. an IP address).
    pub value: String,
}

/// Response body for `POST /graph/overlap`. `found` and `missing`
/// together account for every entity in the request, in the same order
/// (preserved per category).
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct OverlapResponse {
    pub schema_version: u32,
    /// Entities that exist in the current session graph, with degree
    /// information.
    pub found: Vec<FoundEntity>,
    /// Entity values from the request that are NOT in the graph.
    pub missing: Vec<String>,
}

/// An entity from the request that was found in the graph.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct FoundEntity {
    pub entity: String,
    #[serde(rename = "type")]
    pub kind: String,
    /// Total degree (in + out edges).
    pub degree: u32,
    /// The neighbor with the most edges to/from this entity. `None` in v1
    /// (computation deferred to keep the endpoint fast at p99); the MCP
    /// nudge composer uses `degree` only today.
    pub top_neighbor: Option<TopNeighbor>,
}

/// The dominant neighbor of a found entity, by edge count.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct TopNeighbor {
    pub entity: String,
    #[serde(rename = "type")]
    pub kind: String,
    /// Number of distinct edges between the found entity and this neighbor.
    pub edge_count: u32,
}

// ── /graph/summary nested types ────────────────────────────────────────────

/// A single entity that the user pivoted on recently.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct RecentPivot {
    /// The entity identifier (e.g. an IP address, a username).
    pub entity: String,
    /// Entity type tag (e.g. `"IP"`, `"User"`, `"Domain"`).
    #[serde(rename = "type")]
    pub kind: String,
    /// RFC 3339 timestamp when this pivot was recorded.
    pub added_at: String,
    /// Whether the entity has been expanded in the current session.
    pub expanded: bool,
    /// Hop distance from the seed entity that originated this pivot.
    pub degree: u32,
}
