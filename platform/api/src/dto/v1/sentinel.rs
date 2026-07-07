//! DTOs for Sentinel integrations — Watchlist publish (C.2) and the
//! real-time connector commands (C.5) go in the same module because
//! both speak to the same tenant under the same Azure creds.

use crate::sentinel_connector::ConnectorStatus;
use crate::state::SessionHandle;
use serde::{Deserialize, Serialize};

// ── Time window (Phase L) ─────────────────────────────────────────────
//
// Both `SentinelConnectRequest` and `RunKqlRequest` accept a
// `time_window: Option<TimeWindow>` so the analyst can override the
// default `ago(24h)` lookback. Hunting templates (Phase M) reuse the
// same shape via `kql_filter()` so a single picker drives every query.

/// Lookback presets that map to KQL `ago(...)` durations. Serialized
/// as the literal duration string (`"1h"`, `"24h"`, `"7d"`) so the
/// frontend's TimeWindow type can stay symmetrical with KQL syntax.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum LookbackPreset {
    #[serde(rename = "1h")]
    H1,
    #[serde(rename = "6h")]
    H6,
    #[serde(rename = "24h")]
    H24,
    #[serde(rename = "7d")]
    D7,
    #[serde(rename = "30d")]
    D30,
}

impl LookbackPreset {
    /// KQL duration literal for `ago(...)`. Symmetric with the serde
    /// rename so a round-trip serialize/deserialize is the identity.
    pub fn as_kql(self) -> &'static str {
        match self {
            Self::H1 => "1h",
            Self::H6 => "6h",
            Self::H24 => "24h",
            Self::D7 => "7d",
            Self::D30 => "30d",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum TimeWindow {
    /// `where TimeGenerated > ago(<preset>)`.
    Preset { lookback: LookbackPreset },
    /// `where TimeGenerated between (datetime(<from>) .. datetime(<to>))`.
    /// Both fields are ISO-8601 timestamps. UTC assumed when offset is
    /// missing; KQL accepts naked ISO-8601 inside `datetime(...)`.
    Absolute { from_iso: String, to_iso: String },
}

impl TimeWindow {
    /// Render the window as a KQL filter clause. The leading `where`
    /// is included so the caller can splice it into a query without
    /// position-dependent string surgery.
    pub fn kql_filter(&self) -> String {
        match self {
            Self::Preset { lookback } => {
                format!("where TimeGenerated > ago({})", lookback.as_kql())
            }
            Self::Absolute { from_iso, to_iso } => {
                format!(
                    "where TimeGenerated between (datetime({from_iso}) .. datetime({to_iso}))"
                )
            }
        }
    }
}

// ── Real-time connector lifecycle ──────────────────────────────────────

#[derive(Debug, Clone, Default, Deserialize, Serialize)]
pub struct SentinelConnectRequest {
    /// Explicit workspace id; falls back to env `AZURE_WORKSPACE_ID`
    /// when empty.
    #[serde(default)]
    pub workspace_id: String,
    #[serde(default)]
    pub azure_tenant_id: String,
    #[serde(default)]
    pub azure_client_id: String,
    #[serde(default)]
    pub azure_client_secret: String,
    /// Polling interval in seconds. Falls back to env
    /// `SENTINEL_POLL_INTERVAL_SECS` or 30s.
    #[serde(default)]
    pub poll_interval_secs: u64,
    #[serde(default)]
    pub tables: Vec<String>,
    /// Batch size per table. Env fallback:
    /// `SENTINEL_BATCH_SIZE` or 10000.
    #[serde(default)]
    pub batch_size: u32,
    /// Initial-poll time window override. `None` keeps the legacy
    /// `ago(24h)` default. Once the watermark store has a checkpoint
    /// for the connector, the watermark wins (preserves incremental
    /// polling semantics).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub time_window: Option<TimeWindow>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SentinelConnectedEvent {
    pub connector_id: String,
    pub tables: Vec<String>,
    pub poll_interval_secs: u64,
    /// True when the connector was registered paused (no polling yet).
    #[serde(default)]
    pub paused: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConnectorStatusResponse {
    pub connected: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub connector_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub status: Option<ConnectorStatus>,
}

// ── Ad-hoc KQL ─────────────────────────────────────────────────────────

#[derive(Debug, Clone, Default, Deserialize, Serialize)]
pub struct RunKqlRequest {
    #[serde(default)]
    pub kql: String,
    #[serde(default)]
    pub workspace_id: String,
    #[serde(default)]
    pub azure_tenant_id: String,
    #[serde(default)]
    pub azure_client_id: String,
    #[serde(default)]
    pub azure_client_secret: String,
    /// Soft-sugar time window (Phase L). When the analyst's `kql`
    /// already contains a `TimeGenerated` filter, this is ignored —
    /// the user's filter wins. Otherwise the dispatcher prepends a
    /// `where TimeGenerated ...` clause derived from this window.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub time_window: Option<TimeWindow>,
    /// When `Some(false)`, the query runs but results are NOT ingested
    /// into the graph — rows are returned for inspection instead. `None`
    /// is treated as `true` (ingest), preserving the legacy behavior.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ingest: Option<bool>,
    /// Cap on rows returned in inspect mode (`ingest=false`). Default 200.
    /// Ignored when ingesting (`ingest` absent or true).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_rows: Option<u32>,
    /// Optional layer name. When set (and `ingest != false`), this query's
    /// results REPLACE the existing layer with this name (snapshot) instead
    /// of appending — re-running the same query refreshes it rather than
    /// duplicating. Omit for a one-off append (random dataset id).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dataset: Option<String>,
    /// §4.7 fallback gate. An inspect-mode (`ingest != true`) query whose
    /// projection touches entity-class columns is NOT executed unless this is
    /// `true` — instead a ready-to-run `graph_propose` payload is returned to
    /// steer the analyst onto the graph path. Set `true` to acknowledge the
    /// raw-KQL escape hatch and run anyway (logged). Ignored on the ingest path.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub acknowledge_fallback: Option<bool>,
}

/// A ready-to-run `graph_propose` payload (§4.7): the table + entity-class
/// fields extracted from a raw KQL projection, so the analyst can pivot to the
/// graph path in one call instead of reading rows out via raw KQL.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GraphProposePayload {
    /// The tool to call next.
    pub next_tool: String,
    pub table: String,
    pub selected_fields: Vec<SelectedField>,
}

/// One-click hunting template (Phase M). The body is a KQL string
/// templated with a `{TIME}` placeholder that the API substitutes
/// with `time_window.kql_filter()` before dispatch.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HuntingTemplateId {
    FailedLogonBurst,
    LateralMovement,
    EncodedPowerShell,
    SuspiciousDns,
}

#[derive(Debug, Clone, Default, Deserialize, Serialize)]
pub struct RunHuntingTemplateRequest {
    pub template: Option<HuntingTemplateId>,
    #[serde(default)]
    pub workspace_id: String,
    #[serde(default)]
    pub azure_tenant_id: String,
    #[serde(default)]
    pub azure_client_id: String,
    #[serde(default)]
    pub azure_client_secret: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub time_window: Option<TimeWindow>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KqlResult {
    pub new_entities: usize,
    pub new_relations: usize,
    pub total_entities: usize,
    pub total_relations: usize,
    pub kql_executed: String,
    pub row_count: usize,
    /// Wall time of the KQL roundtrip (Phase N). `0` when the
    /// transport doesn't measure (legacy callers).
    #[serde(default)]
    pub took_ms: u64,
    /// `take N` clause that was applied to the query, when
    /// detectable. `None` when the query has no take limit.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub take_limit: Option<u32>,
    /// True when `row_count >= take_limit` — UI surfaces a "narrow
    /// your window" warning instead of a clean success log entry.
    #[serde(default)]
    pub truncated: bool,
    /// Populated only in inspect mode (`ingest=false`): the (capped) raw
    /// rows. `None` when the query was ingested. When `Some` (inspect mode),
    /// `total_entities` and `total_relations` are always 0 — the graph was
    /// not read.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rows: Option<Vec<serde_json::Value>>,
    /// Graph-first nudge: set in inspect mode (`ingest=false`) when the query
    /// touches identity/IP-like columns that could be materialized as graph
    /// entities. Steers the analyst toward `sentinel_seed` / `sentinel_schema`
    /// for recurring pivots instead of repeated raw KQL. `None` when ingesting
    /// or when the query is graph-irrelevant.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub graph_advisory: Option<String>,
    /// §4.7: ready-to-run `graph_propose` arguments derived from the query's
    /// entity-class columns. Present whenever the query is graph-relevant
    /// (both when gated and when an acknowledged fallback runs).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub graph_propose: Option<GraphProposePayload>,
    /// §4.7: `true` when the query was NOT executed because it is an
    /// unacknowledged entity-class raw-KQL fallback. Re-run with
    /// `acknowledge_fallback=true`, or follow `graph_propose`.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub fallback_gated: bool,
}

// ── Schema discovery (Phase 1 / cold-start orientation) ───────────────

/// Discover the active Sentinel tables and, per table, the fields worth
/// building a graph from. Reuses the same field classifier the ingest
/// preview uses, then annotates each field with its `graph_affinity`
/// (node | edge | attribute) and which enrichments apply. The default
/// "what's in this workspace?" call before materializing a graph.
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
pub struct SchemaDiscoverRequest {
    #[serde(default)]
    pub workspace_id: String,
    #[serde(default)]
    pub azure_tenant_id: String,
    #[serde(default)]
    pub azure_client_id: String,
    #[serde(default)]
    pub azure_client_secret: String,
    /// Sampling/aggregation window. Default `ago(24h)` when absent.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub time_window: Option<TimeWindow>,
    /// Restrict discovery to these tables (case-insensitive). Empty = all
    /// active tables in the window.
    #[serde(default)]
    pub table_filter: Vec<String>,
    /// Exclude tables whose billable ingestion in the window is below this
    /// many MB. `None` = no floor.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub min_ingestion_mb: Option<f64>,
    /// Cap on the number of tables sampled + classified (most-ingested
    /// first). Protects against one sample query per table on large
    /// workspaces. Default 25.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_tables: Option<u32>,
    /// Rows sampled per table for field classification. Default 200.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sample_rows: Option<u32>,
}

/// One field within a discovered table, annotated for graph construction.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SchemaField {
    pub name: String,
    /// Coarse JSON type inferred from sample values: `string` | `number`
    /// | `bool`.
    pub r#type: String,
    /// `high` | `low` — distinctness in the sample. High-cardinality
    /// identifier-like fields make the best graph nodes.
    pub cardinality: String,
    /// `node` | `edge` | `attribute` — the field's role in the graph.
    pub graph_affinity: String,
    /// Canonical entity class when `graph_affinity == "node"` (IP, User,
    /// Host, …).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub node_class: Option<String>,
    /// Enrichments that apply to this field's entity type (e.g. `geoip`,
    /// `asn` for IPs). Empty when none apply.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub enrichable: Vec<String>,
    /// Up to 5 distinct sample values, for orientation.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub sample_values: Vec<String>,
}

/// A discovered Sentinel table with its classified fields.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SchemaTable {
    pub name: String,
    /// Billable ingestion in the sampling window (MB), from the `Usage` table.
    /// Named per design doc §4.1; reflects the request `lookback` window
    /// (default 24h).
    #[serde(rename = "ingestion_24h_mb", skip_serializing_if = "Option::is_none")]
    pub ingestion_24h_mb: Option<f64>,
    /// Most recent ingestion timestamp in the window (ISO-8601).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_ingested: Option<String>,
    pub fields: Vec<SchemaField>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SchemaDiscoverResult {
    pub tables: Vec<SchemaTable>,
    /// Total active tables discovered (after filtering, before the
    /// `max_tables` cap).
    pub total_tables: usize,
    /// Set when fewer tables were introspected than discovered (cap hit)
    /// — surfaced so the cap is never silent.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
    /// Aggregate Sentinel query cost for this discovery (usage probe + per-table
    /// samples). Lets analysts measure SIEM usage. `None` when the service
    /// returned no statistics.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cost: Option<QueryCost>,
}

/// Serializable Sentinel query cost surfaced in tool responses. `wall_ms` is
/// measured locally; the other two come from the Log Analytics `statistics`
/// object (see `graph_hunter_siem::QueryStats`).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct QueryCost {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bytes_scanned: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub server_duration_ms: Option<u64>,
    /// Wall-clock time spent in Sentinel round-trips for this tool call.
    pub wall_ms: u64,
}

// ── Graph cycle: proposals (§4.2) + build records (§4.3 / §5) ──────────

/// A node in a proposed graph schema: an entity class sourced from a
/// `Table.Field` column, optionally enriched at build time.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProposalNode {
    /// Entity class (engine `EntityType` name: IP, User, Host, …).
    pub class: String,
    /// `Table.Field` the node value is drawn from.
    pub source: String,
    /// Enrichments to apply to this node's entities at build (e.g. geoip, asn).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub enrich: Vec<String>,
}

/// An edge in a proposed graph schema, connecting two node classes.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProposalEdge {
    /// Relation type label (e.g. `authenticated_from`).
    pub r#type: String,
    pub from: String,
    pub to: String,
    /// Result columns carried onto the edge as metadata.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub attributes: Vec<String>,
}

/// A candidate graph schema (§4.2). Emitted by `graph_propose`, persisted in
/// the session, and executed by `graph_build` via `materialization_kql`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GraphProposal {
    pub proposal_id: String,
    pub description: String,
    pub nodes: Vec<ProposalNode>,
    pub edges: Vec<ProposalEdge>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub estimated_entities: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub estimated_relations: Option<u64>,
    /// Exact KQL `graph_build` runs to materialize this schema.
    pub materialization_kql: String,
}

/// A `{table, field}` the analyst picked from `schema_discover` to build a
/// graph from. Input to `graph_propose`.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct SelectedField {
    pub table: String,
    pub field: String,
}

/// `graph_propose` input (§4.2): selected fields + optional hunt context.
/// Azure creds are optional — they're only used for a best-effort
/// `estimated_entities/relations` probe; proposal generation itself is offline.
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
pub struct GraphProposeRequest {
    #[serde(default)]
    pub workspace_id: String,
    #[serde(default)]
    pub azure_tenant_id: String,
    #[serde(default)]
    pub azure_client_id: String,
    #[serde(default)]
    pub azure_client_secret: String,
    pub selected_fields: Vec<SelectedField>,
    /// Free-text hunt description to orient the proposal's `description`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hypothesis_context: Option<String>,
    /// Max candidate schemas to return (default 3).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_proposals: Option<u32>,
    /// Window spliced into `materialization_kql` and the estimate probe
    /// (default `ago(24h)`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub time_window: Option<TimeWindow>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GraphProposeResult {
    pub proposals: Vec<GraphProposal>,
    /// Cost of the best-effort estimate probes; absent when no probe ran
    /// (e.g. no Azure creds).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cost: Option<QueryCost>,
}

/// `graph_build` input (§4.3): materialize an approved proposal by id.
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
pub struct GraphBuildRequest {
    #[serde(default)]
    pub workspace_id: String,
    #[serde(default)]
    pub azure_tenant_id: String,
    #[serde(default)]
    pub azure_client_id: String,
    #[serde(default)]
    pub azure_client_secret: String,
    /// Id of a proposal previously emitted by `graph_propose` (session-scoped).
    pub proposal_id: String,
    /// Materialization window. The proposal's `materialization_kql` already
    /// carries a `TimeGenerated` filter, which wins; this only applies when the
    /// stored KQL lacks one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub time_window: Option<TimeWindow>,
    /// Enrichments to apply at build (`geoip`, `asn`). Default: all declared on
    /// the schema. `threat_intel` is accepted but a no-op until a feed is wired.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub enrich: Option<Vec<String>>,
    /// `append` (default) — add to the existing graph — or `replace` — refresh
    /// this proposal's prior build (snapshot).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub merge_mode: Option<String>,
}

/// Per-enrichment counts applied during a build (§4.3 `enrichment_applied`).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct EnrichmentApplied {
    pub geoip: usize,
    pub asn: usize,
    /// Always 0 today — honest stub until a threat-intel feed is configured.
    pub threat_intel: usize,
}

/// `graph_build` output (§4.3).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GraphBuildResult {
    pub build_id: String,
    pub proposal_id: String,
    pub entities_created: usize,
    pub relations_created: usize,
    pub enrichment_applied: EnrichmentApplied,
    pub duration_ms: u64,
    /// Active graph state after the build (`empty` | `partial` | `populated`).
    pub graph_state: crate::dto::geoip::GraphState,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cost: Option<QueryCost>,
}

/// Record of the most recent `graph_build`, surfaced in §5 status (`last_build`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BuildRecord {
    pub build_id: String,
    pub proposal_id: String,
    /// Unix seconds when the build completed.
    pub at: i64,
    pub entities_created: usize,
    pub relations_created: usize,
    /// `append` | `replace`.
    pub merge_mode: String,
}

// ── Env probe ──────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SentinelEnvStatus {
    pub azure_client_id: Option<String>,
    pub azure_client_secret_set: bool,
    pub azure_client_secret_masked: Option<String>,
    pub azure_tenant_id: Option<String>,
    pub azure_subscription_id: Option<String>,
    pub azure_resource_group: Option<String>,
    pub azure_workspace_id: Option<String>,
    pub azure_workspace_name: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PublishIocsRequest {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session: Option<SessionHandle>,
    pub watchlist_name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub display_name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tag_prefix: Option<String>,
    #[serde(default)]
    pub dry_run: bool,
    #[serde(default)]
    pub confirm: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PublishIocsResponse {
    pub posted: bool,
    pub dry_run: bool,
    pub target_url: String,
    pub watchlist_alias: String,
    pub items_count: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub http_status: Option<u16>,
    pub payload: serde_json::Value,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub azure_response_body: Option<String>,
}

// ── Cold-start seed from a known IoC (MCP-first) ───────────────────────

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct SeedFromIocRequest {
    /// Reserved for DTO symmetry with the other request types. The
    /// cold-start path is session-agnostic: `seed_from_ioc` operates on
    /// the current session (auto-creating one when none exists) and does
    /// not consult this field today.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session: Option<SessionHandle>,
    /// One of: "IP" | "User" | "Host" | "Process" | "File".
    pub entity_type: String,
    /// The IoC value (e.g. "10.0.0.9", "alice@corp.com").
    pub value: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub time_window: Option<TimeWindow>,
}

/// Pull a specific slice of a node's Sentinel events into the graph on
/// demand (no polling). The node must already exist in the current
/// session graph; its entity type selects the Sentinel tables to query.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct NodeEnrichRequest {
    /// Reserved for DTO symmetry with the other request types. The
    /// on-demand enrichment path is session-agnostic: `node_enrich` operates
    /// on the current session and does not consult this field today.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session: Option<SessionHandle>,
    /// Existing node id (also the value searched in Sentinel, e.g. an IP
    /// or UPN).
    pub node_id: String,
    /// Restrict to these Sentinel tables (default: all tables mapped for
    /// the node's type).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tables: Option<Vec<String>>,
    /// Time window (soft-sugar). Default `ago(24h)` when absent.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub time_window: Option<TimeWindow>,
    /// Cap rows pulled per table. Default 1000.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_rows: Option<u32>,
    /// Optional layer name. When set, this enrichment REPLACES the existing
    /// layer with this name (snapshot) instead of appending — re-enriching
    /// the same node into the same layer refreshes it rather than
    /// duplicating. Omit to append under the default enrich tag.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dataset: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct SeedResult {
    pub hydration: graph_hunter_core::analytics::HydrationOutcome,
    pub neighborhood: graph_hunter_core::analytics::Neighborhood,
    /// Top-N seeded neighborhood nodes by anomaly score (descending).
    pub top_anomalies: Vec<graph_hunter_core::analytics::NeighborNode>,
}
