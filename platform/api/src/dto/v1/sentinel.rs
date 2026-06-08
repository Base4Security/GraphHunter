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
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_rows: Option<u32>,
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
    /// rows. `None` when the query was ingested.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rows: Option<Vec<serde_json::Value>>,
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
}

#[derive(Debug, Clone, Serialize)]
pub struct SeedResult {
    pub hydration: graph_hunter_core::analytics::HydrationOutcome,
    pub neighborhood: graph_hunter_core::analytics::Neighborhood,
    /// Top-N seeded neighborhood nodes by anomaly score (descending).
    pub top_anomalies: Vec<graph_hunter_core::analytics::NeighborNode>,
}
