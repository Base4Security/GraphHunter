//! DTOs for Sentinel integrations — Watchlist publish (C.2) and the
//! real-time connector commands (C.5) go in the same module because
//! both speak to the same tenant under the same Azure creds.

use crate::sentinel_connector::ConnectorStatus;
use crate::state::SessionHandle;
use serde::{Deserialize, Serialize};

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
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SentinelConnectedEvent {
    pub connector_id: String,
    pub tables: Vec<String>,
    pub poll_interval_secs: u64,
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
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KqlResult {
    pub new_entities: usize,
    pub new_relations: usize,
    pub total_entities: usize,
    pub total_relations: usize,
    pub kql_executed: String,
    pub row_count: usize,
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
