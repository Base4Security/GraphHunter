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

/// `GraphSummary` wrapped with the on-demand enrichment capabilities
/// of this process. Flatten keeps the response backwards-compatible
/// with clients that only consumed the original fields.
#[derive(Debug, Clone, Serialize)]
pub struct GraphSummaryWithCapabilities {
    #[serde(flatten)]
    pub summary: graph_hunter_core::GraphSummary,
    pub capabilities: Capabilities,
}
