//! DTOs for IP enrichment and subnet analysis.

use crate::state::SessionHandle;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct SubnetAnalysisRequest {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session: Option<SessionHandle>,
}

/// Subnet aggregation over IP entities in the graph, one row per /24
/// (or narrower) subnet with IP count, optional total bytes, and the
/// top service categories observed via outgoing relations.
///
/// Moved from `app/src-tauri/src/commands/enrichment.rs::SubnetGroup`;
/// the fields are unchanged so the frontend wire shape is preserved.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SubnetGroup {
    pub subnet: String,
    pub ip_count: usize,
    pub ips: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub total_bytes: Option<u64>,
    pub is_internal: bool,
    pub top_services: Vec<String>,
}

pub type SubnetAnalysisResponse = Vec<SubnetGroup>;
