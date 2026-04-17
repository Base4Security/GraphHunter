//! DTOs for export commands: subgraph, hunt results, IoC feeds.

use crate::state::SessionHandle;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExportSubgraphRequest {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session: Option<SessionHandle>,
    pub format: String,
    pub nodes: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExportHuntResultsRequest {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session: Option<SessionHandle>,
    pub format: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub page: Option<usize>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub page_size: Option<usize>,
    /// When true, collapses identical paths (DedupMode::ByPath).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub aggregate: Option<bool>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExportIocsRequest {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session: Option<SessionHandle>,
    pub format: String,
    /// Defaults to `"ioc:"`. Pass `""` to include every tag.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tag_prefix: Option<String>,
}
