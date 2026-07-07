//! DTOs for dataset management commands.

use crate::state::{DatasetInfo, SessionHandle};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ListDatasetsRequest {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session: Option<SessionHandle>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RemoveDatasetRequest {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session: Option<SessionHandle>,
    pub dataset_id: String,
}

/// `(entities_removed, relations_removed)` counts.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RemoveDatasetResponse {
    pub entities_removed: usize,
    pub relations_removed: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RenameTypeInDatasetRequest {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session: Option<SessionHandle>,
    pub dataset_id: String,
    pub from_type: String,
    pub to_type: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DatasetEntityTypesRequest {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session: Option<SessionHandle>,
    pub dataset_id: String,
}

pub type ListDatasetsResponse = Vec<DatasetInfo>;
