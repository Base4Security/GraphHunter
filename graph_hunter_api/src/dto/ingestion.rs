//! DTOs for ingestion commands.

use crate::state::SessionHandle;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PreviewIngestRequest {
    pub path: String,
    pub format: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DetectedField {
    pub field_name: String,
    pub suggested_entity_type: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PreviewIngestResult {
    pub format: String,
    pub detected_fields: Vec<DetectedField>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoadDataRequest {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session: Option<SessionHandle>,
    pub path: String,
    pub format: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct LoadResult {
    pub new_entities: usize,
    pub new_relations: usize,
    pub total_entities: usize,
    pub total_relations: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IngestSiemRequest {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session: Option<SessionHandle>,
    pub params: serde_json::Value,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoadDataWithConfigRequest {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session: Option<SessionHandle>,
    pub path: String,
    pub config: graph_hunter_core::FieldConfig,
}

// ── Background ingest events (consumed by `cmd_load_data_streaming`) ──

/// Response returned immediately when background ingestion starts.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct IngestJobStarted {
    pub job_id: String,
    pub dataset_id: String,
}

/// Emitted when background ingestion completes successfully.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct IngestComplete {
    pub job_id: String,
    pub dataset_id: String,
    pub result: LoadResult,
}

/// Emitted when background ingestion fails.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct IngestError {
    pub job_id: String,
    pub dataset_id: String,
    pub error: String,
}
