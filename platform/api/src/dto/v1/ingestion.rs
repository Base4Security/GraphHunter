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
    /// Canonical target the core recognizes for this field (e.g. `"source_user"`),
    /// or `None` for unrecognized fields the user must map manually.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub canonical_target: Option<String>,
    /// Number of sample events where this field had a non-empty value.
    #[serde(default, skip_serializing_if = "is_zero")]
    pub occurrence_count: usize,
    /// Up to 5 distinct sample values. Empty when the API couldn't sample
    /// (e.g. legacy preview path for a format that doesn't support sampling).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub sample_values: Vec<String>,
    /// Where the `suggested_entity_type` came from. One of `"name"` (matched
    /// a column-name keyword), `"values"` (value regex matched sample
    /// contents), `"canonical"` (canonical alias table's default), or
    /// `"default"` (fell through to raw column name). Lets the UI show
    /// users *why* we guessed what we guessed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub suggestion_source: Option<String>,
}

fn is_zero(v: &usize) -> bool {
    *v == 0
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
    /// True when the parser saw rows but produced no triples — signal for
    /// the UI to show a remap-your-mapping warning.
    #[serde(default)]
    pub zero_triples: bool,
    /// Aggregate parse statistics for this ingest. `None` for legacy parsers
    /// that didn't report stats.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ingest_stats: Option<graph_hunter_core::ParseStats>,
    /// Post-ingest data-quality notices: shared-infra IP detection,
    /// likely-duplicate user identities, etc. Empty when no patterns
    /// fired. Surfaced read-only in DatasetCard so the analyst can see
    /// the engine flagged the structural issues without changing the
    /// ingested triples.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub warnings: Vec<String>,
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

/// Kicks off a background streaming ingestion. The caller gets back the
/// `job_id` / `dataset_id` synchronously; progress + completion are
/// pushed through the API's [`EventEmitter`] under the `ingest-progress`,
/// `ingest-complete`, and `ingest-error` event names.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoadDataStreamingRequest {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session: Option<SessionHandle>,
    pub path: String,
    pub format: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub config: Option<graph_hunter_core::FieldConfig>,
    /// Optional lower bound for line-based formats (IIS/CSV). Compared
    /// lexicographically against the first 10 bytes of each line
    /// (ISO `YYYY-MM-DD` sorts correctly that way).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub date_from: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub date_to: Option<String>,
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
