use std::collections::HashMap;

use graph_hunter_core::{Hypothesis, ScoredPath};
use serde::{Deserialize, Serialize};

// ── Serializable response types for the frontend ──

#[derive(Serialize)]
pub struct GraphStats {
    pub entity_count: usize,
    pub relation_count: usize,
}

#[derive(Clone, Serialize)]
pub struct LoadResult {
    pub new_entities: usize,
    pub new_relations: usize,
    pub total_entities: usize,
    pub total_relations: usize,
}

/// One row in the preview: log field name and suggested node type (or "Skip").
#[derive(Serialize)]
pub struct DetectedField {
    pub field_name: String,
    pub suggested_entity_type: String,
}

/// Result of preview_ingest: detected format and proposed field -> entity type mapping.
#[derive(Serialize)]
pub struct PreviewIngestResult {
    pub format: String,
    pub detected_fields: Vec<DetectedField>,
}

#[derive(Serialize)]
pub struct HuntResults {
    pub paths: Vec<Vec<String>>,
    pub path_count: usize,
    pub truncated: bool,
}

#[derive(Serialize)]
pub struct PaginatedHuntResults {
    pub total_paths: usize,
    pub filtered_paths: usize,
    pub page: usize,
    pub page_size: usize,
    pub paths: Vec<ScoredPath>,
}

#[derive(Clone, Serialize)]
pub struct SubgraphNode {
    pub id: String,
    pub entity_type: String,
    pub score: f64,
    pub metadata: HashMap<String, String>,
}

#[derive(Clone, Serialize)]
pub struct SubgraphEdge {
    pub source: String,
    pub target: String,
    pub rel_type: String,
    pub timestamp: i64,
    pub metadata: HashMap<String, String>,
    /// Dataset this event came from (for UI tooltip in Events view).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dataset_id: Option<String>,
}

#[derive(Clone, Serialize)]
pub struct Subgraph {
    pub nodes: Vec<SubgraphNode>,
    pub edges: Vec<SubgraphEdge>,
}

/// Filter struct received from the frontend for neighborhood expansion.
#[derive(Deserialize, Default)]
pub struct ExpandFilter {
    pub entity_types: Option<Vec<String>>,
    pub relation_types: Option<Vec<String>>,
    pub time_start: Option<i64>,
    pub time_end: Option<i64>,
    pub min_score: Option<f64>,
}

#[derive(Serialize)]
pub struct SessionInfo {
    pub id: String,
    pub name: String,
    pub created_at: i64,
}

/// Response item for entity type counts.
#[derive(Serialize)]
pub struct EntityTypeCount {
    pub entity_type: String,
    pub count: usize,
}

/// Paginated response for entity lists.
#[derive(Serialize)]
pub struct PaginatedEntities {
    pub entities: Vec<String>,
    pub total_count: usize,
}

#[derive(Serialize)]
pub struct DslResult {
    pub hypothesis: Hypothesis,
    pub formatted: String,
}

/// Response returned immediately when ingestion starts.
#[derive(Clone, Serialize)]
pub struct IngestJobStarted {
    pub job_id: String,
    pub dataset_id: String,
}

/// Emitted when background ingestion completes successfully.
#[derive(Clone, Serialize)]
pub struct IngestComplete {
    pub job_id: String,
    pub dataset_id: String,
    pub result: LoadResult,
}

/// Emitted when background ingestion fails.
#[derive(Clone, Serialize)]
pub struct IngestError {
    pub job_id: String,
    pub dataset_id: String,
    pub error: String,
}

#[derive(Serialize)]
pub struct HeatmapRow {
    pub relation_type: String,
    pub bins: Vec<(i64, usize)>,
}

#[derive(Serialize)]
pub struct TimelineRow {
    pub entity_type: String,
    pub min_time: i64,
    pub max_time: i64,
    pub bins: Vec<(i64, usize)>,
}

/// Result of testing the HTTP API health endpoint (for the "Test API" button).
#[derive(Serialize)]
pub struct ApiTestResult {
    pub ok: bool,
    pub status: Option<u16>,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub body: Option<String>,
}
