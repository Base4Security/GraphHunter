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
    /// For `IP` entities: "Private" / "Public" / "Loopback" / etc. so the
    /// frontend can badge internal vs external IPs without re-parsing the
    /// address on every render. `None` for non-IP entities or unparseable
    /// values. Per analyst feedback (2026-04-10), internal/external is the
    /// very first question asked of any finding.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ip_class: Option<String>,
}

/// Computes the IP class label for a node about to be serialized to the
/// frontend. Returns `None` for non-IP entity types so the field is omitted.
pub fn ip_class_for(entity_type: &str, id: &str) -> Option<String> {
    if entity_type != "IP" {
        return None;
    }
    graph_hunter_core::classify_ip(id).map(|c| format!("{:?}", c))
}

impl SubgraphNode {
    /// Builds a SubgraphNode and eagerly computes its `ip_class` via
    /// [`ip_class_for`]. Callers should prefer this over struct-literal
    /// construction so the frontend always sees the internal/external
    /// classification for IP entities.
    pub fn new(
        id: String,
        entity_type: String,
        score: f64,
        metadata: HashMap<String, String>,
    ) -> Self {
        let ip_class = ip_class_for(&entity_type, &id);
        Self { id, entity_type, score, metadata, ip_class }
    }
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

/// Paginated events response for the Event View panel.
#[derive(Serialize)]
pub struct PaginatedEvents {
    pub events: Vec<SubgraphEdge>,
    pub total_count: usize,
    pub page: usize,
    pub page_size: usize,
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

// ── Sentinel real-time connector events ──

#[derive(Clone, Serialize)]
pub struct SentinelConnectedEvent {
    pub connector_id: String,
    pub tables: Vec<String>,
    pub poll_interval_secs: u64,
}

#[derive(Clone, Serialize)]
pub struct SentinelDataEvent {
    pub new_entities: usize,
    pub new_relations: usize,
    pub timestamp: i64,
}

#[derive(Clone, Serialize)]
pub struct SentinelErrorEvent {
    pub error: String,
    pub consecutive_errors: u32,
    pub will_retry: bool,
}

#[derive(Clone, Serialize)]
pub struct ConnectorStatusResponse {
    pub connected: bool,
    pub connector_id: Option<String>,
    pub status: Option<crate::sentinel_connector::ConnectorStatus>,
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── ip_class_for ──

    #[test]
    fn ip_class_private_rfc1918() {
        let result = ip_class_for("IP", "192.168.1.1");
        assert!(result.is_some());
        assert_eq!(result.unwrap(), "Private");
    }

    #[test]
    fn ip_class_private_10() {
        let result = ip_class_for("IP", "10.0.0.1");
        assert!(result.is_some());
        assert_eq!(result.unwrap(), "Private");
    }

    #[test]
    fn ip_class_public() {
        let result = ip_class_for("IP", "8.8.8.8");
        assert!(result.is_some());
        assert_eq!(result.unwrap(), "Public");
    }

    #[test]
    fn ip_class_loopback() {
        let result = ip_class_for("IP", "127.0.0.1");
        assert!(result.is_some());
        assert_eq!(result.unwrap(), "Loopback");
    }

    #[test]
    fn ip_class_non_ip_entity() {
        assert!(ip_class_for("Host", "webserver-01").is_none());
        assert!(ip_class_for("User", "admin").is_none());
        assert!(ip_class_for("Process", "cmd.exe").is_none());
    }

    #[test]
    fn ip_class_invalid_ip_string() {
        // Not a valid IP — classify_ip should return None
        assert!(ip_class_for("IP", "not-an-ip").is_none());
    }

    // ── SubgraphNode::new ──

    #[test]
    fn node_new_auto_ip_class() {
        let node = SubgraphNode::new(
            "10.0.0.5".to_string(),
            "IP".to_string(),
            0.0,
            HashMap::new(),
        );
        assert_eq!(node.ip_class.as_deref(), Some("Private"));
    }

    #[test]
    fn node_new_public_ip() {
        let node = SubgraphNode::new(
            "1.2.3.4".to_string(),
            "IP".to_string(),
            50.0,
            HashMap::new(),
        );
        assert_eq!(node.ip_class.as_deref(), Some("Public"));
    }

    #[test]
    fn node_new_non_ip_no_class() {
        let node = SubgraphNode::new(
            "webserver".to_string(),
            "Host".to_string(),
            0.0,
            HashMap::new(),
        );
        assert!(node.ip_class.is_none());
    }

    #[test]
    fn node_preserves_metadata() {
        let mut meta = HashMap::new();
        meta.insert("key".to_string(), "value".to_string());
        let node = SubgraphNode::new(
            "10.0.0.1".to_string(),
            "IP".to_string(),
            99.5,
            meta,
        );
        assert_eq!(node.score, 99.5);
        assert_eq!(node.metadata.get("key").map(|s| s.as_str()), Some("value"));
    }
}
