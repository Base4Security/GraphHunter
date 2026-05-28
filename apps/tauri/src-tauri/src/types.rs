use graph_hunter_core::{Hypothesis, ScoredPath};
use serde::Serialize;

// ── Serializable response types for the frontend ──

// Moved to `graph_hunter_api::dto::graph_ops::GraphStats` in P1. Re-exported
// here so existing call sites that `use crate::types::GraphStats` keep
// compiling. JSON shape is unchanged.
pub use graph_hunter_api::dto::graph_ops::GraphStats;

// Moved to `graph_hunter_api::dto::ingestion` in P1 Fase 2.
pub use graph_hunter_api::dto::ingestion::{
    DetectedField, LoadResult, PcapIpCount, PcapPortCount, PcapPreviewResult, PcapProtocolCount,
    PcapTimeSpan, PreviewIngestResult,
};

#[derive(Serialize)]
pub struct HuntResults {
    pub paths: Vec<Vec<std::sync::Arc<str>>>,
    pub path_count: usize,
    pub truncated: bool,
    /// Populated only when `path_count == 0` — explains which step would
    /// have failed and (when possible) suggests a fix. See `HuntDiagnostic`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub diagnostic: Option<graph_hunter_core::HuntDiagnostic>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub live_tail_coverage: Option<graph_hunter_core::LiveTailCoverage>,
}

#[derive(Serialize)]
pub struct PaginatedHuntResults {
    pub total_paths: usize,
    pub filtered_paths: usize,
    pub page: usize,
    pub page_size: usize,
    pub paths: Vec<ScoredPath>,
}

// Subgraph wire types and ExpandFilter moved to
// `graph_hunter_api::dto::graph_ops` in P1. Re-exported here so existing
// call sites keep compiling. `ip_class_for` also re-exported from
// `graph_hunter_api::util` — same function, different owner.
pub use graph_hunter_api::dto::graph_ops::{
    ExpandFilter, PaginatedEvents, Subgraph, SubgraphEdge, SubgraphNode,
};
pub use graph_hunter_api::util::ip_class_for;

// Moved to `graph_hunter_api::dto::session::SessionInfo` in P1 Fase 2.
pub use graph_hunter_api::dto::session::SessionInfo;

// Moved to `graph_hunter_api::dto::entity` in P1. Re-exported here so
// existing call sites that `use crate::types::{EntityTypeCount, ...}`
// keep compiling. Structural shape is unchanged (frontend JSON matches).
pub use graph_hunter_api::dto::entity::{EntityTypeCount, PaginatedEntities};

#[derive(Serialize)]
pub struct DslResult {
    pub hypothesis: Hypothesis,
    pub formatted: String,
}

// Moved to `graph_hunter_api::dto::ingestion` in P1 Fase 2. Re-
// exported here so `cmd_load_data_streaming` + the frontend events
// keep their shape.
pub use graph_hunter_api::dto::ingestion::{IngestComplete, IngestError, IngestJobStarted};

// Analytics row types moved to `graph_hunter_api::dto::analytics` in P1.
pub use graph_hunter_api::dto::analytics::{HeatmapRow, TimelineRow};

/// Report of which on-demand enrichment backends are available to the
/// current process. Surfaced alongside `ApiTestResult` so the UI (and MCP
/// clients) can tell the analyst *up front* that e.g. GeoIP is off and
/// they should rely on dataset metadata instead of calling `enrich_ip`
/// only to be told mid-hunt that the provider is missing.
// Moved to `graph_hunter_api::dto::geoip` in P1 Fase 2. Structural
// shape is identical; re-exported here so existing call sites keep
// compiling.
pub use graph_hunter_api::dto::geoip::{ApiTestResult, Capabilities};

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

/// Emitted every time a KQL query is executed (polling or ad-hoc) so the
/// frontend Activity Log can show the exact query for hunter reproducibility.
#[derive(Clone, Serialize)]
pub struct KqlQueryExecutedEvent {
    pub kql: String,
    pub source: String,
    pub target: String,
    pub row_count: usize,
    pub entities_created: usize,
    pub relations_created: usize,
}

/// Result of an ad-hoc KQL query execution, returned to the frontend.
#[derive(Clone, Serialize)]
pub struct KqlResult {
    pub new_entities: usize,
    pub new_relations: usize,
    pub total_entities: usize,
    pub total_relations: usize,
    pub kql_executed: String,
    pub row_count: usize,
}

#[derive(Clone, Serialize)]
pub struct ConnectorStatusResponse {
    pub connected: bool,
    pub connector_id: Option<String>,
    pub status: Option<crate::sentinel_connector::ConnectorStatus>,
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

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
