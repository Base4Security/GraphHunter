use std::sync::Arc;

use graph_hunter_api::dto::analytics::{
    CompactRequest, ComputeBetweennessRequest, ComputeCompositeScoresRequest,
    ComputePagerankRequest, TemporalHeatmapRequest, TimelineDataRequest,
};
use graph_hunter_api::dto::anomaly::{
    ComputeGnnScoresRequest, EnableAnomalyScoringRequest, GetAnomalyConfigRequest,
    LoadGnnModelRequest, UpdateAnomalyWeightsRequest,
};
use graph_hunter_api::GraphHunterApi;
use graph_hunter_core::{CompactionStats, ScoringWeights};
use tauri::State;

use crate::error::CommandError;
use crate::types::{ApiTestResult, Capabilities, HeatmapRow, TimelineRow};

/// Public wrapper so other command modules can reuse capability
/// detection without reimplementing the Mutex probes. Delegates to
/// the canonical API.
pub fn detect_capabilities_public(api: &GraphHunterApi) -> Capabilities {
    // `graph_hunter_api::dto::geoip::Capabilities` is structurally
    // identical to the Tauri-re-exported `Capabilities`; we rely on
    // that re-export to avoid a manual field copy.
    api.capabilities()
}

// ── Temporal heatmap ──

/// Bucketed relation counts grouped by relation type.
#[tauri::command]
pub fn cmd_get_temporal_heatmap(
    api: State<Arc<GraphHunterApi>>,
    bucket_size_seconds: Option<i64>,
) -> Result<Vec<HeatmapRow>, CommandError> {
    api.get_temporal_heatmap(TemporalHeatmapRequest {
        session: None,
        bucket_size_seconds,
    })
    .map_err(CommandError::from)
}

// ── Timeline sparkline ──

/// Timestamp distribution per entity type for sparkline visualization.
#[tauri::command]
pub fn cmd_get_timeline_data(
    api: State<Arc<GraphHunterApi>>,
) -> Result<Vec<TimelineRow>, CommandError> {
    api.get_timeline_data(TimelineDataRequest::default())
        .map_err(CommandError::from)
}

// ── Analytics commands ──

/// Computes betweenness centrality (Brandes algorithm).
#[tauri::command]
pub fn cmd_compute_betweenness(
    api: State<Arc<GraphHunterApi>>,
    sample_limit: Option<usize>,
) -> Result<(), CommandError> {
    api.compute_betweenness(ComputeBetweennessRequest {
        session: None,
        sample_limit,
    })
    .map_err(CommandError::from)
}

/// Computes temporal PageRank with exponential decay.
#[tauri::command]
pub fn cmd_compute_pagerank(
    api: State<Arc<GraphHunterApi>>,
    lambda: Option<f64>,
    damping: Option<f64>,
    max_iter: Option<usize>,
    reference_time: Option<i64>,
) -> Result<(), CommandError> {
    api.compute_pagerank(ComputePagerankRequest {
        session: None,
        lambda,
        damping,
        max_iter,
        reference_time,
    })
    .map_err(CommandError::from)
}

/// Weighted combination of degree, pagerank, betweenness, and rarity.
/// `rarity_weight` defaults to 0 if the caller doesn't pass it, so
/// old clients preserve the pre-rarity (centrality-only) behaviour.
#[tauri::command]
pub fn cmd_compute_composite_scores(
    api: State<Arc<GraphHunterApi>>,
    degree_weight: f64,
    pagerank_weight: f64,
    betweenness_weight: f64,
    rarity_weight: Option<f64>,
) -> Result<(), CommandError> {
    api.compute_composite_scores(ComputeCompositeScoresRequest {
        session: None,
        degree_weight,
        pagerank_weight,
        betweenness_weight,
        rarity_weight: rarity_weight.unwrap_or(0.0),
    })
    .map_err(CommandError::from)
}

/// Compacts old edges before a cutoff timestamp.
#[tauri::command]
pub fn cmd_compact(
    api: State<Arc<GraphHunterApi>>,
    cutoff_timestamp: i64,
) -> Result<CompactionStats, CommandError> {
    api.compact(CompactRequest {
        session: None,
        cutoff_timestamp,
    })
    .map_err(CommandError::from)
}

/// Test the local HTTP API by GET /health and report on-demand
/// enrichment capabilities. Delegates to the canonical API.
#[tauri::command]
pub fn cmd_test_http_api(
    api: State<Arc<GraphHunterApi>>,
) -> Result<ApiTestResult, CommandError> {
    api.test_http_api().map_err(CommandError::from)
}

// ── Anomaly Scoring Commands ──

/// Enable anomaly scoring with optional custom weights.
#[tauri::command]
pub fn cmd_enable_anomaly_scoring(
    api: State<Arc<GraphHunterApi>>,
    weights: Option<ScoringWeights>,
) -> Result<(), CommandError> {
    api.enable_anomaly_scoring(EnableAnomalyScoringRequest {
        session: None,
        weights,
    })
    .map_err(CommandError::from)
}

/// Update anomaly scoring weights without re-finalizing observations.
#[tauri::command]
pub fn cmd_update_anomaly_weights(
    api: State<Arc<GraphHunterApi>>,
    weights: ScoringWeights,
) -> Result<(), CommandError> {
    api.update_anomaly_weights(UpdateAnomalyWeightsRequest {
        session: None,
        weights,
    })
    .map_err(CommandError::from)
}

/// Get current anomaly scoring configuration (None if not enabled).
#[tauri::command]
pub fn cmd_get_anomaly_config(
    api: State<Arc<GraphHunterApi>>,
) -> Result<Option<ScoringWeights>, CommandError> {
    api.get_anomaly_config(GetAnomalyConfigRequest::default())
        .map_err(CommandError::from)
}

/// Load a GNN ONNX model for ML-based threat scoring. `model_path` accepts
/// either an absolute path or one of the built-in aliases (`"gnn_v1"`,
/// `"gnn_v2"`). v2 is the recommended default for hunts that include
/// cloud-identity logs; v1 remains for backward compat.
#[tauri::command]
pub fn cmd_load_gnn_model(
    api: State<Arc<GraphHunterApi>>,
    model_path: String,
) -> Result<String, CommandError> {
    api.load_gnn_model(LoadGnnModelRequest { model_path })
        .map_err(CommandError::from)
}

/// Compute GNN threat scores for all entities in the current graph.
/// Requires: anomaly scoring enabled + GNN model loaded.
#[tauri::command]
pub fn cmd_compute_gnn_scores(
    api: State<Arc<GraphHunterApi>>,
    k_hops: Option<usize>,
) -> Result<usize, CommandError> {
    api.compute_gnn_scores(ComputeGnnScoresRequest {
        session: None,
        k_hops,
    })
    .map_err(CommandError::from)
}

/// Check if a GNN model is currently loaded.
#[tauri::command]
pub fn cmd_gnn_model_status(api: State<Arc<GraphHunterApi>>) -> Result<bool, CommandError> {
    api.gnn_model_status().map_err(CommandError::from)
}
