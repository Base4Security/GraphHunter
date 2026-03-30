use std::error::Error;
use std::sync::Arc;

use graph_hunter_core::{CompactionStats, ScoringWeights};
use tauri::State;

use crate::error::CommandError;
use crate::helpers::{with_current_graph, with_current_graph_mut};
use crate::state::AppState;
use crate::types::{ApiTestResult, HeatmapRow, TimelineRow};

// ── Temporal heatmap ──

/// Returns hourly-bucketed relation counts grouped by relation type.
#[tauri::command]
pub fn cmd_get_temporal_heatmap(state: State<Arc<AppState>>) -> Result<Vec<HeatmapRow>, CommandError> {
    with_current_graph(state.as_ref(), |graph| {
        Ok(graph.temporal_heatmap()
            .into_iter()
            .map(|(relation_type, bins)| HeatmapRow { relation_type, bins })
            .collect())
    })
}

// ── Timeline sparkline ──

/// Returns timestamp distribution per entity type for sparkline visualization.
#[tauri::command]
pub fn cmd_get_timeline_data(state: State<Arc<AppState>>) -> Result<Vec<TimelineRow>, CommandError> {
    with_current_graph(state.as_ref(), |graph| {
        Ok(graph.timeline_data()
            .into_iter()
            .map(|(entity_type, min_time, max_time, bins)| {
                TimelineRow { entity_type, min_time, max_time, bins }
            })
            .collect())
    })
}

// ── Analytics commands ──

/// Computes betweenness centrality (Brandes algorithm).
#[tauri::command]
pub fn cmd_compute_betweenness(state: State<Arc<AppState>>, sample_limit: Option<usize>) -> Result<(), CommandError> {
    with_current_graph_mut(state.as_ref(), |graph| {
        graph.compute_betweenness(sample_limit);
        Ok(())
    })
}

/// Computes temporal PageRank with exponential decay.
#[tauri::command]
pub fn cmd_compute_pagerank(
    state: State<Arc<AppState>>,
    lambda: Option<f64>,
    damping: Option<f64>,
    max_iter: Option<usize>,
    reference_time: Option<i64>,
) -> Result<(), CommandError> {
    with_current_graph_mut(state.as_ref(), |graph| {
        graph.compute_temporal_pagerank(lambda, damping, max_iter, None, reference_time);
        Ok(())
    })
}

/// Computes composite score from weighted combination of degree, pagerank, betweenness.
#[tauri::command]
pub fn cmd_compute_composite_scores(
    state: State<Arc<AppState>>,
    degree_weight: f64,
    pagerank_weight: f64,
    betweenness_weight: f64,
) -> Result<(), CommandError> {
    with_current_graph_mut(state.as_ref(), |graph| {
        graph.compute_composite_score(degree_weight, pagerank_weight, betweenness_weight);
        Ok(())
    })
}

/// Compacts old edges before a cutoff timestamp.
#[tauri::command]
pub fn cmd_compact(state: State<Arc<AppState>>, cutoff_timestamp: i64) -> Result<CompactionStats, CommandError> {
    with_current_graph_mut(state.as_ref(), |graph| {
        graph.compact_before(cutoff_timestamp).map_err(|e| e.to_string())
    })
}

/// Build a full error description from reqwest::Error (including cause chain).
fn reqwest_error_message(e: &reqwest::Error) -> String {
    let mut msg = e.to_string();
    if let Some(source) = e.source() {
        msg.push_str(" (");
        msg.push_str(&source.to_string());
        msg.push(')');
    }
    msg
}

/// Test the local HTTP API by GET /health. Runs in a thread so the UI does not block.
/// First checks if the port is reachable (TCP), then tries HTTP with reqwest.
#[tauri::command]
pub fn cmd_test_http_api() -> Result<ApiTestResult, CommandError> {
    let port = std::env::var("GRAPHHUNTER_API_PORT")
        .ok()
        .and_then(|s| s.parse::<u16>().ok())
        .unwrap_or(37891);
    let url = format!("http://127.0.0.1:{}/health", port);
    let result = std::thread::scope(|s| {
        s.spawn(|| {
            // 1) Quick TCP check: can we reach the port at all?
            let addr = std::net::SocketAddr::from(([127, 0, 0, 1], port));
            let tcp_ok = std::net::TcpStream::connect_timeout(
                &addr,
                std::time::Duration::from_secs(2),
            ).is_ok();
            if !tcp_ok {
                return Ok(ApiTestResult {
                    ok: false,
                    status: None,
                    message: format!(
                        "Cannot connect to 127.0.0.1:{} — connection refused. Is the HTTP API thread running? Check the terminal for \"GraphHunter HTTP API listening\".",
                        port
                    ),
                    body: None,
                });
            }
            // 2) Port is open; try HTTP. Use a client with no proxy to avoid Windows proxy issues on localhost.
            let client = reqwest::blocking::Client::builder()
                .timeout(std::time::Duration::from_secs(3))
                .no_proxy()
                .build()
                .map_err(|e| CommandError::Internal(e.to_string()))?;
            match client.get(&url).send() {
                Ok(resp) => {
                    let status = resp.status();
                    let code = status.as_u16();
                    let body = resp.text().ok();
                    let ok = status.is_success();
                    Ok(ApiTestResult {
                        ok,
                        status: Some(code),
                        message: if ok {
                            "API responded OK.".to_string()
                        } else {
                            format!("API returned HTTP {}", code)
                        },
                        body,
                    })
                }
                Err(e) => Ok(ApiTestResult {
                    ok: false,
                    status: None,
                    message: format!(
                        "Port {} is open but HTTP request failed: {}",
                        port,
                        reqwest_error_message(&e)
                    ),
                    body: None,
                }),
            }
        })
        .join()
        .map_err(|_| CommandError::Internal("Test thread panicked".into()))?
    });
    result
}

// ── Anomaly Scoring Commands ──

/// Enable anomaly scoring with optional custom weights.
#[tauri::command]
pub fn cmd_enable_anomaly_scoring(
    state: State<Arc<AppState>>,
    weights: Option<ScoringWeights>,
) -> Result<(), CommandError> {
    with_current_graph_mut(state.as_ref(), |graph| {
        let w = weights.unwrap_or_default();
        graph.enable_anomaly_scoring(w);
        Ok(())
    })
}

/// Update anomaly scoring weights without re-finalizing observations.
#[tauri::command]
pub fn cmd_update_anomaly_weights(
    state: State<Arc<AppState>>,
    weights: ScoringWeights,
) -> Result<(), CommandError> {
    with_current_graph_mut(state.as_ref(), |graph| {
        if let Some(ref mut scorer) = graph.anomaly_scorer {
            scorer.set_weights(weights);
            Ok(())
        } else {
            Err(CommandError::InvalidInput("Anomaly scoring is not enabled".into()))
        }
    })
}

/// Get current anomaly scoring configuration (None if not enabled).
#[tauri::command]
pub fn cmd_get_anomaly_config(
    state: State<Arc<AppState>>,
) -> Result<Option<ScoringWeights>, CommandError> {
    with_current_graph(state.as_ref(), |graph| {
        Ok(graph.anomaly_scorer.as_ref().map(|s| s.weights().clone()))
    })
}

/// Load a GNN ONNX model for ML-based threat scoring.
/// The model file must be a valid ONNX exported from GraphOS-APT.
#[tauri::command]
pub fn cmd_load_gnn_model(
    state: State<Arc<AppState>>,
    model_path: String,
) -> Result<String, CommandError> {
    match graph_hunter_core::NpuScorer::load(&model_path) {
        Ok(scorer) => {
            *state.npu_scorer.write().map_err(|e| CommandError::GraphLocked(e.to_string()))? = Some(scorer);
            Ok("GNN model loaded successfully".to_string())
        }
        Err(e) => Err(CommandError::IoError(format!("Failed to load GNN model: {}", e))),
    }
}

/// Compute GNN threat scores for all entities in the current graph.
/// Requires: anomaly scoring enabled + GNN model loaded.
/// Returns the number of entities scored.
#[tauri::command]
pub fn cmd_compute_gnn_scores(
    state: State<Arc<AppState>>,
    k_hops: Option<usize>,
) -> Result<usize, CommandError> {
    let hops = k_hops.unwrap_or(2);

    // Get graph access and scorer access separately to avoid lock ordering issues
    let current_id = state
        .current_session_id
        .read()
        .map_err(|e| CommandError::GraphLocked(format!("Lock poisoned: {}", e)))?
        .clone();
    let id = current_id.as_ref().ok_or_else(|| CommandError::SessionNotFound("No session selected".into()))?.clone();

    let sessions = state
        .sessions
        .read()
        .map_err(|e| CommandError::GraphLocked(format!("Lock poisoned: {}", e)))?;
    let session = sessions.get(&id).ok_or_else(|| CommandError::SessionNotFound("Session not found".into()))?.clone();

    let mut graph = session
        .graph
        .write()
        .map_err(|e| CommandError::GraphLocked(format!("Lock poisoned: {}", e)))?;

    if graph.anomaly_scorer.is_none() {
        return Err(CommandError::InvalidInput("Anomaly scoring must be enabled first".into()));
    }

    let mut npu_guard = state.npu_scorer.write().map_err(|e| CommandError::GraphLocked(e.to_string()))?;
    let npu = npu_guard
        .as_mut()
        .ok_or_else(|| CommandError::InvalidInput("GNN model not loaded. Call cmd_load_gnn_model first.".into()))?;

    Ok(graph.compute_gnn_scores(npu, hops))
}

/// Check if a GNN model is currently loaded.
#[tauri::command]
pub fn cmd_gnn_model_status(
    state: State<Arc<AppState>>,
) -> Result<bool, CommandError> {
    let guard = state.npu_scorer.read().map_err(|e| CommandError::GraphLocked(e.to_string()))?;
    Ok(guard.is_some())
}
