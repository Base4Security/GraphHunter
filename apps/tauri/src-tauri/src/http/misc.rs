//! Root / health / metrics / datasets endpoints.

use axum::{
    extract::{Request, State},
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use std::sync::Arc;
use std::time::Duration;

use graph_hunter_api::GraphHunterApi;

use super::helpers::{api_response, ok_json};

pub(super) async fn handler_api_root() -> Response {
    ok_json(serde_json::json!({
        "service": "GraphHunter HTTP API",
        "health": "/health",
        "docs": "GET /v1/schema for the full stable endpoint list (also see platform/mcp/README.md)."
    }))
}

pub(super) async fn handler_schema(State(api): State<Arc<GraphHunterApi>>) -> Response {
    // Static, non-blocking — safe to call from the Axum thread directly.
    ok_json(serde_json::to_value(api.get_schema()).unwrap_or(serde_json::json!({})))
}

pub(super) async fn handler_health(State(api): State<Arc<GraphHunterApi>>) -> Response {
    tracing::debug!("HTTP API: /health request received");
    // Short timeout so /health never blocks on a contended session
    // store (the canonical API uses the same std RwLock internally).
    // Returns `(session_loaded, Option<(entities, relations)>)` so we can
    // surface the active graph_state without a second blocking hop.
    let api = api.clone();
    let (session_loaded, counts, last_build) = tokio::time::timeout(
        Duration::from_millis(500),
        tokio::task::spawn_blocking(move || {
            let loaded = api.sessions().current_id().is_some();
            (loaded, api.current_graph_counts(), api.current_last_build())
        }),
    )
    .await
    .unwrap_or(Ok((false, None, None)))
    .unwrap_or((false, None, None));

    // graph_state/advisory only when a session is loaded; an empty/partial
    // graph actively says so (and how to populate it). Same thresholds as
    // `/graph_summary` via the shared classifier.
    let (graph_state, advisory) = match counts {
        Some((entities, relations)) => {
            let (state, advisory) =
                graph_hunter_api::dto::geoip::GraphState::classify(entities, relations);
            (Some(state), advisory)
        }
        None => (None, None),
    };

    ok_json(serde_json::json!({
        "ok": true,
        "session_loaded": session_loaded,
        "message": if session_loaded {
            "GraphHunter app running with a session loaded."
        } else {
            "GraphHunter app running. No session loaded — create or load a session in the app."
        },
        "graph_state": graph_state,
        "advisory": advisory,
        "last_build": last_build,
    }))
}

/// Prometheus text-exposition endpoint. Emits drift metrics aggregated over
/// the last 24h window. No session required — returns an empty payload if
/// the DriftStore hasn't been initialized.
pub(super) async fn handler_metrics(State(api): State<Arc<GraphHunterApi>>) -> Response {
    let api = api.clone();
    // 24h window. Small enough that Prometheus doesn't need to down-sample,
    // large enough to smooth short-term bursts.
    let body = tokio::task::spawn_blocking(move || api.drift_metrics_text(86_400))
        .await
        .unwrap_or_else(|e| format!("# drift_metrics_text join error: {e}\n"));
    (
        StatusCode::OK,
        [(axum::http::header::CONTENT_TYPE, "text/plain; version=0.0.4; charset=utf-8")],
        body,
    )
        .into_response()
}

pub(super) async fn handler_list_datasets(State(api): State<Arc<GraphHunterApi>>) -> Response {
    api_response(api.list_datasets(
        graph_hunter_api::dto::dataset::ListDatasetsRequest::default(),
    ))
}

/// Fallback for unmatched routes: return 404 with JSON body so MCP/client can show path and method.
pub(super) async fn fallback_404(request: Request) -> Response {
    let path = request.uri().path().to_string();
    let method = request.method().to_string();
    (
        StatusCode::NOT_FOUND,
        Json(serde_json::json!({
            "error": format!("Not found: {} {}", method, path),
            "path": path,
            "method": method
        })),
    )
        .into_response()
}
