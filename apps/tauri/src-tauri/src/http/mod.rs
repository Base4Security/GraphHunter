//! Minimal HTTP API for MCP / external tools. Bind to localhost; requires a loaded session.
//!
//! The module is split into per-domain files (graph, hunt, notes, etc.);
//! this root owns `HttpState`, the auth middleware, and router assembly.

use axum::{
    extract::{FromRef, Request, State},
    http::StatusCode,
    middleware::Next,
    response::{IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use std::sync::Arc;
use subtle::ConstantTimeEq;
use tower_http::cors::{CorsLayer, Any};

use crate::AppState;
use graph_hunter_api::GraphHunterApi;

mod agentic;
mod anomaly;
mod catalog;
mod dlq;
mod export;
mod graph;
mod graph_meta;
mod helpers;
mod hunt;
mod ingest;
mod invariants;
mod misc;
mod notes;
mod siem;
mod tags;

/// Combined axum state. Handlers extract `Arc<AppState>` or
/// `Arc<GraphHunterApi>` (or both) via `FromRef` — no handler signature
/// changes beyond replacing one for the other.
#[derive(Clone)]
pub struct HttpState {
    pub app: Arc<AppState>,
    pub api: Arc<GraphHunterApi>,
}

impl FromRef<HttpState> for Arc<AppState> {
    fn from_ref(s: &HttpState) -> Self {
        s.app.clone()
    }
}

impl FromRef<HttpState> for Arc<GraphHunterApi> {
    fn from_ref(s: &HttpState) -> Self {
        s.api.clone()
    }
}

/// Log each request to stderr so app logs show whether /health (etc.) is hit.
async fn log_requests(request: axum::extract::Request, next: Next) -> Response {
    let method = request.method().clone();
    let uri = request.uri().clone();
    let response = next.run(request).await;
    tracing::debug!("HTTP API {} {} -> {}", method, uri, response.status());
    response
}

/// Bearer token auth middleware. Skips `/` and `/health` routes.
async fn auth_middleware(
    State(state): State<Arc<AppState>>,
    request: Request,
    next: Next,
) -> Response {
    let path = request.uri().path();
    // Skip auth for root, health, and Prometheus metrics endpoints.
    // /metrics is exempt because Prometheus scrapers typically don't send bearer tokens,
    // and the server binds to localhost by default.
    if path == "/" || path == "/health" || path == "/metrics" || path == "/v1/schema" {
        return next.run(request).await;
    }

    let expected = &state.api_token;
    let auth_header = request
        .headers()
        .get("authorization")
        .and_then(|v| v.to_str().ok());

    match auth_header {
        Some(val) if val.starts_with("Bearer ") && {
            let token = val[7..].as_bytes();
            let expect = expected.as_bytes();
            token.len() == expect.len() && token.ct_eq(expect).into()
        } => {
            next.run(request).await
        }
        _ => (
            StatusCode::UNAUTHORIZED,
            Json(serde_json::json!({ "error": "Unauthorized. Provide Authorization: Bearer <token> header." })),
        )
            .into_response(),
    }
}

/// Build the API router (shared by run and run_async).
/// POST routes are also registered with trailing slash so /notes/ and /notes both work.
fn build_app(app_state: Arc<AppState>, api: Arc<GraphHunterApi>) -> Router {
    let state = HttpState { app: app_state, api };
    Router::new()
        .route("/", get(misc::handler_api_root))
        .route("/health", get(misc::handler_health))
        .route("/v1/schema", get(misc::handler_schema))
        .route("/entity_types", get(graph::handler_entity_types))
        .route("/relation_schema", get(graph::handler_relation_schema))
        .route("/explain_score", get(hunt::handler_explain_score))
        .route("/search", get(graph::handler_search))
        .route("/expand", get(graph::handler_expand))
        .route("/node_details", get(graph::handler_node_details))
        .route("/subgraph", post(graph::handler_subgraph))
        .route("/subgraph/", post(graph::handler_subgraph))
        .route("/events_for_node", get(graph::handler_events_for_node))
        .route("/run_hunt", post(hunt::handler_run_hunt))
        .route("/run_hunt/", post(hunt::handler_run_hunt))
        .route("/hunt_results", get(hunt::handler_hunt_results))
        .route("/diff_hunts", post(hunt::handler_diff_hunts))
        .route("/notes", post(notes::handler_create_note))
        .route("/notes/", post(notes::handler_create_note))
        .route("/notes/list", get(notes::handler_list_notes))
        .route("/notes/:id", get(notes::handler_get_note_by_id))
        .route("/graph_summary", get(graph::handler_graph_summary))
        .route("/graph/summary", get(graph_meta::handler_graph_summary))
        .route("/graph/overlap", post(graph_meta::handler_graph_overlap))
        .route("/entity_type_counts", get(graph::handler_entity_type_counts))
        .route("/temporal_heatmap", get(anomaly::handler_temporal_heatmap))
        .route("/subnet_analysis", get(anomaly::handler_subnet_analysis))
        .route("/enrich_ip", post(anomaly::handler_enrich_ip))
        .route("/catalog", get(catalog::handler_catalog))
        .route("/catalog/status", get(catalog::handler_catalog_with_status))
        .route("/catalog/diagnostics", get(catalog::handler_catalog_diagnostics))
        .route("/tag", post(tags::handler_tag_entity))
        .route("/untag", post(tags::handler_untag_entity))
        .route("/tags", get(tags::handler_list_tagged))
        .route("/export_iocs", post(export::handler_export_iocs))
        .route("/publish_iocs_to_sentinel", post(export::handler_publish_iocs_to_sentinel))
        .route("/save_hypothesis_as_sigma", post(export::handler_save_hypothesis_as_sigma))
        .route("/file_ticket", post(export::handler_file_ticket))
        .route("/datasets", get(misc::handler_list_datasets))
        .route("/path_nodes", get(graph::handler_path_nodes))
        .route("/export_subgraph", post(export::handler_export_subgraph))
        .route("/export_ocsf", post(export::handler_export_ocsf))
        .route("/check_invariants", post(invariants::handler_check_invariants))
        .route("/ingest_negotiate", post(ingest::handler_ingest_negotiate))
        .route("/pcap_preview", post(ingest::handler_pcap_preview))
        .route("/canonical_map", post(ingest::handler_canonical_map))
        .route("/parser_generate", post(ingest::handler_parser_generate))
        .route("/schema_drift_detect", post(ingest::handler_schema_drift_detect))
        .route("/mapping_regression_test", post(ingest::handler_mapping_regression_test))
        .route("/invariant_check_hypothetical", post(invariants::handler_invariant_check_hypothetical))
        .route("/agentic_review_list", post(agentic::handler_agentic_review_list))
        .route("/agentic_review_approve", post(agentic::handler_agentic_review_approve))
        .route("/agentic_review_reject", post(agentic::handler_agentic_review_reject))
        .route("/list_dead_letters", post(dlq::handler_list_dead_letters))
        .route("/reingest_dead_letter", post(dlq::handler_reingest_dead_letter))
        .route("/purge_dead_letters", post(dlq::handler_purge_dead_letters))
        .route("/publish_mapping", post(ingest::handler_publish_mapping))
        .route("/fetch_shared_mappings", post(ingest::handler_fetch_shared_mappings))
        .route("/parse_dsl", post(hunt::handler_parse_dsl))
        .route("/events_paginated", get(graph::handler_events_paginated))
        .route("/expand_grouped", get(graph::handler_expand_grouped))
        .route("/heavy_edges", get(graph::handler_heavy_edges))
        .route("/channel_behavior", get(graph::handler_channel_behavior))
        .route("/export_hunt_results", post(export::handler_export_hunt_results))
        .route("/enable_anomaly_scoring", post(anomaly::handler_enable_anomaly_scoring))
        .route("/compute_scores", post(anomaly::handler_compute_scores))
        .route("/kql", post(siem::handler_run_kql))
        .route("/kql/", post(siem::handler_run_kql))
        .route("/node/enrich", post(siem::handler_node_enrich))
        .route("/sentinel/seed", post(siem::handler_seed_from_ioc))
        .route("/sentinel/schema", post(siem::handler_discover_schema))
        .route("/graph/propose", post(siem::handler_graph_propose))
        .route("/graph/build", post(siem::handler_graph_build))
        .route("/graph/neighbors", post(graph::handler_graph_neighbors))
        .route("/graph/path", post(graph::handler_graph_path))
        .route("/graph/anomaly", post(graph::handler_graph_anomaly))
        .route("/sentinel/resume", post(siem::handler_sentinel_resume))
        .route("/sentinel/pause", post(siem::handler_sentinel_pause))
        .route("/sentinel_status", get(siem::handler_sentinel_status))
        .route("/metrics", get(misc::handler_metrics))
        .fallback(misc::fallback_404)
        // 10 MB cap on request bodies. Hunt payloads are small (a DSL string
        // plus maybe a note); anything larger is almost certainly malformed
        // or hostile. Without this, a POST with a 1 GB JSON body would OOM
        // the whole process before a handler ever runs.
        .layer(axum::extract::DefaultBodyLimit::max(10 * 1024 * 1024))
        .layer(CorsLayer::new()
            .allow_origin(Any)
            .allow_methods(Any)
            .allow_headers(Any))
        .layer(axum::middleware::from_fn_with_state(state.app.clone(), auth_middleware))
        .layer(axum::middleware::from_fn(log_requests))
        .with_state(state)
}

/// Run the HTTP API on Tauri's async runtime. Use this from lib.rs via
/// `tauri::async_runtime::spawn(async move { http::run_async(state, api, port).await })`
/// so the server shares Tauri's executor and avoids cross-runtime lock contention.
pub async fn run_async(state: Arc<AppState>, api: Arc<GraphHunterApi>, port: u16) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let host = std::env::var("GRAPHHUNTER_API_HOST").unwrap_or_else(|_| "127.0.0.1".to_string());
    let addr = format!("{}:{}", host, port);
    tracing::info!("GraphHunter HTTP API: binding to {} ...", addr);

    let listener = tokio::net::TcpListener::bind(&addr).await?;
    tracing::info!(
        "GraphHunter HTTP API listening on http://{} (health: /health)",
        addr
    );
    tracing::info!("GraphHunter HTTP API: ready to accept connections.");
    if host == "0.0.0.0" {
        tracing::info!("Use http://127.0.0.1:{}/ in browser (localhost may fail on Windows due to IPv6)", port);
    }

    let app = build_app(state, api);
    axum::serve(listener, app).await?;
    Ok(())
}

/// Legacy: run the HTTP API in a dedicated thread with its own Tokio runtime.
/// Prefer run_async on Tauri's runtime to avoid cross-runtime lock issues.
#[allow(dead_code)]
pub fn run(state: Arc<AppState>, api: Arc<GraphHunterApi>, port: u16) {
    let host = std::env::var("GRAPHHUNTER_API_HOST").unwrap_or_else(|_| "127.0.0.1".to_string());
    tracing::info!("GraphHunter HTTP API: binding to {}:{} ...", host, port);
    let addr = (host.as_str(), port);
    let listener = std::net::TcpListener::bind(addr).unwrap_or_else(|e| {
        tracing::error!("GraphHunter HTTP API: failed to bind to {}:{}: {}", host, port, e);
        std::process::exit(1);
    });
    tracing::info!("GraphHunter HTTP API: bind OK, building router ...");
    let app = build_app(state, api);
    tracing::info!("GraphHunter HTTP API: creating tokio runtime (multi_thread, 8 workers) ...");
    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(8)
        .enable_all()
        .build()
        .expect("tokio runtime");
    rt.block_on(async {
        let listener = tokio::net::TcpListener::from_std(listener).expect("tcp listener");
        tracing::info!(
            "GraphHunter HTTP API listening on http://{}:{}/ (health: /health)",
            host, port
        );
        tracing::info!("GraphHunter HTTP API: ready to accept connections.");
        if host == "0.0.0.0" {
            tracing::info!("Use http://127.0.0.1:{}/ in browser (localhost may fail on Windows due to IPv6)", port);
        }
        axum::serve(listener, app).await.expect("serve");
    });
}
