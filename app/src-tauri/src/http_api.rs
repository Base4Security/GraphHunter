//! Minimal HTTP API for MCP / external tools. Bind to localhost; requires a loaded session.

use axum::{
    extract::{FromRef, Path, Query, Request, State},
    http::StatusCode,
    middleware::Next,
    response::{IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::sync::Arc;
use std::time::Duration;
use subtle::ConstantTimeEq;
use tower_http::cors::{CorsLayer, Any};

use crate::{
    PaginatedHuntResults, Subgraph, SubgraphEdge, SubgraphNode,
    AppState,
};
// `with_current_graph` no longer imported — every handler in this
// module now delegates through `Arc<GraphHunterApi>`.
use graph_hunter_api::GraphHunterApi;
use graph_hunter_core::{Hypothesis, Neighborhood};
use tauri::Emitter;

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

/// Notify frontend that notes changed (e.g. after MCP create_note) so the UI refreshes the notes list.
fn emit_notes_changed(state: &AppState) {
    if let Ok(handle_guard) = state.app_handle.read() {
        if let Some(handle) = handle_guard.as_ref() {
            let _ = handle.emit("notes-changed", ());
        }
    }
}

/// Store subgraph as last MCP view and emit to frontend so the live map updates.
fn mcp_emit_view(state: &AppState, subgraph: Subgraph) {
    if let Ok(mut guard) = state.last_mcp_subgraph.write() {
        *guard = Some(subgraph.clone());
    }
    if let Ok(handle_guard) = state.app_handle.read() {
        if let Some(handle) = handle_guard.as_ref() {
            let _ = handle.emit("mcp-view-update", &subgraph);
        }
    }
}

fn neighborhood_to_subgraph(hood: &Neighborhood) -> Subgraph {
    let nodes = hood
        .nodes
        .iter()
        .map(|n| SubgraphNode::new(
            n.id.clone(),
            n.entity_type.clone(),
            n.score,
            n.metadata.clone(),
        ))
        .collect();
    let edges = hood
        .edges
        .iter()
        .map(|e| SubgraphEdge {
            source: e.source.clone(),
            target: e.target.clone(),
            rel_type: e.rel_type.clone(),
            timestamp: e.timestamp,
            metadata: e.metadata.clone(),
            dataset_id: None,
        })
        .collect();
    Subgraph { nodes, edges }
}

/// Build subgraph for the given node IDs and emit to frontend map
/// (used after search, events, run_hunt). Delegates to the canonical
/// `api.get_subgraph`. The `_state` param is kept so the existing
/// call sites don't have to thread through a new `api` reference.
fn build_subgraph_for_ids(
    api: &GraphHunterApi,
    node_ids: &[String],
) -> Result<Subgraph, crate::error::CommandError> {
    api.get_subgraph(graph_hunter_api::dto::graph_ops::SubgraphRequest {
        session: None,
        node_ids: node_ids.to_vec(),
    })
    .map_err(crate::error::CommandError::from)
}

fn ok_json<T: Serialize>(v: T) -> Response {
    (StatusCode::OK, Json(v)).into_response()
}

fn err_json(e: impl std::fmt::Display) -> Response {
    (
        StatusCode::BAD_REQUEST,
        Json(serde_json::json!({ "error": e.to_string() })),
    )
        .into_response()
}

/// Convert an `ApiResult<T>` to an axum `Response`. Success → 200 with
/// the JSON body; failure → status from [`graph_hunter_api::ApiError::status_code`]
/// with `{ "error": <message> }`. Keeps migrated handlers to one line.
fn api_response<T: Serialize>(result: graph_hunter_api::ApiResult<T>) -> Response {
    match result {
        Ok(v) => ok_json(v),
        Err(e) => {
            let code = StatusCode::from_u16(e.status_code())
                .unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
            (code, Json(serde_json::json!({ "error": e.to_string() }))).into_response()
        }
    }
}

async fn handler_api_root() -> Response {
    ok_json(serde_json::json!({
        "service": "GraphHunter HTTP API",
        "health": "/health",
        "docs": "See README in graph-hunter-mcp for available endpoints."
    }))
}

async fn handler_health(State(api): State<Arc<GraphHunterApi>>) -> Response {
    tracing::debug!("HTTP API: /health request received");
    // Short timeout so /health never blocks on a contended session
    // store (the canonical API uses the same std RwLock internally).
    let api = api.clone();
    let session_loaded = tokio::time::timeout(
        Duration::from_millis(500),
        tokio::task::spawn_blocking(move || api.sessions().current_id().is_some()),
    )
    .await
    .unwrap_or(Ok(false))
    .unwrap_or(false);
    ok_json(serde_json::json!({
        "ok": true,
        "session_loaded": session_loaded,
        "message": if session_loaded {
            "GraphHunter app running with a session loaded."
        } else {
            "GraphHunter app running. No session loaded — create or load a session in the app."
        }
    }))
}

/// Log each request to stderr so app logs show whether /health (etc.) is hit.
async fn log_requests(request: axum::extract::Request, next: Next) -> Response {
    let method = request.method().clone();
    let uri = request.uri().clone();
    let response = next.run(request).await;
    tracing::debug!("HTTP API {} {} -> {}", method, uri, response.status());
    response
}

/// Fallback for unmatched routes: return 404 with JSON body so MCP/client can show path and method.
async fn fallback_404(request: Request) -> Response {
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

/// Bearer token auth middleware. Skips `/` and `/health` routes.
async fn auth_middleware(
    State(state): State<Arc<AppState>>,
    request: Request,
    next: Next,
) -> Response {
    let path = request.uri().path();
    // Skip auth for root and health endpoints
    if path == "/" || path == "/health" {
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
        .route("/", get(handler_api_root))
        .route("/health", get(handler_health))
        .route("/entity_types", get(handler_entity_types))
        .route("/relation_schema", get(handler_relation_schema))
        .route("/explain_score", get(handler_explain_score))
        .route("/search", get(handler_search))
        .route("/expand", get(handler_expand))
        .route("/node_details", get(handler_node_details))
        .route("/subgraph", post(handler_subgraph))
        .route("/subgraph/", post(handler_subgraph))
        .route("/events_for_node", get(handler_events_for_node))
        .route("/run_hunt", post(handler_run_hunt))
        .route("/run_hunt/", post(handler_run_hunt))
        .route("/hunt_results", get(handler_hunt_results))
        .route("/diff_hunts", post(handler_diff_hunts))
        .route("/notes", post(handler_create_note))
        .route("/notes/", post(handler_create_note))
        .route("/notes/list", get(handler_list_notes))
        .route("/notes/:id", get(handler_get_note_by_id))
        .route("/graph_summary", get(handler_graph_summary))
        .route("/entity_type_counts", get(handler_entity_type_counts))
        .route("/temporal_heatmap", get(handler_temporal_heatmap))
        .route("/subnet_analysis", get(handler_subnet_analysis))
        .route("/enrich_ip", post(handler_enrich_ip))
        .route("/catalog", get(handler_catalog))
        .route("/catalog/status", get(handler_catalog_with_status))
        .route("/catalog/diagnostics", get(handler_catalog_diagnostics))
        .route("/tag", post(handler_tag_entity))
        .route("/untag", post(handler_untag_entity))
        .route("/tags", get(handler_list_tagged))
        .route("/export_iocs", post(handler_export_iocs))
        .route("/publish_iocs_to_sentinel", post(handler_publish_iocs_to_sentinel))
        .route("/save_hypothesis_as_sigma", post(handler_save_hypothesis_as_sigma))
        .route("/file_ticket", post(handler_file_ticket))
        .route("/datasets", get(handler_list_datasets))
        .route("/path_nodes", get(handler_path_nodes))
        .route("/export_subgraph", post(handler_export_subgraph))
        .route("/parse_dsl", post(handler_parse_dsl))
        .route("/events_paginated", get(handler_events_paginated))
        .route("/expand_grouped", get(handler_expand_grouped))
        .route("/export_hunt_results", post(handler_export_hunt_results))
        .route("/enable_anomaly_scoring", post(handler_enable_anomaly_scoring))
        .route("/compute_scores", post(handler_compute_scores))
        .route("/kql", post(handler_run_kql))
        .route("/kql/", post(handler_run_kql))
        .route("/sentinel_status", get(handler_sentinel_status))
        .fallback(fallback_404)
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
/// `tauri::async_runtime::spawn(async move { http_api::run_async(state, api, port).await })`
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

async fn handler_entity_types(State(api): State<Arc<GraphHunterApi>>) -> Response {
    api_response(api.get_entity_types_in_graph(
        graph_hunter_api::dto::entity::SessionOnly::default(),
    ))
}

async fn handler_relation_schema(State(api): State<Arc<GraphHunterApi>>) -> Response {
    api_response(api.get_relation_schema(
        graph_hunter_api::dto::entity::SessionOnly::default(),
    ))
}

#[derive(Debug, Deserialize)]
struct ExplainScoreQuery {
    node_id: String,
}

async fn handler_explain_score(
    State(api): State<Arc<GraphHunterApi>>,
    Query(q): Query<ExplainScoreQuery>,
) -> Response {
    api_response(api.explain_score(graph_hunter_api::dto::entity::NodeScopedRequest {
        session: None,
        node_id: q.node_id,
    }))
}

#[derive(Debug, Deserialize)]
struct SearchQuery {
    // `q` is optional on the wire so a missing param produces our own
    // structured 400 JSON instead of axum's plain-text "failed to
    // deserialize query string" response — which the MCP client
    // surfaces as "did not return JSON" and looks like a transport break.
    #[serde(default)]
    q: Option<String>,
    #[serde(rename = "type")]
    type_filter: Option<String>,
    limit: Option<usize>,
}

async fn handler_search(
    State(state): State<Arc<AppState>>,
    State(api): State<Arc<GraphHunterApi>>,
    Query(q): Query<SearchQuery>,
) -> Response {
    match api.search_entities(graph_hunter_api::dto::graph_ops::SearchEntitiesRequest {
        session: None,
        query: q.q.unwrap_or_default(),
        type_filter: q.type_filter,
        limit: q.limit,
    }) {
        Ok(v) => {
            let node_ids: Vec<String> = v.iter().map(|r| r.id.clone()).collect();
            if !node_ids.is_empty() {
                if let Ok(sg) = build_subgraph_for_ids(api.as_ref(), &node_ids) {
                    mcp_emit_view(state.as_ref(), sg);
                }
            }
            ok_json(v)
        }
        Err(e) => {
            let code = StatusCode::from_u16(e.status_code())
                .unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
            (code, Json(serde_json::json!({ "error": e.to_string() }))).into_response()
        }
    }
}

#[derive(Debug, Deserialize)]
struct ExpandQuery {
    node_id: String,
    max_hops: Option<usize>,
    max_nodes: Option<usize>,
}

async fn handler_expand(
    State(state): State<Arc<AppState>>,
    State(api): State<Arc<GraphHunterApi>>,
    Query(q): Query<ExpandQuery>,
) -> Response {
    let api_clone = api.clone();
    let result = tokio::time::timeout(
        Duration::from_secs(60),
        tokio::task::spawn_blocking(move || {
            api_clone.expand_node(graph_hunter_api::dto::graph_ops::ExpandNodeRequest {
                session: None,
                node_id: q.node_id,
                max_hops: q.max_hops,
                max_nodes: q.max_nodes,
                filter: None,
            })
        }),
    )
    .await;
    match result {
        Ok(Ok(Ok(hood))) => {
            let sg = neighborhood_to_subgraph(&hood);
            mcp_emit_view(state.as_ref(), sg);
            ok_json(hood)
        }
        Ok(Ok(Err(e))) => {
            let code = StatusCode::from_u16(e.status_code())
                .unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
            (code, Json(serde_json::json!({ "error": e.to_string() }))).into_response()
        }
        Ok(Err(e)) => err_json(format!("Task error: {}", e)),
        Err(_) => err_json("Expand timed out after 60 seconds"),
    }
}

#[derive(Debug, Deserialize)]
struct NodeDetailsQuery {
    node_id: String,
}

async fn handler_node_details(
    State(api): State<Arc<GraphHunterApi>>,
    Query(q): Query<NodeDetailsQuery>,
) -> Response {
    let api_clone = api.clone();
    let node_id = q.node_id.clone();
    let result = tokio::time::timeout(
        Duration::from_secs(30),
        tokio::task::spawn_blocking(move || {
            api_clone.get_node_details(graph_hunter_api::dto::entity::NodeScopedRequest {
                session: None,
                node_id,
            })
        }),
    )
    .await;
    match result {
        Ok(Ok(Ok(v))) => ok_json(v),
        Ok(Ok(Err(e))) => {
            let code = StatusCode::from_u16(e.status_code())
                .unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
            (code, Json(serde_json::json!({ "error": e.to_string() }))).into_response()
        },
        Ok(Err(e)) => err_json(format!("Task error: {}", e)),
        Err(_) => err_json("Node details timed out after 30 seconds"),
    }
}

#[derive(Debug, Deserialize)]
struct SubgraphBody {
    node_ids: Vec<String>,
}

async fn handler_subgraph(
    State(state): State<Arc<AppState>>,
    State(api): State<Arc<GraphHunterApi>>,
    Json(body): Json<SubgraphBody>,
) -> Response {
    let api_clone = api.clone();
    let result = tokio::time::timeout(
        Duration::from_secs(60),
        tokio::task::spawn_blocking(move || {
            api_clone.get_subgraph(graph_hunter_api::dto::graph_ops::SubgraphRequest {
                session: None,
                node_ids: body.node_ids,
            })
        }),
    )
    .await;
    match result {
        Ok(Ok(Ok(sg))) => {
            mcp_emit_view(state.as_ref(), sg.clone());
            ok_json(sg)
        }
        Ok(Ok(Err(e))) => {
            let code = StatusCode::from_u16(e.status_code())
                .unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
            (code, Json(serde_json::json!({ "error": e.to_string() }))).into_response()
        }
        Ok(Err(e)) => err_json(format!("Task error: {}", e)),
        Err(_) => err_json("Subgraph query timed out after 60 seconds"),
    }
}

#[derive(Debug, Deserialize)]
struct EventsQuery {
    node_id: String,
}

async fn handler_events_for_node(
    State(state): State<Arc<AppState>>,
    State(api): State<Arc<GraphHunterApi>>,
    Query(q): Query<EventsQuery>,
) -> Response {
    let api_clone = api.clone();
    let node_id = q.node_id.clone();
    let result = tokio::time::timeout(
        Duration::from_secs(60),
        tokio::task::spawn_blocking(move || {
            let edges = api_clone.get_events_for_node(
                graph_hunter_api::dto::graph_ops::EventsForNodeRequest {
                    session: None,
                    node_id: node_id.clone(),
                },
            )?;
            // Build subgraph for the event participants to update the frontend map
            let mut ids: HashSet<String> = HashSet::new();
            ids.insert(node_id);
            for e in &edges {
                ids.insert(e.source.clone());
                ids.insert(e.target.clone());
            }
            let node_ids: Vec<String> = ids.into_iter().collect();
            let sg = if !node_ids.is_empty() {
                build_subgraph_for_ids(api_clone.as_ref(), &node_ids).ok()
            } else {
                None
            };
            Ok::<_, graph_hunter_api::ApiError>((edges, sg))
        }),
    )
    .await;
    match result {
        Ok(Ok(Ok((edges, sg)))) => {
            if let Some(sg) = sg {
                mcp_emit_view(state.as_ref(), sg);
            }
            ok_json(edges)
        }
        Ok(Ok(Err(e))) => {
            let code = StatusCode::from_u16(e.status_code())
                .unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
            (code, Json(serde_json::json!({ "error": e.to_string() }))).into_response()
        }
        Ok(Err(e)) => err_json(format!("Task error: {}", e)),
        Err(_) => err_json("Events query timed out after 60 seconds"),
    }
}

#[derive(Debug, Deserialize)]
struct CreateNoteBody {
    content: String,
    node_id: Option<String>,
}

async fn handler_create_note(
    State(state): State<Arc<AppState>>,
    State(api): State<Arc<GraphHunterApi>>,
    Json(body): Json<CreateNoteBody>,
) -> Response {
    match api.create_note(graph_hunter_api::dto::entity::CreateNoteRequest {
        session: None,
        content: body.content,
        node_id: body.node_id,
    }) {
        Ok(note) => {
            emit_notes_changed(state.as_ref());
            ok_json(note)
        }
        Err(e) => {
            let code = axum::http::StatusCode::from_u16(e.status_code())
                .unwrap_or(axum::http::StatusCode::INTERNAL_SERVER_ERROR);
            (code, Json(serde_json::json!({ "error": e.to_string() }))).into_response()
        }
    }
}

#[derive(Debug, Deserialize)]
struct HuntResultsQuery {
    page: Option<usize>,
    page_size: Option<usize>,
    min_score: Option<f64>,
}

async fn handler_hunt_results(
    State(api): State<Arc<GraphHunterApi>>,
    Query(q): Query<HuntResultsQuery>,
) -> Response {
    let page = q.page.unwrap_or(0);
    let page_size = q.page_size.unwrap_or(20);
    match api.get_hunt_page(graph_hunter_api::dto::hunt::GetHuntPageRequest {
        session: None,
        page,
        page_size,
        min_score: q.min_score,
        dedup_mode: Some(graph_hunter_core::DedupMode::ByPath),
    }) {
        Ok(resp) => ok_json(PaginatedHuntResults {
            total_paths: resp.total_paths,
            filtered_paths: resp.filtered_paths,
            page: resp.page,
            page_size: resp.page_size,
            paths: resp.paths,
        }),
        Err(e) => {
            let code = StatusCode::from_u16(e.status_code())
                .unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
            (code, Json(serde_json::json!({ "error": e.to_string() }))).into_response()
        }
    }
}

#[derive(Debug, Deserialize)]
struct RunHuntBody {
    hypothesis_dsl: String,
}

#[derive(serde::Serialize)]
struct RunHuntResponse {
    path_count: usize,
    truncated: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    diagnostic: Option<graph_hunter_core::HuntDiagnostic>,
}

/// Write-heavy handler: uses spawn_blocking + timeout to avoid holding the async runtime.
async fn handler_run_hunt(
    State(state): State<Arc<AppState>>,
    State(api): State<Arc<GraphHunterApi>>,
    Json(body): Json<RunHuntBody>,
) -> Response {
    let hypothesis: Hypothesis = match graph_hunter_core::parse_dsl(
        body.hypothesis_dsl.trim(),
        Some("MCP Hunt"),
    ) {
        Ok(r) => r.hypothesis,
        Err(e) => return err_json(e.to_string()),
    };
    let api_clone = api.clone();
    let hypothesis_for_search = hypothesis.clone();
    let result = tokio::time::timeout(
        Duration::from_secs(30),
        tokio::task::spawn_blocking(move || {
            api_clone.run_hunt(graph_hunter_api::dto::hunt::RunHuntRequest {
                session: None,
                hypothesis: hypothesis_for_search,
                time_window: None,
                max_results: Some(10_000),
            })
        }),
    )
    .await;

    match result {
        Ok(Ok(Ok(resp))) => {
            // The cache is already populated by api.run_hunt; we just
            // need to emit the mcp-view-update for the matched nodes.
            // Build `node_ids` from cache (resp.paths is empty when > 100).
            let paths = if resp.paths.is_empty() {
                // Pull from the shared hunt-cache handle (same Arc the
                // API just wrote to). Using the API's `hunt_cache_handle`
                // keeps every transport on the exact same state.
                api.hunt_cache_handle()
                    .read()
                    .ok()
                    .map(|g| g.clone())
                    .unwrap_or_default()
            } else {
                resp.paths.clone()
            };
            let node_ids: Vec<String> = paths
                .iter()
                .flat_map(|p| p.iter().cloned())
                .collect::<HashSet<_>>()
                .into_iter()
                .collect();
            if !node_ids.is_empty() {
                if let Ok(sg) = build_subgraph_for_ids(api.as_ref(), &node_ids) {
                    mcp_emit_view(state.as_ref(), sg);
                }
            } else if resp.path_count == 0 {
                mcp_emit_view(
                    state.as_ref(),
                    Subgraph {
                        nodes: vec![],
                        edges: vec![],
                    },
                );
            }
            ok_json(RunHuntResponse {
                path_count: resp.path_count,
                truncated: resp.truncated,
                diagnostic: resp.diagnostic,
            })
        }
        Ok(Ok(Err(e))) => {
            let code = StatusCode::from_u16(e.status_code())
                .unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
            (code, Json(serde_json::json!({ "error": e.to_string() }))).into_response()
        }
        Ok(Err(e)) => err_json(format!("Task error: {}", e)),
        Err(_) => err_json("Hunt timed out after 30 seconds".to_string()),
    }
}

#[derive(Debug, Deserialize)]
struct DiffHuntsBody {
    hypothesis_dsl: String,
    baseline_ts: i64,
    current_ts: i64,
}

async fn handler_diff_hunts(
    State(api): State<Arc<GraphHunterApi>>,
    Json(body): Json<DiffHuntsBody>,
) -> Response {
    let hypothesis: Hypothesis = match graph_hunter_core::parse_dsl(
        body.hypothesis_dsl.trim(),
        Some("MCP Diff Hunt"),
    ) {
        Ok(r) => r.hypothesis,
        Err(e) => return err_json(e.to_string()),
    };
    let api_clone = api.clone();
    let result = tokio::time::timeout(
        Duration::from_secs(60),
        tokio::task::spawn_blocking(move || {
            api_clone.diff_hunts(graph_hunter_api::dto::hunt::DiffHuntsRequest {
                session: None,
                hypothesis,
                baseline_ts: body.baseline_ts,
                current_ts: body.current_ts,
            })
        }),
    )
    .await;

    match result {
        Ok(Ok(Ok(v))) => ok_json(v),
        Ok(Ok(Err(e))) => {
            let code = StatusCode::from_u16(e.status_code())
                .unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
            (code, Json(serde_json::json!({ "error": e.to_string() }))).into_response()
        }
        Ok(Err(e)) => err_json(format!("Task error: {}", e)),
        Err(_) => err_json("Diff timed out after 60 seconds".to_string()),
    }
}

// ── New MCP endpoints ──────────────────────────────────────────────────

async fn handler_graph_summary(State(api): State<Arc<GraphHunterApi>>) -> Response {
    api_response(api.get_graph_summary(
        graph_hunter_api::dto::geoip::GraphSummaryRequest::default(),
    ))
}

async fn handler_entity_type_counts(State(api): State<Arc<GraphHunterApi>>) -> Response {
    api_response(api.get_entity_type_counts(
        graph_hunter_api::dto::entity::SessionOnly::default(),
    ))
}

#[derive(Debug, Deserialize)]
struct HeatmapQuery {
    #[serde(default)]
    bucket_size_seconds: Option<i64>,
}

async fn handler_temporal_heatmap(
    State(api): State<Arc<GraphHunterApi>>,
    Query(q): Query<HeatmapQuery>,
) -> Response {
    api_response(api.get_temporal_heatmap(
        graph_hunter_api::dto::analytics::TemporalHeatmapRequest {
            session: None,
            bucket_size_seconds: q.bucket_size_seconds,
        },
    ))
}

async fn handler_subnet_analysis(State(api): State<Arc<GraphHunterApi>>) -> Response {
    match api.get_subnet_analysis(graph_hunter_api::dto::enrichment::SubnetAnalysisRequest::default())
    {
        Ok(v) => ok_json(v),
        Err(e) => {
            let code = axum::http::StatusCode::from_u16(e.status_code())
                .unwrap_or(axum::http::StatusCode::INTERNAL_SERVER_ERROR);
            (code, Json(serde_json::json!({ "error": e.to_string() }))).into_response()
        }
    }
}

#[derive(Debug, Deserialize)]
struct EnrichIpBody {
    ip: String,
}

async fn handler_enrich_ip(
    State(api): State<Arc<GraphHunterApi>>,
    Json(body): Json<EnrichIpBody>,
) -> Response {
    match api
        .enrich_ip(graph_hunter_api::dto::geoip::EnrichIpRequest {
            session: None,
            ip: body.ip,
        })
        .await
    {
        Ok(v) => ok_json(v),
        Err(e) => {
            let code = StatusCode::from_u16(e.status_code())
                .unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
            (code, Json(serde_json::json!({ "error": e.to_string() }))).into_response()
        }
    }
}

async fn handler_catalog(State(api): State<Arc<GraphHunterApi>>) -> Response {
    ok_json(api.get_catalog())
}

async fn handler_catalog_with_status(State(api): State<Arc<GraphHunterApi>>) -> Response {
    match api
        .get_catalog_with_status(graph_hunter_api::dto::dsl::GetCatalogWithStatusRequest::default())
    {
        Ok(v) => ok_json(v),
        Err(e) => {
            let code = axum::http::StatusCode::from_u16(e.status_code())
                .unwrap_or(axum::http::StatusCode::INTERNAL_SERVER_ERROR);
            (code, Json(serde_json::json!({ "error": e.to_string() }))).into_response()
        }
    }
}

async fn handler_catalog_diagnostics(State(api): State<Arc<GraphHunterApi>>) -> Response {
    ok_json(api.get_catalog_diagnostics())
}

#[derive(Debug, Deserialize)]
struct TagEntityBody {
    node_id: String,
    tag: String,
    #[serde(default)]
    reason: Option<String>,
}

async fn handler_tag_entity(
    State(api): State<Arc<GraphHunterApi>>,
    Json(body): Json<TagEntityBody>,
) -> Response {
    api_response(api.tag_entity(graph_hunter_api::dto::entity::TagEntityRequest {
        session: None,
        node_id: body.node_id,
        tag: body.tag,
        reason: body.reason,
    }))
}

#[derive(Debug, Deserialize)]
struct UntagEntityBody {
    node_id: String,
    tag: String,
}

async fn handler_untag_entity(
    State(api): State<Arc<GraphHunterApi>>,
    Json(body): Json<UntagEntityBody>,
) -> Response {
    match api.untag_entity(graph_hunter_api::dto::entity::UntagEntityRequest {
        session: None,
        node_id: body.node_id,
        tag: body.tag,
    }) {
        Ok(()) => ok_json(serde_json::json!({"ok": true})),
        Err(e) => {
            let code = StatusCode::from_u16(e.status_code())
                .unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
            (code, Json(serde_json::json!({ "error": e.to_string() }))).into_response()
        }
    }
}

#[derive(Debug, Deserialize)]
struct ListTaggedQuery {
    #[serde(default)]
    tag_prefix: Option<String>,
}

async fn handler_list_tagged(
    State(api): State<Arc<GraphHunterApi>>,
    Query(q): Query<ListTaggedQuery>,
) -> Response {
    api_response(api.list_tagged(graph_hunter_api::dto::entity::ListTaggedRequest {
        session: None,
        tag_prefix: q.tag_prefix,
    }))
}

#[derive(Debug, Deserialize)]
struct ExportIocsBody {
    format: String,
    #[serde(default)]
    tag_prefix: Option<String>,
}

async fn handler_export_iocs(
    State(api): State<Arc<GraphHunterApi>>,
    Json(body): Json<ExportIocsBody>,
) -> Response {
    let format = body.format.clone();
    match api.export_iocs(graph_hunter_api::dto::export::ExportIocsRequest {
        session: None,
        format: body.format,
        tag_prefix: body.tag_prefix,
    }) {
        Ok(data) => ok_json(serde_json::json!({ "data": data, "format": format })),
        Err(e) => {
            let code = StatusCode::from_u16(e.status_code())
                .unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
            (code, Json(serde_json::json!({ "error": e.to_string() }))).into_response()
        }
    }
}

#[derive(Debug, Deserialize)]
struct PublishIocsBody {
    watchlist_name: String,
    #[serde(default)]
    display_name: Option<String>,
    #[serde(default)]
    description: Option<String>,
    #[serde(default)]
    tag_prefix: Option<String>,
    #[serde(default)]
    dry_run: Option<bool>,
    #[serde(default)]
    confirm: Option<bool>,
}

async fn handler_publish_iocs_to_sentinel(
    State(api): State<Arc<GraphHunterApi>>,
    Json(body): Json<PublishIocsBody>,
) -> Response {
    match api
        .publish_iocs_to_sentinel(graph_hunter_api::dto::sentinel::PublishIocsRequest {
            session: None,
            watchlist_name: body.watchlist_name,
            display_name: body.display_name,
            description: body.description,
            tag_prefix: body.tag_prefix,
            dry_run: body.dry_run.unwrap_or(false),
            confirm: body.confirm.unwrap_or(false),
        })
        .await
    {
        Ok(v) => ok_json(v),
        Err(e) => {
            let code = StatusCode::from_u16(e.status_code())
                .unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
            (code, Json(serde_json::json!({ "error": e.to_string() }))).into_response()
        }
    }
}

#[derive(Debug, Deserialize)]
struct SaveSigmaBody {
    hypothesis_dsl: String,
    title: String,
    #[serde(default)]
    tag_prefix: Option<String>,
    #[serde(default)]
    level: Option<String>,
}

async fn handler_save_hypothesis_as_sigma(
    State(api): State<Arc<GraphHunterApi>>,
    Json(body): Json<SaveSigmaBody>,
) -> Response {
    let api_clone = api.clone();
    let res = tokio::task::spawn_blocking(move || {
        api_clone.save_hypothesis_as_sigma(graph_hunter_api::dto::sigma::SaveHypothesisAsSigmaRequest {
            session: None,
            hypothesis_dsl: body.hypothesis_dsl,
            title: body.title,
            tag_prefix: body.tag_prefix,
            level: body.level,
        })
    })
    .await;
    match res {
        Ok(Ok(v)) => ok_json(v),
        Ok(Err(e)) => {
            let code = StatusCode::from_u16(e.status_code())
                .unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
            (code, Json(serde_json::json!({ "error": e.to_string() }))).into_response()
        }
        Err(e) => err_json(format!("Task error: {e}")),
    }
}

#[derive(Debug, Deserialize)]
struct FileTicketBody {
    system: String,
    title: String,
    body: String,
    #[serde(default)]
    priority: Option<String>,
    #[serde(default)]
    assignee: Option<String>,
    #[serde(default)]
    dry_run: Option<bool>,
    #[serde(default)]
    confirm: Option<bool>,
}

async fn handler_file_ticket(
    State(api): State<Arc<GraphHunterApi>>,
    Json(body): Json<FileTicketBody>,
) -> Response {
    match api
        .file_ticket(graph_hunter_api::dto::ticket::FileTicketRequest {
            system: body.system,
            title: body.title,
            body: body.body,
            priority: body.priority,
            assignee: body.assignee,
            dry_run: body.dry_run.unwrap_or(false),
            confirm: body.confirm.unwrap_or(false),
        })
        .await
    {
        Ok(v) => ok_json(v),
        Err(e) => {
            let code = StatusCode::from_u16(e.status_code())
                .unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
            (code, Json(serde_json::json!({ "error": e.to_string() }))).into_response()
        }
    }
}

async fn handler_list_datasets(State(api): State<Arc<GraphHunterApi>>) -> Response {
    api_response(api.list_datasets(
        graph_hunter_api::dto::dataset::ListDatasetsRequest::default(),
    ))
}

async fn handler_path_nodes(State(api): State<Arc<GraphHunterApi>>) -> Response {
    api_response(api.get_path_nodes(
        graph_hunter_api::dto::entity::SessionOnly::default(),
    ))
}

async fn handler_list_notes(State(api): State<Arc<GraphHunterApi>>) -> Response {
    api_response(api.get_notes(
        graph_hunter_api::dto::entity::SessionOnly::default(),
    ))
}

/// Fetch a single note by its UUID. Used as the target of the `url` field
/// returned by `cmd_create_note` so external systems (Jira, Zoho, Slack)
/// can link directly to the note without reproducing the note list logic.
async fn handler_get_note_by_id(
    State(api): State<Arc<GraphHunterApi>>,
    Path(id): Path<String>,
) -> Response {
    match api.get_notes(graph_hunter_api::dto::entity::SessionOnly::default()) {
        Ok(notes) => match notes.into_iter().find(|n| n.id == id) {
            Some(note) => ok_json(note),
            None => (
                StatusCode::NOT_FOUND,
                Json(serde_json::json!({ "error": format!("note not found: {id}") })),
            )
                .into_response(),
        },
        Err(e) => {
            let code = StatusCode::from_u16(e.status_code())
                .unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
            (code, Json(serde_json::json!({ "error": e.to_string() }))).into_response()
        }
    }
}

#[derive(Debug, Deserialize)]
struct ExportSubgraphBody {
    node_ids: Vec<String>,
    format: Option<String>,
}

async fn handler_export_subgraph(
    State(api): State<Arc<GraphHunterApi>>,
    Json(body): Json<ExportSubgraphBody>,
) -> Response {
    let fmt = body.format.unwrap_or_else(|| "json".to_string());
    let fmt_for_resp = fmt.clone();
    match api.export_subgraph(graph_hunter_api::dto::export::ExportSubgraphRequest {
        session: None,
        format: fmt,
        nodes: body.node_ids,
    }) {
        Ok(text) => ok_json(serde_json::json!({ "data": text, "format": fmt_for_resp })),
        Err(e) => {
            let code = StatusCode::from_u16(e.status_code())
                .unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
            (code, Json(serde_json::json!({ "error": e.to_string() }))).into_response()
        }
    }
}

// ── Phase 2: Complete MCP coverage ─────────────────────────────────────

#[derive(Debug, Deserialize)]
struct ParseDslBody {
    dsl: String,
    name: Option<String>,
}

async fn handler_parse_dsl(
    State(api): State<Arc<GraphHunterApi>>,
    Json(body): Json<ParseDslBody>,
) -> Response {
    // Preserve the legacy `{valid, formatted, steps}` / `{valid:false, error}`
    // shape for existing MCP clients. The canonical error path
    // (`ApiError::InvalidInput` → 400) will become the default when MCP
    // clients are migrated in a later phase; for now, adapt.
    match api.parse_dsl(graph_hunter_api::dto::dsl::ParseDslRequest {
        input: body.dsl,
        name: body.name,
    }) {
        Ok(resp) => ok_json(serde_json::json!({
            "valid": true,
            "formatted": resp.formatted,
            "steps": resp.steps,
        })),
        Err(e) => ok_json(serde_json::json!({
            "valid": false,
            "error": e.to_string(),
        })),
    }
}

#[derive(Debug, Deserialize)]
struct EventsPaginatedQuery {
    node_id: String,
    page: Option<usize>,
    page_size: Option<usize>,
    sort_by: Option<String>,
}

async fn handler_events_paginated(
    State(api): State<Arc<GraphHunterApi>>,
    Query(q): Query<EventsPaginatedQuery>,
) -> Response {
    let api_clone = api.clone();
    let result = tokio::time::timeout(
        Duration::from_secs(60),
        tokio::task::spawn_blocking(move || {
            api_clone.get_events_paginated(
                graph_hunter_api::dto::graph_ops::EventsPaginatedRequest {
                    session: None,
                    node_id: q.node_id,
                    page: q.page.unwrap_or(0),
                    page_size: q.page_size,
                    sort_by: q.sort_by,
                },
            )
        }),
    )
    .await;
    match result {
        Ok(Ok(Ok(v))) => ok_json(v),
        Ok(Ok(Err(e))) => {
            let code = StatusCode::from_u16(e.status_code())
                .unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
            (code, Json(serde_json::json!({ "error": e.to_string() }))).into_response()
        }
        Ok(Err(e)) => err_json(format!("Task error: {e}")),
        Err(_) => err_json("Events query timed out"),
    }
}

async fn handler_expand_grouped(
    State(api): State<Arc<GraphHunterApi>>,
    Query(q): Query<ExpandQuery>,
) -> Response {
    let api_clone = api.clone();
    let result = tokio::time::timeout(
        Duration::from_secs(60),
        tokio::task::spawn_blocking(move || {
            api_clone.expand_node_grouped(graph_hunter_api::dto::graph_ops::ExpandNodeRequest {
                session: None,
                node_id: q.node_id,
                max_hops: q.max_hops,
                max_nodes: q.max_nodes,
                filter: None,
            })
        }),
    )
    .await;
    match result {
        Ok(Ok(Ok(v))) => ok_json(v),
        Ok(Ok(Err(e))) => {
            let code = StatusCode::from_u16(e.status_code())
                .unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
            (code, Json(serde_json::json!({ "error": e.to_string() }))).into_response()
        }
        Ok(Err(e)) => err_json(format!("Task error: {e}")),
        Err(_) => err_json("Expand grouped timed out"),
    }
}

#[derive(Debug, Deserialize)]
struct ExportHuntBody {
    format: Option<String>,
    #[serde(default)]
    page: Option<usize>,
    #[serde(default)]
    page_size: Option<usize>,
    /// When `true`, collapses identical paths (DedupMode::ByPath) — the
    /// critical fix for the 166 KB transport truncation the feedback cited.
    #[serde(default)]
    aggregate: Option<bool>,
}

async fn handler_export_hunt_results(
    State(api): State<Arc<GraphHunterApi>>,
    Json(body): Json<ExportHuntBody>,
) -> Response {
    let fmt = body.format.unwrap_or_else(|| "json".to_string());
    let fmt_for_resp = fmt.clone();
    match api.export_hunt_results(graph_hunter_api::dto::export::ExportHuntResultsRequest {
        session: None,
        format: fmt,
        page: body.page,
        page_size: body.page_size,
        aggregate: body.aggregate,
    }) {
        Ok(text) => ok_json(serde_json::json!({ "data": text, "format": fmt_for_resp })),
        Err(e) => {
            let code = StatusCode::from_u16(e.status_code())
                .unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
            (code, Json(serde_json::json!({ "error": e.to_string() }))).into_response()
        }
    }
}

async fn handler_enable_anomaly_scoring(State(api): State<Arc<GraphHunterApi>>) -> Response {
    match api.enable_anomaly_scoring(
        graph_hunter_api::dto::anomaly::EnableAnomalyScoringRequest::default(),
    ) {
        Ok(()) => ok_json(serde_json::json!({ "enabled": true })),
        Err(e) => {
            let code = StatusCode::from_u16(e.status_code())
                .unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
            (code, Json(serde_json::json!({ "error": e.to_string() }))).into_response()
        }
    }
}

async fn handler_compute_scores(State(api): State<Arc<GraphHunterApi>>) -> Response {
    let api_clone = api.clone();
    let result = tokio::time::timeout(
        Duration::from_secs(120),
        tokio::task::spawn_blocking(move || {
            api_clone
                .compute_scores(graph_hunter_api::dto::graph_ops::ComputeScoresRequest::default())
                .map(|()| serde_json::json!({ "computed": true }))
                .map_err(|e| crate::error::CommandError::from(e))
        }),
    )
    .await;
    match result {
        Ok(Ok(Ok(v))) => ok_json(v),
        Ok(Ok(Err(e))) => err_json(e),
        Ok(Err(e)) => err_json(format!("Task error: {e}")),
        Err(_) => err_json("Score computation timed out"),
    }
}

// ── KQL / Sentinel MCP endpoints ──

#[derive(Debug, Deserialize)]
struct RunKqlBody {
    kql: String,
    #[serde(default)]
    workspace_id: Option<String>,
    #[serde(default)]
    azure_tenant_id: Option<String>,
    #[serde(default)]
    azure_client_id: Option<String>,
    #[serde(default)]
    azure_client_secret: Option<String>,
}

/// Execute an ad-hoc KQL query against Azure Log Analytics. Delegates
/// to the canonical API.
async fn handler_run_kql(
    State(api): State<Arc<GraphHunterApi>>,
    Json(body): Json<RunKqlBody>,
) -> Response {
    let result = tokio::time::timeout(
        Duration::from_secs(120),
        api.run_kql(graph_hunter_api::dto::sentinel::RunKqlRequest {
            kql: body.kql,
            workspace_id: body.workspace_id.unwrap_or_default(),
            azure_tenant_id: body.azure_tenant_id.unwrap_or_default(),
            azure_client_id: body.azure_client_id.unwrap_or_default(),
            azure_client_secret: body.azure_client_secret.unwrap_or_default(),
        }),
    )
    .await;
    match result {
        Ok(Ok(v)) => ok_json(v),
        Ok(Err(e)) => {
            let code = StatusCode::from_u16(e.status_code())
                .unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
            (code, Json(serde_json::json!({ "error": e.to_string() }))).into_response()
        }
        Err(_) => err_json("KQL execution timed out (120s)"),
    }
}

/// Get current Sentinel connector status.
async fn handler_sentinel_status(State(api): State<Arc<GraphHunterApi>>) -> Response {
    match api.sentinel_status() {
        Ok(v) => return ok_json(v),
        Err(e) => {
            let code = StatusCode::from_u16(e.status_code())
                .unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
            return (code, Json(serde_json::json!({ "error": e.to_string() }))).into_response();
        }
    }
    #[allow(unreachable_code)]
    {
        // Legacy branches left as dead code for one release; the
        // canonical api.sentinel_status() already returns the `None`
        // case as a proper response.
        ok_json(serde_json::json!({
            "connected": false,
            "connector_id": null,
            "status": null,
        }))
    }
}
