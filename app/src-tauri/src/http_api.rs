//! Minimal HTTP API for MCP / external tools. Bind to localhost; requires a loaded session.

use axum::{
    extract::{Request, Query, State},
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

use crate::{
    create_note_impl,
    PaginatedHuntResults, Subgraph, SubgraphEdge, SubgraphNode,
    with_current_graph, with_current_session_and_graph,
    AppState,
};
use graph_hunter_core::{Hypothesis, Neighborhood};
use tauri::Emitter;

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

/// Build subgraph for the given node IDs and emit to frontend map (used after search, events, run_hunt).
fn build_subgraph_for_ids(state: &AppState, node_ids: &[String]) -> Result<Subgraph, crate::error::CommandError> {
    const MAX_SUBGRAPH_EDGES: usize = 5000;
    let id_set: HashSet<&str> = node_ids.iter().map(|s| s.as_str()).collect();
    with_current_graph(state, |graph| {
        let nodes: Vec<SubgraphNode> = node_ids
            .iter()
            .filter_map(|id| graph.get_entity(id))
            .map(|e| SubgraphNode::new(
                e.id.clone(),
                format!("{}", e.entity_type),
                e.score,
                e.metadata.clone(),
            ))
            .collect();
        let mut edges: Vec<SubgraphEdge> = Vec::new();
        'outer: for source_id in node_ids {
            // Cap per-source iteration to avoid stalling on high-degree nodes (1M+ edges)
            for compact in graph.get_compact_relations(source_id).iter().take(graph_hunter_core::config::MAX_SCAN_EDGES) {
                if edges.len() >= MAX_SUBGRAPH_EDGES { break 'outer; }
                let dest_str = graph.interner.resolve(compact.dest_sid);
                if id_set.contains(dest_str) {
                    edges.push(SubgraphEdge {
                        source: graph.interner.resolve(compact.source_sid).to_string(),
                        target: dest_str.to_string(),
                        rel_type: format!("{}", compact.rel_type()),
                        timestamp: compact.timestamp,
                        metadata: graph.meta_store.get(compact.metadata_offset),
                        dataset_id: graph.resolve_dataset_tag(compact.dataset_tag).map(|s| s.to_string()),
                    });
                }
            }
        }
        Ok(Subgraph { nodes, edges })
    })
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

async fn handler_api_root() -> Response {
    ok_json(serde_json::json!({
        "service": "GraphHunter HTTP API",
        "health": "/health",
        "docs": "See README in graph-hunter-mcp for available endpoints."
    }))
}

async fn handler_health(State(state): State<Arc<AppState>>) -> Response {
    tracing::debug!("HTTP API: /health request received");
    // Run state read in spawn_blocking with a short timeout so we never hang the handler.
    // If the lock is contended or the blocking pool is starved, we return after 500ms.
    let state = state.clone();
    let session_loaded = tokio::time::timeout(
        Duration::from_millis(500),
        tokio::task::spawn_blocking(move || {
            state
                .current_session_id
                .try_read()
                .ok()
                .and_then(|g| g.clone())
                .is_some()
        }),
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
        Some(val) if val.starts_with("Bearer ") && &val[7..] == expected => {
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
fn build_app(state: Arc<AppState>) -> Router {
    Router::new()
        .route("/", get(handler_api_root))
        .route("/health", get(handler_health))
        .route("/entity_types", get(handler_entity_types))
        .route("/search", get(handler_search))
        .route("/expand", get(handler_expand))
        .route("/node_details", get(handler_node_details))
        .route("/subgraph", post(handler_subgraph))
        .route("/subgraph/", post(handler_subgraph))
        .route("/events_for_node", get(handler_events_for_node))
        .route("/run_hunt", post(handler_run_hunt))
        .route("/run_hunt/", post(handler_run_hunt))
        .route("/hunt_results", get(handler_hunt_results))
        .route("/notes", post(handler_create_note))
        .route("/notes/", post(handler_create_note))
        .route("/notes/list", get(handler_list_notes))
        .route("/graph_summary", get(handler_graph_summary))
        .route("/entity_type_counts", get(handler_entity_type_counts))
        .route("/temporal_heatmap", get(handler_temporal_heatmap))
        .route("/subnet_analysis", get(handler_subnet_analysis))
        .route("/enrich_ip", post(handler_enrich_ip))
        .route("/catalog", get(handler_catalog))
        .route("/datasets", get(handler_list_datasets))
        .route("/path_nodes", get(handler_path_nodes))
        .route("/export_subgraph", post(handler_export_subgraph))
        .route("/parse_dsl", post(handler_parse_dsl))
        .route("/events_paginated", get(handler_events_paginated))
        .route("/expand_grouped", get(handler_expand_grouped))
        .route("/export_hunt_results", post(handler_export_hunt_results))
        .route("/enable_anomaly_scoring", post(handler_enable_anomaly_scoring))
        .route("/compute_scores", post(handler_compute_scores))
        .fallback(fallback_404)
        // 10 MB cap on request bodies. Hunt payloads are small (a DSL string
        // plus maybe a note); anything larger is almost certainly malformed
        // or hostile. Without this, a POST with a 1 GB JSON body would OOM
        // the whole process before a handler ever runs.
        .layer(axum::extract::DefaultBodyLimit::max(10 * 1024 * 1024))
        .layer(axum::middleware::from_fn_with_state(state.clone(), auth_middleware))
        .layer(axum::middleware::from_fn(log_requests))
        .with_state(state)
}

/// Run the HTTP API on Tauri's async runtime. Use this from lib.rs via
/// `tauri::async_runtime::spawn(async move { http_api::run_async(state, port).await })`
/// so the server shares Tauri's executor and avoids cross-runtime lock contention.
pub async fn run_async(state: Arc<AppState>, port: u16) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
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

    let app = build_app(state);
    axum::serve(listener, app).await?;
    Ok(())
}

/// Legacy: run the HTTP API in a dedicated thread with its own Tokio runtime.
/// Prefer run_async on Tauri's runtime to avoid cross-runtime lock issues.
#[allow(dead_code)]
pub fn run(state: Arc<AppState>, port: u16) {
    let host = std::env::var("GRAPHHUNTER_API_HOST").unwrap_or_else(|_| "127.0.0.1".to_string());
    tracing::info!("GraphHunter HTTP API: binding to {}:{} ...", host, port);
    let addr = (host.as_str(), port);
    let listener = std::net::TcpListener::bind(addr).unwrap_or_else(|e| {
        tracing::error!("GraphHunter HTTP API: failed to bind to {}:{}: {}", host, port, e);
        std::process::exit(1);
    });
    tracing::info!("GraphHunter HTTP API: bind OK, building router ...");
    let app = build_app(state);
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

async fn handler_entity_types(State(state): State<Arc<AppState>>) -> Response {
    match with_current_graph(state.as_ref(), |g| Ok(g.entity_types_in_graph())) {
        Ok(v) => ok_json(v),
        Err(e) => err_json(e),
    }
}

#[derive(Debug, Deserialize)]
struct SearchQuery {
    q: String,
    #[serde(rename = "type")]
    type_filter: Option<String>,
    limit: Option<usize>,
}

async fn handler_search(
    State(state): State<Arc<AppState>>,
    Query(q): Query<SearchQuery>,
) -> Response {
    let et = q.type_filter.as_deref().and_then(crate::parse_entity_type);
    match with_current_graph(state.as_ref(), |graph| {
        Ok(graph.search_entities(&q.q, et.as_ref(), q.limit.unwrap_or(50)))
    }) {
        Ok(v) => {
            let node_ids: Vec<String> = v.iter().map(|r| r.id.clone()).collect();
            if !node_ids.is_empty() {
                if let Ok(sg) = build_subgraph_for_ids(state.as_ref(), &node_ids) {
                    mcp_emit_view(state.as_ref(), sg);
                }
            }
            ok_json(v)
        }
        Err(e) => err_json(e),
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
    Query(q): Query<ExpandQuery>,
) -> Response {
    let state_clone = state.clone();
    let result = tokio::time::timeout(
        Duration::from_secs(60),
        tokio::task::spawn_blocking(move || {
            with_current_session_and_graph(state_clone.as_ref(), |session, graph| {
                let mut hood = graph
                    .get_neighborhood(
                        &q.node_id,
                        q.max_hops.unwrap_or(1),
                        q.max_nodes.unwrap_or(50),
                        None,
                    )
                    .ok_or_else(|| crate::error::CommandError::InvalidInput(format!("Entity not found: {}", q.node_id)))?;
                let path_ids: Vec<String> = session
                    .path_node_ids
                    .read()
                    .map_err(|e: std::sync::PoisonError<_>| crate::error::CommandError::GraphLocked(format!("Lock poisoned: {}", e)))?
                    .clone();
                // Use HashSet for O(1) lookups instead of O(n) linear scan per edge
                let mut hood_node_set: HashSet<String> = hood.nodes.iter().map(|n| n.id.clone()).collect();
                for path_id in path_ids {
                    if hood_node_set.contains(&path_id) {
                        continue;
                    }
                    let Some(entity) = graph.get_entity(&path_id) else {
                        continue;
                    };
                    hood.nodes.push(graph_hunter_core::NeighborNode {
                        id: entity.id.clone(),
                        entity_type: format!("{}", entity.entity_type),
                        score: entity.score,
                        metadata: entity.metadata.clone(),
                    });
                    hood_node_set.insert(path_id.clone());
                    // Cap per-path-node edge iteration to avoid stalling on 1M+ edge nodes
                    for compact in graph.get_compact_relations(&path_id)
                        .iter()
                        .take(graph_hunter_core::config::MAX_SCAN_EDGES)
                    {
                        let dest_str = graph.interner.resolve(compact.dest_sid);
                        if hood_node_set.contains(dest_str) {
                            hood.edges.push(graph_hunter_core::NeighborEdge {
                                source: graph.interner.resolve(compact.source_sid).to_string(),
                                target: dest_str.to_string(),
                                rel_type: format!("{}", compact.rel_type()),
                                timestamp: compact.timestamp,
                                metadata: graph.meta_store.get(compact.metadata_offset),
                            });
                        }
                    }
                }
                Ok(hood)
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
        Ok(Ok(Err(e))) => err_json(e),
        Ok(Err(e)) => err_json(format!("Task error: {}", e)),
        Err(_) => err_json("Expand timed out after 60 seconds"),
    }
}

#[derive(Debug, Deserialize)]
struct NodeDetailsQuery {
    node_id: String,
}

async fn handler_node_details(
    State(state): State<Arc<AppState>>,
    Query(q): Query<NodeDetailsQuery>,
) -> Response {
    let state_clone = state.clone();
    let result = tokio::time::timeout(
        Duration::from_secs(30),
        tokio::task::spawn_blocking(move || {
            with_current_graph(state_clone.as_ref(), |graph| {
                graph
                    .get_node_details(&q.node_id)
                    .ok_or_else(|| crate::error::CommandError::InvalidInput(format!("Entity not found: {}", q.node_id)))
            })
        }),
    )
    .await;
    match result {
        Ok(Ok(Ok(v))) => ok_json(v),
        Ok(Ok(Err(e))) => err_json(e),
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
    Json(body): Json<SubgraphBody>,
) -> Response {
    let state_clone = state.clone();
    let result = tokio::time::timeout(
        Duration::from_secs(60),
        tokio::task::spawn_blocking(move || {
            const MAX_SUBGRAPH_EDGES: usize = 5000;
            let node_ids = body.node_ids;
            let id_set: HashSet<String> = node_ids.iter().cloned().collect();
            with_current_graph(state_clone.as_ref(), |graph| {
                let nodes: Vec<SubgraphNode> = node_ids
                    .iter()
                    .filter_map(|id| graph.get_entity(id))
                    .map(|e| SubgraphNode::new(
                        e.id.clone(),
                        format!("{}", e.entity_type),
                        e.score,
                        e.metadata.clone(),
                    ))
                    .collect();
                let mut edges: Vec<SubgraphEdge> = Vec::new();
                'outer: for source_id in &node_ids {
                    // Cap per-source iteration to avoid stalling on high-degree nodes (1M+ edges)
                    for compact in graph.get_compact_relations(source_id).iter().take(graph_hunter_core::config::MAX_SCAN_EDGES) {
                        if edges.len() >= MAX_SUBGRAPH_EDGES { break 'outer; }
                        let dest_str = graph.interner.resolve(compact.dest_sid);
                        if id_set.contains(dest_str) {
                            edges.push(SubgraphEdge {
                                source: graph.interner.resolve(compact.source_sid).to_string(),
                                target: dest_str.to_string(),
                                rel_type: format!("{}", compact.rel_type()),
                                timestamp: compact.timestamp,
                                metadata: graph.meta_store.get(compact.metadata_offset),
                                dataset_id: graph.resolve_dataset_tag(compact.dataset_tag).map(|s| s.to_string()),
                            });
                        }
                    }
                }
                Ok(Subgraph { nodes, edges })
            })
        }),
    )
    .await;
    match result {
        Ok(Ok(Ok(sg))) => {
            mcp_emit_view(state.as_ref(), sg.clone());
            ok_json(sg)
        }
        Ok(Ok(Err(e))) => err_json(e),
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
    Query(q): Query<EventsQuery>,
) -> Response {
    let state_clone = state.clone();
    let node_id = q.node_id.clone();
    let result = tokio::time::timeout(
        Duration::from_secs(60),
        tokio::task::spawn_blocking(move || {
            let edges = with_current_graph(state_clone.as_ref(), |graph| {
                const MAX_EVENTS: usize = 500;
                let mut edges: Vec<SubgraphEdge> = Vec::new();
                for compact in graph.get_compact_relations(&node_id) {
                    if edges.len() >= MAX_EVENTS { break; }
                    edges.push(SubgraphEdge {
                        source: graph.interner.resolve(compact.source_sid).to_string(),
                        target: graph.interner.resolve(compact.dest_sid).to_string(),
                        rel_type: format!("{}", compact.rel_type()),
                        timestamp: compact.timestamp,
                        metadata: graph.meta_store.get(compact.metadata_offset),
                        dataset_id: graph.resolve_dataset_tag(compact.dataset_tag).map(|s| s.to_string()),
                    });
                }
                for &source_sid in graph.get_reverse_source_sids(&node_id).iter().take(MAX_EVENTS) {
                    if edges.len() >= MAX_EVENTS { break; }
                    let source_str = graph.interner.resolve(source_sid);
                    for compact in graph.get_compact_relations(source_str) {
                        if compact.dest_sid == graph.interner.get(&node_id).unwrap_or(compact.dest_sid) {
                            edges.push(SubgraphEdge {
                                source: graph.interner.resolve(compact.source_sid).to_string(),
                                target: graph.interner.resolve(compact.dest_sid).to_string(),
                                rel_type: format!("{}", compact.rel_type()),
                                timestamp: compact.timestamp,
                                metadata: graph.meta_store.get(compact.metadata_offset),
                                dataset_id: graph.resolve_dataset_tag(compact.dataset_tag).map(|s| s.to_string()),
                            });
                            break;
                        }
                    }
                }
                Ok(edges)
            })?;
            // Build subgraph for the event participants to update the frontend map
            let mut ids: HashSet<String> = HashSet::new();
            ids.insert(node_id);
            for e in &edges {
                ids.insert(e.source.clone());
                ids.insert(e.target.clone());
            }
            let node_ids: Vec<String> = ids.into_iter().collect();
            let sg = if !node_ids.is_empty() {
                build_subgraph_for_ids(state_clone.as_ref(), &node_ids).ok()
            } else {
                None
            };
            Ok::<_, crate::error::CommandError>((edges, sg))
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
        Ok(Ok(Err(e))) => err_json(e),
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
    Json(body): Json<CreateNoteBody>,
) -> Response {
    match create_note_impl(state.as_ref(), body.content, body.node_id) {
        Ok(note) => {
            emit_notes_changed(state.as_ref());
            ok_json(note)
        }
        Err(e) => err_json(e),
    }
}

#[derive(Debug, Deserialize)]
struct HuntResultsQuery {
    page: Option<usize>,
    page_size: Option<usize>,
    min_score: Option<f64>,
}

async fn handler_hunt_results(
    State(state): State<Arc<AppState>>,
    Query(q): Query<HuntResultsQuery>,
) -> Response {
    let page = q.page.unwrap_or(0);
    let page_size = q.page_size.unwrap_or(20);
    let min_score = q.min_score;

    let cache = match state.cached_hunt_paths.read() {
        Ok(guard) => guard.clone(),
        Err(_) => return err_json("Lock poisoned".to_string()),
    };
    let total_paths = cache.len();

    if cache.is_empty() {
        return ok_json(PaginatedHuntResults {
            total_paths: 0,
            filtered_paths: 0,
            page,
            page_size,
            paths: vec![],
        });
    }

    match with_current_graph(state.as_ref(), |graph| {
        let (scored_page, filtered_count) =
            graph.score_and_paginate_paths(&cache, page, page_size, min_score);
        Ok(PaginatedHuntResults {
            total_paths,
            filtered_paths: filtered_count,
            page,
            page_size,
            paths: scored_page,
        })
    }) {
        Ok(res) => ok_json(res),
        Err(e) => err_json(e),
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
}

/// Write-heavy handler: uses spawn_blocking + timeout to avoid holding the async runtime.
async fn handler_run_hunt(
    State(state): State<Arc<AppState>>,
    Json(body): Json<RunHuntBody>,
) -> Response {
    let hypothesis: Hypothesis = match graph_hunter_core::parse_dsl(
        body.hypothesis_dsl.trim(),
        Some("MCP Hunt"),
    ) {
        Ok(r) => r.hypothesis,
        Err(e) => return err_json(e.to_string()),
    };
    let state_clone = state.clone();
    let result = tokio::time::timeout(
        Duration::from_secs(30),
        tokio::task::spawn_blocking(move || {
            #[cfg(feature = "simd")]
            {
                with_current_graph(state_clone.as_ref(), |graph| {
                    graph.search_temporal_pattern_simd(&hypothesis, None, Some(10_000))
                        .map_err(|e| crate::error::CommandError::Internal(format!("Search failed: {}", e)))
                })
            }
            #[cfg(not(feature = "simd"))]
            {
                with_current_graph(state_clone.as_ref(), |graph| {
                    let scorer_ready = graph
                        .anomaly_scorer
                        .as_ref()
                        .map(|s| s.is_finalized())
                        .unwrap_or(false);
                    if scorer_ready {
                        graph.search_temporal_pattern_smart(&hypothesis, None, 10_000)
                            .map_err(|e| crate::error::CommandError::Internal(format!("Search failed: {}", e)))
                    } else {
                        graph.search_temporal_pattern(&hypothesis, None, Some(10_000))
                            .map_err(|e| crate::error::CommandError::Internal(format!("Search failed: {}", e)))
                    }
                })
            }
        }),
    )
    .await;

    match result {
        Ok(Ok(Ok((paths, truncated)))) => {
            let path_count = paths.len();
            if let Ok(mut cache) = state.cached_hunt_paths.write() {
                *cache = paths.clone();
            }
            let node_ids: Vec<String> = paths
                .iter()
                .flat_map(|p| p.iter().cloned())
                .collect::<HashSet<_>>()
                .into_iter()
                .collect();
            if !node_ids.is_empty() {
                if let Ok(sg) = build_subgraph_for_ids(state.as_ref(), &node_ids) {
                    mcp_emit_view(state.as_ref(), sg);
                }
            } else if path_count == 0 {
                mcp_emit_view(
                    state.as_ref(),
                    Subgraph {
                        nodes: vec![],
                        edges: vec![],
                    },
                );
            }
            ok_json(RunHuntResponse { path_count, truncated })
        }
        Ok(Ok(Err(e))) => err_json(e),
        Ok(Err(e)) => err_json(format!("Task error: {}", e)),
        Err(_) => err_json("Hunt timed out after 30 seconds".to_string()),
    }
}

// ── New MCP endpoints ──────────────────────────────────────────────────

async fn handler_graph_summary(State(state): State<Arc<AppState>>) -> Response {
    match with_current_graph(state.as_ref(), |g| Ok(g.get_graph_summary())) {
        Ok(v) => ok_json(v),
        Err(e) => err_json(e),
    }
}

async fn handler_entity_type_counts(State(state): State<Arc<AppState>>) -> Response {
    match with_current_graph(state.as_ref(), |g| {
        let counts: Vec<serde_json::Value> = g
            .entity_type_counts()
            .into_iter()
            .map(|(t, c)| serde_json::json!({ "entity_type": t, "count": c }))
            .collect();
        Ok(counts)
    }) {
        Ok(v) => ok_json(v),
        Err(e) => err_json(e),
    }
}

async fn handler_temporal_heatmap(State(state): State<Arc<AppState>>) -> Response {
    match with_current_graph(state.as_ref(), |g| Ok(g.temporal_heatmap())) {
        Ok(v) => ok_json(v),
        Err(e) => err_json(e),
    }
}

async fn handler_subnet_analysis(State(state): State<Arc<AppState>>) -> Response {
    match with_current_graph(state.as_ref(), |graph| {
        use graph_hunter_core::types::EntityType;
        use graph_hunter_core::ip_utils;
        use std::collections::HashMap;

        let ip_ids: Vec<String> = graph
            .entity_ids_for_type(&EntityType::IP)
            .unwrap_or_default();

        if ip_ids.is_empty() {
            return Ok(serde_json::json!([]));
        }

        let refs: Vec<&str> = ip_ids.iter().map(|s| s.as_str()).collect();
        let subnet_groups = ip_utils::group_by_subnet(&refs);

        let mut result: Vec<serde_json::Value> = Vec::new();
        for (subnet, ips) in subnet_groups {
            let is_internal = ips.first().map(|ip| ip_utils::is_private(ip)).unwrap_or(false);
            let mut total_bytes: u64 = 0;
            let mut has_bytes = false;
            let mut service_counts: HashMap<String, usize> = HashMap::new();

            for ip_str in &ips {
                if let Some(entity) = graph.get_entity(ip_str) {
                    if let Some(b) = entity.metadata.get("bytes") {
                        if let Ok(n) = b.trim().parse::<u64>() {
                            total_bytes += n;
                            has_bytes = true;
                        }
                    }
                }
                for rel in graph.get_relations(ip_str) {
                    if let Some(cat) = rel.metadata.get("service_category") {
                        *service_counts.entry(cat.clone()).or_insert(0) += 1;
                    }
                }
            }

            let mut top: Vec<(String, usize)> = service_counts.into_iter().collect();
            top.sort_by(|a, b| b.1.cmp(&a.1));
            let top_services: Vec<String> = top.into_iter().map(|(name, _)| name).collect();

            result.push(serde_json::json!({
                "subnet": subnet,
                "ip_count": ips.len(),
                "ips": ips,
                "total_bytes": if has_bytes { Some(total_bytes) } else { None::<u64> },
                "is_internal": is_internal,
                "top_services": top_services,
            }));
        }
        result.sort_by(|a, b| {
            let ca = a["ip_count"].as_u64().unwrap_or(0);
            let cb = b["ip_count"].as_u64().unwrap_or(0);
            cb.cmp(&ca)
        });
        Ok(serde_json::json!(result))
    }) {
        Ok(v) => ok_json(v),
        Err(e) => err_json(e),
    }
}

#[derive(Debug, Deserialize)]
struct EnrichIpBody {
    ip: String,
}

async fn handler_enrich_ip(
    State(state): State<Arc<AppState>>,
    Json(body): Json<EnrichIpBody>,
) -> Response {
    use graph_hunter_core::{ip_utils, geoip, write_geoip_to_metadata};

    if !ip_utils::is_public(&body.ip) {
        return err_json(format!("IP {} is not a public/routable address", body.ip));
    }

    // Try offline MaxMind first
    let maxmind_result = {
        let provider = state.geoip_provider.lock().ok();
        provider.and_then(|guard| guard.as_ref().and_then(|p| p.lookup(&body.ip)))
    };

    let result = if let Some(r) = maxmind_result {
        r
    } else {
        // Try HTTP fallback
        let client = {
            let guard = state.http_geoip_client.lock().ok();
            guard.and_then(|g| g.clone())
        };
        match client {
            Some(c) => {
                let provider = geoip::http::HttpGeoIpProvider::new(c);
                let cancel = tokio_util::sync::CancellationToken::new();
                match provider.lookup(&body.ip, cancel).await {
                    Ok(r) => r,
                    Err(e) => return err_json(format!("GeoIP lookup failed: {e}")),
                }
            }
            None => return err_json("No GeoIP provider available".to_string()),
        }
    };

    // Write to entity metadata
    let _ = crate::with_current_graph_mut(state.as_ref(), |graph| {
        if let Some(entity) = graph.get_entity_mut(&body.ip) {
            write_geoip_to_metadata(&mut entity.metadata, &result);
        }
        Ok(())
    });

    ok_json(result)
}

async fn handler_catalog(State(_state): State<Arc<AppState>>) -> Response {
    let catalog = graph_hunter_core::get_catalog();
    ok_json(catalog)
}

async fn handler_list_datasets(State(state): State<Arc<AppState>>) -> Response {
    match crate::with_current_session(state.as_ref(), |session| {
        let datasets = session.datasets.read().map_err(|e| {
            crate::error::CommandError::GraphLocked(format!("Lock poisoned: {e}"))
        })?;
        Ok(datasets.clone())
    }) {
        Ok(v) => ok_json(v),
        Err(e) => err_json(e),
    }
}

async fn handler_path_nodes(State(state): State<Arc<AppState>>) -> Response {
    match crate::with_current_session(state.as_ref(), |session| {
        let nodes = session.path_node_ids.read().map_err(|e| {
            crate::error::CommandError::GraphLocked(format!("Lock poisoned: {e}"))
        })?;
        Ok(nodes.clone())
    }) {
        Ok(v) => ok_json(v),
        Err(e) => err_json(e),
    }
}

async fn handler_list_notes(State(state): State<Arc<AppState>>) -> Response {
    match crate::with_current_session(state.as_ref(), |session| {
        let notes = session.notes.read().map_err(|e| {
            crate::error::CommandError::GraphLocked(format!("Lock poisoned: {e}"))
        })?;
        Ok(notes.clone())
    }) {
        Ok(v) => ok_json(v),
        Err(e) => err_json(e),
    }
}

#[derive(Debug, Deserialize)]
struct ExportSubgraphBody {
    node_ids: Vec<String>,
    format: Option<String>,
}

async fn handler_export_subgraph(
    State(state): State<Arc<AppState>>,
    Json(body): Json<ExportSubgraphBody>,
) -> Response {
    let fmt = body.format.unwrap_or_else(|| "json".to_string());
    match with_current_graph(state.as_ref(), |graph| {
        use graph_hunter_core::export::{
            ExportSubgraphEdge, ExportSubgraphNode, export_subgraph_csv, export_subgraph_json,
        };
        let id_set: HashSet<&str> = body.node_ids.iter().map(|s| s.as_str()).collect();
        struct ON { id: String, entity_type: String, score: f64 }
        struct OE { source: String, target: String, rel_type: String, timestamp: i64 }
        let owned_nodes: Vec<ON> = body.node_ids.iter()
            .filter_map(|id| graph.get_entity(id))
            .map(|e| ON { id: e.id.clone(), entity_type: format!("{}", e.entity_type), score: e.score })
            .collect();
        let mut owned_edges: Vec<OE> = Vec::new();
        for src in &body.node_ids {
            for c in graph.get_compact_relations(src) {
                if owned_edges.len() >= 10_000 { break; }
                let dst = graph.interner.resolve(c.dest_sid);
                if id_set.contains(dst) {
                    owned_edges.push(OE {
                        source: graph.interner.resolve(c.source_sid).to_string(),
                        target: dst.to_string(),
                        rel_type: format!("{}", c.rel_type()),
                        timestamp: c.timestamp,
                    });
                }
            }
        }
        let en: Vec<ExportSubgraphNode<'_>> = owned_nodes.iter()
            .map(|n| ExportSubgraphNode { id: &n.id, entity_type: &n.entity_type, score: n.score })
            .collect();
        let ee: Vec<ExportSubgraphEdge<'_>> = owned_edges.iter()
            .map(|e| ExportSubgraphEdge { source: &e.source, target: &e.target, rel_type: &e.rel_type, timestamp: e.timestamp })
            .collect();
        let mut buf = Vec::new();
        match fmt.as_str() {
            "csv" => export_subgraph_csv(&en, &ee, &mut buf)
                .map_err(|e| crate::error::CommandError::IoError(e.to_string()))?,
            _ => export_subgraph_json(&en, &ee, &mut buf)
                .map_err(|e| crate::error::CommandError::IoError(e.to_string()))?,
        }
        String::from_utf8(buf).map_err(|e| crate::error::CommandError::Internal(format!("{e}")))
    }) {
        Ok(text) => ok_json(serde_json::json!({ "data": text, "format": fmt })),
        Err(e) => err_json(e),
    }
}

// ── Phase 2: Complete MCP coverage ─────────────────────────────────────

#[derive(Debug, Deserialize)]
struct ParseDslBody {
    dsl: String,
    name: Option<String>,
}

async fn handler_parse_dsl(Json(body): Json<ParseDslBody>) -> Response {
    match graph_hunter_core::parse_dsl(&body.dsl, body.name.as_deref()) {
        Ok(result) => ok_json(serde_json::json!({
            "valid": true,
            "formatted": result.formatted,
            "steps": result.hypothesis.steps.len(),
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
    State(state): State<Arc<AppState>>,
    Query(q): Query<EventsPaginatedQuery>,
) -> Response {
    let state_clone = state.clone();
    let result = tokio::time::timeout(
        Duration::from_secs(60),
        tokio::task::spawn_blocking(move || {
            with_current_graph(state_clone.as_ref(), |graph| {
                let page = q.page.unwrap_or(0);
                let page_size = q.page_size.unwrap_or(100);

                let mut all_edges: Vec<SubgraphEdge> = Vec::new();
                for compact in graph.get_compact_relations(&q.node_id) {
                    all_edges.push(SubgraphEdge {
                        source: graph.interner.resolve(compact.source_sid).to_string(),
                        target: graph.interner.resolve(compact.dest_sid).to_string(),
                        rel_type: format!("{}", compact.rel_type()),
                        timestamp: compact.timestamp,
                        metadata: graph.meta_store.get(compact.metadata_offset),
                        dataset_id: graph.resolve_dataset_tag(compact.dataset_tag).map(|s| s.to_string()),
                    });
                }
                let target_sid = graph.interner.get(&q.node_id);
                for &source_sid in graph.get_reverse_source_sids(&q.node_id) {
                    for compact in graph.get_relations_by_sid(source_sid) {
                        if Some(compact.dest_sid) == target_sid {
                            all_edges.push(SubgraphEdge {
                                source: graph.interner.resolve(compact.source_sid).to_string(),
                                target: graph.interner.resolve(compact.dest_sid).to_string(),
                                rel_type: format!("{}", compact.rel_type()),
                                timestamp: compact.timestamp,
                                metadata: graph.meta_store.get(compact.metadata_offset),
                                dataset_id: graph.resolve_dataset_tag(compact.dataset_tag).map(|s| s.to_string()),
                            });
                        }
                    }
                }

                match q.sort_by.as_deref() {
                    Some("timestamp") => all_edges.sort_by_key(|e| e.timestamp),
                    Some("rel_type") => all_edges.sort_by(|a, b| a.rel_type.cmp(&b.rel_type)),
                    Some("source") => all_edges.sort_by(|a, b| a.source.cmp(&b.source)),
                    Some("target") => all_edges.sort_by(|a, b| a.target.cmp(&b.target)),
                    _ => {}
                }

                let total_count = all_edges.len();
                let start = page * page_size;
                let events: Vec<SubgraphEdge> = all_edges.into_iter().skip(start).take(page_size).collect();

                Ok(serde_json::json!({
                    "events": events,
                    "total_count": total_count,
                    "page": page,
                    "page_size": page_size,
                }))
            })
        }),
    )
    .await;
    match result {
        Ok(Ok(Ok(v))) => ok_json(v),
        Ok(Ok(Err(e))) => err_json(e),
        Ok(Err(e)) => err_json(format!("Task error: {e}")),
        Err(_) => err_json("Events query timed out"),
    }
}

async fn handler_expand_grouped(
    State(state): State<Arc<AppState>>,
    Query(q): Query<ExpandQuery>,
) -> Response {
    let state_clone = state.clone();
    let result = tokio::time::timeout(
        Duration::from_secs(60),
        tokio::task::spawn_blocking(move || {
            with_current_graph(state_clone.as_ref(), |graph| {
                graph
                    .get_neighborhood_grouped(
                        &q.node_id,
                        q.max_hops.unwrap_or(1),
                        q.max_nodes.unwrap_or(50),
                        None,
                    )
                    .ok_or_else(|| crate::error::CommandError::InvalidInput(
                        format!("Entity not found: {}", q.node_id),
                    ))
            })
        }),
    )
    .await;
    match result {
        Ok(Ok(Ok(v))) => ok_json(v),
        Ok(Ok(Err(e))) => err_json(e),
        Ok(Err(e)) => err_json(format!("Task error: {e}")),
        Err(_) => err_json("Expand grouped timed out"),
    }
}

#[derive(Debug, Deserialize)]
struct ExportHuntBody {
    format: Option<String>,
}

async fn handler_export_hunt_results(
    State(state): State<Arc<AppState>>,
    Json(body): Json<ExportHuntBody>,
) -> Response {
    let fmt = body.format.unwrap_or_else(|| "json".to_string());

    let cache = {
        let guard = state.cached_hunt_paths.read();
        match guard {
            Ok(g) if !g.is_empty() => g.clone(),
            _ => return err_json("No hunt results to export. Run a hunt first."),
        }
    };

    match with_current_graph(state.as_ref(), |graph| {
        use graph_hunter_core::export::{export_hunt_results_csv, export_hunt_results_json};
        let (scored, _) = graph.score_and_paginate_paths(&cache, 0, cache.len(), None);
        let mut buf = Vec::new();
        match fmt.as_str() {
            "csv" => export_hunt_results_csv(&scored, &mut buf)
                .map_err(|e| crate::error::CommandError::IoError(e.to_string()))?,
            _ => export_hunt_results_json(&scored, &mut buf)
                .map_err(|e| crate::error::CommandError::IoError(e.to_string()))?,
        }
        String::from_utf8(buf).map_err(|e| crate::error::CommandError::Internal(format!("{e}")))
    }) {
        Ok(text) => ok_json(serde_json::json!({ "data": text, "format": fmt })),
        Err(e) => err_json(e),
    }
}

async fn handler_enable_anomaly_scoring(State(state): State<Arc<AppState>>) -> Response {
    match crate::with_current_graph_mut(state.as_ref(), |graph| {
        graph.enable_anomaly_scoring(Default::default());
        Ok(serde_json::json!({ "enabled": true }))
    }) {
        Ok(v) => ok_json(v),
        Err(e) => err_json(e),
    }
}

async fn handler_compute_scores(State(state): State<Arc<AppState>>) -> Response {
    let state_clone = state.clone();
    let result = tokio::time::timeout(
        Duration::from_secs(120),
        tokio::task::spawn_blocking(move || {
            crate::with_current_graph_mut(state_clone.as_ref(), |graph| {
                graph.compute_scores();
                Ok(serde_json::json!({ "computed": true }))
            })
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
