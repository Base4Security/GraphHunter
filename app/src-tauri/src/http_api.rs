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
    with_current_graph, with_current_session_and_graph, with_current_graph_mut,
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
        .map(|n| SubgraphNode {
            id: n.id.clone(),
            entity_type: n.entity_type.clone(),
            score: n.score,
            metadata: n.metadata.clone(),
        })
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
fn build_subgraph_for_ids(state: &AppState, node_ids: &[String]) -> Result<Subgraph, String> {
    let id_set: HashSet<&str> = node_ids.iter().map(|s| s.as_str()).collect();
    with_current_graph(state, |graph| {
        let nodes: Vec<SubgraphNode> = node_ids
            .iter()
            .filter_map(|id| graph.get_entity(id))
            .map(|e| SubgraphNode {
                id: e.id.clone(),
                entity_type: format!("{}", e.entity_type),
                score: e.score,
                metadata: e.metadata.clone(),
            })
            .collect();
        let mut edges: Vec<SubgraphEdge> = Vec::new();
        for source_id in node_ids {
            for rel in graph.get_relations(source_id) {
                if id_set.contains(rel.dest_id.as_str()) {
                    edges.push(SubgraphEdge {
                        source: rel.source_id.clone(),
                        target: rel.dest_id.clone(),
                        rel_type: format!("{}", rel.rel_type),
                        timestamp: rel.timestamp,
                        metadata: rel.metadata.clone(),
                        dataset_id: rel.dataset_id.as_deref().map(|s| s.to_string()),
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

fn err_json(e: String) -> Response {
    (
        StatusCode::BAD_REQUEST,
        Json(serde_json::json!({ "error": e })),
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
    eprintln!("HTTP API: /health request received");
    let _ = std::io::Write::flush(&mut std::io::stderr());
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
    eprintln!("HTTP API {} {} -> {}", method, uri, response.status());
    let _ = std::io::Write::flush(&mut std::io::stderr());
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
        .fallback(fallback_404)
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
    eprintln!("GraphHunter HTTP API: binding to {} ...", addr);
    let _ = std::io::Write::flush(&mut std::io::stderr());

    let listener = tokio::net::TcpListener::bind(&addr).await?;
    eprintln!(
        "GraphHunter HTTP API listening on http://{} (health: /health)",
        addr
    );
    eprintln!("GraphHunter HTTP API: ready to accept connections.");
    let _ = std::io::Write::flush(&mut std::io::stderr());
    if host == "0.0.0.0" {
        eprintln!("  → Use http://127.0.0.1:{}/ in browser (localhost may fail on Windows due to IPv6)", port);
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
    eprintln!("GraphHunter HTTP API: binding to {}:{} ...", host, port);
    let _ = std::io::Write::flush(&mut std::io::stderr());
    let addr = (host.as_str(), port);
    let listener = std::net::TcpListener::bind(addr).unwrap_or_else(|e| {
        eprintln!("GraphHunter HTTP API: failed to bind to {}:{}: {}", host, port, e);
        std::process::exit(1);
    });
    eprintln!("GraphHunter HTTP API: bind OK, building router ...");
    let _ = std::io::Write::flush(&mut std::io::stderr());
    let app = build_app(state);
    eprintln!("GraphHunter HTTP API: creating tokio runtime (multi_thread, 8 workers) ...");
    let _ = std::io::Write::flush(&mut std::io::stderr());
    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(8)
        .enable_all()
        .build()
        .expect("tokio runtime");
    rt.block_on(async {
        let listener = tokio::net::TcpListener::from_std(listener).expect("tcp listener");
        eprintln!(
            "GraphHunter HTTP API listening on http://{}:{}/ (health: /health)",
            host, port
        );
        eprintln!("GraphHunter HTTP API: ready to accept connections.");
        let _ = std::io::Write::flush(&mut std::io::stderr());
        if host == "0.0.0.0" {
            eprintln!("  → Use http://127.0.0.1:{}/ in browser (localhost may fail on Windows due to IPv6)", port);
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
    match with_current_session_and_graph(state.as_ref(), |session, graph| {
        let mut hood = graph
            .get_neighborhood(
                &q.node_id,
                q.max_hops.unwrap_or(1),
                q.max_nodes.unwrap_or(50),
                None,
            )
            .ok_or_else(|| format!("Entity not found: {}", q.node_id))?;
        let path_ids: Vec<String> = session
            .path_node_ids
            .read()
            .map_err(|e: std::sync::PoisonError<_>| format!("Lock poisoned: {}", e))?
            .clone();
        for path_id in path_ids {
            if hood.nodes.iter().any(|n| n.id == path_id) {
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
            for rel in graph.get_relations(&path_id) {
                if hood.nodes.iter().any(|n| n.id == rel.dest_id) {
                    hood.edges.push(graph_hunter_core::NeighborEdge {
                        source: rel.source_id.clone(),
                        target: rel.dest_id.clone(),
                        rel_type: format!("{}", rel.rel_type),
                        timestamp: rel.timestamp,
                        metadata: rel.metadata.clone(),
                    });
                }
            }
        }
        Ok(hood)
    }) {
        Ok(hood) => {
            let sg = neighborhood_to_subgraph(&hood);
            mcp_emit_view(state.as_ref(), sg);
            ok_json(hood)
        }
        Err(e) => err_json(e),
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
    match with_current_graph(state.as_ref(), |graph| {
        graph
            .get_node_details(&q.node_id)
            .ok_or_else(|| format!("Entity not found: {}", q.node_id))
    }) {
        Ok(v) => ok_json(v),
        Err(e) => err_json(e),
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
    let node_ids = body.node_ids;
    let id_set: HashSet<&str> = node_ids.iter().map(|s| s.as_str()).collect();
    match with_current_graph(state.as_ref(), |graph| {
        let nodes: Vec<SubgraphNode> = node_ids
            .iter()
            .filter_map(|id| graph.get_entity(id))
            .map(|e| SubgraphNode {
                id: e.id.clone(),
                entity_type: format!("{}", e.entity_type),
                score: e.score,
                metadata: e.metadata.clone(),
            })
            .collect();
        let mut edges: Vec<SubgraphEdge> = Vec::new();
        for source_id in &node_ids {
            for rel in graph.get_relations(source_id) {
                if id_set.contains(rel.dest_id.as_str()) {
                    edges.push(SubgraphEdge {
                        source: rel.source_id.clone(),
                        target: rel.dest_id.clone(),
                        rel_type: format!("{}", rel.rel_type),
                        timestamp: rel.timestamp,
                        metadata: rel.metadata.clone(),
                        dataset_id: rel.dataset_id.as_deref().map(|s| s.to_string()),
                    });
                }
            }
        }
        Ok(Subgraph { nodes, edges })
    }) {
        Ok(sg) => {
            mcp_emit_view(state.as_ref(), sg.clone());
            ok_json(sg)
        }
        Err(e) => err_json(e),
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
    match with_current_graph(state.as_ref(), |graph| {
        let mut edges: Vec<SubgraphEdge> = Vec::new();
        for rel in graph.get_relations(&q.node_id) {
            edges.push(SubgraphEdge {
                source: rel.source_id.clone(),
                target: rel.dest_id.clone(),
                rel_type: format!("{}", rel.rel_type),
                timestamp: rel.timestamp,
                metadata: rel.metadata.clone(),
                dataset_id: rel.dataset_id.as_deref().map(|s| s.to_string()),
            });
        }
        for &source_sid in graph.get_reverse_source_sids(&q.node_id) {
            let source_str = graph.interner.resolve(source_sid);
            for rel in graph.get_relations(source_str) {
                if rel.dest_id == q.node_id {
                    edges.push(SubgraphEdge {
                        source: rel.source_id.clone(),
                        target: rel.dest_id.clone(),
                        rel_type: format!("{}", rel.rel_type),
                        timestamp: rel.timestamp,
                        metadata: rel.metadata.clone(),
                        dataset_id: rel.dataset_id.as_deref().map(|s| s.to_string()),
                    });
                    break;
                }
            }
        }
        Ok(edges)
    }) {
        Ok(v) => {
            let mut ids: HashSet<String> = HashSet::new();
            ids.insert(q.node_id.clone());
            for e in &v {
                ids.insert(e.source.clone());
                ids.insert(e.target.clone());
            }
            let node_ids: Vec<String> = ids.into_iter().collect();
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
            with_current_graph_mut(state_clone.as_ref(), |graph| {
                let scorer_ready = graph
                    .anomaly_scorer
                    .as_ref()
                    .map(|s| s.is_finalized())
                    .unwrap_or(false);
                if scorer_ready {
                    graph.search_temporal_pattern_smart(&hypothesis, None, 10_000)
                        .map_err(|e| format!("Search failed: {}", e))
                } else {
                    graph.search_temporal_pattern(&hypothesis, None, Some(10_000))
                        .map_err(|e| format!("Search failed: {}", e))
                }
            })
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
