//! Shared helpers: response builders and frontend-emitters used by
//! multiple domain routers.

use axum::{http::StatusCode, response::{IntoResponse, Response}, Json};
use serde::Serialize;

use crate::{AppState, Subgraph, SubgraphEdge, SubgraphNode};
use graph_hunter_api::GraphHunterApi;
use graph_hunter_core::Neighborhood;
use tauri::Emitter;

/// Notify frontend that notes changed (e.g. after MCP create_note) so the UI refreshes the notes list.
pub(super) fn emit_notes_changed(state: &AppState) {
    if let Ok(handle_guard) = state.app_handle.read() {
        if let Some(handle) = handle_guard.as_ref() {
            let _ = handle.emit("notes-changed", ());
        }
    }
}

/// Store subgraph as last MCP view and emit to frontend so the live map updates.
pub(super) fn mcp_emit_view(state: &AppState, subgraph: Subgraph) {
    if let Ok(mut guard) = state.last_mcp_subgraph.write() {
        *guard = Some(subgraph.clone());
    }
    if let Ok(handle_guard) = state.app_handle.read() {
        if let Some(handle) = handle_guard.as_ref() {
            let _ = handle.emit("mcp-view-update", &subgraph);
        }
    }
}

pub(super) fn neighborhood_to_subgraph(hood: &Neighborhood) -> Subgraph {
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
    let edges: Vec<SubgraphEdge> = hood
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
    let total = edges.len();
    Subgraph {
        nodes,
        returned_edges: total,
        edges,
        total_edges: total,
        offset: 0,
        page_size: total,
        has_more: false,
    }
}

/// Build subgraph for the given node IDs and emit to frontend map
/// (used after search, events, run_hunt). Delegates to the canonical
/// `api.get_subgraph`. The `_state` param is kept so the existing
/// call sites don't have to thread through a new `api` reference.
pub(super) fn build_subgraph_for_ids(
    api: &GraphHunterApi,
    node_ids: &[String],
) -> Result<Subgraph, crate::error::CommandError> {
    api.get_subgraph(graph_hunter_api::dto::graph_ops::SubgraphRequest {
        session: None,
        node_ids: node_ids.to_vec(),
        page_size: None,
        offset: None,
    })
    .map_err(crate::error::CommandError::from)
}

pub(super) fn ok_json<T: Serialize>(v: T) -> Response {
    (StatusCode::OK, Json(v)).into_response()
}

pub(super) fn err_json(e: impl std::fmt::Display) -> Response {
    (
        StatusCode::BAD_REQUEST,
        Json(serde_json::json!({ "error": e.to_string() })),
    )
        .into_response()
}

/// Convert an `ApiResult<T>` to an axum `Response`. Success → 200 with
/// the JSON body; failure → status from [`graph_hunter_api::ApiError::status_code`]
/// with `{ "error": <message> }`. Keeps migrated handlers to one line.
pub(super) fn api_response<T: Serialize>(result: graph_hunter_api::ApiResult<T>) -> Response {
    match result {
        Ok(v) => ok_json(v),
        Err(e) => {
            let code = StatusCode::from_u16(e.status_code())
                .unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
            (code, Json(serde_json::json!({ "error": e.to_string() }))).into_response()
        }
    }
}

pub(super) fn api_err_response(e: graph_hunter_api::ApiError) -> Response {
    let code = StatusCode::from_u16(e.status_code())
        .unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
    (code, Json(serde_json::json!({ "error": e.to_string() }))).into_response()
}
