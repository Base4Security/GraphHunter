//! Shared helpers: response builders and frontend-emitters used by
//! multiple domain routers.

use axum::{
    Json,
    http::StatusCode,
    response::{IntoResponse, Response},
};
use serde::Serialize;

use crate::ServerState;
use graph_hunter_api::GraphHunterApi;
use graph_hunter_api::dto::graph_ops::{Subgraph, SubgraphEdge, SubgraphNode};
use graph_hunter_core::Neighborhood;

/// Notify frontend that notes changed (e.g. after MCP create_note) so the UI refreshes the notes list.
pub(super) fn emit_notes_changed(state: &ServerState) {
    state.emitter.emit("notes-changed", serde_json::Value::Null);
}

/// Emit a subgraph to the frontend so the live map follows what the
/// MCP client is looking at. A no-op when nothing is listening
/// (headless), so the subgraph is only serialized for a real frontend
/// by whichever emitter the host plugged in.
pub(super) fn mcp_emit_view(state: &ServerState, subgraph: Subgraph) {
    if let Ok(payload) = serde_json::to_value(&subgraph) {
        state.emitter.emit("mcp-view-update", payload);
    }
}

pub(super) fn neighborhood_to_subgraph(hood: &Neighborhood) -> Subgraph {
    let nodes = hood
        .nodes
        .iter()
        .map(|n| {
            SubgraphNode::new(
                n.id.clone(),
                n.entity_type.clone(),
                n.score,
                n.metadata.clone(),
            )
        })
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
) -> graph_hunter_api::ApiResult<Subgraph> {
    api.get_subgraph(graph_hunter_api::dto::graph_ops::SubgraphRequest {
        session: None,
        node_ids: node_ids.to_vec(),
        page_size: None,
        offset: None,
    })
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
            let code =
                StatusCode::from_u16(e.status_code()).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
            (code, Json(serde_json::json!({ "error": e.to_string() }))).into_response()
        }
    }
}

pub(super) fn api_err_response(e: graph_hunter_api::ApiError) -> Response {
    let code = StatusCode::from_u16(e.status_code()).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
    (code, Json(serde_json::json!({ "error": e.to_string() }))).into_response()
}
