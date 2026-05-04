//! Note CRUD endpoints.

use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use serde::Deserialize;
use std::sync::Arc;

use crate::AppState;
use graph_hunter_api::GraphHunterApi;

use super::helpers::{api_response, emit_notes_changed, ok_json};

#[derive(Debug, Deserialize)]
pub(super) struct CreateNoteBody {
    content: String,
    node_id: Option<String>,
}

pub(super) async fn handler_create_note(
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

pub(super) async fn handler_list_notes(State(api): State<Arc<GraphHunterApi>>) -> Response {
    api_response(api.get_notes(
        graph_hunter_api::dto::entity::SessionOnly::default(),
    ))
}

/// Fetch a single note by its UUID. Used as the target of the `url` field
/// returned by `cmd_create_note` so external systems (Jira, Zoho, Slack)
/// can link directly to the note without reproducing the note list logic.
pub(super) async fn handler_get_note_by_id(
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
