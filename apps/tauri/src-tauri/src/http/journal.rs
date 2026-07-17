//! Hunt journal read/write endpoints (Task A5).
//!
//! Thin wrappers around `JournalStore` (Task A2). All paths under
//! `/journal` are exempt from the mandatory capture middleware (see
//! `journal_capture_skips` in `mod.rs`) — reading/exporting past hunts
//! must never journal itself.

use axum::{
    body::Bytes,
    extract::{Path, State},
    http::{header, StatusCode},
    response::{IntoResponse, Response},
    Json,
};
use serde::Deserialize;
use std::sync::Arc;

use crate::AppState;

use super::helpers::ok_json;

#[derive(Debug, Default, Deserialize)]
pub(super) struct StartBody {
    label: Option<String>,
}

#[derive(Debug, Deserialize)]
pub(super) struct ExportBody {
    id: String,
}

fn not_found(id: &str) -> Response {
    (
        StatusCode::NOT_FOUND,
        Json(serde_json::json!({ "error": "unknown hunt id", "id": id })),
    )
        .into_response()
}

/// `POST /journal/start` — body `{label?: String}`. Accepts a missing or
/// empty body (the label is optional) rather than requiring callers to
/// send `{}`.
pub(super) async fn handler_start(State(state): State<Arc<AppState>>, body: Bytes) -> Response {
    let label = if body.is_empty() {
        None
    } else {
        serde_json::from_slice::<StartBody>(&body)
            .ok()
            .and_then(|b| b.label)
    };
    let hunt_id = state.journal.start_hunt(label);
    ok_json(serde_json::json!({ "hunt_id": hunt_id }))
}

/// `POST /journal/close` — closes the current hunt (if any).
pub(super) async fn handler_close(State(state): State<Arc<AppState>>) -> Response {
    let hunt_id = state.journal.close_hunt();
    ok_json(serde_json::json!({ "hunt_id": hunt_id }))
}

/// `GET /journal/list` — summaries of every known hunt.
pub(super) async fn handler_list(State(state): State<Arc<AppState>>) -> Response {
    ok_json(state.journal.list())
}

/// `GET /journal/:id` — full route/topology of one hunt: `{meta, events}`.
pub(super) async fn handler_get(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> Response {
    match state.journal.read(&id) {
        Some((meta, events)) => ok_json(serde_json::json!({ "meta": meta, "events": events })),
        None => not_found(&id),
    }
}

/// `GET /journal/:id/stats` — per-hunt token accounting (Task B2):
/// `{hunt_id, cumulative_est_tokens, event_count, by_kind}`. Additive —
/// does not alter `GET /journal/:id`'s response shape.
pub(super) async fn handler_stats(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> Response {
    match state.journal.stats(&id) {
        Some(stats) => ok_json(stats),
        None => not_found(&id),
    }
}

/// `POST /journal/export` — body `{id: String}`. Streams the hunt's events
/// back as NDJSON (one `HuntEvent` per line), mirroring the on-disk
/// `events.jsonl` byte-for-byte in structure.
pub(super) async fn handler_export(
    State(state): State<Arc<AppState>>,
    Json(body): Json<ExportBody>,
) -> Response {
    match state.journal.read(&body.id) {
        Some((_meta, events)) => {
            let lines: Vec<String> = events
                .iter()
                .map(|ev| {
                    serde_json::to_string(ev).unwrap_or_else(|e| {
                        tracing::error!("journal export: failed to serialize event: {e}");
                        format!("{{\"__journal_export_error\":\"{}\"}}", e)
                    })
                })
                .collect();
            let text = lines.join("\n");
            ([(header::CONTENT_TYPE, "application/x-ndjson")], text).into_response()
        }
        None => not_found(&body.id),
    }
}
