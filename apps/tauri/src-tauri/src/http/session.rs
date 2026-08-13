//! Session lifecycle endpoints.
//!
//! Ingest and hunt operations resolve their target session from the
//! request's `session` field, falling back to the process-global current
//! session. A remote client therefore had no way to create one, which
//! made every other ingest route unusable on a fresh process.
//!
//! **`current` is process-global, not per-connection.** `create_session`
//! sets it, so two HTTP clients sharing one GraphHunter process share one
//! current session and will interleave into the same graph. Clients that
//! care must pass an explicit `session` handle on every subsequent call
//! rather than relying on the fallback.

use axum::{extract::State, response::Response, Json};
use std::sync::Arc;

use graph_hunter_api::GraphHunterApi;

use super::helpers::{api_err_response, ok_json};

pub(super) async fn handler_create_session(
    State(api): State<Arc<GraphHunterApi>>,
    Json(body): Json<graph_hunter_api::dto::session::CreateSessionRequest>,
) -> Response {
    match api.create_session(body) {
        Ok(v) => ok_json(v),
        Err(e) => api_err_response(e),
    }
}

pub(super) async fn handler_list_sessions(State(api): State<Arc<GraphHunterApi>>) -> Response {
    // Scans the session directory on disk — off the async runtime.
    let api_clone = api.clone();
    match tokio::task::spawn_blocking(move || api_clone.list_sessions()).await {
        Ok(Ok(v)) => ok_json(v),
        Ok(Err(e)) => api_err_response(e),
        Err(join) => api_err_response(graph_hunter_api::ApiError::Internal(format!(
            "list_sessions task failed: {join}"
        ))),
    }
}
