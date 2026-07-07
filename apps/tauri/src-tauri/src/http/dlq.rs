//! Dead-letter queue endpoints: list, reingest, purge.

use axum::{
    extract::State,
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use std::sync::Arc;

use graph_hunter_api::GraphHunterApi;

use super::helpers::{api_err_response, ok_json};

pub(super) async fn handler_list_dead_letters(
    State(api): State<Arc<GraphHunterApi>>,
    Json(body): Json<graph_hunter_api::dto::dlq::ListDeadLettersRequest>,
) -> Response {
    match api.list_dead_letters(body) {
        Ok(resp) => ok_json(resp),
        Err(e) => api_err_response(e),
    }
}

pub(super) async fn handler_reingest_dead_letter(
    State(api): State<Arc<GraphHunterApi>>,
    Json(body): Json<graph_hunter_api::dto::dlq::ReingestDeadLetterRequest>,
) -> Response {
    let api_clone = api.clone();
    let joined = tokio::task::spawn_blocking(move || api_clone.reingest_dead_letter(body)).await;
    match joined {
        Ok(Ok(resp)) => ok_json(resp),
        Ok(Err(e)) => api_err_response(e),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({ "error": format!("join error: {e}") })),
        )
            .into_response(),
    }
}

pub(super) async fn handler_purge_dead_letters(
    State(api): State<Arc<GraphHunterApi>>,
    Json(body): Json<graph_hunter_api::dto::dlq::PurgeDeadLettersRequest>,
) -> Response {
    match api.purge_dead_letters(body) {
        Ok(resp) => ok_json(resp),
        Err(e) => api_err_response(e),
    }
}
