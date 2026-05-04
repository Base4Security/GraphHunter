//! Agentic review queue endpoints (list / approve / reject).

use axum::{
    extract::State,
    response::Response,
    Json,
};
use std::sync::Arc;

use graph_hunter_api::GraphHunterApi;

use super::helpers::{api_err_response, ok_json};

pub(super) async fn handler_agentic_review_list(
    State(api): State<Arc<GraphHunterApi>>,
    Json(body): Json<graph_hunter_api::dto::agentic::ListDraftsRequest>,
) -> Response {
    match api.agentic_review_list(body) {
        Ok(resp) => ok_json(resp),
        Err(e) => api_err_response(e),
    }
}

pub(super) async fn handler_agentic_review_approve(
    State(api): State<Arc<GraphHunterApi>>,
    Json(body): Json<graph_hunter_api::dto::agentic::ResolveDraftRequest>,
) -> Response {
    match api.agentic_review_approve(body) {
        Ok(resp) => ok_json(resp),
        Err(e) => api_err_response(e),
    }
}

pub(super) async fn handler_agentic_review_reject(
    State(api): State<Arc<GraphHunterApi>>,
    Json(body): Json<graph_hunter_api::dto::agentic::ResolveDraftRequest>,
) -> Response {
    match api.agentic_review_reject(body) {
        Ok(resp) => ok_json(resp),
        Err(e) => api_err_response(e),
    }
}
