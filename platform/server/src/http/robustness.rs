//! `POST /attribution_robustness` → λ (records) and ρ (failure domains)
//! for an attribution, or for every endpoint pair a chain hypothesis
//! matches, with the summary counts and their denominator.

use std::sync::Arc;
use std::time::Duration;

use axum::{Json, extract::State, response::Response};

use graph_hunter_api::GraphHunterApi;
use graph_hunter_api::dto::robustness::AttributionRobustnessRequest;
use graph_hunter_core::cancel::CancelToken;

use super::helpers::{api_err_response, ok_json};

/// How long the work may run before it is cancelled.
const ROBUSTNESS_TIMEOUT: Duration = Duration::from_secs(120);

pub(super) async fn handler_attribution_robustness(
    State(api): State<Arc<GraphHunterApi>>,
    Json(body): Json<AttributionRobustnessRequest>,
) -> Response {
    let cancel = CancelToken::new();
    let cancel_for_work = cancel.clone();
    let mut work = tokio::task::spawn_blocking(move || {
        api.attribution_robustness_cancellable(body, &cancel_for_work)
    });
    // Dropping a `spawn_blocking` handle does not stop its closure, so a
    // bare timeout would answer and leave the work running under the
    // graph lock. Cancel it and wait for it to let go: the answer is then
    // the work's own `ApiError::Timeout`, and the graph is free again.
    let result = match tokio::time::timeout(ROBUSTNESS_TIMEOUT, &mut work).await {
        Ok(joined) => joined,
        Err(_) => {
            cancel.cancel();
            work.await
        }
    };
    match result {
        Ok(Ok(resp)) => ok_json(resp),
        Ok(Err(e)) => api_err_response(e),
        Err(join) => api_err_response(graph_hunter_api::ApiError::Internal(format!(
            "robustness task failed: {join}"
        ))),
    }
}
