//! Invariant-check endpoints (current graph + hypothetical dry-run).

use axum::{
    extract::State,
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use serde::Deserialize;
use std::sync::Arc;

use graph_hunter_api::GraphHunterApi;

use super::helpers::{api_err_response, ok_json};

#[derive(Debug, Deserialize)]
pub(super) struct CheckInvariantsBody {
    #[serde(default)]
    dataset_id: Option<String>,
}

pub(super) async fn handler_check_invariants(
    State(api): State<Arc<GraphHunterApi>>,
    Json(body): Json<CheckInvariantsBody>,
) -> Response {
    match api.check_invariants(graph_hunter_api::dto::invariants::CheckInvariantsRequest {
        session: None,
        dataset_id: body.dataset_id,
    }) {
        Ok(report) => ok_json(serde_json::to_value(&report).unwrap_or_else(|_| {
            serde_json::json!({ "error": "serialize invariant report" })
        })),
        Err(e) => {
            let code = StatusCode::from_u16(e.status_code())
                .unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
            (code, Json(serde_json::json!({ "error": e.to_string() }))).into_response()
        }
    }
}

pub(super) async fn handler_invariant_check_hypothetical(
    State(api): State<Arc<GraphHunterApi>>,
    Json(body): Json<graph_hunter_api::dto::agentic::InvariantHypotheticalRequest>,
) -> Response {
    let api_clone = api.clone();
    let joined =
        tokio::task::spawn_blocking(move || api_clone.invariant_check_hypothetical(body)).await;
    match joined {
        Ok(Ok(report)) => ok_json(report),
        Ok(Err(e)) => api_err_response(e),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({ "error": format!("join error: {e}") })),
        )
            .into_response(),
    }
}
