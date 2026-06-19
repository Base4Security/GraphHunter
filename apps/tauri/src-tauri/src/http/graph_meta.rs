//! HTTP handlers for `/graph/summary` and `/graph/overlap`.
//!
//! Thin delegates to [`graph_hunter_api::GraphHunterApi::get_graph_meta_summary`]
//! and [`graph_hunter_api::GraphHunterApi::post_graph_overlap`]; no business
//! logic here. Follows the same pattern as the other domain routers in this
//! module.

use axum::{extract::State, response::Response, Json};
use std::sync::Arc;

use graph_hunter_api::dto::v1::graph_meta::OverlapRequest;
use graph_hunter_api::GraphHunterApi;

use super::helpers::api_response;

/// `GET /graph/summary` — returns a `GraphSummary` snapshot of the current
/// session's graph: totals (cached 30s), datasets, hunts, recent pivots.
pub(super) async fn handler_graph_summary(State(api): State<Arc<GraphHunterApi>>) -> Response {
    api_response(api.get_graph_meta_summary())
}

/// `POST /graph/overlap` — given up to 500 entities, returns which are
/// already in the current session graph (with degree) and which are not.
/// Backs the MCP `sentinel_query` overlap nudge.
pub(super) async fn handler_graph_overlap(
    State(api): State<Arc<GraphHunterApi>>,
    Json(req): Json<OverlapRequest>,
) -> Response {
    api_response(api.post_graph_overlap(req))
}
