//! HTTP handlers for `/graph/summary` (and future `/graph/overlap`).
//!
//! Thin delegates to [`graph_hunter_api::GraphHunterApi::get_graph_summary`];
//! no business logic here. Follows the same pattern as the other domain
//! routers in this module.

use axum::{extract::State, response::Response};
use std::sync::Arc;

use graph_hunter_api::GraphHunterApi;

use super::helpers::api_response;

/// `GET /graph/summary` — returns a [`GraphSummary`] snapshot.
///
/// Currently returns hardcoded zero/empty data (Task 1 stub). Later tasks
/// plumb in real session graph counts, hunt-cache state, and recent pivots.
pub(super) async fn handler_graph_summary(State(api): State<Arc<GraphHunterApi>>) -> Response {
    api_response(api.get_graph_meta_summary())
}
