//! Catalog lookup endpoints.

use axum::{
    extract::State,
    response::{IntoResponse, Response},
    Json,
};
use std::sync::Arc;

use graph_hunter_api::GraphHunterApi;

use super::helpers::ok_json;

pub(super) async fn handler_catalog(State(api): State<Arc<GraphHunterApi>>) -> Response {
    ok_json(api.get_catalog())
}

pub(super) async fn handler_catalog_with_status(State(api): State<Arc<GraphHunterApi>>) -> Response {
    match api
        .get_catalog_with_status(graph_hunter_api::dto::dsl::GetCatalogWithStatusRequest::default())
    {
        Ok(v) => ok_json(v),
        Err(e) => {
            let code = axum::http::StatusCode::from_u16(e.status_code())
                .unwrap_or(axum::http::StatusCode::INTERNAL_SERVER_ERROR);
            (code, Json(serde_json::json!({ "error": e.to_string() }))).into_response()
        }
    }
}

pub(super) async fn handler_catalog_diagnostics(State(api): State<Arc<GraphHunterApi>>) -> Response {
    ok_json(api.get_catalog_diagnostics())
}
