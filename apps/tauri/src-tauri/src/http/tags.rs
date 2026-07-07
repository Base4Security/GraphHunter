//! Entity tagging endpoints.

use axum::{
    extract::{Query, State},
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use serde::Deserialize;
use std::sync::Arc;

use graph_hunter_api::GraphHunterApi;

use super::helpers::{api_response, ok_json};

#[derive(Debug, Deserialize)]
pub(super) struct TagEntityBody {
    node_id: String,
    tag: String,
    #[serde(default)]
    reason: Option<String>,
}

pub(super) async fn handler_tag_entity(
    State(api): State<Arc<GraphHunterApi>>,
    Json(body): Json<TagEntityBody>,
) -> Response {
    api_response(api.tag_entity(graph_hunter_api::dto::entity::TagEntityRequest {
        session: None,
        node_id: body.node_id,
        tag: body.tag,
        reason: body.reason,
    }))
}

#[derive(Debug, Deserialize)]
pub(super) struct UntagEntityBody {
    node_id: String,
    tag: String,
}

pub(super) async fn handler_untag_entity(
    State(api): State<Arc<GraphHunterApi>>,
    Json(body): Json<UntagEntityBody>,
) -> Response {
    match api.untag_entity(graph_hunter_api::dto::entity::UntagEntityRequest {
        session: None,
        node_id: body.node_id,
        tag: body.tag,
    }) {
        Ok(removed) => ok_json(serde_json::json!({"removed": removed})),
        Err(e) => {
            let code = StatusCode::from_u16(e.status_code())
                .unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
            (code, Json(serde_json::json!({ "error": e.to_string() }))).into_response()
        }
    }
}

#[derive(Debug, Deserialize)]
pub(super) struct ListTaggedQuery {
    #[serde(default)]
    tag_prefix: Option<String>,
}

pub(super) async fn handler_list_tagged(
    State(api): State<Arc<GraphHunterApi>>,
    Query(q): Query<ListTaggedQuery>,
) -> Response {
    api_response(api.list_tagged(graph_hunter_api::dto::entity::ListTaggedRequest {
        session: None,
        tag_prefix: q.tag_prefix,
    }))
}
