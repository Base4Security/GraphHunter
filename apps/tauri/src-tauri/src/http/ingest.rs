//! Agentic ingest negotiation, mapping generation, and mapping-library endpoints.

use axum::{
    extract::State,
    response::{IntoResponse, Response},
    Json,
};
use std::sync::Arc;

use graph_hunter_api::GraphHunterApi;

use super::helpers::{api_err_response, ok_json};

pub(super) async fn handler_ingest_negotiate(
    State(api): State<Arc<GraphHunterApi>>,
    Json(body): Json<graph_hunter_api::dto::agentic::IngestNegotiateRequest>,
) -> Response {
    match api.ingest_negotiate(body) {
        Ok(resp) => ok_json(resp),
        Err(e) => api_err_response(e),
    }
}

/// PCAP / PCAPNG offline preview — read up to 10K packets, return a
/// non-tabular summary. Separate from the tabular `preview_ingest`
/// endpoint because the binary content can't survive UTF-8 lossy
/// reading and the response shape is richer.
pub(super) async fn handler_pcap_preview(
    State(api): State<Arc<GraphHunterApi>>,
    Json(body): Json<graph_hunter_api::dto::ingestion::PcapPreviewRequest>,
) -> Response {
    let api_clone = api.clone();
    let joined = tokio::task::spawn_blocking(move || api_clone.pcap_preview(body)).await;
    match joined {
        Ok(Ok(resp)) => ok_json(resp),
        Ok(Err(e)) => api_err_response(e),
        Err(e) => (
            axum::http::StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({ "error": format!("join error: {e}") })),
        )
            .into_response(),
    }
}

pub(super) async fn handler_canonical_map(
    State(api): State<Arc<GraphHunterApi>>,
    Json(body): Json<graph_hunter_api::dto::agentic::CanonicalMapRequest>,
) -> Response {
    match api.canonical_map(body) {
        Ok(resp) => ok_json(resp),
        Err(e) => api_err_response(e),
    }
}

pub(super) async fn handler_parser_generate(
    State(api): State<Arc<GraphHunterApi>>,
    Json(body): Json<graph_hunter_api::dto::agentic::ParserGenerateRequest>,
) -> Response {
    match api.parser_generate(body) {
        Ok(resp) => ok_json(resp),
        Err(e) => api_err_response(e),
    }
}

pub(super) async fn handler_schema_drift_detect(
    State(api): State<Arc<GraphHunterApi>>,
    Json(body): Json<graph_hunter_api::dto::agentic::SchemaDriftRequest>,
) -> Response {
    match api.schema_drift_detect(body) {
        Ok(resp) => ok_json(resp),
        Err(e) => api_err_response(e),
    }
}

pub(super) async fn handler_mapping_regression_test(
    State(api): State<Arc<GraphHunterApi>>,
    Json(body): Json<graph_hunter_api::dto::agentic::MappingRegressionRequest>,
) -> Response {
    let api_clone = api.clone();
    let joined = tokio::task::spawn_blocking(move || api_clone.mapping_regression_test(body)).await;
    match joined {
        Ok(Ok(resp)) => ok_json(resp),
        Ok(Err(e)) => api_err_response(e),
        Err(e) => (
            axum::http::StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({ "error": format!("join error: {e}") })),
        )
            .into_response(),
    }
}

pub(super) async fn handler_publish_mapping(
    State(api): State<Arc<GraphHunterApi>>,
    Json(body): Json<graph_hunter_api::dto::mapping_library::PublishMappingRequest>,
) -> Response {
    match api.publish_mapping(body) {
        Ok(resp) => ok_json(resp),
        Err(e) => api_err_response(e),
    }
}

pub(super) async fn handler_fetch_shared_mappings(
    State(api): State<Arc<GraphHunterApi>>,
    Json(body): Json<graph_hunter_api::dto::mapping_library::FetchSharedMappingsRequest>,
) -> Response {
    match api.fetch_shared_mappings(body) {
        Ok(resp) => ok_json(resp),
        Err(e) => api_err_response(e),
    }
}
