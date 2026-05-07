//! Export, publish, sigma-save, and ticket-filing endpoints.

use axum::{
    extract::State,
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use serde::Deserialize;
use std::sync::Arc;

use graph_hunter_api::GraphHunterApi;

use super::helpers::{err_json, ok_json};

#[derive(Debug, Deserialize)]
pub(super) struct ExportIocsBody {
    format: String,
    #[serde(default)]
    tag_prefix: Option<String>,
}

pub(super) async fn handler_export_iocs(
    State(api): State<Arc<GraphHunterApi>>,
    Json(body): Json<ExportIocsBody>,
) -> Response {
    let format = body.format.clone();
    match api.export_iocs(graph_hunter_api::dto::export::ExportIocsRequest {
        session: None,
        format: body.format,
        tag_prefix: body.tag_prefix,
    }) {
        Ok(data) => ok_json(serde_json::json!({ "data": data, "format": format })),
        Err(e) => {
            let code = StatusCode::from_u16(e.status_code())
                .unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
            (code, Json(serde_json::json!({ "error": e.to_string() }))).into_response()
        }
    }
}

#[derive(Debug, Deserialize)]
pub(super) struct PublishIocsBody {
    watchlist_name: String,
    #[serde(default)]
    display_name: Option<String>,
    #[serde(default)]
    description: Option<String>,
    #[serde(default)]
    tag_prefix: Option<String>,
    #[serde(default)]
    dry_run: Option<bool>,
    #[serde(default)]
    confirm: Option<bool>,
}

pub(super) async fn handler_publish_iocs_to_sentinel(
    State(api): State<Arc<GraphHunterApi>>,
    Json(body): Json<PublishIocsBody>,
) -> Response {
    match api
        .publish_iocs_to_sentinel(graph_hunter_api::dto::sentinel::PublishIocsRequest {
            session: None,
            watchlist_name: body.watchlist_name,
            display_name: body.display_name,
            description: body.description,
            tag_prefix: body.tag_prefix,
            dry_run: body.dry_run.unwrap_or(false),
            confirm: body.confirm.unwrap_or(false),
        })
        .await
    {
        Ok(v) => ok_json(v),
        Err(e) => {
            let code = StatusCode::from_u16(e.status_code())
                .unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
            (code, Json(serde_json::json!({ "error": e.to_string() }))).into_response()
        }
    }
}

#[derive(Debug, Deserialize)]
pub(super) struct SaveSigmaBody {
    hypothesis_dsl: String,
    title: String,
    #[serde(default)]
    tag_prefix: Option<String>,
    #[serde(default)]
    level: Option<String>,
}

pub(super) async fn handler_save_hypothesis_as_sigma(
    State(api): State<Arc<GraphHunterApi>>,
    Json(body): Json<SaveSigmaBody>,
) -> Response {
    let api_clone = api.clone();
    let res = tokio::task::spawn_blocking(move || {
        api_clone.save_hypothesis_as_sigma(graph_hunter_api::dto::sigma::SaveHypothesisAsSigmaRequest {
            session: None,
            hypothesis_dsl: body.hypothesis_dsl,
            title: body.title,
            tag_prefix: body.tag_prefix,
            level: body.level,
        })
    })
    .await;
    match res {
        Ok(Ok(v)) => ok_json(v),
        Ok(Err(e)) => {
            let code = StatusCode::from_u16(e.status_code())
                .unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
            (code, Json(serde_json::json!({ "error": e.to_string() }))).into_response()
        }
        Err(e) => err_json(format!("Task error: {e}")),
    }
}

#[derive(Debug, Deserialize)]
pub(super) struct FileTicketBody {
    system: String,
    title: String,
    body: String,
    #[serde(default)]
    priority: Option<String>,
    #[serde(default)]
    assignee: Option<String>,
    #[serde(default)]
    dry_run: Option<bool>,
    #[serde(default)]
    confirm: Option<bool>,
}

pub(super) async fn handler_file_ticket(
    State(api): State<Arc<GraphHunterApi>>,
    Json(body): Json<FileTicketBody>,
) -> Response {
    match api
        .file_ticket(graph_hunter_api::dto::ticket::FileTicketRequest {
            system: body.system,
            title: body.title,
            body: body.body,
            priority: body.priority,
            assignee: body.assignee,
            dry_run: body.dry_run.unwrap_or(false),
            confirm: body.confirm.unwrap_or(false),
        })
        .await
    {
        Ok(v) => ok_json(v),
        Err(e) => {
            let code = StatusCode::from_u16(e.status_code())
                .unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
            (code, Json(serde_json::json!({ "error": e.to_string() }))).into_response()
        }
    }
}

#[derive(Debug, Deserialize)]
pub(super) struct ExportSubgraphBody {
    node_ids: Vec<String>,
    format: Option<String>,
}

pub(super) async fn handler_export_subgraph(
    State(api): State<Arc<GraphHunterApi>>,
    Json(body): Json<ExportSubgraphBody>,
) -> Response {
    let fmt = body.format.unwrap_or_else(|| "json".to_string());
    let fmt_for_resp = fmt.clone();
    match api.export_subgraph(graph_hunter_api::dto::export::ExportSubgraphRequest {
        session: None,
        format: fmt,
        nodes: body.node_ids,
    }) {
        Ok(text) => ok_json(serde_json::json!({ "data": text, "format": fmt_for_resp })),
        Err(e) => {
            let code = StatusCode::from_u16(e.status_code())
                .unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
            (code, Json(serde_json::json!({ "error": e.to_string() }))).into_response()
        }
    }
}

#[derive(Debug, Deserialize)]
pub(super) struct ExportOcsfBody {
    #[serde(default)]
    dataset_id: Option<String>,
    #[serde(default)]
    format: Option<String>,
    #[serde(default)]
    page_size: Option<usize>,
    #[serde(default)]
    offset: Option<usize>,
}

pub(super) async fn handler_export_ocsf(
    State(api): State<Arc<GraphHunterApi>>,
    Json(body): Json<ExportOcsfBody>,
) -> Response {
    let fmt = body.format.unwrap_or_else(|| "ndjson".to_string());
    let fmt_for_resp = fmt.clone();
    match api.export_ocsf(graph_hunter_api::dto::export::ExportOcsfRequest {
        session: None,
        dataset_id: body.dataset_id,
        format: fmt,
        page_size: body.page_size,
        offset: body.offset,
    }) {
        Ok(text) => ok_json(serde_json::json!({ "data": text, "format": fmt_for_resp })),
        Err(e) => {
            let code = StatusCode::from_u16(e.status_code())
                .unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
            (code, Json(serde_json::json!({ "error": e.to_string() }))).into_response()
        }
    }
}

#[derive(Debug, Deserialize)]
pub(super) struct ExportHuntBody {
    format: Option<String>,
    #[serde(default)]
    page: Option<usize>,
    #[serde(default)]
    page_size: Option<usize>,
    /// When `true`, collapses identical paths (DedupMode::ByPath) — the
    /// critical fix for the 166 KB transport truncation the feedback cited.
    #[serde(default)]
    aggregate: Option<bool>,
}

pub(super) async fn handler_export_hunt_results(
    State(api): State<Arc<GraphHunterApi>>,
    Json(body): Json<ExportHuntBody>,
) -> Response {
    let fmt = body.format.unwrap_or_else(|| "json".to_string());
    let fmt_for_resp = fmt.clone();
    match api.export_hunt_results(graph_hunter_api::dto::export::ExportHuntResultsRequest {
        session: None,
        format: fmt,
        page: body.page,
        page_size: body.page_size,
        aggregate: body.aggregate,
    }) {
        Ok(text) => ok_json(serde_json::json!({ "data": text, "format": fmt_for_resp })),
        Err(e) => {
            let code = StatusCode::from_u16(e.status_code())
                .unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
            (code, Json(serde_json::json!({ "error": e.to_string() }))).into_response()
        }
    }
}
