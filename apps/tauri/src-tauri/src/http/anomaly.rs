//! Anomaly scoring, heatmap, subnet analysis, IP enrichment.

use axum::{
    extract::{Query, State},
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use serde::Deserialize;
use std::sync::Arc;
use std::time::Duration;

use graph_hunter_api::GraphHunterApi;

use super::helpers::{api_response, err_json, ok_json};

#[derive(Debug, Deserialize)]
pub(super) struct HeatmapQuery {
    #[serde(default)]
    bucket_size_seconds: Option<i64>,
}

pub(super) async fn handler_temporal_heatmap(
    State(api): State<Arc<GraphHunterApi>>,
    Query(q): Query<HeatmapQuery>,
) -> Response {
    api_response(api.get_temporal_heatmap(
        graph_hunter_api::dto::analytics::TemporalHeatmapRequest {
            session: None,
            bucket_size_seconds: q.bucket_size_seconds,
        },
    ))
}

pub(super) async fn handler_subnet_analysis(State(api): State<Arc<GraphHunterApi>>) -> Response {
    match api.get_subnet_analysis(graph_hunter_api::dto::enrichment::SubnetAnalysisRequest::default())
    {
        Ok(v) => ok_json(v),
        Err(e) => {
            let code = axum::http::StatusCode::from_u16(e.status_code())
                .unwrap_or(axum::http::StatusCode::INTERNAL_SERVER_ERROR);
            (code, Json(serde_json::json!({ "error": e.to_string() }))).into_response()
        }
    }
}

#[derive(Debug, Deserialize)]
pub(super) struct EnrichIpBody {
    ip: String,
}

pub(super) async fn handler_enrich_ip(
    State(api): State<Arc<GraphHunterApi>>,
    Json(body): Json<EnrichIpBody>,
) -> Response {
    match api
        .enrich_ip(graph_hunter_api::dto::geoip::EnrichIpRequest {
            session: None,
            ip: body.ip,
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

pub(super) async fn handler_enable_anomaly_scoring(State(api): State<Arc<GraphHunterApi>>) -> Response {
    match api.enable_anomaly_scoring(
        graph_hunter_api::dto::anomaly::EnableAnomalyScoringRequest::default(),
    ) {
        Ok(()) => ok_json(serde_json::json!({ "enabled": true })),
        Err(e) => {
            let code = StatusCode::from_u16(e.status_code())
                .unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
            (code, Json(serde_json::json!({ "error": e.to_string() }))).into_response()
        }
    }
}

pub(super) async fn handler_compute_scores(State(api): State<Arc<GraphHunterApi>>) -> Response {
    let api_clone = api.clone();
    let result = tokio::time::timeout(
        Duration::from_secs(120),
        tokio::task::spawn_blocking(move || {
            api_clone
                .compute_scores(graph_hunter_api::dto::graph_ops::ComputeScoresRequest::default())
                .map(|()| serde_json::json!({ "computed": true }))
                .map_err(|e| crate::error::CommandError::from(e))
        }),
    )
    .await;
    match result {
        Ok(Ok(Ok(v))) => ok_json(v),
        Ok(Ok(Err(e))) => err_json(e),
        Ok(Err(e)) => err_json(format!("Task error: {e}")),
        Err(_) => err_json("Score computation timed out"),
    }
}
