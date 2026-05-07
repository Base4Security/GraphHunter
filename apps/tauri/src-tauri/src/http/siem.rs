//! Sentinel/KQL endpoints.

use axum::{
    extract::State,
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use serde::Deserialize;
use std::sync::Arc;
use std::time::Duration;

use graph_hunter_api::GraphHunterApi;

use super::helpers::{err_json, ok_json};

#[derive(Debug, Deserialize)]
pub(super) struct RunKqlBody {
    kql: String,
    #[serde(default)]
    workspace_id: Option<String>,
    #[serde(default)]
    azure_tenant_id: Option<String>,
    #[serde(default)]
    azure_client_id: Option<String>,
    #[serde(default)]
    azure_client_secret: Option<String>,
}

/// Execute an ad-hoc KQL query against Azure Log Analytics. Delegates
/// to the canonical API.
pub(super) async fn handler_run_kql(
    State(api): State<Arc<GraphHunterApi>>,
    Json(body): Json<RunKqlBody>,
) -> Response {
    let result = tokio::time::timeout(
        Duration::from_secs(120),
        api.run_kql(graph_hunter_api::dto::sentinel::RunKqlRequest {
            kql: body.kql,
            workspace_id: body.workspace_id.unwrap_or_default(),
            azure_tenant_id: body.azure_tenant_id.unwrap_or_default(),
            azure_client_id: body.azure_client_id.unwrap_or_default(),
            azure_client_secret: body.azure_client_secret.unwrap_or_default(),
            // HTTP transport doesn't currently expose a time window
            // picker — the analyst supplies the `where TimeGenerated`
            // filter in their KQL when they hit this route directly.
            time_window: None,
        }),
    )
    .await;
    match result {
        Ok(Ok(v)) => ok_json(v),
        Ok(Err(e)) => {
            let code = StatusCode::from_u16(e.status_code())
                .unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
            (code, Json(serde_json::json!({ "error": e.to_string() }))).into_response()
        }
        Err(_) => err_json("KQL execution timed out (120s)"),
    }
}

/// Get current Sentinel connector status.
pub(super) async fn handler_sentinel_status(State(api): State<Arc<GraphHunterApi>>) -> Response {
    match api.sentinel_status() {
        Ok(v) => return ok_json(v),
        Err(e) => {
            let code = StatusCode::from_u16(e.status_code())
                .unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
            return (code, Json(serde_json::json!({ "error": e.to_string() }))).into_response();
        }
    }
    #[allow(unreachable_code)]
    {
        // Legacy branches left as dead code for one release; the
        // canonical api.sentinel_status() already returns the `None`
        // case as a proper response.
        ok_json(serde_json::json!({
            "connected": false,
            "connector_id": null,
            "status": null,
        }))
    }
}
