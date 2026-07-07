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
    #[serde(default)]
    pub ingest: Option<bool>,
    #[serde(default)]
    pub max_rows: Option<u32>,
    #[serde(default)]
    pub lookback: Option<String>,
    #[serde(default)]
    pub dataset: Option<String>,
    #[serde(default)]
    pub acknowledge_fallback: Option<bool>,
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
            time_window: super::graph::lookback_to_window(body.lookback.as_deref()),
            ingest: body.ingest,
            max_rows: body.max_rows,
            dataset: body.dataset,
            acknowledge_fallback: body.acknowledge_fallback,
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

#[derive(Debug, Default, Deserialize)]
pub(super) struct SchemaDiscoverBody {
    #[serde(default)]
    workspace_id: Option<String>,
    #[serde(default)]
    azure_tenant_id: Option<String>,
    #[serde(default)]
    azure_client_id: Option<String>,
    #[serde(default)]
    azure_client_secret: Option<String>,
    #[serde(default)]
    lookback: Option<String>,
    #[serde(default)]
    table_filter: Option<Vec<String>>,
    #[serde(default)]
    min_ingestion_mb: Option<f64>,
    #[serde(default)]
    max_tables: Option<u32>,
    #[serde(default)]
    sample_rows: Option<u32>,
}

/// Discover active Sentinel tables + classify their fields for graph
/// construction. Read-only; delegates to the canonical API.
pub(super) async fn handler_discover_schema(
    State(api): State<Arc<GraphHunterApi>>,
    Json(body): Json<SchemaDiscoverBody>,
) -> Response {
    let result = tokio::time::timeout(
        Duration::from_secs(120),
        api.discover_schema(graph_hunter_api::dto::sentinel::SchemaDiscoverRequest {
            workspace_id: body.workspace_id.unwrap_or_default(),
            azure_tenant_id: body.azure_tenant_id.unwrap_or_default(),
            azure_client_id: body.azure_client_id.unwrap_or_default(),
            azure_client_secret: body.azure_client_secret.unwrap_or_default(),
            time_window: super::graph::lookback_to_window(body.lookback.as_deref()),
            table_filter: body.table_filter.unwrap_or_default(),
            min_ingestion_mb: body.min_ingestion_mb,
            max_tables: body.max_tables,
            sample_rows: body.sample_rows,
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
        Err(_) => err_json("Schema discovery timed out (120s)"),
    }
}

#[derive(Debug, Default, Deserialize)]
pub(super) struct GraphProposeBody {
    #[serde(default)]
    workspace_id: Option<String>,
    #[serde(default)]
    azure_tenant_id: Option<String>,
    #[serde(default)]
    azure_client_id: Option<String>,
    #[serde(default)]
    azure_client_secret: Option<String>,
    #[serde(default)]
    selected_fields: Vec<graph_hunter_api::dto::sentinel::SelectedField>,
    #[serde(default)]
    hypothesis_context: Option<String>,
    #[serde(default)]
    max_proposals: Option<u32>,
    #[serde(default)]
    lookback: Option<String>,
}

/// Propose candidate graph schemas (§4.2) from analyst-selected fields,
/// including the materialization KQL. Delegates to the canonical API.
pub(super) async fn handler_graph_propose(
    State(api): State<Arc<GraphHunterApi>>,
    Json(body): Json<GraphProposeBody>,
) -> Response {
    let result = tokio::time::timeout(
        Duration::from_secs(120),
        api.graph_propose(graph_hunter_api::dto::sentinel::GraphProposeRequest {
            workspace_id: body.workspace_id.unwrap_or_default(),
            azure_tenant_id: body.azure_tenant_id.unwrap_or_default(),
            azure_client_id: body.azure_client_id.unwrap_or_default(),
            azure_client_secret: body.azure_client_secret.unwrap_or_default(),
            selected_fields: body.selected_fields,
            hypothesis_context: body.hypothesis_context,
            max_proposals: body.max_proposals,
            time_window: super::graph::lookback_to_window(body.lookback.as_deref()),
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
        Err(_) => err_json("graph_propose timed out (120s)"),
    }
}

#[derive(Debug, Default, Deserialize)]
pub(super) struct GraphBuildBody {
    #[serde(default)]
    workspace_id: Option<String>,
    #[serde(default)]
    azure_tenant_id: Option<String>,
    #[serde(default)]
    azure_client_id: Option<String>,
    #[serde(default)]
    azure_client_secret: Option<String>,
    proposal_id: String,
    #[serde(default)]
    lookback: Option<String>,
    #[serde(default)]
    enrich: Option<Vec<String>>,
    #[serde(default)]
    merge_mode: Option<String>,
}

/// Materialize an approved proposal (§4.3): run its KQL, map rows to the graph,
/// enrich once. Delegates to the canonical API.
pub(super) async fn handler_graph_build(
    State(api): State<Arc<GraphHunterApi>>,
    Json(body): Json<GraphBuildBody>,
) -> Response {
    let result = tokio::time::timeout(
        Duration::from_secs(300),
        api.graph_build(graph_hunter_api::dto::sentinel::GraphBuildRequest {
            workspace_id: body.workspace_id.unwrap_or_default(),
            azure_tenant_id: body.azure_tenant_id.unwrap_or_default(),
            azure_client_id: body.azure_client_id.unwrap_or_default(),
            azure_client_secret: body.azure_client_secret.unwrap_or_default(),
            proposal_id: body.proposal_id,
            time_window: super::graph::lookback_to_window(body.lookback.as_deref()),
            enrich: body.enrich,
            merge_mode: body.merge_mode,
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
        Err(_) => err_json("graph_build timed out (300s)"),
    }
}

#[derive(Deserialize)]
pub(super) struct SeedBody {
    pub entity_type: String,
    pub value: String,
    #[serde(default)]
    pub lookback: Option<String>,
}

/// Cold-start the graph from a known Sentinel IoC. Pulls the IoC's
/// events, ingests them, returns the seeded neighborhood + anomalies.
pub(super) async fn handler_seed_from_ioc(
    State(api): State<Arc<GraphHunterApi>>,
    Json(body): Json<SeedBody>,
) -> Response {
    let time_window = super::graph::lookback_to_window(body.lookback.as_deref());
    let result = tokio::time::timeout(
        Duration::from_secs(120),
        api.seed_from_ioc(graph_hunter_api::dto::sentinel::SeedFromIocRequest {
            session: None,
            entity_type: body.entity_type,
            value: body.value,
            time_window,
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
        Err(_) => err_json("Sentinel seed timed out (120s)"),
    }
}

#[derive(Debug, Deserialize)]
pub(super) struct NodeEnrichBody {
    pub node_id: String,
    #[serde(default)]
    pub tables: Option<Vec<String>>,
    #[serde(default)]
    pub lookback: Option<String>,
    #[serde(default)]
    pub max_rows: Option<u32>,
    #[serde(default)]
    pub dataset: Option<String>,
}

/// Enrich an existing graph node on demand by pulling its Sentinel events.
pub(super) async fn handler_node_enrich(
    State(api): State<Arc<GraphHunterApi>>,
    Json(body): Json<NodeEnrichBody>,
) -> Response {
    let time_window = super::graph::lookback_to_window(body.lookback.as_deref());
    let result = tokio::time::timeout(
        Duration::from_secs(120),
        api.node_enrich(graph_hunter_api::dto::sentinel::NodeEnrichRequest {
            session: None,
            node_id: body.node_id,
            tables: body.tables,
            time_window,
            max_rows: body.max_rows,
            dataset: body.dataset,
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
        Err(_) => err_json("Node enrich timed out (120s)"),
    }
}

/// Resume the paused Sentinel polling loop.
pub(super) async fn handler_sentinel_resume(State(api): State<Arc<GraphHunterApi>>) -> Response {
    match api.sentinel_resume() {
        Ok(()) => ok_json(serde_json::json!({ "resumed": true })),
        Err(e) => {
            let code = StatusCode::from_u16(e.status_code())
                .unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
            (code, Json(serde_json::json!({ "error": e.to_string() }))).into_response()
        }
    }
}

/// Pause the Sentinel polling loop.
pub(super) async fn handler_sentinel_pause(State(api): State<Arc<GraphHunterApi>>) -> Response {
    match api.sentinel_pause() {
        Ok(()) => ok_json(serde_json::json!({ "paused": true })),
        Err(e) => {
            let code = StatusCode::from_u16(e.status_code())
                .unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
            (code, Json(serde_json::json!({ "error": e.to_string() }))).into_response()
        }
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
