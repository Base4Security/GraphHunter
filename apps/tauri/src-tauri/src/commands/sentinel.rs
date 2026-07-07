//! Sentinel real-time connector commands. All five delegate to the
//! canonical API; the polling loop + three-gate publish logic lives
//! in `graph_hunter_api::operations::sentinel` and
//! `graph_hunter_api::sentinel_connector`.

use std::sync::Arc;

use tauri::State;

use graph_hunter_api::dto::sentinel::{
    ConnectorStatusResponse, HuntingTemplateId, KqlResult, RunHuntingTemplateRequest,
    RunKqlRequest, SentinelConnectRequest, SentinelConnectedEvent, SentinelEnvStatus, TimeWindow,
};
use graph_hunter_api::operations::sentinel::preview_hunting_template;
use graph_hunter_api::GraphHunterApi;

use crate::error::CommandError;

// Re-exports for backward compat with anything that still references
// these by the old path (e.g. tests, external integrations).
pub use graph_hunter_api::dto::sentinel::{
    SentinelConnectRequest as SentinelConnectParams, RunKqlRequest as RunKqlParams,
};

/// Start real-time Sentinel streaming. Returns immediately with
/// connector info; a background task polls each configured table and
/// emits `sentinel-data` / `kql-executed` / `sentinel-error` events.
#[tauri::command]
pub async fn cmd_sentinel_connect(
    api: State<'_, Arc<GraphHunterApi>>,
    params: SentinelConnectRequest,
) -> Result<SentinelConnectedEvent, CommandError> {
    api.sentinel_connect(params, None)
        .await
        .map_err(CommandError::from)
}

/// Stop the connector. Runs full adaptive scoring on accumulated data.
#[tauri::command]
pub async fn cmd_sentinel_disconnect(
    api: State<'_, Arc<GraphHunterApi>>,
) -> Result<(), CommandError> {
    api.sentinel_disconnect().await.map_err(CommandError::from)
}

/// Current connector status.
#[tauri::command]
pub fn cmd_sentinel_status(
    api: State<Arc<GraphHunterApi>>,
) -> Result<ConnectorStatusResponse, CommandError> {
    api.sentinel_status().map_err(CommandError::from)
}

/// Resume the paused Sentinel polling loop.
#[tauri::command]
pub fn cmd_sentinel_resume(api: State<Arc<GraphHunterApi>>) -> Result<(), CommandError> {
    api.sentinel_resume().map_err(CommandError::from)
}

/// Pause the Sentinel polling loop (stop querying; keep the connector).
#[tauri::command]
pub fn cmd_sentinel_pause(api: State<Arc<GraphHunterApi>>) -> Result<(), CommandError> {
    api.sentinel_pause().map_err(CommandError::from)
}

/// Ad-hoc KQL query against Log Analytics — ingest results into the
/// current session's graph and run full scoring.
#[tauri::command]
pub async fn cmd_run_kql(
    api: State<'_, Arc<GraphHunterApi>>,
    params: RunKqlRequest,
) -> Result<KqlResult, CommandError> {
    api.run_kql(params).await.map_err(CommandError::from)
}

/// Check which Sentinel env vars are configured. Stateless — pure
/// env probe, returns the masked secret hint for the UI.
#[tauri::command]
pub fn cmd_sentinel_check_env(api: State<Arc<GraphHunterApi>>) -> SentinelEnvStatus {
    api.sentinel_check_env()
}

/// Phase M: run one of the pre-built hunting templates against
/// Sentinel. The KQL is rendered server-side from `template` +
/// `time_window` and dispatched through the same `run_kql` path.
#[tauri::command]
pub async fn cmd_run_hunting_template(
    api: State<'_, Arc<GraphHunterApi>>,
    params: RunHuntingTemplateRequest,
) -> Result<KqlResult, CommandError> {
    api.run_hunting_template(params)
        .await
        .map_err(CommandError::from)
}

/// Stateless: render a hunting template's KQL without dispatching.
/// Powers the "ver KQL" toggle in the templates UI so the analyst
/// inspects the query before clicking Run.
#[tauri::command]
pub fn cmd_preview_hunting_template(
    template: HuntingTemplateId,
    time_window: Option<TimeWindow>,
) -> String {
    let window = time_window.unwrap_or(TimeWindow::Preset {
        lookback: graph_hunter_api::dto::sentinel::LookbackPreset::H24,
    });
    preview_hunting_template(template, &window)
}
