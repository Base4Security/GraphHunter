use std::sync::Arc;

use serde::Deserialize;
use tauri::{Emitter, State};
use uuid::Uuid;

use graph_hunter_cli::siem::{
    HttpSentinelTransport, SentinelAuth, SentinelPollingConfig, SentinelTokenCache,
};

use crate::scoring::run_scoring_adaptive;
use crate::sentinel_connector::{
    self, ConnectorStatus, SentinelConnectorHandle, default_tables,
};
use crate::state::AppState;
use crate::types::{ConnectorStatusResponse, SentinelConnectedEvent};

#[derive(Deserialize)]
pub struct SentinelConnectParams {
    pub workspace_id: String,
    pub azure_tenant_id: String,
    pub azure_client_id: String,
    pub azure_client_secret: String,
    #[serde(default = "default_poll_interval")]
    pub poll_interval_secs: u64,
    #[serde(default = "default_sentinel_tables")]
    pub tables: Vec<String>,
    #[serde(default = "default_batch_size")]
    pub batch_size: u32,
}

fn default_poll_interval() -> u64 { 30 }
fn default_sentinel_tables() -> Vec<String> { default_tables() }
fn default_batch_size() -> u32 { 10000 }

/// Start real-time Sentinel streaming. Returns immediately with connector info.
#[tauri::command]
pub async fn cmd_sentinel_connect(
    state: State<'_, Arc<AppState>>,
    app: tauri::AppHandle,
    params: SentinelConnectParams,
) -> Result<SentinelConnectedEvent, String> {
    // Check no connector is already running
    {
        let guard = state
            .sentinel_connector
            .read()
            .map_err(|e| format!("Lock poisoned: {}", e))?;
        if guard.is_some() {
            return Err("Sentinel connector is already running. Disconnect first.".into());
        }
    }

    // Verify we have a current session
    let session_id = state
        .current_session_id
        .read()
        .map_err(|e| format!("Lock poisoned: {}", e))?
        .clone()
        .ok_or("No current session. Create or load a session first.")?;

    let session = {
        let sessions = state
            .sessions
            .read()
            .map_err(|e| format!("Lock poisoned: {}", e))?;
        Arc::clone(sessions.get(&session_id).ok_or("Session not found")?)
    };

    let connector_id = Uuid::new_v4().to_string();
    let dataset_id = format!("sentinel-live-{}", &connector_id[..8]);

    // Create dataset entry
    {
        let created_at = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|e| e.to_string())?
            .as_secs() as i64;
        let mut datasets = session
            .datasets
            .write()
            .map_err(|e| format!("Lock poisoned: {}", e))?;
        datasets.push(crate::state::DatasetInfo {
            id: dataset_id.clone(),
            name: format!("Sentinel Live ({})", &connector_id[..8]),
            path: None,
            created_at,
            entity_count: 0,
            relation_count: 0,
        });
    }

    let config = SentinelPollingConfig {
        workspace_id: params.workspace_id,
        auth: SentinelAuth {
            tenant_id: params.azure_tenant_id,
            client_id: params.azure_client_id,
            client_secret: params.azure_client_secret,
        },
        poll_interval_secs: params.poll_interval_secs.max(5),
        tables: if params.tables.is_empty() {
            default_tables()
        } else {
            params.tables.clone()
        },
        batch_size: params.batch_size.max(100),
    };

    let transport = Arc::new(HttpSentinelTransport::new());
    let token_cache = Arc::new(SentinelTokenCache::new());
    let cancel = tokio_util::sync::CancellationToken::new();
    let (status_tx, status_rx) = tokio::sync::watch::channel(ConnectorStatus::Connecting);

    let event = SentinelConnectedEvent {
        connector_id: connector_id.clone(),
        tables: config.tables.clone(),
        poll_interval_secs: config.poll_interval_secs,
    };

    // Spawn the polling loop
    let task_cancel = cancel.clone();
    let task_handle = tauri::async_runtime::spawn(sentinel_connector::polling_loop(
        config,
        transport,
        token_cache,
        session,
        session_id,
        app.clone(),
        task_cancel,
        status_tx,
        dataset_id,
    ));

    // Store the handle
    {
        let mut guard = state
            .sentinel_connector
            .write()
            .map_err(|e| format!("Lock poisoned: {}", e))?;
        *guard = Some(SentinelConnectorHandle {
            connector_id: connector_id.clone(),
            cancel_token: cancel,
            task_handle,
            status_rx,
        });
    }

    let _ = app.emit("sentinel-connected", event.clone());
    Ok(event)
}

/// Stop the real-time Sentinel connector. Runs full scoring on accumulated data.
#[tauri::command]
pub async fn cmd_sentinel_disconnect(
    state: State<'_, Arc<AppState>>,
) -> Result<(), String> {
    let handle = {
        let mut guard = state
            .sentinel_connector
            .write()
            .map_err(|e| format!("Lock poisoned: {}", e))?;
        guard.take()
    };

    let handle = handle.ok_or("No Sentinel connector is running.")?;

    // Signal cancellation
    handle.cancel_token.cancel();

    // Wait for task to finish (with timeout)
    let _ = tokio::time::timeout(
        std::time::Duration::from_secs(10),
        handle.task_handle,
    )
    .await;

    // Run full scoring on accumulated data
    let session_id = state
        .current_session_id
        .read()
        .map_err(|e| format!("Lock poisoned: {}", e))?
        .clone();

    if let Some(id) = session_id {
        let sessions = state
            .sessions
            .read()
            .map_err(|e| format!("Lock poisoned: {}", e))?;
        if let Some(session) = sessions.get(&id) {
            if let Ok(mut graph) = session.graph.write() {
                run_scoring_adaptive(&mut graph);
            }
        }
    }

    Ok(())
}

/// Get current Sentinel connector status.
#[tauri::command]
pub fn cmd_sentinel_status(
    state: State<Arc<AppState>>,
) -> Result<ConnectorStatusResponse, String> {
    let guard = state
        .sentinel_connector
        .read()
        .map_err(|e| format!("Lock poisoned: {}", e))?;

    match guard.as_ref() {
        Some(handle) => {
            let status = handle.status_rx.borrow().clone();
            Ok(ConnectorStatusResponse {
                connected: true,
                connector_id: Some(handle.connector_id.clone()),
                status: Some(status),
            })
        }
        None => Ok(ConnectorStatusResponse {
            connected: false,
            connector_id: None,
            status: None,
        }),
    }
}
