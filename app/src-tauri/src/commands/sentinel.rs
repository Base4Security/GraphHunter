use std::sync::Arc;

use serde::Deserialize;
use tauri::{Emitter, State};
use uuid::Uuid;

use graph_hunter_cli::siem::{
    HttpSentinelTransport, SentinelAuth, SentinelPollingConfig, SentinelTokenCache,
};

use crate::error::CommandError;
use crate::scoring::run_scoring_adaptive;
use crate::sentinel_connector::{
    self, ConnectorStatus, SentinelConnectorHandle, default_tables,
};
use crate::state::AppState;
use crate::types::{ConnectorStatusResponse, SentinelConnectedEvent};

#[derive(Deserialize)]
pub struct SentinelConnectParams {
    #[serde(default)]
    pub workspace_id: String,
    #[serde(default)]
    pub azure_tenant_id: String,
    #[serde(default)]
    pub azure_client_id: String,
    #[serde(default)]
    pub azure_client_secret: String,
    #[serde(default)]
    pub poll_interval_secs: u64,
    #[serde(default)]
    pub tables: Vec<String>,
    #[serde(default)]
    pub batch_size: u32,
}

/// Resolves a param value: uses the explicit value if non-empty, otherwise falls back to env var.
fn env_or(explicit: &str, env_key: &str) -> Result<String, CommandError> {
    if !explicit.is_empty() {
        return Ok(explicit.to_string());
    }
    std::env::var(env_key).map_err(|_| CommandError::SentinelError(format!("Missing '{}': not provided and {} not set in .env", env_key, env_key)))
}

fn resolve_poll_interval(explicit: u64) -> u64 {
    if explicit > 0 { return explicit; }
    std::env::var("SENTINEL_POLL_INTERVAL_SECS")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(30)
}

fn resolve_batch_size(explicit: u32) -> u32 {
    if explicit > 0 { return explicit; }
    std::env::var("SENTINEL_BATCH_SIZE")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(10000)
}

fn resolve_tables(explicit: &[String]) -> Vec<String> {
    if !explicit.is_empty() { return explicit.to_vec(); }
    std::env::var("SENTINEL_TABLES")
        .ok()
        .map(|s| s.split(',').map(|t| t.trim().to_string()).filter(|t| !t.is_empty()).collect())
        .unwrap_or_else(default_tables)
}

/// Start real-time Sentinel streaming. Returns immediately with connector info.
#[tauri::command]
pub async fn cmd_sentinel_connect(
    state: State<'_, Arc<AppState>>,
    app: tauri::AppHandle,
    params: SentinelConnectParams,
) -> Result<SentinelConnectedEvent, CommandError> {
    // Check no connector is already running
    {
        let guard = state
            .sentinel_connector
            .read()
            .map_err(|e| CommandError::GraphLocked(format!("Lock poisoned: {}", e)))?;
        if guard.is_some() {
            return Err(CommandError::SentinelError("Sentinel connector is already running. Disconnect first.".into()));
        }
    }

    // Verify we have a current session
    let session_id = state
        .current_session_id
        .read()
        .map_err(|e| CommandError::GraphLocked(format!("Lock poisoned: {}", e)))?
        .clone()
        .ok_or_else(|| CommandError::SessionNotFound("No current session. Create or load a session first.".into()))?;

    let session = {
        let sessions = state
            .sessions
            .read()
            .map_err(|e| CommandError::GraphLocked(format!("Lock poisoned: {}", e)))?;
        Arc::clone(sessions.get(&session_id).ok_or_else(|| CommandError::SessionNotFound("Session not found".into()))?)
    };

    let connector_id = Uuid::new_v4().to_string();
    let dataset_id = format!("sentinel-live-{}", &connector_id[..8]);

    // Create dataset entry
    {
        let created_at = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|e| CommandError::Internal(e.to_string()))?
            .as_secs() as i64;
        let mut datasets = session
            .datasets
            .write()
            .map_err(|e| CommandError::GraphLocked(format!("Lock poisoned: {}", e)))?;
        datasets.push(crate::state::DatasetInfo {
            id: dataset_id.clone(),
            name: format!("Sentinel Live ({})", &connector_id[..8]),
            path: None,
            created_at,
            entity_count: 0,
            relation_count: 0,
        });
    }

    // Resolve params: explicit values override .env fallbacks
    let workspace_id = env_or(&params.workspace_id, "AZURE_WORKSPACE_ID")?;
    let tenant_id = env_or(&params.azure_tenant_id, "AZURE_TENANT_ID")?;
    let client_id = env_or(&params.azure_client_id, "AZURE_CLIENT_ID")?;
    let client_secret = env_or(&params.azure_client_secret, "AZURE_CLIENT_SECRET")?;
    let poll_interval = resolve_poll_interval(params.poll_interval_secs).max(5);
    let tables = resolve_tables(&params.tables);
    let batch_size = resolve_batch_size(params.batch_size).max(100);

    let config = SentinelPollingConfig {
        workspace_id,
        auth: SentinelAuth {
            tenant_id,
            client_id,
            client_secret,
        },
        poll_interval_secs: poll_interval,
        tables,
        batch_size,
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
            .map_err(|e| CommandError::GraphLocked(format!("Lock poisoned: {}", e)))?;
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
) -> Result<(), CommandError> {
    let handle = {
        let mut guard = state
            .sentinel_connector
            .write()
            .map_err(|e| CommandError::GraphLocked(format!("Lock poisoned: {}", e)))?;
        guard.take()
    };

    let handle = handle.ok_or_else(|| CommandError::SentinelError("No Sentinel connector is running.".into()))?;

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
        .map_err(|e| CommandError::GraphLocked(format!("Lock poisoned: {}", e)))?
        .clone();

    if let Some(id) = session_id {
        let sessions = state
            .sessions
            .read()
            .map_err(|e| CommandError::GraphLocked(format!("Lock poisoned: {}", e)))?;
        if let Some(session) = sessions.get(&id) {
            if let Ok(mut graph) = session.graph.write() {
                let _ = run_scoring_adaptive(&mut graph);
            }
        }
    }

    Ok(())
}

/// Get current Sentinel connector status.
#[tauri::command]
pub fn cmd_sentinel_status(
    state: State<Arc<AppState>>,
) -> Result<ConnectorStatusResponse, CommandError> {
    let guard = state
        .sentinel_connector
        .read()
        .map_err(|e| CommandError::GraphLocked(format!("Lock poisoned: {}", e)))?;

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

/// Check which Sentinel env vars are configured (for UI setup panel).
#[tauri::command]
pub fn cmd_sentinel_check_env() -> SentinelEnvStatus {
    SentinelEnvStatus {
        azure_client_id: std::env::var("AZURE_CLIENT_ID").is_ok(),
        azure_client_secret: std::env::var("AZURE_CLIENT_SECRET").is_ok(),
        azure_tenant_id: std::env::var("AZURE_TENANT_ID").is_ok(),
        azure_subscription_id: std::env::var("AZURE_SUBSCRIPTION_ID").is_ok(),
        azure_resource_group: std::env::var("AZURE_RESOURCE_GROUP").is_ok(),
        azure_workspace_id: std::env::var("AZURE_WORKSPACE_ID").is_ok(),
        azure_workspace_name: std::env::var("AZURE_WORKSPACE_NAME").ok(),
    }
}

#[derive(serde::Serialize)]
pub struct SentinelEnvStatus {
    pub azure_client_id: bool,
    pub azure_client_secret: bool,
    pub azure_tenant_id: bool,
    pub azure_subscription_id: bool,
    pub azure_resource_group: bool,
    pub azure_workspace_id: bool,
    pub azure_workspace_name: Option<String>,
}
