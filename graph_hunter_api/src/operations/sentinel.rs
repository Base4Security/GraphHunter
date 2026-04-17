//! Sentinel real-time connector commands: connect, disconnect, status,
//! env probe, and ad-hoc KQL. The polling loop itself lives in
//! `crate::sentinel_connector`; these operations manage its lifecycle.

use std::sync::Arc;
use std::time::Duration;

use graph_hunter_cli::siem::{
    run_sentinel_query, HttpSentinelTransport, SentinelAuth, SentinelPollingConfig,
    SentinelTokenCache,
};
use uuid::Uuid;

use crate::dto::sentinel::{
    ConnectorStatusResponse, KqlResult, RunKqlRequest, SentinelConnectRequest,
    SentinelConnectedEvent, SentinelEnvStatus,
};
use crate::events::events as event_names;
use crate::format_registry::make_parser_for_format;
use crate::scoring::{run_full_scoring, run_scoring_adaptive};
use crate::sentinel_connector::{default_tables, polling_loop, ConnectorStatus, SentinelConnectorHandle};
use crate::state::{DatasetInfo, SessionHandle};
use crate::util::now_secs;
use crate::{ApiError, ApiResult, GraphHunterApi};

// LogParser is pulled in transitively via `make_parser_for_format`,
// no direct import needed here.

fn env_or(explicit: &str, env_key: &str) -> ApiResult<String> {
    if !explicit.is_empty() {
        return Ok(explicit.to_string());
    }
    std::env::var(env_key).map_err(|_| {
        ApiError::InvalidInput(format!(
            "Missing '{env_key}': not provided and {env_key} not set in .env"
        ))
    })
}

fn resolve_poll_interval(explicit: u64) -> u64 {
    if explicit > 0 {
        return explicit;
    }
    std::env::var("SENTINEL_POLL_INTERVAL_SECS")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(30)
}

fn resolve_batch_size(explicit: u32) -> u32 {
    if explicit > 0 {
        return explicit;
    }
    std::env::var("SENTINEL_BATCH_SIZE")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(10000)
}

fn resolve_tables(explicit: &[String]) -> Vec<String> {
    if !explicit.is_empty() {
        return explicit.to_vec();
    }
    std::env::var("SENTINEL_TABLES")
        .ok()
        .map(|s| {
            s.split(',')
                .map(|t| t.trim().to_string())
                .filter(|t| !t.is_empty())
                .collect()
        })
        .unwrap_or_else(default_tables)
}

impl GraphHunterApi {
    /// Start the real-time Sentinel polling connector. Returns
    /// immediately with the connector metadata; the polling loop
    /// spawns as a background task and emits progress events through
    /// the canonical [`crate::EventEmitter`].
    pub async fn sentinel_connect(
        &self,
        req: SentinelConnectRequest,
        explicit_session: Option<SessionHandle>,
    ) -> ApiResult<SentinelConnectedEvent> {
        // Reject if a connector is already running.
        {
            let handle = self.sentinel_connector_handle();
            let guard = handle
                .read()
                .map_err(|e| ApiError::Internal(format!("sentinel lock poisoned: {e}")))?;
            if guard.is_some() {
                return Err(ApiError::InvalidState(
                    "Sentinel connector is already running. Disconnect first.".into(),
                ));
            }
        }

        let session = self.resolve_session(explicit_session.as_ref())?;
        let session_id = session.id.clone();

        let connector_id = Uuid::new_v4().to_string();
        let dataset_id = format!("sentinel-live-{}", &connector_id[..8]);

        // Add a dataset entry so the UI shows "Sentinel Live (xxxx)".
        {
            let mut datasets = session
                .datasets
                .write()
                .map_err(|e| ApiError::Internal(format!("datasets lock poisoned: {e}")))?;
            datasets.push(DatasetInfo {
                id: dataset_id.clone(),
                name: format!("Sentinel Live ({})", &connector_id[..8]),
                path: None,
                created_at: now_secs(),
                entity_count: 0,
                relation_count: 0,
            });
        }

        // Resolve creds + config: explicit params override .env fallbacks.
        let workspace_id = env_or(&req.workspace_id, "AZURE_WORKSPACE_ID")?;
        let tenant_id = env_or(&req.azure_tenant_id, "AZURE_TENANT_ID")?;
        let client_id = env_or(&req.azure_client_id, "AZURE_CLIENT_ID")?;
        let client_secret = env_or(&req.azure_client_secret, "AZURE_CLIENT_SECRET")?;
        let poll_interval = resolve_poll_interval(req.poll_interval_secs).max(5);
        let tables = resolve_tables(&req.tables);
        let batch_size = resolve_batch_size(req.batch_size).max(100);

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
        let (status_tx, status_rx) =
            tokio::sync::watch::channel(ConnectorStatus::Connecting);

        let event = SentinelConnectedEvent {
            connector_id: connector_id.clone(),
            tables: config.tables.clone(),
            poll_interval_secs: config.poll_interval_secs,
        };

        let task_cancel = cancel.clone();
        let emitter = self.emitter_arc();
        let session_for_task = session.clone();
        let task_handle = tokio::spawn(polling_loop(
            config,
            transport,
            token_cache,
            session_for_task,
            session_id,
            emitter.clone(),
            task_cancel,
            status_tx,
            dataset_id,
        ));

        // Register the handle.
        {
            let handle_slot = self.sentinel_connector_handle();
            let mut guard = handle_slot
                .write()
                .map_err(|e| ApiError::Internal(format!("sentinel lock poisoned: {e}")))?;
            *guard = Some(SentinelConnectorHandle {
                connector_id: connector_id.clone(),
                cancel_token: cancel,
                task_handle,
                status_rx,
            });
        }

        // Announce on the canonical event channel.
        self.emitter_arc().emit(
            "sentinel-connected",
            serde_json::to_value(&event).unwrap_or(serde_json::Value::Null),
        );
        Ok(event)
    }

    /// Disconnect the active connector. Cancels the polling task with
    /// a 10s grace period, then runs full adaptive scoring over the
    /// accumulated graph so the "end of run" analytics are correct.
    pub async fn sentinel_disconnect(&self) -> ApiResult<()> {
        let handle = {
            let handle_slot = self.sentinel_connector_handle();
            let mut guard = handle_slot
                .write()
                .map_err(|e| ApiError::Internal(format!("sentinel lock poisoned: {e}")))?;
            guard.take()
        }
        .ok_or_else(|| ApiError::InvalidState("No Sentinel connector is running.".into()))?;

        handle.cancel_token.cancel();
        let _ = tokio::time::timeout(Duration::from_secs(10), handle.task_handle).await;

        // Final scoring pass.
        if let Some(session) = self.sessions().current_session() {
            if let Ok(mut graph) = session.graph.write() {
                let _ = run_scoring_adaptive(&mut graph);
            }
        }
        // Emit status so the UI updates promptly.
        self.emitter_arc().emit(
            event_names::SENTINEL_STATUS,
            serde_json::json!({"disconnected": true}),
        );
        Ok(())
    }

    /// Return the current connector status (or disconnected when no
    /// handle exists).
    pub fn sentinel_status(&self) -> ApiResult<ConnectorStatusResponse> {
        let handle_slot = self.sentinel_connector_handle();
        let guard = handle_slot
            .read()
            .map_err(|e| ApiError::Internal(format!("sentinel lock poisoned: {e}")))?;
        Ok(match guard.as_ref() {
            Some(h) => ConnectorStatusResponse {
                connected: true,
                connector_id: Some(h.connector_id.clone()),
                status: Some(h.status_rx.borrow().clone()),
            },
            None => ConnectorStatusResponse {
                connected: false,
                connector_id: None,
                status: None,
            },
        })
    }

    /// Check which Sentinel-related env vars are configured. Returns
    /// actual values for non-secret fields and a masked hint for the
    /// client secret so the UI form can auto-populate.
    pub fn sentinel_check_env(&self) -> SentinelEnvStatus {
        let secret = std::env::var("AZURE_CLIENT_SECRET").ok();
        SentinelEnvStatus {
            azure_client_id: std::env::var("AZURE_CLIENT_ID").ok(),
            azure_client_secret_set: secret.is_some(),
            azure_client_secret_masked: secret.map(|s| {
                if s.len() > 6 {
                    format!("{}...{}", &s[..3], &s[s.len() - 3..])
                } else {
                    "***".into()
                }
            }),
            azure_tenant_id: std::env::var("AZURE_TENANT_ID").ok(),
            azure_subscription_id: std::env::var("AZURE_SUBSCRIPTION_ID").ok(),
            azure_resource_group: std::env::var("AZURE_RESOURCE_GROUP").ok(),
            azure_workspace_id: std::env::var("AZURE_WORKSPACE_ID").ok(),
            azure_workspace_name: std::env::var("AZURE_WORKSPACE_NAME").ok(),
        }
    }

    /// Run an ad-hoc KQL query against Log Analytics, ingest the
    /// resulting triples into the current session's graph, and return
    /// the executed KQL so the analyst can replicate it in the Azure
    /// portal.
    pub async fn run_kql(&self, req: RunKqlRequest) -> ApiResult<KqlResult> {
        let kql = req.kql.trim().to_string();
        if kql.is_empty() {
            return Err(ApiError::InvalidInput("KQL query cannot be empty".into()));
        }

        let workspace_id = env_or(&req.workspace_id, "AZURE_WORKSPACE_ID")?;
        let tenant_id = env_or(&req.azure_tenant_id, "AZURE_TENANT_ID")?;
        let client_id = env_or(&req.azure_client_id, "AZURE_CLIENT_ID")?;
        let client_secret = env_or(&req.azure_client_secret, "AZURE_CLIENT_SECRET")?;

        let auth = SentinelAuth {
            tenant_id,
            client_id,
            client_secret,
        };
        let kql_clone = kql.clone();
        let ws_clone = workspace_id.clone();
        let res = tokio::task::spawn_blocking(move || {
            run_sentinel_query(&ws_clone, &kql_clone, Some(auth))
        })
        .await
        .map_err(|e| ApiError::Internal(format!("task join error: {e}")))?
        .map_err(|e| ApiError::Upstream {
            service: "sentinel-kql".into(),
            message: e,
        })?;

        let row_count = res.data.matches('{').count();

        let session = self.sessions().current_session().ok_or_else(|| {
            ApiError::InvalidState("No current session. Create or load a session first.".into())
        })?;

        // Register a dataset for audit.
        let dataset_id = Uuid::new_v4().to_string();
        {
            let mut datasets = session
                .datasets
                .write()
                .map_err(|e| ApiError::Internal(format!("datasets lock poisoned: {e}")))?;
            datasets.push(DatasetInfo {
                id: dataset_id.clone(),
                name: format!(
                    "KQL: {}",
                    if kql.len() > 40 { &kql[..40] } else { &kql }
                ),
                path: None,
                created_at: now_secs(),
                entity_count: 0,
                relation_count: 0,
            });
        }

        // Parse + ingest + score.
        let (new_entities, new_relations) = {
            let mut graph = session
                .graph
                .write()
                .map_err(|e| ApiError::Internal(format!("graph lock poisoned: {e}")))?;
            let parser = make_parser_for_format("sentinel")
                .map_err(ApiError::InvalidInput)?;
            let triples = parser.parse(&res.data);
            let (e, r) = graph
                .insert_triples(triples, Some(dataset_id.as_str()))
                .map_err(|e| ApiError::Internal(e.to_string()))?;
            run_full_scoring(&mut graph);
            (e, r)
        };

        // Patch dataset counts.
        {
            let mut datasets = session
                .datasets
                .write()
                .map_err(|e| ApiError::Internal(format!("datasets lock poisoned: {e}")))?;
            if let Some(last) = datasets.last_mut() {
                last.entity_count = new_entities;
                last.relation_count = new_relations;
            }
        }

        let (total_entities, total_relations) = {
            let graph = session
                .graph
                .read()
                .map_err(|e| ApiError::Internal(format!("graph lock poisoned: {e}")))?;
            (graph.entity_count(), graph.relation_count())
        };

        // Emit audit event.
        self.emitter_arc().emit(
            "kql-executed",
            serde_json::json!({
                "kql": kql,
                "source": "adhoc",
                "target": "custom",
                "row_count": row_count,
                "entities_created": new_entities,
                "relations_created": new_relations,
            }),
        );

        Ok(KqlResult {
            new_entities,
            new_relations,
            total_entities,
            total_relations,
            kql_executed: kql,
            row_count,
        })
    }
}
