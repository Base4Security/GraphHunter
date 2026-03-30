//! Real-time Sentinel polling connector.
//!
//! Manages a persistent background task that polls Microsoft Sentinel
//! at a configurable interval, ingests new events into the session graph,
//! and emits Tauri events for live UI updates.

use std::sync::Arc;
use std::time::Duration;

use graph_hunter_core::{LogParser, SentinelJsonParser};
use rand::Rng;
use tauri::Emitter;
use tokio::sync::{watch, RwLock};
use tokio_util::sync::CancellationToken;

use graph_hunter_cli::siem::{
    KqlQueryBuilder, SentinelPollingConfig, SentinelTokenCache, SentinelTransport,
    SentinelWatermarkStore, normalize_response,
};

use crate::scoring::run_scoring_incremental;
use crate::state::SessionState;
use crate::types::{SentinelDataEvent, SentinelErrorEvent};

// ── Connector status ──

/// Live status of the Sentinel connector, broadcast via watch channel.
#[derive(Clone, serde::Serialize)]
#[serde(tag = "state")]
pub enum ConnectorStatus {
    Connecting,
    Connected {
        last_data_at: String,
        total_entities: usize,
        total_relations: usize,
    },
    Polling,
    Error {
        message: String,
        consecutive: u32,
    },
    Disconnected,
}

/// Handle to control a running connector from Tauri commands.
pub struct SentinelConnectorHandle {
    pub connector_id: String,
    pub cancel_token: CancellationToken,
    pub task_handle: tauri::async_runtime::JoinHandle<()>,
    pub status_rx: watch::Receiver<ConnectorStatus>,
}

// ── Polling loop ──

/// The main polling loop. Runs as a spawned tokio task.
/// Queries each configured Sentinel table with per-table watermarks,
/// parses results, inserts into the graph, and emits events.
pub async fn polling_loop<T: SentinelTransport>(
    config: SentinelPollingConfig,
    transport: Arc<T>,
    token_cache: Arc<SentinelTokenCache>,
    session: Arc<SessionState>,
    _session_id: String,
    app_handle: tauri::AppHandle,
    cancel: CancellationToken,
    status_tx: watch::Sender<ConnectorStatus>,
    dataset_id: String,
) {
    let watermarks: Arc<RwLock<SentinelWatermarkStore>> =
        Arc::new(RwLock::new(SentinelWatermarkStore::new()));

    let poll_duration = Duration::from_secs(config.poll_interval_secs.max(5));
    let parser = SentinelJsonParser;

    let mut consecutive_errors: u32 = 0;
    let max_backoff_secs: u64 = 300;
    let max_auth_failures: u32 = 3;
    let mut first_poll = true;

    let _ = status_tx.send(ConnectorStatus::Connected {
        last_data_at: "starting".into(),
        total_entities: 0,
        total_relations: 0,
    });

    loop {
        // First poll: brief delay so frontend event listeners are ready.
        // Subsequent polls: wait for the full interval.
        if first_poll {
            first_poll = false;
            tokio::time::sleep(Duration::from_secs(2)).await;
        } else {
            tokio::select! {
                _ = cancel.cancelled() => {
                    let _ = status_tx.send(ConnectorStatus::Disconnected);
                    let _ = app_handle.emit("sentinel-disconnected", ());
                    break;
                }
                _ = tokio::time::sleep(poll_duration) => {}
            }

            if cancel.is_cancelled() {
                let _ = status_tx.send(ConnectorStatus::Disconnected);
                let _ = app_handle.emit("sentinel-disconnected", ());
                break;
            }
        }

        let _ = status_tx.send(ConnectorStatus::Polling);

        // Acquire token (cached or refresh)
        let token = match token_cache.get_or_refresh(transport.as_ref(), &config.auth).await {
            Ok(t) => t,
            Err(e) => {
                consecutive_errors += 1;
                let is_auth = e.contains("401") || e.contains("403") || e.contains("token");
                if is_auth {
                    token_cache.invalidate().await;
                    if consecutive_errors >= max_auth_failures {
                        let _ = app_handle.emit("sentinel-error", SentinelErrorEvent {
                            error: format!("Auth failed {} times, stopping: {}", consecutive_errors, e),
                            consecutive_errors,
                            will_retry: false,
                        });
                        let _ = status_tx.send(ConnectorStatus::Disconnected);
                        break;
                    }
                }
                let _ = app_handle.emit("sentinel-error", SentinelErrorEvent {
                    error: e.clone(),
                    consecutive_errors,
                    will_retry: true,
                });
                let _ = status_tx.send(ConnectorStatus::Error {
                    message: e,
                    consecutive: consecutive_errors,
                });
                // Exponential backoff with jitter to avoid thundering herd
                let base_backoff = (2u64.pow(consecutive_errors.min(8))).min(max_backoff_secs);
                let jittered = base_backoff as f64 * (0.5 + rand::thread_rng().gen::<f64>() * 0.5);
                tokio::time::sleep(Duration::from_secs_f64(jittered)).await;
                continue;
            }
        };

        // Query each table with its watermark
        let mut total_new_entities = 0usize;
        let mut total_new_relations = 0usize;

        for table in &config.tables {
            if cancel.is_cancelled() {
                break;
            }

            let watermark = {
                let store = watermarks.read().await;
                store.get(table).cloned()
            };
            let kql = KqlQueryBuilder::build(table, watermark.as_deref(), config.batch_size);

            tracing::info!("SENTINEL: querying table {}", table);
            match transport.execute_query(&config.workspace_id, &kql, &token).await {
                Ok(raw) => {
                    match normalize_response(&raw) {
                        Ok(result) => {
                            // Parse and insert if we got data
                            if !result.data.is_empty() && result.data != "[]" {
                                let row_count = result.data.matches('{').count();
                                let triples = parser.parse(&result.data);
                                tracing::info!("SENTINEL: table {} -> {} rows, {} triples", table, row_count, triples.len());
                                if triples.is_empty() {
                                    // Data received but parser produced no triples — tell the user
                                    let _ = app_handle.emit("sentinel-error", SentinelErrorEvent {
                                        error: format!(
                                            "Table {}: received ~{} rows but parser produced 0 triples (check that the table schema matches expected Sentinel fields)",
                                            table, row_count
                                        ),
                                        consecutive_errors: 0,
                                        will_retry: true,
                                    });
                                } else {
                                    match session.graph.write() {
                                        Ok(mut graph) => {
                                            match graph.insert_triples(
                                                triples,
                                                Some(&dataset_id),
                                            ) {
                                                Ok((ne, nr)) => {
                                                    total_new_entities += ne;
                                                    total_new_relations += nr;
                                                }
                                                Err(e) => {
                                                    let _ = app_handle.emit("sentinel-error", SentinelErrorEvent {
                                                        error: format!("Spill store error: {}", e),
                                                        consecutive_errors: 0,
                                                        will_retry: true,
                                                    });
                                                }
                                            }
                                        }
                                        Err(e) => {
                                            let _ = app_handle.emit("sentinel-error", SentinelErrorEvent {
                                                error: format!("Graph lock poisoned: {}", e),
                                                consecutive_errors: 0,
                                                will_retry: false,
                                            });
                                            let _ = status_tx.send(ConnectorStatus::Disconnected);
                                            return;
                                        }
                                    }
                                }
                            } else {
                                tracing::debug!("SENTINEL: table {} -> 0 rows (empty)", table);
                            }
                            // Advance watermark
                            if let Some(next) = result.next_query_start {
                                let mut store = watermarks.write().await;
                                store.set(table, next);
                            }
                            consecutive_errors = 0;
                        }
                        Err(e) => {
                            tracing::error!("SENTINEL: table {} normalize error: {}", table, e);
                            consecutive_errors += 1;
                            let _ = app_handle.emit("sentinel-error", SentinelErrorEvent {
                                error: format!("Table {} normalize error: {}", table, e),
                                consecutive_errors,
                                will_retry: true,
                            });
                        }
                    }
                }
                Err(e) => {
                    tracing::error!("SENTINEL: table {} query error: {}", table, e);
                    consecutive_errors += 1;
                    let _ = app_handle.emit("sentinel-error", SentinelErrorEvent {
                        error: format!("Table {} query error: {}", table, e),
                        consecutive_errors,
                        will_retry: true,
                    });
                }
            }
        }

        // Emit batch results and run incremental scoring
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        if total_new_entities > 0 || total_new_relations > 0 {
            if let Ok(mut graph) = session.graph.write() {
                run_scoring_incremental(&mut graph);
            }

            let _ = app_handle.emit("sentinel-data", SentinelDataEvent {
                new_entities: total_new_entities,
                new_relations: total_new_relations,
                timestamp: now as i64,
            });
        }

        // Always update status after a poll cycle so UI doesn't stay stuck on "Polling"
        let (te, tr) = session
            .graph
            .read()
            .map(|g| (g.entity_count(), g.relation_count()))
            .unwrap_or((0, 0));

        let _ = status_tx.send(ConnectorStatus::Connected {
            last_data_at: format!("{}", now),
            total_entities: te,
            total_relations: tr,
        });
    }
}

/// Default Sentinel table list for comprehensive monitoring.
pub fn default_tables() -> Vec<String> {
    vec![
        "SecurityEvent".into(),
        "SigninLogs".into(),
        "DeviceProcessEvents".into(),
        "DeviceNetworkEvents".into(),
        "DeviceFileEvents".into(),
        "CommonSecurityLog".into(),
    ]
}
