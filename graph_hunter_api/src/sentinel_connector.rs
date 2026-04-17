//! Real-time Sentinel polling connector.
//!
//! Manages a persistent background task that polls Microsoft Sentinel
//! at a configurable interval, ingests new events into the session
//! graph, and emits canonical API events for live UI updates.
//!
//! Moved from `app/src-tauri/src/sentinel_connector.rs`. The one
//! structural change: instead of taking a `tauri::AppHandle` and
//! calling `handle.emit(…)` directly, the loop takes a
//! `Arc<dyn EventEmitter>` and emits through the canonical channel.
//! Tauri wires up its `TauriEventEmitter` at startup, so analysts
//! still see `sentinel-data` / `sentinel-error` / `sentinel-disconnected` /
//! `kql-executed` events on the frontend.

use std::sync::Arc;
use std::time::Duration;

use graph_hunter_core::{LogParser, SentinelJsonParser};
use rand::Rng;
use tokio::sync::{watch, RwLock};
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;

use graph_hunter_cli::siem::{
    normalize_response, KqlQueryBuilder, SentinelPollingConfig, SentinelTokenCache,
    SentinelTransport, SentinelWatermarkStore,
};

use crate::events::events as event_names;
use crate::scoring::run_scoring_incremental;
use crate::state::Session;
use crate::EventEmitter;

/// Maximum exponential back-off (seconds) between retries after poll failures.
const MAX_BACKOFF_SECS: u64 = 300;

/// Consecutive authentication failures before the connector gives up.
const MAX_AUTH_FAILURES: u32 = 3;

/// Brief delay (seconds) before the first poll so frontend listeners are ready.
const FIRST_POLL_DELAY_SECS: u64 = 2;

// ── Connector status ──

/// Live status of the Sentinel connector, broadcast via watch channel.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
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

/// Handle to control a running connector from the canonical API /
/// Tauri commands. Tokio-agnostic: uses `tokio::task::JoinHandle`
/// (which `tauri::async_runtime` already wraps).
pub struct SentinelConnectorHandle {
    pub connector_id: String,
    pub cancel_token: CancellationToken,
    pub task_handle: JoinHandle<()>,
    pub status_rx: watch::Receiver<ConnectorStatus>,
}

// ── Event payloads ─────────────────────────────────────────────────────

#[derive(serde::Serialize)]
struct SentinelDataEvent {
    new_entities: usize,
    new_relations: usize,
    timestamp: i64,
}

#[derive(serde::Serialize)]
struct SentinelErrorEvent {
    error: String,
    consecutive_errors: u32,
    will_retry: bool,
}

#[derive(serde::Serialize)]
struct KqlQueryExecutedEvent {
    kql: String,
    source: String,
    target: String,
    row_count: usize,
    entities_created: usize,
    relations_created: usize,
}

// ── Polling loop ──────────────────────────────────────────────────────

/// The main polling loop. Runs as a spawned tokio task, emitting
/// progress events through the canonical [`EventEmitter`].
#[allow(clippy::too_many_arguments)]
pub async fn polling_loop<T: SentinelTransport>(
    config: SentinelPollingConfig,
    transport: Arc<T>,
    token_cache: Arc<SentinelTokenCache>,
    session: Arc<Session>,
    _session_id: String,
    emitter: Arc<dyn EventEmitter>,
    cancel: CancellationToken,
    status_tx: watch::Sender<ConnectorStatus>,
    dataset_id: String,
) {
    let watermarks: Arc<RwLock<SentinelWatermarkStore>> =
        Arc::new(RwLock::new(SentinelWatermarkStore::new()));

    let poll_duration = Duration::from_secs(config.poll_interval_secs.max(5));
    let parser = SentinelJsonParser;

    let mut consecutive_errors: u32 = 0;
    let mut first_poll = true;

    let _ = status_tx.send(ConnectorStatus::Connected {
        last_data_at: "starting".into(),
        total_entities: 0,
        total_relations: 0,
    });

    loop {
        if first_poll {
            first_poll = false;
            tokio::time::sleep(Duration::from_secs(FIRST_POLL_DELAY_SECS)).await;
        } else {
            tokio::select! {
                _ = cancel.cancelled() => {
                    let _ = status_tx.send(ConnectorStatus::Disconnected);
                    emitter.emit(event_names::SENTINEL_STATUS, serde_json::json!({"disconnected": true}));
                    break;
                }
                _ = tokio::time::sleep(poll_duration) => {}
            }

            if cancel.is_cancelled() {
                let _ = status_tx.send(ConnectorStatus::Disconnected);
                emitter.emit(event_names::SENTINEL_STATUS, serde_json::json!({"disconnected": true}));
                break;
            }
        }

        let _ = status_tx.send(ConnectorStatus::Polling);

        let token = match token_cache.get_or_refresh(transport.as_ref(), &config.auth).await {
            Ok(t) => t,
            Err(e) => {
                consecutive_errors += 1;
                let is_auth = e.contains("401") || e.contains("403") || e.contains("token");
                if is_auth {
                    token_cache.invalidate().await;
                    if consecutive_errors >= MAX_AUTH_FAILURES {
                        emit_error(
                            &emitter,
                            format!("Auth failed {consecutive_errors} times, stopping: {e}"),
                            consecutive_errors,
                            false,
                        );
                        let _ = status_tx.send(ConnectorStatus::Disconnected);
                        break;
                    }
                }
                emit_error(&emitter, e.clone(), consecutive_errors, true);
                let _ = status_tx.send(ConnectorStatus::Error {
                    message: e,
                    consecutive: consecutive_errors,
                });
                let base_backoff = (2u64.pow(consecutive_errors.min(8))).min(MAX_BACKOFF_SECS);
                let jittered = base_backoff as f64 * (0.5 + rand::thread_rng().r#gen::<f64>() * 0.5);
                tokio::time::sleep(Duration::from_secs_f64(jittered)).await;
                continue;
            }
        };

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
                Ok(raw) => match normalize_response(&raw) {
                    Ok(result) => {
                        if !result.data.is_empty() && result.data != "[]" {
                            let row_count = result.data.matches('{').count();
                            let triples = parser.parse(&result.data);
                            tracing::info!(
                                "SENTINEL: table {} -> {} rows, {} triples",
                                table,
                                row_count,
                                triples.len()
                            );
                            if triples.is_empty() {
                                emit_error(
                                    &emitter,
                                    format!(
                                        "Table {table}: received ~{row_count} rows but parser produced 0 triples (check that the table schema matches expected Sentinel fields)"
                                    ),
                                    0,
                                    true,
                                );
                            } else {
                                match session.graph.write() {
                                    Ok(mut graph) => {
                                        match graph.insert_triples(triples, Some(&dataset_id)) {
                                            Ok((ne, nr)) => {
                                                total_new_entities += ne;
                                                total_new_relations += nr;
                                                emitter.emit(
                                                    "kql-executed",
                                                    serde_json::to_value(KqlQueryExecutedEvent {
                                                        kql: kql.clone(),
                                                        source: "polling".into(),
                                                        target: table.clone(),
                                                        row_count,
                                                        entities_created: ne,
                                                        relations_created: nr,
                                                    })
                                                    .unwrap_or(serde_json::Value::Null),
                                                );
                                            }
                                            Err(e) => {
                                                emit_error(
                                                    &emitter,
                                                    format!("Spill store error: {e}"),
                                                    0,
                                                    true,
                                                );
                                            }
                                        }
                                    }
                                    Err(e) => {
                                        emit_error(
                                            &emitter,
                                            format!("Graph lock poisoned: {e}"),
                                            0,
                                            false,
                                        );
                                        let _ = status_tx.send(ConnectorStatus::Disconnected);
                                        return;
                                    }
                                }
                            }
                        } else {
                            tracing::debug!("SENTINEL: table {} -> 0 rows (empty)", table);
                        }
                        if let Some(next) = result.next_query_start {
                            let mut store = watermarks.write().await;
                            store.set(table, next);
                        }
                        consecutive_errors = 0;
                    }
                    Err(e) => {
                        tracing::error!("SENTINEL: table {} normalize error: {}", table, e);
                        consecutive_errors += 1;
                        emit_error(
                            &emitter,
                            format!("Table {table} normalize error: {e}"),
                            consecutive_errors,
                            true,
                        );
                    }
                },
                Err(e) => {
                    tracing::error!("SENTINEL: table {} query error: {}", table, e);
                    consecutive_errors += 1;
                    emit_error(
                        &emitter,
                        format!("Table {table} query error: {e}"),
                        consecutive_errors,
                        true,
                    );
                }
            }
        }

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        if total_new_entities > 0 || total_new_relations > 0 {
            if let Ok(mut graph) = session.graph.write() {
                run_scoring_incremental(&mut graph);
            }
            emitter.emit(
                event_names::SENTINEL_DATA,
                serde_json::to_value(SentinelDataEvent {
                    new_entities: total_new_entities,
                    new_relations: total_new_relations,
                    timestamp: now as i64,
                })
                .unwrap_or(serde_json::Value::Null),
            );
        }

        let (te, tr) = session
            .graph
            .read()
            .map(|g| (g.entity_count(), g.relation_count()))
            .unwrap_or((0, 0));

        let _ = status_tx.send(ConnectorStatus::Connected {
            last_data_at: format!("{now}"),
            total_entities: te,
            total_relations: tr,
        });
    }
}

fn emit_error(
    emitter: &Arc<dyn EventEmitter>,
    error: String,
    consecutive_errors: u32,
    will_retry: bool,
) {
    emitter.emit(
        "sentinel-error",
        serde_json::to_value(SentinelErrorEvent {
            error,
            consecutive_errors,
            will_retry,
        })
        .unwrap_or(serde_json::Value::Null),
    );
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
