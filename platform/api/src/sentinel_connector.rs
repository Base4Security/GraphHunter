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
use tokio::sync::{RwLock, watch};
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;

use graph_hunter_siem::{
    KqlQueryBuilder, SentinelPollingConfig, SentinelTokenCache, SentinelTransport,
    SentinelWatermarkStore, normalize_response,
};

use crate::EventEmitter;
use crate::events::events as event_names;
use crate::scoring::run_scoring_incremental;
use crate::state::Session;

/// Maximum exponential back-off (seconds) between retries after poll failures.
const MAX_BACKOFF_SECS: u64 = 300;

/// Consecutive authentication failures before the connector gives up.
const MAX_AUTH_FAILURES: u32 = 3;

/// Brief delay (seconds) before the first poll so frontend listeners are ready.
const FIRST_POLL_DELAY_SECS: u64 = 2;

/// Backstop against a pathological non-advancing cursor: caps how many
/// times a single table can be drained within one poll.
const MAX_DRAIN_ITERS: u32 = 100;

/// Consecutive-failure threshold before a table's per-source `SourceCoverage`
/// breaker opens (a reporting signal only — see
/// `coverage::record_siem_outcome`'s doc comment). Mirrors
/// `operations::ingestion::SIEM_BREAKER_MAX_FAILURES` (same value, same
/// semantics); kept as its own module-local constant here rather than
/// importing that one because it's private to `ingestion.rs`.
const COVERAGE_MAX_FAILURES: u32 = 5;

/// `SourceCoverage` source-id scheme for the connector: `sentinel:<table>`.
/// Each Sentinel table is tracked as an independent source so one table
/// going blind (auth/table/transport error) marks only that table missing
/// on `missing_sources` — a healthy table polling fine alongside it must
/// not be dragged down. Must stay consistent between the success and
/// failure recording call sites below.
fn coverage_source_id(table: &str) -> String {
    format!("sentinel:{table}")
}

// ── Whole-phase fix wave: drain-iteration outcome + tie-aware cut ──
//
// Pure / synchronous helpers so the exact "no silent loss + honest
// coverage" rules (review fix wave, Fixes 1/2/3/4) are unit-testable
// without spinning up the async polling loop, a mock transport, or the
// graph engine.

/// What one drain iteration (one query + optional insert) should do to
/// the table's watermark and per-source coverage, given how it went.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DrainOutcome {
    /// Fix 1: `insert_triples` returned `Err` — the batch was NOT
    /// durably ingested. The watermark must NOT advance (so the batch is
    /// retried next poll, not silently skipped forever), the drain for
    /// this table must stop, and coverage must record a FAILURE.
    InsertBlocked,
    /// Fix 3: the batch had rows but the parser produced zero triples
    /// (schema mismatch). Advancing the watermark past unparseable rows
    /// is fine (don't wedge forever on a row that will never parse), but
    /// the table contributed nothing to the graph, so coverage must
    /// record a FAILURE/missing rather than success.
    ZeroTriples,
    /// Rows were ingested (or the batch was a clean empty read) and the
    /// table is now caught up (partial or empty batch): advance the
    /// watermark and record coverage SUCCESS.
    CaughtUp,
    /// Rows were ingested and the watermark may advance, but the batch
    /// was FULL — backlog remains. Fix 4: this iteration must NOT claim
    /// "covered to now"; the drain loop continues to the next batch.
    StillDraining,
}

/// Decides the [`DrainOutcome`] for one drain iteration. `row_count` is
/// the batch's raw row count (0 for an empty read); `batch_size` is the
/// table's configured page size.
fn drain_outcome(
    insert_failed: bool,
    zero_triples: bool,
    row_count: usize,
    batch_size: usize,
) -> DrainOutcome {
    if insert_failed {
        return DrainOutcome::InsertBlocked;
    }
    if zero_triples {
        return DrainOutcome::ZeroTriples;
    }
    if row_count == 0 || row_count < batch_size {
        DrainOutcome::CaughtUp
    } else {
        DrainOutcome::StillDraining
    }
}

/// Fix 2: tie-aware cut for a FULL batch (`row_count == batch_size`).
///
/// A strict `_ingest_ts > watermark` + `take N` cursor risks splitting
/// rows that share the exact max `_ingest_ts` tick across the `take N`
/// boundary: whichever share falls past the cut is lost forever, because
/// advancing the watermark to that tick makes the next `> wm` query skip
/// it. Bulk ingestion routinely shares one `ingestion_time` tick, and
/// full batches are exactly when this matters (drain/backfill).
///
/// `rows` are the batch's decoded row objects (in the KQL's `order by
/// _ingest_ts asc` order); `batch_max_tick` is the batch's max
/// `_ingest_ts` (`SentinelQueryResult::next_query_start`). Returns
/// `(kept_rows, new_watermark, all_same_tick)`:
///   - `kept_rows`: rows to actually ingest this round — rows strictly
///     below `batch_max_tick`, or, in the pathological all-one-tick case,
///     every row in the batch (see below).
///   - `new_watermark`: the watermark to advance to — the max
///     `_ingest_ts` among `kept_rows`, so the excluded max-tick rows are
///     re-fetched (and ingested exactly once) by the next `> wm` query.
///   - `all_same_tick`: true when every row in the batch shares
///     `batch_max_tick`, so excluding them would empty the batch
///     entirely (a single ingestion tick alone exceeds `batch_size`).
///     The caller falls back to ingesting all + advancing to that tick,
///     and should warn the operator to raise `batch_size` for this table.
fn tie_aware_cut(
    rows: Vec<serde_json::Map<String, serde_json::Value>>,
    batch_max_tick: &str,
) -> (
    Vec<serde_json::Map<String, serde_json::Value>>,
    String,
    bool,
) {
    let (kept, excluded): (Vec<_>, Vec<_>) = rows.into_iter().partition(|r| {
        r.get("_ingest_ts")
            .and_then(|v| v.as_str())
            // A row missing `_ingest_ts` shouldn't happen (the polling
            // KQL always projects it) — keep it defensively rather than
            // silently drop it.
            .map(|s| s < batch_max_tick)
            .unwrap_or(true)
    });
    if kept.is_empty() {
        // Every row shares the max tick: can't exclude without emptying
        // the batch. Accept the batch as-is and advance to the tick.
        (excluded, batch_max_tick.to_string(), true)
    } else {
        let kept_max = kept
            .iter()
            .filter_map(|r| r.get("_ingest_ts").and_then(|v| v.as_str()))
            .max()
            .unwrap_or(batch_max_tick)
            .to_string();
        (kept, kept_max, false)
    }
}

/// Best-effort ISO-8601 tick -> epoch seconds, for timestamping a
/// coverage recording (Fix 4: `record_covered` wants the batch's own max
/// `_ingest_ts` when caught up, not just "now"). Falls back to wall-clock
/// `now` when there's no tick to derive from (an empty, already-caught-up
/// batch) or it fails to parse — `record_covered`'s marker only needs to
/// advance, so an approximate fallback is acceptable.
fn ts_or_now(tick: Option<&str>) -> i64 {
    tick.and_then(|s| chrono::DateTime::parse_from_rfc3339(s).ok())
        .map(|dt| dt.timestamp())
        .unwrap_or_else(crate::util::now_secs)
}

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
    Paused,
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
    pub pause_tx: watch::Sender<bool>,
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
    mut pause_rx: watch::Receiver<bool>,
) {
    let watermarks: Arc<RwLock<SentinelWatermarkStore>> =
        Arc::new(RwLock::new(SentinelWatermarkStore::new()));

    let poll_duration = Duration::from_secs(config.poll_interval_secs.max(5));
    let parser = SentinelJsonParser;

    let mut consecutive_errors: u32 = 0;
    let mut first_poll = true;

    loop {
        // Wait while paused: no token, no query, no ingest.
        let mut announced_paused = false;
        while *pause_rx.borrow() {
            if !announced_paused {
                let _ = status_tx.send(ConnectorStatus::Paused);
                announced_paused = true;
            }
            tokio::select! {
                _ = cancel.cancelled() => {
                    let _ = status_tx.send(ConnectorStatus::Disconnected);
                    emitter.emit(event_names::SENTINEL_STATUS, serde_json::json!({"disconnected": true}));
                    return;
                }
                result = pause_rx.changed() => {
                    if result.is_err() {
                        let _ = status_tx.send(ConnectorStatus::Disconnected);
                        emitter.emit(event_names::SENTINEL_STATUS, serde_json::json!({"disconnected": true}));
                        return;
                    }
                }
            }
        }
        // ── existing first_poll / interval-sleep logic stays here, unchanged ──
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
                emitter.emit(
                    event_names::SENTINEL_STATUS,
                    serde_json::json!({"disconnected": true}),
                );
                break;
            }
        }

        let _ = status_tx.send(ConnectorStatus::Polling);

        let token = match token_cache
            .get_or_refresh(transport.as_ref(), &config.auth)
            .await
        {
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
                let jittered =
                    base_backoff as f64 * (0.5 + rand::thread_rng().r#gen::<f64>() * 0.5);
                tokio::time::sleep(Duration::from_secs_f64(jittered)).await;
                continue;
            }
        };

        let mut total_new_entities = 0usize;
        let mut total_new_relations = 0usize;

        // GRAPHHUNTER_SOURCE_COVERAGE gate: checked once per poll (not once
        // per table/row) so the flag-off path stays a single cheap env read
        // per poll iteration and touches `source_coverage` zero times.
        let coverage_on = crate::coverage::source_coverage_enabled();

        for table in &config.tables {
            if cancel.is_cancelled() {
                break;
            }

            // Drain this table's backlog within the current poll: keep
            // pulling+ingesting batches until caught up (a partial or
            // empty batch), the cursor stops advancing (guards against
            // an infinite loop), or the iteration backstop is hit.
            // Cancel-checked per iteration; the graph write lock is
            // acquired per-batch, never held across iterations.
            let mut drained = 0u32;
            loop {
                // Fix 5: honor a pause requested mid-drain, same predicate
                // the outer loop checks at the top of every poll — without
                // this, a long backlog drain could run for many iterations
                // (up to MAX_DRAIN_ITERS) after the operator paused.
                if cancel.is_cancelled() || *pause_rx.borrow() {
                    break;
                }
                let watermark = {
                    let store = watermarks.read().await;
                    store.get(table).cloned()
                };
                let kql = KqlQueryBuilder::build(
                    table,
                    watermark.as_deref(),
                    config.batch_size,
                    config.initial_time_window_filter.as_deref(),
                );

                tracing::info!("SENTINEL: querying table {}", table);
                let row_count;
                let mut advanced = false;
                match transport
                    .execute_query(&config.workspace_id, &kql, &token)
                    .await
                {
                    Ok(raw) => match normalize_response(&raw) {
                        Ok(result) => {
                            let mut insert_failed = false;
                            let mut zero_triples = false;
                            // Effective watermark to advance to for this
                            // iteration. `None` for an empty batch (nothing
                            // to advance past). Otherwise either the
                            // batch's own max tick, or — Fix 2, full batch
                            // with a tie at the max tick — the max tick
                            // among only the rows actually kept/ingested.
                            let mut effective_next: Option<String> = None;

                            if !result.data.is_empty() && result.data != "[]" {
                                row_count = result.data.matches('{').count();
                                let is_full_batch = row_count == config.batch_size as usize;
                                let mut data_to_parse = result.data.clone();

                                if is_full_batch {
                                    if let Some(batch_max) = result.next_query_start.as_deref() {
                                        match serde_json::from_str::<
                                            Vec<serde_json::Map<String, serde_json::Value>>,
                                        >(&result.data)
                                        {
                                            Ok(rows) => {
                                                let (kept, new_wm, all_same_tick) =
                                                    tie_aware_cut(rows, batch_max);
                                                if all_same_tick {
                                                    emit_error(
                                                        &emitter,
                                                        format!(
                                                            "Table {table}: a single ingestion tick has >= {} rows (batch_size); raise batch_size for this table to avoid repeatedly re-reading a full tick",
                                                            config.batch_size
                                                        ),
                                                        0,
                                                        true,
                                                    );
                                                }
                                                if let Ok(kept_json) = serde_json::to_string(&kept)
                                                {
                                                    data_to_parse = kept_json;
                                                }
                                                effective_next = Some(new_wm);
                                            }
                                            Err(_) => {
                                                // Couldn't decode rows for the
                                                // tie check: fall back to the
                                                // pre-Fix-2 behavior (ingest
                                                // all, advance to batch max)
                                                // rather than lose the batch.
                                                effective_next = result.next_query_start.clone();
                                            }
                                        }
                                    } else {
                                        effective_next = result.next_query_start.clone();
                                    }
                                } else {
                                    // Partial batch (caught up): no tie
                                    // risk — no more rows at any tick <=
                                    // max, so ingest all + advance to max.
                                    effective_next = result.next_query_start.clone();
                                }

                                let triples = parser.parse(&data_to_parse);
                                tracing::info!(
                                    "SENTINEL: table {} -> {} rows, {} triples",
                                    table,
                                    row_count,
                                    triples.len()
                                );
                                if triples.is_empty() {
                                    zero_triples = true;
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
                                                        serde_json::to_value(
                                                            KqlQueryExecutedEvent {
                                                                kql: kql.clone(),
                                                                source: "polling".into(),
                                                                target: table.clone(),
                                                                row_count,
                                                                entities_created: ne,
                                                                relations_created: nr,
                                                            },
                                                        )
                                                        .unwrap_or(serde_json::Value::Null),
                                                    );
                                                }
                                                Err(e) => {
                                                    // Fix 1: an insert failure means this
                                                    // batch was NOT durably ingested. Do
                                                    // NOT treat it like a clean success
                                                    // below — `insert_failed` routes this
                                                    // through `DrainOutcome::InsertBlocked`,
                                                    // which skips the watermark advance
                                                    // entirely and records coverage as
                                                    // missing instead of covered.
                                                    insert_failed = true;
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
                                row_count = 0;
                                tracing::debug!("SENTINEL: table {} -> 0 rows (empty)", table);
                            }

                            let outcome = drain_outcome(
                                insert_failed,
                                zero_triples,
                                row_count,
                                config.batch_size as usize,
                            );

                            if matches!(outcome, DrainOutcome::InsertBlocked) {
                                // Fix 1: do not advance the watermark (so this
                                // batch is retried, not skipped forever),
                                // stop draining this table this poll, and
                                // record coverage as missing.
                                consecutive_errors += 1;
                                if coverage_on && let Ok(mut sc) = session.source_coverage.write() {
                                    crate::coverage::record_siem_outcome(
                                        &mut sc,
                                        &coverage_source_id(table),
                                        false,
                                        crate::util::now_secs(),
                                        COVERAGE_MAX_FAILURES,
                                    );
                                }
                                break;
                            }

                            if let Some(next) = effective_next.clone() {
                                let mut store = watermarks.write().await;
                                let prev = store.get(table).cloned();
                                if prev.as_deref() != Some(next.as_str()) {
                                    store.set(table, next);
                                    advanced = true;
                                }
                            }
                            consecutive_errors = 0;

                            if coverage_on {
                                match outcome {
                                    DrainOutcome::ZeroTriples => {
                                        // Fix 3: the watermark advanced above
                                        // (unparseable rows shouldn't wedge
                                        // the cursor forever), but this table
                                        // contributed nothing to the graph —
                                        // report it missing, not covered.
                                        if let Ok(mut sc) = session.source_coverage.write() {
                                            crate::coverage::record_siem_outcome(
                                                &mut sc,
                                                &coverage_source_id(table),
                                                false,
                                                crate::util::now_secs(),
                                                COVERAGE_MAX_FAILURES,
                                            );
                                        }
                                    }
                                    DrainOutcome::CaughtUp => {
                                        // Fix 4: only claim "covered" once
                                        // this table is actually caught up
                                        // (partial/empty batch), timestamped
                                        // from the batch's own max tick when
                                        // available (else now).
                                        if let Ok(mut sc) = session.source_coverage.write() {
                                            crate::coverage::record_siem_outcome(
                                                &mut sc,
                                                &coverage_source_id(table),
                                                true,
                                                ts_or_now(effective_next.as_deref()),
                                                COVERAGE_MAX_FAILURES,
                                            );
                                        }
                                    }
                                    DrainOutcome::StillDraining => {
                                        // Fix 4: backlog remains (full batch)
                                        // — do NOT claim "covered to now"
                                        // mid-drain.
                                    }
                                    DrainOutcome::InsertBlocked => {
                                        unreachable!("handled above; already broke the drain loop")
                                    }
                                }
                            }
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
                            if coverage_on && let Ok(mut sc) = session.source_coverage.write() {
                                crate::coverage::record_siem_outcome(
                                    &mut sc,
                                    &coverage_source_id(table),
                                    false,
                                    crate::util::now_secs(),
                                    COVERAGE_MAX_FAILURES,
                                );
                            }
                            // Don't spin on a broken response for this table.
                            break;
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
                        if coverage_on && let Ok(mut sc) = session.source_coverage.write() {
                            crate::coverage::record_siem_outcome(
                                &mut sc,
                                &coverage_source_id(table),
                                false,
                                crate::util::now_secs(),
                                COVERAGE_MAX_FAILURES,
                            );
                        }
                        // Don't spin on a broken transport for this table.
                        break;
                    }
                }

                drained += 1;
                // Stop draining this table when: caught up (partial
                // batch), empty, the cursor didn't advance (guards
                // infinite loop), or the backstop is hit.
                if row_count < config.batch_size as usize
                    || row_count == 0
                    || !advanced
                    || drained >= MAX_DRAIN_ITERS
                {
                    break;
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
            // Bump the live dataset's counters so the UI's
            // `DatasetCard` reflects what's actually been ingested
            // — without this it sat at "0 entities, 0 relations"
            // even while the graph kept growing under the hood.
            // Bookkeeping is per-dataset_id, NOT total graph counts:
            // a session may have other datasets we mustn't double-
            // count.
            if let Ok(mut datasets) = session.datasets.write()
                && let Some(ds) = datasets.iter_mut().find(|d| d.id == dataset_id)
            {
                ds.entity_count = ds.entity_count.saturating_add(total_new_entities);
                ds.relation_count = ds.relation_count.saturating_add(total_new_relations);
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

#[cfg(test)]
// Tests hold the process-wide `ENV_LOCK` (std Mutex, via `lock_env()`) across
// awaits on purpose: it serializes env-var mutation for the whole test body.
// `#[tokio::test]` runs on a current-thread runtime, so nothing else
// contends for it there.
#[allow(clippy::await_holding_lock)]
mod pause_tests {
    use super::*;
    use crate::dto::session::CreateSessionRequest;
    use crate::{GraphHunterApi, NoopEmitter};
    use graph_hunter_siem::{SentinelAuth, SentinelTransport, TokenResponse};
    use std::sync::atomic::{AtomicUsize, Ordering};

    struct CountingTransport {
        queries: AtomicUsize,
    }

    impl SentinelTransport for CountingTransport {
        async fn acquire_token(
            &self,
            _t: &str,
            _c: &str,
            _s: &str,
        ) -> Result<TokenResponse, String> {
            Ok(TokenResponse {
                access_token: "tok".into(),
                expires_in: 3600,
            })
        }

        async fn execute_query(
            &self,
            _ws: &str,
            _q: &str,
            _b: &str,
        ) -> Result<serde_json::Value, String> {
            self.queries.fetch_add(1, Ordering::SeqCst);
            Ok(serde_json::json!({ "tables": [] }))
        }
    }

    fn test_config() -> SentinelPollingConfig {
        SentinelPollingConfig {
            workspace_id: "ws".into(),
            auth: SentinelAuth {
                tenant_id: "t".into(),
                client_id: "c".into(),
                client_secret: "s".into(),
            },
            poll_interval_secs: 5,
            tables: vec!["SigninLogs".into()],
            batch_size: 100,
            initial_time_window_filter: None,
        }
    }

    #[tokio::test(start_paused = true)]
    async fn paused_loop_issues_no_queries_until_resumed() {
        let api = GraphHunterApi::new_noop();
        api.create_session(CreateSessionRequest {
            name: Some("pause-test".into()),
        })
        .expect("session");
        let session = api.sessions().current_session().expect("session");

        let transport = Arc::new(CountingTransport {
            queries: AtomicUsize::new(0),
        });
        let cache = Arc::new(SentinelTokenCache::new());
        let cancel = tokio_util::sync::CancellationToken::new();
        let (status_tx, status_rx) = tokio::sync::watch::channel(ConnectorStatus::Paused);
        let (pause_tx, pause_rx) = tokio::sync::watch::channel(true);

        let loop_handle = tokio::spawn(polling_loop(
            test_config(),
            transport.clone(),
            cache,
            session,
            "sid".into(),
            Arc::new(NoopEmitter) as Arc<dyn EventEmitter>,
            cancel.clone(),
            status_tx,
            "ds".into(),
            pause_rx,
        ));

        tokio::time::sleep(std::time::Duration::from_secs(30)).await;
        assert_eq!(
            transport.queries.load(Ordering::SeqCst),
            0,
            "paused loop must not query"
        );
        assert!(
            matches!(*status_rx.borrow(), ConnectorStatus::Paused),
            "status must be Paused while paused"
        );

        pause_tx.send(false).unwrap();
        // Bounded poll: wait up to 50s for the first query to arrive.
        for _ in 0..50 {
            tokio::time::sleep(std::time::Duration::from_secs(1)).await;
            if transport.queries.load(Ordering::SeqCst) >= 1 {
                break;
            }
        }
        assert!(
            transport.queries.load(Ordering::SeqCst) >= 1,
            "resumed loop must query"
        );

        pause_tx.send(true).unwrap();
        // Drain: allow the loop to finish any in-flight iteration, then
        // snapshot the count. The loop's poll_interval is 5s so one full
        // cycle plus a little slack is enough.
        tokio::time::sleep(std::time::Duration::from_secs(10)).await;
        let after_pause = transport.queries.load(Ordering::SeqCst);
        // Now 60 more seconds must pass without any new query.
        tokio::time::sleep(std::time::Duration::from_secs(60)).await;
        assert_eq!(
            transport.queries.load(Ordering::SeqCst),
            after_pause,
            "paused again -> no new queries"
        );

        cancel.cancel();
        let _ = loop_handle.await;
    }

    // ── Drain test ──
    //
    // Mock transport that scripts a fixed row count per call (in order)
    // and records every KQL string it receives. Proves the connector
    // drains a table's backlog within a single poll: it must issue one
    // query per drain iteration until a batch returns fewer rows than
    // `batch_size` (caught up), not stop after the first batch.
    struct DrainMockTransport {
        /// Row counts to return, indexed by call order (0-based).
        row_counts: Vec<usize>,
        /// Running offset into the synthetic user/IP id space, so every
        /// row across every call gets a distinct entity pair.
        rows_emitted: AtomicUsize,
        call_count: AtomicUsize,
        queries_seen: std::sync::Mutex<Vec<String>>,
    }

    impl DrainMockTransport {
        fn new(row_counts: Vec<usize>) -> Self {
            Self {
                row_counts,
                rows_emitted: AtomicUsize::new(0),
                call_count: AtomicUsize::new(0),
                queries_seen: std::sync::Mutex::new(Vec::new()),
            }
        }
    }

    /// Builds a synthetic Log Analytics response for `count` SigninLogs
    /// rows starting at global row index `start_idx`. Each row gets a
    /// unique `UserPrincipalName`/`IPAddress` pair (so ingestion counts
    /// are checkable) and a strictly increasing `_ingest_ts` (so the
    /// watermark advances every call and the next KQL differs).
    fn build_signin_rows(start_idx: usize, count: usize) -> serde_json::Value {
        let rows: Vec<serde_json::Value> = (0..count)
            .map(|i| {
                let idx = start_idx + i;
                serde_json::json!([
                    "SigninLogs",
                    "2024-01-15T10:00:00Z",
                    format!("2024-01-15T00:00:00.{:07}Z", idx),
                    format!("user{idx}@contoso.com"),
                    format!("10.0.{}.{}", idx / 256, idx % 256)
                ])
            })
            .collect();
        serde_json::json!({
            "tables": [{
                "name": "PrimaryResult",
                "columns": [
                    {"name": "Type", "type": "string"},
                    {"name": "TimeGenerated", "type": "datetime"},
                    {"name": "_ingest_ts", "type": "datetime"},
                    {"name": "UserPrincipalName", "type": "string"},
                    {"name": "IPAddress", "type": "string"}
                ],
                "rows": rows
            }]
        })
    }

    impl SentinelTransport for DrainMockTransport {
        async fn acquire_token(
            &self,
            _t: &str,
            _c: &str,
            _s: &str,
        ) -> Result<TokenResponse, String> {
            Ok(TokenResponse {
                access_token: "tok".into(),
                expires_in: 3600,
            })
        }

        async fn execute_query(
            &self,
            _ws: &str,
            q: &str,
            _b: &str,
        ) -> Result<serde_json::Value, String> {
            let idx = self.call_count.fetch_add(1, Ordering::SeqCst);
            self.queries_seen.lock().unwrap().push(q.to_string());
            let count = self.row_counts.get(idx).copied().unwrap_or(0);
            let start = self.rows_emitted.fetch_add(count, Ordering::SeqCst);
            Ok(build_signin_rows(start, count))
        }
    }

    #[tokio::test]
    async fn drain_within_one_poll_issues_multiple_queries_until_caught_up() {
        let api = GraphHunterApi::new_noop();
        api.create_session(CreateSessionRequest {
            name: Some("drain-test".into()),
        })
        .expect("session");
        let session = api.sessions().current_session().expect("session");

        // batch_size (100) rows on calls 1-2 (still behind), fewer on
        // call 3 (10, caught up) -> drain must stop after exactly 3 calls.
        let transport = Arc::new(DrainMockTransport::new(vec![100, 100, 10]));
        let cache = Arc::new(SentinelTokenCache::new());
        let cancel = tokio_util::sync::CancellationToken::new();
        let (status_tx, _status_rx) = tokio::sync::watch::channel(ConnectorStatus::Connecting);
        let (_pause_tx, pause_rx) = tokio::sync::watch::channel(false);

        let mut config = test_config();
        // Long poll interval so the whole test happens inside ONE poll;
        // a second poll (if it ever fired) would add a spurious 4th query.
        config.poll_interval_secs = 300;

        let loop_handle = tokio::spawn(polling_loop(
            config,
            transport.clone(),
            cache,
            session.clone(),
            "sid".into(),
            Arc::new(NoopEmitter) as Arc<dyn EventEmitter>,
            cancel.clone(),
            status_tx,
            "ds".into(),
            pause_rx,
        ));

        // Bounded wait: the drain loop fires all 3 queries back-to-back
        // (no sleeps between them), so this resolves quickly once the
        // fixed first-poll delay elapses.
        for _ in 0..100 {
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
            if transport.call_count.load(Ordering::SeqCst) >= 3 {
                break;
            }
        }
        // Give the loop a brief moment past the 3rd call to make sure it
        // doesn't fire a 4th query before we snapshot (it shouldn't: the
        // 3rd batch was a partial batch, i.e. caught up).
        tokio::time::sleep(std::time::Duration::from_millis(300)).await;

        let calls = transport.call_count.load(Ordering::SeqCst);
        assert_eq!(
            calls, 3,
            "drain must issue exactly 3 queries within one poll, got {calls}"
        );

        let queries = transport.queries_seen.lock().unwrap().clone();
        assert_eq!(queries.len(), 3);
        assert!(
            !queries[0].contains("datetime("),
            "first query has no watermark yet: {}",
            queries[0]
        );
        assert!(
            queries[1].contains("datetime(") && queries[1] != queries[0],
            "second query must cursor on the watermark advanced by call 1: {}",
            queries[1]
        );
        assert!(
            queries[2].contains("datetime(") && queries[2] != queries[1],
            "third query must cursor on the watermark advanced by call 2: {}",
            queries[2]
        );

        let (entities, relations) = session
            .graph
            .read()
            .map(|g| (g.entity_count(), g.relation_count()))
            .unwrap_or((0, 0));
        // Whole-phase fix wave, Fix 2 (tie-aware cut): each of the two FULL
        // batches (calls 1-2, 100 rows apiece) now defers its own single
        // max-`_ingest_ts` row to the next drain iteration rather than
        // ingesting it immediately -- even a lone row at the max tick might
        // share it with rows just past the `take N` cut in a real backend,
        // so it's held back and re-queried with `_ingest_ts > wm`. This
        // mock's row generator isn't reactive to the watermark it's handed
        // (it just serves the next slice of a global, strictly-increasing
        // row-id space), so unlike a real Sentinel backend it never
        // actually replays those 2 deferred rows -- hence 208, not 210.
        // (`fix2_tie_aware_cut_...` below proves the deferred rows DO come
        // back around when the mock is reactive.) The point of *this* test
        // remains intact: the drain issued 3 queries and processed all 3
        // batches, not just the first.
        assert_eq!(
            entities, 416,
            "expected 208 distinct users + 208 distinct IPs ingested across all 3 drain batches \
             (210 rows minus the 2 max-tick rows Fix 2 defers, one per full batch)"
        );
        assert_eq!(
            relations, 208,
            "expected 208 rows ingested as relations (210 minus the 2 rows Fix 2 defers from \
             the two full batches) -- proves drain didn't stop after batch 1"
        );

        cancel.cancel();
        let _ = loop_handle.await;
    }

    // ── Source coverage tests (Task 4: connector loop wires SourceCoverage) ──
    //
    // GRAPHHUNTER_SOURCE_COVERAGE is process-global env state, and cargo runs
    // tests in parallel by default. Serialize mutation of it with a
    // module-local mutex, mirroring the `ENV_LOCK` convention used in
    // `coverage.rs` / `journal.rs` / `operations/hunt.rs`. `pub(super)` so
    // the sibling `fix_wave_tests` module (whole-phase fix wave) shares this
    // exact lock instead of racing it with a second, independent mutex.
    pub(super) static ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    pub(super) fn lock_env() -> std::sync::MutexGuard<'static, ()> {
        ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Mock transport whose `execute_query` always fails (simulated
    /// transport error), so the connector's per-table failure arm fires on
    /// every poll.
    struct FailingQueryTransport {
        calls: AtomicUsize,
    }

    impl SentinelTransport for FailingQueryTransport {
        async fn acquire_token(
            &self,
            _t: &str,
            _c: &str,
            _s: &str,
        ) -> Result<TokenResponse, String> {
            Ok(TokenResponse {
                access_token: "tok".into(),
                expires_in: 3600,
            })
        }

        async fn execute_query(
            &self,
            _ws: &str,
            _q: &str,
            _b: &str,
        ) -> Result<serde_json::Value, String> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            Err("simulated transport failure".into())
        }
    }

    #[tokio::test]
    async fn coverage_off_by_default_records_nothing() {
        let _guard = lock_env();
        // Source coverage now defaults ON; exercise the explicit-off path.
        unsafe { std::env::set_var("GRAPHHUNTER_SOURCE_COVERAGE", "0") };

        let api = GraphHunterApi::new_noop();
        api.create_session(CreateSessionRequest {
            name: Some("coverage-off-test".into()),
        })
        .expect("session");
        let session = api.sessions().current_session().expect("session");

        let transport = Arc::new(FailingQueryTransport {
            calls: AtomicUsize::new(0),
        });
        let cache = Arc::new(SentinelTokenCache::new());
        let cancel = tokio_util::sync::CancellationToken::new();
        let (status_tx, _status_rx) = tokio::sync::watch::channel(ConnectorStatus::Connecting);
        let (_pause_tx, pause_rx) = tokio::sync::watch::channel(false);

        let mut config = test_config();
        // Long interval: only the first poll fires during this test.
        config.poll_interval_secs = 300;

        let loop_handle = tokio::spawn(polling_loop(
            config,
            transport.clone(),
            cache,
            session.clone(),
            "sid".into(),
            Arc::new(NoopEmitter) as Arc<dyn EventEmitter>,
            cancel.clone(),
            status_tx,
            "ds".into(),
            pause_rx,
        ));

        for _ in 0..100 {
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
            if transport.calls.load(Ordering::SeqCst) >= 1 {
                break;
            }
        }
        assert!(
            transport.calls.load(Ordering::SeqCst) >= 1,
            "expected at least one poll attempt"
        );
        // Give the (no-op) failure-handling path a moment to run past the
        // query call before snapshotting.
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;

        let (watermarks, missing) = session.source_coverage.read().unwrap().snapshot();
        assert!(
            watermarks.is_empty() && missing.is_empty(),
            "flag off: source_coverage must stay untouched (zero recordings), \
             got watermarks={watermarks:?} missing={missing:?}"
        );

        unsafe { std::env::remove_var("GRAPHHUNTER_SOURCE_COVERAGE") };
        cancel.cancel();
        let _ = loop_handle.await;
    }

    #[tokio::test]
    async fn failing_table_query_marks_source_missing_when_coverage_enabled() {
        let _guard = lock_env();
        unsafe { std::env::set_var("GRAPHHUNTER_SOURCE_COVERAGE", "1") };

        let api = GraphHunterApi::new_noop();
        api.create_session(CreateSessionRequest {
            name: Some("coverage-fail-test".into()),
        })
        .expect("session");
        let session = api.sessions().current_session().expect("session");

        let transport = Arc::new(FailingQueryTransport {
            calls: AtomicUsize::new(0),
        });
        let cache = Arc::new(SentinelTokenCache::new());
        let cancel = tokio_util::sync::CancellationToken::new();
        let (status_tx, _status_rx) = tokio::sync::watch::channel(ConnectorStatus::Connecting);
        let (_pause_tx, pause_rx) = tokio::sync::watch::channel(false);

        let mut config = test_config();
        config.poll_interval_secs = 300;

        let loop_handle = tokio::spawn(polling_loop(
            config,
            transport.clone(),
            cache,
            session.clone(),
            "sid".into(),
            Arc::new(NoopEmitter) as Arc<dyn EventEmitter>,
            cancel.clone(),
            status_tx,
            "ds".into(),
            pause_rx,
        ));

        for _ in 0..100 {
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
            if transport.calls.load(Ordering::SeqCst) >= 1 {
                break;
            }
        }
        assert!(
            transport.calls.load(Ordering::SeqCst) >= 1,
            "expected at least one poll attempt"
        );
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;

        let (_watermarks, missing) = session.source_coverage.read().unwrap().snapshot();
        assert!(
            missing.contains(&"sentinel:SigninLogs".to_string()),
            "expected sentinel:SigninLogs to be reported missing after a \
             transport-error poll, got {missing:?}"
        );

        unsafe { std::env::remove_var("GRAPHHUNTER_SOURCE_COVERAGE") };
        cancel.cancel();
        let _ = loop_handle.await;
    }

    #[tokio::test]
    async fn successful_poll_records_covered_and_not_missing() {
        let _guard = lock_env();
        unsafe { std::env::set_var("GRAPHHUNTER_SOURCE_COVERAGE", "1") };

        let api = GraphHunterApi::new_noop();
        api.create_session(CreateSessionRequest {
            name: Some("coverage-success-test".into()),
        })
        .expect("session");
        let session = api.sessions().current_session().expect("session");

        // A single batch under batch_size (caught up after one call), so
        // the drain loop stops after exactly one query.
        let transport = Arc::new(DrainMockTransport::new(vec![10]));
        let cache = Arc::new(SentinelTokenCache::new());
        let cancel = tokio_util::sync::CancellationToken::new();
        let (status_tx, _status_rx) = tokio::sync::watch::channel(ConnectorStatus::Connecting);
        let (_pause_tx, pause_rx) = tokio::sync::watch::channel(false);

        let mut config = test_config();
        config.poll_interval_secs = 300;

        let loop_handle = tokio::spawn(polling_loop(
            config,
            transport.clone(),
            cache,
            session.clone(),
            "sid".into(),
            Arc::new(NoopEmitter) as Arc<dyn EventEmitter>,
            cancel.clone(),
            status_tx,
            "ds".into(),
            pause_rx,
        ));

        for _ in 0..100 {
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
            if transport.call_count.load(Ordering::SeqCst) >= 1 {
                break;
            }
        }
        assert!(
            transport.call_count.load(Ordering::SeqCst) >= 1,
            "expected at least one poll attempt"
        );
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;

        let (watermarks, missing) = session.source_coverage.read().unwrap().snapshot();
        assert!(
            watermarks.contains_key("sentinel:SigninLogs"),
            "expected sentinel:SigninLogs watermark to be recorded on a \
             successful poll, got {watermarks:?}"
        );
        assert!(
            !missing.contains(&"sentinel:SigninLogs".to_string()),
            "a successful poll must not mark the source missing, got {missing:?}"
        );

        unsafe { std::env::remove_var("GRAPHHUNTER_SOURCE_COVERAGE") };
        cancel.cancel();
        let _ = loop_handle.await;
    }
}

// ── Whole-phase fix wave tests (Fixes 1-5) ──
//
// Pure unit tests for the decision helpers (`drain_outcome`, `tie_aware_cut`,
// `ts_or_now`) plus async integration tests through the full `polling_loop`
// for the fixes that are cleanly reachable via a mock transport (2, 3, 4, 5).
//
// Fix 1 (insert-error => silent loss labeled covered) has no pure-data
// integration test here: `graph.insert_triples` only returns `Err` via a
// spill-store failure, and nothing in this codebase currently constructs
// that failure path from a unit test (no configurable disk-full/IO-failure
// injection point exists in `graph-engine`, and adding one is out of scope
// for this connector-focused fix wave). Its exact behavior — no watermark
// advance, drain break, coverage FAILURE — is unit-tested at the decision
// level via `drain_outcome(insert_failed: true, ...)` below, and the wiring
// at the call site (`Err(e) => { insert_failed = true; ... }` in
// `polling_loop`) follows the identical `record_siem_outcome(..., false,
// ...)` + `break` pattern already exercised end-to-end by
// `failing_table_query_marks_source_missing_when_coverage_enabled` above
// (a transport error, not an insert error, but the same call shape).
#[cfg(test)]
// Tests hold the process-wide `ENV_LOCK` (std Mutex, via `lock_env()`) across
// awaits on purpose: it serializes env-var mutation for the whole test body.
// `#[tokio::test]` runs on a current-thread runtime, so nothing else
// contends for it there.
#[allow(clippy::await_holding_lock)]
mod fix_wave_tests {
    use super::*;
    use crate::dto::session::CreateSessionRequest;
    use crate::{GraphHunterApi, NoopEmitter};
    use graph_hunter_siem::{SentinelAuth, SentinelTransport, TokenResponse};
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::time::Duration;

    // ── Pure decision-function tests ──

    #[test]
    fn drain_outcome_insert_failure_blocks_regardless_of_batch_shape() {
        // Fix 1: even a batch that would otherwise be "still draining"
        // (full) or "caught up" (partial) must be blocked when the insert
        // itself failed -- the rows never made it into the graph.
        assert_eq!(
            drain_outcome(true, false, 100, 100),
            DrainOutcome::InsertBlocked
        );
        assert_eq!(
            drain_outcome(true, false, 5, 100),
            DrainOutcome::InsertBlocked
        );
    }

    #[test]
    fn drain_outcome_zero_triples_reported_even_though_watermark_can_advance() {
        // Fix 3: unlike an insert failure, a 0-triples batch is still
        // reported distinctly from a normal success -- ZeroTriples, not
        // CaughtUp/StillDraining -- so the caller records coverage as
        // missing even though it still advances the watermark.
        assert_eq!(
            drain_outcome(false, true, 50, 100),
            DrainOutcome::ZeroTriples
        );
    }

    #[test]
    fn drain_outcome_partial_or_empty_batch_is_caught_up() {
        assert_eq!(drain_outcome(false, false, 0, 100), DrainOutcome::CaughtUp);
        assert_eq!(drain_outcome(false, false, 50, 100), DrainOutcome::CaughtUp);
    }

    #[test]
    fn drain_outcome_full_batch_is_still_draining() {
        // Fix 4: a full batch must NOT be reported as caught up -- the
        // caller must not claim "covered to now" while backlog remains.
        assert_eq!(
            drain_outcome(false, false, 100, 100),
            DrainOutcome::StillDraining
        );
    }

    fn ts_row(ts: &str) -> serde_json::Map<String, serde_json::Value> {
        let mut m = serde_json::Map::new();
        m.insert(
            "_ingest_ts".to_string(),
            serde_json::Value::String(ts.to_string()),
        );
        m
    }

    #[test]
    fn tie_aware_cut_excludes_rows_at_the_max_tick_and_uses_kept_max_as_watermark() {
        // Fix 2: 5 rows, the last 2 share the max tick "t4".
        let rows = vec![
            ts_row("t1"),
            ts_row("t2"),
            ts_row("t3"),
            ts_row("t4"),
            ts_row("t4"),
        ];
        let (kept, new_wm, all_same_tick) = tie_aware_cut(rows, "t4");
        assert_eq!(
            kept.len(),
            3,
            "the 2 rows tied at the max tick must be excluded"
        );
        assert_eq!(
            new_wm, "t3",
            "watermark must be the max tick AMONG KEPT rows, not the batch max"
        );
        assert!(!all_same_tick);
    }

    #[test]
    fn tie_aware_cut_all_rows_same_tick_falls_back_to_ingest_all_and_warns() {
        // Fix 2 pathological case: every row shares the one tick -- can't
        // exclude without emptying the batch.
        let rows = vec![ts_row("t4"), ts_row("t4"), ts_row("t4")];
        let (kept, new_wm, all_same_tick) = tie_aware_cut(rows, "t4");
        assert_eq!(kept.len(), 3, "all-same-tick fallback must keep every row");
        assert_eq!(new_wm, "t4");
        assert!(
            all_same_tick,
            "caller must be told to warn + raise batch_size"
        );
    }

    #[test]
    fn ts_or_now_parses_the_given_tick() {
        let secs = ts_or_now(Some("2024-01-15T10:07:00Z"));
        assert_eq!(
            secs,
            chrono::DateTime::parse_from_rfc3339("2024-01-15T10:07:00Z")
                .unwrap()
                .timestamp()
        );
    }

    #[test]
    fn ts_or_now_falls_back_to_wall_clock_when_no_tick() {
        let before = crate::util::now_secs();
        let secs = ts_or_now(None);
        let after = crate::util::now_secs();
        assert!(
            secs >= before && secs <= after,
            "expected now()-ish fallback, got {secs} (window [{before}, {after}])"
        );
    }

    // ── Async integration tests through the full polling_loop ──

    // Reuse `pause_tests`' env lock (not a second, independent mutex) --
    // `GRAPHHUNTER_SOURCE_COVERAGE` is one process-global var, so every
    // test mutating it across both modules must serialize on the SAME
    // mutex or they race each other under cargo's parallel test runner.
    use super::pause_tests::lock_env;

    fn test_config() -> SentinelPollingConfig {
        SentinelPollingConfig {
            workspace_id: "ws".into(),
            auth: SentinelAuth {
                tenant_id: "t".into(),
                client_id: "c".into(),
                client_secret: "s".into(),
            },
            poll_interval_secs: 5,
            tables: vec!["SigninLogs".into()],
            batch_size: 100,
            initial_time_window_filter: None,
        }
    }

    /// Serves pre-built canned responses, one per call (by index), and
    /// records every KQL query it receives. Unlike `DrainMockTransport`
    /// (which auto-generates strictly-increasing timestamps), this lets
    /// tests script exact `_ingest_ts` values per row -- needed to set up
    /// ties at the max tick (Fix 2).
    struct ScriptedTransport {
        responses: Vec<serde_json::Value>,
        call_count: AtomicUsize,
        queries_seen: std::sync::Mutex<Vec<String>>,
    }

    impl ScriptedTransport {
        fn new(responses: Vec<serde_json::Value>) -> Self {
            Self {
                responses,
                call_count: AtomicUsize::new(0),
                queries_seen: std::sync::Mutex::new(Vec::new()),
            }
        }
    }

    impl SentinelTransport for ScriptedTransport {
        async fn acquire_token(
            &self,
            _t: &str,
            _c: &str,
            _s: &str,
        ) -> Result<TokenResponse, String> {
            Ok(TokenResponse {
                access_token: "tok".into(),
                expires_in: 3600,
            })
        }

        async fn execute_query(
            &self,
            _ws: &str,
            q: &str,
            _b: &str,
        ) -> Result<serde_json::Value, String> {
            let idx = self.call_count.fetch_add(1, Ordering::SeqCst);
            self.queries_seen.lock().unwrap().push(q.to_string());
            Ok(self.responses.get(idx).cloned().unwrap_or_else(|| {
                serde_json::json!({"tables": [{
                    "name": "PrimaryResult",
                    "columns": [
                        {"name": "Type", "type": "string"},
                        {"name": "TimeGenerated", "type": "datetime"},
                        {"name": "_ingest_ts", "type": "datetime"},
                        {"name": "UserPrincipalName", "type": "string"},
                        {"name": "IPAddress", "type": "string"}
                    ],
                    "rows": []
                }]})
            }))
        }
    }

    /// Builds a SigninLogs response from explicit `(row_index,
    /// _ingest_ts)` pairs, so a test can put ties at the max tick.
    fn build_signin_rows_with_ts(rows: &[(usize, &str)]) -> serde_json::Value {
        let rows: Vec<serde_json::Value> = rows
            .iter()
            .map(|(idx, ts)| {
                serde_json::json!([
                    "SigninLogs",
                    "2024-01-15T10:00:00Z",
                    ts,
                    format!("user{idx}@contoso.com"),
                    format!("10.0.{}.{}", idx / 256, idx % 256)
                ])
            })
            .collect();
        serde_json::json!({
            "tables": [{
                "name": "PrimaryResult",
                "columns": [
                    {"name": "Type", "type": "string"},
                    {"name": "TimeGenerated", "type": "datetime"},
                    {"name": "_ingest_ts", "type": "datetime"},
                    {"name": "UserPrincipalName", "type": "string"},
                    {"name": "IPAddress", "type": "string"}
                ],
                "rows": rows
            }]
        })
    }

    fn empty_signin_response() -> serde_json::Value {
        serde_json::json!({"tables": [{
            "name": "PrimaryResult",
            "columns": [
                {"name": "Type", "type": "string"},
                {"name": "TimeGenerated", "type": "datetime"},
                {"name": "_ingest_ts", "type": "datetime"},
                {"name": "UserPrincipalName", "type": "string"},
                {"name": "IPAddress", "type": "string"}
            ],
            "rows": []
        }]})
    }

    /// Builds a synthetic SigninLogs response for `count` rows starting at
    /// global row index `start_idx`, each with a unique user/IP pair and a
    /// strictly increasing `_ingest_ts`. Local copy of the equivalent
    /// helper in `pause_tests` (module-private there) so this module
    /// doesn't reach across a sibling module's privacy boundary.
    fn build_signin_rows(start_idx: usize, count: usize) -> serde_json::Value {
        let rows: Vec<serde_json::Value> = (0..count)
            .map(|i| {
                let idx = start_idx + i;
                serde_json::json!([
                    "SigninLogs",
                    "2024-01-15T10:00:00Z",
                    format!("2024-01-15T00:00:00.{:07}Z", idx),
                    format!("user{idx}@contoso.com"),
                    format!("10.0.{}.{}", idx / 256, idx % 256)
                ])
            })
            .collect();
        serde_json::json!({
            "tables": [{
                "name": "PrimaryResult",
                "columns": [
                    {"name": "Type", "type": "string"},
                    {"name": "TimeGenerated", "type": "datetime"},
                    {"name": "_ingest_ts", "type": "datetime"},
                    {"name": "UserPrincipalName", "type": "string"},
                    {"name": "IPAddress", "type": "string"}
                ],
                "rows": rows
            }]
        })
    }

    /// Local copy of the equivalent mock in `pause_tests` (module-private
    /// there): scripts a fixed row count per call (in order), each call
    /// getting a fresh slice of the global synthetic row-id space so every
    /// row across every call is a distinct entity pair.
    struct DrainMockTransport {
        row_counts: Vec<usize>,
        rows_emitted: AtomicUsize,
        call_count: AtomicUsize,
    }

    impl DrainMockTransport {
        fn new(row_counts: Vec<usize>) -> Self {
            Self {
                row_counts,
                rows_emitted: AtomicUsize::new(0),
                call_count: AtomicUsize::new(0),
            }
        }
    }

    impl SentinelTransport for DrainMockTransport {
        async fn acquire_token(
            &self,
            _t: &str,
            _c: &str,
            _s: &str,
        ) -> Result<TokenResponse, String> {
            Ok(TokenResponse {
                access_token: "tok".into(),
                expires_in: 3600,
            })
        }

        async fn execute_query(
            &self,
            _ws: &str,
            _q: &str,
            _b: &str,
        ) -> Result<serde_json::Value, String> {
            let idx = self.call_count.fetch_add(1, Ordering::SeqCst);
            let count = self.row_counts.get(idx).copied().unwrap_or(0);
            let start = self.rows_emitted.fetch_add(count, Ordering::SeqCst);
            Ok(build_signin_rows(start, count))
        }
    }

    #[tokio::test]
    async fn fix2_tie_aware_cut_excludes_max_tick_rows_and_advances_to_kept_max() {
        let api = GraphHunterApi::new_noop();
        api.create_session(CreateSessionRequest {
            name: Some("fix2-test".into()),
        })
        .expect("session");
        let session = api.sessions().current_session().expect("session");

        let t1 = "2024-01-15T00:00:00.0000001Z";
        let t2 = "2024-01-15T00:00:00.0000002Z";
        let t3 = "2024-01-15T00:00:00.0000003Z";
        let t_max = "2024-01-15T00:00:00.0000004Z"; // shared by rows 3 and 4

        // Full batch (batch_size=5): rows 0-2 at distinct ticks, rows 3-4
        // tied at the max tick t_max.
        let first = build_signin_rows_with_ts(&[(0, t1), (1, t2), (2, t3), (3, t_max), (4, t_max)]);
        // Nothing further queued: if the 2 tied rows were (incorrectly)
        // ingested this round, they'd show up in the final graph counts;
        // if they were dropped forever (rather than just deferred), the
        // 2nd query wouldn't target the kept-rows' tick either. This
        // isolates "excluded this round" from "eventually re-read".
        let second = empty_signin_response();

        let transport = Arc::new(ScriptedTransport::new(vec![first, second]));
        let cache = Arc::new(SentinelTokenCache::new());
        let cancel = tokio_util::sync::CancellationToken::new();
        let (status_tx, _status_rx) = tokio::sync::watch::channel(ConnectorStatus::Connecting);
        let (_pause_tx, pause_rx) = tokio::sync::watch::channel(false);

        let mut config = test_config();
        config.poll_interval_secs = 300;
        config.batch_size = 5;

        let loop_handle = tokio::spawn(polling_loop(
            config,
            transport.clone(),
            cache,
            session.clone(),
            "sid".into(),
            Arc::new(NoopEmitter) as Arc<dyn EventEmitter>,
            cancel.clone(),
            status_tx,
            "ds".into(),
            pause_rx,
        ));

        for _ in 0..100 {
            tokio::time::sleep(Duration::from_millis(100)).await;
            if transport.call_count.load(Ordering::SeqCst) >= 2 {
                break;
            }
        }
        tokio::time::sleep(Duration::from_millis(300)).await;

        let calls = transport.call_count.load(Ordering::SeqCst);
        assert_eq!(
            calls, 2,
            "a full batch (5 rows == batch_size) must trigger a 2nd drain query, got {calls}"
        );

        let queries = transport.queries_seen.lock().unwrap().clone();
        assert!(
            queries[1].contains(&format!("datetime({t3})")),
            "2nd query must cursor on the KEPT rows' max tick ({t3}), not the batch max: {}",
            queries[1]
        );
        assert!(
            !queries[1].contains(&format!("datetime({t_max})")),
            "2nd query must NOT cursor on the excluded tied tick ({t_max}): {}",
            queries[1]
        );

        let (_entities, relations) = session
            .graph
            .read()
            .map(|g| (g.entity_count(), g.relation_count()))
            .unwrap_or((0, 0));
        assert_eq!(
            relations, 3,
            "only the 3 rows strictly below the max tick may be ingested this poll -- \
             the 2 rows tied at the max tick must be excluded (not silently lost, not \
             double-counted): got {relations} relations"
        );

        cancel.cancel();
        let _ = loop_handle.await;
    }

    #[tokio::test]
    async fn fix2_all_same_tick_fallback_ingests_all_and_warns() {
        let api = GraphHunterApi::new_noop();
        api.create_session(CreateSessionRequest {
            name: Some("fix2-fallback-test".into()),
        })
        .expect("session");
        let session = api.sessions().current_session().expect("session");

        let t_max = "2024-01-15T00:00:00.0000009Z";
        // Pathological: every row in this full batch shares one tick.
        let first = build_signin_rows_with_ts(&[
            (0, t_max),
            (1, t_max),
            (2, t_max),
            (3, t_max),
            (4, t_max),
        ]);
        let second = empty_signin_response();

        let transport = Arc::new(ScriptedTransport::new(vec![first, second]));
        let cache = Arc::new(SentinelTokenCache::new());
        let cancel = tokio_util::sync::CancellationToken::new();
        let (status_tx, _status_rx) = tokio::sync::watch::channel(ConnectorStatus::Connecting);
        let (_pause_tx, pause_rx) = tokio::sync::watch::channel(false);

        let warnings: Arc<std::sync::Mutex<Vec<String>>> =
            Arc::new(std::sync::Mutex::new(Vec::new()));
        let warnings_clone = warnings.clone();
        let emitter: Arc<dyn EventEmitter> =
            Arc::new(crate::events::FnEmitter(move |_ev, payload| {
                if let Some(msg) = payload.get("error").and_then(|v| v.as_str()) {
                    warnings_clone.lock().unwrap().push(msg.to_string());
                }
            }));

        let mut config = test_config();
        config.poll_interval_secs = 300;
        config.batch_size = 5;

        let loop_handle = tokio::spawn(polling_loop(
            config,
            transport.clone(),
            cache,
            session.clone(),
            "sid".into(),
            emitter,
            cancel.clone(),
            status_tx,
            "ds".into(),
            pause_rx,
        ));

        for _ in 0..100 {
            tokio::time::sleep(Duration::from_millis(100)).await;
            if transport.call_count.load(Ordering::SeqCst) >= 2 {
                break;
            }
        }
        tokio::time::sleep(Duration::from_millis(300)).await;

        let (_entities, relations) = session
            .graph
            .read()
            .map(|g| (g.entity_count(), g.relation_count()))
            .unwrap_or((0, 0));
        assert_eq!(
            relations, 5,
            "all-same-tick fallback must ingest every row rather than emptying the batch: got {relations}"
        );

        {
            let msgs = warnings.lock().unwrap();
            assert!(
                msgs.iter().any(|m| m.contains("batch_size")),
                "expected a warning to raise batch_size for this table, got {msgs:?}"
            );
        }

        cancel.cancel();
        let _ = loop_handle.await;
    }

    /// Rows tagged with an unrecognized `Type` -- `detect_table` returns
    /// `Unknown` for every one, so `parse_event` yields zero triples per
    /// row regardless of the other fields present.
    fn build_unknown_type_rows(count: usize) -> serde_json::Value {
        let rows: Vec<serde_json::Value> = (0..count)
            .map(|i| {
                serde_json::json!([
                    "SomeUnknownTable",
                    "2024-01-15T10:00:00Z",
                    format!("2024-01-15T00:00:00.{:07}Z", i),
                    format!("whatever{i}")
                ])
            })
            .collect();
        serde_json::json!({
            "tables": [{
                "name": "PrimaryResult",
                "columns": [
                    {"name": "Type", "type": "string"},
                    {"name": "TimeGenerated", "type": "datetime"},
                    {"name": "_ingest_ts", "type": "datetime"},
                    {"name": "SomeField", "type": "string"}
                ],
                "rows": rows
            }]
        })
    }

    struct ZeroTriplesTransport {
        response: serde_json::Value,
        calls: AtomicUsize,
    }

    impl SentinelTransport for ZeroTriplesTransport {
        async fn acquire_token(
            &self,
            _t: &str,
            _c: &str,
            _s: &str,
        ) -> Result<TokenResponse, String> {
            Ok(TokenResponse {
                access_token: "tok".into(),
                expires_in: 3600,
            })
        }

        async fn execute_query(
            &self,
            _ws: &str,
            _q: &str,
            _b: &str,
        ) -> Result<serde_json::Value, String> {
            let idx = self.calls.fetch_add(1, Ordering::SeqCst);
            if idx == 0 {
                Ok(self.response.clone())
            } else {
                Ok(empty_signin_response())
            }
        }
    }

    #[tokio::test]
    async fn fix3_zero_triples_batch_reports_source_missing_not_covered() {
        let _guard = lock_env();
        unsafe { std::env::set_var("GRAPHHUNTER_SOURCE_COVERAGE", "1") };

        let api = GraphHunterApi::new_noop();
        api.create_session(CreateSessionRequest {
            name: Some("fix3-test".into()),
        })
        .expect("session");
        let session = api.sessions().current_session().expect("session");

        // 3 rows, well under batch_size (100) -- a partial/caught-up
        // batch that would (pre-fix) have recorded coverage SUCCESS
        // despite producing zero triples.
        let transport = Arc::new(ZeroTriplesTransport {
            response: build_unknown_type_rows(3),
            calls: AtomicUsize::new(0),
        });
        let cache = Arc::new(SentinelTokenCache::new());
        let cancel = tokio_util::sync::CancellationToken::new();
        let (status_tx, _status_rx) = tokio::sync::watch::channel(ConnectorStatus::Connecting);
        let (_pause_tx, pause_rx) = tokio::sync::watch::channel(false);

        let mut config = test_config();
        config.poll_interval_secs = 300;

        let loop_handle = tokio::spawn(polling_loop(
            config,
            transport.clone(),
            cache,
            session.clone(),
            "sid".into(),
            Arc::new(NoopEmitter) as Arc<dyn EventEmitter>,
            cancel.clone(),
            status_tx,
            "ds".into(),
            pause_rx,
        ));

        for _ in 0..100 {
            tokio::time::sleep(Duration::from_millis(100)).await;
            if transport.calls.load(Ordering::SeqCst) >= 1 {
                break;
            }
        }
        tokio::time::sleep(Duration::from_millis(200)).await;

        let (_watermarks, missing) = session.source_coverage.read().unwrap().snapshot();
        assert!(
            missing.contains(&"sentinel:SigninLogs".to_string()),
            "a batch that parsed to 0 triples must report the source missing (blind), \
             got {missing:?}"
        );

        unsafe { std::env::remove_var("GRAPHHUNTER_SOURCE_COVERAGE") };
        cancel.cancel();
        let _ = loop_handle.await;
    }

    #[tokio::test]
    async fn fix4_backstop_exit_with_full_last_batch_does_not_record_covered() {
        let _guard = lock_env();
        unsafe { std::env::set_var("GRAPHHUNTER_SOURCE_COVERAGE", "1") };

        let api = GraphHunterApi::new_noop();
        api.create_session(CreateSessionRequest {
            name: Some("fix4-test".into()),
        })
        .expect("session");
        let session = api.sessions().current_session().expect("session");

        // Every call returns exactly batch_size rows -> the table never
        // catches up within this poll, hitting the MAX_DRAIN_ITERS(100)
        // backstop while the last batch is still full.
        let transport = Arc::new(DrainMockTransport::new(vec![2; 100]));
        let cache = Arc::new(SentinelTokenCache::new());
        let cancel = tokio_util::sync::CancellationToken::new();
        let (status_tx, _status_rx) = tokio::sync::watch::channel(ConnectorStatus::Connecting);
        let (_pause_tx, pause_rx) = tokio::sync::watch::channel(false);

        let mut config = test_config();
        config.poll_interval_secs = 300;
        config.batch_size = 2;

        let loop_handle = tokio::spawn(polling_loop(
            config,
            transport.clone(),
            cache,
            session.clone(),
            "sid".into(),
            Arc::new(NoopEmitter) as Arc<dyn EventEmitter>,
            cancel.clone(),
            status_tx,
            "ds".into(),
            pause_rx,
        ));

        for _ in 0..300 {
            tokio::time::sleep(Duration::from_millis(20)).await;
            if transport.call_count.load(Ordering::SeqCst) >= 100 {
                break;
            }
        }
        tokio::time::sleep(Duration::from_millis(300)).await;

        let calls = transport.call_count.load(Ordering::SeqCst);
        assert_eq!(
            calls, 100,
            "drain must stop exactly at the MAX_DRAIN_ITERS(100) backstop, got {calls}"
        );

        let (watermarks, missing) = session.source_coverage.read().unwrap().snapshot();
        assert!(
            !watermarks.contains_key("sentinel:SigninLogs"),
            "a backstop exit with backlog remaining (still-full last batch) must NOT \
             record 'covered to now' -- got watermarks={watermarks:?}"
        );
        assert!(
            missing.is_empty(),
            "not-yet-covered isn't the same as 'missing' either: got {missing:?}"
        );

        unsafe { std::env::remove_var("GRAPHHUNTER_SOURCE_COVERAGE") };
        cancel.cancel();
        let _ = loop_handle.await;
    }

    /// Like `DrainMockTransport` but with a fixed per-call delay, so a
    /// test can reliably observe (and interrupt) an in-progress drain
    /// instead of racing a drain loop that would otherwise burn through
    /// 100 in-memory mock calls in under a millisecond.
    struct SlowDrainMockTransport {
        row_counts: Vec<usize>,
        rows_emitted: AtomicUsize,
        call_count: AtomicUsize,
    }

    impl SlowDrainMockTransport {
        fn new(row_counts: Vec<usize>) -> Self {
            Self {
                row_counts,
                rows_emitted: AtomicUsize::new(0),
                call_count: AtomicUsize::new(0),
            }
        }
    }

    impl SentinelTransport for SlowDrainMockTransport {
        async fn acquire_token(
            &self,
            _t: &str,
            _c: &str,
            _s: &str,
        ) -> Result<TokenResponse, String> {
            Ok(TokenResponse {
                access_token: "tok".into(),
                expires_in: 3600,
            })
        }

        async fn execute_query(
            &self,
            _ws: &str,
            _q: &str,
            _b: &str,
        ) -> Result<serde_json::Value, String> {
            tokio::time::sleep(Duration::from_millis(15)).await;
            let idx = self.call_count.fetch_add(1, Ordering::SeqCst);
            let count = self.row_counts.get(idx).copied().unwrap_or(0);
            let start = self.rows_emitted.fetch_add(count, Ordering::SeqCst);
            Ok(build_signin_rows(start, count))
        }
    }

    #[tokio::test]
    async fn fix5_pause_mid_drain_stops_promptly() {
        let api = GraphHunterApi::new_noop();
        api.create_session(CreateSessionRequest {
            name: Some("fix5-test".into()),
        })
        .expect("session");
        let session = api.sessions().current_session().expect("session");

        // Scripted for 100 full batches (15ms apiece); pausing mid-drain
        // must cut this off well short of exhausting the script or
        // hitting the MAX_DRAIN_ITERS backstop.
        let transport = Arc::new(SlowDrainMockTransport::new(vec![2; 100]));
        let cache = Arc::new(SentinelTokenCache::new());
        let cancel = tokio_util::sync::CancellationToken::new();
        let (status_tx, _status_rx) = tokio::sync::watch::channel(ConnectorStatus::Connecting);
        let (pause_tx, pause_rx) = tokio::sync::watch::channel(false);

        let mut config = test_config();
        config.poll_interval_secs = 300;
        config.batch_size = 2;

        let loop_handle = tokio::spawn(polling_loop(
            config,
            transport.clone(),
            cache,
            session.clone(),
            "sid".into(),
            Arc::new(NoopEmitter) as Arc<dyn EventEmitter>,
            cancel.clone(),
            status_tx,
            "ds".into(),
            pause_rx,
        ));

        // Let a few drain iterations happen (~15ms each), then pause.
        for _ in 0..50 {
            tokio::time::sleep(Duration::from_millis(5)).await;
            if transport.call_count.load(Ordering::SeqCst) >= 3 {
                break;
            }
        }
        pause_tx.send(true).unwrap();

        // Bounded settle window for any in-flight call to finish and the
        // drain loop to notice the pause on its next iteration.
        tokio::time::sleep(Duration::from_millis(150)).await;
        let count_shortly_after = transport.call_count.load(Ordering::SeqCst);

        // No further queries should arrive once settled.
        tokio::time::sleep(Duration::from_millis(300)).await;
        let count_later = transport.call_count.load(Ordering::SeqCst);

        assert_eq!(
            count_later, count_shortly_after,
            "paused mid-drain: no further queries once stopped"
        );
        assert!(
            count_later < 100,
            "pause must cut the drain off well short of exhausting all 100 scripted \
             batches (proves it noticed the pause rather than running to the \
             MAX_DRAIN_ITERS backstop): got {count_later} calls"
        );

        cancel.cancel();
        let _ = loop_handle.await;
    }
}
