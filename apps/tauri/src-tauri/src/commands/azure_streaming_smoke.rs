//! Smoke test for the Phase 5–9 Azure streaming core modules.
//!
//! Exercises every new primitive from `graph_hunter_core::sources::*`
//! and `graph_hunter_core::ingest::*` end-to-end **without** hitting
//! Azure, without real HTTP, and without touching the session's real
//! `GraphHunter`. The point is to validate:
//!
//! 1. The new core compiles as a dep of the Tauri app (the long-run
//!    scope intentionally skipped this cross-crate integration).
//! 2. Every new public type serializes cleanly across the Tauri IPC
//!    boundary so the frontend can display structured reports.
//! 3. All six primitives can be instantiated, used, and dropped
//!    without panics inside a Tauri command's async context.
//!
//! Invoked from the React side via `invoke("cmd_azure_streaming_smoke_test")`.
//! Returns a `SmokeTestReport` that the UI pretty-prints.
//!
//! Wired: Phase 5 `DataCoverage` + `QuotaLimiter`, Phase 6
//! `InMemoryTokenStorage`, Phase 7 `EnrichmentEngine` + `EnrichmentCache`,
//! Phase 9 `IngestCancelTree` + `OverflowStore`.
//!
//! Not covered (needs real HTTP or Azure creds):
//! - `HttpTokenFetcher` (needs live Azure AD endpoint)
//! - `LogAnalyticsSource` / `DefenderXdrSource` live queries
//! - Full `SourcePoller` cycle (needs persistent WatermarkStore + live source)
//!
//! This file is additive and safe to delete once real Tauri commands
//! land — it has no dependencies outside `graph_hunter_core`.

use async_trait::async_trait;
use bytes::Bytes;
use futures::stream;
use futures::StreamExt;
use serde::Serialize;
use std::sync::Arc;
use std::time::Duration;
use tokio_util::sync::CancellationToken;

use graph_hunter_core::{
    // Core types
    Entity,
    EntityType,
    LogParser,
    ParsedTriple,
    RawIngestEvent,
    Relation,
    RelationType,
    // Ingest primitives
    ParsedBatch,
    Priority,
    // Graph (for EnrichmentEngine's graph_access fixture)
    GraphHunter,
};

// Phase 5: QuotaLimiter
use graph_hunter_core::sources::quota::QuotaLimiter;
// Phase 5: DataCoverage
use graph_hunter_core::ingest::coverage::{DataCoverage, DEFAULT_BUCKET_SECONDS};
// Phase 6: TokenStorage
use graph_hunter_core::sources::token_cache::TokenKey;
use graph_hunter_core::sources::token_storage::{
    InMemoryTokenStorage, StoredToken, TokenStorage,
};
// Phase 7: EnrichmentEngine + cache
use graph_hunter_core::ingest::enrichment::{EnrichmentEngine, EnrichmentRequest};
use graph_hunter_core::ingest::enrichment_cache::EnrichmentCache;
use graph_hunter_core::ingest::graph_access::{GraphAccess, InMemoryGraphAccess};
// Phase 9: cancellation tree + overflow store
use graph_hunter_core::ingest::cancellation::IngestCancelTree;
use graph_hunter_core::ingest::overflow::OverflowStore;
// LogSource trait + types for a mock source
use graph_hunter_core::sources::{
    ChunkEncoding, ChunkStream, EntityRef, LogSource, PollStream, QueryScope, RawChunk,
    SourceError, SourceKind, Watermark,
};

// ---------------------------------------------------------------------------
// Report shape — every primitive gets its own sub-report, pretty-printed
// by the React side.
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize)]
pub struct SmokeTestReport {
    pub overall_ok: bool,
    pub total_duration_ms: u64,
    pub phase_5_data_coverage: DataCoverageReport,
    pub phase_5_quota_limiter: QuotaReport,
    pub phase_6_token_storage: TokenStorageReport,
    pub phase_7_enrichment: EnrichmentReport,
    pub phase_9_cancellation: CancellationReport,
    pub phase_9_overflow: OverflowReport,
    pub errors: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct DataCoverageReport {
    pub ok: bool,
    pub buckets_recorded: usize,
    pub count_in_full_range: u64,
    pub gaps_count: usize,
    pub error: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct QuotaReport {
    pub ok: bool,
    pub capacity: u32,
    pub refill_per_second: f64,
    pub initial_available: f64,
    pub tokens_acquired: u32,
    pub post_drain_available: f64,
    pub penalty_remaining_ms: Option<u64>,
    pub error: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct TokenStorageReport {
    pub ok: bool,
    pub save_ok: bool,
    pub load_matches: bool,
    pub delete_ok: bool,
    pub final_len: usize,
    pub error: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct EnrichmentReport {
    pub ok: bool,
    pub first_call_rows_fetched: usize,
    pub first_call_rows_inserted: usize,
    pub first_call_cache_hit: bool,
    pub second_call_cache_hit: bool,
    pub second_call_source_calls: u32,
    pub error: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct CancellationReport {
    pub ok: bool,
    pub ingest_cancelled_after_source_cancel: bool,
    pub enrichment_affected_by_ingest_cancel: bool,
    pub root_cancel_propagates: bool,
    pub source_count: usize,
    pub error: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct OverflowReport {
    pub ok: bool,
    pub batches_written: usize,
    pub batches_read: usize,
    pub first_batch_source_id: String,
    pub first_batch_triple_count: usize,
    pub consume_ok: bool,
    pub post_consume_count: usize,
    pub error: Option<String>,
}

// ---------------------------------------------------------------------------
// The Tauri command entry point
// ---------------------------------------------------------------------------

/// Phase 5-9 core primitive smoke test. Kept per the file's own
/// "additive and safe to delete once real Tauri commands land"
/// note — real commands have landed (see `sentinel.rs`,
/// `ingestion.rs`), so this command is now cosmetic. It does not
/// delegate through the canonical API because it exercises core
/// primitives directly; migrating it would defeat its purpose as a
/// cross-crate integration check.
#[deprecated(note = "Intended for one-shot smoke testing during Phase 5-9 integration. Real Tauri commands cover production workflows; this command can be removed when the Phase 5-9 audit trail is no longer useful.")]
#[tauri::command]
pub async fn cmd_azure_streaming_smoke_test() -> Result<SmokeTestReport, String> {
    let start = std::time::Instant::now();
    let mut errors: Vec<String> = Vec::new();

    let phase_5_data_coverage = test_data_coverage(&mut errors);
    let phase_5_quota_limiter = test_quota_limiter(&mut errors).await;
    let phase_6_token_storage = test_token_storage(&mut errors).await;
    let phase_7_enrichment = test_enrichment(&mut errors).await;
    let phase_9_cancellation = test_cancellation(&mut errors);
    let phase_9_overflow = test_overflow(&mut errors);

    let overall_ok = errors.is_empty()
        && phase_5_data_coverage.ok
        && phase_5_quota_limiter.ok
        && phase_6_token_storage.ok
        && phase_7_enrichment.ok
        && phase_9_cancellation.ok
        && phase_9_overflow.ok;

    Ok(SmokeTestReport {
        overall_ok,
        total_duration_ms: start.elapsed().as_millis() as u64,
        phase_5_data_coverage,
        phase_5_quota_limiter,
        phase_6_token_storage,
        phase_7_enrichment,
        phase_9_cancellation,
        phase_9_overflow,
        errors,
    })
}

// ---------------------------------------------------------------------------
// Phase 5 — DataCoverage
// ---------------------------------------------------------------------------

fn test_data_coverage(errors: &mut Vec<String>) -> DataCoverageReport {
    let cov = DataCoverage::default();
    // Record 5 events across 5 minute-buckets starting at a minute-aligned
    // timestamp (1_700_000_040 = 28333334 × 60).
    let base = 1_700_000_040_i64;
    for i in 0..5 {
        cov.record("smoke:la", base + i * DEFAULT_BUCKET_SECONDS, 10);
    }
    // Skip a minute to create a gap, then record one more.
    cov.record("smoke:la", base + 10 * DEFAULT_BUCKET_SECONDS, 5);

    let buckets = cov.buckets_in_range("smoke:la", 0, i64::MAX);
    let count = cov.count_in_range("smoke:la", 0, i64::MAX);
    let gaps = cov.gaps(
        "smoke:la",
        base,
        base + 10 * DEFAULT_BUCKET_SECONDS,
    );

    let ok = buckets.len() == 6 && count == 55 && !gaps.is_empty();
    if !ok {
        errors.push(format!(
            "data_coverage: unexpected state (buckets={}, count={}, gaps={})",
            buckets.len(),
            count,
            gaps.len()
        ));
    }

    DataCoverageReport {
        ok,
        buckets_recorded: buckets.len(),
        count_in_full_range: count,
        gaps_count: gaps.len(),
        error: if ok {
            None
        } else {
            Some("see errors array".to_string())
        },
    }
}

// ---------------------------------------------------------------------------
// Phase 5 — QuotaLimiter
// ---------------------------------------------------------------------------

async fn test_quota_limiter(errors: &mut Vec<String>) -> QuotaReport {
    let capacity = 10u32;
    let refill = 1.0_f64;
    let limiter = QuotaLimiter::new(capacity, refill);

    let initial_available = limiter.available();
    let mut acquired = 0u32;
    for _ in 0..capacity {
        if limiter.try_acquire().is_ok() {
            acquired += 1;
        } else {
            break;
        }
    }
    let post_drain = limiter.available();

    // Apply a 2-second penalty so the UI can see penalty_remaining_ms.
    limiter.penalize(Duration::from_secs(2));
    let penalty_ms = limiter.penalty_remaining().map(|d| d.as_millis() as u64);

    let ok = acquired == capacity && post_drain < 1.0 && penalty_ms.is_some();
    if !ok {
        errors.push(format!(
            "quota_limiter: acquired={acquired} post_drain={post_drain} penalty_ms={penalty_ms:?}"
        ));
    }

    QuotaReport {
        ok,
        capacity,
        refill_per_second: refill,
        initial_available,
        tokens_acquired: acquired,
        post_drain_available: post_drain,
        penalty_remaining_ms: penalty_ms,
        error: if ok {
            None
        } else {
            Some("see errors array".to_string())
        },
    }
}

// ---------------------------------------------------------------------------
// Phase 6 — TokenStorage
// ---------------------------------------------------------------------------

async fn test_token_storage(errors: &mut Vec<String>) -> TokenStorageReport {
    let storage = InMemoryTokenStorage::new();
    let key = TokenKey::new("smoke-tenant", "https://api.loganalytics.io/.default");
    let token = StoredToken::new("rt_smoke_abc", 2_000_000_000);

    let save_ok = storage.save(&key, token.clone()).await.is_ok();

    let loaded = match storage.load(&key).await {
        Ok(Some(t)) => Some(t),
        _ => None,
    };
    let load_matches = loaded.as_ref() == Some(&token);

    let delete_ok = storage.delete(&key).await.is_ok();
    let final_len = storage.len();

    let ok = save_ok && load_matches && delete_ok && final_len == 0;
    if !ok {
        errors.push(format!(
            "token_storage: save={save_ok} load_matches={load_matches} delete={delete_ok} final_len={final_len}"
        ));
    }

    TokenStorageReport {
        ok,
        save_ok,
        load_matches,
        delete_ok,
        final_len,
        error: if ok {
            None
        } else {
            Some("see errors array".to_string())
        },
    }
}

// ---------------------------------------------------------------------------
// Phase 7 — EnrichmentEngine
// ---------------------------------------------------------------------------

async fn test_enrichment(errors: &mut Vec<String>) -> EnrichmentReport {
    let graph = GraphHunter::new();
    let access: Arc<dyn GraphAccess> = Arc::new(InMemoryGraphAccess::new(graph));
    let cache = Arc::new(EnrichmentCache::default());
    let parser: Arc<dyn LogParser> = Arc::new(SmokeParser {
        triples_per_call: 3,
    });
    let engine = EnrichmentEngine::new(cache, access, parser);

    let source = Arc::new(SmokeSource::new("smoke:la"));
    let sources: Vec<Arc<dyn LogSource>> = vec![source.clone()];

    let req = EnrichmentRequest::new(
        EntityRef {
            entity_type: "IpAddress".to_string(),
            value: "10.0.0.1".to_string(),
        },
        (1_700_000_000_000, 1_700_086_400_000),
    );

    let now_1 = 1_700_000_500;
    let result_1 = match engine
        .enrich(
            req.clone(),
            sources.clone(),
            now_1,
            CancellationToken::new(),
        )
        .await
    {
        Ok(r) => r,
        Err(e) => {
            errors.push(format!("enrichment first call: {e}"));
            return failed_enrichment(Some(e.to_string()));
        }
    };
    let first_call_rows_fetched = result_1.total_rows_fetched;
    let first_call_rows_inserted = result_1.total_rows_inserted;
    let first_call_cache_hit = result_1
        .per_source
        .first()
        .map(|s| s.cache_hit)
        .unwrap_or(false);

    // Second call within TTL — must hit the cache, not the source.
    let calls_before_second = source.call_count();
    let now_2 = 1_700_000_700;
    let result_2 = match engine
        .enrich(req, sources, now_2, CancellationToken::new())
        .await
    {
        Ok(r) => r,
        Err(e) => {
            errors.push(format!("enrichment second call: {e}"));
            return failed_enrichment(Some(e.to_string()));
        }
    };
    let second_call_cache_hit = result_2
        .per_source
        .first()
        .map(|s| s.cache_hit)
        .unwrap_or(false);
    let second_call_source_calls = source.call_count() - calls_before_second;

    let ok = first_call_rows_fetched == 3
        && first_call_rows_inserted == 3
        && !first_call_cache_hit
        && second_call_cache_hit
        && second_call_source_calls == 0;
    if !ok {
        errors.push(format!(
            "enrichment: fetch={first_call_rows_fetched} insert={first_call_rows_inserted} \
             first_hit={first_call_cache_hit} second_hit={second_call_cache_hit} \
             source_calls_delta={second_call_source_calls}"
        ));
    }

    EnrichmentReport {
        ok,
        first_call_rows_fetched,
        first_call_rows_inserted,
        first_call_cache_hit,
        second_call_cache_hit,
        second_call_source_calls,
        error: if ok {
            None
        } else {
            Some("see errors array".to_string())
        },
    }
}

fn failed_enrichment(err: Option<String>) -> EnrichmentReport {
    EnrichmentReport {
        ok: false,
        first_call_rows_fetched: 0,
        first_call_rows_inserted: 0,
        first_call_cache_hit: false,
        second_call_cache_hit: false,
        second_call_source_calls: 0,
        error: err,
    }
}

// ---------------------------------------------------------------------------
// Phase 9 — IngestCancelTree
// ---------------------------------------------------------------------------

fn test_cancellation(errors: &mut Vec<String>) -> CancellationReport {
    let tree = IngestCancelTree::new();

    let la = tree.source("smoke:la");
    let xdr = tree.source("smoke:xdr");
    let enrichment = tree.enrichment();

    // Cancel the ingest branch — should fire both source tokens but
    // leave enrichment alone.
    tree.cancel_ingest();
    let ingest_cancelled_after_source_cancel = la.is_cancelled() && xdr.is_cancelled();
    let enrichment_affected_by_ingest_cancel = enrichment.is_cancelled();

    // Cancel the root — everything fires.
    let hunt = tree.hunt();
    tree.cancel_all();
    let root_cancel_propagates =
        tree.is_cancelled() && enrichment.is_cancelled() && hunt.is_cancelled();

    let source_count = tree.source_count();

    let ok = ingest_cancelled_after_source_cancel
        && !enrichment_affected_by_ingest_cancel
        && root_cancel_propagates;
    if !ok {
        errors.push(format!(
            "cancellation: ingest_affect={ingest_cancelled_after_source_cancel} \
             enrich_affect={enrichment_affected_by_ingest_cancel} \
             root_cancel={root_cancel_propagates}"
        ));
    }

    CancellationReport {
        ok,
        ingest_cancelled_after_source_cancel,
        enrichment_affected_by_ingest_cancel,
        root_cancel_propagates,
        source_count,
        error: if ok {
            None
        } else {
            Some("see errors array".to_string())
        },
    }
}

// ---------------------------------------------------------------------------
// Phase 9 — OverflowStore
// ---------------------------------------------------------------------------

fn test_overflow(errors: &mut Vec<String>) -> OverflowReport {
    let tmp = match tempfile::tempdir() {
        Ok(t) => t,
        Err(e) => {
            errors.push(format!("overflow: tempdir: {e}"));
            return failed_overflow(Some(e.to_string()));
        }
    };
    let store = match OverflowStore::open(tmp.path()) {
        Ok(s) => s,
        Err(e) => {
            errors.push(format!("overflow: open: {e}"));
            return failed_overflow(Some(e.to_string()));
        }
    };

    // Write two batches.
    let batch_a = ParsedBatch::new(
        "smoke:la",
        vec![
            mk_smoke_triple("alice", "proc-a", 100),
            mk_smoke_triple("alice", "proc-b", 200),
        ],
    )
    .with_dataset_id("smoke-dataset")
    .with_priority(Priority::Normal);

    let batch_b = ParsedBatch::new(
        "smoke:xdr",
        vec![mk_smoke_triple("bob", "proc-c", 300)],
    );

    if let Err(e) = store.write_batch(&batch_a) {
        errors.push(format!("overflow: write_batch a: {e}"));
        return failed_overflow(Some(e.to_string()));
    }
    if let Err(e) = store.write_batch(&batch_b) {
        errors.push(format!("overflow: write_batch b: {e}"));
        return failed_overflow(Some(e.to_string()));
    }

    let batches_written = match store.pending_count() {
        Ok(n) => n,
        Err(e) => {
            errors.push(format!("overflow: pending_count: {e}"));
            return failed_overflow(Some(e.to_string()));
        }
    };

    let pending = match store.read_pending() {
        Ok(p) => p,
        Err(e) => {
            errors.push(format!("overflow: read_pending: {e}"));
            return failed_overflow(Some(e.to_string()));
        }
    };
    let batches_read = pending.len();
    let first = pending.first();
    let first_source_id = first
        .map(|(_, b)| b.source_id.clone())
        .unwrap_or_default();
    let first_triple_count = first.map(|(_, b)| b.events.len()).unwrap_or(0);

    // Consume the first batch.
    let consume_ok = if let Some((path, _)) = pending.first() {
        store.consume_batch(path).is_ok()
    } else {
        false
    };
    let post_consume_count = store.pending_count().unwrap_or(9999);

    let ok = batches_written == 2
        && batches_read == 2
        && first_source_id == "smoke:la"
        && first_triple_count == 2
        && consume_ok
        && post_consume_count == 1;
    if !ok {
        errors.push(format!(
            "overflow: written={batches_written} read={batches_read} \
             first_src={first_source_id} first_triples={first_triple_count} \
             consume={consume_ok} post={post_consume_count}"
        ));
    }

    OverflowReport {
        ok,
        batches_written,
        batches_read,
        first_batch_source_id: first_source_id,
        first_batch_triple_count: first_triple_count,
        consume_ok,
        post_consume_count,
        error: if ok {
            None
        } else {
            Some("see errors array".to_string())
        },
    }
}

fn failed_overflow(err: Option<String>) -> OverflowReport {
    OverflowReport {
        ok: false,
        batches_written: 0,
        batches_read: 0,
        first_batch_source_id: String::new(),
        first_batch_triple_count: 0,
        consume_ok: false,
        post_consume_count: 0,
        error: err,
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn mk_smoke_triple(src_id: &str, dst_id: &str, ts: i64) -> RawIngestEvent {
    use std::collections::HashMap;
    RawIngestEvent {
        src_id: src_id.to_string(),
        src_type: EntityType::User,
        src_metadata: HashMap::new(),
        dst_id: dst_id.to_string(),
        dst_type: EntityType::Process,
        dst_metadata: HashMap::new(),
        rel_type: RelationType::Auth,
        rel_metadata: HashMap::new(),
        timestamp: ts,
    }
}

/// A parser that emits a fixed number of deterministic triples per call.
struct SmokeParser {
    triples_per_call: usize,
}

impl LogParser for SmokeParser {
    fn parse(&self, _data: &str) -> Vec<ParsedTriple> {
        (0..self.triples_per_call)
            .map(|i| {
                (
                    Entity::new(format!("smoke-u-{i}"), EntityType::User),
                    Relation::new(
                        format!("smoke-u-{i}"),
                        format!("smoke-p-{i}"),
                        RelationType::Auth,
                        100 + i as i64,
                    ),
                    Entity::new(format!("smoke-p-{i}"), EntityType::Process),
                )
            })
            .collect()
    }

    fn parse_raw(&self, _data: &str) -> Vec<RawIngestEvent> {
        (0..self.triples_per_call)
            .map(|i| mk_smoke_triple(&format!("smoke-u-{i}"), &format!("smoke-p-{i}"), 100 + i as i64))
            .collect()
    }
}

/// A `LogSource` that emits one canned chunk per `query_scoped` call
/// and counts how many times it's been called. No HTTP, no Azure.
struct SmokeSource {
    id: String,
    tables: Vec<&'static str>,
    calls: std::sync::Mutex<u32>,
}

impl SmokeSource {
    fn new(id: impl Into<String>) -> Self {
        Self {
            id: id.into(),
            tables: vec!["SecurityEvent"],
            calls: std::sync::Mutex::new(0),
        }
    }

    fn call_count(&self) -> u32 {
        *self.calls.lock().unwrap()
    }
}

#[async_trait]
impl LogSource for SmokeSource {
    fn source_id(&self) -> &str {
        &self.id
    }

    fn kind(&self) -> SourceKind {
        SourceKind::LogAnalytics
    }

    fn available_tables(&self) -> &[&'static str] {
        &self.tables
    }

    async fn check_auth(&self) -> Result<(), SourceError> {
        Ok(())
    }

    async fn query_scoped(
        &self,
        _scope: QueryScope,
        _cancel: CancellationToken,
    ) -> Result<ChunkStream, SourceError> {
        *self.calls.lock().unwrap() += 1;
        let chunk = RawChunk {
            source_id: self.id.clone(),
            table: "SecurityEvent".to_string(),
            rows: Bytes::from_static(b"{}"),
            encoding: ChunkEncoding::Json,
            fetched_at: 1_700_000_000,
            watermark_candidate: None,
        };
        Ok(stream::iter(vec![Ok(chunk)]).boxed())
    }

    async fn poll_since(
        &self,
        _table: &str,
        _watermark: Watermark,
        _cancel: CancellationToken,
    ) -> Result<PollStream, SourceError> {
        Ok(stream::iter(vec![]).boxed())
    }
}
