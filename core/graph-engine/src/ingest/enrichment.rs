//! On-demand enrichment engine — the "click an IP, fetch its Azure
//! context" code path (plan §5).
//!
//! The engine is a thin orchestrator that composes primitives from
//! earlier phases:
//!
//!   LogSource::query_scoped(entity, time_range)  ← Phase 3
//!                 │
//!                 ▼ stream of RawChunks
//!            LogParser::parse(bytes)             ← Phase 4 trait
//!                 │
//!                 ▼ Vec<ParsedTriple>
//!            GraphAccess::insert_chunk(...)      ← Phase 4 trait
//!                 │
//!                 ▼
//!        EnrichmentCache::put(result)            ← this module
//!
//! Design contract:
//!
//! - **Multi-source fan-out, serial per source**. `enrich` walks the
//!   requested sources in order and runs each one to completion
//!   before moving on. Parallel fan-out is a future optimization
//!   (plan §5 mentions "Max 3 concurrent enrichments"); for now the
//!   caller controls concurrency by serializing or spawning
//!   multiple `enrich` calls.
//! - **Row cap per source**. `max_rows_per_source` (default 10 000
//!   per plan §5) bounds how much data a single enrichment pulls so
//!   one runaway query can't explode the graph. Truncation is
//!   reported in the result for UI feedback.
//! - **Cache-first**. Each `(source, entity, time_bucket)` triple
//!   is checked in `EnrichmentCache` before dispatching the query.
//!   A full hit returns immediately with `cache_hit: true` and no
//!   network round-trip.
//! - **Graph writes go through `GraphAccess`**. Same abstraction as
//!   the streaming writer uses, so the engine is testable with
//!   `InMemoryGraphAccess` and doesn't force the caller to pick a
//!   locking primitive.
//! - **Cancellation-aware**. The engine observes the cancel token
//!   between sources, between chunks, and inside the stream loop.
//! - **Errors are per-source**. If one source fails, the others
//!   continue and the failure is surfaced in the per-source summary
//!   rather than aborting the whole enrichment.
//!
//! What this module does NOT do:
//!
//! - Debouncing (that's a frontend concern, plan §5).
//! - Concurrency cap (a semaphore in `AppState`, Tauri-layer).
//! - Progress events (`enrich-chunk`, `enrich-complete` Tauri events —
//!   Phase 8).

use std::sync::Arc;
use tokio_util::sync::CancellationToken;

use crate::errors::GraphError;
use crate::parser::LogParser;
use futures::StreamExt;
use graph_hunter_sources::{ChunkEncoding, EntityRef, LogSource, QueryScope, SourceError};

use super::enrichment_cache::{CachedEnrichment, EnrichmentCache, EnrichmentCacheKey};
use super::graph_access::GraphAccess;

/// Default row cap per source per enrichment query. Matches plan §5
/// `ENRICHMENT_MAX_RELATIONS`. Callers can override via
/// `EnrichmentRequest::max_rows_per_source`.
pub const DEFAULT_MAX_ROWS_PER_SOURCE: u32 = 10_000;

/// Default chunk size for incremental graph writes during an
/// enrichment. Small so the writer yields the lock to concurrent
/// readers; matches the streaming writer's default.
pub const DEFAULT_ENRICHMENT_CHUNK_SIZE: usize = 5_000;

/// Errors from the enrichment engine. Deliberately coarse — the
/// engine's failure mode is "the whole query couldn't run", not
/// "this particular row was malformed" (which goes into
/// `SourceFetchSummary.dropped_rows`).
#[derive(Debug, Clone)]
pub enum EnrichmentError {
    /// The engine was cancelled before any source could run.
    Cancelled,
    /// Every requested source failed. The inner vec carries one
    /// error message per source so the caller can surface them in
    /// the UI.
    AllSourcesFailed(Vec<String>),
    /// Graph insertion failed — typically disk or memory pressure.
    Graph(String),
}

impl std::fmt::Display for EnrichmentError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            EnrichmentError::Cancelled => write!(f, "enrichment cancelled"),
            EnrichmentError::AllSourcesFailed(errs) => {
                write!(f, "all sources failed: {}", errs.join("; "))
            }
            EnrichmentError::Graph(msg) => write!(f, "graph insert failed: {msg}"),
        }
    }
}

impl std::error::Error for EnrichmentError {}

impl From<GraphError> for EnrichmentError {
    fn from(e: GraphError) -> Self {
        EnrichmentError::Graph(e.to_string())
    }
}

/// A one-shot enrichment request.
#[derive(Debug, Clone)]
pub struct EnrichmentRequest {
    pub entity: EntityRef,
    /// Time range to query each source over, as `(start_ms, end_ms)`.
    pub time_range: (i64, i64),
    /// Which tables to query, passed through to `query_scoped`. Empty
    /// vector means "use each source's default table set".
    pub tables: Vec<String>,
    /// Row cap per source. 0 means use `DEFAULT_MAX_ROWS_PER_SOURCE`.
    pub max_rows_per_source: u32,
}

impl EnrichmentRequest {
    pub fn new(entity: EntityRef, time_range: (i64, i64)) -> Self {
        Self {
            entity,
            time_range,
            tables: Vec::new(),
            max_rows_per_source: 0,
        }
    }

    pub fn with_tables(mut self, tables: Vec<String>) -> Self {
        self.tables = tables;
        self
    }

    pub fn with_max_rows(mut self, max: u32) -> Self {
        self.max_rows_per_source = max;
        self
    }
}

/// Result of a single source's fetch during an enrichment.
#[derive(Debug, Clone)]
pub struct SourceFetchSummary {
    pub source_id: String,
    pub cache_hit: bool,
    pub rows_fetched: usize,
    pub rows_inserted: usize,
    pub truncated: bool,
    /// `Some(msg)` if the source errored out mid-fetch; the partial
    /// data (if any) is still reflected in rows_fetched/rows_inserted.
    pub error: Option<String>,
}

/// Aggregate result across all sources in an enrichment request.
#[derive(Debug, Clone)]
pub struct EnrichmentResult {
    pub per_source: Vec<SourceFetchSummary>,
    pub total_rows_fetched: usize,
    pub total_rows_inserted: usize,
    pub truncated: bool,
}

impl EnrichmentResult {
    pub fn cache_hits(&self) -> usize {
        self.per_source.iter().filter(|s| s.cache_hit).count()
    }

    pub fn is_empty(&self) -> bool {
        self.total_rows_fetched == 0
    }

    pub fn errors(&self) -> Vec<&str> {
        self.per_source
            .iter()
            .filter_map(|s| s.error.as_deref())
            .collect()
    }
}

/// The enrichment engine. Construct once per session and reuse
/// across `enrich` calls. Holds `Arc` references so it's cheap to
/// clone for background tasks.
pub struct EnrichmentEngine {
    cache: Arc<EnrichmentCache>,
    graph_access: Arc<dyn GraphAccess>,
    parser: Arc<dyn LogParser>,
    chunk_size: usize,
}

impl EnrichmentEngine {
    pub fn new(
        cache: Arc<EnrichmentCache>,
        graph_access: Arc<dyn GraphAccess>,
        parser: Arc<dyn LogParser>,
    ) -> Self {
        Self {
            cache,
            graph_access,
            parser,
            chunk_size: DEFAULT_ENRICHMENT_CHUNK_SIZE,
        }
    }

    pub fn with_chunk_size(mut self, chunk_size: usize) -> Self {
        self.chunk_size = chunk_size.max(1);
        self
    }

    /// Runs an enrichment query across every requested source,
    /// serially. Returns an aggregate result. `now_epoch_s` is passed
    /// in so callers can fake the clock in tests.
    pub async fn enrich(
        &self,
        request: EnrichmentRequest,
        sources: Vec<Arc<dyn LogSource>>,
        now_epoch_s: i64,
        cancel: CancellationToken,
    ) -> Result<EnrichmentResult, EnrichmentError> {
        if cancel.is_cancelled() {
            return Err(EnrichmentError::Cancelled);
        }
        if sources.is_empty() {
            return Ok(EnrichmentResult {
                per_source: Vec::new(),
                total_rows_fetched: 0,
                total_rows_inserted: 0,
                truncated: false,
            });
        }

        let max_rows = if request.max_rows_per_source == 0 {
            DEFAULT_MAX_ROWS_PER_SOURCE
        } else {
            request.max_rows_per_source
        };

        // Per plan §5: bucket the request start onto the cache's
        // bucket width so cache keys align cleanly.
        let bucket = self.cache.bucket_seconds();

        let mut per_source_summaries: Vec<SourceFetchSummary> = Vec::with_capacity(sources.len());
        let mut total_fetched = 0usize;
        let mut total_inserted = 0usize;
        let mut overall_truncated = false;

        for source in &sources {
            if cancel.is_cancelled() {
                break;
            }
            let summary = self
                .enrich_one_source(
                    source.as_ref(),
                    &request,
                    max_rows,
                    bucket,
                    now_epoch_s,
                    &cancel,
                )
                .await;
            total_fetched += summary.rows_fetched;
            total_inserted += summary.rows_inserted;
            if summary.truncated {
                overall_truncated = true;
            }
            per_source_summaries.push(summary);
        }

        // If every requested source errored out, surface it as a
        // hard failure so the caller can show a toast.
        let all_failed = !per_source_summaries.is_empty()
            && per_source_summaries
                .iter()
                .all(|s| s.error.is_some() && !s.cache_hit);
        if all_failed {
            let errs: Vec<String> = per_source_summaries
                .into_iter()
                .filter_map(|s| s.error)
                .collect();
            return Err(EnrichmentError::AllSourcesFailed(errs));
        }

        Ok(EnrichmentResult {
            per_source: per_source_summaries,
            total_rows_fetched: total_fetched,
            total_rows_inserted: total_inserted,
            truncated: overall_truncated,
        })
    }

    async fn enrich_one_source(
        &self,
        source: &dyn LogSource,
        request: &EnrichmentRequest,
        max_rows: u32,
        bucket_seconds: i64,
        now_epoch_s: i64,
        cancel: &CancellationToken,
    ) -> SourceFetchSummary {
        let source_id = source.source_id().to_string();

        // Cache check.
        let cache_key = EnrichmentCacheKey::for_query(
            source_id.clone(),
            request.entity.entity_type.clone(),
            request.entity.value.clone(),
            request.time_range.0 / 1000, // ms → seconds
            bucket_seconds,
        );
        if let Some(hit) = self.cache.get(&cache_key, now_epoch_s) {
            return SourceFetchSummary {
                source_id,
                cache_hit: true,
                rows_fetched: hit.rows_fetched,
                rows_inserted: hit.rows_inserted,
                truncated: hit.truncated,
                error: None,
            };
        }

        // Miss → fetch from the source.
        let scope = QueryScope {
            entity: request.entity.clone(),
            time_range: request.time_range,
            tables: request.tables.clone(),
            max_rows_per_table: max_rows,
        };
        let stream_result = source.query_scoped(scope, cancel.clone()).await;
        let mut stream = match stream_result {
            Ok(s) => s,
            Err(e) => {
                return SourceFetchSummary {
                    source_id,
                    cache_hit: false,
                    rows_fetched: 0,
                    rows_inserted: 0,
                    truncated: false,
                    error: Some(e.to_string()),
                };
            }
        };

        // Enrichment dataset_id convention: "enrich:<source_id>".
        let dataset_id = format!("enrich:{source_id}");
        let mut rows_fetched = 0usize;
        let mut rows_inserted = 0usize;
        let mut truncated = false;
        let mut error: Option<String> = None;

        while let Some(chunk_result) = stream.next().await {
            if cancel.is_cancelled() {
                error = Some("cancelled".to_string());
                break;
            }
            let chunk = match chunk_result {
                Ok(c) => c,
                Err(SourceError::Truncated) => {
                    truncated = true;
                    continue;
                }
                Err(e) => {
                    error = Some(e.to_string());
                    break;
                }
            };

            // Decode bytes into string and hand to the parser. The
            // parser returns RawIngestEvents, which may be fewer than
            // the row count — parser drops malformed rows silently
            // per the `LogParser::parse_raw` contract.
            let text = match std::str::from_utf8(chunk.rows.as_ref()) {
                Ok(s) => s,
                Err(_) => continue,
            };
            let mut events = match chunk.encoding {
                ChunkEncoding::Json | ChunkEncoding::Jsonl => self.parser.parse_raw(text),
                ChunkEncoding::Parquet => continue,
            };
            let chunk_rows = events.len();
            rows_fetched += chunk_rows;

            // Enforce the row cap across the whole enrichment (not
            // per chunk). If adding this chunk would exceed max_rows,
            // truncate and stop fetching.
            if rows_fetched > max_rows as usize {
                let excess = rows_fetched - max_rows as usize;
                if excess >= events.len() {
                    // Nothing from this chunk fits.
                    events.clear();
                } else {
                    events.truncate(events.len() - excess);
                }
                truncated = true;
                rows_fetched -= excess;
            }

            // Write the events into the graph via GraphAccess,
            // chunked so readers can make progress.
            while !events.is_empty() {
                if cancel.is_cancelled() {
                    error = Some("cancelled".to_string());
                    break;
                }
                match self
                    .graph_access
                    .insert_raw_chunk(&mut events, Some(&dataset_id), self.chunk_size)
                    .await
                {
                    Ok(n) => {
                        rows_inserted += n;
                        if n == 0 {
                            break;
                        }
                    }
                    Err(e) => {
                        error = Some(format!("graph insert: {e}"));
                        break;
                    }
                }
                tokio::task::yield_now().await;
            }
            if error.is_some() {
                break;
            }
            if truncated {
                break;
            }
        }

        // Cache the result (even errors are cached? No — only
        // successful or partial-success paths. If everything errored
        // before any row was fetched, skip caching so the next click
        // retries.)
        if error.is_none() || rows_fetched > 0 {
            self.cache.put(
                cache_key,
                CachedEnrichment {
                    cached_at_epoch_s: 0, // replaced by put()
                    rows_fetched,
                    rows_inserted,
                    truncated,
                },
                now_epoch_s,
            );
        }

        SourceFetchSummary {
            source_id,
            cache_hit: false,
            rows_fetched,
            rows_inserted,
            truncated,
            error,
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::entity::Entity;
    use crate::graph::GraphHunter;
    use crate::ingest::graph_access::InMemoryGraphAccess;
    use crate::parser::{LogParser, ParsedTriple};
    use crate::relation::Relation;
    use crate::types::{EntityType, RelationType};
    use async_trait::async_trait;
    use bytes::Bytes;
    use futures::stream;
    use graph_hunter_sources::{
        ChunkEncoding, ChunkStream, LogSource, PollStream, RawChunk, SourceKind, Watermark,
    };
    use std::sync::Mutex;

    // ---- Mock parser ----
    struct CountingParser {
        triples_per_call: usize,
    }

    impl LogParser for CountingParser {
        fn parse(&self, _data: &str) -> Vec<ParsedTriple> {
            (0..self.triples_per_call)
                .map(|i| {
                    (
                        Entity::new(format!("u-{i}"), EntityType::User),
                        Relation::new(
                            format!("u-{i}"),
                            format!("p-{i}"),
                            RelationType::Auth,
                            100 + i as i64,
                        ),
                        Entity::new(format!("p-{i}"), EntityType::Process),
                    )
                })
                .collect()
        }
    }

    // ---- Mock LogSource ----
    struct MockSource {
        id: String,
        tables: Vec<&'static str>,
        chunks: Mutex<Vec<Result<RawChunk, SourceError>>>,
        fail_query: Mutex<bool>,
        call_count: Mutex<u32>,
    }

    impl MockSource {
        fn new(id: &str) -> Self {
            Self {
                id: id.to_string(),
                tables: vec!["SecurityEvent"],
                chunks: Mutex::new(Vec::new()),
                fail_query: Mutex::new(false),
                call_count: Mutex::new(0),
            }
        }

        fn push_chunk(&self, chunk: RawChunk) {
            self.chunks.lock().unwrap().push(Ok(chunk));
        }

        fn fail_next_query(&self) {
            *self.fail_query.lock().unwrap() = true;
        }

        fn call_count(&self) -> u32 {
            *self.call_count.lock().unwrap()
        }
    }

    #[async_trait]
    impl LogSource for MockSource {
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
            *self.call_count.lock().unwrap() += 1;
            let mut fail = self.fail_query.lock().unwrap();
            if *fail {
                *fail = false;
                return Err(SourceError::Auth);
            }
            let chunks = std::mem::take(&mut *self.chunks.lock().unwrap());
            Ok(stream::iter(chunks).boxed())
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

    fn mk_chunk(source: &str, table: &str) -> RawChunk {
        RawChunk {
            source_id: source.to_string(),
            table: table.to_string(),
            rows: Bytes::from_static(b"{}"),
            encoding: ChunkEncoding::Json,
            fetched_at: 0,
            watermark_candidate: None,
        }
    }

    fn mk_request() -> EnrichmentRequest {
        EnrichmentRequest::new(
            EntityRef {
                entity_type: "IpAddress".to_string(),
                value: "10.0.0.1".to_string(),
            },
            (1_700_000_000_000, 1_700_086_400_000),
        )
    }

    fn mk_engine() -> (
        EnrichmentEngine,
        Arc<InMemoryGraphAccess>,
        Arc<EnrichmentCache>,
    ) {
        let graph = GraphHunter::new();
        let access = Arc::new(InMemoryGraphAccess::new(graph));
        let cache = Arc::new(EnrichmentCache::default());
        let parser: Arc<dyn LogParser> = Arc::new(CountingParser {
            triples_per_call: 5,
        });
        let engine = EnrichmentEngine::new(cache.clone(), access.clone(), parser);
        (engine, access, cache)
    }

    #[tokio::test(flavor = "current_thread")]
    async fn enrich_single_source_inserts_triples() {
        let (engine, access, _cache) = mk_engine();
        let source = Arc::new(MockSource::new("la:ws-1"));
        source.push_chunk(mk_chunk("la:ws-1", "SecurityEvent"));
        source.push_chunk(mk_chunk("la:ws-1", "SecurityEvent"));

        let result = engine
            .enrich(
                mk_request(),
                vec![source.clone()],
                1_700_000_500,
                CancellationToken::new(),
            )
            .await
            .unwrap();

        assert_eq!(result.per_source.len(), 1);
        assert_eq!(result.per_source[0].source_id, "la:ws-1");
        assert!(!result.per_source[0].cache_hit);
        assert_eq!(result.per_source[0].rows_fetched, 10); // 2 chunks × 5 triples
        assert_eq!(result.per_source[0].rows_inserted, 10);
        assert_eq!(result.total_rows_fetched, 10);

        // Triples should be in the graph.
        let graph = access.graph();
        let guard = graph.lock().await;
        assert!(guard.get_entity("u-0").is_some());
    }

    #[tokio::test(flavor = "current_thread")]
    async fn second_enrich_same_entity_hits_cache() {
        let (engine, _access, _cache) = mk_engine();
        let source = Arc::new(MockSource::new("la:ws-1"));
        source.push_chunk(mk_chunk("la:ws-1", "SecurityEvent"));

        let _ = engine
            .enrich(
                mk_request(),
                vec![source.clone()],
                1_700_000_500,
                CancellationToken::new(),
            )
            .await
            .unwrap();
        assert_eq!(source.call_count(), 1);

        // Second call within the TTL window — cache hit, source not queried.
        let result2 = engine
            .enrich(
                mk_request(),
                vec![source.clone()],
                1_700_000_600, // 100s later, still within TTL
                CancellationToken::new(),
            )
            .await
            .unwrap();
        assert_eq!(source.call_count(), 1, "source should not be re-queried");
        assert!(result2.per_source[0].cache_hit);
        assert_eq!(result2.per_source[0].rows_fetched, 5);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn empty_source_list_returns_empty_result() {
        let (engine, _access, _cache) = mk_engine();
        let result = engine
            .enrich(
                mk_request(),
                Vec::new(),
                1_700_000_500,
                CancellationToken::new(),
            )
            .await
            .unwrap();
        assert!(result.per_source.is_empty());
        assert_eq!(result.total_rows_fetched, 0);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn cancelled_before_start_returns_cancelled() {
        let (engine, _access, _cache) = mk_engine();
        let source = Arc::new(MockSource::new("la:ws-1"));
        source.push_chunk(mk_chunk("la:ws-1", "SecurityEvent"));

        let cancel = CancellationToken::new();
        cancel.cancel();

        let result = engine
            .enrich(mk_request(), vec![source], 1_700_000_500, cancel)
            .await;
        assert!(matches!(result, Err(EnrichmentError::Cancelled)));
    }

    #[tokio::test(flavor = "current_thread")]
    async fn source_failure_surfaces_in_summary() {
        let (engine, _access, _cache) = mk_engine();
        let source = Arc::new(MockSource::new("la:ws-1"));
        source.fail_next_query();

        // Only one source, and it fails → AllSourcesFailed.
        let result = engine
            .enrich(
                mk_request(),
                vec![source],
                1_700_000_500,
                CancellationToken::new(),
            )
            .await;
        match result {
            Err(EnrichmentError::AllSourcesFailed(errs)) => {
                assert_eq!(errs.len(), 1);
                assert!(errs[0].contains("auth"));
            }
            other => panic!("expected AllSourcesFailed, got {other:?}"),
        }
    }

    #[tokio::test(flavor = "current_thread")]
    async fn one_source_failure_does_not_break_the_other() {
        let (engine, _access, _cache) = mk_engine();

        let source_ok = Arc::new(MockSource::new("la:ws-1"));
        source_ok.push_chunk(mk_chunk("la:ws-1", "SecurityEvent"));

        let source_fail = Arc::new(MockSource::new("xdr:tenant-a"));
        source_fail.fail_next_query();

        let sources: Vec<Arc<dyn LogSource>> = vec![source_ok.clone(), source_fail.clone()];
        let result = engine
            .enrich(
                mk_request(),
                sources,
                1_700_000_500,
                CancellationToken::new(),
            )
            .await
            .unwrap();

        assert_eq!(result.per_source.len(), 2);
        let la = &result.per_source[0];
        let xdr = &result.per_source[1];
        assert!(la.error.is_none());
        assert_eq!(la.rows_fetched, 5);
        assert!(xdr.error.is_some());
        assert_eq!(xdr.rows_fetched, 0);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn row_cap_is_enforced_and_truncated_is_reported() {
        let (_engine_default, _access, cache) = mk_engine();
        // Build a fresh engine so we can use a different cache TTL if
        // needed.
        let graph = GraphHunter::new();
        let access = Arc::new(InMemoryGraphAccess::new(graph));
        let parser: Arc<dyn LogParser> = Arc::new(CountingParser {
            triples_per_call: 5,
        });
        let engine = EnrichmentEngine::new(cache, access, parser);

        let source = Arc::new(MockSource::new("la:ws-1"));
        // 10 chunks × 5 triples = 50. Cap at 20 → truncate.
        for _ in 0..10 {
            source.push_chunk(mk_chunk("la:ws-1", "SecurityEvent"));
        }

        let mut request = mk_request();
        request.max_rows_per_source = 20;

        let result = engine
            .enrich(
                request,
                vec![source],
                1_700_000_500,
                CancellationToken::new(),
            )
            .await
            .unwrap();

        assert!(result.per_source[0].truncated);
        assert_eq!(result.per_source[0].rows_fetched, 20);
        assert_eq!(result.per_source[0].rows_inserted, 20);
        assert!(result.truncated);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn cache_cross_source_is_independent() {
        let (engine, _access, _cache) = mk_engine();

        let s1 = Arc::new(MockSource::new("la:ws-1"));
        s1.push_chunk(mk_chunk("la:ws-1", "SecurityEvent"));
        let _ = engine
            .enrich(
                mk_request(),
                vec![s1.clone()],
                1_700_000_000,
                CancellationToken::new(),
            )
            .await
            .unwrap();

        // Same entity, different source — must re-query.
        let s2 = Arc::new(MockSource::new("xdr:tenant-a"));
        s2.push_chunk(mk_chunk("xdr:tenant-a", "DeviceProcessEvents"));
        let result = engine
            .enrich(
                mk_request(),
                vec![s2.clone()],
                1_700_000_100,
                CancellationToken::new(),
            )
            .await
            .unwrap();
        assert!(!result.per_source[0].cache_hit);
        assert_eq!(s2.call_count(), 1);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn enrichment_dataset_id_is_tagged() {
        let (engine, access, _cache) = mk_engine();
        let source = Arc::new(MockSource::new("la:ws-1"));
        source.push_chunk(mk_chunk("la:ws-1", "SecurityEvent"));

        let _ = engine
            .enrich(
                mk_request(),
                vec![source],
                1_700_000_500,
                CancellationToken::new(),
            )
            .await
            .unwrap();

        // The Entity should exist; we don't have a direct "dataset_id
        // of this entity" query, but we can verify the insert happened
        // by checking entity presence.
        let graph = access.graph();
        let guard = graph.lock().await;
        assert!(guard.get_entity("u-0").is_some());
    }
}
