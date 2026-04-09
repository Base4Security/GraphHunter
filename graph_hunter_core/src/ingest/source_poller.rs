//! The long-lived `SourcePoller` that drives `LogSource::poll_since` on
//! a timer and forwards chunks into the raw channel, advancing a
//! persistent watermark as it goes.
//!
//! One poller runs per source instance. On each iteration it:
//!
//! 1. Loads the current watermark for each configured table from the
//!    `WatermarkStore`.
//! 2. Calls `source.poll_since(table, watermark, cancel)` to get a
//!    `PollStream`.
//! 3. Forwards every `(RawChunk, new_watermark)` pair into `raw_tx`.
//! 4. On successful forward, persists the new watermark via
//!    `WatermarkStore::set`.
//! 5. Sleeps `poll_interval` between cycles (interruptible by cancel).
//!
//! Design notes:
//!
//! - **Single raw channel, round-robin tables.** The poller round-
//!   robins through `config.tables` each cycle, sending every table's
//!   chunks into the same shared raw channel. Per-table fairness is
//!   approximate — a very hot table can stall the cycle briefly while
//!   the writer drains — but this is acceptable because the channel is
//!   bounded and backpressure eventually halts the polling cycle.
//! - **Watermark persistence is the poller's job, not the writer's.**
//!   The writer acks by implicit FIFO ordering on the channel. Once
//!   `raw_tx.send(...).await` returns, the chunk is at least queued.
//!   If the process crashes between the send and the watermark update,
//!   the next startup re-polls from the old watermark and potentially
//!   re-ingests a few rows — the graph insertion is idempotent at the
//!   `(src_sid, dst_sid, timestamp, rel_type_tag, metadata_offset)`
//!   level so this is safe.
//! - **Source errors don't advance the watermark.** If `poll_since`
//!   returns an error or the stream yields `Err`, the watermark stays
//!   put and the next cycle retries the same range. This means a
//!   permanently-broken table will loop forever — the upper layer
//!   (polling loop supervisor, Phase 5 quota limiter) is responsible
//!   for the circuit breaker.
//! - **Cancellation.** Cancel is checked between every table and
//!   between every sleep. In-flight HTTP requests are cancelled via
//!   the `cancel` clone handed to `poll_since`.

use futures::StreamExt;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio_util::sync::CancellationToken;

use crate::sources::{LogSource, Watermark};
use crate::watermark_store::{WatermarkKey, WatermarkStore};

use super::channels::RawSender;

/// Default interval between polling cycles. Matches the existing
/// `sentinel_connector.rs` default.
pub const DEFAULT_POLL_INTERVAL: Duration = Duration::from_secs(30);

/// Configuration for a `SourcePoller` instance.
#[derive(Debug, Clone)]
pub struct PollerConfig {
    /// How long to sleep between polling cycles.
    pub poll_interval: Duration,

    /// Which tables to poll, in round-robin order. Each cycle walks
    /// the entire list; pollers can share a raw channel across tables
    /// because each `RawChunk` carries its own `table` field.
    pub tables: Vec<String>,

    /// Tenant ID, used as part of the `WatermarkKey` composite PK.
    pub tenant_id: String,

    /// Workspace / cluster / tenant-scope identifier. For Log Analytics
    /// this is the workspace ID; for Defender XDR it's the tenant ID
    /// (same as `tenant_id`); for blob export it's the storage account.
    pub workspace_id: String,
}

impl PollerConfig {
    pub fn new(
        tenant_id: impl Into<String>,
        workspace_id: impl Into<String>,
        tables: Vec<String>,
    ) -> Self {
        Self {
            poll_interval: DEFAULT_POLL_INTERVAL,
            tables,
            tenant_id: tenant_id.into(),
            workspace_id: workspace_id.into(),
        }
    }

    pub fn with_poll_interval(mut self, interval: Duration) -> Self {
        self.poll_interval = interval;
        self
    }
}

/// Metrics collected by a source poller over its lifetime.
#[derive(Debug, Default)]
pub struct PollerMetrics {
    pub cycles: AtomicU64,
    pub tables_polled: AtomicU64,
    pub chunks_forwarded: AtomicU64,
    pub errors: AtomicU64,
    pub watermark_advances: AtomicU64,
}

impl PollerMetrics {
    pub fn snapshot(&self) -> PollerMetricsSnapshot {
        PollerMetricsSnapshot {
            cycles: self.cycles.load(Ordering::Relaxed),
            tables_polled: self.tables_polled.load(Ordering::Relaxed),
            chunks_forwarded: self.chunks_forwarded.load(Ordering::Relaxed),
            errors: self.errors.load(Ordering::Relaxed),
            watermark_advances: self.watermark_advances.load(Ordering::Relaxed),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PollerMetricsSnapshot {
    pub cycles: u64,
    pub tables_polled: u64,
    pub chunks_forwarded: u64,
    pub errors: u64,
    pub watermark_advances: u64,
}

/// A long-lived polling task for one source.
pub struct SourcePoller {
    source: Arc<dyn LogSource>,
    config: PollerConfig,
    watermarks: Arc<dyn WatermarkStore>,
    metrics: Arc<PollerMetrics>,
}

impl SourcePoller {
    pub fn new(
        source: Arc<dyn LogSource>,
        config: PollerConfig,
        watermarks: Arc<dyn WatermarkStore>,
    ) -> Self {
        Self {
            source,
            config,
            watermarks,
            metrics: Arc::new(PollerMetrics::default()),
        }
    }

    pub fn metrics(&self) -> Arc<PollerMetrics> {
        self.metrics.clone()
    }

    fn watermark_key(&self, table: &str) -> WatermarkKey {
        WatermarkKey::new(
            self.source.source_id(),
            &self.config.tenant_id,
            &self.config.workspace_id,
            table,
        )
    }

    /// Runs the polling loop until cancellation. Each cycle polls every
    /// configured table once in order, sends chunks into `raw_tx`, and
    /// advances the watermark after each successful forward.
    pub async fn run(
        self,
        raw_tx: RawSender,
        cancel: CancellationToken,
    ) -> PollerMetricsSnapshot {
        while !cancel.is_cancelled() {
            self.metrics.cycles.fetch_add(1, Ordering::Relaxed);
            for table in &self.config.tables {
                if cancel.is_cancelled() {
                    break;
                }
                self.metrics.tables_polled.fetch_add(1, Ordering::Relaxed);
                self.poll_one_table(&raw_tx, table, &cancel).await;
                if raw_tx.is_closed() {
                    // Downstream receiver gone — exit cleanly.
                    return self.metrics.snapshot();
                }
            }
            // Interruptible sleep between cycles.
            tokio::select! {
                _ = tokio::time::sleep(self.config.poll_interval) => {}
                _ = cancel.cancelled() => break,
            }
        }
        self.metrics.snapshot()
    }

    async fn poll_one_table(
        &self,
        raw_tx: &RawSender,
        table: &str,
        cancel: &CancellationToken,
    ) {
        let key = self.watermark_key(table);
        // Load current watermark. If the store fails to read, treat
        // as empty and let `poll_since` decide the lookback default.
        let current_wm = match self.watermarks.get(&key).await {
            Ok(Some(wm)) => wm,
            Ok(None) | Err(_) => Watermark::default(),
        };

        // Issue the query.
        let stream_result = self
            .source
            .poll_since(table, current_wm.clone(), cancel.clone())
            .await;
        let mut stream = match stream_result {
            Ok(s) => s,
            Err(err) => {
                self.metrics.errors.fetch_add(1, Ordering::Relaxed);
                // Forward the error so the parser task can count it in
                // per-source metrics too.
                let _ = raw_tx.send(Err(err)).await;
                return;
            }
        };

        // Drain the stream.
        while let Some(item) = stream.next().await {
            if cancel.is_cancelled() {
                return;
            }
            match item {
                Ok((chunk, new_wm)) => {
                    // Forward the chunk; if send fails the receiver is
                    // gone and we bail out of the cycle entirely.
                    if raw_tx.send(Ok(chunk)).await.is_err() {
                        return;
                    }
                    self.metrics
                        .chunks_forwarded
                        .fetch_add(1, Ordering::Relaxed);

                    // Persist the new watermark ONLY if it actually
                    // advanced. A stream that echoes the input wm
                    // (e.g., the LA impl when it has nothing new to
                    // say) is a no-op.
                    if new_wm != current_wm {
                        if self.watermarks.set(&key, &new_wm).await.is_ok() {
                            self.metrics
                                .watermark_advances
                                .fetch_add(1, Ordering::Relaxed);
                        }
                    }
                }
                Err(err) => {
                    self.metrics.errors.fetch_add(1, Ordering::Relaxed);
                    let _ = raw_tx.send(Err(err)).await;
                    // Per the "source errors don't advance watermark"
                    // contract, we don't persist anything here.
                    break;
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ingest::channels::raw_channel;
    use crate::sources::{
        ChunkEncoding, ChunkStream, LogSource, PollStream, QueryScope, RawChunk, SourceError,
        SourceKind,
    };
    use crate::watermark_store::SqliteWatermarkStore;
    use async_trait::async_trait;
    use bytes::Bytes;
    use futures::stream;
    use std::sync::Mutex;

    /// Mock source that yields a pre-programmed sequence of chunks per
    /// poll, recording how many times it was called per table.
    struct MockSource {
        id: String,
        tables: Vec<&'static str>,
        chunks_per_poll: Mutex<std::collections::HashMap<String, Vec<(RawChunk, Watermark)>>>,
        call_count: Mutex<std::collections::HashMap<String, u32>>,
    }

    impl MockSource {
        fn new(id: impl Into<String>) -> Self {
            Self {
                id: id.into(),
                tables: vec!["SecurityEvent", "SigninLogs"],
                chunks_per_poll: Mutex::new(std::collections::HashMap::new()),
                call_count: Mutex::new(std::collections::HashMap::new()),
            }
        }

        fn queue_chunks(&self, table: &str, chunks: Vec<(RawChunk, Watermark)>) {
            self.chunks_per_poll
                .lock()
                .unwrap()
                .insert(table.to_string(), chunks);
        }

        fn call_count_for(&self, table: &str) -> u32 {
            *self
                .call_count
                .lock()
                .unwrap()
                .get(table)
                .unwrap_or(&0)
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
            Ok(stream::iter(vec![]).boxed())
        }

        async fn poll_since(
            &self,
            table: &str,
            _watermark: Watermark,
            _cancel: CancellationToken,
        ) -> Result<PollStream, SourceError> {
            *self
                .call_count
                .lock()
                .unwrap()
                .entry(table.to_string())
                .or_insert(0) += 1;
            let chunks = self
                .chunks_per_poll
                .lock()
                .unwrap()
                .remove(table)
                .unwrap_or_default();
            let items: Vec<Result<(RawChunk, Watermark), SourceError>> =
                chunks.into_iter().map(Ok).collect();
            Ok(stream::iter(items).boxed())
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

    #[tokio::test(flavor = "current_thread")]
    async fn poller_forwards_chunks_and_persists_watermark() {
        let mock = Arc::new(MockSource::new("la:ws-1"));
        mock.queue_chunks(
            "SecurityEvent",
            vec![
                (mk_chunk("la:ws-1", "SecurityEvent"), Watermark::new("ts-1")),
                (mk_chunk("la:ws-1", "SecurityEvent"), Watermark::new("ts-2")),
            ],
        );
        mock.queue_chunks(
            "SigninLogs",
            vec![(mk_chunk("la:ws-1", "SigninLogs"), Watermark::new("ts-3"))],
        );

        let watermarks: Arc<dyn WatermarkStore> =
            Arc::new(SqliteWatermarkStore::open_in_memory().await.unwrap());

        let config = PollerConfig::new(
            "tenant-a",
            "ws-1",
            vec!["SecurityEvent".to_string(), "SigninLogs".to_string()],
        )
        .with_poll_interval(Duration::from_millis(100));

        let source: Arc<dyn LogSource> = mock.clone();
        let poller = SourcePoller::new(source, config, watermarks.clone());

        let (raw_tx, mut raw_rx) = raw_channel(8);
        let cancel = CancellationToken::new();
        let cancel2 = cancel.clone();

        let handle = tokio::spawn(async move { poller.run(raw_tx, cancel2).await });

        // Drain 3 chunks (2 from SecurityEvent + 1 from SigninLogs).
        let mut chunks = Vec::new();
        for _ in 0..3 {
            match raw_rx.recv().await {
                Some(Ok(chunk)) => chunks.push(chunk),
                Some(Err(e)) => panic!("unexpected error: {e}"),
                None => break,
            }
        }
        assert_eq!(chunks.len(), 3);
        assert_eq!(chunks[0].table, "SecurityEvent");
        assert_eq!(chunks[1].table, "SecurityEvent");
        assert_eq!(chunks[2].table, "SigninLogs");

        // Cancel and join.
        cancel.cancel();
        drop(raw_rx);
        let snapshot = handle.await.unwrap();
        assert!(snapshot.cycles >= 1);
        assert!(snapshot.tables_polled >= 2);
        assert!(snapshot.chunks_forwarded >= 3);

        // Watermarks should be persisted to their latest values.
        let sec_wm = watermarks
            .get(&WatermarkKey::new("la:ws-1", "tenant-a", "ws-1", "SecurityEvent"))
            .await
            .unwrap();
        let sig_wm = watermarks
            .get(&WatermarkKey::new("la:ws-1", "tenant-a", "ws-1", "SigninLogs"))
            .await
            .unwrap();
        assert_eq!(sec_wm.unwrap().as_str(), "ts-2");
        assert_eq!(sig_wm.unwrap().as_str(), "ts-3");
    }

    #[tokio::test(flavor = "current_thread")]
    async fn poller_exits_when_raw_rx_dropped() {
        let mock = Arc::new(MockSource::new("la:ws-1"));
        mock.queue_chunks(
            "SecurityEvent",
            vec![(mk_chunk("la:ws-1", "SecurityEvent"), Watermark::new("ts-1"))],
        );
        let watermarks: Arc<dyn WatermarkStore> =
            Arc::new(SqliteWatermarkStore::open_in_memory().await.unwrap());

        let config = PollerConfig::new("tenant-a", "ws-1", vec!["SecurityEvent".to_string()])
            .with_poll_interval(Duration::from_millis(10));

        let source: Arc<dyn LogSource> = mock;
        let poller = SourcePoller::new(source, config, watermarks);

        let (raw_tx, raw_rx) = raw_channel(1);
        let cancel = CancellationToken::new();
        let cancel2 = cancel.clone();

        // Drop the receiver immediately — next send should fail.
        drop(raw_rx);

        let handle = tokio::spawn(async move { poller.run(raw_tx, cancel2).await });

        // Give the poller a few ticks to attempt and fail.
        for _ in 0..20 {
            tokio::time::sleep(Duration::from_millis(5)).await;
            if handle.is_finished() {
                break;
            }
        }
        cancel.cancel();
        let snapshot = handle.await.unwrap();
        // Forwarded nothing because receiver was gone from the start.
        assert_eq!(snapshot.chunks_forwarded, 0);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn poller_forwards_source_error_without_advancing_watermark() {
        struct FailingSource;
        #[async_trait]
        impl LogSource for FailingSource {
            fn source_id(&self) -> &str {
                "la:fail"
            }
            fn kind(&self) -> SourceKind {
                SourceKind::LogAnalytics
            }
            fn available_tables(&self) -> &[&'static str] {
                &["SecurityEvent"]
            }
            async fn check_auth(&self) -> Result<(), SourceError> {
                Ok(())
            }
            async fn query_scoped(
                &self,
                _scope: QueryScope,
                _cancel: CancellationToken,
            ) -> Result<ChunkStream, SourceError> {
                Ok(stream::iter(vec![]).boxed())
            }
            async fn poll_since(
                &self,
                _table: &str,
                _watermark: Watermark,
                _cancel: CancellationToken,
            ) -> Result<PollStream, SourceError> {
                Err(SourceError::Auth)
            }
        }

        let source: Arc<dyn LogSource> = Arc::new(FailingSource);
        let watermarks: Arc<dyn WatermarkStore> =
            Arc::new(SqliteWatermarkStore::open_in_memory().await.unwrap());
        let config = PollerConfig::new("tenant-a", "ws-1", vec!["SecurityEvent".to_string()])
            .with_poll_interval(Duration::from_millis(20));

        let poller = SourcePoller::new(source, config, watermarks.clone());
        let (raw_tx, mut raw_rx) = raw_channel(4);
        let cancel = CancellationToken::new();
        let cancel2 = cancel.clone();
        let handle = tokio::spawn(async move { poller.run(raw_tx, cancel2).await });

        // Expect an Err message on raw_rx.
        let first = raw_rx.recv().await.unwrap();
        assert!(matches!(first, Err(SourceError::Auth)));

        cancel.cancel();
        drop(raw_rx);
        let snapshot = handle.await.unwrap();
        assert!(snapshot.errors >= 1);
        assert_eq!(snapshot.watermark_advances, 0);

        // Watermark never got persisted.
        let got = watermarks
            .get(&WatermarkKey::new("la:fail", "tenant-a", "ws-1", "SecurityEvent"))
            .await
            .unwrap();
        assert!(got.is_none());
    }

    #[tokio::test(flavor = "current_thread")]
    async fn poller_polls_each_table_multiple_times() {
        let mock = Arc::new(MockSource::new("la:ws-1"));
        // Queue one chunk for the first poll only; subsequent polls
        // return empty streams.
        mock.queue_chunks(
            "SecurityEvent",
            vec![(mk_chunk("la:ws-1", "SecurityEvent"), Watermark::new("ts-1"))],
        );
        let watermarks: Arc<dyn WatermarkStore> =
            Arc::new(SqliteWatermarkStore::open_in_memory().await.unwrap());
        let config = PollerConfig::new("tenant-a", "ws-1", vec!["SecurityEvent".to_string()])
            .with_poll_interval(Duration::from_millis(20));

        let source: Arc<dyn LogSource> = mock.clone();
        let poller = SourcePoller::new(source, config, watermarks);
        let (raw_tx, mut raw_rx) = raw_channel(4);
        let cancel = CancellationToken::new();
        let cancel2 = cancel.clone();
        let handle = tokio::spawn(async move { poller.run(raw_tx, cancel2).await });

        // Drain the first chunk.
        let _ = raw_rx.recv().await.unwrap();
        // Let the poller loop a few more times.
        tokio::time::sleep(Duration::from_millis(100)).await;
        cancel.cancel();
        drop(raw_rx);
        let _snapshot = handle.await.unwrap();

        // Mock should have been called more than once for SecurityEvent.
        assert!(mock.call_count_for("SecurityEvent") >= 2);
    }
}
