//! The single `GraphWriter` task that drains `parsed_tx` into the graph.
//!
//! This is where the streaming pipeline converges. Every source's
//! `ParserTask` sends `ParsedBatch`es into one shared `parsed_tx` mpsc
//! channel; the single `GraphWriter` task reads from the corresponding
//! receiver and inserts each batch via chunked writes that yield to
//! readers between chunks.
//!
//! Design choices pulled from plan §3:
//!
//! - **One writer, not per-source.** Fewer lock transitions under
//!   contention, deterministic ordering of inserts from different
//!   sources, and a single place to attach metrics. The single-writer
//!   assumption is an unmeasured bet — if production metrics show the
//!   writer saturated (>80% CPU) we'll revisit in Phase 5 via sharding.
//! - **Chunked inserts with yields.** Each `insert_triples_chunk`
//!   call grabs the write lock for ~5 000 triples, then releases.
//!   `tokio::task::yield_now().await` between chunks lets readers
//!   make progress even under sustained bulk load.
//! - **No priority preemption YET.** The writer drains the channel
//!   in FIFO order. `Priority::Enrichment` is recorded in metrics
//!   so operators can see if enrichment is being starved, but actual
//!   preemption is deferred until measurement shows it matters. The
//!   plan's "priority_preempt AtomicBool" idea is easy to add later
//!   on top of this skeleton.
//! - **Graceful shutdown.** The writer exits cleanly when the channel
//!   closes (all senders dropped) or when the cancel token fires
//!   between chunks. In-flight batches finish their current chunk
//!   before exit so partial batches don't leak into the graph in an
//!   inconsistent state.

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use tokio_util::sync::CancellationToken;

use crate::errors::GraphError;

use super::batch::{ParsedBatch, Priority};
use super::channels::ParsedReceiver;
use super::graph_access::{DEFAULT_WRITE_CHUNK_SIZE, GraphAccess};

/// Metrics collected by the writer over its lifetime. All counters are
/// monotonic `AtomicU64` so they can be sampled from the outside
/// without taking a lock.
#[derive(Debug, Default)]
pub struct WriterMetrics {
    /// Batches fully drained into the graph.
    pub batches_processed: AtomicU64,
    /// Total triples actually inserted (sum of return values from
    /// `GraphAccess::insert_chunk`).
    pub triples_inserted: AtomicU64,
    /// Chunk write calls issued (typically `ceil(triples / chunk_size)`).
    pub chunks_written: AtomicU64,
    /// Batches abandoned mid-stream because the cancel token fired.
    /// The chunks already written before cancellation are counted in
    /// `triples_inserted`; the remaining triples in the batch are
    /// dropped.
    pub batches_cancelled: AtomicU64,
    /// `GraphAccess::insert_chunk` error returns. Does NOT include
    /// cancellations, channel closures, or spill failures.
    pub errors: AtomicU64,
    /// Auto-spill failures surfaced as [`GraphError::Spill`].
    pub spill_errors: AtomicU64,
    /// Batches drained that carried `Priority::Enrichment`.
    pub enrichment_batches: AtomicU64,
}

impl WriterMetrics {
    pub fn snapshot(&self) -> WriterMetricsSnapshot {
        WriterMetricsSnapshot {
            batches_processed: self.batches_processed.load(Ordering::Relaxed),
            triples_inserted: self.triples_inserted.load(Ordering::Relaxed),
            chunks_written: self.chunks_written.load(Ordering::Relaxed),
            batches_cancelled: self.batches_cancelled.load(Ordering::Relaxed),
            errors: self.errors.load(Ordering::Relaxed),
            spill_errors: self.spill_errors.load(Ordering::Relaxed),
            enrichment_batches: self.enrichment_batches.load(Ordering::Relaxed),
        }
    }
}

/// Clonable, `Copy`-able snapshot of `WriterMetrics`. Useful for
/// logging, test assertions, and the forthcoming `cmd_get_ingest_metrics`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WriterMetricsSnapshot {
    pub batches_processed: u64,
    pub triples_inserted: u64,
    pub chunks_written: u64,
    pub batches_cancelled: u64,
    pub errors: u64,
    pub spill_errors: u64,
    pub enrichment_batches: u64,
}

/// The single writer task. Drains `parsed_rx` and pushes each batch
/// through `GraphAccess::insert_chunk` in chunked loops.
pub struct GraphWriter<A: GraphAccess + 'static> {
    access: Arc<A>,
    chunk_size: usize,
    metrics: Arc<WriterMetrics>,
}

impl<A: GraphAccess + 'static> GraphWriter<A> {
    pub fn new(access: Arc<A>) -> Self {
        Self {
            access,
            chunk_size: DEFAULT_WRITE_CHUNK_SIZE,
            metrics: Arc::new(WriterMetrics::default()),
        }
    }

    /// Overrides the per-chunk triple count. Clamps to at least 1 so
    /// a 0 here doesn't cause an infinite drain loop.
    pub fn with_chunk_size(mut self, chunk_size: usize) -> Self {
        self.chunk_size = chunk_size.max(1);
        self
    }

    /// Returns a shared handle to the writer's metrics. The handle
    /// stays live after `run()` consumes `self`, which is how external
    /// observers inspect the counters mid-run.
    pub fn metrics(&self) -> Arc<WriterMetrics> {
        self.metrics.clone()
    }

    /// Runs the writer loop until the receiver closes (all senders
    /// dropped) or the cancel token is fired. Always drains the
    /// current batch's current chunk before checking the cancel token.
    ///
    /// Returns the final metrics snapshot so callers that don't retain
    /// an external `Arc<WriterMetrics>` handle can still see totals.
    pub async fn run(
        self,
        mut rx: ParsedReceiver,
        cancel: CancellationToken,
    ) -> WriterMetricsSnapshot {
        while let Some(batch) = rx.recv().await {
            if cancel.is_cancelled() {
                self.metrics
                    .batches_cancelled
                    .fetch_add(1, Ordering::Relaxed);
                break;
            }
            self.write_one_batch(batch, &cancel).await;
        }
        self.metrics.snapshot()
    }

    async fn write_one_batch(&self, batch: ParsedBatch, cancel: &CancellationToken) {
        // Record the priority for metrics. The writer doesn't actually
        // reorder batches — this counter just lets operators see
        // whether enrichment is flowing through.
        if matches!(batch.priority, Priority::Enrichment) {
            self.metrics
                .enrichment_batches
                .fetch_add(1, Ordering::Relaxed);
        }

        let mut pending = batch.events;
        let dataset_id = batch.dataset_id.clone();
        let mut cancelled_mid_batch = false;

        while !pending.is_empty() {
            if cancel.is_cancelled() {
                cancelled_mid_batch = true;
                break;
            }

            match self
                .access
                .insert_raw_chunk(&mut pending, dataset_id.as_deref(), self.chunk_size)
                .await
            {
                Ok(n) => {
                    self.metrics.chunks_written.fetch_add(1, Ordering::Relaxed);
                    self.metrics
                        .triples_inserted
                        .fetch_add(n as u64, Ordering::Relaxed);
                    if n == 0 {
                        // Defensive: a correctly-implemented `GraphAccess`
                        // never returns `Ok(0)` from a non-empty pending
                        // vec. If we see this, bail out to avoid an
                        // infinite loop.
                        break;
                    }
                }
                Err(e) => {
                    if matches!(e, GraphError::Spill(_)) {
                        self.metrics
                            .spill_errors
                            .fetch_add(1, Ordering::Relaxed);
                    } else {
                        self.metrics.errors.fetch_add(1, Ordering::Relaxed);
                    }
                    // Abandon the rest of this batch. A more
                    // sophisticated policy (retry, dead-letter queue)
                    // is a Phase 5 concern.
                    return;
                }
            }

            // Yield between chunks so readers can grab the lock.
            tokio::task::yield_now().await;
        }

        if cancelled_mid_batch {
            self.metrics
                .batches_cancelled
                .fetch_add(1, Ordering::Relaxed);
        } else {
            self.metrics
                .batches_processed
                .fetch_add(1, Ordering::Relaxed);
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::graph::GraphHunter;
    use crate::ingest::batch::ParsedBatch;
    use crate::ingest::channels::parsed_channel;
    use crate::ingest::graph_access::InMemoryGraphAccess;
    use crate::parser::RawIngestEvent;
    use crate::types::{EntityType, RelationType};
    use std::collections::HashMap;

    fn mk_triple(src_id: &str, dst_id: &str, ts: i64) -> RawIngestEvent {
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

    fn mk_batch(source_id: &str, events: Vec<RawIngestEvent>) -> ParsedBatch {
        ParsedBatch::new(source_id, events)
    }

    #[tokio::test(flavor = "current_thread")]
    async fn writer_drains_single_batch_fully() {
        let access = Arc::new(InMemoryGraphAccess::new(GraphHunter::new()));
        let writer = GraphWriter::new(access.clone()).with_chunk_size(2);
        let metrics = writer.metrics();

        let (tx, rx) = parsed_channel(4);
        let triples = vec![
            mk_triple("alice", "p1", 100),
            mk_triple("bob", "p2", 200),
            mk_triple("carol", "p3", 300),
            mk_triple("dave", "p4", 400),
            mk_triple("eve", "p5", 500),
        ];
        tx.send(mk_batch("la:ws-1", triples)).await.unwrap();
        drop(tx); // close the channel so run() exits

        let cancel = CancellationToken::new();
        let snapshot = writer.run(rx, cancel).await;

        assert_eq!(snapshot.batches_processed, 1);
        assert_eq!(snapshot.triples_inserted, 5);
        // 5 triples / chunk size 2 → 3 chunks (2, 2, 1).
        assert_eq!(snapshot.chunks_written, 3);
        assert_eq!(snapshot.errors, 0);
        assert_eq!(snapshot.batches_cancelled, 0);

        // Verify the graph actually received all 5 entities.
        let g = access.graph();
        let guard = g.lock().await;
        for id in ["alice", "bob", "carol", "dave", "eve"] {
            assert!(guard.get_entity(id).is_some(), "missing {id}");
        }
        // metrics should also be observable via the shared handle.
        let snap2 = metrics.snapshot();
        assert_eq!(snap2.triples_inserted, 5);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn writer_counts_enrichment_batches_separately() {
        let access = Arc::new(InMemoryGraphAccess::new(GraphHunter::new()));
        let writer = GraphWriter::new(access).with_chunk_size(10);

        let (tx, rx) = parsed_channel(4);
        tx.send(mk_batch("la:ws-1", vec![mk_triple("a", "b", 1)]))
            .await
            .unwrap();
        tx.send(
            mk_batch("la:ws-1", vec![mk_triple("c", "d", 2)]).with_priority(Priority::Enrichment),
        )
        .await
        .unwrap();
        tx.send(
            mk_batch("la:ws-1", vec![mk_triple("e", "f", 3)]).with_priority(Priority::Enrichment),
        )
        .await
        .unwrap();
        drop(tx);

        let snapshot = writer.run(rx, CancellationToken::new()).await;
        assert_eq!(snapshot.batches_processed, 3);
        assert_eq!(snapshot.enrichment_batches, 2);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn writer_exits_when_cancelled_between_batches() {
        let access = Arc::new(InMemoryGraphAccess::new(GraphHunter::new()));
        let writer = GraphWriter::new(access.clone()).with_chunk_size(100);

        let (tx, rx) = parsed_channel(4);
        // Queue two batches. Cancel BEFORE sending anything so the
        // first `rx.recv().await` still returns, but the cancel check
        // after recv sees the token and exits.
        tx.send(mk_batch("la:ws-1", vec![mk_triple("a", "b", 1)]))
            .await
            .unwrap();
        tx.send(mk_batch("la:ws-1", vec![mk_triple("c", "d", 2)]))
            .await
            .unwrap();
        drop(tx);

        let cancel = CancellationToken::new();
        cancel.cancel();
        let snapshot = writer.run(rx, cancel).await;
        // Cancelled between batches — first batch triggers the
        // cancellation check in run() and exits.
        assert_eq!(snapshot.batches_processed, 0);
        assert_eq!(snapshot.batches_cancelled, 1);
        assert_eq!(snapshot.triples_inserted, 0);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn writer_exits_when_cancelled_mid_batch() {
        // Large batch + small chunk size + cancel between chunks.
        let access = Arc::new(InMemoryGraphAccess::new(GraphHunter::new()));
        let writer = GraphWriter::new(access.clone()).with_chunk_size(1);
        let metrics = writer.metrics();

        let (tx, rx) = parsed_channel(4);
        let triples: Vec<_> = (0..100)
            .map(|i| mk_triple(&format!("u-{i}"), &format!("p-{i}"), i))
            .collect();
        tx.send(mk_batch("la:ws-1", triples)).await.unwrap();
        drop(tx);

        let cancel = CancellationToken::new();
        let cancel_clone = cancel.clone();
        // Race: let the writer drain a few chunks, then cancel.
        let writer_task = tokio::spawn(async move { writer.run(rx, cancel_clone).await });
        // Yield a few times to let the writer start, then cancel.
        for _ in 0..5 {
            tokio::task::yield_now().await;
        }
        cancel.cancel();
        let snapshot = writer_task.await.unwrap();

        // Something was inserted before the cancel fired, but not all 100.
        // The exact count depends on scheduling; assert that cancellation
        // was observed.
        assert!(snapshot.triples_inserted < 100);
        assert_eq!(snapshot.batches_cancelled, 1);
        // batches_processed stays 0 because the one batch was cancelled.
        assert_eq!(snapshot.batches_processed, 0);

        // Metrics are still observable via the external handle.
        let snap2 = metrics.snapshot();
        assert_eq!(snap2.batches_cancelled, 1);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn writer_continues_after_receiving_each_batch_in_order() {
        let access = Arc::new(InMemoryGraphAccess::new(GraphHunter::new()));
        let writer = GraphWriter::new(access.clone());

        let (tx, rx) = parsed_channel(8);
        for i in 0..5 {
            tx.send(mk_batch(
                "la:ws-1",
                vec![mk_triple(&format!("u-{i}"), &format!("p-{i}"), i)],
            ))
            .await
            .unwrap();
        }
        drop(tx);

        let snapshot = writer.run(rx, CancellationToken::new()).await;
        assert_eq!(snapshot.batches_processed, 5);
        assert_eq!(snapshot.triples_inserted, 5);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn writer_exits_on_closed_channel() {
        let access = Arc::new(InMemoryGraphAccess::new(GraphHunter::new()));
        let writer = GraphWriter::new(access);
        let (tx, rx) = parsed_channel(4);
        drop(tx); // close immediately
        let snapshot = writer.run(rx, CancellationToken::new()).await;
        assert_eq!(snapshot.batches_processed, 0);
        assert_eq!(snapshot.triples_inserted, 0);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn writer_handles_empty_batch() {
        let access = Arc::new(InMemoryGraphAccess::new(GraphHunter::new()));
        let writer = GraphWriter::new(access);
        let (tx, rx) = parsed_channel(4);
        tx.send(mk_batch("la:ws-1", Vec::new())).await.unwrap();
        drop(tx);
        let snapshot = writer.run(rx, CancellationToken::new()).await;
        // Empty batch still counts as processed.
        assert_eq!(snapshot.batches_processed, 1);
        assert_eq!(snapshot.triples_inserted, 0);
        assert_eq!(snapshot.chunks_written, 0);
    }
}
