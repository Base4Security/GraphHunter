//! The `ParserTask` that bridges `raw_rx` → `parsed_tx`.
//!
//! One `ParserTask` runs per source. It reads `Result<RawChunk,
//! SourceError>` from the source's raw channel, decodes each successful
//! chunk via a `LogParser` implementation, wraps the resulting triples
//! in a `ParsedBatch`, and forwards the batch to the shared writer
//! channel.
//!
//! Responsibilities:
//!
//! - **Decoding.** Reads `chunk.rows` as UTF-8 text and passes it to
//!   `LogParser::parse(&str)`. For sources whose output is already a
//!   `serde_json::Value::Array` of row objects, this could eventually
//!   use the `parse_rows` fast path — but `RawChunk` today carries
//!   raw bytes, so the task takes the string path for compatibility.
//!   Moving to pre-decoded rows in the source layer is a Phase 5
//!   optimization.
//! - **Backpressure.** `parsed_tx.send().await` blocks when the
//!   writer is behind. This halts the source poller too (via the
//!   full raw channel), which is the pipeline's whole point.
//! - **Error forwarding.** `SourceError`s carried via `raw_rx` (auth,
//!   throttle, timeout, etc.) are surfaced to the task's own metrics
//!   and then **silently skipped** — they're logged and handled at
//!   the poller level (where retry/backoff policy lives), not here.
//! - **Cancellation.** Exits cleanly on cancel between messages.
//!   Does not interrupt an in-flight parse call (parses are
//!   millisecond-scale on small chunks; interrupting them adds no value).
//! - **Watermark advance.** If a `RawChunk` carries a
//!   `watermark_candidate`, the ParserTask copies it into the
//!   `ParsedBatch::watermark_after` field so the writer (well, the
//!   downstream consumer) knows to advance the watermark for that
//!   source+table after a successful insert.

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use tokio_util::sync::CancellationToken;

use crate::parser::LogParser;
use graph_hunter_sources::{ChunkEncoding, RawChunk};

use super::batch::{ParsedBatch, Priority};
use super::channels::{ParsedSender, RawReceiver};

/// Metrics collected by a single `ParserTask` over its lifetime.
#[derive(Debug, Default)]
pub struct ParserMetrics {
    /// Raw chunks received from the source poller.
    pub chunks_received: AtomicU64,
    /// Chunks successfully parsed into non-empty batches.
    pub chunks_parsed: AtomicU64,
    /// Chunks received whose `Result` was an `Err(SourceError)`.
    pub source_errors: AtomicU64,
    /// Chunks skipped because the bytes weren't valid UTF-8 or the
    /// encoding was `Parquet` (not yet supported).
    pub chunks_dropped: AtomicU64,
    /// Triples forwarded to the writer via `parsed_tx`.
    pub triples_forwarded: AtomicU64,
}

impl ParserMetrics {
    pub fn snapshot(&self) -> ParserMetricsSnapshot {
        ParserMetricsSnapshot {
            chunks_received: self.chunks_received.load(Ordering::Relaxed),
            chunks_parsed: self.chunks_parsed.load(Ordering::Relaxed),
            source_errors: self.source_errors.load(Ordering::Relaxed),
            chunks_dropped: self.chunks_dropped.load(Ordering::Relaxed),
            triples_forwarded: self.triples_forwarded.load(Ordering::Relaxed),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ParserMetricsSnapshot {
    pub chunks_received: u64,
    pub chunks_parsed: u64,
    pub source_errors: u64,
    pub chunks_dropped: u64,
    pub triples_forwarded: u64,
}

/// A parser task bound to a single log source.
pub struct ParserTask {
    parser: Arc<dyn LogParser>,
    source_id: String,
    dataset_id: Option<String>,
    priority: Priority,
    metrics: Arc<ParserMetrics>,
}

impl ParserTask {
    pub fn new(parser: Arc<dyn LogParser>, source_id: impl Into<String>) -> Self {
        Self {
            parser,
            source_id: source_id.into(),
            dataset_id: None,
            priority: Priority::Normal,
            metrics: Arc::new(ParserMetrics::default()),
        }
    }

    pub fn with_dataset_id(mut self, dataset_id: impl Into<String>) -> Self {
        self.dataset_id = Some(dataset_id.into());
        self
    }

    pub fn with_priority(mut self, priority: Priority) -> Self {
        self.priority = priority;
        self
    }

    pub fn metrics(&self) -> Arc<ParserMetrics> {
        self.metrics.clone()
    }

    /// Runs the parser loop until the raw channel closes or the cancel
    /// token fires between messages.
    pub async fn run(
        self,
        mut raw_rx: RawReceiver,
        parsed_tx: ParsedSender,
        cancel: CancellationToken,
    ) -> ParserMetricsSnapshot {
        while let Some(result) = raw_rx.recv().await {
            if cancel.is_cancelled() {
                break;
            }
            self.metrics.chunks_received.fetch_add(1, Ordering::Relaxed);
            match result {
                Ok(chunk) => {
                    if let Some(batch) = self.parse_chunk(chunk) {
                        if !batch.events.is_empty() {
                            self.metrics.chunks_parsed.fetch_add(1, Ordering::Relaxed);
                        }
                        self.metrics
                            .triples_forwarded
                            .fetch_add(batch.events.len() as u64, Ordering::Relaxed);
                        if parsed_tx.send(batch).await.is_err() {
                            // Writer dropped the receiver — no point
                            // continuing. Exit cleanly.
                            break;
                        }
                    } else {
                        self.metrics.chunks_dropped.fetch_add(1, Ordering::Relaxed);
                    }
                }
                Err(_err) => {
                    // SourceError is handled at the poller level
                    // (retry/backoff/strike counter). We just count it
                    // in metrics and keep consuming.
                    self.metrics.source_errors.fetch_add(1, Ordering::Relaxed);
                }
            }
        }
        self.metrics.snapshot()
    }

    /// Decodes a single raw chunk into a `ParsedBatch`. Returns `None`
    /// if the bytes are unparseable (non-UTF-8) or the encoding is
    /// unsupported (Parquet).
    fn parse_chunk(&self, chunk: RawChunk) -> Option<ParsedBatch> {
        let events = match chunk.encoding {
            ChunkEncoding::Json | ChunkEncoding::Jsonl => {
                let text = match std::str::from_utf8(chunk.rows.as_ref()) {
                    Ok(s) => s,
                    Err(_) => return None,
                };
                // parse_raw is the raw-event production path. For
                // parsers that override it (currently SysmonJsonParser
                // covering all 16 typed Sysmon/WinSec/PowerShell
                // EventIDs), this skips the Entity/Relation struct
                // allocations the legacy parse() pays per triple. For
                // parsers that haven't overridden, the default impl
                // wraps parse() and lifts — same behavior as before.
                self.parser.parse_raw(text)
            }
            ChunkEncoding::Parquet => {
                // Not yet supported — future Data Lake v2 path.
                return None;
            }
        };

        let row_count = events.len();
        let mut batch = ParsedBatch {
            source_id: self.source_id.clone(),
            dataset_id: self.dataset_id.clone(),
            priority: self.priority,
            events,
            row_count,
            dropped_rows: 0,
            watermark_after: chunk
                .watermark_candidate
                .map(|wm| (chunk.table.clone(), wm)),
        };
        batch.row_count = batch.events.len();
        Some(batch)
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::entity::Entity;
    use crate::ingest::channels::{parsed_channel, raw_channel};
    use crate::parser::{LogParser, ParsedTriple};
    use crate::relation::Relation;
    use crate::types::{EntityType, RelationType};
    use bytes::Bytes;
    use graph_hunter_sources::{ChunkEncoding, RawChunk, SourceError, Watermark};

    /// Parser that emits one hardcoded triple per call, regardless of input.
    /// Exists to decouple ParserTask tests from any real parser logic.
    struct CountingParser {
        emit_per_call: usize,
    }

    impl LogParser for CountingParser {
        fn parse(&self, _data: &str) -> Vec<ParsedTriple> {
            (0..self.emit_per_call)
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

    fn mk_chunk(source: &str, table: &str, body: &[u8]) -> RawChunk {
        RawChunk {
            source_id: source.to_string(),
            table: table.to_string(),
            rows: Bytes::copy_from_slice(body),
            encoding: ChunkEncoding::Json,
            fetched_at: 0,
            watermark_candidate: None,
        }
    }

    #[tokio::test(flavor = "current_thread")]
    async fn parser_task_forwards_one_batch_per_chunk() {
        let parser = Arc::new(CountingParser { emit_per_call: 3 });
        let task = ParserTask::new(parser, "la:ws-1");
        let metrics = task.metrics();

        let (raw_tx, raw_rx) = raw_channel(4);
        let (parsed_tx, mut parsed_rx) = parsed_channel(4);

        raw_tx
            .send(Ok(mk_chunk("la:ws-1", "SecurityEvent", b"{}")))
            .await
            .unwrap();
        raw_tx
            .send(Ok(mk_chunk("la:ws-1", "SecurityEvent", b"{}")))
            .await
            .unwrap();
        drop(raw_tx);

        let snapshot = task.run(raw_rx, parsed_tx, CancellationToken::new()).await;

        let batch1 = parsed_rx.recv().await.unwrap();
        let batch2 = parsed_rx.recv().await.unwrap();
        assert!(parsed_rx.recv().await.is_none());

        assert_eq!(batch1.events.len(), 3);
        assert_eq!(batch2.events.len(), 3);
        assert_eq!(batch1.source_id, "la:ws-1");

        assert_eq!(snapshot.chunks_received, 2);
        assert_eq!(snapshot.chunks_parsed, 2);
        assert_eq!(snapshot.triples_forwarded, 6);
        assert_eq!(snapshot.source_errors, 0);
        assert_eq!(snapshot.chunks_dropped, 0);

        assert_eq!(metrics.snapshot().chunks_received, 2);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn parser_task_counts_source_errors_without_failing() {
        let parser = Arc::new(CountingParser { emit_per_call: 1 });
        let task = ParserTask::new(parser, "la:ws-1");

        let (raw_tx, raw_rx) = raw_channel(4);
        let (parsed_tx, mut parsed_rx) = parsed_channel(4);

        raw_tx.send(Err(SourceError::Auth)).await.unwrap();
        raw_tx
            .send(Ok(mk_chunk("la:ws-1", "SecurityEvent", b"{}")))
            .await
            .unwrap();
        raw_tx.send(Err(SourceError::Timeout)).await.unwrap();
        drop(raw_tx);

        let snapshot = task.run(raw_rx, parsed_tx, CancellationToken::new()).await;

        // Only the one successful chunk should have produced a batch.
        assert!(parsed_rx.recv().await.is_some());
        assert!(parsed_rx.recv().await.is_none());

        assert_eq!(snapshot.chunks_received, 3);
        assert_eq!(snapshot.source_errors, 2);
        assert_eq!(snapshot.chunks_parsed, 1);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn parser_task_propagates_watermark_candidate() {
        let parser = Arc::new(CountingParser { emit_per_call: 1 });
        let task = ParserTask::new(parser, "la:ws-1");

        let (raw_tx, raw_rx) = raw_channel(4);
        let (parsed_tx, mut parsed_rx) = parsed_channel(4);

        let mut chunk = mk_chunk("la:ws-1", "SigninLogs", b"{}");
        chunk.watermark_candidate = Some(Watermark::new("2026-04-09T10:00:00Z"));
        raw_tx.send(Ok(chunk)).await.unwrap();
        drop(raw_tx);

        let _snapshot = task.run(raw_rx, parsed_tx, CancellationToken::new()).await;
        let batch = parsed_rx.recv().await.unwrap();
        let (table, wm) = batch.watermark_after.as_ref().unwrap();
        assert_eq!(table, "SigninLogs");
        assert_eq!(wm.as_str(), "2026-04-09T10:00:00Z");
    }

    #[tokio::test(flavor = "current_thread")]
    async fn parser_task_drops_parquet_chunks() {
        let parser = Arc::new(CountingParser { emit_per_call: 1 });
        let task = ParserTask::new(parser, "datalake:ws-1");

        let (raw_tx, raw_rx) = raw_channel(4);
        let (parsed_tx, mut parsed_rx) = parsed_channel(4);

        let mut chunk = mk_chunk("datalake:ws-1", "SomeTable", b"parquet bytes");
        chunk.encoding = ChunkEncoding::Parquet;
        raw_tx.send(Ok(chunk)).await.unwrap();
        drop(raw_tx);

        let snapshot = task.run(raw_rx, parsed_tx, CancellationToken::new()).await;
        assert!(parsed_rx.recv().await.is_none());
        assert_eq!(snapshot.chunks_received, 1);
        assert_eq!(snapshot.chunks_dropped, 1);
        assert_eq!(snapshot.chunks_parsed, 0);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn parser_task_exits_on_cancel_between_messages() {
        let parser = Arc::new(CountingParser { emit_per_call: 1 });
        let task = ParserTask::new(parser, "la:ws-1");

        let (raw_tx, raw_rx) = raw_channel(4);
        let (parsed_tx, _parsed_rx) = parsed_channel(4);

        // Cancel BEFORE any send. The first `recv().await` blocks
        // until something arrives; send one, then the cancel check
        // after recv fires and the loop exits.
        let cancel = CancellationToken::new();
        cancel.cancel();
        raw_tx
            .send(Ok(mk_chunk("la:ws-1", "SecurityEvent", b"{}")))
            .await
            .unwrap();
        drop(raw_tx);

        let snapshot = task.run(raw_rx, parsed_tx, cancel).await;
        assert_eq!(snapshot.chunks_received, 0); // exited before incrementing
    }

    #[tokio::test(flavor = "current_thread")]
    async fn parser_task_exits_when_writer_drops() {
        let parser = Arc::new(CountingParser { emit_per_call: 1 });
        let task = ParserTask::new(parser, "la:ws-1");

        let (raw_tx, raw_rx) = raw_channel(4);
        let (parsed_tx, parsed_rx) = parsed_channel(4);

        // Send something, drop parsed_rx so send fails.
        raw_tx
            .send(Ok(mk_chunk("la:ws-1", "SecurityEvent", b"{}")))
            .await
            .unwrap();
        drop(parsed_rx);
        // Send a second chunk — the task should exit after the first
        // failed send.
        raw_tx
            .send(Ok(mk_chunk("la:ws-1", "SecurityEvent", b"{}")))
            .await
            .unwrap();
        drop(raw_tx);

        let snapshot = task.run(raw_rx, parsed_tx, CancellationToken::new()).await;
        // Exactly one chunk was received and its send failed → loop
        // exited. The second chunk sits unread in raw_rx.
        assert_eq!(snapshot.chunks_received, 1);
    }

    #[test]
    fn parse_rows_default_round_trips_through_parse() {
        // Verify the `LogParser::parse_rows` default impl round-trips
        // through `parse(&str)` without mangling the data. Uses a
        // parser that echoes the number of input rows.
        struct EchoParser;
        impl LogParser for EchoParser {
            fn parse(&self, data: &str) -> Vec<ParsedTriple> {
                // Count the characters and emit one placeholder triple
                // per 10 characters — just a deterministic function of
                // the input size to verify the data made it through.
                let n = data.len() / 10;
                (0..n)
                    .map(|i| {
                        (
                            Entity::new(format!("u-{i}"), EntityType::User),
                            Relation::new(
                                format!("u-{i}"),
                                format!("p-{i}"),
                                RelationType::Auth,
                                i as i64,
                            ),
                            Entity::new(format!("p-{i}"), EntityType::Process),
                        )
                    })
                    .collect()
            }
        }
        let parser = EchoParser;
        let rows = vec![
            serde_json::json!({"col": "value1"}),
            serde_json::json!({"col": "value2"}),
        ];
        let triples = parser.parse_rows(&rows);
        assert!(
            !triples.is_empty(),
            "default parse_rows should delegate to parse"
        );
    }
}
