//! IngestAdapter — the higher-level wrapper around
//! [`LogSource`] + [`LogParser`] (P2-E foundation).
//!
//! Where [`LogSource`] talks in raw JSON chunks and [`LogParser`]
//! talks in parsed triples, an [`IngestAdapter`] talks in
//! [`TripleBatch`]es — ready-to-write triples plus the watermark the
//! orchestrator should persist once the write succeeds. The adapter
//! is the surface a new source author implements: bring your own
//! [`LogSource`] (or skip it and stream from wherever), bring your
//! own parser (or use one of the built-ins), compose them into an
//! adapter, register it, done.
//!
//! # Migration story
//!
//! This module ships the trait + one generic impl that wraps an
//! existing [`LogSource`] + [`LogParser`]. Production ingest paths
//! (`graph_hunter_api::operations::ingestion`) keep their direct
//! `LogSource.poll_since → LogParser.parse_rows` wiring for now —
//! the adapter is here as the seam so the *next* new source (Okta,
//! Crowdstrike, …) plugs in via `impl IngestAdapter` rather than
//! editing core files.

use std::pin::Pin;
use std::sync::Arc;

use async_trait::async_trait;
use futures::stream::{BoxStream, StreamExt};
use tokio_util::sync::CancellationToken;

use crate::parser::{LogParser, ParsedTriple};
use graph_hunter_sources::{LogSource, RawChunk, SourceError, Watermark};

/// A single batch of ready-to-write triples plus the watermark the
/// orchestrator must persist after the batch has been written to the
/// graph successfully. Aligns with how the existing ingest pipeline
/// handles backpressure — one batch = one transaction boundary.
#[derive(Debug)]
pub struct TripleBatch {
    pub triples: Vec<ParsedTriple>,
    /// Watermark to persist AFTER this batch's triples are in the
    /// graph. If the caller crashes between write and watermark
    /// persistence, the source will re-deliver the batch on the next
    /// poll — ingest must stay idempotent on `(source_id, event_id)`.
    pub watermark: Watermark,
    /// When the upstream chunk was fetched, epoch milliseconds.
    /// Forwarded from [`RawChunk::fetched_at_ms`]. The P3 MVCC path
    /// will stamp `ingested_at` on each edge from this.
    pub fetched_at: i64,
}

/// Stream of triple batches. Boxed + `'static` so orchestrators can
/// push it into a tokio spawn without lifetime contortions.
pub type TripleBatchStream = BoxStream<'static, Result<TripleBatch, SourceError>>;

/// The adapter trait new source authors implement.
///
/// Implementations compose upstream primitives (`LogSource`,
/// `LogParser`, custom HTTP clients, file readers, …) into a single
/// "give me triples" contract. The adapter owns its own credentials,
/// watermark state, and parser — from the orchestrator's point of
/// view, it's a self-contained unit.
#[async_trait]
pub trait IngestAdapter: Send + Sync {
    /// Stable identifier for diagnostics and watermark scoping.
    /// Unique per running instance, e.g. `"sentinel:prod-eu"` or
    /// `"okta-webhook:acme-tenant"`.
    fn adapter_id(&self) -> &str;

    /// Tables / logical streams this adapter can drive. Same shape
    /// as [`LogSource::available_tables`] for adapters wrapping a
    /// LogSource; adapters that don't have a concept of "table" can
    /// return a single entry (e.g. `&["default"]`).
    fn tables(&self) -> &[&'static str];

    /// Start a long-lived stream of [`TripleBatch`]es for `table`,
    /// resuming from `since`. Mirrors [`LogSource::poll_since`]
    /// semantics:
    ///
    /// * The stream ends when there is no more new data. The
    ///   orchestrator sleeps and re-invokes.
    /// * `cancel` is observed at batch boundaries.
    /// * Watermarks are strictly monotonic.
    async fn stream_triples(
        &self,
        table: &str,
        since: Watermark,
        cancel: CancellationToken,
    ) -> Result<TripleBatchStream, SourceError>;
}

/// Generic adapter that wires any [`LogSource`] to any
/// [`LogParser`]. Ships so the three existing sources (Log
/// Analytics, Defender XDR, Data Lake) can be exposed as adapters
/// without rewriting their connectors.
pub struct LogSourceAdapter {
    /// Stable id for diagnostics.
    pub id: String,
    /// The underlying source — owned via `Arc` because the poll
    /// stream it hands back borrows from self.
    pub source: Arc<dyn LogSource>,
    /// The format parser that turns `RawChunk::rows` JSON into
    /// [`ParsedTriple`]s.
    pub parser: Arc<dyn LogParser>,
}

impl LogSourceAdapter {
    pub fn new(
        id: impl Into<String>,
        source: Arc<dyn LogSource>,
        parser: Arc<dyn LogParser>,
    ) -> Self {
        Self {
            id: id.into(),
            source,
            parser,
        }
    }

    /// Convert a single raw chunk into a [`TripleBatch`] using the
    /// parser. Extracted so unit tests can exercise the parse logic
    /// in isolation without spinning up the stream.
    pub fn parse_chunk(&self, chunk: &RawChunk) -> Vec<ParsedTriple> {
        // For chunks that carry pre-decoded JSON rows we could
        // call `parser.parse_rows(...)` directly. The RawChunk API
        // currently exposes `rows: Bytes` (raw bytes), so we take
        // the string path — a parser override (`SentinelJsonParser`)
        // does the rows path when the orchestrator feeds it
        // `serde_json::Value` arrays directly.
        let text = match std::str::from_utf8(&chunk.rows) {
            Ok(s) => s,
            Err(_) => return Vec::new(),
        };
        self.parser.parse(text)
    }
}

#[async_trait]
impl IngestAdapter for LogSourceAdapter {
    fn adapter_id(&self) -> &str {
        &self.id
    }

    fn tables(&self) -> &[&'static str] {
        self.source.available_tables()
    }

    async fn stream_triples(
        &self,
        table: &str,
        since: Watermark,
        cancel: CancellationToken,
    ) -> Result<TripleBatchStream, SourceError> {
        let source = Arc::clone(&self.source);
        let parser = Arc::clone(&self.parser);
        let poll = source.poll_since(table, since, cancel).await?;

        // Map each (RawChunk, Watermark) yield into a TripleBatch.
        // `.boxed()` is required to match the `BoxStream<'static>`
        // alias; the closure captures the parser by `Arc` so nothing
        // borrows `&self` across the await boundary.
        let stream: Pin<Box<_>> = poll
            .map(move |item| {
                let (chunk, wm) = item?;
                let text = std::str::from_utf8(&chunk.rows)
                    .map_err(|e| SourceError::Schema(format!("utf8 decode: {e}")))?;
                let triples = parser.parse(text);
                Ok(TripleBatch {
                    triples,
                    watermark: wm,
                    fetched_at: chunk.fetched_at,
                })
            })
            .boxed();

        Ok(stream)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::entity::Entity;
    use crate::relation::Relation;
    use crate::types::{EntityType, RelationType};
    use async_trait::async_trait;
    use bytes::Bytes;
    use futures::stream;
    use graph_hunter_sources::{ChunkEncoding, ChunkStream, QueryScope, SourceKind};

    struct FixedParser;
    impl LogParser for FixedParser {
        fn parse(&self, data: &str) -> Vec<ParsedTriple> {
            // Deterministic: one triple per non-empty line.
            data.lines()
                .filter(|l| !l.trim().is_empty())
                .enumerate()
                .map(|(i, _)| {
                    (
                        Entity::new(format!("u{i}"), EntityType::User),
                        Relation::new(
                            format!("u{i}"),
                            "web-01".to_string(),
                            RelationType::Auth,
                            1_700_000_000 + i as i64,
                        ),
                        Entity::new("web-01".to_string(), EntityType::Host),
                    )
                })
                .collect()
        }
    }

    struct MockSource {
        chunks: Vec<RawChunk>,
    }

    #[async_trait]
    impl LogSource for MockSource {
        fn source_id(&self) -> &str {
            "mock"
        }
        fn kind(&self) -> SourceKind {
            SourceKind::LogAnalytics
        }
        fn available_tables(&self) -> &[&'static str] {
            &["MockTable"]
        }
        async fn check_auth(&self) -> Result<(), SourceError> {
            Ok(())
        }
        async fn query_scoped(
            &self,
            _scope: QueryScope,
            _cancel: CancellationToken,
        ) -> Result<ChunkStream, SourceError> {
            Ok(stream::empty().boxed())
        }
        async fn poll_since(
            &self,
            _table: &str,
            _watermark: Watermark,
            _cancel: CancellationToken,
        ) -> Result<graph_hunter_sources::PollStream, SourceError> {
            // Emit each chunk with an increasing watermark.
            let items: Vec<Result<(RawChunk, Watermark), SourceError>> = self
                .chunks
                .iter()
                .enumerate()
                .map(|(i, c)| {
                    Ok((
                        c.clone(),
                        Watermark::new((1_700_000_000i64 + i as i64).to_string()),
                    ))
                })
                .collect();
            Ok(stream::iter(items).boxed())
        }
    }

    #[tokio::test]
    async fn log_source_adapter_yields_parsed_batches() {
        let source = Arc::new(MockSource {
            chunks: vec![
                RawChunk {
                    source_id: "mock".into(),
                    table: "MockTable".into(),
                    rows: Bytes::from_static(b"line1\nline2\n"),
                    encoding: ChunkEncoding::Jsonl,
                    fetched_at: 12_345,
                    watermark_candidate: None,
                },
                RawChunk {
                    source_id: "mock".into(),
                    table: "MockTable".into(),
                    rows: Bytes::from_static(b"line3\n"),
                    encoding: ChunkEncoding::Jsonl,
                    fetched_at: 12_346,
                    watermark_candidate: None,
                },
            ],
        });
        let parser: Arc<dyn LogParser> = Arc::new(FixedParser);
        let adapter = LogSourceAdapter::new("mock-1", source, parser);

        assert_eq!(adapter.adapter_id(), "mock-1");
        assert_eq!(adapter.tables(), &["MockTable"]);

        let cancel = CancellationToken::new();
        let mut stream = adapter
            .stream_triples("MockTable", Watermark::default(), cancel)
            .await
            .expect("stream");

        let first = stream.next().await.expect("first").expect("ok");
        assert_eq!(first.triples.len(), 2);
        assert_eq!(first.fetched_at, 12_345);

        let second = stream.next().await.expect("second").expect("ok");
        assert_eq!(second.triples.len(), 1);
        assert_eq!(second.fetched_at, 12_346);

        assert!(stream.next().await.is_none(), "stream must end");
    }

    #[tokio::test]
    async fn parse_chunk_standalone() {
        let parser: Arc<dyn LogParser> = Arc::new(FixedParser);
        let source: Arc<dyn LogSource> = Arc::new(MockSource { chunks: vec![] });
        let adapter = LogSourceAdapter::new("test", source, parser);
        let chunk = RawChunk {
            source_id: "test".into(),
            table: "MockTable".into(),
            rows: Bytes::from_static(b"a\nb\nc\n"),
            encoding: ChunkEncoding::Jsonl,
            fetched_at: 0,
            watermark_candidate: None,
        };
        let triples = adapter.parse_chunk(&chunk);
        assert_eq!(triples.len(), 3);
    }
}
