//! Streaming ingest pipeline (Phase 4 of the Azure streaming plan).
//!
//! Wires together the Phase 2 / Phase 3 abstractions — [`LogSource`],
//! [`LogParser`], [`WatermarkStore`], and [`GraphHunter`] — into a
//! backpressure-aware pipeline that can sustain tera-scale polling
//! without bottlenecking on the graph write lock or ballooning RAM.
//!
//! ## Topology
//!
//! ```text
//!   SourcePoller (one per source instance)
//!        │  raw_tx: bounded(4)
//!        ▼
//!   ParserTask  (one per source instance)
//!        │  parsed_tx: bounded(8)
//!        ▼
//!   GraphWriter (single task, shared across all sources)
//!        │  holds write lock only during `insert_triples_chunk`
//!        ▼
//!   RwLock<GraphHunter>
//! ```
//!
//! ## Why bounded channels
//!
//! Every channel here is a `tokio::sync::mpsc::channel(N)` with a small
//! fixed capacity. `sender.send().await` blocks when the channel is
//! full, which is exactly the backpressure signal we want: if the
//! graph writer falls behind, the parser's `parsed_tx.send` blocks,
//! which causes the parser's `raw_rx.recv` to back up, which causes
//! the source poller's `raw_tx.send` to block, which makes the poller
//! stop calling Azure. Backpressure propagates all the way to the
//! remote API without dropping data.
//!
//! ## Why one writer, not one-per-source
//!
//! The graph's `RwLock` is held exclusively during writes. If every
//! source wrote independently, they'd fight over the lock and starve
//! readers (hunts, on-demand enrichment). A single [`GraphWriter`]
//! serializes access and yields between chunks, giving readers
//! deterministic progress bounds.
//!
//! The single-writer model is an unmeasured bet (plan §Risks #3). If
//! metrics show the writer saturated at >80% CPU, Phase 5 will add
//! per-shard writers or a lock-striping layer. For now, ship the
//! simpler design and instrument it.
//!
//! ## Module layout
//!
//! - [`batch`] — the `ParsedBatch` type that flows through `parsed_tx`,
//!   plus the `Priority` enum that lets enrichment batches preempt
//!   background streaming batches.
//! - [`channels`] — typed wrappers + default capacities for the two
//!   pipeline channels.
//! - [`graph_access`] — the `GraphAccess` trait that abstracts over
//!   "grab the graph write lock, insert a chunk, release". Lets the
//!   writer run against a mock graph in unit tests without any Tauri
//!   dependency.
//! - [`writer`] — the `GraphWriter` task and its metrics.
//! - [`parser_task`] — the `ParserTask` that decodes raw chunks into
//!   `ParsedBatch`es using a `LogParser`.
//! - [`source_poller`] — the `SourcePoller` that drives
//!   `LogSource::poll_since` on a timer and forwards chunks into
//!   `raw_tx`, advancing the persistent watermark as it goes.
//!
//! ## What this module does NOT include
//!
//! - Task spawning — the caller owns `tokio::spawn` / `JoinHandle`
//!   lifecycle. This keeps the module testable without a runtime
//!   already up and makes the ownership story explicit at the Tauri
//!   app layer (Phase 5).
//! - The real `HttpClient` — still trait-level (Phase 3 + `MockHttpClient`).
//!   A `reqwest`-backed impl lands in the Tauri app alongside the task
//!   wiring.
//! - Memory-pressure guards and disk-space guards — those live in
//!   `streaming.with_memory_budget_edges` (auto-spill threshold).
//!   The writer just trusts the graph to push back via `GraphError::Spill`.
//!
//! [`LogSource`]: graph_hunter_sources::LogSource
//! [`LogParser`]: crate::parser::LogParser
//! [`WatermarkStore`]: crate::watermark_store::WatermarkStore
//! [`GraphHunter`]: crate::graph::GraphHunter
//! [`GraphWriter`]: writer::GraphWriter

pub mod batch;
pub mod cancellation;
pub mod channels;
pub mod coverage;
pub mod enrichment;
pub mod enrichment_cache;
pub mod graph_access;
pub mod metrics;
pub mod overflow;
pub mod parser_task;
pub mod source_poller;
pub mod writer;

pub use batch::{ParsedBatch, Priority};
pub use channels::{
    DEFAULT_PARSED_CAPACITY, DEFAULT_RAW_CAPACITY, ParsedReceiver, ParsedSender, RawReceiver,
    RawSender, parsed_channel, raw_channel,
};
pub use coverage::{
    CoverageBucket, CoverageGap, DEFAULT_BUCKET_SECONDS, DEFAULT_MAX_BUCKETS, DataCoverage,
};
pub use graph_access::{DEFAULT_WRITE_CHUNK_SIZE, GraphAccess};
pub use metrics::{
    IngestMetricsRegistry, IngestMetricsSnapshot, QuotaKey, QuotaSnapshot, SourceMetricHandles,
    SourceMetricsSnapshot,
};
pub use parser_task::ParserTask;
pub use source_poller::{
    CircuitState, DEFAULT_POLL_INTERVAL, PollerConfig, SourcePoller,
};
pub use writer::{GraphWriter, WriterMetrics, WriterMetricsSnapshot};
