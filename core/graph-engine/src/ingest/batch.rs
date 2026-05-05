//! The `ParsedBatch` type that flows between `ParserTask` and
//! `GraphWriter`, plus the `Priority` enum that lets enrichment batches
//! preempt background streaming batches.
//!
//! A `ParsedBatch` is the unit of work the graph writer consumes. It
//! carries:
//!
//! - The parsed events, ready for `insert_raw_events_chunk`.
//! - The source identity and dataset tag so the writer can tag the
//!   resulting `CompactRelation`s correctly without consulting external
//!   state.
//! - A priority flag so enrichment queries jump the writer queue.
//! - An optional watermark advance that the writer notifies back to the
//!   poller (via a side channel or direct call) once the batch is
//!   successfully inserted.
//! - Diagnostic counters (`row_count`, `dropped_rows`) for metrics.

use serde::{Deserialize, Serialize};

use crate::parser::RawIngestEvent;
use graph_hunter_sources::Watermark;

/// Priority of a parsed batch. Enrichment batches preempt normal
/// streaming ingest batches so on-demand drill-down stays responsive
/// even during bulk ingestion.
///
/// The writer doesn't actually reorder batches itself — it drains the
/// `parsed_tx` channel in arrival order. Priority is instead used at
/// two places:
///
/// 1. The writer's metrics break down chunks-written by priority, so
///    operators can see if enrichment is being starved.
/// 2. A future optimization can route enrichment batches through a
///    separate, higher-priority channel that the writer drains first.
///    The [`Priority`] field on every batch is the hook that enables
///    that without changing the writer's public API.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Priority {
    /// Background streaming ingest. The default for `SourcePoller`-
    /// originated batches.
    Normal,
    /// On-demand enrichment query triggered by an explicit user action
    /// (`cmd_enrich_entity` in Phase 7). Gets per-batch preemption
    /// accounting in the writer metrics.
    Enrichment,
}

impl Default for Priority {
    fn default() -> Self {
        Priority::Normal
    }
}

/// A parsed batch of events ready for the `GraphWriter` to insert.
///
/// The batch owns its `events` Vec. The writer drains the Vec via
/// repeated calls to `GraphHunter::insert_raw_events_chunk`, releasing
/// the write lock between chunks to let readers make progress.
///
/// `Serialize + Deserialize` derives support the overflow persistence
/// code path in `crate::ingest::overflow` — when a writer is cancelled
/// mid-shutdown with pending batches, they get round-tripped through
/// JSON to disk so the next startup can replay them.
#[derive(Debug, Serialize, Deserialize)]
pub struct ParsedBatch {
    /// Stable identifier of the source that produced the underlying
    /// raw chunk. Stored here so the writer can tag metrics and so
    /// downstream consumers (progress events, audit log) can associate
    /// the batch with its origin without a cross-lookup.
    pub source_id: String,

    /// Dataset the events should be attributed to when they land in
    /// `GraphHunter`. Passed straight through to `insert_raw_events_chunk`.
    /// `None` means "untagged" (legacy ingestion behavior).
    pub dataset_id: Option<String>,

    /// Scheduling priority.
    pub priority: Priority,

    /// The parsed events. Drained in-place by the writer.
    pub events: Vec<RawIngestEvent>,

    /// Number of source rows that produced this batch. May be larger
    /// than `events.len()` because one row can yield zero or many
    /// events depending on the parser.
    pub row_count: usize,

    /// Number of rows the parser rejected (malformed, schema drift,
    /// etc.). Surfaces in metrics so operators can see parser quality.
    pub dropped_rows: usize,

    /// Optional `(table, watermark)` that the caller (typically the
    /// source poller) should persist to the [`WatermarkStore`] after
    /// the writer successfully inserts this batch. `None` means the
    /// batch does not advance any watermark (e.g., it came from an
    /// enrichment query, not a polling cycle).
    ///
    /// The writer does NOT itself touch the watermark store. The
    /// source poller retains responsibility for ordering: it sends the
    /// batch, waits for the writer's ack, then updates the watermark.
    /// In the current design the ack is implicit — the writer drains
    /// the channel in FIFO order, so by the time the poller's send
    /// completes and it moves on to the next iteration, the batch is
    /// at least in the writer's queue.
    ///
    /// [`WatermarkStore`]: crate::watermark_store::WatermarkStore
    pub watermark_after: Option<(String, Watermark)>,
}

impl ParsedBatch {
    /// Constructs a batch with default priority (`Normal`) and zero
    /// dropped-row count. Convenience for parser-task code paths that
    /// don't need to set everything.
    pub fn new(source_id: impl Into<String>, events: Vec<RawIngestEvent>) -> Self {
        let row_count = events.len();
        Self {
            source_id: source_id.into(),
            dataset_id: None,
            priority: Priority::Normal,
            events,
            row_count,
            dropped_rows: 0,
            watermark_after: None,
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

    pub fn with_row_count(mut self, row_count: usize) -> Self {
        self.row_count = row_count;
        self
    }

    pub fn with_dropped_rows(mut self, dropped: usize) -> Self {
        self.dropped_rows = dropped;
        self
    }

    pub fn with_watermark(mut self, table: impl Into<String>, watermark: Watermark) -> Self {
        self.watermark_after = Some((table.into(), watermark));
        self
    }

    /// Returns the number of events still waiting to be inserted.
    /// Used by writer metrics.
    pub fn events_remaining(&self) -> usize {
        self.events.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_priority_is_normal() {
        assert_eq!(Priority::default(), Priority::Normal);
    }

    #[test]
    fn builder_round_trip() {
        let batch = ParsedBatch::new("la:ws-1", Vec::new())
            .with_dataset_id("dataset-7")
            .with_priority(Priority::Enrichment)
            .with_row_count(100)
            .with_dropped_rows(3)
            .with_watermark("SecurityEvent", Watermark::new("2026-04-09T12:00:00Z"));

        assert_eq!(batch.source_id, "la:ws-1");
        assert_eq!(batch.dataset_id.as_deref(), Some("dataset-7"));
        assert_eq!(batch.priority, Priority::Enrichment);
        assert_eq!(batch.row_count, 100);
        assert_eq!(batch.dropped_rows, 3);
        let (table, wm) = batch.watermark_after.as_ref().unwrap();
        assert_eq!(table, "SecurityEvent");
        assert_eq!(wm.as_str(), "2026-04-09T12:00:00Z");
        assert_eq!(batch.events_remaining(), 0);
    }
}
