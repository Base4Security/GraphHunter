//! Typed channel wrappers + default capacities for the streaming
//! ingest pipeline.
//!
//! The two channels the pipeline uses are:
//!
//! - `raw_tx` / `raw_rx` — `SourcePoller` → `ParserTask`. Carries
//!   `Result<RawChunk, SourceError>` so transport errors (429, 401,
//!   timeout) are propagated inline and the parser can skip them
//!   without crashing the task.
//! - `parsed_tx` / `parsed_rx` — `ParserTask` → `GraphWriter`. Carries
//!   `ParsedBatch` directly; parsing errors become dropped-row counters
//!   in the batch rather than channel errors.
//!
//! Both are `tokio::sync::mpsc::channel(N)` with small fixed capacities.
//! `sender.send().await` blocks when the channel is full — that's the
//! backpressure signal the pipeline relies on. Data never gets dropped
//! unless the receiver is explicitly closed.
//!
//! ## Capacity tuning
//!
//! Defaults come from the plan §3:
//!
//! - `DEFAULT_RAW_CAPACITY = 4` — a raw Log Analytics page can be
//!   ~50 MB of JSON at 500K rows × ~100 bytes, so 4 × 50 MB = 200 MB
//!   worst-case queue depth per source.
//! - `DEFAULT_PARSED_CAPACITY = 8` — a parsed batch is ~25K triples ×
//!   ~500 bytes per triple = 12 MB, so 8 × 12 MB = ~100 MB.
//!
//! Three concurrent sources (LA, Data Lake, Defender XDR) at steady
//! state queue roughly 1 GB worth of data in flight, well under the
//! 2 GB streaming-backend memory budget (set via
//! `InMemoryStreamingBackend::with_memory_budget_edges`, which auto-
//! spills past the threshold).
//!
//! Tune per-source by passing an explicit capacity to
//! [`raw_channel`] / [`parsed_channel`].

use graph_hunter_sources::{RawChunk, SourceError};
use tokio::sync::mpsc;

use super::batch::ParsedBatch;

/// Default raw-chunk channel capacity. Plan §3.
pub const DEFAULT_RAW_CAPACITY: usize = 4;

/// Default parsed-batch channel capacity. Plan §3.
pub const DEFAULT_PARSED_CAPACITY: usize = 8;

/// Sender type for the `SourcePoller` → `ParserTask` channel.
pub type RawSender = mpsc::Sender<Result<RawChunk, SourceError>>;

/// Receiver type for the `SourcePoller` → `ParserTask` channel.
pub type RawReceiver = mpsc::Receiver<Result<RawChunk, SourceError>>;

/// Sender type for the `ParserTask` → `GraphWriter` channel.
pub type ParsedSender = mpsc::Sender<ParsedBatch>;

/// Receiver type for the `ParserTask` → `GraphWriter` channel.
pub type ParsedReceiver = mpsc::Receiver<ParsedBatch>;

/// Creates a bounded `Result<RawChunk, SourceError>` channel with the
/// given capacity. Capacity of 0 is rejected — use `DEFAULT_RAW_CAPACITY`
/// as a safe default.
pub fn raw_channel(capacity: usize) -> (RawSender, RawReceiver) {
    let cap = capacity.max(1);
    mpsc::channel(cap)
}

/// Creates a bounded `ParsedBatch` channel.
pub fn parsed_channel(capacity: usize) -> (ParsedSender, ParsedReceiver) {
    let cap = capacity.max(1);
    mpsc::channel(cap)
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::Bytes;
    use graph_hunter_sources::{ChunkEncoding, RawChunk};

    fn make_chunk() -> RawChunk {
        RawChunk {
            source_id: "la:ws-1".to_string(),
            table: "SecurityEvent".to_string(),
            rows: Bytes::from_static(b"{}"),
            encoding: ChunkEncoding::Json,
            fetched_at: 0,
            watermark_candidate: None,
        }
    }

    #[tokio::test(flavor = "current_thread")]
    async fn raw_channel_roundtrip() {
        let (tx, mut rx) = raw_channel(DEFAULT_RAW_CAPACITY);
        tx.send(Ok(make_chunk())).await.unwrap();
        let got = rx.recv().await.unwrap().unwrap();
        assert_eq!(got.source_id, "la:ws-1");
    }

    #[tokio::test(flavor = "current_thread")]
    async fn raw_channel_blocks_when_full() {
        let (tx, mut rx) = raw_channel(1);
        tx.send(Ok(make_chunk())).await.unwrap();
        // try_send should fail now — channel is full.
        let try_res = tx.try_send(Ok(make_chunk()));
        assert!(try_res.is_err());
        // Draining one makes room again.
        let _ = rx.recv().await.unwrap();
        tx.try_send(Ok(make_chunk())).unwrap();
    }

    #[test]
    fn capacity_clamped_to_one() {
        // A zero capacity would panic inside tokio::sync::mpsc::channel;
        // we clamp to 1 so misuse doesn't crash the caller.
        let (_, _) = raw_channel(0);
        let (_, _) = parsed_channel(0);
    }
}
