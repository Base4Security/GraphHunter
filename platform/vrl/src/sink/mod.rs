//! Cold-store sinks for the VRL fast lane.
//!
//! Today the pipeline ships the in-memory projection path plus a
//! Parquet sink (always available): local rolling files under
//! `<session>/cold/`, mature Arrow ecosystem, no external service
//! dependency.
//!
//! [`SinkRecord`] is the in-memory contract between the VRL projector
//! and any sink — the rest of the pipeline emits one
//! `Vec<SinkRecord>` and lets the configured sink decide how to land
//! it.

use serde::{Deserialize, Serialize};

/// One canonical event ready for cold-store persistence.
///
/// Carries the OCSF event payload as `serde_json::Value` (the same
/// shape `triple_to_ocsf` emits) plus the provenance fields the
/// review/audit path needs to cross-reference back to the raw row.
/// Sinks own the schema → physical-format mapping; this struct is the
/// stable in-memory contract between the VRL projector and the sink.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SinkRecord {
    pub event: serde_json::Value,
    pub source_dataset_id: String,
    pub mapping_id: String,
    pub mapping_hash: String,
    pub raw_event_sha256: String,
    /// Unix seconds of the event timestamp (not the ingest time).
    pub event_ts: i64,
}

/// Outcome of one batch write. Sinks return totals so the caller can
/// surface them in `LoadResult.ingest_stats` without needing to know
/// the underlying file/table layout.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct SinkWriteStats {
    pub records_written: u64,
    pub bytes_written: u64,
    /// Sink-specific identifiers (file paths, table snapshot ids, …)
    /// produced by this batch. Surfaced for audit but not interpreted
    /// by the ingest pipeline.
    pub artefacts: Vec<String>,
}
