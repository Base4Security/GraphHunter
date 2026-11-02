//! The canonical event envelope: what a raw event carries through the journal
//! that ProvenanceCtx alone does not — event vs ingestion time, native id,
//! routing (tenant/workspace/table), normalizer version, a canonical hash, the
//! raw payload, and a change kind (insert/correction/tombstone/skipped). The
//! envelope is frozen at ingest time and never re-derived, which is what lets
//! the journal answer "what raw event produced this, and when did it arrive?"
//! (design spec §8; closes assessment channels ingestion_time, field_survival,
//! provenance_stability, row_completeness).

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::provenance::ProvenanceCtx;

/// The current envelope/normalizer version. Bump when the envelope shape or the
/// canonicalization rules change; already-journaled events keep their recorded
/// version, so a bump never reinterprets old events (design spec §10).
pub const NORMALIZER_VERSION: u32 = 1;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ChangeKind {
    Insert,
    Correction,
    Tombstone,
    Skipped,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct CanonicalEnvelope {
    pub source_id: String,
    pub source_kind: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tenant: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub workspace: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub table: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub native_id: Option<String>,
    /// Epoch-ms event time (when the event occurred), from the source row.
    pub event_time: i64,
    /// Epoch-ms ingestion time (when GraphHunter received it). Distinct from
    /// event_time — this is what the graph edge hardcodes to 0 today (S6).
    pub ingestion_time: i64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cursor: Option<String>,
    pub normalizer_version: u32,
    pub canonical_hash: String,
    /// The serialized event used for identity (`canonical_hash`, via
    /// `compute_hash`) and reconstruction (`envelope_to_delta` deserializes
    /// this back into a `RawIngestEvent`). For Insert envelopes this MUST be
    /// per-event-distinct — see `raw_source_row` below for the verbatim
    /// source row instead.
    pub raw_payload: String,
    /// The verbatim/canonical source row, kept separately from `raw_payload`
    /// so unmapped fields and skipped rows remain reconstructable
    /// (field_survival, row_completeness) WITHOUT perturbing edge identity or
    /// multiplicity. A single source row can produce multiple distinct
    /// events (e.g. a Sentinel 4688 process-create row yields both a
    /// User->Execute->Process and a Parent->Execute->Child event) that all
    /// share the same `raw_source_row` but must still hash and dedup
    /// independently via their own `raw_payload` (Fase C-2 critical-fix
    /// wave, whole-phase final review). Deliberately excluded from
    /// `compute_hash` — identity stays keyed on `raw_payload` alone.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub raw_source_row: Option<String>,
    /// On-disk form only: "my `raw_source_row` is the one this many
    /// envelopes back". The journal writes a source row once per row group
    /// instead of once per event — an Auth0 row fans out to several events,
    /// and the row was a third of each JSONL line. Readers never see it:
    /// `JournalStore::read_all` resolves it back into `raw_source_row`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub raw_source_back: Option<u32>,
    pub change_kind: ChangeKind,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub skip_reason: Option<String>,
    /// Provenance frozen at ingest. Never re-read at export (provenance_stability).
    pub provenance: ProvenanceCtx,
}

impl CanonicalEnvelope {
    pub fn new_insert(
        source_id: String,
        source_kind: String,
        event_time: i64,
        ingestion_time: i64,
        raw_payload: String,
        provenance: ProvenanceCtx,
    ) -> Self {
        let canonical_hash = Self::compute_hash(&raw_payload, &provenance);
        CanonicalEnvelope {
            source_id,
            source_kind,
            tenant: None,
            workspace: None,
            table: None,
            native_id: None,
            event_time,
            ingestion_time,
            cursor: None,
            normalizer_version: NORMALIZER_VERSION,
            canonical_hash,
            raw_payload,
            raw_source_row: None,
            raw_source_back: None,
            change_kind: ChangeKind::Insert,
            skip_reason: None,
            provenance,
        }
    }

    /// Attach the verbatim source row for field_survival (see
    /// `raw_source_row`'s doc comment). Does NOT affect `canonical_hash` —
    /// call this AFTER `new_insert`, whose hash is already computed from
    /// `raw_payload` alone.
    pub fn with_source_row(mut self, raw_source_row: Option<String>) -> Self {
        self.raw_source_row = raw_source_row;
        self
    }

    /// Mark this envelope as a skipped (unparseable) row, preserving its raw
    /// payload and recording why. Used so the journal accounts for every row,
    /// not just the ones that produced graph edges.
    pub fn as_skipped(mut self, reason: String) -> Self {
        self.change_kind = ChangeKind::Skipped;
        self.skip_reason = Some(reason);
        self
    }

    /// sha256(raw_payload || provenance.mapping_hash) as lowercase hex. Ties the
    /// hash to the mapping that produced it, so the same raw row under two
    /// mappings hashes differently.
    pub fn compute_hash(raw_payload: &str, provenance: &ProvenanceCtx) -> String {
        let mut h = Sha256::new();
        h.update(raw_payload.as_bytes());
        h.update(b"\0");
        h.update(provenance.mapping_hash.as_bytes());
        format!("{:x}", h.finalize())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::provenance::ProvenanceCtx;

    fn prov() -> ProvenanceCtx {
        ProvenanceCtx::for_builtin_parser("sysmon", "ds-1", b"{\"raw\":1}")
    }

    #[test]
    fn insert_envelope_carries_both_times_and_frozen_provenance() {
        let p = prov();
        let e = CanonicalEnvelope::new_insert(
            "la:ws-1".into(),
            "la".into(),
            1000,
            2000,
            "{\"raw\":1}".into(),
            p.clone(),
        );
        assert_eq!(e.event_time, 1000);
        assert_eq!(e.ingestion_time, 2000);
        assert_eq!(e.change_kind, ChangeKind::Insert);
        assert!(e.skip_reason.is_none());
        // provenance is embedded verbatim (frozen at ingest).
        assert_eq!(e.provenance, p);
        // hash is deterministic and non-empty.
        assert!(!e.canonical_hash.is_empty());
        assert_eq!(
            e.canonical_hash,
            CanonicalEnvelope::compute_hash("{\"raw\":1}", &p)
        );
    }

    #[test]
    fn skipped_envelope_records_reason_and_preserves_raw() {
        let e = CanonicalEnvelope::new_insert(
            "la:ws-1".into(),
            "la".into(),
            0,
            5,
            "malformed-row".into(),
            prov(),
        )
        .as_skipped("no_triple".into());
        assert_eq!(e.change_kind, ChangeKind::Skipped);
        assert_eq!(e.skip_reason.as_deref(), Some("no_triple"));
        // the raw row survives even though it was skipped (row_completeness).
        assert_eq!(e.raw_payload, "malformed-row");
    }

    #[test]
    fn hash_changes_with_payload_and_is_stable() {
        let p = prov();
        let h1 = CanonicalEnvelope::compute_hash("a", &p);
        let h2 = CanonicalEnvelope::compute_hash("b", &p);
        assert_ne!(h1, h2);
        assert_eq!(h1, CanonicalEnvelope::compute_hash("a", &p)); // stable
    }

    #[test]
    fn envelope_roundtrips_through_json() {
        let e = CanonicalEnvelope::new_insert("s".into(), "la".into(), 1, 2, "{}".into(), prov());
        let s = serde_json::to_string(&e).unwrap();
        let back: CanonicalEnvelope = serde_json::from_str(&s).unwrap();
        assert_eq!(e, back);
    }
}
