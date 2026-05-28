use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::collections::HashMap;
use std::sync::Arc;

use crate::interner::StrId;
use crate::types::RelationType;

fn deserialize_arc_str<'de, D>(deserializer: D) -> Result<Option<Arc<str>>, D::Error>
where
    D: Deserializer<'de>,
{
    let opt: Option<String> = Option::deserialize(deserializer)?;
    Ok(opt.map(|s| Arc::from(s.as_str())))
}

fn serialize_arc_str<S>(val: &Option<Arc<str>>, serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    match val {
        Some(s) => serializer.serialize_some(&**s),
        None => serializer.serialize_none(),
    }
}

/// A directed edge in the threat graph representing an observed relationship
/// between two entities at a specific point in time.
///
/// The `timestamp` field stores Unix epoch seconds and is critical for
/// temporal pattern matching (causal monotonicity enforcement).
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct Relation {
    pub source_id: String,
    pub dest_id: String,
    pub rel_type: RelationType,
    pub timestamp: i64,
    pub metadata: HashMap<String, String>,
    /// Optional dataset this relation came from (for remove by dataset).
    #[serde(
        default,
        deserialize_with = "deserialize_arc_str",
        serialize_with = "serialize_arc_str"
    )]
    pub dataset_id: Option<Arc<str>>,
}

impl Relation {
    /// Creates a new relation with empty metadata.
    pub fn new(
        source_id: impl Into<String>,
        dest_id: impl Into<String>,
        rel_type: RelationType,
        timestamp: i64,
    ) -> Self {
        Self {
            source_id: source_id.into(),
            dest_id: dest_id.into(),
            rel_type,
            timestamp,
            metadata: HashMap::new(),
            dataset_id: None,
        }
    }

    /// Adds a metadata key-value pair, returning self for builder-pattern chaining.
    pub fn with_metadata(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.metadata.insert(key.into(), value.into());
        self
    }
}

/// Memory-efficient edge representation for the adjacency list.
///
/// **Layout note (2026-04-07 repack):** the previous field order was
/// [source_sid, dest_sid, rel_type_tag, timestamp, metadata_offset, dataset_tag]
/// which under `#[repr(C)]` produced 40 bytes due to padding before `timestamp`
/// (i64 alignment) and after `dataset_tag` (struct alignment to 8). Reordering
/// from largest to smallest alignment compacts inline data to 27 bytes plus
/// 5 bytes of trailing struct-alignment padding → **32 bytes** total.
///
/// **MVCC note (P3):** the 5 bytes of trailing padding were free real
/// estate. `ingested_at_delta: u32` reclaims 4 of them; the struct
/// stays at 32 bytes. The delta is stored against
/// [`INGEST_EPOCH_BASE`] (2024-01-01 UTC); `fn ingested_at()` adds it
/// back. Range covers ~136 years from the epoch base — well beyond
/// any realistic retention window. `Default` produces `0`, which
/// resolves to the epoch itself; legacy loaders that don't populate
/// the field surface as "ingested at 2024-01-01" rather than NaN.
///
/// This is a 20% saving over the previous 40-byte layout (~1.6 GB on a
/// 28 GB EVTX with ~200M relations). Going further to 27 bytes requires
/// `#[repr(C, packed)]`, which complicates field references and is deferred.
///
/// Compared to the full `Relation` struct (~200 B), this is still ~84% smaller.
/// Metadata is stored externally in `MetadataStore`, referenced by offset.
#[derive(Clone, Copy, Debug)]
#[repr(C)]
pub struct CompactRelation {
    pub timestamp: i64,       // 8 bytes (align 8) — placed first to avoid pre-padding
    pub metadata_offset: u64, // 8 bytes (0 = no metadata)
    pub source_sid: StrId,    // 4 bytes
    pub dest_sid: StrId,      // 4 bytes
    /// Seconds since [`INGEST_EPOCH_BASE`] — the moment this edge was
    /// written to the graph, independent of the event's own
    /// [`timestamp`]. Used by the P3 MVCC snapshot API to answer
    /// "what did the graph know at time T".
    pub ingested_at_delta: u32, // 4 bytes
    pub dataset_tag: u16,     // 2 bytes (index into dataset_tags vec, 0 = none)
    pub rel_type_tag: u8,     // 1 byte
                              // 31 bytes inline + 1 byte trailing struct-alignment padding (mult. of 8) = 32 B.
}

/// Epoch base for [`CompactRelation::ingested_at_delta`].
/// `2024-01-01T00:00:00Z` — chosen so the `u32` delta covers
/// ~2160-01 before overflow, and so every retention window the tool
/// sees in practice fits in the positive range.
pub const INGEST_EPOCH_BASE: i64 = 1_704_067_200;

impl CompactRelation {
    /// Creates a new CompactRelation with no metadata. `ingested_at`
    /// defaults to the epoch base — callers that care about the
    /// MVCC semantics should set it via
    /// [`Self::with_ingested_at`] or the ingest pipeline.
    pub fn new(
        source_sid: StrId,
        dest_sid: StrId,
        rel_type: &RelationType,
        timestamp: i64,
    ) -> Self {
        Self {
            source_sid,
            dest_sid,
            rel_type_tag: rel_type.to_u8(),
            timestamp,
            metadata_offset: 0,
            dataset_tag: 0,
            ingested_at_delta: 0,
        }
    }

    /// Builder-style setter for `ingested_at` (epoch seconds). Values
    /// below [`INGEST_EPOCH_BASE`] are clamped to the base; values
    /// above the `u32` ceiling (year ~2160) saturate at `u32::MAX`
    /// and will still compare monotonically within the supported
    /// range.
    pub fn with_ingested_at(mut self, ingested_at: i64) -> Self {
        self.ingested_at_delta = encode_ingested_at(ingested_at);
        self
    }

    /// Resolves the stored delta back to absolute epoch seconds.
    #[inline]
    pub fn ingested_at(&self) -> i64 {
        INGEST_EPOCH_BASE + self.ingested_at_delta as i64
    }

    /// Returns the relation type.
    #[inline]
    pub fn rel_type(&self) -> RelationType {
        RelationType::from_u8(self.rel_type_tag)
    }
}

/// Encode an absolute epoch-second timestamp into the delta stored
/// inside [`CompactRelation`]. Used by ingest paths; exposed so
/// callers constructing a [`CompactRelation`] manually can compute
/// the delta without re-deriving the formula.
#[inline]
pub fn encode_ingested_at(ingested_at: i64) -> u32 {
    if ingested_at <= INGEST_EPOCH_BASE {
        return 0;
    }
    let delta = ingested_at - INGEST_EPOCH_BASE;
    if delta > u32::MAX as i64 {
        u32::MAX
    } else {
        delta as u32
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn compact_relation_stays_32_bytes() {
        // The MVCC `ingested_at_delta` must fit into pre-existing
        // trailing padding. If this assertion ever fires, a struct
        // edit accidentally grew `CompactRelation` and is about to
        // cost ~20% of the in-memory graph footprint.
        assert_eq!(std::mem::size_of::<CompactRelation>(), 32);
    }

    #[test]
    fn encode_ingested_at_clamps_to_epoch_base() {
        assert_eq!(encode_ingested_at(0), 0);
        assert_eq!(encode_ingested_at(INGEST_EPOCH_BASE - 100), 0);
        assert_eq!(encode_ingested_at(INGEST_EPOCH_BASE), 0);
    }

    #[test]
    fn encode_ingested_at_saturates_beyond_u32() {
        // Year ~2160 is the delta ceiling (u32::MAX seconds ≈ 136yr).
        let way_future = INGEST_EPOCH_BASE + u32::MAX as i64 + 10;
        assert_eq!(encode_ingested_at(way_future), u32::MAX);
    }

    #[test]
    fn ingested_at_roundtrips() {
        let sid = StrId::from_raw(0);
        let rel = CompactRelation::new(sid, sid, &RelationType::Auth, 123);
        let stamped = rel.with_ingested_at(INGEST_EPOCH_BASE + 3_600 * 24);
        assert_eq!(stamped.ingested_at(), INGEST_EPOCH_BASE + 86_400);
    }

    #[test]
    fn default_delta_resolves_to_epoch_base() {
        let sid = StrId::from_raw(0);
        let rel = CompactRelation::new(sid, sid, &RelationType::Auth, 0);
        // Legacy edges (`ingested_at_delta = 0`) surface as the epoch
        // base rather than NaN/0 — a defined, if imprecise, instant.
        assert_eq!(rel.ingested_at(), INGEST_EPOCH_BASE);
    }
}
