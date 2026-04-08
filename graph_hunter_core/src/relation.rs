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
    #[serde(default, deserialize_with = "deserialize_arc_str", serialize_with = "serialize_arc_str")]
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
/// This is a 20% saving over the previous 40-byte layout (~1.6 GB on a
/// 28 GB EVTX with ~200M relations). Going further to 27 bytes requires
/// `#[repr(C, packed)]`, which complicates field references and is deferred.
///
/// Compared to the full `Relation` struct (~200 B), this is still ~84% smaller.
/// Metadata is stored externally in `MetadataStore`, referenced by offset.
#[derive(Clone, Copy, Debug)]
#[repr(C)]
pub struct CompactRelation {
    pub timestamp: i64,         // 8 bytes (align 8) — placed first to avoid pre-padding
    pub metadata_offset: u64,   // 8 bytes (0 = no metadata)
    pub source_sid: StrId,      // 4 bytes
    pub dest_sid: StrId,        // 4 bytes
    pub dataset_tag: u16,       // 2 bytes (index into dataset_tags vec, 0 = none)
    pub rel_type_tag: u8,       // 1 byte
    // 27 bytes inline + 5 bytes trailing struct-alignment padding (mult. of 8) = 32 B.
}

impl CompactRelation {
    /// Creates a new CompactRelation with no metadata.
    pub fn new(source_sid: StrId, dest_sid: StrId, rel_type: &RelationType, timestamp: i64) -> Self {
        Self {
            source_sid,
            dest_sid,
            rel_type_tag: rel_type.to_u8(),
            timestamp,
            metadata_offset: 0,
            dataset_tag: 0,
        }
    }

    /// Returns the relation type.
    #[inline]
    pub fn rel_type(&self) -> RelationType {
        RelationType::from_u8(self.rel_type_tag)
    }
}
