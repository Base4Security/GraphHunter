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
/// 27 bytes vs ~200 bytes per Relation. Metadata is stored externally
/// in MetadataStore, referenced by offset.
#[derive(Clone, Copy, Debug)]
#[repr(C)]
pub struct CompactRelation {
    pub source_sid: StrId,      // 4 bytes
    pub dest_sid: StrId,        // 4 bytes
    pub rel_type_tag: u8,       // 1 byte
    pub timestamp: i64,         // 8 bytes
    pub metadata_offset: u64,   // 8 bytes (0 = no metadata)
    pub dataset_tag: u16,       // 2 bytes (index into dataset_tags vec, 0 = none)
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
