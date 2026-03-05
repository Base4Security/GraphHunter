use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::collections::HashMap;
use std::sync::Arc;

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
