use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::collections::HashMap;
use std::sync::Arc;

use crate::types::EntityType;

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

/// A node in the threat graph representing an observable entity.
///
/// Uses String IDs instead of references to avoid borrow checker complexity.
/// Metadata is a flexible key-value store for enrichment data (GeoIP, reputation, etc.).
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct Entity {
    pub id: String,
    pub entity_type: EntityType,
    pub score: f64,
    pub metadata: HashMap<String, String>,
    /// Optional dataset this entity came from (for remove/rename by dataset).
    #[serde(default, deserialize_with = "deserialize_arc_str", serialize_with = "serialize_arc_str")]
    pub dataset_id: Option<Arc<str>>,
    /// Normalized degree centrality [0, 100].
    #[serde(default)]
    pub degree_score: f64,
    /// Betweenness centrality (Brandes), normalized [0, 100].
    #[serde(default)]
    pub betweenness: f64,
    /// Temporal PageRank score, normalized [0, 100].
    #[serde(default)]
    pub pagerank_score: f64,
}

impl Entity {
    /// Creates a new entity with zero threat score and empty metadata.
    pub fn new(id: impl Into<String>, entity_type: EntityType) -> Self {
        Self {
            id: id.into(),
            entity_type,
            score: 0.0,
            metadata: HashMap::new(),
            dataset_id: None,
            degree_score: 0.0,
            betweenness: 0.0,
            pagerank_score: 0.0,
        }
    }

    /// Creates a new entity with an initial threat score.
    pub fn with_score(id: impl Into<String>, entity_type: EntityType, score: f64) -> Self {
        Self {
            id: id.into(),
            entity_type,
            score,
            metadata: HashMap::new(),
            dataset_id: None,
            degree_score: 0.0,
            betweenness: 0.0,
            pagerank_score: 0.0,
        }
    }

    /// Adds a metadata key-value pair, returning self for builder-pattern chaining.
    pub fn with_metadata(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.metadata.insert(key.into(), value.into());
        self
    }
}

impl PartialEq for Entity {
    fn eq(&self, other: &Self) -> bool {
        self.id == other.id
    }
}

impl Eq for Entity {}

impl std::hash::Hash for Entity {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.id.hash(state);
    }
}
