//! DTOs for analytics commands (heatmap, timeline, centrality, compact).

use crate::state::SessionHandle;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HeatmapRow {
    pub relation_type: String,
    pub bins: Vec<(i64, usize)>,
    /// Bucket width in seconds (default 3600). Included so consumers do
    /// not have to infer it from adjacent bucket deltas.
    pub bucket_size_seconds: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TimelineRow {
    pub entity_type: String,
    pub min_time: i64,
    pub max_time: i64,
    pub bins: Vec<(i64, usize)>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct TemporalHeatmapRequest {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session: Option<SessionHandle>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bucket_size_seconds: Option<i64>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct TimelineDataRequest {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session: Option<SessionHandle>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ComputeBetweennessRequest {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session: Option<SessionHandle>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sample_limit: Option<usize>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ComputePagerankRequest {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session: Option<SessionHandle>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub lambda: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub damping: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_iter: Option<usize>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reference_time: Option<i64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComputeCompositeScoresRequest {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session: Option<SessionHandle>,
    pub degree_weight: f64,
    pub pagerank_weight: f64,
    pub betweenness_weight: f64,
    /// Weight on `rarity_score` (inverse of degree). Omitted by old
    /// clients falls back to 0, preserving pre-rarity behaviour;
    /// defaults in new callers should lean on this as the dominant
    /// signal.
    #[serde(default)]
    pub rarity_weight: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CompactRequest {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session: Option<SessionHandle>,
    pub cutoff_timestamp: i64,
}
