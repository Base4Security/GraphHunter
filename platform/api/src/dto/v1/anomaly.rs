//! DTOs for the anomaly scorer lifecycle and the GNN model.

use crate::state::SessionHandle;
use graph_hunter_core::ScoringWeights;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct EnableAnomalyScoringRequest {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session: Option<SessionHandle>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub weights: Option<ScoringWeights>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpdateAnomalyWeightsRequest {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session: Option<SessionHandle>,
    pub weights: ScoringWeights,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct GetAnomalyConfigRequest {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session: Option<SessionHandle>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoadGnnModelRequest {
    pub model_path: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ComputeGnnScoresRequest {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session: Option<SessionHandle>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub k_hops: Option<usize>,
}
