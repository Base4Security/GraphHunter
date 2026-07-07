//! F4.7 / ADR-003 §D5 — process health + GNN model status.
//!
//! Returned by [`crate::GraphHunterApi::get_health`]. Surfaces which
//! inference models are currently usable so operators can tell at a
//! glance whether threat scores are coming from the stable v1 model,
//! the experimental v2 model, or nothing at all.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HealthResponse {
    pub status: HealthStatus,
    /// Crate version of `platform/api` at build time.
    pub version: String,
    pub gnn: GnnHealth,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum HealthStatus {
    Ok,
    Degraded,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GnnHealth {
    pub v1: ModelStatus,
    pub v2: ModelStatus,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModelStatus {
    /// True when the runtime has a model ready for inference.
    pub loaded: bool,
    /// True for models that are not yet production-validated.
    pub experimental: bool,
    /// Optional human-readable explanation — populated when `loaded`
    /// is false (e.g. "gnn-v2-experimental feature disabled") or when
    /// the scorer is running in a reduced mode.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}
