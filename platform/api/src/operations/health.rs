//! F4.7 / ADR-003 §D5 — process health + GNN model status probe.
//!
//! Exposes [`GraphHunterApi::get_health`], called by every transport
//! that wants to render a status indicator (Tauri status panel, MCP
//! `check_connection`, HTTP `/v1/health`).
//!
//! The v1 slot reads the runtime-loaded `NpuScorer`. The v2 slot is
//! driven by the compile-time `gnn-v2-experimental` feature; when the
//! feature is off, `loaded` is `false` with a reason explaining why.
//! When the feature is on, the current wiring still reports `loaded =
//! false` until a v2 scorer slot is added to `ApiState` — this leaves
//! the door open for that wiring without a contract change.

use crate::GraphHunterApi;
use crate::dto::health::{GnnHealth, HealthResponse, HealthStatus, ModelStatus};

impl GraphHunterApi {
    /// Returns a snapshot of process health + model availability.
    /// Cheap and non-blocking — safe to poll.
    pub fn get_health(&self) -> HealthResponse {
        HealthResponse {
            status: HealthStatus::Ok,
            version: env!("CARGO_PKG_VERSION").to_string(),
            gnn: GnnHealth {
                v1: self.gnn_v1_status(),
                v2: self.gnn_v2_status(),
            },
        }
    }

    #[cfg(feature = "ml-scoring")]
    fn gnn_v1_status(&self) -> ModelStatus {
        // `try_read` so we never block the health probe. A writer
        // holding the lock (rare — only during `load_gnn_model`) means
        // we report "unknown, in transition" rather than waiting.
        let loaded = self
            .inner
            .npu_scorer
            .try_read()
            .map(|g| g.is_some())
            .unwrap_or(false);
        ModelStatus {
            loaded,
            experimental: false,
            reason: (!loaded).then(|| "no v1 model loaded — call load_gnn_model first".to_string()),
        }
    }

    #[cfg(not(feature = "ml-scoring"))]
    fn gnn_v1_status(&self) -> ModelStatus {
        ModelStatus {
            loaded: false,
            experimental: false,
            reason: Some("ml-scoring feature disabled at compile time".to_string()),
        }
    }

    fn gnn_v2_status(&self) -> ModelStatus {
        #[cfg(feature = "gnn-v2-experimental")]
        {
            ModelStatus {
                loaded: false,
                experimental: true,
                reason: Some(
                    "gnn-v2-experimental compiled in; no v2 scorer slot wired yet".to_string(),
                ),
            }
        }
        #[cfg(not(feature = "gnn-v2-experimental"))]
        {
            ModelStatus {
                loaded: false,
                experimental: true,
                reason: Some("gnn-v2-experimental feature disabled at compile time".to_string()),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn health_reports_ok_and_expected_shape() {
        let api = GraphHunterApi::new_noop();
        let h = api.get_health();
        assert_eq!(h.status, HealthStatus::Ok);
        assert!(!h.version.is_empty(), "version present");
        // v2 is always experimental; never loaded at this F4.7 cut.
        assert!(h.gnn.v2.experimental);
        assert!(!h.gnn.v2.loaded);
        assert!(h.gnn.v2.reason.is_some(), "v2 reason populated");
    }

    #[test]
    fn health_response_serializes_stable_shape() {
        let api = GraphHunterApi::new_noop();
        let h = api.get_health();
        let v = serde_json::to_value(&h).unwrap();
        assert!(v.get("status").is_some());
        assert!(v.get("gnn").is_some());
        assert!(v["gnn"].get("v1").is_some());
        assert!(v["gnn"].get("v2").is_some());
        // status serializes lowercase
        assert_eq!(v["status"], "ok");
    }

    #[cfg(not(feature = "ml-scoring"))]
    #[test]
    fn v1_reports_feature_disabled_when_ml_scoring_off() {
        let api = GraphHunterApi::new_noop();
        let h = api.get_health();
        assert!(!h.gnn.v1.loaded);
        assert!(
            h.gnn
                .v1
                .reason
                .as_deref()
                .unwrap_or("")
                .contains("ml-scoring")
        );
    }
}
