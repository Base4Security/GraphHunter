//! Anomaly scoring + GNN model operations.
//!
//! The anomaly scorer lives inside the graph (`graph.anomaly_scorer`);
//! enabling / updating / reading it is per-session state. The GNN
//! scorer is app-global (one ONNX model shared across sessions) and
//! lives in [`ApiState::npu_scorer`], exposed by
//! [`GraphHunterApi::npu_scorer_handle`].

use graph_hunter_core::ScoringWeights;

use crate::dto::anomaly::{
    EnableAnomalyScoringRequest, GetAnomalyConfigRequest, UpdateAnomalyWeightsRequest,
};
use crate::{ApiError, ApiResult, GraphHunterApi};

impl GraphHunterApi {
    /// Enable anomaly scoring with optional custom weights. If the
    /// scorer is already active, this re-installs it with fresh
    /// weights (re-finalizes observations).
    pub fn enable_anomaly_scoring(&self, req: EnableAnomalyScoringRequest) -> ApiResult<()> {
        self.with_graph_write(req.session.as_ref(), |g| {
            g.enable_anomaly_scoring(req.weights.unwrap_or_default());
            Ok(())
        })
    }

    /// Update the weights on an already-enabled scorer without
    /// re-finalizing. Errors if the scorer is not enabled.
    pub fn update_anomaly_weights(&self, req: UpdateAnomalyWeightsRequest) -> ApiResult<()> {
        self.with_graph_write(req.session.as_ref(), |g| {
            if let Some(s) = g.anomaly_scorer.as_mut() {
                s.set_weights(req.weights);
                Ok(())
            } else {
                Err(ApiError::InvalidState(
                    "anomaly scoring is not enabled".into(),
                ))
            }
        })
    }

    /// Returns the current scorer's weights or `None` when scoring is
    /// not enabled.
    pub fn get_anomaly_config(
        &self,
        req: GetAnomalyConfigRequest,
    ) -> ApiResult<Option<ScoringWeights>> {
        self.with_graph_read(req.session.as_ref(), |g| {
            Ok(g.anomaly_scorer.as_ref().map(|s| s.weights().clone()))
        })
    }
}

// ── GNN scorer (only compiled with the `ml-scoring` feature) ────────────

#[cfg(feature = "ml-scoring")]
mod gnn_ops {
    use super::*;
    use crate::dto::anomaly::{ComputeGnnScoresRequest, LoadGnnModelRequest};
    use graph_hunter_gnn::NpuScorer;

    impl GraphHunterApi {
        /// Load a GNN ONNX model. `model_path` accepts either an
        /// absolute path or one of the built-in aliases (`"gnn_v1"`,
        /// `"gnn_v2"`). Returns a human-readable confirmation string
        /// with the resolved path.
        pub fn load_gnn_model(&self, req: LoadGnnModelRequest) -> ApiResult<String> {
            let resolved = resolve_gnn_model_path(&req.model_path)?;
            let scorer = NpuScorer::load(&resolved)
                .map_err(|e| ApiError::Io(format!("failed to load GNN model: {e}")))?;
            let handle = self.npu_scorer_handle();
            let mut guard = handle
                .write()
                .map_err(|e| ApiError::Internal(format!("npu scorer poisoned: {e}")))?;
            *guard = Some(scorer);
            Ok(format!("GNN model loaded: {resolved}"))
        }

        /// Compute GNN threat scores for every entity in the session's
        /// graph. Requires the anomaly scorer to be enabled AND a GNN
        /// model to be loaded. Returns the number of entities scored.
        pub fn compute_gnn_scores(&self, req: ComputeGnnScoresRequest) -> ApiResult<usize> {
            let hops = req.k_hops.unwrap_or(2);
            let session = self.resolve_session(req.session.as_ref())?;
            let mut graph = session
                .graph
                .write()
                .map_err(|e| ApiError::Internal(format!("graph lock poisoned: {e}")))?;
            if graph.anomaly_scorer.is_none() {
                return Err(ApiError::InvalidState(
                    "anomaly scoring must be enabled first".into(),
                ));
            }
            let handle = self.npu_scorer_handle();
            let mut guard = handle
                .write()
                .map_err(|e| ApiError::Internal(format!("npu scorer poisoned: {e}")))?;
            let npu = guard.as_mut().ok_or_else(|| {
                ApiError::InvalidState("GNN model not loaded (call load_gnn_model first)".into())
            })?;
            Ok(graph_hunter_gnn::compute_gnn_scores(&mut graph, npu, hops))
        }

        /// True iff a GNN model is currently loaded.
        pub fn gnn_model_status(&self) -> ApiResult<bool> {
            let handle = self.npu_scorer_handle();
            let guard = handle
                .read()
                .map_err(|e| ApiError::Internal(format!("npu scorer poisoned: {e}")))?;
            Ok(guard.is_some())
        }
    }

    /// Resolve a model path or alias to a filesystem path. Moved from
    /// `app/src-tauri/src/commands/analytics.rs::resolve_gnn_model_path`.
    fn resolve_gnn_model_path(input: &str) -> ApiResult<String> {
        if std::path::Path::new(input).is_file() {
            return Ok(input.to_string());
        }
        let filename = match input {
            "gnn_v1" | "v1" => "gnn_v1.onnx",
            "gnn_v2" | "v2" => "gnn_v2.onnx",
            other if other.ends_with(".onnx") => other,
            _ => input,
        };
        let candidates = [
            format!("assets/{filename}"),
            format!("graph_hunter_core/assets/{filename}"),
            filename.to_string(),
        ];
        for c in &candidates {
            if std::path::Path::new(c).is_file() {
                return Ok(c.clone());
            }
        }
        Err(ApiError::InvalidInput(format!(
            "model '{input}' not found. Tried: {candidates:?}. Pass an absolute path, or place the .onnx file in the assets/ directory."
        )))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state::Session;
    use graph_hunter_core::GraphHunter;
    use std::sync::Arc;

    fn api() -> GraphHunterApi {
        let api = GraphHunterApi::new_noop();
        let s = Arc::new(Session::new("s1", "t", GraphHunter::new(), 0));
        api.sessions().insert(s);
        api.sessions().set_current(Some("s1".into()));
        api
    }

    #[test]
    fn update_weights_without_enable_is_invalid_state() {
        let api = api();
        let err = api
            .update_anomaly_weights(UpdateAnomalyWeightsRequest {
                session: None,
                weights: ScoringWeights::default(),
            })
            .unwrap_err();
        assert!(matches!(err, ApiError::InvalidState(_)));
    }

    #[test]
    fn get_config_default_is_none() {
        let api = api();
        let cfg = api
            .get_anomaly_config(GetAnomalyConfigRequest::default())
            .unwrap();
        assert!(cfg.is_none());
    }

    #[test]
    fn enable_then_get_roundtrips() {
        let api = api();
        api.enable_anomaly_scoring(EnableAnomalyScoringRequest::default())
            .unwrap();
        let cfg = api
            .get_anomaly_config(GetAnomalyConfigRequest::default())
            .unwrap();
        assert!(cfg.is_some());
    }
}
