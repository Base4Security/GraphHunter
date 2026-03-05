//! NPU/GPU-accelerated GNN scorer using ONNX Runtime.
//!
//! This module is only compiled when the `ml-scoring` feature is enabled.
//! It loads a pre-trained GNN model (exported from GraphOS-APT as ONNX)
//! and runs inference on subgraph features extracted by `gnn_bridge`.
//!
//! Execution provider priority:
//! 1. DirectML (Windows NPU/GPU)
//! 2. CPU fallback (always available)

#[cfg(feature = "ml-scoring")]
pub mod scorer {
    use std::path::Path;

    use ahash::HashMapExt;
    use crate::anomaly::ThreatClass;
    use crate::gnn_bridge::{SubgraphFeatures, GNN_INPUT_DIM};

    /// GNN scorer that wraps an ONNX Runtime session.
    pub struct NpuScorer {
        session: ort::session::Session,
    }

    /// Error type for NPU scorer operations.
    #[derive(Debug)]
    pub enum NpuError {
        ModelLoad(String),
        Inference(String),
        InvalidOutput(String),
    }

    impl std::fmt::Display for NpuError {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            match self {
                NpuError::ModelLoad(msg) => write!(f, "Model load error: {}", msg),
                NpuError::Inference(msg) => write!(f, "Inference error: {}", msg),
                NpuError::InvalidOutput(msg) => write!(f, "Invalid output: {}", msg),
            }
        }
    }

    impl std::error::Error for NpuError {}

    impl NpuScorer {
        /// Load a GNN ONNX model from the given file path.
        ///
        /// Attempts to use DirectML (NPU/GPU) if enabled, otherwise CPU.
        pub fn load(model_path: &str) -> Result<Self, NpuError> {
            let path = Path::new(model_path);
            if !path.exists() {
                return Err(NpuError::ModelLoad(format!(
                    "Model file not found: {}",
                    model_path
                )));
            }

            let builder = ort::session::Session::builder()
                .map_err(|e| NpuError::ModelLoad(format!("Session builder error: {}", e)))?;

            // Only register DirectML EP when the feature is enabled;
            // otherwise skip with_execution_providers entirely so ort
            // uses the default CPU backend without trying to init DirectML.
            #[cfg(feature = "directml")]
            let builder = builder
                .with_execution_providers([ort::ep::DirectML::default().build()])
                .map_err(|e| NpuError::ModelLoad(format!("Execution provider error: {}", e)))?;

            let session = builder
                .commit_from_file(model_path)
                .map_err(|e| NpuError::ModelLoad(format!("Model load error: {}", e)))?;

            Ok(Self { session })
        }

        /// Run GNN inference on a single subgraph.
        ///
        /// Returns 5 logits: [benign, exfiltration, c2_beacon, lateral_movement, privilege_escalation]
        pub fn classify_subgraph(
            &mut self,
            features: &SubgraphFeatures,
        ) -> Result<[f64; 5], NpuError> {
            let input_tensor = features.to_input_tensor();
            debug_assert_eq!(input_tensor.len(), GNN_INPUT_DIM);

            // Create input as [1, GNN_INPUT_DIM] tensor
            let input_array =
                ndarray::Array2::from_shape_vec((1, GNN_INPUT_DIM), input_tensor)
                    .map_err(|e| NpuError::Inference(format!("Input shape error: {}", e)))?;

            // Get output name before running (avoids borrow conflict with session.run)
            let output_name = self.session.outputs()
                .first()
                .map(|o| o.name().to_string())
                .ok_or_else(|| NpuError::InvalidOutput("Model has no outputs".to_string()))?;

            let input_value = ort::value::TensorRef::from_array_view(&input_array)
                .map_err(|e| NpuError::Inference(format!("Tensor create error: {}", e)))?;

            let outputs = self
                .session
                .run(ort::inputs![input_value])
                .map_err(|e| NpuError::Inference(format!("Inference error: {}", e)))?;

            // Extract output: expect shape [1, 5]
            let output = outputs
                .get(&output_name)
                .ok_or_else(|| NpuError::InvalidOutput("No output tensor".to_string()))?;

            let (_, output_slice) = output
                .try_extract_tensor::<f32>()
                .map_err(|e| NpuError::InvalidOutput(format!("Output extract error: {}", e)))?;

            if output_slice.len() < 5 {
                return Err(NpuError::InvalidOutput(format!(
                    "Expected 5 logits, got {}",
                    output_slice.len()
                )));
            }

            Ok([
                output_slice[0] as f64,
                output_slice[1] as f64,
                output_slice[2] as f64,
                output_slice[3] as f64,
                output_slice[4] as f64,
            ])
        }

        /// Convenience: classify and return a threat score in [0, 1].
        pub fn threat_score(
            &mut self,
            features: &SubgraphFeatures,
        ) -> Result<f64, NpuError> {
            let logits = self.classify_subgraph(features)?;
            Ok(ThreatClass::threat_score_from_logits(&logits))
        }

        /// Convenience: classify and return the predicted threat class.
        pub fn threat_class(
            &mut self,
            features: &SubgraphFeatures,
        ) -> Result<ThreatClass, NpuError> {
            let logits = self.classify_subgraph(features)?;
            let max_idx = logits
                .iter()
                .enumerate()
                .max_by(|(_, a), (_, b)| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal))
                .map(|(i, _)| i)
                .unwrap_or(0);
            Ok(ThreatClass::from_index(max_idx))
        }

        /// Batch-score multiple subgraphs. Returns entity_id -> threat_score mapping.
        pub fn batch_score(
            &mut self,
            features_map: &ahash::HashMap<String, SubgraphFeatures>,
        ) -> ahash::HashMap<String, f64> {
            let mut scores = ahash::HashMap::with_capacity(features_map.len());
            for (entity_id, features) in features_map {
                match self.threat_score(features) {
                    Ok(score) => {
                        scores.insert(entity_id.clone(), score);
                    }
                    Err(_) => {
                        // Silently skip failed inferences (neutral score)
                        scores.insert(entity_id.clone(), 0.0);
                    }
                }
            }
            scores
        }
    }
}

/// Stub module when ml-scoring feature is not enabled.
/// Provides a no-op NpuScorer that always returns None.
#[cfg(not(feature = "ml-scoring"))]
pub mod scorer {
    use ahash::HashMapExt;
    use crate::gnn_bridge::SubgraphFeatures;

    /// Placeholder scorer when ML feature is disabled.
    pub struct NpuScorer;

    #[derive(Debug)]
    pub enum NpuError {
        NotAvailable,
    }

    impl std::fmt::Display for NpuError {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            write!(f, "ML scoring not available (feature 'ml-scoring' not enabled)")
        }
    }

    impl std::error::Error for NpuError {}

    impl NpuScorer {
        pub fn load(_model_path: &str) -> Result<Self, NpuError> {
            Err(NpuError::NotAvailable)
        }

        pub fn threat_score(
            &mut self,
            _features: &SubgraphFeatures,
        ) -> Result<f64, NpuError> {
            Err(NpuError::NotAvailable)
        }

        pub fn batch_score(
            &mut self,
            _features_map: &ahash::HashMap<String, SubgraphFeatures>,
        ) -> ahash::HashMap<String, f64> {
            ahash::HashMap::new()
        }
    }
}
