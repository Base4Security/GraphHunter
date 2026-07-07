//! F4.5 / ADR-003 §D2 — load-time gate for GNN models.
//!
//! Every `.onnx` file intended for production must ship with a sidecar
//! `.metadata.json` describing its provenance (corpus, validation
//! accuracy, class labels, tensor shape, content hash). The gate
//! rejects any model that hasn't cleared an accuracy bar or that was
//! trained on synthetic data alone when the experimental feature flag
//! is off.
//!
//! Shapes are shared across v1 and v2 — the `version` field on
//! `ModelMetadata` tells the caller which path to take.
//!
//! This module is compiled unconditionally (not behind a feature flag)
//! because the validator is pure and the v1 loader can consume the same
//! gate without opting into the experimental v2 surface.

use serde::{Deserialize, Serialize};
use std::path::Path;

/// Minimum validation accuracy a model must report to be loaded. Chosen
/// from ADR-003 §D2 — the floor below which the scorer's outputs add
/// more noise than signal.
pub const MIN_VALIDATION_ACCURACY: f32 = 0.80;

/// Model schema revision. Not to be confused with *training corpus*
/// freshness (see [`TrainingCorpus`]); this field pins the tensor /
/// class-label shape the runtime expects.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ModelVersion {
    V1,
    V2,
}

/// What the model was trained on. `Synthetic` is a release-blocker
/// unless the caller explicitly opted in via `gnn-v2-experimental` at
/// compile time.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum TrainingCorpus {
    Synthetic,
    Production,
    Mixed,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TensorShape {
    pub k_max: u32,
    pub d_node: u32,
}

/// Sidecar metadata describing a GNN model. Lives alongside the `.onnx`
/// file as `<same-stem>.metadata.json`. Produced by `train_gnn_v2.py`
/// at export time (F4.6).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModelMetadata {
    pub version: ModelVersion,
    pub trained_on: TrainingCorpus,
    pub validation_accuracy: f32,
    pub class_labels: Vec<String>,
    pub input_shape: TensorShape,
    /// Lowercase hex SHA-256 of the `.onnx` payload. Optional in the
    /// schema to avoid breaking early exports; the loader can still
    /// check it against the file if present.
    #[serde(default)]
    pub sha256: Option<String>,
}

/// Errors raised by the gate. Every variant is a **rejection** — the
/// loader short-circuits before any ONNX work.
#[derive(Debug)]
pub enum ModelLoadError {
    /// No `.metadata.json` next to the `.onnx` file.
    MissingMetadata(String),
    /// Could not parse the sidecar.
    MalformedMetadata(String),
    /// The `.onnx` file itself could not be read.
    MissingModel(String),
    /// Synthetic-only corpus without the experimental feature flag.
    UntrainedOnSynthetic,
    /// Validation accuracy below [`MIN_VALIDATION_ACCURACY`] — always
    /// fatal regardless of the feature flag.
    ValidationAccuracyBelowThreshold { got: f32, min: f32 },
    /// `input_shape` doesn't match the version's expected k_max/d_node.
    ShapeMismatch { got: TensorShape, expected: TensorShape },
    /// Declared sha256 didn't match the file's actual hash.
    SignatureMismatch,
}

impl std::fmt::Display for ModelLoadError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::MissingMetadata(p) => write!(f, "missing sidecar metadata: {p}"),
            Self::MalformedMetadata(p) => write!(f, "malformed metadata: {p}"),
            Self::MissingModel(p) => write!(f, "missing onnx model: {p}"),
            Self::UntrainedOnSynthetic => write!(
                f,
                "model trained on synthetic corpus; enable feature `gnn-v2-experimental` to load it"
            ),
            Self::ValidationAccuracyBelowThreshold { got, min } => write!(
                f,
                "validation accuracy {got:.3} below minimum {min:.3}"
            ),
            Self::ShapeMismatch { got, expected } => write!(
                f,
                "tensor shape mismatch: got k_max={} d_node={}, expected k_max={} d_node={}",
                got.k_max, got.d_node, expected.k_max, expected.d_node
            ),
            Self::SignatureMismatch => write!(f, "sha256 mismatch between metadata and file"),
        }
    }
}

impl std::error::Error for ModelLoadError {}

/// Runtime-observable toggle set at compile time by the
/// `gnn-v2-experimental` feature. Separated from the validator's boolean
/// argument so callers can override (e.g. for tests).
pub const EXPERIMENTAL_V2_ENABLED: bool = cfg!(feature = "gnn-v2-experimental");

/// Validates a parsed [`ModelMetadata`] against the gate rules
/// (ADR-003 §D2).
///
/// `experimental_v2_enabled` is typically [`EXPERIMENTAL_V2_ENABLED`]
/// but callers may pass a different value in tests.
pub fn validate_metadata(
    meta: &ModelMetadata,
    experimental_v2_enabled: bool,
) -> Result<(), ModelLoadError> {
    if meta.validation_accuracy < MIN_VALIDATION_ACCURACY {
        return Err(ModelLoadError::ValidationAccuracyBelowThreshold {
            got: meta.validation_accuracy,
            min: MIN_VALIDATION_ACCURACY,
        });
    }
    if matches!(meta.trained_on, TrainingCorpus::Synthetic) && !experimental_v2_enabled {
        return Err(ModelLoadError::UntrainedOnSynthetic);
    }
    let expected = expected_shape_for(meta.version);
    if meta.input_shape != expected {
        return Err(ModelLoadError::ShapeMismatch {
            got: meta.input_shape.clone(),
            expected,
        });
    }
    Ok(())
}

/// Expected tensor shape per model version.
/// - v1: `K_MAX=32`, `D_NODE=16` — matches `gnn_bridge::D_NODE`.
/// - v2: `K_MAX=32`, `D_NODE=24` — matches `gnn_bridge::D_NODE_V2`,
///   widened to carry cloud-identity attributes.
///
/// Any drift between this table and `gnn_bridge` trips a runtime
/// mismatch via `validate_metadata`.
pub fn expected_shape_for(version: ModelVersion) -> TensorShape {
    match version {
        ModelVersion::V1 => TensorShape { k_max: 32, d_node: 16 },
        ModelVersion::V2 => TensorShape { k_max: 32, d_node: 24 },
    }
}

/// Reads and validates a model's sidecar metadata, returning the parsed
/// struct on success. Does **not** open the ONNX session — the caller
/// pipes this result into whatever inference backend it uses.
///
/// `onnx_path` points at the `.onnx` file; the sidecar is discovered as
/// `<same-stem>.metadata.json` in the same directory.
pub fn load_and_validate_metadata<P: AsRef<Path>>(
    onnx_path: P,
    experimental_v2_enabled: bool,
) -> Result<ModelMetadata, ModelLoadError> {
    let onnx_path = onnx_path.as_ref();
    if !onnx_path.exists() {
        return Err(ModelLoadError::MissingModel(onnx_path.display().to_string()));
    }
    let sidecar = sidecar_path_for(onnx_path);
    let text = std::fs::read_to_string(&sidecar)
        .map_err(|_| ModelLoadError::MissingMetadata(sidecar.display().to_string()))?;
    let meta: ModelMetadata = serde_json::from_str(&text)
        .map_err(|e| ModelLoadError::MalformedMetadata(e.to_string()))?;
    validate_metadata(&meta, experimental_v2_enabled)?;
    Ok(meta)
}

fn sidecar_path_for(onnx_path: &Path) -> std::path::PathBuf {
    let mut p = onnx_path.to_path_buf();
    p.set_extension("metadata.json");
    p
}

#[cfg(test)]
mod tests {
    use super::*;

    fn base_meta() -> ModelMetadata {
        ModelMetadata {
            version: ModelVersion::V1,
            trained_on: TrainingCorpus::Production,
            validation_accuracy: 0.87,
            class_labels: vec!["benign".into(), "c2_beacon".into()],
            input_shape: TensorShape { k_max: 32, d_node: 16 },
            sha256: None,
        }
    }

    #[test]
    fn accepts_production_model_above_threshold() {
        let meta = base_meta();
        assert!(validate_metadata(&meta, false).is_ok());
    }

    #[test]
    fn rejects_synthetic_without_experimental_flag() {
        let mut meta = base_meta();
        meta.trained_on = TrainingCorpus::Synthetic;
        let err = validate_metadata(&meta, false).unwrap_err();
        assert!(matches!(err, ModelLoadError::UntrainedOnSynthetic));
    }

    #[test]
    fn accepts_synthetic_with_experimental_flag() {
        let mut meta = base_meta();
        meta.trained_on = TrainingCorpus::Synthetic;
        assert!(validate_metadata(&meta, true).is_ok());
    }

    #[test]
    fn rejects_accuracy_below_threshold_even_with_flag() {
        let mut meta = base_meta();
        meta.validation_accuracy = 0.42;
        let err = validate_metadata(&meta, true).unwrap_err();
        assert!(matches!(
            err,
            ModelLoadError::ValidationAccuracyBelowThreshold { .. }
        ));
    }

    #[test]
    fn rejects_shape_mismatch() {
        let mut meta = base_meta();
        meta.input_shape = TensorShape { k_max: 16, d_node: 8 };
        let err = validate_metadata(&meta, false).unwrap_err();
        assert!(matches!(err, ModelLoadError::ShapeMismatch { .. }));
    }

    #[test]
    fn metadata_roundtrips_json() {
        let meta = base_meta();
        let s = serde_json::to_string(&meta).unwrap();
        let back: ModelMetadata = serde_json::from_str(&s).unwrap();
        assert_eq!(back.version, meta.version);
        assert_eq!(back.validation_accuracy, meta.validation_accuracy);
        assert_eq!(back.input_shape, meta.input_shape);
    }

    #[test]
    fn missing_model_file_errors() {
        let err = load_and_validate_metadata("/nonexistent/path/model.onnx", false).unwrap_err();
        assert!(matches!(err, ModelLoadError::MissingModel(_)));
    }

    #[test]
    fn trained_on_serializes_lowercase() {
        let mut meta = base_meta();
        meta.trained_on = TrainingCorpus::Mixed;
        let s = serde_json::to_value(&meta).unwrap();
        assert_eq!(s["trained_on"], "mixed");
    }
}
