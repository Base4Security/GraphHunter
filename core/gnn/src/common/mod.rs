//! Shared shapes between v1 and v2 GNN models.
//!
//! F4.5 introduces [`model_gate`] — the pure validator that every model
//! loader runs before opening an ONNX session. The types in this module
//! are compiled unconditionally so the v1 loader (no feature flag) and
//! the v2 loader (behind `gnn-v2-experimental`) share one contract.

pub mod model_gate;

pub use model_gate::{
    EXPERIMENTAL_V2_ENABLED, MIN_VALIDATION_ACCURACY, ModelLoadError, ModelMetadata,
    ModelVersion, TensorShape, TrainingCorpus, expected_shape_for, load_and_validate_metadata,
    validate_metadata,
};
