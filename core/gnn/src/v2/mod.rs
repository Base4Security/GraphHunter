//! **EXPERIMENTAL** GNN v2 surface — compiled only under
//! `--features gnn-v2-experimental` per ADR-003.
//!
//! Trained on synthetic corpus; not production-validated. Do not rely
//! on scores from this path for detection decisions until a corpus
//! refresh reaches `validation_accuracy >= 0.80` and the model is
//! re-emitted with `trained_on = "production"` or `"mixed"` in its
//! sidecar metadata.
//!
//! Structure mirrors v1 once it fills in:
//! - `bridge.rs` — feature extraction into the v2 tensor shape
//!   (k_max=32, d_node widened for cloud-identity context).
//! - `scorer.rs` — ONNX session wrapper.
//!
//! The v2 loader is the only entry point that may accept a `.onnx`
//! file whose sidecar says `trained_on = "synthetic"`, and only when
//! this feature is enabled. The gate in [`crate::common::model_gate`]
//! enforces that invariant regardless of the entry point used.

use crate::common::model_gate::{
    ModelLoadError, ModelMetadata, ModelVersion, load_and_validate_metadata,
};
use std::path::Path;

/// Load a v2 model's sidecar metadata after the ADR-003 gate runs.
/// Returns the parsed metadata on success or a [`ModelLoadError`]
/// describing exactly which rule tripped.
///
/// Because this function is only reachable when the crate is built with
/// `--features gnn-v2-experimental`, `experimental_v2_enabled` is
/// hard-wired to `true` here — the compile-time gate is the primary
/// defence; the runtime accuracy check is the secondary.
pub fn load_v2_metadata<P: AsRef<Path>>(onnx_path: P) -> Result<ModelMetadata, ModelLoadError> {
    let meta = load_and_validate_metadata(onnx_path, true)?;
    if meta.version != ModelVersion::V2 {
        // A v1 file accidentally handed to the v2 loader. Treat as a
        // shape-mismatch-like error — the metadata format is valid but
        // the version field disagrees with this entry point.
        return Err(ModelLoadError::ShapeMismatch {
            got: meta.input_shape.clone(),
            expected: crate::common::model_gate::expected_shape_for(ModelVersion::V2),
        });
    }
    Ok(meta)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::common::model_gate::{TensorShape, TrainingCorpus};
    use std::io::Write;

    fn write_pair(dir: &Path, stem: &str, json: &str) -> std::path::PathBuf {
        let onnx = dir.join(format!("{stem}.onnx"));
        std::fs::File::create(&onnx).unwrap().write_all(b"\x00").unwrap();
        let meta = dir.join(format!("{stem}.metadata.json"));
        std::fs::File::create(&meta).unwrap().write_all(json.as_bytes()).unwrap();
        onnx
    }

    #[test]
    fn loads_v2_synthetic_model() {
        let tmp = tempdir();
        let onnx = write_pair(
            &tmp,
            "m",
            r#"{
                "version": "v2",
                "trained_on": "synthetic",
                "validation_accuracy": 0.85,
                "class_labels": ["benign","c2"],
                "input_shape": { "k_max": 32, "d_node": 24 }
            }"#,
        );
        let meta = load_v2_metadata(&onnx).unwrap();
        assert_eq!(meta.version, ModelVersion::V2);
        assert_eq!(meta.trained_on, TrainingCorpus::Synthetic);
    }

    #[test]
    fn rejects_v1_file_on_v2_loader() {
        let tmp = tempdir();
        let onnx = write_pair(
            &tmp,
            "m",
            r#"{
                "version": "v1",
                "trained_on": "production",
                "validation_accuracy": 0.9,
                "class_labels": [],
                "input_shape": { "k_max": 32, "d_node": 16 }
            }"#,
        );
        assert!(matches!(
            load_v2_metadata(&onnx),
            Err(ModelLoadError::ShapeMismatch { .. })
        ));
    }

    fn tempdir() -> std::path::PathBuf {
        let base = std::env::temp_dir().join(format!(
            "gnn_v2_test_{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&base).unwrap();
        base
    }

    #[test]
    fn shape_sanity() {
        let _ = TensorShape { k_max: 32, d_node: 16 };
    }
}
