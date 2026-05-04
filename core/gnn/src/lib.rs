//! Graph-neural-network inference + training-corpus export. Extracted
//! from `graph_hunter_core` per F2.14 so the core graph engine no longer
//! names ONNX Runtime or the feature-extraction shapes directly.
//!
//! The public surface is a thin re-export layer: downstream code keeps
//! writing `graph_hunter_core::{SubgraphFeatures, NpuScorer, ...}`
//! because `graph_hunter_core::lib.rs` forwards those names through
//! `pub use graph_hunter_gnn::...`.
//!
//! The `v1/`, `common/`, `v2/` directories are placeholders for the
//! ADR-003 split that lands in F4.5. Today the active implementation is
//! the flat `gnn_bridge` + `npu_scorer` at the crate root.

pub mod aad_training_export;
pub mod gnn_bridge;
pub mod npu_scorer;

pub mod common;
pub mod v1;
#[cfg(feature = "gnn-v2-experimental")]
pub mod v2;

// Ergonomic top-level re-exports so call sites can write
// `graph_hunter_gnn::{SubgraphFeatures, NpuScorer}` instead of
// drilling through `gnn_bridge::` / `npu_scorer::scorer::`.
pub use gnn_bridge::{
    D_NODE, D_NODE_V2, GNN_INPUT_DIM, GNN_INPUT_DIM_V2, K_MAX, SubgraphFeatures,
    SubgraphFeaturesV2, extract_batch_features, extract_subgraph_features,
    extract_subgraph_features_v2,
};
#[cfg(feature = "ml-scoring")]
pub use npu_scorer::scorer::{NpuError, NpuScorer};

#[cfg(feature = "ml-scoring")]
use graph_hunter_core::graph::GraphHunter;

/// Compute GNN threat scores for every entity in `hunter`.
///
/// Extracts k-hop subgraphs around each entity, runs GNN inference, and
/// injects the resulting threat scores into the anomaly scorer.
/// Requires anomaly scoring to be enabled first.
///
/// Returns the number of entities successfully scored. Moved from
/// `GraphHunter::compute_gnn_scores` (graph.rs) in F2.14 so the core
/// crate doesn't name `NpuScorer`; the function takes `&mut GraphHunter`
/// instead of being a method, preserving the previous call semantics at
/// the call sites that used to write `hunter.compute_gnn_scores(...)`.
#[cfg(feature = "ml-scoring")]
pub fn compute_gnn_scores(
    hunter: &mut GraphHunter,
    scorer: &mut crate::npu_scorer::scorer::NpuScorer,
    k_hops: usize,
) -> usize {
    let entity_ids: Vec<String> = hunter
        .entities
        .keys()
        .map(|&sid| hunter.interner.resolve(sid).to_string())
        .collect();

    let features = crate::gnn_bridge::extract_batch_features(hunter, &entity_ids, k_hops);
    let gnn_scores = scorer.batch_score(&features);
    let scored_count = gnn_scores.len();

    if let Some(ref mut anomaly) = hunter.anomaly_scorer {
        anomaly.set_gnn_scores(gnn_scores);
    }

    scored_count
}
