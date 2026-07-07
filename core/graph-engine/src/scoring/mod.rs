//! Scorer + ScoreComponent traits (P2-A).
//!
//! The legacy [`crate::AnomalyScorer::score_path`] hardcodes five
//! anomaly dimensions (entity rarity, edge rarity, neighborhood
//! concentration, temporal novelty, GNN threat). Adding a sixth — a
//! Bayesian scorer, a learned model, a domain-specific component —
//! today requires editing [`ScoreBreakdown`], [`ScoringWeights`], the
//! composite formula, the narrative builder, and every test that
//! snapshots the breakdown shape.
//!
//! This module introduces a trait-based orchestration so each scoring
//! dimension is a self-contained [`ScoreComponent`]: it owns its
//! [`ScoreComponent::score_path`] math and its
//! [`ScoreComponent::explain`] narrative. The orchestrator
//! ([`composite::CompositeScorer`]) owns the weights and does the
//! weighted average.
//!
//! # Hot-path caveat
//!
//! [`crate::AnomalyScorer::node_anomaly_estimate`] /
//! [`crate::AnomalyScorer::edge_anomaly_estimate`] are called millions
//! of times inside DFS pruning — dynamic dispatch there is noise we
//! can't afford. Those two stay inline on `AnomalyScorer`; only the
//! path-level score (≤10K calls per hunt) flows through the trait.
//!
//! # Migration story
//!
//! `AnomalyScorer::score_path_v2` is a drop-in alternative to
//! `score_path` that routes through this module. A snapshot test
//! (`tests/scoring_snapshot.rs`) asserts the two produce
//! bit-equivalent results. Once the test rides a release, the legacy
//! body gets deleted and `score_path` delegates to v2.

use ahash::HashMap;

pub mod components;
pub mod composite;

pub use components::{
    EdgeRarity, EntityRarity, GnnThreat, NeighborhoodConcentration, TemporalNovelty,
};
pub use composite::CompositeScorer;

/// Borrowed view over the caches an [`crate::AnomalyScorer`] builds at
/// finalize time.
///
/// Components don't own this data — they read from the live scorer via
/// a shared reference. Keeps memory flat and lets a second scorer
/// impl (e.g. Bayesian) share the same cache layout if it wants.
pub struct ScoringCaches<'a> {
    pub entity_freq: &'a HashMap<String, u64>,
    pub pair_freq: &'a HashMap<(String, String), u64>,
    pub first_seen: &'a HashMap<String, i64>,
    pub nc_cache: &'a HashMap<String, f64>,
    pub gnn_cache: &'a HashMap<String, f64>,
    pub log_max_freq: f64,
    pub log_max_pair_freq: f64,
    pub tau_min: i64,
    pub tau_max: i64,
}

/// Everything a component needs to score a single path.
pub struct PathContext<'a> {
    pub path: &'a [String],
    pub caches: &'a ScoringCaches<'a>,
}

/// One scoring dimension. Self-contained: owns its score math and its
/// narrative contribution.
///
/// The default `explain` returns `None` so components that don't have a
/// useful narrative (or whose contribution is only meaningful in
/// aggregate) don't have to opt out explicitly.
pub trait ScoreComponent: Send + Sync {
    /// Stable name. Snake_case. Must not collide across components in
    /// the same [`CompositeScorer`] — [`ScoreOutcome`] uses this as the
    /// lookup key and downstream DTOs (`ScoreBreakdown`) rely on it to
    /// populate their named fields.
    fn name(&self) -> &'static str;

    /// Compute this component's contribution for a path. Must return a
    /// value clamped to `[0, 1]`.
    fn score_path(&self, ctx: &PathContext<'_>) -> f64;

    /// Optional narrative snippet. Returned text is concatenated by the
    /// orchestrator in component order. `None` means "no narrative".
    fn explain(&self, _value: f64, _ctx: &PathContext<'_>) -> Option<String> {
        None
    }
}

/// Result of [`CompositeScorer::score_path`].
///
/// `components` is ordered to match the `CompositeScorer`'s component
/// list so callers can zip them with weights if they need to. Callers
/// that just want named lookup use [`Self::get`].
#[derive(Clone, Debug)]
pub struct ScoreOutcome {
    pub composite: f64,
    pub components: Vec<(String, f64)>,
    pub narrative_parts: Vec<String>,
}

impl ScoreOutcome {
    /// Look up a component's score by name. `O(n)` over the component
    /// list — fine for n≤~10.
    pub fn get(&self, name: &str) -> Option<f64> {
        self.components
            .iter()
            .find(|(n, _)| n == name)
            .map(|(_, v)| *v)
    }
}
