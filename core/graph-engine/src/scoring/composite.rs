//! [`CompositeScorer`] — weighted-average orchestrator over
//! [`ScoreComponent`]s.

use super::components::{
    EdgeRarity, EntityRarity, GnnThreat, NeighborhoodConcentration, TemporalNovelty,
};
use super::{PathContext, ScoreComponent, ScoreOutcome};
use crate::anomaly::ScoringWeights;

/// Owns a set of components + their weights. The weights do not have
/// to sum to 1 — the composite is `Σ(wᵢ·cᵢ) / Σ(wᵢ)` so any positive
/// weighting works. A weight of 0 effectively disables the component
/// (it's still evaluated; the contribution gets multiplied by 0).
pub struct CompositeScorer {
    pub components: Vec<Box<dyn ScoreComponent>>,
    pub weights: Vec<f64>,
}

impl CompositeScorer {
    /// Build a new scorer from a raw component list + matching weights.
    /// Panics in debug if the two lengths disagree — that's a
    /// programmer error, not a user error, so a panic is the right
    /// failure mode.
    pub fn new(components: Vec<Box<dyn ScoreComponent>>, weights: Vec<f64>) -> Self {
        debug_assert_eq!(
            components.len(),
            weights.len(),
            "CompositeScorer: weights count must match components count"
        );
        Self {
            components,
            weights,
        }
    }

    /// Build the default 5-component composite from a [`ScoringWeights`]
    /// struct. This is the shape that matches
    /// [`crate::AnomalyScorer::score_path`] and is what
    /// `score_path_v2` uses.
    pub fn from_weights(weights: &ScoringWeights) -> Self {
        Self::new(
            vec![
                Box::new(EntityRarity),
                Box::new(EdgeRarity),
                Box::new(NeighborhoodConcentration),
                Box::new(TemporalNovelty),
                Box::new(GnnThreat),
            ],
            vec![
                weights.w1_entity_rarity,
                weights.w2_edge_rarity,
                weights.w3_neighborhood_conc,
                weights.w4_temporal_novelty,
                weights.w5_gnn_threat,
            ],
        )
    }

    /// Run every component against the path context, combine with
    /// weights, and return the [`ScoreOutcome`].
    pub fn score_path(&self, ctx: &PathContext<'_>) -> ScoreOutcome {
        let n = self.components.len();
        let mut components = Vec::with_capacity(n);
        let mut narrative_parts = Vec::new();
        let mut weighted_sum = 0.0;
        let mut w_sum = 0.0;

        for (i, component) in self.components.iter().enumerate() {
            let value = component.score_path(ctx);
            let weight = self.weights.get(i).copied().unwrap_or(0.0);
            weighted_sum += weight * value;
            w_sum += weight;
            if let Some(text) = component.explain(value, ctx) {
                narrative_parts.push(text);
            }
            components.push((component.name().to_string(), value));
        }

        let composite = if w_sum > 0.0 {
            weighted_sum / w_sum
        } else {
            0.0
        };

        ScoreOutcome {
            composite: composite.clamp(0.0, 1.0),
            components,
            narrative_parts,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ahash::{HashMap, HashMapExt};

    #[test]
    fn empty_path_yields_zero_composite() {
        let w = ScoringWeights::default();
        let scorer = CompositeScorer::from_weights(&w);
        let entity_freq = HashMap::new();
        let pair_freq = HashMap::new();
        let first_seen = HashMap::new();
        let nc_cache = HashMap::new();
        let gnn_cache = HashMap::new();
        let caches = super::super::ScoringCaches {
            entity_freq: &entity_freq,
            pair_freq: &pair_freq,
            first_seen: &first_seen,
            nc_cache: &nc_cache,
            gnn_cache: &gnn_cache,
            log_max_freq: 0.0,
            log_max_pair_freq: 0.0,
            tau_min: 0,
            tau_max: 0,
        };
        let path: Vec<String> = vec![];
        let ctx = PathContext {
            path: &path,
            caches: &caches,
        };
        // With all weights > 0 and all components returning 0 for an
        // empty path, composite is 0.
        let outcome = scorer.score_path(&ctx);
        assert_eq!(outcome.composite, 0.0);
        assert_eq!(outcome.components.len(), 5);
    }

    #[test]
    fn zero_weights_return_zero_composite() {
        let w = ScoringWeights {
            w1_entity_rarity: 0.0,
            w2_edge_rarity: 0.0,
            w3_neighborhood_conc: 0.0,
            w4_temporal_novelty: 0.0,
            w5_gnn_threat: 0.0,
        };
        let scorer = CompositeScorer::from_weights(&w);
        let entity_freq = HashMap::new();
        let pair_freq = HashMap::new();
        let first_seen = HashMap::new();
        let nc_cache: HashMap<String, f64> = HashMap::new();
        let gnn_cache = HashMap::new();
        let caches = super::super::ScoringCaches {
            entity_freq: &entity_freq,
            pair_freq: &pair_freq,
            first_seen: &first_seen,
            nc_cache: &nc_cache,
            gnn_cache: &gnn_cache,
            log_max_freq: 10.0,
            log_max_pair_freq: 10.0,
            tau_min: 0,
            tau_max: 100,
        };
        let path = vec!["alice".to_string()];
        let ctx = PathContext {
            path: &path,
            caches: &caches,
        };
        let outcome = scorer.score_path(&ctx);
        assert_eq!(outcome.composite, 0.0);
    }

    #[test]
    fn component_names_are_stable_snake_case() {
        // Contract test: `ScoreBreakdown` relies on these names to
        // populate its named fields. If anyone renames a component,
        // this test fires and forces a matching rename in `anomaly.rs`.
        let scorer = CompositeScorer::from_weights(&ScoringWeights::default());
        let names: Vec<&'static str> = scorer.components.iter().map(|c| c.name()).collect();
        assert_eq!(
            names,
            vec![
                "entity_rarity",
                "edge_rarity",
                "neighborhood_concentration",
                "temporal_novelty",
                "gnn_threat",
            ]
        );
    }
}
