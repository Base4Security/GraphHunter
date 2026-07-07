//! F3.8 — property tests for anomaly scoring invariants.
//!
//! The score_path() math is straightforward to read but has five
//! components, each with its own bounds/normalization logic, then a
//! weighted composite. This file pins down the invariants the
//! implementation must satisfy across ALL valid inputs, not just the
//! hand-picked cases unit tests exercise today.
//!
//! Properties covered:
//! - Every component of `ScoreBreakdown` ∈ [0, 1].
//! - Composite score ∈ [0, 1].
//! - All-zero weights ⇒ composite == 0 (no divide-by-zero NaN leakage).
//! - Entity-rarity monotonicity: if entity A is observed strictly more
//!   than entity B (with equal first-seen timestamps), then
//!   ER(A) ≤ ER(B). More observations ⇒ less rare ⇒ lower score.
//! - Un-finalized scorer returns zeros (contract with callers that check
//!   `is_finalized()` before trusting output).

use graph_hunter_core::anomaly::{AnomalyScorer, ScoringWeights};
use graph_hunter_core::{Entity, EntityType, GraphHunter, Relation, RelationType};
use proptest::prelude::*;

/// Builds a graph with `n` entities named `e0..e{n-1}`, all typed `Host`,
/// linked in a simple chain `e0 -> e1 -> e2 -> ...`. Enough structure for
/// `finalize()` to compute neighborhood concentration without being
/// degenerate.
fn build_graph(n: usize) -> GraphHunter {
    let mut g = GraphHunter::new();
    for i in 0..n {
        g.add_entity(Entity::new(format!("e{i}"), EntityType::Host))
            .unwrap();
    }
    for i in 0..n.saturating_sub(1) {
        g.add_relation(Relation::new(
            format!("e{i}"),
            format!("e{}", i + 1),
            RelationType::Connect,
            (i as i64) * 10,
        ))
        .unwrap();
    }
    g.sort_edges_by_timestamp().unwrap();
    g
}

fn arb_weights() -> impl Strategy<Value = ScoringWeights> {
    (
        0.0f64..=1.0,
        0.0f64..=1.0,
        0.0f64..=1.0,
        0.0f64..=1.0,
        0.0f64..=1.0,
    )
        .prop_map(|(w1, w2, w3, w4, w5)| ScoringWeights {
            w1_entity_rarity: w1,
            w2_edge_rarity: w2,
            w3_neighborhood_conc: w3,
            w4_temporal_novelty: w4,
            w5_gnn_threat: w5,
        })
}

proptest! {
    #![proptest_config(ProptestConfig {
        cases: 256,
        .. ProptestConfig::default()
    })]

    /// For any valid observation distribution and weight config, the
    /// composite score and every component stay inside [0, 1]. No NaN,
    /// no overflow, no sneaky log(0) leaks.
    #[test]
    fn scores_are_bounded_in_unit_interval(
        weights in arb_weights(),
        observations in prop::collection::vec(1u64..=1_000, 3..=8),
        timestamps in prop::collection::vec(1i64..=100_000, 3..=8),
    ) {
        let n = observations.len().min(timestamps.len());
        let graph = build_graph(n);
        let mut scorer = AnomalyScorer::new(weights);
        for i in 0..n {
            for _ in 0..observations[i] {
                scorer.observe_entity(&format!("e{i}"), timestamps[i]);
            }
        }
        for i in 0..n.saturating_sub(1) {
            scorer.observe_edge(&format!("e{i}"), &format!("e{}", i + 1));
        }
        scorer.finalize(&graph);

        // Score the full chain and each single-node path.
        let full: Vec<String> = (0..n).map(|i| format!("e{i}")).collect();
        let (composite, bd) = scorer.score_path(&full, &graph);
        prop_assert!((0.0..=1.0).contains(&composite), "composite OOB: {composite}");
        prop_assert!((0.0..=1.0).contains(&bd.entity_rarity), "ER OOB: {}", bd.entity_rarity);
        prop_assert!((0.0..=1.0).contains(&bd.edge_rarity), "EdgeR OOB: {}", bd.edge_rarity);
        prop_assert!((0.0..=1.0).contains(&bd.neighborhood_concentration), "NC OOB: {}", bd.neighborhood_concentration);
        prop_assert!((0.0..=1.0).contains(&bd.temporal_novelty), "TN OOB: {}", bd.temporal_novelty);
        prop_assert!((0.0..=1.0).contains(&bd.gnn_threat), "GNN OOB: {}", bd.gnn_threat);

        for i in 0..n {
            let (c, _) = scorer.score_path(&[format!("e{i}")], &graph);
            prop_assert!((0.0..=1.0).contains(&c), "single-node composite OOB: {c}");
        }
    }

    /// When every weight is zero, the scorer must return composite == 0
    /// rather than NaN from the final divide. This is the invariant that
    /// protects callers from propagating NaN through downstream sorts /
    /// heap comparisons where NaN breaks strict-weak-ordering.
    #[test]
    fn zero_weights_yield_zero_composite(
        observations in prop::collection::vec(1u64..=50, 3..=6),
    ) {
        let n = observations.len();
        let graph = build_graph(n);
        let mut scorer = AnomalyScorer::new(ScoringWeights {
            w1_entity_rarity: 0.0,
            w2_edge_rarity: 0.0,
            w3_neighborhood_conc: 0.0,
            w4_temporal_novelty: 0.0,
            w5_gnn_threat: 0.0,
        });
        for i in 0..n {
            for _ in 0..observations[i] {
                scorer.observe_entity(&format!("e{i}"), 100);
            }
        }
        scorer.finalize(&graph);
        let path: Vec<String> = (0..n).map(|i| format!("e{i}")).collect();
        let (composite, _) = scorer.score_path(&path, &graph);
        prop_assert_eq!(composite, 0.0);
        prop_assert!(composite.is_finite(), "composite must not be NaN/Inf");
    }

    /// Entity-rarity monotonicity: fix a 2-entity scorer where A is
    /// observed `a` times and B is observed `b` times with a < b. Then
    /// ER(A) ≥ ER(B) because A is rarer. Using weights that isolate
    /// entity_rarity (w1 = 1, others 0) makes the composite equal the
    /// ER component directly, turning the math into a clean inequality
    /// test.
    #[test]
    fn entity_rarity_monotone_in_observation_count(
        (a, b) in (1u64..=50).prop_flat_map(|a| (Just(a), (a + 1)..=100)),
    ) {
        let graph = build_graph(2);
        let mut scorer = AnomalyScorer::new(ScoringWeights {
            w1_entity_rarity: 1.0,
            w2_edge_rarity: 0.0,
            w3_neighborhood_conc: 0.0,
            w4_temporal_novelty: 0.0,
            w5_gnn_threat: 0.0,
        });
        // Equal timestamps to neutralize temporal_novelty bleed.
        for _ in 0..a { scorer.observe_entity("e0", 100); }
        for _ in 0..b { scorer.observe_entity("e1", 100); }
        scorer.finalize(&graph);

        let (score_a, _) = scorer.score_path(&["e0".to_string()], &graph);
        let (score_b, _) = scorer.score_path(&["e1".to_string()], &graph);
        // A observed less → A is rarer → higher rarity score.
        prop_assert!(
            score_a >= score_b - 1e-9,
            "ER not monotone: obs(A)={a} → {score_a}, obs(B)={b} → {score_b}"
        );
    }

    /// A scorer that hasn't been finalized must return all-zero scores.
    /// This is the explicit contract in `score_path`'s guard clause —
    /// callers rely on it to avoid acting on half-built caches.
    #[test]
    fn un_finalized_scorer_returns_zeros(
        weights in arb_weights(),
        n_obs in 1u64..=100,
    ) {
        let graph = build_graph(3);
        let mut scorer = AnomalyScorer::new(weights);
        for _ in 0..n_obs {
            scorer.observe_entity("e0", 100);
        }
        // Deliberately skip finalize().
        let (composite, bd) = scorer.score_path(&["e0".to_string()], &graph);
        prop_assert_eq!(composite, 0.0);
        prop_assert_eq!(bd.entity_rarity, 0.0);
        prop_assert_eq!(bd.edge_rarity, 0.0);
        prop_assert_eq!(bd.neighborhood_concentration, 0.0);
        prop_assert_eq!(bd.temporal_novelty, 0.0);
        prop_assert_eq!(bd.gnn_threat, 0.0);
    }
}
