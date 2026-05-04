//! F3.6 / F5 — matcher equivalence property tests. Two variants:
//! (a) the original 2-way DFS ↔ SIMD (critical safety net for ADR-002's
//! typestate/RAII refactor) and (b) the F5 3-way iterative ↔ smart ↔
//! SIMD test, which pins that smart-DFS's A*-admissible pruning never
//! silently drops valid matches when `top_k` exceeds the graph's total
//! match count.
//!
//! For every random small graph + predicate-free hypothesis we can
//! generate, both the pure-Rust DFS matcher (`search_temporal_pattern`)
//! and the C++ SIMD matcher (`run_simd_search` via `ffi::build_gm_graph`)
//! MUST return the same SET of hunt paths. This is the property RISKS.md
//! R2 identified as the highest-impact latent bug category — a subtle
//! reordering in `add_node`/`add_edge` on the FFI side could cause silent
//! divergence that unit tests never cover.
//!
//! Scope constraints (enforced by the generator):
//! - Hypothesis carries NO predicates — SIMD falls back to DFS when any
//!   edge/dest predicate exists (see `search_temporal_pattern_simd`),
//!   which would make the comparison self-referential.
//! - Only built-in entity/relation types (no `Other(_)`) — the SIMD side
//!   uses numeric tags and `Any` wildcards are skipped to keep
//!   comparison semantically tight.
//! - Chain validation is guaranteed: each step i+1's `origin_type`
//!   equals step i's `dest_type`, so the hypothesis always passes
//!   `validate()`.
//! - Graph size capped at 10 entities × 15 relations; hypothesis length
//!   1-3 steps. Small enough to iterate hundreds of cases fast.

#![cfg(feature = "simd")]

use std::collections::HashSet;

use graph_hunter_core::{
    Entity, EntityType, GraphHunter, Hypothesis, HypothesisStep, Relation, RelationType,
    ScoringWeights,
};
use graph_hunter_matcher_ffi::ffi;
use proptest::prelude::*;

const ENTITY_TYPES: &[EntityType] = &[
    EntityType::IP,
    EntityType::Host,
    EntityType::User,
    EntityType::Process,
    EntityType::File,
];

const RELATION_TYPES: &[RelationType] = &[
    RelationType::Auth,
    RelationType::Connect,
    RelationType::Execute,
    RelationType::Read,
    RelationType::Write,
    RelationType::Spawn,
];

fn arb_entity_type() -> impl Strategy<Value = EntityType> {
    (0usize..ENTITY_TYPES.len()).prop_map(|i| ENTITY_TYPES[i].clone())
}

fn arb_relation_type() -> impl Strategy<Value = RelationType> {
    (0usize..RELATION_TYPES.len()).prop_map(|i| RELATION_TYPES[i].clone())
}

/// A 1-3 step chain where consecutive `origin_type`/`dest_type` agree,
/// so `Hypothesis::validate()` always accepts it.
fn arb_hypothesis() -> impl Strategy<Value = Hypothesis> {
    // First generate the entity-type chain (N+1 nodes for N steps), then
    // the N relation types. This guarantees chain validity without post-
    // filtering (which would bias the distribution).
    (
        prop::collection::vec(arb_entity_type(), 2..=4), // chain of types, length 2..=4 → 1..=3 steps
        prop::collection::vec(arb_relation_type(), 1..=3),
    )
        .prop_map(|(types, rels)| {
            let steps_n = (types.len() - 1).min(rels.len());
            let mut h = Hypothesis::new("prop");
            for i in 0..steps_n {
                h = h.add_step(HypothesisStep::new(
                    types[i].clone(),
                    rels[i].clone(),
                    types[i + 1].clone(),
                ));
            }
            h
        })
}

/// Generates a small graph as (entities, relations). Entity names are
/// `t{type_idx}_n{index}` to keep them unique and to encode the entity
/// type in the name — useful when shrinking traces trip an assertion.
fn arb_graph() -> impl Strategy<
    Value = (
        Vec<(String, EntityType)>,
        Vec<(String, String, RelationType, i64)>,
    ),
> {
    prop::collection::vec(arb_entity_type(), 3..=10).prop_flat_map(|types| {
        let n = types.len();
        let entities: Vec<(String, EntityType)> = types
            .iter()
            .enumerate()
            .map(|(i, t)| (format!("e{i}_{}", t.to_u8()), t.clone()))
            .collect();
        let entities_for_rels = entities.clone();
        let rels = prop::collection::vec(
            (0usize..n, 0usize..n, arb_relation_type(), 0i64..1_000i64),
            1..=15,
        )
        .prop_map(move |raw| {
            raw.into_iter()
                .filter(|(s, d, _, _)| s != d) // drop self-loops — DFS rejects them (k-simplicity=1)
                .map(|(s, d, r, ts)| {
                    (
                        entities_for_rels[s].0.clone(),
                        entities_for_rels[d].0.clone(),
                        r,
                        ts,
                    )
                })
                .collect::<Vec<_>>()
        });
        (Just(entities), rels)
    })
}

fn build_graph(
    entities: &[(String, EntityType)],
    relations: &[(String, String, RelationType, i64)],
) -> GraphHunter {
    let mut g = GraphHunter::new();
    for (name, et) in entities {
        g.add_entity(Entity::new(name.as_str(), et.clone()))
            .unwrap();
    }
    // Dedup (src,dst,rel,ts) quadruples — core rejects exact duplicates.
    let mut seen = HashSet::new();
    for (src, dst, rel, ts) in relations {
        let key = (src.clone(), dst.clone(), rel.to_u8(), *ts);
        if !seen.insert(key) {
            continue;
        }
        let _ = g.add_relation(Relation::new(src.as_str(), dst.as_str(), rel.clone(), *ts));
    }
    g.sort_edges_by_timestamp().unwrap();
    g
}

proptest! {
    // 256 cases keeps CI-wall-time sane (~100ms on a cold cache) while
    // exercising thousands of (graph × hypothesis) combinations once
    // proptest's built-in shrinking expands each failure. Bumped from
    // the original 128 in F5 to hit the plan's ≥256-cases DoD. For
    // deeper regression sweeps set PROPTEST_CASES=4096 at the shell.
    #![proptest_config(ProptestConfig {
        cases: 256,
        .. ProptestConfig::default()
    })]

    /// The property: for any predicate-free hypothesis and any small
    /// graph, DFS and SIMD must agree on the SET of matching paths.
    #[test]
    fn dfs_and_simd_return_identical_result_sets(
        (entities, relations) in arb_graph(),
        hypothesis in arb_hypothesis(),
    ) {
        // Skip ISA targets where SIMD transparently falls back — the
        // equivalence test is vacuous and would just double-run DFS.
        let isa = ffi::simd_isa_name();
        prop_assume!(!matches!(isa, "scalar" | "none" | "unknown"));

        let graph = build_graph(&entities, &relations);

        let (rust_results, _) = graph
            .search_temporal_pattern(&hypothesis, None, Some(10_000))
            .expect("DFS should not error on a validated hypothesis");

        let cached = ffi::build_gm_graph(&graph);
        let simd_results =
            ffi::run_simd_search(&cached, &graph.interner, &hypothesis, None, Some(10_000));

        let rust_set: HashSet<Vec<std::sync::Arc<str>>> = rust_results.into_iter().collect();
        let simd_set: HashSet<Vec<std::sync::Arc<str>>> = simd_results.into_iter().collect();

        prop_assert_eq!(
            &rust_set,
            &simd_set,
            "DFS/SIMD divergence\n  only_in_dfs:  {:?}\n  only_in_simd: {:?}",
            rust_set.difference(&simd_set).collect::<Vec<_>>(),
            simd_set.difference(&rust_set).collect::<Vec<_>>(),
        );
    }

    /// F5 — 3-way equivalence: iterative DFS
    /// (`search_temporal_pattern`) vs smart scored DFS
    /// (`search_temporal_pattern_smart` with a finalized scorer) vs
    /// SIMD. When `top_k` is large enough to not prune real matches,
    /// all three MUST agree as sets.
    ///
    /// Why this test is worth the extra runtime: `dfs_match_smart`'s
    /// A*-admissible pruning is the single most complex piece of
    /// matcher logic. An off-by-one in the heap threshold or a bug in
    /// the "future-step can score 1.0" heuristic would cause smart to
    /// silently drop valid matches — invisible to unit tests that only
    /// check scores.
    #[test]
    fn iterative_smart_simd_return_identical_result_sets(
        (entities, relations) in arb_graph(),
        hypothesis in arb_hypothesis(),
    ) {
        let isa = ffi::simd_isa_name();
        prop_assume!(!matches!(isa, "scalar" | "none" | "unknown"));

        let mut graph = build_graph(&entities, &relations);
        // Attach a default-weights scorer so smart mode actually runs
        // the dfs_match_smart path (it falls back to iterative when no
        // scorer is present, which would make the test vacuous).
        graph.enable_anomaly_scoring(ScoringWeights::default());

        let (iter_results, _) = graph
            .search_temporal_pattern(&hypothesis, None, Some(10_000))
            .expect("iterative DFS should succeed");

        // top_k must dominate the graph's total match count so the
        // smart heap does no real pruning — otherwise the set diff is
        // a property of pruning aggressiveness, not correctness.
        let (smart_results, _) = graph
            .search_temporal_pattern_smart(&hypothesis, None, 10_000)
            .expect("smart DFS should succeed");

        let cached = ffi::build_gm_graph(&graph);
        let simd_results =
            ffi::run_simd_search(&cached, &graph.interner, &hypothesis, None, Some(10_000));

        let iter_set: HashSet<Vec<std::sync::Arc<str>>> = iter_results.into_iter().collect();
        let smart_set: HashSet<Vec<std::sync::Arc<str>>> = smart_results.into_iter().collect();
        let simd_set: HashSet<Vec<std::sync::Arc<str>>> = simd_results.into_iter().collect();

        prop_assert_eq!(
            &iter_set,
            &smart_set,
            "iterative/smart divergence\n  only_iter:  {:?}\n  only_smart: {:?}",
            iter_set.difference(&smart_set).collect::<Vec<_>>(),
            smart_set.difference(&iter_set).collect::<Vec<_>>(),
        );
        prop_assert_eq!(
            &iter_set,
            &simd_set,
            "iterative/SIMD divergence\n  only_iter: {:?}\n  only_simd: {:?}",
            iter_set.difference(&simd_set).collect::<Vec<_>>(),
            simd_set.difference(&iter_set).collect::<Vec<_>>(),
        );
    }
}
