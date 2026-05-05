//! M1 — end-to-end integration test for the planner-driven dispatch.
//!
//! S3 already covers the legacy name-marker route via
//! `tests/k4_lftj_dispatch.rs`. M1 adds a *structural* route gated by
//! `GRAPHHUNTER_LFTJ_PLANNER=1`: a six-step homogeneous hypothesis
//! routes to the K4 LFTJ enumerator without needing the `k4-clique`
//! name marker. This test verifies:
//!
//! 1. With the planner env var off, a six-step Host→Connect→Host
//!    hypothesis runs through DFS-Match and returns the regular
//!    "single-edge path per match" semantics.
//! 2. With the planner env var on, the *same* hypothesis dispatches to
//!    the LFTJ enumerator and returns one K4 tuple
//!    (`["a","b","c","d"]`).
//! 3. The structural detector is conservative: a hypothesis with five
//!    steps does NOT dispatch even with the env var on — confirms we
//!    don't accidentally route arbitrary chains.

use graph_hunter_core::{
    Entity, EntityType, GraphHunter, Hypothesis, HypothesisStep, Relation, RelationType,
};

/// Process-wide mutex serializing env-var mutations within this
/// integration-test binary. The three tests below mutate
/// `GRAPHHUNTER_K4_LFTJ` and `GRAPHHUNTER_LFTJ_PLANNER`; without
/// this guard parallel runs would race. Mirrors the pattern in
/// `core/graph-engine/src/planner.rs::tests::ENV_LOCK`.
static ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

fn k4_graph() -> GraphHunter {
    let mut g = GraphHunter::new();
    for id in ["a", "b", "c", "d"] {
        g.add_entity(Entity::new(id, EntityType::Host)).unwrap();
    }
    let edges = [
        ("a", "b", 1),
        ("a", "c", 2),
        ("a", "d", 3),
        ("b", "c", 4),
        ("b", "d", 5),
        ("c", "d", 6),
    ];
    for (s, d, t) in edges {
        g.add_relation(Relation::new(s, d, RelationType::Connect, t))
            .unwrap();
    }
    g.sort_edges_by_timestamp().unwrap();
    g
}

fn six_homogeneous_steps(name: &str) -> Hypothesis {
    let mut h = Hypothesis::new(name);
    for _ in 0..6 {
        h = h.add_step(HypothesisStep::new(
            EntityType::Host,
            RelationType::Connect,
            EntityType::Host,
        ));
    }
    h
}

fn five_homogeneous_steps(name: &str) -> Hypothesis {
    let mut h = Hypothesis::new(name);
    for _ in 0..5 {
        h = h.add_step(HypothesisStep::new(
            EntityType::Host,
            RelationType::Connect,
            EntityType::Host,
        ));
    }
    h
}

#[test]
fn structural_route_off_by_default_falls_back_to_dfs() {
    let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let g = k4_graph();
    let h = six_homogeneous_steps("plain six-step probe");
    unsafe {
        std::env::remove_var("GRAPHHUNTER_K4_LFTJ");
        std::env::remove_var("GRAPHHUNTER_LFTJ_PLANNER");
    }
    let (results, _) = g.search_temporal_pattern(&h, None, None).unwrap();
    // DFS-Match over six identical steps emits zero paths on a 4-clique
    // because there's no chronological 6-edge chain through 4 vertices
    // (the graph has only 6 directed edges; any DFS path through them
    // visits the same vertex twice). The point of the test is that the
    // count is NOT 1 — i.e. we did not dispatch to LFTJ.
    assert_ne!(
        results.len(),
        1,
        "default dispatch must be DFS, not LFTJ (LFTJ would return exactly 1 K4 tuple)"
    );
}

#[test]
fn structural_route_dispatches_when_env_set() {
    let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let g = k4_graph();
    let h = six_homogeneous_steps("plain six-step probe (no marker)");
    unsafe {
        std::env::remove_var("GRAPHHUNTER_K4_LFTJ");
        std::env::set_var("GRAPHHUNTER_LFTJ_PLANNER", "1");
    }
    let (results, truncated) = g.search_temporal_pattern(&h, None, None).unwrap();
    unsafe {
        std::env::remove_var("GRAPHHUNTER_LFTJ_PLANNER");
    }
    assert!(!truncated);
    assert_eq!(
        results.len(),
        1,
        "structural route should dispatch to K4 LFTJ → exactly one K4 tuple"
    );
    let tuple: Vec<&str> = results[0].iter().map(|s| &**s).collect();
    assert_eq!(tuple, vec!["a", "b", "c", "d"]);
}

#[test]
fn structural_route_does_not_misfire_on_five_step_chain() {
    let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let g = k4_graph();
    let h = five_homogeneous_steps("five-step probe");
    unsafe {
        std::env::remove_var("GRAPHHUNTER_K4_LFTJ");
        std::env::set_var("GRAPHHUNTER_LFTJ_PLANNER", "1");
    }
    let (results, _) = g.search_temporal_pattern(&h, None, None).unwrap();
    unsafe {
        std::env::remove_var("GRAPHHUNTER_LFTJ_PLANNER");
    }
    // Five-step is NOT a K4 shape — must run through DFS-Match. We
    // assert the count is *not* 1, which is the LFTJ K4 signature on
    // this graph. (Exact DFS count depends on iteration order; we only
    // care that the route did not misfire.)
    assert_ne!(
        results.len(),
        1,
        "five-step chain must not be misclassified as K4"
    );
}
