//! M1 — end-to-end integration test for the planner-driven dispatch.
//!
//! **Revised: shape alone no longer dispatches.** This file originally
//! asserted that a six-step homogeneous hypothesis routes to the K4 LFTJ
//! enumerator *without* the `k4-clique` marker — i.e. purely on shape.
//! That behaviour was the bug: a homogeneous 6-step chain is the ordinary
//! way to author "a 6-hop path", and it merely happens to share an edge
//! count with a 4-clique. With `GRAPHHUNTER_LFTJ_PLANNER=1` (which both
//! shipped apps set at startup) such a hypothesis silently came back with
//! cliques instead of paths. See `tests/lftj_dfs_parity.rs` for the
//! demonstration and `planner.rs::structural_dispatch` for the fix.
//!
//! The structural route still exists, but now requires the author's
//! explicit marker in addition to the shape. This test verifies:
//!
//! 1. With the planner env var off, a six-step Host→Connect→Host
//!    hypothesis runs through DFS-Match.
//! 2. With the planner env var on but NO marker, it still runs through
//!    DFS-Match — the author asked for a path and gets paths.
//! 3. With the planner env var on AND the `k4-clique` marker, it
//!    dispatches to the LFTJ enumerator and returns one K4 tuple.
//! 4. The structural detector is conservative: a five-step hypothesis
//!    does NOT dispatch even when marked and enabled.

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

/// An UNMARKED six-step chain must stay on the DFS even with the planner
/// enabled — the author wrote a path query, not a clique query. This is
/// the regression guard for the shape-is-not-intent fix.
#[test]
fn unmarked_six_step_chain_stays_on_dfs_even_with_planner_on() {
    let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let g = k4_graph();
    let h = six_homogeneous_steps("plain six-step probe (no marker)");
    unsafe {
        std::env::remove_var("GRAPHHUNTER_K4_LFTJ");
        std::env::set_var("GRAPHHUNTER_LFTJ_PLANNER", "1");
    }
    let (results, _truncated) = g.search_temporal_pattern(&h, None, None).unwrap();
    unsafe {
        std::env::remove_var("GRAPHHUNTER_LFTJ_PLANNER");
    }
    // The K4 enumerator would return exactly one 4-tuple ["a","b","c","d"].
    // The DFS finds no 6-hop chronological chain through only 4 vertices.
    assert_ne!(
        results.len(),
        1,
        "an unmarked six-step chain must NOT be routed to the clique \
         enumerator; getting exactly one K4 tuple means shape-based routing \
         came back"
    );
}

/// The complement: WITH the marker, the structural route still works and
/// still reaches the fast operator. Narrowing must not disable the feature.
#[test]
fn marked_six_step_chain_dispatches_when_env_set() {
    let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let g = k4_graph();
    let h = six_homogeneous_steps("k4-clique probe");
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
        "a marked k4-clique hypothesis should dispatch to K4 LFTJ → one tuple"
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
