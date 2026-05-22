//! Integration test for Cap 20 — Yannakakis on acyclic queries (M3 Phase F).
//!
//! Goals:
//!   1. Verify that `search_temporal_pattern_yannakakis` gives the same
//!      results as the default DFS matcher on an acyclic (chain) query.
//!   2. Verify that `Hypergraph::of` + `gyo_reduce` produce the expected
//!      structural output on known query shapes.
//!   3. Verify that a cyclic query (triangle via explicit bindings) is
//!      correctly classified as non-α-acyclic and returns empty from the
//!      Yannakakis entry point.
//!
//! The synthetic graph used here mirrors the fixture in
//! `core/graph-engine/src/yannakakis.rs` unit tests (small chain with
//! a decoy). A larger 3-hop chain on 5 vertices gives a clean parity
//! surface without depending on the full Cap 0 dataset.
//!
//! This test is the regression guard for Cap 20 (Yannakakis):
//! if the semi-join reducer or the enumerator changes semantics, the
//! parity assertion will catch it.

use graph_hunter_core::yannakakis::{
    Hypergraph, gyo_reduce, is_alpha_acyclic, search_temporal_pattern_yannakakis,
};
use graph_hunter_core::{
    Entity, EntityType, GraphHunter, Hypothesis, HypothesisStep, Relation, RelationType,
};
use std::collections::HashSet;

// ── Small synthetic graph ──────────────────────────────────────────────────

/// 5-vertex linear chain with one dead-end decoy.
///
/// Edges (strictly increasing timestamps):
///   u1 --Auth(100)--> u2
///   u2 --Auth(110)--> u3
///   u3 --Auth(120)--> u4
///   u1 --Auth(100)--> u5  ← decoy: no continuation
///
/// The only 3-hop path is u1→u2→u3→u4. The Yannakakis semi-join
/// reducer should drop the u1→u5 decoy before enumeration.
fn small_chain_graph() -> GraphHunter {
    let mut g = GraphHunter::new();
    for n in ["u1", "u2", "u3", "u4", "u5"] {
        g.add_entity(Entity::new(n, EntityType::User)).unwrap();
    }
    for (s, d, t) in [
        ("u1", "u2", 100i64),
        ("u2", "u3", 110),
        ("u3", "u4", 120),
        ("u1", "u5", 100), // decoy
    ] {
        g.add_relation(Relation::new(s, d, RelationType::Auth, t))
            .unwrap();
    }
    g.sort_edges_by_timestamp().unwrap();
    g
}

fn user_auth_chain(n_steps: usize) -> Hypothesis {
    Hypothesis {
        steps: (0..n_steps)
            .map(|_| HypothesisStep::new(EntityType::User, RelationType::Auth, EntityType::User))
            .collect(),
        ..Hypothesis::new("cap20-yannakakis-test")
    }
}

// ── Test 1: parity with DFS on a 3-hop chain ──────────────────────────────

static ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

#[test]
fn cap20_yannakakis_parity_with_dfs_3hop() {
    let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    // Disable Yannakakis auto-dispatch so search_temporal_pattern runs DFS.
    unsafe {
        std::env::remove_var("GRAPHHUNTER_YANNAKAKIS");
        std::env::remove_var("GRAPHHUNTER_K4_LFTJ");
        std::env::remove_var("GRAPHHUNTER_LFTJ_PLANNER");
        std::env::remove_var("GRAPHHUNTER_LFTJ_AUTO");
    }

    let g = small_chain_graph();
    let h = user_auth_chain(3);

    // Yannakakis runner (direct call, bypasses planner flags).
    let (yanni_paths, yanni_truncated) =
        search_temporal_pattern_yannakakis(&g, &h, None, Some(1_000));
    assert!(!yanni_truncated, "result must not be truncated on tiny graph");

    // DFS runner (via search_temporal_pattern with no dispatch env flags).
    let (dfs_paths, dfs_truncated) = g
        .search_temporal_pattern(&h, None, Some(1_000))
        .expect("DFS must succeed");
    assert!(!dfs_truncated);

    // Convert both result sets to comparable string sets.
    let yanni_set: HashSet<Vec<String>> = yanni_paths
        .iter()
        .map(|p| p.iter().map(|s| s.to_string()).collect())
        .collect();
    let dfs_set: HashSet<Vec<String>> = dfs_paths
        .iter()
        .map(|p| p.iter().map(|s| s.to_string()).collect())
        .collect();

    assert_eq!(
        yanni_set, dfs_set,
        "Yannakakis and DFS must return the same path set on an acyclic query"
    );

    // Sanity: exactly one 3-hop path exists in this fixture.
    assert_eq!(
        yanni_set.len(),
        1,
        "exactly one 3-hop path must exist in the fixture"
    );
    let path: Vec<String> = yanni_paths[0].iter().map(|s| s.to_string()).collect();
    assert_eq!(
        path,
        vec!["u1", "u2", "u3", "u4"],
        "the single 3-hop path must be u1→u2→u3→u4"
    );

    println!(
        "\n[cap20_yannakakis_parity] PASS: {} Yannakakis paths == {} DFS paths",
        yanni_paths.len(),
        dfs_paths.len()
    );
}

// ── Test 2: Yannakakis drops the decoy via semi-join ───────────────────────

#[test]
fn cap20_yannakakis_semijoin_drops_decoy() {
    let g = small_chain_graph();
    let h = user_auth_chain(2);

    let (paths, _) = search_temporal_pattern_yannakakis(&g, &h, None, Some(100));

    // Two valid 2-hop paths: u1→u2→u3 and u2→u3→u4.
    assert_eq!(
        paths.len(),
        2,
        "semi-join reducer must produce exactly 2 paths; got {}",
        paths.len()
    );

    // The u1→u5 decoy must not appear in any emitted path.
    for p in &paths {
        for s in p.iter() {
            assert_ne!(&**s, "u5", "decoy vertex u5 must not appear in results");
        }
    }

    println!("\n[cap20_semijoin_decoy] PASS: decoy dropped, 2 paths found");
}

// ── Test 3: GYO + α-acyclicity on known shapes ─────────────────────────────

#[test]
fn cap20_gyo_chain_is_acyclic() {
    // A 3-step chain is always α-acyclic; GYO must succeed.
    let h = user_auth_chain(3);
    let g = Hypergraph::of(&h);

    assert_eq!(g.n_vars, 4, "3-step chain must have 4 distinct variables");
    assert_eq!(g.edges.len(), 3);

    let order = gyo_reduce(&g);
    assert!(
        order.is_some(),
        "GYO must succeed on a linear chain (α-acyclic)"
    );
    let order = order.unwrap();
    assert_eq!(
        order.len(),
        3,
        "GYO elimination order must cover all 3 edges"
    );
    assert!(is_alpha_acyclic(&g));
}

#[test]
fn cap20_gyo_triangle_is_cyclic() {
    // A triangle formed via explicit bindings: (a→b), (b→c), (c→a).
    // This is the canonical cyclic example — GYO must fail.
    let mut step0 = HypothesisStep::new(EntityType::User, RelationType::Auth, EntityType::User);
    step0.origin_binding = Some("a".into());
    step0.dest_binding = Some("b".into());

    let mut step1 = HypothesisStep::new(EntityType::User, RelationType::Auth, EntityType::User);
    step1.origin_binding = Some("b".into());
    step1.dest_binding = Some("c".into());

    let mut step2 = HypothesisStep::new(EntityType::User, RelationType::Auth, EntityType::User);
    step2.origin_binding = Some("c".into());
    step2.dest_binding = Some("a".into());

    let h = Hypothesis {
        steps: vec![step0, step1, step2],
        ..Hypothesis::new("triangle")
    };

    let g = Hypergraph::of(&h);
    assert_eq!(g.n_vars, 3, "triangle must collapse to 3 distinct variables");
    assert!(!is_alpha_acyclic(&g), "K_3 must NOT be α-acyclic");
    assert!(
        gyo_reduce(&g).is_none(),
        "GYO must return None on a cyclic hypergraph"
    );

    // Yannakakis on a cyclic query must return empty (safe fallback).
    let mut gh = GraphHunter::new();
    for n in ["a", "b", "c"] {
        gh.add_entity(Entity::new(n, EntityType::User)).unwrap();
    }
    for (s, d, t) in [("a", "b", 1i64), ("b", "c", 2), ("c", "a", 3)] {
        gh.add_relation(Relation::new(s, d, RelationType::Auth, t))
            .unwrap();
    }
    gh.sort_edges_by_timestamp().unwrap();

    let (paths, _) = search_temporal_pattern_yannakakis(&gh, &h, None, Some(100));
    assert!(
        paths.is_empty(),
        "Yannakakis must return no results for a cyclic query"
    );

    println!("\n[cap20_gyo_triangle] PASS: triangle correctly identified as cyclic");
}

// ── Test 4: Yannakakis parity on the Cap 0 dataset ────────────────────────

use graph_hunter_core::GenericParser;

const AUTH_EVENTS: &str =
    include_str!("../../../docs/libro/examples/parte0/auth-events.jsonl");

#[test]
fn cap20_yannakakis_parity_on_cap0_dataset() {
    let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    unsafe {
        std::env::remove_var("GRAPHHUNTER_YANNAKAKIS");
        std::env::remove_var("GRAPHHUNTER_K4_LFTJ");
        std::env::remove_var("GRAPHHUNTER_LFTJ_PLANNER");
        std::env::remove_var("GRAPHHUNTER_LFTJ_AUTO");
    }

    let mut g = GraphHunter::new();
    g.ingest_logs(AUTH_EVENTS, &GenericParser, None)
        .expect("ingest must succeed");

    // 1-step User-[Auth]->IP: an acyclic chain, Yannakakis applies.
    let h = Hypothesis::new("cap20-cap0-parity").add_step(HypothesisStep::new(
        EntityType::User,
        RelationType::Auth,
        EntityType::IP,
    ));

    let (yanni_paths, _) = search_temporal_pattern_yannakakis(&g, &h, None, Some(10_000));
    let (dfs_paths, _) = g
        .search_temporal_pattern(&h, None, Some(10_000))
        .expect("DFS must succeed");

    let yanni_set: HashSet<Vec<String>> = yanni_paths
        .iter()
        .map(|p| p.iter().map(|s| s.to_string()).collect())
        .collect();
    let dfs_set: HashSet<Vec<String>> = dfs_paths
        .iter()
        .map(|p| p.iter().map(|s| s.to_string()).collect())
        .collect();

    assert_eq!(
        yanni_set, dfs_set,
        "Yannakakis and DFS must agree on the Cap 0 dataset"
    );

    assert!(
        !yanni_set.is_empty(),
        "parity result must not be empty on a dataset with auth edges"
    );

    println!(
        "\n[cap20_cap0_parity] PASS: Yannakakis={} paths == DFS={} paths",
        yanni_paths.len(),
        dfs_paths.len()
    );
}
