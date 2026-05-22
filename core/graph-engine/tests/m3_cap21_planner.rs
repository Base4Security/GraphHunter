//! Integration test for Cap 21 — the query planner (M3 Phase F).
//!
//! Goal: verify that `planner::plan` dispatches each query shape to the
//! correct physical operator. The planner is a pure function of the
//! `Hypothesis` and the process environment, so no graph is needed —
//! these are cheap shape-detection tests.
//!
//! Shape → expected `DispatchPlan` under the relevant env flag:
//!
//!   | Shape           | Steps | Env flag                   | Expected          |
//!   |-----------------|-------|----------------------------|--------------------|
//!   | Chain (no flag) |  2    | (none)                     | DfsMatch           |
//!   | Chain+Yannakakis|  2    | GRAPHHUNTER_YANNAKAKIS=1   | Yannakakis         |
//!   | Triangle        |  3    | GRAPHHUNTER_LFTJ_PLANNER=1 | TriangleLftj       |
//!   | K4-clique       |  6    | GRAPHHUNTER_LFTJ_PLANNER=1 | K4Lftj             |
//!   | K5-clique       | 10    | GRAPHHUNTER_LFTJ_PLANNER=1 | K5Lftj             |
//!   | 6-cycle name    |  6    | GRAPHHUNTER_C6_LFTJ=1      | C6Lftj             |
//!   | Star (Graph)    |  3    | GRAPHHUNTER_YANNAKAKIS=1   | Yannakakis         |
//!
//! The test also verifies the cost-aware planner (`plan_with_hints`)
//! under `GRAPHHUNTER_LFTJ_AUTO=1`, confirming the model selects
//! TriangleLftj for a dense hub graph (the regime where AGM wins).
//!
//! This test is the regression guard for Cap 21 (the planner):
//! if the dispatch logic is refactored incorrectly, these assertions
//! catch the breakage before it reaches production.

use graph_hunter_core::planner::{CostHints, DispatchPlan, plan, plan_with_hints};
use graph_hunter_core::{EntityType, Hypothesis, HypothesisStep, RelationType};

/// Process-wide mutex serializing env-var mutations. Mirrors the
/// pattern in `src/planner.rs::tests::ENV_LOCK`.
static ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

/// Set one env var for the duration of the closure, then restore.
fn with_var<F: FnOnce()>(name: &str, value: &str, f: F) {
    let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let prior = std::env::var(name).ok();
    unsafe { std::env::set_var(name, value); }
    f();
    unsafe {
        match prior {
            Some(v) => std::env::set_var(name, v),
            None => std::env::remove_var(name),
        }
    }
}

fn lock_env() -> std::sync::MutexGuard<'static, ()> {
    ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner())
}

// ── Hypothesis builders ────────────────────────────────────────────────────

fn chain_hypothesis(n_steps: usize) -> Hypothesis {
    let mut h = Hypothesis::new("chain");
    for _ in 0..n_steps {
        h = h.add_step(HypothesisStep::new(
            EntityType::User,
            RelationType::Auth,
            EntityType::User,
        ));
    }
    h
}

fn homogeneous_hypothesis(n_steps: usize) -> Hypothesis {
    let mut h = Hypothesis::new("homogeneous");
    for _ in 0..n_steps {
        h = h.add_step(HypothesisStep::new(
            EntityType::Host,
            RelationType::Connect,
            EntityType::Host,
        ));
    }
    h
}

fn c6_hypothesis() -> Hypothesis {
    // Six homogeneous steps with the "6-cycle" name marker.
    let mut h = Hypothesis::new("APT lateral movement (6-cycle)");
    for _ in 0..6 {
        h = h.add_step(HypothesisStep::new(
            EntityType::Host,
            RelationType::Connect,
            EntityType::Host,
        ));
    }
    h
}

fn star_hypothesis() -> Hypothesis {
    // 3-leaf star via Graph shape + explicit bindings.
    let mut step0 = HypothesisStep::new(EntityType::User, RelationType::Auth, EntityType::User);
    step0.origin_binding = Some("c".into());
    step0.dest_binding = Some("l0".into());
    let mut step1 = HypothesisStep::new(EntityType::User, RelationType::Auth, EntityType::User);
    step1.origin_binding = Some("c".into());
    step1.dest_binding = Some("l1".into());
    let mut step2 = HypothesisStep::new(EntityType::User, RelationType::Auth, EntityType::User);
    step2.origin_binding = Some("c".into());
    step2.dest_binding = Some("l2".into());
    Hypothesis {
        steps: vec![step0, step1, step2],
        shape: graph_hunter_core::dsl::hypothesis::HypothesisShape::Graph,
        ..Hypothesis::new("star")
    }
}

// ── Tests ──────────────────────────────────────────────────────────────────

#[test]
fn cap21_chain_defaults_to_dfs_without_flags() {
    let _guard = lock_env();
    unsafe {
        std::env::remove_var("GRAPHHUNTER_YANNAKAKIS");
        std::env::remove_var("GRAPHHUNTER_K4_LFTJ");
        std::env::remove_var("GRAPHHUNTER_LFTJ_PLANNER");
        std::env::remove_var("GRAPHHUNTER_TRIANGLE_LFTJ");
        std::env::remove_var("GRAPHHUNTER_LFTJ_AUTO");
        std::env::remove_var("GRAPHHUNTER_C6_LFTJ");
        std::env::remove_var("GRAPHHUNTER_K5_LFTJ");
    }
    let h = chain_hypothesis(2);
    assert_eq!(
        plan(&h),
        DispatchPlan::DfsMatch,
        "a chain with no env flags must dispatch to DfsMatch"
    );
    println!("\n[cap21_chain_dfs] PASS: 2-step chain → DfsMatch");
}

#[test]
fn cap21_chain_dispatches_to_yannakakis_when_flag_set() {
    let h = chain_hypothesis(2);
    with_var("GRAPHHUNTER_YANNAKAKIS", "1", || {
        assert_eq!(
            plan(&h),
            DispatchPlan::Yannakakis,
            "GRAPHHUNTER_YANNAKAKIS=1 must route an acyclic chain to Yannakakis"
        );
    });
    println!("\n[cap21_chain_yannakakis] PASS: 2-step chain + flag → Yannakakis");
}

#[test]
fn cap21_triangle_dispatches_to_lftj_when_planner_set() {
    let h = homogeneous_hypothesis(3);
    with_var("GRAPHHUNTER_LFTJ_PLANNER", "1", || {
        assert_eq!(
            plan(&h),
            DispatchPlan::TriangleLftj,
            "a 3-step homogeneous hypothesis must dispatch to TriangleLftj under LFTJ_PLANNER"
        );
    });
    println!("\n[cap21_triangle_lftj] PASS: 3-step homogeneous + planner → TriangleLftj");
}

#[test]
fn cap21_k4_clique_dispatches_to_k4_lftj_when_planner_set() {
    let h = homogeneous_hypothesis(6);
    with_var("GRAPHHUNTER_LFTJ_PLANNER", "1", || {
        assert_eq!(
            plan(&h),
            DispatchPlan::K4Lftj,
            "a 6-step homogeneous hypothesis must dispatch to K4Lftj under LFTJ_PLANNER"
        );
    });
    println!("\n[cap21_k4_lftj] PASS: 6-step homogeneous + planner → K4Lftj");
}

#[test]
fn cap21_k5_clique_dispatches_to_k5_lftj_when_planner_set() {
    let h = homogeneous_hypothesis(10);
    with_var("GRAPHHUNTER_LFTJ_PLANNER", "1", || {
        assert_eq!(
            plan(&h),
            DispatchPlan::K5Lftj,
            "a 10-step homogeneous hypothesis must dispatch to K5Lftj under LFTJ_PLANNER"
        );
    });
    println!("\n[cap21_k5_lftj] PASS: 10-step homogeneous + planner → K5Lftj");
}

#[test]
fn cap21_c6_cycle_dispatches_to_c6_lftj_via_name_marker() {
    let h = c6_hypothesis();
    with_var("GRAPHHUNTER_C6_LFTJ", "1", || {
        assert_eq!(
            plan(&h),
            DispatchPlan::C6Lftj,
            "a 6-cycle name marker + GRAPHHUNTER_C6_LFTJ=1 must dispatch to C6Lftj"
        );
    });
    println!("\n[cap21_c6_lftj] PASS: 6-cycle name + flag → C6Lftj");
}

#[test]
fn cap21_star_dispatches_to_yannakakis_when_flag_set() {
    // A Graph-shape star is α-acyclic (a 3-leaf star graph is a tree).
    let h = star_hypothesis();
    with_var("GRAPHHUNTER_YANNAKAKIS", "1", || {
        assert_eq!(
            plan(&h),
            DispatchPlan::Yannakakis,
            "a Graph-shape star is α-acyclic → Yannakakis under GRAPHHUNTER_YANNAKAKIS=1"
        );
    });
    println!("\n[cap21_star_yannakakis] PASS: star + flag → Yannakakis");
}

// ── Cost-aware planner tests ───────────────────────────────────────────────

#[test]
fn cap21_cost_model_picks_triangle_lftj_for_dense_graph() {
    // Dense hub graph: V=1K, E=250K, d=500. At this density the AGM
    // bound (m^1.5) beats DFS (m·d^2). The cost model must select
    // TriangleLftj. (Calibrated in `src/planner.rs` cost-model tests.)
    let h = homogeneous_hypothesis(3);
    let hints = CostHints {
        vertex_count: 1_000,
        edge_count: 250_000,
        avg_degree: 500.0,
    };
    with_var("GRAPHHUNTER_LFTJ_AUTO", "1", || {
        assert_eq!(
            plan_with_hints(&h, &hints),
            DispatchPlan::TriangleLftj,
            "cost model must select TriangleLftj on a dense hub graph"
        );
    });
    println!("\n[cap21_cost_dense] PASS: dense hub → TriangleLftj via cost model");
}

#[test]
fn cap21_cost_model_picks_dfs_for_sparse_small_graph() {
    // Small sparse graph: V=1K, E=20K, d=20. Trie build cost dominates
    // at this scale — DFS-Match should win (or Yannakakis, since the
    // chain is acyclic). Either way, NOT TriangleLftj.
    let h = homogeneous_hypothesis(3);
    let hints = CostHints {
        vertex_count: 1_000,
        edge_count: 20_000,
        avg_degree: 20.0,
    };
    with_var("GRAPHHUNTER_LFTJ_AUTO", "1", || {
        let p = plan_with_hints(&h, &hints);
        assert_ne!(
            p,
            DispatchPlan::TriangleLftj,
            "cost model must NOT select TriangleLftj on a sparse small graph; got {:?}",
            p
        );
    });
    println!("\n[cap21_cost_sparse] PASS: sparse small graph → not TriangleLftj");
}

#[test]
fn cap21_planner_without_any_flag_always_returns_dfs_for_chain() {
    // Contract: the *default* configuration (no env flags) must always
    // return DfsMatch for plain chain queries. This ensures that the
    // planner does not silently change behaviour on a fresh install.
    let _guard = lock_env();
    unsafe {
        std::env::remove_var("GRAPHHUNTER_YANNAKAKIS");
        std::env::remove_var("GRAPHHUNTER_K4_LFTJ");
        std::env::remove_var("GRAPHHUNTER_LFTJ_PLANNER");
        std::env::remove_var("GRAPHHUNTER_TRIANGLE_LFTJ");
        std::env::remove_var("GRAPHHUNTER_LFTJ_AUTO");
        std::env::remove_var("GRAPHHUNTER_C6_LFTJ");
        std::env::remove_var("GRAPHHUNTER_K5_LFTJ");
    }
    for n_steps in [1, 2, 3, 5, 7] {
        let h = chain_hypothesis(n_steps);
        assert_eq!(
            plan(&h),
            DispatchPlan::DfsMatch,
            "default plan must be DfsMatch for {}-step chain",
            n_steps
        );
    }
    println!("\n[cap21_default_dfs] PASS: all chain shapes → DfsMatch without flags");
}
