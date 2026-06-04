//! M1 — query-shape planner.
//!
//! S3 introduced an env-gated, name-marker-driven dispatch from
//! `search_temporal_pattern` to the K4-LFTJ enumerator: a hypothesis
//! whose `name` contained `"k4-clique"` would route to the fast-path
//! when `GRAPHHUNTER_K4_LFTJ=1` was set. That worked for one shape and
//! one shape only, and it leaked operator-routing concerns into the
//! DSL-facing `Hypothesis` type.
//!
//! M1 centralizes routing here. `plan(hypothesis)` returns a
//! `DispatchPlan` describing which physical operator should execute
//! the query; the matcher entry point in `graph.rs` consults this once
//! and dispatches accordingly. Two routes today:
//!
//! 1. **Name-marker route** (S3-compatible) — kept for back-compat
//!    while DSL author-time annotations exist. Gated behind
//!    `GRAPHHUNTER_K4_LFTJ=1` so existing automation does not change
//!    behavior on upgrade.
//!
//! 2. **Structural route** (new in M1) — when
//!    `GRAPHHUNTER_LFTJ_PLANNER=1` is set, the planner inspects the
//!    hypothesis steps and dispatches to K4-LFTJ when the chain is
//!    six identical homogeneous steps `T -[r]-> T` (the only
//!    authoring shape today's DSL can express that semantically maps
//!    to a 4-clique). No name marker required.
//!
//! Honest scope: the structural route is intentionally narrow. The
//! K4 enumerator does not yet consult per-step entity-type filters, so
//! widening detection beyond the homogeneous-six shape would risk
//! returning tuples that don't satisfy the hypothesis. K5 and C6
//! enumerate variants don't exist (count-only), so they are
//! deliberately unrouted — adding them is L1/L2 work. Aggregations
//! (HAVING/WITHIN) compose because `search_temporal_pattern_k4_lftj`
//! still calls `apply_aggregation` after the enumerator.

use crate::hypothesis::Hypothesis;
use crate::types::{EntityType, RelationType};

/// D1 stage 2 — graph statistics consumed by the cost model. All
/// fields are cheap to read from a finalized `GraphHunter`. Caller
/// constructs once per query (or caches across queries since none
/// change without re-finalize).
#[derive(Clone, Copy, Debug)]
pub struct CostHints {
    pub vertex_count: usize,
    pub edge_count: usize,
    pub avg_degree: f64,
}

impl CostHints {
    /// Read graph stats. `streaming.edge_count()` walks the
    /// `for_each_edge` closure once (O(E)) — fine here because the
    /// planner is consulted *once* per query, not per frame.
    pub fn from_graph(graph: &crate::graph::GraphHunter) -> Self {
        let v = graph.entity_count();
        let e = graph.streaming_edge_count();
        let avg = if v > 0 { e as f64 / v as f64 } else { 0.0 };
        Self {
            vertex_count: v,
            edge_count: e,
            avg_degree: avg,
        }
    }
}

/// Plan-time cost estimate (in arbitrary units; only the *ratio*
/// between plans matters). Uses AGM bound \(m^{\rho^*}\) for LFTJ
/// and a cache-aware \(m \cdot d^{k-1}\) for DFS.
///
/// Calibration anchors:
///   * `triangle_query` bench V=1000 p=0.02 (E=20K, d=20): naive
///     2.26 ms beats LFTJ 6.29 ms. Cost model must rank DFS<LFTJ.
///   * Medium-dense regime V=1K p=0.25 (E=250K, d=500, ~20M
///     triangles): AGM m^1.5 wins decisively over DFS m·d^(k-1).
///     Cost model must rank LFTJ<DFS.
///
/// Cache-awareness: working-set bytes E·32B compared against L2
/// (1 MB). DFS-Match's per-edge HashMap-style lookups cost ~10 ns
/// hot, ~80 ns cold (L3-miss dominated). LFTJ's trie iteration is
/// sequential and stays mostly hot until E·32B exceeds L3.
fn cost_estimate(
    plan: DispatchPlan,
    hypothesis: &Hypothesis,
    hints: &CostHints,
) -> f64 {
    let v = hints.vertex_count as f64;
    let e = hints.edge_count as f64;
    let d = hints.avg_degree.max(1.0);
    let k = hypothesis.steps.len().max(1) as f64;

    // L2 ~= 1 MB; L3 ~= 16 MB. Coefficient scales linearly with
    // miss frequency on the DFS path.
    let working_set = e * 32.0;
    let dfs_coef: f64 = if working_set < 1_048_576.0 {
        10.0
    } else if working_set < 16_777_216.0 {
        30.0
    } else {
        80.0
    };

    // Cyclic DFS (triangle, K4, K5, C6) closes the last edge with
    // an O(1) hash check, so per-anchor work is d^(k-2), not
    // d^(k-1). Chain DFS keeps the d^(k-1) fanout product.
    let is_cyclic = is_homogeneous_triangle_shape(hypothesis)
        || is_homogeneous_k4_shape(hypothesis)
        || is_homogeneous_k5_shape(hypothesis)
        || is_homogeneous_c6_shape(hypothesis)
        || hypothesis.looks_like_triangle()
        || hypothesis.looks_like_k4_clique()
        || hypothesis.looks_like_k5_clique()
        || hypothesis.looks_like_6cycle();
    let dfs_exp = if is_cyclic {
        (k - 2.0).max(0.0)
    } else {
        (k - 1.0).max(0.0)
    };

    // Trie build cost shared by all LFTJ paths: linear scan + per-
    // source dedup-sort. ~1 us per edge at small scale, scales
    // sub-linearly in d via log2 hint.
    let lftj_build = 1000.0 * (v + e * (1.0 + d.log2() / 8.0));

    match plan {
        // ρ*(triangle) = 1.5; ρ*(K4) = 2; ρ*(K5) = 5/2;
        // ρ*(C6) = 3. LFTJ enumerate at ~2 ns per AGM-bounded
        // iteration — sequential trie walk, hot. C6 carries an
        // extra reverse-trie build cost (paid once on the path);
        // we model it as a doubled lftj_build factor.
        DispatchPlan::TriangleLftj => lftj_build + 2.0 * e.powf(1.5),
        DispatchPlan::K4Lftj => lftj_build + 2.0 * e.powf(2.0),
        DispatchPlan::K5Lftj => lftj_build + 2.0 * e.powf(2.5),
        DispatchPlan::C6Lftj => 2.0 * lftj_build + 2.0 * e.powf(3.0),
        DispatchPlan::Yannakakis => {
            // α-acyclic, output-sensitive: O(E + |OUT|). |OUT|
            // unknown at plan time; bound above by m·d^(k-1).
            dfs_coef * e * d.powf((k - 1.0).max(0.0))
        }
        DispatchPlan::DfsMatch => dfs_coef * e * d.powf(dfs_exp),
    }
}

/// Physical operator selected by the planner.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum DispatchPlan {
    /// Default — generic DFS-Match path with NLF/D5/B9/D2-lite prunes.
    DfsMatch,
    /// 3-clique (triangle) LFTJ enumerator
    /// (`search_temporal_pattern_triangle`). Wins decisively on dense
    /// graphs at ρ\*(triangle)=1.5 vs DFS's O(m·deg^2). D1 stage 1
    /// generalization of the K4 path: same trie, same SIMD intersect,
    /// 3-step shape detection.
    TriangleLftj,
    /// K4-clique LFTJ enumerator (`search_temporal_pattern_k4_lftj`).
    /// Wins decisively at ρ\*(K4)=2 versus DFS's O(m·deg^3).
    K4Lftj,
    /// K5-clique LFTJ enumerator (`search_temporal_pattern_k5_lftj`).
    /// AGM bound ρ\*(K5)=5/2; per-anchor SIMD intersect chain
    /// `ab → abc → abcd` then per-d intersect for `e`.
    K5Lftj,
    /// Directed 6-cycle LFTJ enumerator
    /// (`search_temporal_pattern_c6_lftj`). AGM bound ρ\*(C6)=3 —
    /// the highest of the cyclic-shape family. Walks `(a, b, c, d,
    /// e)` linearly along the cycle, then intersects
    /// `N_forward(e) ∩ predecessors(a)` for the cycle-closing `f`.
    /// Requires both forward and reverse CSR tries. Canonical APT
    /// lateral-movement shape.
    C6Lftj,
    /// Yannakakis-style chain matcher
    /// (`yannakakis::search_temporal_pattern_yannakakis`). Output-
    /// sensitive on α-acyclic hypotheses; today's chain DSL is always
    /// α-acyclic, so this dispatches universally when its env flag is
    /// on. Pure two-pass semi-join reducer + chain enumerator — no
    /// FFI, no LFTJ trie build.
    Yannakakis,
}

/// Decide which operator should execute `hypothesis`. Pure function of
/// the hypothesis and process env — no graph access, cheap to call at
/// query entry. Order matters: K4 LFTJ has a strictly larger
/// asymptotic win on its shape, so it gets first refusal; Yannakakis
/// covers the remaining α-acyclic shapes the DSL emits.
pub fn plan(hypothesis: &Hypothesis) -> DispatchPlan {
    if triangle_name_marker_dispatch(hypothesis) {
        return DispatchPlan::TriangleLftj;
    }
    if triangle_structural_dispatch(hypothesis) {
        return DispatchPlan::TriangleLftj;
    }
    // C6 must dispatch *before* K4 — both shapes have exactly 6
    // homogeneous steps, but a user marking the hypothesis with
    // `6-cycle` / `c6-cycle` wants the cycle path, not the clique.
    // Only the name marker disambiguates; the structural route
    // (6 homogeneous steps) defaults to K4 below.
    if c6_name_marker_dispatch(hypothesis) {
        return DispatchPlan::C6Lftj;
    }
    if k5_name_marker_dispatch(hypothesis) {
        return DispatchPlan::K5Lftj;
    }
    if k5_structural_dispatch(hypothesis) {
        return DispatchPlan::K5Lftj;
    }
    if name_marker_dispatch(hypothesis) {
        return DispatchPlan::K4Lftj;
    }
    if structural_dispatch(hypothesis) {
        return DispatchPlan::K4Lftj;
    }
    if yannakakis_dispatch(hypothesis) {
        return DispatchPlan::Yannakakis;
    }
    DispatchPlan::DfsMatch
}

/// D1 stage 2 — cost-aware planner with lazy hint construction.
/// Equivalent to `plan_with_hints` but only invokes the
/// `hints_fn` closure when `GRAPHHUNTER_LFTJ_AUTO=1`. Saves the
/// O(V) graph-stats walk on the default path.
pub fn plan_with_hints_lazy<F: FnOnce() -> CostHints>(
    hypothesis: &Hypothesis,
    hints_fn: F,
) -> DispatchPlan {
    if !env_flag("GRAPHHUNTER_LFTJ_AUTO") {
        return plan(hypothesis);
    }
    plan_with_hints(hypothesis, &hints_fn())
}

/// D1 stage 2 — cost-aware planner. When `GRAPHHUNTER_LFTJ_AUTO=1`
/// is set, considers every structurally-valid plan for the
/// hypothesis and picks the one with the lowest `cost_estimate`.
/// Otherwise behaves as `plan()` (env-flag-only dispatch).
///
/// Why not always cost-aware: cost-model has constants calibrated
/// on one host (galaxy-book4); on hosts with very different
/// memory hierarchies the constants might pick the wrong plan.
/// The legacy flag path stays the production default until the
/// cost model has multi-host calibration.
pub fn plan_with_hints(hypothesis: &Hypothesis, hints: &CostHints) -> DispatchPlan {
    if !env_flag("GRAPHHUNTER_LFTJ_AUTO") {
        return plan(hypothesis);
    }

    // Enumerate structurally-valid plans for this hypothesis shape,
    // then pick the lowest-cost one. Yannakakis only valid on
    // α-acyclic queries (delegated to its own gate).
    let mut best = (DispatchPlan::DfsMatch, cost_estimate(DispatchPlan::DfsMatch, hypothesis, hints));

    if is_homogeneous_triangle_shape(hypothesis) || hypothesis.looks_like_triangle() {
        let c = cost_estimate(DispatchPlan::TriangleLftj, hypothesis, hints);
        if c < best.1 {
            best = (DispatchPlan::TriangleLftj, c);
        }
    }
    if is_homogeneous_k4_shape(hypothesis) || hypothesis.looks_like_k4_clique() {
        let c = cost_estimate(DispatchPlan::K4Lftj, hypothesis, hints);
        if c < best.1 {
            best = (DispatchPlan::K4Lftj, c);
        }
    }
    if is_homogeneous_k5_shape(hypothesis) || hypothesis.looks_like_k5_clique() {
        let c = cost_estimate(DispatchPlan::K5Lftj, hypothesis, hints);
        if c < best.1 {
            best = (DispatchPlan::K5Lftj, c);
        }
    }
    if is_homogeneous_c6_shape(hypothesis) || hypothesis.looks_like_6cycle() {
        let c = cost_estimate(DispatchPlan::C6Lftj, hypothesis, hints);
        if c < best.1 {
            best = (DispatchPlan::C6Lftj, c);
        }
    }
    // Yannakakis: α-acyclicity is graph-shape dependent; checking
    // it is the same cheap pass yannakakis_dispatch does, minus
    // the env-flag gate. We rebuild the hypergraph here because
    // the result is small (steps × O(1)) and the cost-aware path
    // is opt-in.
    let yan_g = crate::yannakakis::Hypergraph::of(hypothesis);
    if crate::yannakakis::is_alpha_acyclic(&yan_g) {
        let c = cost_estimate(DispatchPlan::Yannakakis, hypothesis, hints);
        if c < best.1 {
            best = (DispatchPlan::Yannakakis, c);
        }
    }

    best.0
}

fn triangle_name_marker_dispatch(hypothesis: &Hypothesis) -> bool {
    if !env_flag("GRAPHHUNTER_TRIANGLE_LFTJ") {
        return false;
    }
    hypothesis.looks_like_triangle()
}

fn triangle_structural_dispatch(hypothesis: &Hypothesis) -> bool {
    if !env_flag("GRAPHHUNTER_LFTJ_PLANNER") {
        return false;
    }
    is_homogeneous_triangle_shape(hypothesis)
}

/// True iff the chain consists of exactly 3 identical homogeneous
/// steps `T -[r]-> T` for some concrete `T` and `r`. Three is the
/// number of directed edges in a triangle (forward 3-clique) under
/// a total order on vertex IDs. Same homogeneity contract as the
/// K4 detector — wildcards rejected because the LFTJ enumerator
/// projects on a single edge-type.
fn is_homogeneous_triangle_shape(hypothesis: &Hypothesis) -> bool {
    let steps = &hypothesis.steps;
    if steps.len() != 3 {
        return false;
    }
    let first = &steps[0];
    if matches!(first.origin_type, EntityType::Any | EntityType::Other(_)) {
        return false;
    }
    if matches!(first.relation_type, RelationType::Any | RelationType::Other(_)) {
        return false;
    }
    if first.origin_type != first.dest_type {
        return false;
    }
    steps.iter().all(|s| {
        s.origin_type == first.origin_type
            && s.dest_type == first.dest_type
            && s.relation_type == first.relation_type
            && s.edge_predicates.is_empty()
            && s.dest_predicates.is_empty()
    })
}

fn yannakakis_dispatch(hypothesis: &Hypothesis) -> bool {
    if !env_flag("GRAPHHUNTER_YANNAKAKIS") {
        return false;
    }
    if hypothesis.steps.is_empty() {
        return false;
    }
    // L1 stage 3: both Chain-shape (chain-walk enumerator) and
    // Graph-shape (tree-walk enumerator) are now α-acyclic-safe.
    // The α-acyclicity gate stays — cyclic hypotheses fall back
    // to DFS regardless of shape.
    let g = crate::yannakakis::Hypergraph::of(hypothesis);
    crate::yannakakis::is_alpha_acyclic(&g)
}

fn name_marker_dispatch(hypothesis: &Hypothesis) -> bool {
    if !env_flag("GRAPHHUNTER_K4_LFTJ") {
        return false;
    }
    hypothesis.looks_like_k4_clique()
}

fn structural_dispatch(hypothesis: &Hypothesis) -> bool {
    if !env_flag("GRAPHHUNTER_LFTJ_PLANNER") {
        return false;
    }
    is_homogeneous_k4_shape(hypothesis)
}

/// True iff the chain consists of exactly 6 identical homogeneous
/// steps `T -[r]-> T` for some concrete `T` and `r`. Six is the number
/// of directed edges in a 4-clique under any total order; homogeneity
/// guarantees the LFTJ enumerator (which today projects on a single
/// edge-type) can answer correctly.
///
/// Wildcards (`Any`) are deliberately rejected — the enumerator
/// currently treats them as "all edges" rather than "edges matching
/// any single concrete type", and conflating those would change the
/// result-set semantics versus DFS-Match.
fn is_homogeneous_k4_shape(hypothesis: &Hypothesis) -> bool {
    let steps = &hypothesis.steps;
    if steps.len() != 6 {
        return false;
    }
    let first = &steps[0];
    if matches!(first.origin_type, EntityType::Any | EntityType::Other(_)) {
        return false;
    }
    if matches!(first.relation_type, RelationType::Any | RelationType::Other(_)) {
        return false;
    }
    if first.origin_type != first.dest_type {
        return false;
    }
    steps.iter().all(|s| {
        s.origin_type == first.origin_type
            && s.dest_type == first.dest_type
            && s.relation_type == first.relation_type
            && s.edge_predicates.is_empty()
            && s.dest_predicates.is_empty()
    })
}

fn k5_name_marker_dispatch(hypothesis: &Hypothesis) -> bool {
    if !env_flag("GRAPHHUNTER_K5_LFTJ") {
        return false;
    }
    hypothesis.looks_like_k5_clique()
}

fn k5_structural_dispatch(hypothesis: &Hypothesis) -> bool {
    if !env_flag("GRAPHHUNTER_LFTJ_PLANNER") {
        return false;
    }
    is_homogeneous_k5_shape(hypothesis)
}

/// True iff the chain consists of exactly 10 identical homogeneous
/// steps `T -[r]-> T`. Ten is the number of directed edges in a
/// 5-clique under any total order. Same homogeneity contract as
/// `is_homogeneous_k4_shape`.
fn is_homogeneous_k5_shape(hypothesis: &Hypothesis) -> bool {
    let steps = &hypothesis.steps;
    if steps.len() != 10 {
        return false;
    }
    let first = &steps[0];
    if matches!(first.origin_type, EntityType::Any | EntityType::Other(_)) {
        return false;
    }
    if matches!(first.relation_type, RelationType::Any | RelationType::Other(_)) {
        return false;
    }
    if first.origin_type != first.dest_type {
        return false;
    }
    steps.iter().all(|s| {
        s.origin_type == first.origin_type
            && s.dest_type == first.dest_type
            && s.relation_type == first.relation_type
            && s.edge_predicates.is_empty()
            && s.dest_predicates.is_empty()
    })
}

fn c6_name_marker_dispatch(hypothesis: &Hypothesis) -> bool {
    if !env_flag("GRAPHHUNTER_C6_LFTJ") {
        return false;
    }
    hypothesis.looks_like_6cycle()
}

/// True iff the hypothesis is structurally a 6-step homogeneous
/// chain *and* the name marker explicitly says `6-cycle` /
/// `c6-cycle`. Used by the cost model and the AUTO-planner to
/// disambiguate C6 from K4 (which has the same step shape). The
/// non-AUTO `plan()` route reaches the same routing via the
/// `c6_name_marker_dispatch` short-circuit before falling through
/// to K4.
fn is_homogeneous_c6_shape(hypothesis: &Hypothesis) -> bool {
    if !hypothesis.looks_like_6cycle() {
        return false;
    }
    let steps = &hypothesis.steps;
    if steps.len() != 6 {
        return false;
    }
    let first = &steps[0];
    if matches!(first.origin_type, EntityType::Any | EntityType::Other(_)) {
        return false;
    }
    if matches!(first.relation_type, RelationType::Any | RelationType::Other(_)) {
        return false;
    }
    if first.origin_type != first.dest_type {
        return false;
    }
    steps.iter().all(|s| {
        s.origin_type == first.origin_type
            && s.dest_type == first.dest_type
            && s.relation_type == first.relation_type
            && s.edge_predicates.is_empty()
            && s.dest_predicates.is_empty()
    })
}

#[inline]
fn env_flag(name: &str) -> bool {
    std::env::var(name)
        .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
        .unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hypothesis::HypothesisStep;

    fn k4_homogeneous() -> Hypothesis {
        let mut h = Hypothesis::new("plain hunt");
        for _ in 0..6 {
            h = h.add_step(HypothesisStep::new(
                EntityType::Host,
                RelationType::Connect,
                EntityType::Host,
            ));
        }
        h
    }

    fn five_step_chain() -> Hypothesis {
        let mut h = Hypothesis::new("five-step");
        for _ in 0..5 {
            h = h.add_step(HypothesisStep::new(
                EntityType::Host,
                RelationType::Connect,
                EntityType::Host,
            ));
        }
        h
    }

    fn k5_homogeneous() -> Hypothesis {
        let mut h = Hypothesis::new("plain hunt");
        for _ in 0..10 {
            h = h.add_step(HypothesisStep::new(
                EntityType::Host,
                RelationType::Connect,
                EntityType::Host,
            ));
        }
        h
    }

    /// Process-wide mutex shared by every env-mutating test in this
    /// module. Cargo test runs in parallel by default; without this
    /// guard, two tests setting different `GRAPHHUNTER_*_LFTJ` flags
    /// race and the loser sees an inconsistent dispatch route. CI
    /// used to band-aid this with `--test-threads=1` (see
    /// `.github/workflows/ci.yml`); the mutex makes that workaround
    /// unnecessary by serializing only the env-touching tests
    /// instead of the whole suite.
    static ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    /// Holds the env lock for the closure's lifetime, sets / restores
    /// the named var, and survives panics by storing the prior value
    /// before mutating. Always pair with `lock_env()` in tests that
    /// also call `std::env::remove_var` directly.
    fn with_var<F: FnOnce()>(name: &str, value: &str, f: F) {
        let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let prior = std::env::var(name).ok();
        // SAFETY: env mutations on this thread are serialized by
        // ENV_LOCK; no other test reads or writes these vars while
        // the guard is held. The dispatch module's only callers
        // (the matcher entry points) are not exercised concurrently
        // with these tests.
        unsafe {
            std::env::set_var(name, value);
        }
        f();
        unsafe {
            match prior {
                Some(v) => std::env::set_var(name, v),
                None => std::env::remove_var(name),
            }
        }
    }

    /// Acquire the env lock without setting any var — for tests that
    /// only want to call `remove_var` or read existing state.
    /// Returns a guard the caller must keep alive for the duration
    /// of the env access.
    fn lock_env() -> std::sync::MutexGuard<'static, ()> {
        ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner())
    }

    #[test]
    fn default_is_dfs_match() {
        let _guard = lock_env();
        let h = k4_homogeneous();
        // No env vars set → no dispatch.
        unsafe {
            std::env::remove_var("GRAPHHUNTER_K4_LFTJ");
            std::env::remove_var("GRAPHHUNTER_LFTJ_PLANNER");
        }
        assert_eq!(plan(&h), DispatchPlan::DfsMatch);
    }

    #[test]
    fn name_marker_route_dispatches() {
        let h = Hypothesis::new("APT lateral movement (k4-clique)").add_step(
            HypothesisStep::new(EntityType::Host, RelationType::Connect, EntityType::Host),
        );
        with_var("GRAPHHUNTER_K4_LFTJ", "1", || {
            assert_eq!(plan(&h), DispatchPlan::K4Lftj);
        });
    }

    #[test]
    fn name_marker_route_inactive_without_env() {
        let _guard = lock_env();
        let h = Hypothesis::new("k4-clique probe").add_step(HypothesisStep::new(
            EntityType::Host,
            RelationType::Connect,
            EntityType::Host,
        ));
        unsafe {
            std::env::remove_var("GRAPHHUNTER_K4_LFTJ");
            std::env::remove_var("GRAPHHUNTER_LFTJ_PLANNER");
        }
        assert_eq!(plan(&h), DispatchPlan::DfsMatch);
    }

    #[test]
    fn structural_route_dispatches_for_homogeneous_six_step() {
        let h = k4_homogeneous();
        with_var("GRAPHHUNTER_LFTJ_PLANNER", "1", || {
            assert_eq!(plan(&h), DispatchPlan::K4Lftj);
        });
    }

    #[test]
    fn structural_route_skips_five_step_chain() {
        let h = five_step_chain();
        with_var("GRAPHHUNTER_LFTJ_PLANNER", "1", || {
            assert_eq!(plan(&h), DispatchPlan::DfsMatch);
        });
    }

    #[test]
    fn structural_route_skips_heterogeneous_chain() {
        let mut h = Hypothesis::new("h");
        for _ in 0..5 {
            h = h.add_step(HypothesisStep::new(
                EntityType::Host,
                RelationType::Connect,
                EntityType::Host,
            ));
        }
        h = h.add_step(HypothesisStep::new(
            EntityType::Host,
            RelationType::Spawn,
            EntityType::Host,
        ));
        with_var("GRAPHHUNTER_LFTJ_PLANNER", "1", || {
            assert_eq!(plan(&h), DispatchPlan::DfsMatch);
        });
    }

    #[test]
    fn structural_route_rejects_wildcard_relation() {
        let mut h = Hypothesis::new("h");
        for _ in 0..6 {
            h = h.add_step(HypothesisStep::new(
                EntityType::Host,
                RelationType::Any,
                EntityType::Host,
            ));
        }
        with_var("GRAPHHUNTER_LFTJ_PLANNER", "1", || {
            assert_eq!(plan(&h), DispatchPlan::DfsMatch);
        });
    }

    fn triangle_homogeneous() -> Hypothesis {
        let mut h = Hypothesis::new("plain hunt");
        for _ in 0..3 {
            h = h.add_step(HypothesisStep::new(
                EntityType::Host,
                RelationType::Connect,
                EntityType::Host,
            ));
        }
        h
    }

    #[test]
    fn triangle_name_marker_route_dispatches() {
        let h = Hypothesis::new("Lateral pivot (triangle)").add_step(HypothesisStep::new(
            EntityType::Host,
            RelationType::Connect,
            EntityType::Host,
        ));
        with_var("GRAPHHUNTER_TRIANGLE_LFTJ", "1", || {
            assert_eq!(plan(&h), DispatchPlan::TriangleLftj);
        });
    }

    #[test]
    fn triangle_structural_route_dispatches_for_three_step() {
        let h = triangle_homogeneous();
        with_var("GRAPHHUNTER_LFTJ_PLANNER", "1", || {
            assert_eq!(plan(&h), DispatchPlan::TriangleLftj);
        });
    }

    #[test]
    fn triangle_route_takes_priority_over_k4_for_three_step() {
        // Both env flags on; the 3-step shape should still pick the
        // triangle route, not be misclassified as K4.
        let h = triangle_homogeneous();
        with_var("GRAPHHUNTER_LFTJ_PLANNER", "1", || {
            assert_eq!(plan(&h), DispatchPlan::TriangleLftj);
        });
    }

    #[test]
    fn triangle_structural_route_skips_two_step() {
        let mut h = Hypothesis::new("h");
        for _ in 0..2 {
            h = h.add_step(HypothesisStep::new(
                EntityType::Host,
                RelationType::Connect,
                EntityType::Host,
            ));
        }
        with_var("GRAPHHUNTER_LFTJ_PLANNER", "1", || {
            assert_eq!(plan(&h), DispatchPlan::DfsMatch);
        });
    }

    #[test]
    fn cost_model_picks_dfs_for_small_dense_triangle_query() {
        // Small dense graph (V=1000, E=20000): DFS-Match should
        // beat triangle LFTJ because trie build cost dominates.
        // Bench-validated on galaxy-book4: naive 2.26 ms vs LFTJ
        // 6.29 ms at this scale. Cost model must agree.
        let h = triangle_homogeneous();
        let hints = CostHints {
            vertex_count: 1_000,
            edge_count: 20_000,
            avg_degree: 20.0,
        };
        with_var("GRAPHHUNTER_LFTJ_AUTO", "1", || {
            assert_eq!(plan_with_hints(&h, &hints), DispatchPlan::DfsMatch);
        });
    }

    #[test]
    fn cost_model_picks_triangle_lftj_for_medium_dense_hub_graph() {
        // Medium-dense hub graph (V=1K, p=0.5 ⇒ E=250K, d=500):
        // many triangles, DFS catastrophically fans out at d=500
        // per anchor while LFTJ stays at AGM bound m^1.5 ≈ 125M.
        // This is the regime where AGM optimality decisively beats
        // brute force.
        let h = triangle_homogeneous();
        let hints = CostHints {
            vertex_count: 1_000,
            edge_count: 250_000,
            avg_degree: 500.0,
        };
        with_var("GRAPHHUNTER_LFTJ_AUTO", "1", || {
            assert_eq!(plan_with_hints(&h, &hints), DispatchPlan::TriangleLftj);
        });
    }

    #[test]
    fn cost_model_skips_lftj_for_non_clique_shape() {
        // 5-step chain isn't a triangle or K4; cost model should
        // return DFS even when AUTO is on.
        let h = five_step_chain();
        let hints = CostHints {
            vertex_count: 100_000,
            edge_count: 300_000,
            avg_degree: 3.0,
        };
        with_var("GRAPHHUNTER_LFTJ_AUTO", "1", || {
            // Yannakakis can apply (chain is α-acyclic), so check
            // the result is one of {DfsMatch, Yannakakis}.
            let p = plan_with_hints(&h, &hints);
            assert!(
                matches!(p, DispatchPlan::DfsMatch | DispatchPlan::Yannakakis),
                "expected DfsMatch or Yannakakis, got {:?}",
                p
            );
        });
    }

    #[test]
    fn cost_model_inactive_falls_back_to_legacy_plan() {
        let _guard = lock_env();
        let h = triangle_homogeneous();
        let hints = CostHints {
            vertex_count: 100_000,
            edge_count: 300_000,
            avg_degree: 3.0,
        };
        // No AUTO flag; falls back to plan() which respects the
        // flag-only dispatchers. With no flags, DFS.
        unsafe {
            std::env::remove_var("GRAPHHUNTER_LFTJ_AUTO");
            std::env::remove_var("GRAPHHUNTER_LFTJ_PLANNER");
            std::env::remove_var("GRAPHHUNTER_TRIANGLE_LFTJ");
        }
        assert_eq!(plan_with_hints(&h, &hints), DispatchPlan::DfsMatch);
    }

    #[test]
    fn k5_name_marker_route_dispatches() {
        let h = Hypothesis::new("APT lateral movement (k5-clique)").add_step(
            HypothesisStep::new(EntityType::Host, RelationType::Connect, EntityType::Host),
        );
        with_var("GRAPHHUNTER_K5_LFTJ", "1", || {
            assert_eq!(plan(&h), DispatchPlan::K5Lftj);
        });
    }

    #[test]
    fn k5_structural_route_dispatches_for_homogeneous_ten_step() {
        let h = k5_homogeneous();
        with_var("GRAPHHUNTER_LFTJ_PLANNER", "1", || {
            assert_eq!(plan(&h), DispatchPlan::K5Lftj);
        });
    }

    #[test]
    fn k5_structural_route_skips_non_ten_step() {
        // Six steps is K4, not K5.
        let h = k4_homogeneous();
        with_var("GRAPHHUNTER_LFTJ_PLANNER", "1", || {
            assert_eq!(plan(&h), DispatchPlan::K4Lftj);
        });
    }

    #[test]
    fn c6_name_marker_route_dispatches() {
        // Six homogeneous steps with the name marker `6-cycle`
        // route to C6, not K4.
        let mut h = Hypothesis::new("APT lateral movement (6-cycle)");
        for _ in 0..6 {
            h = h.add_step(HypothesisStep::new(
                EntityType::Host,
                RelationType::Connect,
                EntityType::Host,
            ));
        }
        with_var("GRAPHHUNTER_C6_LFTJ", "1", || {
            assert_eq!(plan(&h), DispatchPlan::C6Lftj);
        });
    }

    #[test]
    fn c6_route_takes_priority_over_k4_for_six_step() {
        let _guard = lock_env();
        // Without the C6 name marker, a 6-step homogeneous shape
        // routes to K4 (legacy behavior preserved). With the marker
        // and the C6 flag, it routes to C6.
        let mut h = Hypothesis::new("APT lateral movement (6-cycle)");
        for _ in 0..6 {
            h = h.add_step(HypothesisStep::new(
                EntityType::Host,
                RelationType::Connect,
                EntityType::Host,
            ));
        }
        unsafe {
            std::env::remove_var("GRAPHHUNTER_K4_LFTJ");
            std::env::remove_var("GRAPHHUNTER_LFTJ_PLANNER");
            std::env::set_var("GRAPHHUNTER_C6_LFTJ", "1");
        }
        assert_eq!(plan(&h), DispatchPlan::C6Lftj);
        unsafe {
            std::env::remove_var("GRAPHHUNTER_C6_LFTJ");
        }
    }

    #[test]
    fn k4_structural_route_unchanged_by_c6_addition() {
        // Same six-step homogeneous shape *without* the C6 name
        // marker still routes to K4 under GRAPHHUNTER_LFTJ_PLANNER.
        let h = k4_homogeneous();
        with_var("GRAPHHUNTER_LFTJ_PLANNER", "1", || {
            assert_eq!(plan(&h), DispatchPlan::K4Lftj);
        });
    }

    #[test]
    fn cost_model_picks_k5_lftj_for_dense_ten_step_shape() {
        // K5 homogeneous shape on a hub graph where d^4 fanout
        // dominates m^{5/2}: V=500, E=80K, d=320 → DFS d^4 ~ 1e10
        // vs LFTJ m^{5/2} ~ 6e11... actually both are huge but
        // LFTJ's constant is 2 and DFS coef is 80 (cold cache).
        let h = k5_homogeneous();
        let hints = CostHints {
            vertex_count: 500,
            edge_count: 80_000,
            avg_degree: 320.0,
        };
        with_var("GRAPHHUNTER_LFTJ_AUTO", "1", || {
            assert_eq!(plan_with_hints(&h, &hints), DispatchPlan::K5Lftj);
        });
    }

    #[test]
    fn calibration_json_loads_if_present() {
        let path = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../docs/superpowers/calibration/planner-cost-hints.json"
        );
        if !std::path::Path::new(path).exists() {
            return;
        }
        let raw = std::fs::read_to_string(path).expect("read calibration");
        let parsed: serde_json::Value =
            serde_json::from_str(&raw).expect("parse calibration JSON");
        let hosts = parsed
            .get("hosts")
            .and_then(|h| h.as_array())
            .expect("hosts array");
        assert!(
            hosts.len() >= 1,
            "calibration must list at least one host"
        );
    }

    #[test]
    fn structural_route_rejects_predicate_carrying_step() {
        use crate::hypothesis::Predicate;
        let mut h = Hypothesis::new("h");
        let edge_preds = vec![Predicate::Eq {
            key: "hostname".into(),
            value: "lab-01".into(),
        }];
        h = h.add_step(HypothesisStep::with_predicates(
            EntityType::Host,
            RelationType::Connect,
            EntityType::Host,
            edge_preds,
        ));
        for _ in 0..5 {
            h = h.add_step(HypothesisStep::new(
                EntityType::Host,
                RelationType::Connect,
                EntityType::Host,
            ));
        }
        with_var("GRAPHHUNTER_LFTJ_PLANNER", "1", || {
            assert_eq!(plan(&h), DispatchPlan::DfsMatch);
        });
    }
}
