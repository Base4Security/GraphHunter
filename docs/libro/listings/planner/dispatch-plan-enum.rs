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
