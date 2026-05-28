//! L1 stage 1 — Hypergraph + GYO reduction + join tree primitives
//! used by Yannakakis-style output-sensitive enumeration.
//!
//! Stage 1 (this commit) ships the **structural primitives only**:
//!   * `Hypergraph::of(&Hypothesis)` — lifts a hypothesis to its
//!     hypergraph view (variables = vertex bindings, hyperedges =
//!     steps).
//!   * `gyo_reduce` — Graham-Yu-Ozsoyoglu ear-elimination, returning
//!     the elimination order when the hypergraph is α-acyclic, or
//!     `None` when a cyclic core remains.
//!   * `JoinTree::build` — derives a binary join tree from a
//!     successful GYO trace. The tree is the data structure
//!     Yannakakis's two-pass semi-join reducer walks.
//!   * `is_free_connex` — the quick check for the constant-delay
//!     enumeration regime (Bagan-Durand-Grandjean CSL 2007).
//!
//! Stage 2 (a follow-up commit) wires the actual semi-join reducer
//! and the enumeration loop into `search_temporal_pattern`. Today
//! the primitives are not consumed by any hot path; they validate
//! the GYO/α-acyclicity story on the existing DSL surface so the
//! Stage 2 wiring lands without surprises.
//!
//! Why a binary-only hypergraph for now: every `HypothesisStep` is
//! a single edge `origin -[rel]-> dest`, so each hyperedge has
//! exactly two variables. For binary hypergraphs α-acyclicity
//! collapses to forest-ness of the primal graph, which makes GYO
//! cheap and the implementation small. When the DSL grows
//! star/clique shapes (post-L1), the hyperedge representation is
//! already general enough — only `gyo_reduce` and `build_join_tree`
//! need extending.
//!
//! Honest scope of the binding model. The current matcher
//! enforces a strict positional convention: `dest(step_i)` is the
//! same vertex as `origin(step_{i+1})`. Explicit
//! `origin_binding` / `dest_binding` can collapse other position
//! pairs into one variable (closing a chain into a cycle), but
//! cannot introduce a new branch — so today's expressible shapes
//! are linear paths and chains-with-tail-cycles. Stars and trees
//! await a coordinated change to the DSL surface and the matcher
//! contract; this module's hypergraph builder will need a small
//! amendment to drop the auto-chaining default when that lands.

use graph_hunter_dsl::hypothesis::Hypothesis;
use graph_hunter_dsl::hypothesis::HypothesisStep;
use graph_hunter_dsl::types::RelationType;

use crate::graph::{GraphHunter, HuntResult};
use crate::interner::StrId;

#[inline]
fn rel_tag_matches(pattern: &RelationType, tag: u8) -> bool {
    *pattern == RelationType::Any || pattern.to_u8() == tag
}

/// A variable in the hypergraph view of a hypothesis.
///
/// One `VarId` per *distinct* vertex position. For a linear chain
/// `A -[r1]-> B -[r2]-> C` the positions are `[A, B, C]` —
/// `dest(step_i)` is the same vertex as `origin(step_{i+1})`,
/// following the matcher's convention (see
/// `graph.rs` line ≈815). Explicit `origin_binding` /
/// `dest_binding` overrides the positional default and merges the
/// two positions into one variable.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct VarId(pub u32);

/// One hyperedge per `HypothesisStep`. Carries the step index so
/// downstream stages can join the bag back to predicates and
/// timestamps; the hyperedge itself is just `{origin, dest}`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Hyperedge {
    pub step_idx: usize,
    pub origin: VarId,
    pub dest: VarId,
}

impl Hyperedge {
    /// Returns the two variables incident to this hyperedge as a
    /// length-2 tuple in (origin, dest) order. Convenient for
    /// degree counting and ear detection.
    pub fn endpoints(&self) -> (VarId, VarId) {
        (self.origin, self.dest)
    }

    /// Whether this hyperedge mentions `v`.
    pub fn contains(&self, v: VarId) -> bool {
        self.origin == v || self.dest == v
    }
}

/// Hypergraph of a hypothesis.
#[derive(Clone, Debug)]
pub struct Hypergraph {
    /// Number of distinct variables. Variables are `VarId(0)` ..
    /// `VarId(n_vars - 1)`; no gaps.
    pub n_vars: usize,
    /// One hyperedge per step, in step order.
    pub edges: Vec<Hyperedge>,
}

impl Hypergraph {
    /// Lift a hypothesis to its hypergraph view.
    ///
    /// `Chain` shape (default): linear-chain semantics. Position
    /// `i+1` is shared between `dest(step_i)` and `origin(step_{i+1})`,
    /// so the positional vector already collapses adjacent step
    /// boundaries to one variable. Explicit shared bindings can
    /// further collapse non-adjacent positions, producing cycles
    /// when the same binding appears at non-adjacent positions.
    ///
    /// `Graph` shape (L1 stage 3): each `(step, side)` position is
    /// its own independent variable unless an explicit binding
    /// merges it with another. This is the mode that lets a
    /// hypothesis express stars, trees, and arbitrary α-acyclic
    /// shapes — bindings are the source of truth.
    pub fn of(hypothesis: &Hypothesis) -> Self {
        let n_steps = hypothesis.steps.len();
        if n_steps == 0 {
            return Self {
                n_vars: 0,
                edges: Vec::new(),
            };
        }

        // In Chain shape, the positional default ties dest(step_i)
        // to origin(step_{i+1}) (both at position i+1) — so the
        // initial assignment gives `i+1` to both, and they share a
        // var. In Graph shape, every (step, side) position gets
        // its own unique var; explicit bindings are the only
        // mechanism that ties positions together.
        let mut position_to_var: Vec<u32> = match hypothesis.shape {
            graph_hunter_dsl::hypothesis::HypothesisShape::Chain => {
                (0..=n_steps as u32).collect()
            }
            graph_hunter_dsl::hypothesis::HypothesisShape::Graph => {
                // Two unique slots per step: one for origin, one
                // for dest. Total = 2 * n_steps positions. We map
                // step k's origin to slot 2k and dest to slot 2k+1
                // — the matcher's existing positional convention
                // doesn't apply here, so we synthesize independent
                // identifiers.
                (0..(2 * n_steps) as u32).collect()
            }
        };

        // Closure that maps a (step, side) reference to its position
        // index in `position_to_var`. The math depends on shape:
        //   Chain: position == idx for origin, idx+1 for dest.
        //   Graph: position == 2*idx for origin, 2*idx+1 for dest.
        // The slot total above already reserved the right capacity.
        let pos_origin = |idx: usize| match hypothesis.shape {
            graph_hunter_dsl::hypothesis::HypothesisShape::Chain => idx,
            graph_hunter_dsl::hypothesis::HypothesisShape::Graph => 2 * idx,
        };
        let pos_dest = |idx: usize| match hypothesis.shape {
            graph_hunter_dsl::hypothesis::HypothesisShape::Chain => idx + 1,
            graph_hunter_dsl::hypothesis::HypothesisShape::Graph => 2 * idx + 1,
        };

        // Resolve explicit bindings: if two positions share a
        // binding name, merge their variables. Use union-find on
        // the position vector (small N, no need for path
        // compression infrastructure).
        let mut binding_to_pos: std::collections::HashMap<&str, usize> =
            std::collections::HashMap::new();
        let merge = |a: usize, b: usize, position_to_var: &mut Vec<u32>| {
            let va = position_to_var[a];
            let vb = position_to_var[b];
            if va == vb {
                return;
            }
            let target = va.min(vb);
            let other = va.max(vb);
            for slot in position_to_var.iter_mut() {
                if *slot == other {
                    *slot = target;
                }
            }
        };
        for (idx, step) in hypothesis.steps.iter().enumerate() {
            let origin_pos = pos_origin(idx);
            let dest_pos = pos_dest(idx);
            if let Some(name) = step.origin_binding.as_deref() {
                if let Some(&earlier) = binding_to_pos.get(name) {
                    merge(earlier, origin_pos, &mut position_to_var);
                } else {
                    binding_to_pos.insert(name, origin_pos);
                }
            }
            if let Some(name) = step.dest_binding.as_deref() {
                if let Some(&earlier) = binding_to_pos.get(name) {
                    merge(earlier, dest_pos, &mut position_to_var);
                } else {
                    binding_to_pos.insert(name, dest_pos);
                }
            }
        }
        // Compact: rename variables to dense `0..k` so callers can
        // treat `VarId(i)` as a small index without surprises.
        let mut canonical: Vec<u32> = position_to_var.clone();
        canonical.sort();
        canonical.dedup();
        let mut remap = std::collections::HashMap::new();
        for (new_id, &old_id) in canonical.iter().enumerate() {
            remap.insert(old_id, new_id as u32);
        }
        let position_var = |pos: usize| VarId(*remap.get(&position_to_var[pos]).unwrap());

        let edges = hypothesis
            .steps
            .iter()
            .enumerate()
            .map(|(idx, _step)| Hyperedge {
                step_idx: idx,
                origin: position_var(pos_origin(idx)),
                dest: position_var(pos_dest(idx)),
            })
            .collect();

        Self {
            n_vars: canonical.len(),
            edges,
        }
    }

    /// Variables (vertices) covered by this hyperedge set. Useful
    /// for the free-connex head-coverage check.
    pub fn covered_vars(edges: &[Hyperedge]) -> std::collections::BTreeSet<VarId> {
        let mut out = std::collections::BTreeSet::new();
        for e in edges {
            out.insert(e.origin);
            out.insert(e.dest);
        }
        out
    }
}

/// GYO ear-elimination (Graham 1979 / Yu-Ozsoyoglu 1979). Returns
/// the elimination order when the hypergraph is α-acyclic, or
/// `None` when a non-trivial cyclic core remains after no more
/// ears can be removed.
///
/// For a binary hyperedge set the procedure simplifies to:
///   * find a hyperedge containing a vertex of degree 1 (an
///     "ear" — its non-shared endpoint);
///   * remove that hyperedge;
///   * repeat.
/// All hyperedges eliminated ⇒ α-acyclic. Some hyperedges remain
/// with all endpoints of degree ≥ 2 ⇒ the primal graph contains a
/// cycle ⇒ not α-acyclic. The returned `Vec<usize>` is the
/// step-index sequence in elimination order, which `JoinTree::build`
/// reverses to derive parent pointers.
pub fn gyo_reduce(g: &Hypergraph) -> Option<Vec<usize>> {
    if g.edges.is_empty() {
        return Some(Vec::new());
    }

    let n_edges = g.edges.len();
    let mut alive = vec![true; n_edges];
    let mut order: Vec<usize> = Vec::with_capacity(n_edges);

    loop {
        let alive_edges: Vec<usize> = (0..n_edges).filter(|&i| alive[i]).collect();
        if alive_edges.is_empty() {
            break;
        }

        // Vertex degree count over the alive edges.
        let mut degree: std::collections::HashMap<VarId, usize> =
            std::collections::HashMap::new();
        for &i in &alive_edges {
            let (a, b) = g.edges[i].endpoints();
            *degree.entry(a).or_insert(0) += 1;
            *degree.entry(b).or_insert(0) += 1;
        }

        // Find an "ear": an alive edge with at least one endpoint
        // of degree 1. Pick the smallest step index for
        // determinism.
        let ear = alive_edges.iter().copied().find(|&i| {
            let (a, b) = g.edges[i].endpoints();
            degree.get(&a) == Some(&1) || degree.get(&b) == Some(&1)
        });

        match ear {
            Some(idx) => {
                order.push(idx);
                alive[idx] = false;
            }
            None => return None,
        }
    }

    Some(order)
}

/// True iff the hypergraph is α-acyclic. Convenience wrapper over
/// `gyo_reduce` for callers that only need the boolean answer.
pub fn is_alpha_acyclic(g: &Hypergraph) -> bool {
    gyo_reduce(g).is_some()
}

/// Free-connex check: returns true iff the hypergraph is α-acyclic
/// AND there exists a hyperedge that contains every variable in
/// `head`. This is the quick form for single-bag head atoms; the
/// general definition (Bagan-Durand-Grandjean CSL 2007) lets the
/// head atoms span a connected subset of the join tree, which we
/// will implement in stage 2.
///
/// For typical threat-hunt enumeration we want the *full path* in
/// the result, which means `head = all variables`. With that head,
/// free-connex collapses to "some hyperedge covers every
/// variable" — true only when the hypothesis has one step. Larger
/// patterns fall back to the O(|D|·|OUT|) general Yannakakis form.
pub fn is_free_connex(g: &Hypergraph, head: &[VarId]) -> bool {
    if !is_alpha_acyclic(g) {
        return false;
    }
    if head.is_empty() {
        return true;
    }
    let head_set: std::collections::BTreeSet<VarId> = head.iter().copied().collect();
    g.edges
        .iter()
        .any(|e| head_set.iter().all(|v| e.contains(*v)))
}

/// A binary join tree over hyperedges. `nodes[i]` is a step index
/// (key into `Hypergraph::edges`); `parent[i]` is the index *into
/// `nodes`* of this node's parent, or `i` itself for the root.
///
/// The tree is rooted at the *last* edge eliminated by GYO (the
/// core of the hypergraph). Children are the ears that depended on
/// the parent for connection. Yannakakis's bottom-up semi-join
/// reducer walks `nodes` in order; the top-down pass walks them
/// reversed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JoinTree {
    pub nodes: Vec<usize>,
    pub parent: Vec<usize>,
}

impl JoinTree {
    /// Build a join tree from a successful GYO trace. Returns
    /// `None` if the hypergraph is cyclic.
    pub fn build(g: &Hypergraph) -> Option<Self> {
        let elimination = gyo_reduce(g)?;
        if elimination.is_empty() {
            return Some(Self {
                nodes: Vec::new(),
                parent: Vec::new(),
            });
        }

        // GYO eliminated nodes in `elimination[0], elimination[1],
        // ...`. The last surviving edge is the root; everyone
        // earlier in the order is a leaf-or-internal node whose
        // parent is the *next* alive edge that shares a variable
        // when it was eliminated. Walking elimination in reverse
        // (root → leaves) and keeping track of which edges are
        // "already in the tree" gives a clean parent assignment:
        // when edge `e` is being inserted, its parent is whichever
        // already-inserted edge shares a variable with `e`.
        let n = elimination.len();
        let mut nodes: Vec<usize> = Vec::with_capacity(n);
        let mut parent: Vec<usize> = Vec::with_capacity(n);
        let root = *elimination.last().unwrap();
        nodes.push(root);
        parent.push(0);

        // Reverse iterate: skip the root (already pushed).
        for &edge_idx in elimination.iter().rev().skip(1) {
            let (a, b) = g.edges[edge_idx].endpoints();
            // Find the existing tree node sharing a variable.
            let parent_pos = nodes
                .iter()
                .position(|&n_idx| g.edges[n_idx].contains(a) || g.edges[n_idx].contains(b))
                .expect("GYO invariant: every non-root ear shares a var with the surviving core");
            nodes.push(edge_idx);
            parent.push(parent_pos);
        }
        Some(Self { nodes, parent })
    }
}

// ─── Stage 2 — Bag materialization, semi-join reducer, enumerator ─────
//
// What follows turns the structural primitives above into a working
// path matcher for linear chain hypotheses. Today's DSL only emits
// chains, so this is the entire scope; once the DSL grows non-chain
// shapes the join-tree machinery in stage 1 becomes the dispatch
// surface and this section will graduate to walk arbitrary trees.

/// One row of a materialized bag — a single edge that satisfies one
/// hypothesis step's structural and predicate constraints.
#[derive(Clone, Copy, Debug)]
pub struct BagRow {
    pub origin: StrId,
    pub dest: StrId,
    pub timestamp: i64,
}

/// All rows materializing one step's bag. Vec<BagRow> wrapped so
/// callers can later swap in a sorted-by-key representation without
/// changing call sites.
#[derive(Clone, Debug, Default)]
pub struct Bag {
    pub rows: Vec<BagRow>,
}

impl Bag {
    pub fn len(&self) -> usize {
        self.rows.len()
    }

    pub fn is_empty(&self) -> bool {
        self.rows.is_empty()
    }
}

/// Materialize one step's bag by scanning every relation in the
/// graph and keeping the ones that satisfy the step. Returns a `Bag`
/// of `(origin, dest, ts)` rows whose timestamps fall in
/// `[t_lo, t_hi]`.
///
/// O(|E|) per step; identical work to what the DFS does inline,
/// just batched up-front so the semi-join reducer can prune dead
/// rows before enumeration runs.
pub fn materialize_bag(
    graph: &GraphHunter,
    step: &HypothesisStep,
    t_lo: i64,
    t_hi: i64,
) -> Bag {
    let mut rows = Vec::new();
    graph.streaming.for_each_edge(|src_sid, edge| {
        if edge.timestamp < t_lo || edge.timestamp > t_hi {
            return;
        }
        if !rel_tag_matches(&step.relation_type, edge.rel_type_tag) {
            return;
        }
        if !graph.fast_type_matches(&step.origin_type, src_sid) {
            return;
        }
        if !graph.fast_type_matches(&step.dest_type, edge.dest_sid) {
            return;
        }
        if !step.edge_predicates.is_empty() {
            let metadata = if edge.metadata_offset != 0 {
                graph.meta_store.get(edge.metadata_offset)
            } else {
                std::collections::HashMap::new()
            };
            if !graph_hunter_dsl::hypothesis::all_predicates_match(
                &step.edge_predicates,
                &metadata,
            ) {
                return;
            }
        }
        if !step.dest_predicates.is_empty() {
            let entity = match graph.entities.get(&edge.dest_sid) {
                Some(e) => e,
                None => return,
            };
            if !graph_hunter_dsl::hypothesis::all_predicates_match(
                &step.dest_predicates,
                &entity.metadata,
            ) {
                return;
            }
        }
        rows.push(BagRow {
            origin: src_sid,
            dest: edge.dest_sid,
            timestamp: edge.timestamp,
        });
    });
    Bag { rows }
}

/// Two-pass semi-join reducer for a chain of bags. Mutates each bag
/// in place, dropping rows that cannot extend to a full match.
///
/// Pass 1 (bottom-up): for `i = n-2 .. 0`, drop rows in `bag[i]`
/// whose `dest` does not appear as `origin` in `bag[i+1]`.
///
/// Pass 2 (top-down): for `i = 1 .. n-1`, drop rows in `bag[i]`
/// whose `origin` does not appear as `dest` in `bag[i-1]`.
///
/// After both passes every surviving row participates in at least
/// one structural full join. Temporal strictness (`t_i < t_{i+1}`)
/// is *not* enforced here — that's a per-row constraint applied
/// during enumeration. Conservative: we keep rows that the temporal
/// filter might still drop, but never drop rows that could survive.
pub fn semijoin_reduce_chain(bags: &mut [Bag]) {
    let n = bags.len();
    if n <= 1 {
        return;
    }
    use std::collections::HashSet;

    // Bottom-up pass: each bag[i] keeps only rows whose dest is
    // some origin in bag[i+1].
    for i in (0..n - 1).rev() {
        let live_origins: HashSet<StrId> =
            bags[i + 1].rows.iter().map(|r| r.origin).collect();
        bags[i].rows.retain(|r| live_origins.contains(&r.dest));
    }

    // Top-down pass: each bag[i] keeps only rows whose origin is
    // some dest in bag[i-1].
    for i in 1..n {
        let live_dests: HashSet<StrId> = bags[i - 1].rows.iter().map(|r| r.dest).collect();
        bags[i].rows.retain(|r| live_dests.contains(&r.origin));
    }
}

/// Enumerate every full path through the (already-reduced) chain
/// of bags, respecting strict temporal ordering and `k_simplicity`.
/// Returns up to `cap` paths as resolved `HuntResult` (one
/// `Arc<str>` per visited vertex, length = `n_steps + 1`).
///
/// Algorithm: for each row in `bag[0]`, walk the chain looking for
/// `bag[i+1]` rows where `origin == prev.dest` and `timestamp >
/// prev.timestamp`. Standard depth-first chain enumeration; the
/// reducer's pruning means we never expand a row that has no live
/// continuation.
pub fn enumerate_chain(
    graph: &GraphHunter,
    bags: &[Bag],
    cap: usize,
    k_simplicity: usize,
) -> Vec<HuntResult> {
    enumerate_chain_from_prefix(graph, bags, &[], 0, cap, k_simplicity)
}

/// L2 stage 3b — resumable chain enumerator. Caller can pass a
/// `starting` slice of partial paths (each pair: full
/// `Vec<StrId>` of vertices visited so far + the timestamp of
/// the most recent edge, so the strictly-increasing temporal
/// constraint holds across the resume boundary) and a
/// `start_depth` denoting which step to walk next. When
/// `start_depth == 0` and `starting.is_empty()` the function
/// bootstraps from `bag[0].rows` — equivalent to the legacy
/// `enumerate_chain` entry point.
///
/// The CSH cache in `run_hunt_batch` populates `starting` from a
/// previously-completed hypothesis whose first `start_depth`
/// steps have identical fingerprints, so the prefix work runs
/// once per batch instead of once per hypothesis.
pub fn enumerate_chain_from_prefix(
    graph: &GraphHunter,
    bags: &[Bag],
    starting: &[(Vec<StrId>, i64)],
    start_depth: usize,
    cap: usize,
    k_simplicity: usize,
) -> Vec<HuntResult> {
    if bags.is_empty() || cap == 0 {
        return Vec::new();
    }
    let by_origin: Vec<std::collections::HashMap<StrId, Vec<&BagRow>>> = bags
        .iter()
        .map(|b| {
            let mut m: std::collections::HashMap<StrId, Vec<&BagRow>> =
                std::collections::HashMap::new();
            for row in &b.rows {
                m.entry(row.origin).or_default().push(row);
            }
            m
        })
        .collect();

    let n = bags.len();
    let mut out: Vec<HuntResult> = Vec::new();

    fn k_simplicity_ok(path: &[StrId], candidate: StrId, k: usize) -> bool {
        let mut count = 0usize;
        for &s in path {
            if s == candidate {
                count += 1;
                if count >= k {
                    return false;
                }
            }
        }
        true
    }

    fn recurse(
        graph: &GraphHunter,
        bags: &[Bag],
        by_origin: &[std::collections::HashMap<StrId, Vec<&BagRow>>],
        path_sids: &mut Vec<StrId>,
        last_ts: i64,
        step_idx: usize,
        cap: usize,
        k_simplicity: usize,
        out: &mut Vec<HuntResult>,
    ) {
        if out.len() >= cap {
            return;
        }
        if step_idx == bags.len() {
            // Reached the end of the chain — emit the path.
            let result: HuntResult = path_sids
                .iter()
                .map(|sid| graph.interner.resolve_arc(*sid))
                .collect();
            out.push(result);
            return;
        }
        let last = *path_sids.last().expect("path always has the chain start before recursing");
        let candidates = match by_origin[step_idx].get(&last) {
            Some(v) => v,
            None => return,
        };
        for row in candidates {
            if row.timestamp <= last_ts {
                continue;
            }
            if !k_simplicity_ok(path_sids, row.dest, k_simplicity) {
                continue;
            }
            path_sids.push(row.dest);
            recurse(
                graph,
                bags,
                by_origin,
                path_sids,
                row.timestamp,
                step_idx + 1,
                cap,
                k_simplicity,
                out,
            );
            path_sids.pop();
            if out.len() >= cap {
                return;
            }
        }
    }

    if start_depth == 0 && starting.is_empty() {
        // Bootstrap: iterate root bag's rows.
        let mut path_sids: Vec<StrId> = Vec::with_capacity(n + 1);
        for row in &bags[0].rows {
            if !k_simplicity_ok(&path_sids, row.origin, k_simplicity) {
                continue;
            }
            path_sids.push(row.origin);
            if k_simplicity_ok(&path_sids, row.dest, k_simplicity) {
                path_sids.push(row.dest);
                recurse(
                    graph,
                    bags,
                    &by_origin,
                    &mut path_sids,
                    row.timestamp,
                    1,
                    cap,
                    k_simplicity,
                    &mut out,
                );
                path_sids.pop();
            }
            path_sids.pop();
            if out.len() >= cap {
                break;
            }
        }
        return out;
    }

    // Resume path: each starting entry is a fully-formed prefix
    // (length = start_depth + 1 vertices) plus the timestamp of
    // the most recent edge. Walk the suffix bags from
    // `start_depth` onward.
    let mut path_sids: Vec<StrId> = Vec::with_capacity(n + 1);
    for (prefix_path, prefix_last_ts) in starting {
        path_sids.clear();
        path_sids.extend_from_slice(prefix_path);
        recurse(
            graph,
            bags,
            &by_origin,
            &mut path_sids,
            *prefix_last_ts,
            start_depth,
            cap,
            k_simplicity,
            &mut out,
        );
        if out.len() >= cap {
            break;
        }
    }
    out
}

/// L2 stage 3b — capture partial paths after the first `depth`
/// steps of a chain. Used by the CSH cache in `run_hunt_batch` to
/// store prefix snapshots for reuse across hypotheses sharing the
/// first `depth` steps.
///
/// Returns an empty `Vec` if `depth` is 0 (no work done) or
/// greater than `bags.len()`. The `cap` parameter limits how many
/// partial paths to record — when the count would exceed it, the
/// caller should skip caching this prefix to avoid pathological
/// memory growth on huge graphs.
pub fn compute_prefix_snapshot(
    graph: &GraphHunter,
    bags: &[Bag],
    depth: usize,
    cap: usize,
    k_simplicity: usize,
) -> Vec<(Vec<StrId>, i64)> {
    let _ = graph; // unused — kept in the signature for future consumers
    if depth == 0 || depth > bags.len() || bags.is_empty() {
        return Vec::new();
    }
    let by_origin: Vec<std::collections::HashMap<StrId, Vec<&BagRow>>> = bags
        .iter()
        .take(depth)
        .map(|b| {
            let mut m: std::collections::HashMap<StrId, Vec<&BagRow>> =
                std::collections::HashMap::new();
            for row in &b.rows {
                m.entry(row.origin).or_default().push(row);
            }
            m
        })
        .collect();

    fn k_ok(path: &[StrId], candidate: StrId, k: usize) -> bool {
        let mut count = 0usize;
        for &s in path {
            if s == candidate {
                count += 1;
                if count >= k {
                    return false;
                }
            }
        }
        true
    }

    fn recurse_prefix(
        bags: &[Bag],
        by_origin: &[std::collections::HashMap<StrId, Vec<&BagRow>>],
        path_sids: &mut Vec<StrId>,
        last_ts: i64,
        step_idx: usize,
        target_depth: usize,
        cap: usize,
        k: usize,
        out: &mut Vec<(Vec<StrId>, i64)>,
    ) {
        if out.len() >= cap {
            return;
        }
        if step_idx == target_depth {
            out.push((path_sids.clone(), last_ts));
            return;
        }
        let last = *path_sids.last().unwrap();
        let candidates = match by_origin[step_idx].get(&last) {
            Some(v) => v,
            None => return,
        };
        for row in candidates {
            if row.timestamp <= last_ts {
                continue;
            }
            if !k_ok(path_sids, row.dest, k) {
                continue;
            }
            path_sids.push(row.dest);
            recurse_prefix(
                bags,
                by_origin,
                path_sids,
                row.timestamp,
                step_idx + 1,
                target_depth,
                cap,
                k,
                out,
            );
            path_sids.pop();
            if out.len() >= cap {
                return;
            }
        }
    }

    let mut out: Vec<(Vec<StrId>, i64)> = Vec::new();
    let mut path_sids: Vec<StrId> = Vec::with_capacity(depth + 1);
    let _ = bags;
    let bags_ref: &[Bag] = bags;
    for row in &bags[0].rows {
        if !k_ok(&path_sids, row.origin, k_simplicity) {
            continue;
        }
        path_sids.push(row.origin);
        if k_ok(&path_sids, row.dest, k_simplicity) {
            path_sids.push(row.dest);
            recurse_prefix(
                bags_ref,
                &by_origin,
                &mut path_sids,
                row.timestamp,
                1,
                depth,
                cap,
                k_simplicity,
                &mut out,
            );
            path_sids.pop();
        }
        path_sids.pop();
        if out.len() >= cap {
            break;
        }
    }
    out
}

/// L1 stage 3 part B — tree-walk enumerator. Generalizes
/// `enumerate_chain` to walk an arbitrary `JoinTree` instead of
/// a positional chain.
///
/// Algorithm: maintain a `binding: Vec<Option<StrId>>` indexed by
/// `VarId`. Visit join-tree nodes in their stored order
/// (root-first by `JoinTree::build` convention). For each node,
/// look up rows in the corresponding bag whose origin/dest match
/// whatever the binding already has for the shared variable; the
/// other side becomes the new binding. When all nodes are
/// visited, emit a `HuntResult` with one resolved `Arc<str>` per
/// VarId in ascending order.
///
/// Non-chain hypotheses don't have a canonical temporal spine, so
/// this enumerator does *not* enforce strictly-increasing
/// timestamps across the join-tree edges. Per-bag temporal
/// windowing (the `time_window` passed at materialize time) still
/// applies. If a future shape needs cross-edge temporal
/// constraints, they belong on `Predicate` / `WITHIN` clauses,
/// not in the enumerator.
fn enumerate_tree(
    graph: &GraphHunter,
    hypergraph: &Hypergraph,
    join_tree: &JoinTree,
    bags: &[Bag],
    cap: usize,
    k_simplicity: usize,
) -> Vec<HuntResult> {
    if join_tree.nodes.is_empty() || cap == 0 {
        return Vec::new();
    }
    let n_vars = hypergraph.n_vars;
    let n_nodes = join_tree.nodes.len();

    // Per-bag indexes, both directions. Joining can come from
    // either side: a child bag whose origin-var is shared with
    // the parent looks up by origin; a child whose dest-var is
    // shared looks up by dest. Building both indexes upfront
    // keeps the recursion branchless beyond a single match.
    let by_origin: Vec<std::collections::HashMap<StrId, Vec<&BagRow>>> = bags
        .iter()
        .map(|b| {
            let mut m: std::collections::HashMap<StrId, Vec<&BagRow>> =
                std::collections::HashMap::new();
            for row in &b.rows {
                m.entry(row.origin).or_default().push(row);
            }
            m
        })
        .collect();
    let by_dest: Vec<std::collections::HashMap<StrId, Vec<&BagRow>>> = bags
        .iter()
        .map(|b| {
            let mut m: std::collections::HashMap<StrId, Vec<&BagRow>> =
                std::collections::HashMap::new();
            for row in &b.rows {
                m.entry(row.dest).or_default().push(row);
            }
            m
        })
        .collect();

    let mut binding: Vec<Option<StrId>> = vec![None; n_vars];
    let mut out: Vec<HuntResult> = Vec::new();

    fn k_ok(binding: &[Option<StrId>], candidate: StrId, k: usize) -> bool {
        let mut count = 0usize;
        for slot in binding {
            if let Some(s) = slot {
                if *s == candidate {
                    count += 1;
                    if count >= k {
                        return false;
                    }
                }
            }
        }
        true
    }

    fn try_bind(
        binding: &mut [Option<StrId>],
        var: VarId,
        value: StrId,
        k: usize,
    ) -> bool {
        // Existing-binding check first. A separate scope releases
        // the &mut before we run the k_ok &-borrow.
        if let Some(existing) = binding[var.0 as usize] {
            return existing == value;
        }
        if !k_ok(binding, value, k) {
            return false;
        }
        binding[var.0 as usize] = Some(value);
        true
    }

    fn unbind(binding: &mut [Option<StrId>], var: VarId, was_bound: bool) {
        if !was_bound {
            binding[var.0 as usize] = None;
        }
    }

    fn recurse(
        graph: &GraphHunter,
        hypergraph: &Hypergraph,
        join_tree: &JoinTree,
        bags: &[Bag],
        by_origin: &[std::collections::HashMap<StrId, Vec<&BagRow>>],
        by_dest: &[std::collections::HashMap<StrId, Vec<&BagRow>>],
        binding: &mut Vec<Option<StrId>>,
        node_idx: usize,
        cap: usize,
        k_simplicity: usize,
        out: &mut Vec<HuntResult>,
    ) {
        if out.len() >= cap {
            return;
        }
        if node_idx == join_tree.nodes.len() {
            // All vars must be bound at this point — emit.
            let result: HuntResult = binding
                .iter()
                .map(|sid| {
                    let s = sid.expect("all vars bound when tree is fully walked");
                    graph.interner.resolve_arc(s)
                })
                .collect();
            out.push(result);
            return;
        }

        let step = join_tree.nodes[node_idx];
        let edge = &hypergraph.edges[step];
        let origin_bound = binding[edge.origin.0 as usize];
        let dest_bound = binding[edge.dest.0 as usize];

        // Collect compatible rows in a small Vec so the recursive
        // call can mutate `binding` freely. The bag is already
        // pruned by the matcher's predicates and time window;
        // rows-per-bag is bounded by graph size and typically tiny.
        let mut candidates: Vec<&BagRow> = Vec::new();
        match (origin_bound, dest_bound) {
            (Some(o), _) => {
                if let Some(rows) = by_origin[step].get(&o) {
                    candidates.extend(rows.iter().copied());
                }
            }
            (None, Some(d)) => {
                if let Some(rows) = by_dest[step].get(&d) {
                    candidates.extend(rows.iter().copied());
                }
            }
            (None, None) => {
                candidates.extend(bags[step].rows.iter());
            }
        }

        for row in candidates {
            // Filter by dest when both sides are pre-bound.
            if let Some(d) = dest_bound {
                if row.dest != d {
                    continue;
                }
            }
            let origin_was = binding[edge.origin.0 as usize].is_some();
            let dest_was = binding[edge.dest.0 as usize].is_some();
            if !try_bind(binding, edge.origin, row.origin, k_simplicity) {
                continue;
            }
            if !try_bind(binding, edge.dest, row.dest, k_simplicity) {
                unbind(binding, edge.origin, origin_was);
                continue;
            }
            recurse(
                graph,
                hypergraph,
                join_tree,
                bags,
                by_origin,
                by_dest,
                binding,
                node_idx + 1,
                cap,
                k_simplicity,
                out,
            );
            unbind(binding, edge.dest, dest_was);
            unbind(binding, edge.origin, origin_was);
            if out.len() >= cap {
                return;
            }
        }
    }

    let _ = n_nodes;
    let _ = n_vars;
    recurse(
        graph,
        hypergraph,
        join_tree,
        bags,
        &by_origin,
        &by_dest,
        &mut binding,
        0,
        cap,
        k_simplicity,
        &mut out,
    );
    out
}

/// End-to-end Yannakakis-style matcher. Materializes every step's
/// bag, runs the two-pass semi-join reducer over the join tree,
/// and enumerates up to `cap` paths.
///
/// Branches by `Hypothesis::shape`:
///   * `Chain` (legacy): chain reducer + chain enumerator.
///   * `Graph`: tree-walk reducer + tree-walk enumerator
///     (L1 stage 3 part B).
///
/// Cyclic hypotheses (any shape) return an empty result with
/// `truncated = false`. The planner is the gate on α-acyclicity.
pub fn search_temporal_pattern_yannakakis(
    graph: &GraphHunter,
    hypothesis: &Hypothesis,
    time_window: Option<(i64, i64)>,
    max_results: Option<usize>,
) -> (Vec<HuntResult>, bool) {
    let cap = max_results.unwrap_or(10_000);
    let n = hypothesis.steps.len();
    if n == 0 || cap == 0 {
        return (Vec::new(), false);
    }
    let (t_lo, t_hi) = time_window.unwrap_or((i64::MIN, i64::MAX));
    let bags: Vec<Bag> = hypothesis
        .steps
        .iter()
        .map(|step| materialize_bag(graph, step, t_lo, t_hi))
        .collect();
    search_temporal_pattern_yannakakis_with_bags(graph, hypothesis, bags, max_results)
}

/// L2 stage 2 — Yannakakis variant that takes pre-materialized
/// `Bag`s. Used by the batch entry point's CSH bucketing layer
/// to share bag materialization across hypotheses with identical
/// step fingerprints.
///
/// `bags.len()` must equal `hypothesis.steps.len()`. Each bag must
/// have been materialized for the hypothesis's `time_window` and
/// for the corresponding step's predicates — passing
/// inconsistent inputs is a logic bug, not a runtime check (the
/// matcher would silently emit wrong results).
pub fn search_temporal_pattern_yannakakis_with_bags(
    graph: &GraphHunter,
    hypothesis: &Hypothesis,
    bags: Vec<Bag>,
    max_results: Option<usize>,
) -> (Vec<HuntResult>, bool) {
    let cap = max_results.unwrap_or(10_000);
    let n = hypothesis.steps.len();
    if n == 0 || cap == 0 {
        return (Vec::new(), false);
    }
    debug_assert_eq!(
        bags.len(),
        n,
        "bag count mismatch: caller must materialize one Bag per hypothesis step"
    );
    let g = Hypergraph::of(hypothesis);
    if !is_alpha_acyclic(&g) {
        return (Vec::new(), false);
    }
    let mut bags = bags;

    let paths = match hypothesis.shape {
        graph_hunter_dsl::hypothesis::HypothesisShape::Chain => {
            semijoin_reduce_chain(&mut bags);
            enumerate_chain(graph, &bags, cap, hypothesis.k_simplicity.max(1))
        }
        graph_hunter_dsl::hypothesis::HypothesisShape::Graph => {
            // Stage 3 part B: tree-walk enumerator. We don't run
            // the chain semi-join reducer here because it assumes
            // the bag-i+1.origin == bag-i.dest invariant; the
            // tree's join keys can come from either side. The
            // enumerator filters on demand via the shared-var
            // bindings, which is equivalent to a per-walk
            // semi-join.
            let tree = match JoinTree::build(&g) {
                Some(t) => t,
                None => return (Vec::new(), false),
            };
            enumerate_tree(
                graph,
                &g,
                &tree,
                &bags,
                cap,
                hypothesis.k_simplicity.max(1),
            )
        }
    };
    let truncated = paths.len() >= cap;
    (paths, truncated)
}

#[cfg(test)]
mod tests {
    use super::*;
    use graph_hunter_dsl::hypothesis::{Hypothesis, HypothesisStep};
    use graph_hunter_dsl::types::{EntityType, RelationType};

    fn h_chain(n: usize) -> Hypothesis {
        let steps: Vec<_> = (0..n)
            .map(|_| HypothesisStep::new(EntityType::User, RelationType::Auth, EntityType::User))
            .collect();
        Hypothesis {
            steps,
            ..Hypothesis::new("test")
        }
    }

    #[test]
    fn empty_hypothesis_is_trivially_acyclic() {
        let h = Hypothesis::new("empty");
        let g = Hypergraph::of(&h);
        assert_eq!(g.n_vars, 0);
        assert!(g.edges.is_empty());
        assert!(is_alpha_acyclic(&g));
    }

    #[test]
    fn one_step_chain() {
        let h = h_chain(1);
        let g = Hypergraph::of(&h);
        assert_eq!(g.n_vars, 2);
        assert_eq!(g.edges.len(), 1);
        assert!(is_alpha_acyclic(&g));
        let tree = JoinTree::build(&g).unwrap();
        assert_eq!(tree.nodes, vec![0]);
        assert_eq!(tree.parent, vec![0]);
    }

    #[test]
    fn linear_chain_is_acyclic_and_yields_path_tree() {
        // 3-step chain v0 -- v1 -- v2 -- v3
        let h = h_chain(3);
        let g = Hypergraph::of(&h);
        assert_eq!(g.n_vars, 4, "chain of 3 edges has 4 distinct vertices");
        assert_eq!(g.edges.len(), 3);
        assert!(is_alpha_acyclic(&g));
        let tree = JoinTree::build(&g).unwrap();
        assert_eq!(tree.nodes.len(), 3);
        // Each non-root node points at a parent earlier in the list.
        for (i, &p) in tree.parent.iter().enumerate() {
            if i == 0 {
                assert_eq!(p, 0, "root parent points to itself");
            } else {
                assert!(p < i, "parent index must precede child");
            }
        }
    }

    #[test]
    fn triangle_via_shared_bindings_is_cyclic() {
        // 3 steps with bindings forming a triangle:
        //   step 0: A(a) -> B(b)      origin=a, dest=b
        //   step 1: B(b) -> C(c)      origin=b, dest=c   (b shared)
        //   step 2: C(c) -> A(a)      origin=c, dest=a   (a, c shared)
        // Variables collapse to {a, b, c}; edges {(a,b), (b,c), (c,a)}.
        let mut step0 = HypothesisStep::new(
            EntityType::User,
            RelationType::Auth,
            EntityType::User,
        );
        step0.origin_binding = Some("a".into());
        step0.dest_binding = Some("b".into());
        let mut step1 = HypothesisStep::new(
            EntityType::User,
            RelationType::Auth,
            EntityType::User,
        );
        step1.origin_binding = Some("b".into());
        step1.dest_binding = Some("c".into());
        let mut step2 = HypothesisStep::new(
            EntityType::User,
            RelationType::Auth,
            EntityType::User,
        );
        step2.origin_binding = Some("c".into());
        step2.dest_binding = Some("a".into());
        let h = Hypothesis {
            steps: vec![step0, step1, step2],
            ..Hypothesis::new("test")
        };
        let g = Hypergraph::of(&h);
        assert_eq!(g.n_vars, 3, "triangle should collapse to 3 vars via bindings");
        assert_eq!(g.edges.len(), 3);
        assert!(!is_alpha_acyclic(&g), "K_3 is the canonical cyclic example");
        assert!(JoinTree::build(&g).is_none());
    }

    #[test]
    fn star_in_graph_shape_yields_three_edges_around_center() {
        // L1 stage 3: a 3-leaf star. Three steps, each with the same
        // origin_binding "c" but distinct dest bindings. With
        // HypothesisShape::Graph the auto-chain default is dropped,
        // so the three (c, leaf_i) pairs become three independent
        // hyperedges sharing the variable `c`.
        let mut step0 = HypothesisStep::new(
            EntityType::User,
            RelationType::Auth,
            EntityType::User,
        );
        step0.origin_binding = Some("c".into());
        step0.dest_binding = Some("l0".into());
        let mut step1 = HypothesisStep::new(
            EntityType::User,
            RelationType::Auth,
            EntityType::User,
        );
        step1.origin_binding = Some("c".into());
        step1.dest_binding = Some("l1".into());
        let mut step2 = HypothesisStep::new(
            EntityType::User,
            RelationType::Auth,
            EntityType::User,
        );
        step2.origin_binding = Some("c".into());
        step2.dest_binding = Some("l2".into());
        let h = Hypothesis {
            steps: vec![step0, step1, step2],
            shape: graph_hunter_dsl::hypothesis::HypothesisShape::Graph,
            ..Hypothesis::new("star")
        };
        let g = Hypergraph::of(&h);
        // Center + three distinct leaves = 4 vars.
        assert_eq!(g.n_vars, 4);
        assert_eq!(g.edges.len(), 3);
        // Every edge shares the same origin (the center "c").
        let center = g.edges[0].origin;
        for e in &g.edges {
            assert_eq!(e.origin, center, "all star edges share center vertex");
        }
        // The three dest variables are pairwise distinct (l0, l1, l2).
        let dests: std::collections::BTreeSet<VarId> =
            g.edges.iter().map(|e| e.dest).collect();
        assert_eq!(dests.len(), 3);
        // Star is α-acyclic and produces a 3-edge join tree.
        assert!(is_alpha_acyclic(&g));
        let tree = JoinTree::build(&g).unwrap();
        assert_eq!(tree.nodes.len(), 3);
    }

    #[test]
    fn graph_shape_without_bindings_keeps_steps_independent() {
        // Three steps with no bindings under Graph shape: every
        // (step, side) is its own variable, so the 3 edges are
        // structurally independent — no shared vertices, the
        // hypergraph is disconnected. GYO eliminates each edge as
        // a degenerate ear (both endpoints have degree 1) so the
        // result is still α-acyclic.
        let h = Hypothesis {
            steps: (0..3)
                .map(|_| HypothesisStep::new(EntityType::User, RelationType::Auth, EntityType::User))
                .collect(),
            shape: graph_hunter_dsl::hypothesis::HypothesisShape::Graph,
            ..Hypothesis::new("disconnected")
        };
        let g = Hypergraph::of(&h);
        // 3 steps × 2 distinct vars per step = 6 unique variables.
        assert_eq!(g.n_vars, 6);
        assert_eq!(g.edges.len(), 3);
        assert!(is_alpha_acyclic(&g));
    }

    #[test]
    fn endpoint_binding_collapses_into_self_loop() {
        // Step 0: A(a) -> B(b)
        // Step 1: B(b) -> A(a)   ← dest_binding "a" merges pos 2 with pos 0.
        // The hypergraph collapses to two variables {a, b} with two
        // edges {(a,b), (b,a)} — degree-2 on both ends, so the GYO
        // step finds no ear and the result is correctly cyclic.
        let mut step0 = HypothesisStep::new(
            EntityType::User,
            RelationType::Auth,
            EntityType::User,
        );
        step0.origin_binding = Some("a".into());
        step0.dest_binding = Some("b".into());
        let mut step1 = HypothesisStep::new(
            EntityType::User,
            RelationType::Auth,
            EntityType::User,
        );
        step1.origin_binding = Some("b".into());
        step1.dest_binding = Some("a".into());
        let h = Hypothesis {
            steps: vec![step0, step1],
            ..Hypothesis::new("test")
        };
        let g = Hypergraph::of(&h);
        assert_eq!(g.n_vars, 2);
        assert!(!is_alpha_acyclic(&g));
        assert!(JoinTree::build(&g).is_none());
    }

    #[test]
    fn one_step_chain_is_free_connex_for_full_head() {
        let h = h_chain(1);
        let g = Hypergraph::of(&h);
        let head: Vec<VarId> = (0..g.n_vars as u32).map(VarId).collect();
        assert!(
            is_free_connex(&g, &head),
            "single hyperedge covers both vars, so full-head free-connex holds"
        );
    }

    #[test]
    fn long_chain_is_not_free_connex_for_full_head() {
        let h = h_chain(3);
        let g = Hypergraph::of(&h);
        let head: Vec<VarId> = (0..g.n_vars as u32).map(VarId).collect();
        assert!(
            !is_free_connex(&g, &head),
            "no single binary hyperedge covers four head vars"
        );
    }

    #[test]
    fn empty_head_is_free_connex_for_any_acyclic() {
        let h = h_chain(3);
        let g = Hypergraph::of(&h);
        assert!(is_free_connex(&g, &[]));
    }

    fn small_chain_graph() -> GraphHunter {
        // u1 → u2 → u3 → u4 with timestamps 100, 110, 120 (strictly
        // increasing) plus a decoy edge u1 → u5 that has no
        // continuation past u5. The Yannakakis reducer should drop
        // the decoy at the bottom-up pass.
        use crate::entity::Entity;
        use crate::relation::Relation;
        let mut g = GraphHunter::new();
        for n in ["u1", "u2", "u3", "u4", "u5"] {
            g.add_entity(Entity::new(n, EntityType::User)).unwrap();
        }
        for (s, d, t) in [
            ("u1", "u2", 100i64),
            ("u2", "u3", 110),
            ("u3", "u4", 120),
            ("u1", "u5", 100),
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
                .map(|_| {
                    HypothesisStep::new(EntityType::User, RelationType::Auth, EntityType::User)
                })
                .collect(),
            ..Hypothesis::new("yannakakis-test")
        }
    }

    #[test]
    fn yannakakis_chain_finds_3hop_path() {
        let g = small_chain_graph();
        let h = user_auth_chain(3);
        let (paths, truncated) =
            search_temporal_pattern_yannakakis(&g, &h, None, Some(10));
        assert!(!truncated);
        assert_eq!(paths.len(), 1, "exactly one 3-hop chain in the fixture");
        let p = &paths[0];
        assert_eq!(p.len(), 4);
        assert_eq!(&*p[0], "u1");
        assert_eq!(&*p[1], "u2");
        assert_eq!(&*p[2], "u3");
        assert_eq!(&*p[3], "u4");
    }

    #[test]
    fn yannakakis_chain_matches_dfs_on_chain_hypothesis() {
        // Parity test: every path the Yannakakis runner emits must
        // also appear in the DFS-based result, and vice versa.
        let g = small_chain_graph();
        let h = user_auth_chain(3);
        let (yanni, _) = search_temporal_pattern_yannakakis(&g, &h, None, Some(10_000));
        let (dfs, _) = g
            .search_temporal_pattern(&h, None, Some(10_000))
            .expect("DFS should succeed");
        let yanni_set: std::collections::HashSet<Vec<String>> = yanni
            .into_iter()
            .map(|p| p.iter().map(|s| s.to_string()).collect())
            .collect();
        let dfs_set: std::collections::HashSet<Vec<String>> = dfs
            .into_iter()
            .map(|p| p.iter().map(|s| s.to_string()).collect())
            .collect();
        assert_eq!(yanni_set, dfs_set, "Yannakakis and DFS must enumerate the same path set");
    }

    #[test]
    fn yannakakis_tree_walk_matches_star_hypothesis() {
        // L1 stage 3 part B end-to-end. Graph-shape star with one
        // center and three leaves; the tree-walk enumerator should
        // emit exactly one binding [center, l0, l1, l2] when the
        // graph contains the right three edges.
        use crate::entity::Entity;
        use crate::relation::Relation;
        let mut g = GraphHunter::new();
        for n in ["c", "a", "b", "d", "extra"] {
            g.add_entity(Entity::new(n, EntityType::User)).unwrap();
        }
        // Three star edges from c.
        for (s, dst, t) in [("c", "a", 100i64), ("c", "b", 110), ("c", "d", 120)] {
            g.add_relation(Relation::new(s, dst, RelationType::Auth, t))
                .unwrap();
        }
        // Decoy: extra → a (different origin, shouldn't match).
        g.add_relation(Relation::new("extra", "a", RelationType::Auth, 130))
            .unwrap();
        g.sort_edges_by_timestamp().unwrap();

        let mut step0 = HypothesisStep::new(
            EntityType::User,
            RelationType::Auth,
            EntityType::User,
        );
        step0.origin_binding = Some("c".into());
        step0.dest_binding = Some("l0".into());
        let mut step1 = HypothesisStep::new(
            EntityType::User,
            RelationType::Auth,
            EntityType::User,
        );
        step1.origin_binding = Some("c".into());
        step1.dest_binding = Some("l1".into());
        let mut step2 = HypothesisStep::new(
            EntityType::User,
            RelationType::Auth,
            EntityType::User,
        );
        step2.origin_binding = Some("c".into());
        step2.dest_binding = Some("l2".into());
        // Default k_simplicity = 1 forces all bound vertices to be
        // distinct, which is the correct semantics for a star
        // pattern: the three leaves should map to distinct
        // entities, and the decoy edge `extra → a` cannot match
        // (it would require another binding with `a` already
        // taken by the leaf bag, or `extra` instead of `c` as
        // center, which the enumerator catches via the shared
        // `c` variable across the three star edges).
        let h = Hypothesis {
            steps: vec![step0, step1, step2],
            shape: graph_hunter_dsl::hypothesis::HypothesisShape::Graph,
            ..Hypothesis::new("star")
        };

        let (paths, truncated) =
            search_temporal_pattern_yannakakis(&g, &h, None, Some(100));
        assert!(!truncated);
        // The star has one unordered match {c, a, b, d}; the
        // enumerator's bindings can pair (l0, l1, l2) with any
        // permutation of (a, b, d), so we expect 3! = 6 results
        // — one per assignment.
        assert_eq!(paths.len(), 6, "3 leaves × 3! permutations of l0/l1/l2");
        // Every emitted result has 4 distinct vertices, one of
        // which is the center "c".
        for p in &paths {
            assert_eq!(p.len(), 4);
            let unique: std::collections::HashSet<&str> =
                p.iter().map(|s| &**s).collect();
            assert_eq!(unique.len(), 4);
            assert!(unique.contains("c"));
            assert!(!unique.contains("extra"), "decoy must not appear");
        }
    }

    #[test]
    fn yannakakis_drops_decoy_via_semijoin() {
        // 2-hop hypothesis on the same fixture. The chain has two
        // valid 2-hops: u1→u2→u3 and u2→u3→u4. The u1→u5 decoy has
        // no continuation, so the bottom-up semi-join pass drops
        // it from bag[0] before enumeration even starts.
        let g = small_chain_graph();
        let h = user_auth_chain(2);
        let (paths, _) = search_temporal_pattern_yannakakis(&g, &h, None, Some(10));
        assert_eq!(paths.len(), 2);
        let starts: std::collections::HashSet<&str> =
            paths.iter().map(|p| &*p[0]).collect();
        // Crucially, u1 → u5 (the decoy) cannot start a 2-hop, so
        // u5 never appears in any emitted path.
        for p in &paths {
            assert!(p.iter().all(|s| &**s != "u5"));
        }
        assert!(starts.contains("u1"));
        assert!(starts.contains("u2"));
    }

    #[test]
    fn empty_head_on_cyclic_is_not_free_connex() {
        // free-connex requires α-acyclic AND head coverage.
        // Empty head trivially covered, but the alpha-acyclic
        // gate must still fail on cycles.
        let mut step0 = HypothesisStep::new(
            EntityType::User,
            RelationType::Auth,
            EntityType::User,
        );
        step0.origin_binding = Some("a".into());
        step0.dest_binding = Some("b".into());
        let mut step1 = HypothesisStep::new(
            EntityType::User,
            RelationType::Auth,
            EntityType::User,
        );
        step1.origin_binding = Some("b".into());
        step1.dest_binding = Some("a".into());
        let h = Hypothesis {
            steps: vec![step0, step1],
            ..Hypothesis::new("test")
        };
        let g = Hypergraph::of(&h);
        assert!(!is_alpha_acyclic(&g));
        assert!(!is_free_connex(&g, &[]));
    }
}
