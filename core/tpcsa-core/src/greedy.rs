//! Greedy time-respecting prize-collecting Steiner arborescence
//! (Takahashi–Matsuyama on the time-expanded DAG; Algorithm 1 of the paper).
//!
//! Grow a tree from a root by repeatedly attaching the terminal whose
//! cheapest time-respecting path from the current tree costs less than
//! its prize; real arcs into nodes already in the tree are blocked so the
//! result is an arborescence in the original graph. Two details decide
//! quality and are kept on purpose:
//!
//! 1. terminals are never entry points (otherwise each terminal's
//!    cheapest "path" is to be its own root);
//! 2. the root is not chosen greedily from one Dijkstra — every
//!    terminal's cheapest origin is its closest ancestor, not the true
//!    entry point — but by re-running the greedy from the top-`top_roots`
//!    candidates by aggregate gain and keeping the best objective.
//!
//! For `k > 1` the procedure repeats with collected prizes removed and the
//! nodes of earlier trees blocked, so the trees are node-disjoint.

use std::cmp::Reverse;
use std::collections::BinaryHeap;

use crate::expand::TeGraph;
use crate::graph::{Compiled, NONE, OrdF64};
use crate::instance::Time;

#[derive(Clone, Debug)]
pub struct GreedyOptions {
    /// Maximum number of trees (entry points).
    pub k: usize,
    /// Optional cap on real arcs per tree.
    pub budget: Option<usize>,
    /// How many root candidates (by aggregate gain) get a full greedy run.
    pub top_roots: usize,
}

impl Default for GreedyOptions {
    fn default() -> Self {
        Self {
            k: 2,
            budget: None,
            top_roots: 8,
        }
    }
}

/// A tree in index space (over the compiled instance it was built on).
#[derive(Clone, Debug)]
pub(crate) struct RawTree {
    pub root: u32,
    /// Real arcs (indices into `Compiled::arcs`) in attachment order.
    pub arcs: Vec<u32>,
    /// Original nodes in the tree, root first.
    pub nodes: Vec<u32>,
    /// Terminals whose prize was collected.
    pub collected: Vec<u32>,
    pub arc_cost: f64,
    pub root_cost: f64,
    pub prize: f64,
    pub entry_time: Time,
}

impl RawTree {
    /// `Σ c_a + ρ_r − Σ collected p_v` — negative means the tree beats
    /// leaving those terminals uncollected.
    pub fn net(&self) -> f64 {
        self.arc_cost + self.root_cost - self.prize
    }
}

/// Multi-source Dijkstra over the expanded DAG. Real arcs whose head
/// (original node) is `blocked` are skipped; wait arcs always pass.
/// `dist`/`pred` are overwritten (pred = index of the incoming TE arc).
///
/// `bound` stops the search once every remaining label exceeds it: a
/// terminal further than its prize can never be attached, so with `bound`
/// = the largest live prize the result is identical and the explored
/// region shrinks from the whole DAG to a radius of a few arcs.
fn dijkstra(
    te: &TeGraph,
    sources: &[u32],
    blocked: &[bool],
    bound: f64,
    dist: &mut [f64],
    pred: &mut [u32],
) {
    dist.fill(f64::INFINITY);
    pred.fill(NONE);
    let mut heap: BinaryHeap<Reverse<(OrdF64, u32)>> = BinaryHeap::new();
    for &s in sources {
        dist[s as usize] = 0.0;
        heap.push(Reverse((OrdF64(0.0), s)));
    }
    while let Some(Reverse((OrdF64(d), c))) = heap.pop() {
        if d > dist[c as usize] {
            continue;
        }
        if d >= bound {
            break;
        }
        for &ai in te.out(c) {
            let a = &te.arcs[ai as usize];
            if a.real != NONE && blocked[te.copies[a.to as usize].node as usize] {
                continue;
            }
            let nd = d + a.cost;
            if nd < dist[a.to as usize] {
                dist[a.to as usize] = nd;
                pred[a.to as usize] = ai;
                heap.push(Reverse((OrdF64(nd), a.to)));
            }
        }
    }
}

/// Backward Dijkstra: `dist[c]` = cheapest cost from copy `c` to any source.
/// Real arcs into `blocked` nodes are skipped, mirroring [`dijkstra`].
fn dijkstra_reverse(te: &TeGraph, sources: &[u32], blocked: &[bool], bound: f64, dist: &mut [f64]) {
    dist.fill(f64::INFINITY);
    let mut heap: BinaryHeap<Reverse<(OrdF64, u32)>> = BinaryHeap::new();
    for &s in sources {
        dist[s as usize] = 0.0;
        heap.push(Reverse((OrdF64(0.0), s)));
    }
    while let Some(Reverse((OrdF64(d), c))) = heap.pop() {
        if d > dist[c as usize] {
            continue;
        }
        if d >= bound {
            break;
        }
        for &ai in te.inn(c) {
            let a = &te.arcs[ai as usize];
            if a.real != NONE && blocked[te.copies[a.to as usize].node as usize] {
                continue;
            }
            let nd = d + a.cost;
            if nd < dist[a.from as usize] {
                dist[a.from as usize] = nd;
                heap.push(Reverse((OrdF64(nd), a.from)));
            }
        }
    }
}

/// Cheapest reachable copy of `node` under `dist`.
fn best_copy(te: &TeGraph, node: u32, dist: &[f64]) -> Option<(u32, f64)> {
    te.node_copies[node as usize]
        .iter()
        .filter_map(|&c| {
            let d = dist[c as usize];
            d.is_finite().then_some((c, d))
        })
        .min_by(|a, b| a.1.total_cmp(&b.1).then(a.0.cmp(&b.0)))
}

struct Grower<'a> {
    g: &'a Compiled,
    te: &'a TeGraph,
    /// Nodes that no path may enter: earlier trees + this tree.
    blocked: Vec<bool>,
    /// Terminals already collected by earlier trees (their prize is gone).
    spent: &'a [bool],
    dist: Vec<f64>,
    pred: Vec<u32>,
}

impl<'a> Grower<'a> {
    fn new(g: &'a Compiled, te: &'a TeGraph, prev_blocked: &[bool], spent: &'a [bool]) -> Self {
        Self {
            g,
            te,
            blocked: prev_blocked.to_vec(),
            spent,
            dist: vec![f64::INFINITY; te.len_copies()],
            pred: vec![NONE; te.len_copies()],
        }
    }

    fn live_prize(&self, v: u32) -> f64 {
        if self.spent[v as usize] {
            0.0
        } else {
            self.g.prize[v as usize]
        }
    }

    /// Aggregate gain `Σ_t max(0, p_t − d_r(t))` for every eligible root
    /// `r`, computed with one *backward* Dijkstra per live terminal on the
    /// reversed DAG (|T| runs) instead of one forward run per root
    /// candidate (|R| runs, typically an order of magnitude more).
    fn root_scores(&mut self, eligible: &[u32]) -> Vec<(f64, u32)> {
        let te = self.te;
        let mut agg = vec![0.0f64; self.g.n];
        let entry: Vec<Option<u32>> = (0..self.g.n as u32).map(|v| te.entry_copy(v)).collect();
        for t in 0..self.g.n as u32 {
            if self.blocked[t as usize] {
                continue;
            }
            let p = self.live_prize(t);
            if p <= 0.0 {
                continue;
            }
            // Distance from every copy to any copy of `t`, under the same
            // blocking rule as the forward search.
            let sources: Vec<u32> = te.node_copies[t as usize].clone();
            dijkstra_reverse(te, &sources, &self.blocked, p, &mut self.dist);
            for &r in eligible {
                if r == t {
                    continue;
                }
                if let Some(e) = entry[r as usize] {
                    let d = self.dist[e as usize];
                    if d.is_finite() && p - d > 0.0 {
                        agg[r as usize] += p - d;
                    }
                }
            }
        }
        eligible
            .iter()
            .filter(|&&r| agg[r as usize] > 0.0)
            .map(|&r| (agg[r as usize], r))
            .collect()
    }

    /// Walks `pred` back from `copy` to a zero-distance source; returns the
    /// TE arcs from source to `copy` in path order.
    fn trace(&self, mut copy: u32) -> Vec<u32> {
        let mut path = Vec::new();
        while self.pred[copy as usize] != NONE {
            let ai = self.pred[copy as usize];
            path.push(ai);
            copy = self.te.arcs[ai as usize].from;
        }
        path.reverse();
        path
    }

    /// Full greedy from root `r`, with the caller's `blocked` as the
    /// starting exclusion set (this tree's own nodes are added as it grows
    /// and removed again before returning).
    fn grow(&mut self, r: u32, budget: Option<usize>) -> RawTree {
        let g = self.g;
        let te = self.te;
        let mut tree = RawTree {
            root: r,
            arcs: Vec::new(),
            nodes: vec![r],
            collected: Vec::new(),
            arc_cost: 0.0,
            root_cost: g.root_cost[r as usize].unwrap_or(0.0),
            prize: 0.0,
            entry_time: Time::MAX,
        };
        let Some(entry) = te.entry_copy(r) else {
            return tree;
        };
        let mut own: Vec<u32> = vec![r];
        self.blocked[r as usize] = true;
        let mut sources: Vec<u32> = vec![entry];
        let mut in_tree: Vec<bool> = vec![false; g.n];
        in_tree[r as usize] = true;

        loop {
            let bound = (0..g.n as u32)
                .filter(|&v| !self.blocked[v as usize])
                .map(|v| self.live_prize(v))
                .fold(0.0_f64, f64::max);
            if bound <= 0.0 {
                break;
            }
            dijkstra(
                te,
                &sources,
                &self.blocked,
                bound,
                &mut self.dist,
                &mut self.pred,
            );
            // Candidate terminals by gain, descending; index breaks ties.
            let mut cands: Vec<(f64, u32, u32)> = Vec::new();
            for v in 0..g.n as u32 {
                if self.blocked[v as usize] {
                    continue;
                }
                let p = self.live_prize(v);
                if p <= 0.0 {
                    continue;
                }
                if let Some((c, d)) = best_copy(te, v, &self.dist)
                    && p - d > 0.0
                {
                    cands.push((p - d, v, c));
                }
            }
            cands.sort_by(|a, b| b.0.total_cmp(&a.0).then(a.1.cmp(&b.1)));

            let mut attached = false;
            for (_, _, copy) in cands {
                let path = self.trace(copy);
                // Real arcs of the path must enter distinct, new nodes
                // (a time-respecting walk may otherwise revisit a node).
                let mut heads: Vec<u32> = Vec::new();
                let mut ok = true;
                for &ai in &path {
                    let a = &te.arcs[ai as usize];
                    if a.real == NONE {
                        continue;
                    }
                    let h = te.copies[a.to as usize].node;
                    if in_tree[h as usize] || heads.contains(&h) {
                        ok = false;
                        break;
                    }
                    heads.push(h);
                }
                if !ok {
                    continue;
                }
                if let Some(b) = budget
                    && tree.arcs.len() + heads.len() > b
                {
                    continue;
                }
                // Commit.
                for &ai in &path {
                    let a = &te.arcs[ai as usize];
                    sources.push(a.to);
                    if a.real == NONE {
                        continue;
                    }
                    let real = &g.arcs[a.real as usize];
                    tree.arcs.push(a.real);
                    tree.arc_cost += real.cost;
                    let h = real.head;
                    in_tree[h as usize] = true;
                    self.blocked[h as usize] = true;
                    own.push(h);
                    tree.nodes.push(h);
                    let p = self.live_prize(h);
                    if p > 0.0 {
                        tree.collected.push(h);
                        tree.prize += p;
                    }
                    if real.tail == r {
                        tree.entry_time = tree.entry_time.min(real.lo);
                    }
                }
                attached = true;
                break;
            }
            if !attached {
                break;
            }
        }
        for v in own {
            self.blocked[v as usize] = false;
        }
        tree
    }
}

/// Builds up to `opts.k` node-disjoint trees; each is the best of the
/// greedy runs from the top root candidates. Stops early when no tree
/// has positive net gain.
pub(crate) fn greedy_forest(g: &Compiled, te: &TeGraph, opts: &GreedyOptions) -> Vec<RawTree> {
    let mut forest: Vec<RawTree> = Vec::new();
    let mut blocked = vec![false; g.n];
    let mut spent = vec![false; g.n];
    for _ in 0..opts.k.max(1) {
        let mut grower = Grower::new(g, te, &blocked, &spent);
        // Score every eligible root: candidate, not a terminal, not blocked.
        let eligible: Vec<u32> = (0..g.n as u32)
            .filter(|&r| g.is_root_candidate(r) && !g.is_terminal(r) && !blocked[r as usize])
            .collect();
        let mut scored = grower.root_scores(&eligible);
        scored.sort_by(|a, b| b.0.total_cmp(&a.0).then(a.1.cmp(&b.1)));
        scored.truncate(opts.top_roots.max(1));

        let mut best: Option<RawTree> = None;
        for (_, r) in scored {
            let t = grower.grow(r, opts.budget);
            if t.arcs.is_empty() {
                continue;
            }
            let better = match &best {
                None => true,
                Some(b) => t.net() < b.net() || (t.net() == b.net() && t.root < b.root),
            };
            if better {
                best = Some(t);
            }
        }
        let Some(t) = best else { break };
        if t.net() >= 0.0 {
            break;
        }
        for &v in &t.nodes {
            blocked[v as usize] = true;
        }
        for &v in &t.collected {
            spent[v as usize] = true;
        }
        forest.push(t);
    }
    forest
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::instance::{Arc, Instance, Node};

    fn compile(i: &Instance) -> (Compiled, TeGraph) {
        let g = Compiled::from_instance(i).unwrap();
        let te = TeGraph::build(&g);
        (g, te)
    }

    fn base() -> Instance {
        // ip -(recv,10)-> p0 -(start,20)-> p1 -(start,30)-> p2
        //                 p0 -(start,25)-> p3
        let mut i = Instance::new(1);
        i.nodes.push(Node::new("ip", "ip").with_root_cost(2.0));
        i.nodes.push(Node::new("p0", "process").with_root_cost(6.0));
        i.nodes.push(
            Node::new("p1", "process")
                .with_root_cost(6.0)
                .with_prize(8.0),
        );
        i.nodes.push(
            Node::new("p2", "process")
                .with_root_cost(6.0)
                .with_prize(8.0),
        );
        i.nodes.push(
            Node::new("p3", "process")
                .with_root_cost(6.0)
                .with_prize(8.0),
        );
        i.arcs.push(Arc::point("ip", "p0", "recv", 10, 1.0));
        i.arcs.push(Arc::point("p0", "p1", "start", 20, 1.0));
        i.arcs.push(Arc::point("p1", "p2", "start", 30, 1.0));
        i.arcs.push(Arc::point("p0", "p3", "start", 25, 1.0));
        i
    }

    #[test]
    fn picks_the_cheap_external_root_and_collects_everything() {
        let i = base();
        let (g, te) = compile(&i);
        let f = greedy_forest(
            &g,
            &te,
            &GreedyOptions {
                k: 1,
                budget: None,
                top_roots: 8,
            },
        );
        assert_eq!(f.len(), 1);
        let t = &f[0];
        assert_eq!(t.root, 0, "ip (cost 2) beats p0 (cost 6)");
        assert_eq!(t.collected.len(), 3);
        assert_eq!(t.arcs.len(), 4);
        assert_eq!(t.prize, 24.0);
        assert_eq!(t.arc_cost, 4.0);
        assert_eq!(t.root_cost, 2.0);
        assert_eq!(t.entry_time, 10);
    }

    #[test]
    fn terminals_are_never_roots() {
        // Only terminals are root candidates → no tree.
        let mut i = base();
        i.nodes[0].root_cost = None;
        i.nodes[1].root_cost = None;
        let (g, te) = compile(&i);
        let f = greedy_forest(&g, &te, &GreedyOptions::default());
        assert!(f.is_empty());
    }

    #[test]
    fn an_expensive_terminal_is_dropped_not_forced() {
        // p3 reachable only through a 20-cost arc; prize 8 → dropped.
        let mut i = base();
        i.arcs[3].cost = 20.0;
        let (g, te) = compile(&i);
        let f = greedy_forest(
            &g,
            &te,
            &GreedyOptions {
                k: 1,
                ..Default::default()
            },
        );
        let t = &f[0];
        assert!(!t.collected.contains(&4));
        assert_eq!(t.collected.len(), 2);
    }

    #[test]
    fn time_respect_blocks_a_backwards_shortcut() {
        // Add a cheap arc p2 -> p3 at t=5 (before p2 is even reached): must not be used.
        let mut i = base();
        i.arcs[3].cost = 20.0; // make the direct route to p3 expensive
        i.arcs.push(Arc::point("p2", "p3", "start", 5, 0.1));
        let (g, te) = compile(&i);
        let f = greedy_forest(
            &g,
            &te,
            &GreedyOptions {
                k: 1,
                ..Default::default()
            },
        );
        let t = &f[0];
        assert!(
            !t.arcs.contains(&4),
            "arc at t=5 cannot follow arrival at t=30"
        );
    }

    #[test]
    fn second_root_recovers_a_second_implant() {
        // Two disconnected chains; k=1 finds one, k=2 finds both.
        let mut i = base();
        i.nodes.push(Node::new("ip2", "ip").with_root_cost(2.0));
        i.nodes.push(Node::new("q0", "process").with_root_cost(6.0));
        i.nodes.push(
            Node::new("q1", "process")
                .with_root_cost(6.0)
                .with_prize(8.0),
        );
        i.arcs.push(Arc::point("ip2", "q0", "recv", 100, 1.0));
        i.arcs.push(Arc::point("q0", "q1", "start", 110, 1.0));
        let (g, te) = compile(&i);
        let f1 = greedy_forest(
            &g,
            &te,
            &GreedyOptions {
                k: 1,
                ..Default::default()
            },
        );
        assert_eq!(f1.len(), 1);
        let f2 = greedy_forest(
            &g,
            &te,
            &GreedyOptions {
                k: 2,
                ..Default::default()
            },
        );
        assert_eq!(f2.len(), 2);
        let roots: Vec<u32> = f2.iter().map(|t| t.root).collect();
        assert_eq!(roots, vec![0, 5]);
        // Node-disjoint.
        let mut all: Vec<u32> = f2.iter().flat_map(|t| t.nodes.clone()).collect();
        let n = all.len();
        all.sort();
        all.dedup();
        assert_eq!(all.len(), n);
    }

    #[test]
    fn budget_caps_arcs_per_tree() {
        let i = base();
        let (g, te) = compile(&i);
        let f = greedy_forest(
            &g,
            &te,
            &GreedyOptions {
                k: 1,
                budget: Some(2),
                top_roots: 8,
            },
        );
        assert_eq!(f[0].arcs.len(), 2);
    }

    #[test]
    fn in_degree_one_is_enforced_across_paths() {
        // Two routes into p2 (from p1 at 30 and from p3 at 27); only one may be used.
        let mut i = base();
        i.arcs.push(Arc::point("p3", "p2", "start", 27, 0.5));
        let (g, te) = compile(&i);
        let f = greedy_forest(
            &g,
            &te,
            &GreedyOptions {
                k: 1,
                ..Default::default()
            },
        );
        let t = &f[0];
        let into_p2 = t
            .arcs
            .iter()
            .filter(|&&ai| g.arcs[ai as usize].head == 3)
            .count();
        assert_eq!(into_p2, 1);
    }
}
