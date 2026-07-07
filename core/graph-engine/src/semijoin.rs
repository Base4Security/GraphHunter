//! D2-lite — bidirectional semi-join prune for linear chain hypotheses.
//!
//! For a chain Q = `A0 -r1-> A1 -r2-> ... -rn-> An`, we maintain a
//! candidate bitset per chain position and refine it with two passes of
//! semi-join:
//!
//!   * **Forward** (i = 1..=n): retain `v ∈ C_i` only if there exists
//!     `u ∈ C_{i-1}` with an edge `u -r_i-> v` matching the step's
//!     relation/type/predicate constraints.
//!   * **Backward** (i = n-1..=0): retain `u ∈ C_i` only if there exists
//!     `v ∈ C_{i+1}` with an edge `u -r_{i+1}-> v`.
//!
//! Vertices that don't survive both passes can never participate in a
//! match — so the DFS skips them. This catches the cases NLF (B2) and
//! k-hop reachability (D5) miss: NLF only checks the 1-hop label
//! histogram, D5 only checks "can reach a vertex of the final type
//! within k hops" (ignoring the relation-type sequence). Semi-join
//! verifies the full alternating type/relation pattern.
//!
//! Honest scope: this is the Yannakakis bottom-up pass restricted to
//! linear chains. The full Yannakakis machinery enumerates output
//! tuples in O(|D| + |OUT|) over arbitrary acyclic CQs. Here we only
//! use the *prune* phase to shrink the start set fed into DFS;
//! enumeration still goes through the existing matcher. The temporal
//! constraint is *not* applied during semi-join (would require a
//! per-edge time check that defeats the linear-pass premise) — the
//! DFS validates time order. A miss prune is a perf loss, not a
//! correctness bug.
//!
//! Cost: O((n+1)·|V|/64) bits of memory, two passes of O(E). Skipped
//! when the chain is trivial (single step or all-`Any`).

use crate::hypothesis::{Hypothesis, HypothesisStep};
use crate::interner::StrId;
use crate::types::{EntityType, RelationType};

/// Compact bitset over vertex indices. `Vec<u64>` keeps deps light;
/// the per-word AND/OR is enough for our O(E) semi-join passes.
#[derive(Clone, Debug)]
pub struct Bitset {
    words: Vec<u64>,
    len: usize,
}

impl Bitset {
    pub fn with_capacity(len: usize) -> Self {
        let n_words = len.div_ceil(64);
        Self {
            words: vec![0u64; n_words],
            len,
        }
    }

    #[inline]
    pub fn set(&mut self, idx: usize) {
        if idx < self.len {
            self.words[idx >> 6] |= 1u64 << (idx & 63);
        }
    }

    #[inline]
    pub fn contains(&self, idx: usize) -> bool {
        if idx >= self.len {
            return false;
        }
        (self.words[idx >> 6] >> (idx & 63)) & 1 == 1
    }

    pub fn count(&self) -> usize {
        self.words.iter().map(|w| w.count_ones() as usize).sum()
    }

    pub fn is_empty(&self) -> bool {
        self.words.iter().all(|&w| w == 0)
    }
}

/// Candidate sets per chain position: `candidates[i]` holds the surviving
/// vertices for position `i` of the chain (0..=n where n = steps.len()).
#[derive(Clone, Debug)]
pub struct CandidateSets {
    pub candidates: Vec<Bitset>,
}

impl CandidateSets {
    /// Seed candidates from the type index. Position 0 is the chain's
    /// origin; position i (1..=n) is `steps[i-1].dest_type`.
    pub fn seed(graph: &crate::graph::GraphHunter, hypothesis: &Hypothesis) -> Self {
        let n = graph.entity_type_tags.len();
        let depth = hypothesis.steps.len() + 1;
        let mut candidates: Vec<Bitset> = (0..depth).map(|_| Bitset::with_capacity(n)).collect();

        for (pos, slot) in candidates.iter_mut().enumerate() {
            let ty = if pos == 0 {
                &hypothesis.steps[0].origin_type
            } else {
                &hypothesis.steps[pos - 1].dest_type
            };
            seed_by_type(graph, ty, slot);
        }

        Self { candidates }
    }
}

fn seed_by_type(graph: &crate::graph::GraphHunter, ty: &EntityType, out: &mut Bitset) {
    match ty {
        EntityType::Any => {
            for sid in graph.entities.keys().copied() {
                out.set(sid.index());
            }
        }
        _ => {
            if let Some(ids) = graph.type_index.get(ty) {
                for sid in ids.iter().copied() {
                    out.set(sid.index());
                }
            }
        }
    }
}

/// True iff the chain is too trivial for semi-join to help. NLF/D5
/// already cover single-step queries; an all-`Any` chain has no
/// label discrimination so the pass would degenerate to "every vertex
/// passes".
pub fn is_trivial(hypothesis: &Hypothesis) -> bool {
    if hypothesis.steps.len() < 2 {
        return true;
    }
    let all_any = hypothesis.steps.iter().all(|s| {
        matches!(s.origin_type, EntityType::Any)
            && matches!(s.dest_type, EntityType::Any)
            && matches!(s.relation_type, RelationType::Any)
    });
    all_any
}

/// Run the bidirectional semi-join, refining `cands` in place. Returns
/// the surviving candidate count for position 0 (the start set the DFS
/// will iterate over).
pub fn refine(graph: &crate::graph::GraphHunter, hypothesis: &Hypothesis, cands: &mut CandidateSets) {
    let steps = &hypothesis.steps;
    let n = steps.len();
    if n == 0 {
        return;
    }

    // Forward pass: for i = 1..=n, keep v at position i only if some
    // u at position i-1 has an edge u -r_i-> v matching the step.
    for i in 1..=n {
        let step = &steps[i - 1];
        let mut next = Bitset::with_capacity(cands.candidates[i].len);
        forward_step(graph, step, &cands.candidates[i - 1], &cands.candidates[i], &mut next);
        cands.candidates[i] = next;
    }

    // Backward pass: for i = n-1..=0, keep u at position i only if some
    // v at position i+1 has an edge u -r_{i+1}-> v.
    for i in (0..n).rev() {
        let step = &steps[i];
        let mut prev = Bitset::with_capacity(cands.candidates[i].len);
        backward_step(graph, step, &cands.candidates[i], &cands.candidates[i + 1], &mut prev);
        cands.candidates[i] = prev;
    }
}

/// For each `u` in `prev`, walk its outgoing edges; if the edge's
/// relation matches `step.relation_type` and `dest` is in `next_seed`,
/// mark `dest` in `out`.
fn forward_step(
    graph: &crate::graph::GraphHunter,
    step: &HypothesisStep,
    prev: &Bitset,
    next_seed: &Bitset,
    out: &mut Bitset,
) {
    for sid in graph.entities.keys().copied() {
        let u_idx = sid.index();
        if !prev.contains(u_idx) {
            continue;
        }
        let arc = match graph.streaming.neighbors_arc(sid) {
            Some(a) => a,
            None => continue,
        };
        let g = arc.read();
        for edge in g.as_slice() {
            if !relation_tag_matches(&step.relation_type, edge.rel_type_tag) {
                continue;
            }
            let dst_idx = edge.dest_sid.index();
            if next_seed.contains(dst_idx) {
                out.set(dst_idx);
            }
        }
    }
}

/// Mirror of `forward_step` for the backward pass: keep `u` if any
/// of its outgoing edges (matching the step) lands in `next`.
fn backward_step(
    graph: &crate::graph::GraphHunter,
    step: &HypothesisStep,
    prev_seed: &Bitset,
    next: &Bitset,
    out: &mut Bitset,
) {
    for sid in graph.entities.keys().copied() {
        let u_idx = sid.index();
        if !prev_seed.contains(u_idx) {
            continue;
        }
        let mut keep = false;
        if let Some(arc) = graph.streaming.neighbors_arc(sid) {
            let g = arc.read();
            for edge in g.as_slice() {
                if !relation_tag_matches(&step.relation_type, edge.rel_type_tag) {
                    continue;
                }
                if next.contains(edge.dest_sid.index()) {
                    keep = true;
                    break;
                }
            }
        }
        if keep {
            out.set(u_idx);
        }
    }
}

#[inline]
fn relation_tag_matches(pattern: &RelationType, tag: u8) -> bool {
    match pattern {
        RelationType::Any => true,
        _ => pattern.to_u8() == tag,
    }
}

/// Filter a list of candidate `StrId`s by the semi-join survivor set
/// at position 0. Used by the matcher to shrink `start_sids` before
/// the DFS.
pub fn filter_starts(starts: &mut Vec<StrId>, survivor: &Bitset) {
    starts.retain(|sid| survivor.contains(sid.index()));
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::graph::GraphHunter;
    use crate::hypothesis::HypothesisStep;
    use crate::types::{EntityType, RelationType};
    use crate::{Entity, Relation};

    fn build_chain_graph() -> GraphHunter {
        let mut g = GraphHunter::new();
        // Two Users; only one connects through the full chain.
        g.add_entity(Entity::new("u1", EntityType::User)).unwrap();
        g.add_entity(Entity::new("u2", EntityType::User)).unwrap(); // decoy
        g.add_entity(Entity::new("h1", EntityType::Host)).unwrap();
        g.add_entity(Entity::new("h2", EntityType::Host)).unwrap(); // decoy host
        g.add_entity(Entity::new("ip1", EntityType::IP)).unwrap();

        // Full chain: u1 -Auth-> h1 -Connect-> ip1
        g.add_relation(Relation::new("u1", "h1", RelationType::Auth, 100))
            .unwrap();
        g.add_relation(Relation::new("h1", "ip1", RelationType::Connect, 110))
            .unwrap();
        // Decoy: u2 has Host neighbor (passes NLF) but no Connect-IP downstream.
        g.add_relation(Relation::new("u2", "h2", RelationType::Auth, 100))
            .unwrap();

        g.sort_edges_by_timestamp().unwrap();
        g
    }

    fn user_host_ip_hypothesis() -> Hypothesis {
        Hypothesis::new("test")
            .add_step(HypothesisStep::new(
                EntityType::User,
                RelationType::Auth,
                EntityType::Host,
            ))
            .add_step(HypothesisStep::new(
                EntityType::Host,
                RelationType::Connect,
                EntityType::IP,
            ))
    }

    #[test]
    fn semijoin_drops_decoy_user() {
        let g = build_chain_graph();
        let h = user_host_ip_hypothesis();
        let mut cands = CandidateSets::seed(&g, &h);

        let u1_idx = g.interner.get("u1").unwrap().index();
        let u2_idx = g.interner.get("u2").unwrap().index();

        // Both Users are seeded at position 0 by type.
        assert!(cands.candidates[0].contains(u1_idx));
        assert!(cands.candidates[0].contains(u2_idx));

        refine(&g, &h, &mut cands);

        // Only u1 survives the bidirectional pass.
        assert!(cands.candidates[0].contains(u1_idx));
        assert!(!cands.candidates[0].contains(u2_idx));
    }

    #[test]
    fn semijoin_keeps_full_chain_vertices() {
        let g = build_chain_graph();
        let h = user_host_ip_hypothesis();
        let mut cands = CandidateSets::seed(&g, &h);
        refine(&g, &h, &mut cands);

        let h1_idx = g.interner.get("h1").unwrap().index();
        let ip1_idx = g.interner.get("ip1").unwrap().index();

        assert!(cands.candidates[1].contains(h1_idx));
        assert!(cands.candidates[2].contains(ip1_idx));
    }

    #[test]
    fn is_trivial_for_single_step() {
        let h = Hypothesis::new("t").add_step(HypothesisStep::new(
            EntityType::User,
            RelationType::Auth,
            EntityType::Host,
        ));
        assert!(is_trivial(&h));
    }

    #[test]
    fn is_trivial_for_all_any_chain() {
        let h = Hypothesis::new("t")
            .add_step(HypothesisStep::new(
                EntityType::Any,
                RelationType::Any,
                EntityType::Any,
            ))
            .add_step(HypothesisStep::new(
                EntityType::Any,
                RelationType::Any,
                EntityType::Any,
            ));
        assert!(is_trivial(&h));
    }

    #[test]
    fn filter_starts_shrinks_list() {
        let g = build_chain_graph();
        let h = user_host_ip_hypothesis();
        let mut cands = CandidateSets::seed(&g, &h);
        refine(&g, &h, &mut cands);

        let u1 = g.interner.get("u1").unwrap();
        let u2 = g.interner.get("u2").unwrap();
        let mut starts = vec![u1, u2];
        filter_starts(&mut starts, &cands.candidates[0]);

        assert_eq!(starts.len(), 1);
        assert_eq!(starts[0], u1);
    }
}
