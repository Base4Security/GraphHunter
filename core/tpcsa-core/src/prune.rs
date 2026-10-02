//! Temporal pruning: keep an arc only if it lies on some time-respecting
//! path from a root candidate to a terminal.
//!
//! Two label-setting passes. Forward from the roots computes the earliest
//! arrival `arr[v]` (a root can depart at any time, so its label is −∞);
//! backward from the terminals computes the latest departure `dep[v]` (a
//! terminal never has to leave, so its label is +∞). Arc `a = (u, v)`
//! survives iff `max(lo_a, arr[u] + ε) ≤ min(hi_a, dep[v] − ε)`: there is a
//! time at which one can traverse it having arrived at `u` and still reach
//! a terminal from `v`.
//!
//! This is exact for "lies on a time-respecting root→terminal walk" (the
//! walk may revisit a node at a later time; the arborescence constraint
//! is enforced downstream, so the survivor set is a safe superset).
//! On the paper's 20-hour trace it takes 212k arcs to 160–1 500.

use std::cmp::Reverse;
use std::collections::BinaryHeap;

use serde::{Deserialize, Serialize};

use crate::graph::Compiled;
use crate::instance::{Instance, InstanceError, Time};

/// Sentinels kept far from the `i64` edges so `±ε` never overflows.
const NEG_INF: Time = i64::MIN / 4;
const POS_INF: Time = i64::MAX / 4;

#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct PruneStats {
    pub arcs_before: usize,
    pub arcs_after: usize,
    pub nodes_before: usize,
    pub nodes_after: usize,
}

/// Earliest arrival at every node from any root candidate (`NEG_INF` on
/// the roots themselves, `POS_INF` when unreachable).
fn earliest_arrival(g: &Compiled) -> Vec<Time> {
    let mut arr = vec![POS_INF; g.n];
    let mut heap: BinaryHeap<Reverse<(Time, u32)>> = BinaryHeap::new();
    for v in 0..g.n as u32 {
        if g.is_root_candidate(v) {
            arr[v as usize] = NEG_INF;
            heap.push(Reverse((NEG_INF, v)));
        }
    }
    while let Some(Reverse((t, u))) = heap.pop() {
        if t > arr[u as usize] {
            continue;
        }
        for &ai in g.out(u) {
            let a = &g.arcs[ai as usize];
            let earliest = if t == NEG_INF {
                a.lo
            } else {
                a.lo.max(t + g.epsilon)
            };
            if earliest > a.hi {
                continue;
            }
            if earliest < arr[a.head as usize] {
                arr[a.head as usize] = earliest;
                heap.push(Reverse((earliest, a.head)));
            }
        }
    }
    arr
}

/// Latest departure from every node that still reaches a terminal
/// (`POS_INF` on the terminals themselves, `NEG_INF` when no terminal is
/// reachable).
fn latest_departure(g: &Compiled) -> Vec<Time> {
    let mut dep = vec![NEG_INF; g.n];
    let mut heap: BinaryHeap<(Time, u32)> = BinaryHeap::new();
    for v in 0..g.n as u32 {
        if g.is_terminal(v) {
            dep[v as usize] = POS_INF;
            heap.push((POS_INF, v));
        }
    }
    while let Some((t, v)) = heap.pop() {
        if t < dep[v as usize] {
            continue;
        }
        for &ai in g.inn(v) {
            let a = &g.arcs[ai as usize];
            let latest = if t == POS_INF {
                a.hi
            } else {
                a.hi.min(t - g.epsilon)
            };
            if latest < a.lo {
                continue;
            }
            if latest > dep[a.tail as usize] {
                dep[a.tail as usize] = latest;
                heap.push((latest, a.tail));
            }
        }
    }
    dep
}

/// Indices (into `inst.arcs`) of the arcs that survive pruning.
pub(crate) fn surviving_arcs(g: &Compiled) -> Vec<usize> {
    let arr = earliest_arrival(g);
    let dep = latest_departure(g);
    let mut keep = Vec::new();
    for a in &g.arcs {
        let at = arr[a.tail as usize];
        let dv = dep[a.head as usize];
        if at == POS_INF || dv == NEG_INF {
            continue;
        }
        let earliest = if at == NEG_INF {
            a.lo
        } else {
            a.lo.max(at + g.epsilon)
        };
        let latest = if dv == POS_INF {
            a.hi
        } else {
            a.hi.min(dv - g.epsilon)
        };
        if earliest <= latest {
            keep.push(a.orig);
        }
    }
    keep
}

/// Returns the pruned instance and the before/after counts.
///
/// Node policy: every node touched by a surviving arc is kept; every
/// terminal is kept even when isolated (so the objective still charges
/// its prize as "dropped"); isolated root candidates are removed (they
/// cannot start a tree).
pub fn temporal_prune(inst: &Instance) -> Result<(Instance, PruneStats), InstanceError> {
    let g = Compiled::from_instance(inst)?;
    let keep = surviving_arcs(&g);
    let mut touched = vec![false; inst.nodes.len()];
    let index = inst.index();
    for &ai in &keep {
        let a = &inst.arcs[ai];
        touched[index[a.tail.as_str()]] = true;
        touched[index[a.head.as_str()]] = true;
    }
    let nodes: Vec<_> = inst
        .nodes
        .iter()
        .enumerate()
        .filter(|(i, n)| touched[*i] || n.is_terminal())
        .map(|(_, n)| n.clone())
        .collect();
    let arcs: Vec<_> = keep.iter().map(|&ai| inst.arcs[ai].clone()).collect();
    let stats = PruneStats {
        arcs_before: inst.arcs.len(),
        arcs_after: arcs.len(),
        nodes_before: inst.nodes.len(),
        nodes_after: nodes.len(),
    };
    Ok((
        Instance {
            epsilon: inst.epsilon,
            nodes,
            arcs,
        },
        stats,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::instance::{Arc, Node};

    fn inst(
        eps: Time,
        nodes: &[(&str, f64, Option<f64>)],
        arcs: &[(&str, &str, Time, Time)],
    ) -> Instance {
        let mut i = Instance::new(eps);
        for (id, prize, root) in nodes {
            let mut n = Node::new(*id, "process").with_prize(*prize);
            n.root_cost = *root;
            i.nodes.push(n);
        }
        for (t, h, lo, hi) in arcs {
            i.arcs.push(Arc {
                tail: t.to_string(),
                head: h.to_string(),
                etype: "e".into(),
                lo: *lo,
                hi: *hi,
                cost: 1.0,
            });
        }
        i
    }

    #[test]
    fn keeps_time_respecting_chain_and_drops_backwards_one() {
        // r -(10)-> a -(20)-> t is fine; r -(30)-> b -(25)-> t runs backwards.
        let i = inst(
            1,
            &[
                ("r", 0.0, Some(1.0)),
                ("a", 0.0, None),
                ("b", 0.0, None),
                ("t", 5.0, None),
            ],
            &[
                ("r", "a", 10, 10),
                ("a", "t", 20, 20),
                ("r", "b", 30, 30),
                ("b", "t", 25, 25),
            ],
        );
        let (p, s) = temporal_prune(&i).unwrap();
        assert_eq!(s.arcs_before, 4);
        assert_eq!(s.arcs_after, 2);
        let kept: Vec<(&str, &str)> = p
            .arcs
            .iter()
            .map(|a| (a.tail.as_str(), a.head.as_str()))
            .collect();
        assert_eq!(kept, vec![("r", "a"), ("a", "t")]);
        // b is isolated and neither terminal nor useful → gone; t kept.
        let ids: Vec<&str> = p.nodes.iter().map(|n| n.id.as_str()).collect();
        assert_eq!(ids, vec!["r", "a", "t"]);
    }

    #[test]
    fn epsilon_separates_cause_from_effect() {
        // Same-timestamp hop is not causal when ε = 1, is when ε = 0.
        let mk = |eps| {
            inst(
                eps,
                &[("r", 0.0, Some(1.0)), ("a", 0.0, None), ("t", 5.0, None)],
                &[("r", "a", 10, 10), ("a", "t", 10, 10)],
            )
        };
        assert_eq!(temporal_prune(&mk(1)).unwrap().1.arcs_after, 0);
        assert_eq!(temporal_prune(&mk(0)).unwrap().1.arcs_after, 2);
    }

    #[test]
    fn interval_arcs_use_the_feasible_slice() {
        // a→t can depart anywhere in [5, 15]; arrival at a is 10, ε=1 → 11 ≤ 15 ok.
        let i = inst(
            1,
            &[("r", 0.0, Some(1.0)), ("a", 0.0, None), ("t", 5.0, None)],
            &[("r", "a", 10, 10), ("a", "t", 5, 15)],
        );
        assert_eq!(temporal_prune(&i).unwrap().1.arcs_after, 2);
        // Now the interval closes before we can arrive.
        let j = inst(
            1,
            &[("r", 0.0, Some(1.0)), ("a", 0.0, None), ("t", 5.0, None)],
            &[("r", "a", 10, 10), ("a", "t", 5, 10)],
        );
        assert_eq!(temporal_prune(&j).unwrap().1.arcs_after, 0);
    }

    #[test]
    fn arcs_past_the_last_terminal_are_dropped() {
        let i = inst(
            1,
            &[("r", 0.0, Some(1.0)), ("t", 5.0, None), ("x", 0.0, None)],
            &[("r", "t", 10, 10), ("t", "x", 20, 20)],
        );
        let (p, _) = temporal_prune(&i).unwrap();
        assert_eq!(p.arcs.len(), 1);
        assert_eq!(p.arcs[0].head, "t");
    }

    #[test]
    fn isolated_terminal_is_kept_for_the_objective() {
        let i = inst(1, &[("r", 0.0, Some(1.0)), ("t", 5.0, None)], &[]);
        let (p, s) = temporal_prune(&i).unwrap();
        assert_eq!(s.nodes_after, 1);
        assert_eq!(p.nodes[0].id, "t");
    }
}
