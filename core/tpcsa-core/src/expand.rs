//! Time-expanded DAG (Kempe–Kleinberg–Kumar construction).
//!
//! Every node `u` gets an *arrival* copy `(u, lo_a)` for each incoming arc
//! `a` and a *departure* copy `(u, hi_b − ε)` for each outgoing arc `b`.
//! Copies of one node are chained in time order by zero-cost *wait* arcs
//! (arrival before departure when the times tie). A real arc `a = (u, v)`
//! becomes `(u, hi_a − ε) → (v, lo_a)` with cost `c_a`. An arrival at time
//! `t` can therefore feed only departures at times `≥ t + ε`, which is
//! exactly the time-respect constraint — so any path in this DAG is a
//! time-respecting path in the original graph (exact for point
//! timestamps, a relaxation for interval arcs, as in the paper).
//!
//! Size: ≤ 2|A| copies, ≤ 3|A| arcs.

use std::collections::HashMap;

use crate::graph::{Compiled, NONE};
use crate::instance::Time;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct TeCopy {
    pub node: u32,
    pub time: Time,
    pub arrival: bool,
}

#[derive(Clone, Copy, Debug)]
pub(crate) struct TeArc {
    pub from: u32,
    pub to: u32,
    pub cost: f64,
    /// Index into `Compiled::arcs`, or `NONE` for a wait arc.
    pub real: u32,
}

#[derive(Clone, Debug)]
pub(crate) struct TeGraph {
    pub copies: Vec<TeCopy>,
    /// Copies of each original node in chain (time) order.
    pub node_copies: Vec<Vec<u32>>,
    pub arcs: Vec<TeArc>,
    out_start: Vec<usize>,
    out_idx: Vec<u32>,
    in_start: Vec<usize>,
    in_idx: Vec<u32>,
}

impl TeGraph {
    pub fn build(g: &Compiled) -> Self {
        let mut key: HashMap<(u32, Time, bool), u32> = HashMap::with_capacity(2 * g.arcs.len());
        let mut copies: Vec<TeCopy> = Vec::with_capacity(2 * g.arcs.len());
        let mut intern = |node: u32, time: Time, arrival: bool| -> u32 {
            *key.entry((node, time, arrival)).or_insert_with(|| {
                copies.push(TeCopy {
                    node,
                    time,
                    arrival,
                });
                (copies.len() - 1) as u32
            })
        };
        // (departure copy, arrival copy) per real arc.
        let ends: Vec<(u32, u32)> = g
            .arcs
            .iter()
            .map(|a| {
                let dep = intern(a.tail, a.hi - g.epsilon, false);
                let arr = intern(a.head, a.lo, true);
                (dep, arr)
            })
            .collect();

        let mut node_copies: Vec<Vec<u32>> = vec![Vec::new(); g.n];
        for (ci, c) in copies.iter().enumerate() {
            node_copies[c.node as usize].push(ci as u32);
        }
        for list in node_copies.iter_mut() {
            list.sort_by_key(|&ci| {
                let c = &copies[ci as usize];
                (c.time, !c.arrival)
            });
        }

        let mut arcs: Vec<TeArc> = Vec::with_capacity(3 * g.arcs.len());
        for list in &node_copies {
            for w in list.windows(2) {
                arcs.push(TeArc {
                    from: w[0],
                    to: w[1],
                    cost: 0.0,
                    real: NONE,
                });
            }
        }
        for (ai, (dep, arr)) in ends.iter().enumerate() {
            arcs.push(TeArc {
                from: *dep,
                to: *arr,
                cost: g.arcs[ai].cost,
                real: ai as u32,
            });
        }

        // CSR by `from` (forward) and by `to` (reverse, for root scoring).
        let m = copies.len();
        let (out_start, out_idx) = csr(m, &arcs, |a| a.from);
        let (in_start, in_idx) = csr(m, &arcs, |a| a.to);

        Self {
            copies,
            node_copies,
            arcs,
            out_start,
            out_idx,
            in_start,
            in_idx,
        }
    }

    /// TE arcs leaving `copy`.
    pub fn out(&self, copy: u32) -> &[u32] {
        &self.out_idx[self.out_start[copy as usize]..self.out_start[copy as usize + 1]]
    }

    /// TE arcs entering `copy`.
    pub fn inn(&self, copy: u32) -> &[u32] {
        &self.in_idx[self.in_start[copy as usize]..self.in_start[copy as usize + 1]]
    }

    /// The earliest copy of `node`, where a tree rooted there starts.
    pub fn entry_copy(&self, node: u32) -> Option<u32> {
        self.node_copies[node as usize].first().copied()
    }

    pub fn len_copies(&self) -> usize {
        self.copies.len()
    }
}

fn csr(m: usize, arcs: &[TeArc], key: impl Fn(&TeArc) -> u32) -> (Vec<usize>, Vec<u32>) {
    let mut start = vec![0usize; m + 1];
    for a in arcs {
        start[key(a) as usize + 1] += 1;
    }
    for v in 0..m {
        start[v + 1] += start[v];
    }
    let mut fill = start.clone();
    let mut idx = vec![0u32; arcs.len()];
    for (i, a) in arcs.iter().enumerate() {
        let k = key(a) as usize;
        idx[fill[k]] = i as u32;
        fill[k] += 1;
    }
    (start, idx)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::instance::{Arc, Instance, Node};

    #[test]
    fn reverse_adjacency_mirrors_forward() {
        let g = chain();
        let te = TeGraph::build(&g);
        for (ai, a) in te.arcs.iter().enumerate() {
            assert!(te.out(a.from).contains(&(ai as u32)));
            assert!(te.inn(a.to).contains(&(ai as u32)));
        }
    }

    fn chain() -> Compiled {
        // r -(10)-> a -(20)-> t, plus a -(5)-> x (too early to follow r→a).
        let mut i = Instance::new(1);
        for id in ["r", "a", "t", "x"] {
            i.nodes.push(Node::new(id, "process"));
        }
        i.nodes[0].root_cost = Some(1.0);
        i.nodes[2].prize = 5.0;
        i.arcs.push(Arc::point("r", "a", "e", 10, 1.0));
        i.arcs.push(Arc::point("a", "t", "e", 20, 1.0));
        i.arcs.push(Arc::point("a", "x", "e", 5, 1.0));
        Compiled::from_instance(&i).unwrap()
    }

    #[test]
    fn sizes_are_bounded_by_two_and_three_times_the_arcs() {
        let g = chain();
        let te = TeGraph::build(&g);
        assert!(te.len_copies() <= 2 * g.arcs.len());
        assert!(te.arcs.len() <= 3 * g.arcs.len());
    }

    #[test]
    fn wait_arcs_chain_copies_in_time_order_and_only_forward() {
        let g = chain();
        let te = TeGraph::build(&g);
        // a has: departure at 4 (for a→x at 5), arrival at 10 (from r→a), departure at 19 (for a→t at 20).
        let a_copies = &te.node_copies[1];
        let times: Vec<(Time, bool)> = a_copies
            .iter()
            .map(|&c| (te.copies[c as usize].time, te.copies[c as usize].arrival))
            .collect();
        assert_eq!(times, vec![(4, false), (10, true), (19, false)]);
        // From the arrival copy at 10 you can reach the departure at 19 but not the one at 4.
        let arr10 = a_copies[1];
        let reachable: Vec<u32> = te
            .out(arr10)
            .iter()
            .map(|&ai| te.arcs[ai as usize].to)
            .collect();
        assert_eq!(reachable, vec![a_copies[2]]);
        let dep4 = a_copies[0];
        let from_dep4: Vec<u32> = te
            .out(dep4)
            .iter()
            .map(|&ai| te.arcs[ai as usize].to)
            .collect();
        // dep4 → (wait) arr10, and dep4 → (real a→x) x's arrival copy.
        assert_eq!(from_dep4.len(), 2);
    }

    #[test]
    fn ties_put_arrival_before_departure() {
        // a arrives at 10 and must depart at 10 (arc at 11 with ε=1): allowed.
        let mut i = Instance::new(1);
        for id in ["r", "a", "t"] {
            i.nodes.push(Node::new(id, "process"));
        }
        i.arcs.push(Arc::point("r", "a", "e", 10, 1.0));
        i.arcs.push(Arc::point("a", "t", "e", 11, 1.0));
        let te = TeGraph::build(&Compiled::from_instance(&i).unwrap());
        let a = &te.node_copies[1];
        assert!(te.copies[a[0] as usize].arrival);
        assert!(!te.copies[a[1] as usize].arrival);
        assert_eq!(te.copies[a[0] as usize].time, te.copies[a[1] as usize].time);
    }

    #[test]
    fn duplicate_copies_are_shared() {
        // Two arcs into `a` at the same time share one arrival copy.
        let mut i = Instance::new(1);
        for id in ["r", "s", "a"] {
            i.nodes.push(Node::new(id, "process"));
        }
        i.arcs.push(Arc::point("r", "a", "e", 10, 1.0));
        i.arcs.push(Arc::point("s", "a", "e", 10, 1.0));
        let te = TeGraph::build(&Compiled::from_instance(&i).unwrap());
        assert_eq!(te.node_copies[2].len(), 1);
    }
}
