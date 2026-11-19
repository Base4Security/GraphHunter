//! Compiled, index-based view of an [`Instance`]: node ids interned to
//! `u32`, arcs in a `Vec`, CSR adjacency in both directions. Everything
//! downstream (prune, expand, greedy, verify) works on this.

use std::collections::HashMap;

use crate::instance::{Instance, InstanceError, Time};

pub(crate) const NONE: u32 = u32::MAX;

#[derive(Clone, Debug)]
pub(crate) struct CArc {
    pub tail: u32,
    pub head: u32,
    pub lo: Time,
    pub hi: Time,
    pub cost: f64,
    /// Position in `Instance::arcs`.
    pub orig: usize,
}

#[derive(Clone, Debug)]
pub(crate) struct Compiled {
    pub n: usize,
    pub epsilon: Time,
    pub prize: Vec<f64>,
    pub root_cost: Vec<Option<f64>>,
    pub arcs: Vec<CArc>,
    out_start: Vec<usize>,
    out_idx: Vec<u32>,
    in_start: Vec<usize>,
    in_idx: Vec<u32>,
}

impl Compiled {
    pub fn from_instance(inst: &Instance) -> Result<Self, InstanceError> {
        inst.validate()?;
        let index: HashMap<&str, u32> = inst
            .nodes
            .iter()
            .enumerate()
            .map(|(i, n)| (n.id.as_str(), i as u32))
            .collect();
        let n = inst.nodes.len();
        let arcs: Vec<CArc> = inst
            .arcs
            .iter()
            .enumerate()
            .map(|(orig, a)| CArc {
                tail: index[a.tail.as_str()],
                head: index[a.head.as_str()],
                lo: a.lo,
                hi: a.hi,
                cost: a.cost,
                orig,
            })
            .collect();
        let (out_start, out_idx) = csr(n, arcs.iter().map(|a| a.tail));
        let (in_start, in_idx) = csr(n, arcs.iter().map(|a| a.head));
        Ok(Self {
            n,
            epsilon: inst.epsilon,
            prize: inst.nodes.iter().map(|x| x.prize).collect(),
            root_cost: inst.nodes.iter().map(|x| x.root_cost).collect(),
            arcs,
            out_start,
            out_idx,
            in_start,
            in_idx,
        })
    }

    /// Indices of arcs leaving `v`.
    pub fn out(&self, v: u32) -> &[u32] {
        &self.out_idx[self.out_start[v as usize]..self.out_start[v as usize + 1]]
    }

    /// Indices of arcs entering `v`.
    pub fn inn(&self, v: u32) -> &[u32] {
        &self.in_idx[self.in_start[v as usize]..self.in_start[v as usize + 1]]
    }

    pub fn is_terminal(&self, v: u32) -> bool {
        self.prize[v as usize] > 0.0
    }

    pub fn is_root_candidate(&self, v: u32) -> bool {
        self.root_cost[v as usize].is_some()
    }
}

/// Counting-sort CSR: returns `(start, idx)` with `idx[start[v]..start[v+1]]`
/// listing the arc indices whose key is `v`, in arc order.
fn csr(n: usize, keys: impl Iterator<Item = u32> + Clone) -> (Vec<usize>, Vec<u32>) {
    let mut start = vec![0usize; n + 1];
    for k in keys.clone() {
        start[k as usize + 1] += 1;
    }
    for v in 0..n {
        start[v + 1] += start[v];
    }
    let mut fill = start.clone();
    let mut idx = vec![0u32; start[n]];
    for (i, k) in keys.enumerate() {
        idx[fill[k as usize]] = i as u32;
        fill[k as usize] += 1;
    }
    (start, idx)
}

/// `f64` with a total order, for use as a heap key.
#[derive(Clone, Copy, Debug, PartialEq)]
pub(crate) struct OrdF64(pub f64);

impl Eq for OrdF64 {}

impl PartialOrd for OrdF64 {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for OrdF64 {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.0.total_cmp(&other.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::instance::{Arc, Node};

    #[test]
    fn csr_lists_arcs_by_tail_and_head_in_arc_order() {
        let mut inst = Instance::new(1);
        for id in ["a", "b", "c"] {
            inst.nodes.push(Node::new(id, "process"));
        }
        inst.arcs.push(Arc::point("a", "b", "x", 1, 1.0));
        inst.arcs.push(Arc::point("a", "c", "x", 2, 1.0));
        inst.arcs.push(Arc::point("b", "c", "x", 3, 1.0));
        let g = Compiled::from_instance(&inst).unwrap();
        assert_eq!(g.out(0), &[0, 1]);
        assert_eq!(g.out(1), &[2]);
        assert_eq!(g.out(2), &[] as &[u32]);
        assert_eq!(g.inn(2), &[1, 2]);
        assert_eq!(g.inn(0), &[] as &[u32]);
    }

    #[test]
    fn ordf64_orders_like_f64() {
        let mut v = vec![OrdF64(2.5), OrdF64(-1.0), OrdF64(0.0)];
        v.sort();
        assert_eq!(v, vec![OrdF64(-1.0), OrdF64(0.0), OrdF64(2.5)]);
    }
}
