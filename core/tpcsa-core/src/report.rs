//! Public output types: what `reconstruct_chain` hands to the analyst.

use serde::{Deserialize, Serialize};

use crate::instance::Time;
use crate::prune::PruneStats;
use crate::verify::Problem;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct RootInfo {
    pub node: String,
    pub kind: String,
    /// Timestamp of the first tree arc leaving the root.
    pub entry_time: Time,
    pub root_cost: f64,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct ArcReport {
    pub tail: String,
    pub head: String,
    pub etype: String,
    /// Event time assigned by the earliest-feasible schedule (equals the
    /// timestamp for point events).
    pub t: Time,
    pub cost: f64,
}

/// A node without a prize on which detections depend: the candidate
/// implant / C2 that no template flagged.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct Connector {
    pub node: String,
    pub kind: String,
    /// Terminals that are direct children in the tree.
    pub terminal_children: usize,
    /// Terminals anywhere in the subtree.
    pub terminal_descendants: usize,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct TreeReport {
    /// 1-based position after ranking.
    pub rank: usize,
    pub root: RootInfo,
    /// Arcs in root-to-leaf (BFS) order, times non-decreasing along every branch.
    pub arcs: Vec<ArcReport>,
    /// Terminals inside the tree.
    pub collected: Vec<String>,
    /// Terminals of the instance left outside this tree.
    pub dropped: Vec<String>,
    pub connectors: Vec<Connector>,
    /// Distinct tactics among collected terminals, sorted.
    pub tactics: Vec<String>,
    pub prize: f64,
    /// Arc costs plus the root's entry cost.
    pub cost: f64,
}

impl TreeReport {
    /// `prize − cost`; the greedy keeps a tree only when this is positive.
    pub fn net_gain(&self) -> f64 {
        self.prize - self.cost
    }

    pub fn nodes(&self) -> Vec<&str> {
        let mut out = vec![self.root.node.as_str()];
        out.extend(self.arcs.iter().map(|a| a.head.as_str()));
        out
    }
}

/// A tree the greedy produced but [`crate::verify`] rejected. Never shown
/// as a result; kept so the failure is visible instead of silent.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct RejectedTree {
    pub root: String,
    pub problems: Vec<Problem>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct Reconstruction {
    pub trees: Vec<TreeReport>,
    /// Pairs of ranks whose net gain lies within 1 % of each other: two
    /// hypotheses the evidence does not separate.
    pub ties: Vec<(usize, usize)>,
    pub pruning: PruneStats,
    /// Paper-convention objective over the forest:
    /// `Σ arc cost + Σ root cost + Σ prize of uncollected terminals`.
    pub objective: f64,
    pub total_prize: f64,
    pub rejected: Vec<RejectedTree>,
}
