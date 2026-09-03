//! The TPCSA instance: what the solver needs and nothing else.
//!
//! A directed multigraph of timestamped events. Nodes are entities
//! (process, user, host, ip, file, registry key…), arcs are events with a
//! *causal-flow* direction (who acts → on what) and a timestamp interval
//! `[lo, hi]` (`lo == hi` for point events). Terminals carry a prize; root
//! candidates carry an entry cost; `epsilon` is the resolution that
//! separates cause from effect.
//!
//! # Time unit
//!
//! Times are plain `i64` in whatever unit the producer chose, as long as
//! `epsilon` uses the same unit. Graph Hunter's exporter emits
//! **microseconds** (ε = 1 ms → `1_000`; ε = 1 s → `1_000_000`).
//!
//! # JSON shape
//!
//! ```json
//! {"epsilon": 1000,
//!  "nodes": [{"id":"p1","kind":"process","prize":7.5,"tactic":"execution","root_cost":6.0}],
//!  "arcs":  [{"tail":"p0","head":"p1","etype":"start","lo":81700,"hi":81700,"cost":1.0}]}
//! ```
//!
//! `root_cost: null` (or absent) means "not a root candidate"; `prize: 0`
//! (or absent) means "not a terminal". Unknown keys are ignored so a
//! producer may attach provenance without breaking the reader.

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

/// Timestamp in the instance's unit (see module docs).
pub type Time = i64;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct Node {
    pub id: String,
    pub kind: String,
    #[serde(default)]
    pub prize: f64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tactic: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub root_cost: Option<f64>,
}

impl Node {
    pub fn new(id: impl Into<String>, kind: impl Into<String>) -> Self {
        Self {
            id: id.into(),
            kind: kind.into(),
            prize: 0.0,
            tactic: None,
            root_cost: None,
        }
    }

    pub fn with_prize(mut self, prize: f64) -> Self {
        self.prize = prize;
        self
    }

    pub fn with_tactic(mut self, tactic: impl Into<String>) -> Self {
        self.tactic = Some(tactic.into());
        self
    }

    pub fn with_root_cost(mut self, cost: f64) -> Self {
        self.root_cost = Some(cost);
        self
    }

    pub fn is_terminal(&self) -> bool {
        self.prize > 0.0
    }

    pub fn is_root_candidate(&self) -> bool {
        self.root_cost.is_some()
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct Arc {
    pub tail: String,
    pub head: String,
    pub etype: String,
    pub lo: Time,
    pub hi: Time,
    pub cost: f64,
}

impl Arc {
    /// Point-timestamp arc (`lo == hi == t`).
    pub fn point(
        tail: impl Into<String>,
        head: impl Into<String>,
        etype: impl Into<String>,
        t: Time,
        cost: f64,
    ) -> Self {
        Self {
            tail: tail.into(),
            head: head.into(),
            etype: etype.into(),
            lo: t,
            hi: t,
            cost,
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct Instance {
    pub epsilon: Time,
    pub nodes: Vec<Node>,
    pub arcs: Vec<Arc>,
}

#[derive(Debug, thiserror::Error, PartialEq)]
pub enum InstanceError {
    #[error("epsilon must be >= 0, got {0}")]
    NegativeEpsilon(Time),
    #[error("duplicate node id {0:?}")]
    DuplicateNode(String),
    #[error("arc #{index} references unknown node {node:?}")]
    UnknownNode { index: usize, node: String },
    #[error("arc #{index} has lo > hi ({lo} > {hi})")]
    InvertedInterval { index: usize, lo: Time, hi: Time },
    #[error("arc #{index} has a negative or non-finite cost ({cost})")]
    BadCost { index: usize, cost: f64 },
    #[error("node {id:?} has a negative or non-finite prize ({prize})")]
    BadPrize { id: String, prize: f64 },
    #[error("node {id:?} has a negative or non-finite root cost ({cost})")]
    BadRootCost { id: String, cost: f64 },
    #[error("json: {0}")]
    Json(String),
}

impl Instance {
    pub fn new(epsilon: Time) -> Self {
        Self {
            epsilon,
            nodes: Vec::new(),
            arcs: Vec::new(),
        }
    }

    pub fn to_json(&self) -> String {
        serde_json::to_string(self).expect("Instance is always serializable")
    }

    pub fn to_json_pretty(&self) -> String {
        serde_json::to_string_pretty(self).expect("Instance is always serializable")
    }

    /// Parses and validates.
    pub fn from_json(s: &str) -> Result<Self, InstanceError> {
        let inst: Instance =
            serde_json::from_str(s).map_err(|e| InstanceError::Json(e.to_string()))?;
        inst.validate()?;
        Ok(inst)
    }

    /// Structural validation: unique ids, arcs reference known nodes,
    /// well-formed intervals, non-negative finite weights.
    pub fn validate(&self) -> Result<(), InstanceError> {
        if self.epsilon < 0 {
            return Err(InstanceError::NegativeEpsilon(self.epsilon));
        }
        let mut seen: HashMap<&str, ()> = HashMap::with_capacity(self.nodes.len());
        for n in &self.nodes {
            if seen.insert(n.id.as_str(), ()).is_some() {
                return Err(InstanceError::DuplicateNode(n.id.clone()));
            }
            if !(n.prize.is_finite() && n.prize >= 0.0) {
                return Err(InstanceError::BadPrize {
                    id: n.id.clone(),
                    prize: n.prize,
                });
            }
            if let Some(c) = n.root_cost {
                if !(c.is_finite() && c >= 0.0) {
                    return Err(InstanceError::BadRootCost {
                        id: n.id.clone(),
                        cost: c,
                    });
                }
            }
        }
        for (index, a) in self.arcs.iter().enumerate() {
            for node in [&a.tail, &a.head] {
                if !seen.contains_key(node.as_str()) {
                    return Err(InstanceError::UnknownNode {
                        index,
                        node: node.clone(),
                    });
                }
            }
            if a.lo > a.hi {
                return Err(InstanceError::InvertedInterval {
                    index,
                    lo: a.lo,
                    hi: a.hi,
                });
            }
            if !(a.cost.is_finite() && a.cost >= 0.0) {
                return Err(InstanceError::BadCost {
                    index,
                    cost: a.cost,
                });
            }
        }
        Ok(())
    }

    /// `id → position in `nodes``.
    pub fn index(&self) -> HashMap<&str, usize> {
        self.nodes
            .iter()
            .enumerate()
            .map(|(i, n)| (n.id.as_str(), i))
            .collect()
    }

    pub fn terminals(&self) -> impl Iterator<Item = &Node> {
        self.nodes.iter().filter(|n| n.is_terminal())
    }

    pub fn root_candidates(&self) -> impl Iterator<Item = &Node> {
        self.nodes.iter().filter(|n| n.is_root_candidate())
    }

    pub fn total_prize(&self) -> f64 {
        self.nodes.iter().map(|n| n.prize).sum()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tiny() -> Instance {
        let mut inst = Instance::new(1);
        inst.nodes.push(Node::new("r", "ip").with_root_cost(2.0));
        inst.nodes
            .push(Node::new("p", "process").with_root_cost(6.0));
        inst.nodes.push(
            Node::new("t", "process")
                .with_prize(8.0)
                .with_tactic("execution")
                .with_root_cost(6.0),
        );
        inst.arcs.push(Arc::point("r", "p", "recv", 10, 1.0));
        inst.arcs.push(Arc::point("p", "t", "start", 12, 1.0));
        inst
    }

    #[test]
    fn json_round_trip_preserves_everything() {
        let inst = tiny();
        let back = Instance::from_json(&inst.to_json()).unwrap();
        assert_eq!(inst, back);
    }

    #[test]
    fn absent_optional_fields_default() {
        let s = r#"{"epsilon":1,"nodes":[{"id":"a","kind":"process"},{"id":"b","kind":"file"}],
                    "arcs":[{"tail":"a","head":"b","etype":"write","lo":1,"hi":1,"cost":1.0,"extra":"ignored"}]}"#;
        let inst = Instance::from_json(s).unwrap();
        assert_eq!(inst.nodes[0].prize, 0.0);
        assert_eq!(inst.nodes[0].tactic, None);
        assert_eq!(inst.nodes[0].root_cost, None);
        assert!(!inst.nodes[0].is_terminal());
        assert!(!inst.nodes[0].is_root_candidate());
    }

    #[test]
    fn validation_rejects_unknown_nodes_and_bad_intervals() {
        let mut inst = tiny();
        inst.arcs.push(Arc::point("p", "ghost", "start", 1, 1.0));
        assert!(matches!(
            inst.validate(),
            Err(InstanceError::UnknownNode { index: 2, .. })
        ));

        let mut inst = tiny();
        inst.arcs[0].lo = 20;
        assert!(matches!(
            inst.validate(),
            Err(InstanceError::InvertedInterval { index: 0, .. })
        ));

        let mut inst = tiny();
        inst.nodes.push(Node::new("r", "ip"));
        assert_eq!(
            inst.validate(),
            Err(InstanceError::DuplicateNode("r".into()))
        );

        let mut inst = tiny();
        inst.arcs[1].cost = -1.0;
        assert!(matches!(
            inst.validate(),
            Err(InstanceError::BadCost { index: 1, .. })
        ));

        let mut inst = tiny();
        inst.epsilon = -5;
        assert_eq!(inst.validate(), Err(InstanceError::NegativeEpsilon(-5)));
    }

    #[test]
    fn terminals_and_roots_are_derived_from_fields() {
        let inst = tiny();
        let t: Vec<_> = inst.terminals().map(|n| n.id.as_str()).collect();
        assert_eq!(t, vec!["t"]);
        let r: Vec<_> = inst.root_candidates().map(|n| n.id.as_str()).collect();
        assert_eq!(r, vec!["r", "p", "t"]);
        assert_eq!(inst.total_prize(), 8.0);
    }
}
