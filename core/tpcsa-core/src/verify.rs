//! Independent re-verification of any tree, wherever it came from
//! (greedy or MILP). Checks arborescence structure, time consistency and
//! the reported objective. A tree with problems is never presented.

use std::collections::{HashMap, VecDeque};

use serde::{Deserialize, Serialize};

use crate::instance::{Instance, Time};
use crate::report::TreeReport;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Problem {
    UnknownNode {
        node: String,
    },
    UnknownArc {
        tail: String,
        head: String,
        etype: String,
    },
    RootNotCandidate {
        node: String,
    },
    RootHasIncoming {
        node: String,
    },
    InDegree {
        node: String,
        count: usize,
    },
    Unreachable {
        node: String,
    },
    /// The earliest feasible schedule needs `theta` but the arc closes at `hi`.
    TimeViolation {
        tail: String,
        head: String,
        theta: Time,
        hi: Time,
    },
    ObjectiveMismatch {
        field: String,
        reported: f64,
        recomputed: f64,
    },
}

/// Earliest-feasible event times along a tree given as `(tail, head, lo,
/// hi)` arcs. Returns one time per arc (same order) or the first
/// violation. `root` must be the unique in-degree-0 node.
pub fn schedule(
    epsilon: Time,
    root: &str,
    arcs: &[(&str, &str, Time, Time)],
) -> Result<Vec<Time>, Problem> {
    let mut children: HashMap<&str, Vec<usize>> = HashMap::new();
    for (i, a) in arcs.iter().enumerate() {
        children.entry(a.0).or_default().push(i);
    }
    let mut theta = vec![Time::MIN; arcs.len()];
    // (node, time of the arc that reached it; None for the root)
    let mut queue: VecDeque<(&str, Option<Time>)> = VecDeque::new();
    queue.push_back((root, None));
    while let Some((u, arrived)) = queue.pop_front() {
        let Some(out) = children.get(u) else { continue };
        for &i in out {
            let (tail, head, lo, hi) = arcs[i];
            let t = match arrived {
                None => lo,
                Some(at) => lo.max(at + epsilon),
            };
            if t > hi {
                return Err(Problem::TimeViolation {
                    tail: tail.to_string(),
                    head: head.to_string(),
                    theta: t,
                    hi,
                });
            }
            theta[i] = t;
            queue.push_back((head, Some(t)));
        }
    }
    Ok(theta)
}

/// Every problem found; empty means the tree is sound.
pub fn verify(inst: &Instance, tree: &TreeReport) -> Vec<Problem> {
    let mut problems = Vec::new();
    let index = inst.index();

    // Nodes and arcs must exist in the instance.
    let root_id = tree.root.node.as_str();
    match index.get(root_id) {
        None => {
            problems.push(Problem::UnknownNode {
                node: root_id.to_string(),
            });
            return problems;
        }
        Some(&i) => {
            if !inst.nodes[i].is_root_candidate() {
                problems.push(Problem::RootNotCandidate {
                    node: root_id.to_string(),
                });
            }
        }
    }
    let mut arc_lookup: HashMap<(&str, &str, &str), Vec<&crate::instance::Arc>> = HashMap::new();
    for a in &inst.arcs {
        arc_lookup
            .entry((a.tail.as_str(), a.head.as_str(), a.etype.as_str()))
            .or_default()
            .push(a);
    }
    let mut resolved: Vec<(&str, &str, Time, Time, f64)> = Vec::with_capacity(tree.arcs.len());
    for a in &tree.arcs {
        for node in [&a.tail, &a.head] {
            if !index.contains_key(node.as_str()) {
                problems.push(Problem::UnknownNode { node: node.clone() });
            }
        }
        // Match the instance arc whose interval contains the reported time
        // and whose cost matches; fall back to any arc with that signature.
        let cands = arc_lookup.get(&(a.tail.as_str(), a.head.as_str(), a.etype.as_str()));
        let hit = cands.and_then(|v| {
            v.iter()
                .find(|x| x.lo <= a.t && a.t <= x.hi && (x.cost - a.cost).abs() < 1e-9)
                .or_else(|| v.first())
                .copied()
        });
        match hit {
            Some(x) => resolved.push((x.tail.as_str(), x.head.as_str(), x.lo, x.hi, x.cost)),
            None => problems.push(Problem::UnknownArc {
                tail: a.tail.clone(),
                head: a.head.clone(),
                etype: a.etype.clone(),
            }),
        }
    }
    if !problems.is_empty() {
        return problems;
    }

    // In-degree: root 0, everyone else exactly 1.
    let mut indeg: HashMap<&str, usize> = HashMap::new();
    for a in &resolved {
        *indeg.entry(a.1).or_default() += 1;
    }
    if indeg.contains_key(root_id) {
        problems.push(Problem::RootHasIncoming {
            node: root_id.to_string(),
        });
    }
    for (node, &count) in &indeg {
        if count != 1 {
            problems.push(Problem::InDegree {
                node: node.to_string(),
                count,
            });
        }
    }
    // Every tail must itself be in the tree (root or reached).
    for a in &resolved {
        if a.0 != root_id && !indeg.contains_key(a.0) {
            problems.push(Problem::Unreachable {
                node: a.0.to_string(),
            });
        }
    }
    if !problems.is_empty() {
        return problems;
    }

    // Reachability from the root (rules out cycles among in-degree-1 nodes).
    let mut children: HashMap<&str, Vec<&str>> = HashMap::new();
    for a in &resolved {
        children.entry(a.0).or_default().push(a.1);
    }
    let mut seen: HashMap<&str, ()> = HashMap::new();
    let mut stack = vec![root_id];
    while let Some(u) = stack.pop() {
        if seen.insert(u, ()).is_some() {
            continue;
        }
        if let Some(c) = children.get(u) {
            stack.extend(c.iter().copied());
        }
    }
    for node in indeg.keys() {
        if !seen.contains_key(node) {
            problems.push(Problem::Unreachable {
                node: node.to_string(),
            });
        }
    }
    if !problems.is_empty() {
        return problems;
    }

    // Time consistency.
    let quads: Vec<(&str, &str, Time, Time)> =
        resolved.iter().map(|a| (a.0, a.1, a.2, a.3)).collect();
    if let Err(p) = schedule(inst.epsilon, root_id, &quads) {
        problems.push(p);
    }

    // Objective: prize over terminals in the tree, cost = arcs + root.
    let mut prize = 0.0;
    for node in indeg.keys() {
        prize += inst.nodes[index[node]].prize;
    }
    let root_cost = inst.nodes[index[root_id]].root_cost.unwrap_or(0.0);
    let cost: f64 = resolved.iter().map(|a| a.4).sum::<f64>() + root_cost;
    if (prize - tree.prize).abs() > 1e-6 {
        problems.push(Problem::ObjectiveMismatch {
            field: "prize".into(),
            reported: tree.prize,
            recomputed: prize,
        });
    }
    if (cost - tree.cost).abs() > 1e-6 {
        problems.push(Problem::ObjectiveMismatch {
            field: "cost".into(),
            reported: tree.cost,
            recomputed: cost,
        });
    }
    problems
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::instance::{Arc, Node};
    use crate::report::{ArcReport, RootInfo};

    fn inst() -> Instance {
        let mut i = Instance::new(1);
        i.nodes.push(Node::new("r", "ip").with_root_cost(2.0));
        i.nodes.push(Node::new("a", "process").with_root_cost(6.0));
        i.nodes.push(
            Node::new("t", "process")
                .with_prize(8.0)
                .with_root_cost(6.0),
        );
        i.arcs.push(Arc::point("r", "a", "recv", 10, 1.0));
        i.arcs.push(Arc::point("a", "t", "start", 20, 1.5));
        i
    }

    fn arc(tail: &str, head: &str, etype: &str, t: Time, cost: f64) -> ArcReport {
        ArcReport {
            tail: tail.into(),
            head: head.into(),
            etype: etype.into(),
            t,
            cost,
        }
    }

    fn tree(root: &str, arcs: Vec<ArcReport>, prize: f64, cost: f64) -> TreeReport {
        TreeReport {
            rank: 1,
            root: RootInfo {
                node: root.into(),
                kind: "ip".into(),
                entry_time: 10,
                root_cost: 2.0,
            },
            arcs,
            collected: vec![],
            dropped: vec![],
            connectors: vec![],
            tactics: vec![],
            prize,
            cost,
        }
    }

    #[test]
    fn a_sound_tree_has_no_problems() {
        let t = tree(
            "r",
            vec![
                arc("r", "a", "recv", 10, 1.0),
                arc("a", "t", "start", 20, 1.5),
            ],
            8.0,
            4.5,
        );
        assert!(verify(&inst(), &t).is_empty());
    }

    #[test]
    fn root_must_be_a_candidate_and_have_no_incoming() {
        let mut i = inst();
        i.nodes[0].root_cost = None;
        let t = tree("r", vec![arc("r", "a", "recv", 10, 1.0)], 0.0, 1.0);
        assert!(verify(&i, &t).contains(&Problem::RootNotCandidate { node: "r".into() }));

        let i = inst();
        let t = tree(
            "a",
            vec![
                arc("a", "t", "start", 20, 1.5),
                arc("r", "a", "recv", 10, 1.0),
            ],
            8.0,
            8.5,
        );
        assert!(verify(&i, &t).contains(&Problem::RootHasIncoming { node: "a".into() }));
    }

    #[test]
    fn in_degree_two_is_flagged() {
        let mut i = inst();
        i.arcs.push(Arc::point("r", "t", "recv", 30, 1.0));
        let t = tree(
            "r",
            vec![
                arc("r", "a", "recv", 10, 1.0),
                arc("a", "t", "start", 20, 1.5),
                arc("r", "t", "recv", 30, 1.0),
            ],
            8.0,
            5.5,
        );
        assert!(
            verify(&i, &t)
                .iter()
                .any(|p| matches!(p, Problem::InDegree { node, count: 2 } if node == "t"))
        );
    }

    #[test]
    fn backwards_time_is_flagged() {
        let mut i = inst();
        i.arcs[1].lo = 5;
        i.arcs[1].hi = 5;
        let t = tree(
            "r",
            vec![
                arc("r", "a", "recv", 10, 1.0),
                arc("a", "t", "start", 5, 1.5),
            ],
            8.0,
            4.5,
        );
        assert!(verify(&i, &t).iter().any(|p| matches!(
            p,
            Problem::TimeViolation {
                theta: 11,
                hi: 5,
                ..
            }
        )));
    }

    #[test]
    fn objective_is_recomputed() {
        let t = tree(
            "r",
            vec![
                arc("r", "a", "recv", 10, 1.0),
                arc("a", "t", "start", 20, 1.5),
            ],
            7.0,
            4.5,
        );
        let p = verify(&inst(), &t);
        assert!(
            p.iter()
                .any(|p| matches!(p, Problem::ObjectiveMismatch { field, .. } if field == "prize"))
        );
    }

    #[test]
    fn disconnected_arc_is_unreachable() {
        let mut i = inst();
        i.nodes.push(Node::new("x", "process"));
        i.nodes.push(Node::new("y", "process"));
        i.arcs.push(Arc::point("x", "y", "start", 50, 1.0));
        let t = tree(
            "r",
            vec![
                arc("r", "a", "recv", 10, 1.0),
                arc("x", "y", "start", 50, 1.0),
            ],
            0.0,
            4.0,
        );
        assert!(verify(&i, &t).contains(&Problem::Unreachable { node: "x".into() }));
    }

    #[test]
    fn schedule_assigns_earliest_feasible_times() {
        let arcs = [("r", "a", 0, 100), ("a", "b", 0, 100), ("b", "c", 50, 60)];
        assert_eq!(schedule(1, "r", &arcs).unwrap(), vec![0, 1, 50]);
        let bad = [("r", "a", 70, 70), ("a", "b", 50, 60)];
        assert!(matches!(
            schedule(1, "r", &bad),
            Err(Problem::TimeViolation {
                theta: 71,
                hi: 60,
                ..
            })
        ));
    }
}
