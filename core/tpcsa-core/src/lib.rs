//! Temporal Prize-Collecting Steiner Arborescence for attack-chain
//! reconstruction.
//!
//! Given a directed multigraph of timestamped events with prized alerts
//! and priced entry points, find the cheapest time-respecting
//! arborescence (or forest of `k`) that collects the most prize — alerts
//! that do not fit the causal story are left out rather than forced in.
//!
//! Pipeline ([`reconstruct`]): validate → [`temporal_prune`] → time-expanded
//! DAG → greedy forest → [`verify`] every tree → rank by tactic coverage →
//! declare ties → surface connectors. The greedy is the product; an
//! optional MILP certificate is produced out of process (see the
//! certification sidecar) and re-verified with the same [`verify`].

pub mod cost;
pub mod expand;
pub mod graph;
pub mod greedy;
pub mod instance;
pub mod prune;
pub mod rank;
pub mod report;
pub mod verify;

use std::collections::BTreeSet;

pub use cost::{DEFAULT_KAPPA, rarity_costs};
pub use greedy::GreedyOptions;
pub use instance::{Arc, Instance, InstanceError, Node, Time};
pub use prune::{PruneStats, temporal_prune};
pub use rank::{TIE_TOLERANCE, connectors, find_ties, rank_trees};
pub use report::{ArcReport, Connector, Reconstruction, RejectedTree, RootInfo, TreeReport};
pub use verify::{Problem, schedule, verify};

use expand::TeGraph;
use graph::Compiled;

#[derive(Clone, Debug)]
pub struct ReconstructOptions {
    pub greedy: GreedyOptions,
    pub tie_tolerance: f64,
}

impl Default for ReconstructOptions {
    fn default() -> Self {
        Self {
            greedy: GreedyOptions::default(),
            tie_tolerance: TIE_TOLERANCE,
        }
    }
}

/// End-to-end reconstruction on an instance. Trees that fail [`verify`]
/// are reported under `rejected`, never under `trees`.
pub fn reconstruct(
    inst: &Instance,
    opts: &ReconstructOptions,
) -> Result<Reconstruction, InstanceError> {
    inst.validate()?;
    let (pruned, pruning) = temporal_prune(inst)?;
    let g = Compiled::from_instance(&pruned)?;
    let te = TeGraph::build(&g);
    let raw = greedy::greedy_forest(&g, &te, &opts.greedy);

    let index = inst.index();
    let prize_of = |id: &str| index.get(id).map(|&i| inst.nodes[i].prize).unwrap_or(0.0);
    let kind_of = |id: &str| {
        index
            .get(id)
            .map(|&i| inst.nodes[i].kind.clone())
            .unwrap_or_default()
    };
    let all_terminals: Vec<&str> = inst.terminals().map(|n| n.id.as_str()).collect();

    let mut trees: Vec<TreeReport> = Vec::new();
    let mut rejected: Vec<RejectedTree> = Vec::new();
    for t in &raw {
        let root = &pruned.nodes[t.root as usize];
        // Arcs in BFS (root-to-leaf) order with scheduled times.
        let quads: Vec<(&str, &str, Time, Time)> = t
            .arcs
            .iter()
            .map(|&ai| {
                let a = &g.arcs[ai as usize];
                let orig = &pruned.arcs[a.orig];
                (orig.tail.as_str(), orig.head.as_str(), orig.lo, orig.hi)
            })
            .collect();
        let times = match schedule(inst.epsilon, &root.id, &quads) {
            Ok(v) => v,
            Err(p) => {
                rejected.push(RejectedTree {
                    root: root.id.clone(),
                    problems: vec![p],
                });
                continue;
            }
        };
        let mut arcs: Vec<ArcReport> = t
            .arcs
            .iter()
            .zip(times.iter())
            .map(|(&ai, &tm)| {
                let orig = &pruned.arcs[g.arcs[ai as usize].orig];
                ArcReport {
                    tail: orig.tail.clone(),
                    head: orig.head.clone(),
                    etype: orig.etype.clone(),
                    t: tm,
                    cost: orig.cost,
                }
            })
            .collect();
        arcs = bfs_order(&root.id, arcs);
        let collected: Vec<String> = t
            .collected
            .iter()
            .map(|&v| pruned.nodes[v as usize].id.clone())
            .collect();
        let in_tree: BTreeSet<&str> = collected.iter().map(String::as_str).collect();
        let dropped: Vec<String> = all_terminals
            .iter()
            .filter(|id| !in_tree.contains(*id))
            .map(|s| s.to_string())
            .collect();
        let tactics: BTreeSet<String> = collected
            .iter()
            .filter_map(|id| inst.nodes[index[id.as_str()]].tactic.clone())
            .collect();
        let mut report = TreeReport {
            rank: 0,
            root: RootInfo {
                node: root.id.clone(),
                kind: root.kind.clone(),
                entry_time: t.entry_time,
                root_cost: t.root_cost,
            },
            arcs,
            collected,
            dropped,
            connectors: Vec::new(),
            tactics: tactics.into_iter().collect(),
            prize: t.prize,
            cost: t.arc_cost + t.root_cost,
        };
        let problems = verify(inst, &report);
        if !problems.is_empty() {
            rejected.push(RejectedTree {
                root: report.root.node.clone(),
                problems,
            });
            continue;
        }
        report.connectors = connectors(&report, &prize_of, &kind_of);
        trees.push(report);
    }

    rank_trees(&mut trees);
    let ties = find_ties(&trees, opts.tie_tolerance);
    let total_prize = inst.total_prize();
    let collected_prize: f64 = trees.iter().map(|t| t.prize).sum();
    let cost: f64 = trees.iter().map(|t| t.cost).sum();
    let objective = cost + (total_prize - collected_prize);
    Ok(Reconstruction {
        trees,
        ties,
        pruning,
        objective,
        total_prize,
        rejected,
    })
}

/// Reorders arcs root-to-leaf (BFS by tail), keeping sibling order stable.
fn bfs_order(root: &str, arcs: Vec<ArcReport>) -> Vec<ArcReport> {
    let mut remaining: Vec<Option<ArcReport>> = arcs.into_iter().map(Some).collect();
    let mut out = Vec::with_capacity(remaining.len());
    let mut frontier: Vec<String> = vec![root.to_string()];
    while let Some(u) = frontier.first().cloned() {
        frontier.remove(0);
        for slot in remaining.iter_mut() {
            if slot.as_ref().is_some_and(|a| a.tail == u) {
                let a = slot.take().unwrap();
                frontier.push(a.head.clone());
                out.push(a);
            }
        }
    }
    // Anything unreachable (should not happen for a verified tree) is appended.
    out.extend(remaining.into_iter().flatten());
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn win10_like() -> Instance {
        // Two entry points: ip1 → implant (no prize) → {t1 c2, t2 cred}; ip2 → q0 → t3 lateral.
        // Plus a benign chrome subtree with many small prizes of one tactic.
        let mut i = Instance::new(1);
        i.nodes.push(Node::new("ip1", "ip").with_root_cost(2.0));
        i.nodes
            .push(Node::new("implant", "process").with_root_cost(6.0));
        i.nodes.push(
            Node::new("t1", "process")
                .with_root_cost(6.0)
                .with_prize(9.0)
                .with_tactic("command-and-control"),
        );
        i.nodes.push(
            Node::new("t2", "process")
                .with_root_cost(6.0)
                .with_prize(8.0)
                .with_tactic("credential-access"),
        );
        i.nodes.push(Node::new("ip2", "ip").with_root_cost(2.0));
        i.nodes.push(Node::new("q0", "process").with_root_cost(6.0));
        i.nodes.push(
            Node::new("t3", "process")
                .with_root_cost(6.0)
                .with_prize(8.0)
                .with_tactic("lateral-movement"),
        );
        i.nodes
            .push(Node::new("chrome", "process").with_root_cost(6.0));
        for j in 0..6 {
            i.nodes.push(
                Node::new(format!("tab{j}"), "process")
                    .with_root_cost(6.0)
                    .with_prize(4.0)
                    .with_tactic("execution"),
            );
        }
        i.arcs.push(Arc::point("ip1", "implant", "recv", 10, 1.0));
        i.arcs.push(Arc::point("implant", "t1", "start", 20, 1.0));
        i.arcs.push(Arc::point("implant", "t2", "start", 30, 1.0));
        i.arcs.push(Arc::point("ip2", "q0", "recv", 100, 1.0));
        i.arcs.push(Arc::point("q0", "t3", "start", 110, 1.0));
        for j in 0..6 {
            i.arcs.push(Arc::point(
                "chrome",
                format!("tab{j}"),
                "start",
                200 + j,
                1.0,
            ));
        }
        i
    }

    #[test]
    fn forest_ranks_attack_first_and_finds_the_connector() {
        let inst = win10_like();
        let r = reconstruct(
            &inst,
            &ReconstructOptions {
                greedy: GreedyOptions {
                    k: 3,
                    ..Default::default()
                },
                ..Default::default()
            },
        )
        .unwrap();
        assert!(r.rejected.is_empty(), "{:?}", r.rejected);
        assert_eq!(r.trees.len(), 3);
        let roots: Vec<&str> = r.trees.iter().map(|t| t.root.node.as_str()).collect();
        // The attack tree covers 2 tactics. chrome (24/12) and ip2 (8/4)
        // tie at prize/cost = 2.0 with one tactic each; prize breaks it.
        assert_eq!(roots, vec!["ip1", "chrome", "ip2"]);
        assert_eq!(
            r.trees[0].tactics,
            vec!["command-and-control", "credential-access"]
        );
        assert_eq!(r.trees[0].connectors.len(), 1);
        assert_eq!(r.trees[0].connectors[0].node, "implant");
        assert_eq!(r.trees[0].connectors[0].terminal_children, 2);
        assert_eq!(r.trees[0].collected, vec!["t1", "t2"]);
        assert!(r.trees[0].dropped.contains(&"t3".to_string()));
        assert_eq!(r.trees[0].root.entry_time, 10);
        // Arcs come root-first with scheduled times.
        assert_eq!(r.trees[0].arcs[0].tail, "ip1");
        assert_eq!(r.trees[0].arcs[0].t, 10);
    }

    #[test]
    fn objective_uses_the_paper_convention() {
        let inst = win10_like();
        let r = reconstruct(
            &inst,
            &ReconstructOptions {
                greedy: GreedyOptions {
                    k: 1,
                    ..Default::default()
                },
                ..Default::default()
            },
        )
        .unwrap();
        // One tree (ip1): cost 3 arcs + 2 root = 5; uncollected = 8 + 24 = 32 → 37.
        assert_eq!(r.trees.len(), 1);
        assert!((r.objective - 37.0).abs() < 1e-9, "{}", r.objective);
        assert_eq!(r.total_prize, 49.0);
        assert_eq!(r.pruning.arcs_before, 11);
    }

    #[test]
    fn empty_instance_gives_empty_result() {
        let inst = Instance::new(1);
        let r = reconstruct(&inst, &ReconstructOptions::default()).unwrap();
        assert!(r.trees.is_empty());
        assert_eq!(r.objective, 0.0);
    }
}
