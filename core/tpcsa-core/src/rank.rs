//! Ranking, ties and connectors over verified trees.
//!
//! Trees are ordered by how many distinct ATT&CK tactics they cover,
//! then by prize/cost. Never by prize alone: on both of the paper's
//! datasets prize ranking put the attack third and tactic coverage put
//! it first. Two trees whose net gain is within 1 % are declared a tie —
//! the difference between "this is the chain" and "two hypotheses fit
//! this evidence".

use std::collections::HashMap;

use crate::report::{Connector, TreeReport};

pub const TIE_TOLERANCE: f64 = 0.01;

fn ratio(t: &TreeReport) -> f64 {
    if t.cost > 0.0 {
        t.prize / t.cost
    } else {
        f64::INFINITY
    }
}

/// Sorts in place and assigns 1-based ranks.
pub fn rank_trees(trees: &mut [TreeReport]) {
    trees.sort_by(|a, b| {
        b.tactics
            .len()
            .cmp(&a.tactics.len())
            .then(ratio(b).total_cmp(&ratio(a)))
            .then(b.prize.total_cmp(&a.prize))
            .then(a.root.node.cmp(&b.root.node))
    });
    for (i, t) in trees.iter_mut().enumerate() {
        t.rank = i + 1;
    }
}

/// Pairs of ranks whose net gain differs by at most `tol` (relative to
/// the larger magnitude).
pub fn find_ties(trees: &[TreeReport], tol: f64) -> Vec<(usize, usize)> {
    let mut ties = Vec::new();
    for i in 0..trees.len() {
        for j in i + 1..trees.len() {
            let a = trees[i].net_gain();
            let b = trees[j].net_gain();
            let scale = a.abs().max(b.abs());
            if scale == 0.0 || (a - b).abs() <= tol * scale {
                ties.push((trees[i].rank, trees[j].rank));
            }
        }
    }
    ties
}

/// Nodes without a prize that have at least one terminal child, with
/// their terminal descendant count; sorted by descendants, then children,
/// then id.
pub fn connectors(
    tree: &TreeReport,
    prize_of: &dyn Fn(&str) -> f64,
    kind_of: &dyn Fn(&str) -> String,
) -> Vec<Connector> {
    let mut children: HashMap<&str, Vec<&str>> = HashMap::new();
    for a in &tree.arcs {
        children
            .entry(a.tail.as_str())
            .or_default()
            .push(a.head.as_str());
    }
    // Terminal descendants by post-order.
    fn desc<'a>(
        u: &'a str,
        children: &HashMap<&'a str, Vec<&'a str>>,
        prize_of: &dyn Fn(&str) -> f64,
        memo: &mut HashMap<&'a str, usize>,
    ) -> usize {
        if let Some(&d) = memo.get(u) {
            return d;
        }
        let mut total = 0;
        if let Some(cs) = children.get(u) {
            for c in cs {
                total += usize::from(prize_of(c) > 0.0) + desc(c, children, prize_of, memo);
            }
        }
        memo.insert(u, total);
        total
    }
    let mut memo = HashMap::new();
    let mut out: Vec<Connector> = Vec::new();
    for node in tree.nodes() {
        if prize_of(node) > 0.0 {
            continue;
        }
        let Some(cs) = children.get(node) else {
            continue;
        };
        let terminal_children = cs.iter().filter(|c| prize_of(c) > 0.0).count();
        if terminal_children == 0 {
            continue;
        }
        let terminal_descendants = desc(node, &children, prize_of, &mut memo);
        out.push(Connector {
            node: node.to_string(),
            kind: kind_of(node),
            terminal_children,
            terminal_descendants,
        });
    }
    out.sort_by(|a, b| {
        b.terminal_descendants
            .cmp(&a.terminal_descendants)
            .then(b.terminal_children.cmp(&a.terminal_children))
            .then(a.node.cmp(&b.node))
    });
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::report::{ArcReport, RootInfo};

    fn tree(root: &str, tactics: &[&str], prize: f64, cost: f64) -> TreeReport {
        TreeReport {
            rank: 0,
            root: RootInfo {
                node: root.into(),
                kind: "ip".into(),
                entry_time: 0,
                root_cost: 0.0,
            },
            arcs: vec![],
            collected: vec![],
            dropped: vec![],
            connectors: vec![],
            tactics: tactics.iter().map(|s| s.to_string()).collect(),
            prize,
            cost,
        }
    }

    #[test]
    fn tactic_coverage_beats_prize() {
        // The chrome-like tree has a huge prize but one tactic; the attack covers three.
        let mut trees = vec![
            tree("chrome", &["execution"], 1778.0, 200.0),
            tree(
                "attack",
                &["c2", "credential-access", "lateral-movement"],
                590.0,
                41.0,
            ),
            tree("third", &[], 100.0, 10.0),
        ];
        rank_trees(&mut trees);
        let order: Vec<&str> = trees.iter().map(|t| t.root.node.as_str()).collect();
        assert_eq!(order, vec!["attack", "chrome", "third"]);
        assert_eq!(trees[0].rank, 1);
        assert_eq!(trees[2].rank, 3);
    }

    #[test]
    fn equal_coverage_falls_back_to_prize_per_cost() {
        let mut trees = vec![tree("a", &["x"], 10.0, 5.0), tree("b", &["x"], 30.0, 10.0)];
        rank_trees(&mut trees);
        assert_eq!(trees[0].root.node, "b");
    }

    #[test]
    fn ties_within_one_percent_are_declared() {
        let mut trees = vec![
            tree("a", &["x"], 647.10, 0.0),
            tree("b", &["y"], 647.03, 0.0),
            tree("c", &["z"], 500.0, 0.0),
        ];
        rank_trees(&mut trees);
        let ties = find_ties(&trees, TIE_TOLERANCE);
        assert_eq!(ties, vec![(1, 2)]);
    }

    #[test]
    fn connectors_are_prize_less_parents_of_terminals() {
        let mut t = tree("ip", &[], 0.0, 0.0);
        let arc = |tail: &str, head: &str| ArcReport {
            tail: tail.into(),
            head: head.into(),
            etype: "start".into(),
            t: 0,
            cost: 1.0,
        };
        // ip → c2 → {t1, t2, mid → t3}; ip → benign
        t.arcs = vec![
            arc("ip", "c2"),
            arc("c2", "t1"),
            arc("c2", "t2"),
            arc("c2", "mid"),
            arc("mid", "t3"),
            arc("ip", "benign"),
        ];
        let prize = |n: &str| if n.starts_with('t') { 5.0 } else { 0.0 };
        let kind = |_: &str| "process".to_string();
        let cs = connectors(&t, &prize, &kind);
        let names: Vec<(&str, usize, usize)> = cs
            .iter()
            .map(|c| (c.node.as_str(), c.terminal_children, c.terminal_descendants))
            .collect();
        assert_eq!(names, vec![("c2", 2, 3), ("mid", 1, 1)]);
    }
}
