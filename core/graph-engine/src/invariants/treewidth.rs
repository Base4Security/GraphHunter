//! Treewidth estimator for the invariant report.
//!
//! Operates on the **type quotient graph** — the multigraph where each
//! node is a distinct [`EntityType`] and each relation is projected to
//! `(src_type, dst_type)`. This keeps the problem tiny (≤ 30 node types
//! in practice) so an exact bound by a min-degree heuristic runs in
//! milliseconds even over graphs with millions of instance edges.
//!
//! Method: **min-degree elimination heuristic** (a.k.a. the min-fill
//! upper bound's simpler cousin). Exact treewidth is NP-hard; we ship
//! an upper bound and tag the output `method: "min-degree-quotient"`
//! so callers never confuse it for the exact value.

use std::collections::{HashMap, HashSet};

use crate::entity::Entity;
use crate::relation::Relation;
use crate::types::EntityType;

use super::TreewidthEstimate;

/// Build the type quotient and run the min-degree elimination
/// heuristic. Returns an upper bound on the treewidth of the quotient
/// graph.
pub fn estimate_treewidth(entities: &[Entity], relations: &[Relation]) -> TreewidthEstimate {
    // ── 1. Project to the quotient graph ─────────────────────────
    let type_of: HashMap<&str, &EntityType> = entities
        .iter()
        .map(|e| (e.id.as_str(), &e.entity_type))
        .collect();

    let mut nodes: HashSet<String> = entities.iter().map(|e| e.entity_type.to_string()).collect();

    // Adjacency as a HashSet<String> per type-key, undirected.
    let mut adj: HashMap<String, HashSet<String>> = HashMap::new();
    for r in relations {
        let (Some(src_t), Some(dst_t)) = (
            type_of.get(r.source_id.as_str()),
            type_of.get(r.dest_id.as_str()),
        ) else {
            continue;
        };
        let s = src_t.to_string();
        let d = dst_t.to_string();
        nodes.insert(s.clone());
        nodes.insert(d.clone());
        if s != d {
            adj.entry(s.clone()).or_default().insert(d.clone());
            adj.entry(d).or_default().insert(s);
        }
    }

    let quotient_node_count = nodes.len();
    let quotient_edge_count: usize = adj.values().map(|s| s.len()).sum::<usize>() / 2;

    if quotient_node_count == 0 {
        return TreewidthEstimate {
            value: 0,
            method: "min-degree-quotient".to_string(),
            quotient_node_count,
            quotient_edge_count,
        };
    }

    // ── 2. Min-degree elimination heuristic ──────────────────────
    // Work on owned copies so we can mutate during elimination.
    let mut alive: HashSet<String> = nodes.clone();
    let mut edges: HashMap<String, HashSet<String>> = HashMap::with_capacity(nodes.len());
    for n in &nodes {
        edges.insert(n.clone(), adj.get(n).cloned().unwrap_or_default());
    }

    let mut max_width: usize = 0;
    while let Some(v) = alive
        .iter()
        .min_by_key(|n| edges.get(n.as_str()).map(|s| s.len()).unwrap_or(0))
        .cloned()
    {
        let neighbours: Vec<String> = edges
            .get(&v)
            .cloned()
            .unwrap_or_default()
            .into_iter()
            .filter(|n| alive.contains(n))
            .collect();
        max_width = max_width.max(neighbours.len());

        // Fill: connect every pair of v's neighbours.
        for i in 0..neighbours.len() {
            for j in (i + 1)..neighbours.len() {
                let a = &neighbours[i];
                let b = &neighbours[j];
                edges.entry(a.clone()).or_default().insert(b.clone());
                edges.entry(b.clone()).or_default().insert(a.clone());
            }
        }

        // Remove v from the live set and from its neighbours' lists.
        alive.remove(&v);
        for n in &neighbours {
            if let Some(set) = edges.get_mut(n) {
                set.remove(&v);
            }
        }
    }

    TreewidthEstimate {
        value: max_width,
        method: "min-degree-quotient".to_string(),
        quotient_node_count,
        quotient_edge_count,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{EntityType, RelationType};

    fn ent(id: &str, t: EntityType) -> Entity {
        Entity::new(id, t)
    }
    fn rel(src: &str, dst: &str, ts: i64) -> Relation {
        Relation::new(src, dst, RelationType::Connect, ts)
    }

    #[test]
    fn empty_graph_reports_zero() {
        let est = estimate_treewidth(&[], &[]);
        assert_eq!(est.value, 0);
        assert_eq!(est.method, "min-degree-quotient");
        assert_eq!(est.quotient_node_count, 0);
        assert_eq!(est.quotient_edge_count, 0);
    }

    #[test]
    fn single_type_graph_has_tw_zero() {
        // All hosts, many edges: quotient collapses to 1 node + 0 edges
        // (the min-degree heuristic never sees a neighbour).
        let entities = vec![
            ent("h1", EntityType::Host),
            ent("h2", EntityType::Host),
            ent("h3", EntityType::Host),
        ];
        let relations = vec![rel("h1", "h2", 1), rel("h2", "h3", 2)];
        let est = estimate_treewidth(&entities, &relations);
        assert_eq!(est.value, 0);
        assert_eq!(est.quotient_node_count, 1);
        assert_eq!(est.quotient_edge_count, 0);
    }

    #[test]
    fn chain_types_have_tw_one() {
        // User — Host — Process (3 types, 2 edges).
        // Path graphs have tw = 1.
        let entities = vec![
            ent("alice", EntityType::User),
            ent("dc-01", EntityType::Host),
            ent("cmd.exe", EntityType::Process),
        ];
        let relations = vec![rel("alice", "dc-01", 1), rel("dc-01", "cmd.exe", 2)];
        let est = estimate_treewidth(&entities, &relations);
        assert_eq!(est.value, 1);
        assert_eq!(est.quotient_node_count, 3);
        assert_eq!(est.quotient_edge_count, 2);
    }

    #[test]
    fn triangle_of_types_has_tw_two() {
        // User — Host, Host — Process, Process — User forms a K3 in
        // the quotient. tw(K3) = 2.
        let entities = vec![
            ent("alice", EntityType::User),
            ent("dc-01", EntityType::Host),
            ent("cmd.exe", EntityType::Process),
        ];
        let relations = vec![
            rel("alice", "dc-01", 1),
            rel("dc-01", "cmd.exe", 2),
            rel("cmd.exe", "alice", 3),
        ];
        let est = estimate_treewidth(&entities, &relations);
        assert_eq!(est.value, 2);
        assert_eq!(est.quotient_edge_count, 3);
    }

    #[test]
    fn method_tag_is_always_set() {
        let est = estimate_treewidth(&[], &[]);
        assert!(est.method.starts_with("min-degree"));
    }
}
