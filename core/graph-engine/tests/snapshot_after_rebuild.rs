//! Removing a dataset and compacting old edges rebuild the edge store. A
//! hunt that ran before either one must not leave the matcher reading the
//! edges as they were: the snapshot it reads is cached until a mutation
//! drops it, and these two rebuilds did not.

use std::sync::Arc;

use graph_hunter_core::{
    Entity, EntityType, GraphHunter, Hypothesis, HypothesisStep, Relation, RelationType,
};

fn execute() -> Hypothesis {
    Hypothesis::new("execute").add_step(HypothesisStep::new(
        EntityType::User,
        RelationType::Execute,
        EntityType::Process,
    ))
}

fn graph() -> GraphHunter {
    let mut g = GraphHunter::new();
    g.add_entity(Entity::new("alice@example.com", EntityType::User))
        .unwrap();
    g.add_entity(Entity::new("p", EntityType::Process)).unwrap();
    for (t, ds) in [(100, "edr"), (200, "edr"), (300, "sentinel")] {
        let mut rel = Relation::new("alice@example.com", "p", RelationType::Execute, t);
        rel.dataset_id = Some(Arc::from(ds));
        g.add_relation(rel).unwrap();
    }
    g.sort_edges_by_timestamp().unwrap();
    g
}

fn matches(g: &GraphHunter) -> usize {
    g.search_temporal_pattern(&execute(), None, None)
        .unwrap()
        .0
        .len()
}

#[test]
fn a_removed_dataset_stops_matching() {
    let mut g = graph();
    assert_eq!(matches(&g), 3);
    g.remove_entities_and_relations_by_dataset("edr").unwrap();
    assert_eq!(matches(&g), 1);
}

#[test]
fn compacted_edges_are_what_the_matcher_reads() {
    let mut g = graph();
    assert_eq!(matches(&g), 3);
    // All three edges of the pair are older than 400, so they collapse
    // into one summary edge.
    g.compact_before(400).unwrap();
    assert_eq!(matches(&g), 1);
}
