//! A hunt over a graph whose edges were never sorted must answer the same as
//! one over the sorted graph. The matcher bounds each step's time range with
//! a binary search over the vertex's edges, which is only correct when they
//! are in timestamp order; `sort_edges_by_timestamp` is the documented way to
//! get there, but nothing forced callers to run it, and a graph built straight
//! from `add_relation` / `ingest_logs` kept its arrival order.

use graph_hunter_core::{
    Entity, EntityType, GraphHunter, Hypothesis, HypothesisStep, Relation, RelationType,
};

fn chain() -> Hypothesis {
    Hypothesis::new("execute-then-spawn")
        .add_step(HypothesisStep::new(
            EntityType::User,
            RelationType::Execute,
            EntityType::Process,
        ))
        .add_step(HypothesisStep::new(
            EntityType::Process,
            RelationType::Spawn,
            EntityType::Process,
        ))
}

fn ends(g: &GraphHunter) -> Vec<String> {
    let (paths, _) = g.search_temporal_pattern(&chain(), None, None).unwrap();
    let mut out: Vec<String> = paths
        .iter()
        .map(|p| p.last().unwrap().to_string())
        .collect();
    out.sort();
    out
}

/// alice runs p1 at t=100. p1 spawns p3 at t=300 (a valid next step) and p2
/// at t=50 (before p1 ran, so not a chain). The later edge arrives first.
fn unsorted_graph() -> GraphHunter {
    let mut g = GraphHunter::new();
    g.add_entity(Entity::new("alice@example.com", EntityType::User))
        .unwrap();
    for p in ["p1", "p2", "p3"] {
        g.add_entity(Entity::new(p, EntityType::Process)).unwrap();
    }
    for (s, d, r, t) in [
        ("alice@example.com", "p1", RelationType::Execute, 100),
        ("p1", "p3", RelationType::Spawn, 300),
        ("p1", "p2", RelationType::Spawn, 50),
    ] {
        g.add_relation(Relation::new(s, d, r, t)).unwrap();
    }
    g
}

#[test]
fn a_never_sorted_graph_keeps_the_temporal_order() {
    let g = unsorted_graph();
    assert_eq!(ends(&g), vec!["p3".to_string()]);
}

#[test]
fn sorting_does_not_change_the_answer() {
    let unsorted = unsorted_graph();
    let mut sorted = unsorted_graph();
    sorted.sort_edges_by_timestamp().unwrap();
    assert_eq!(ends(&unsorted), ends(&sorted));
}

/// A hub whose edges arrive in a scrambled order: every Spawn at or after the
/// Execute is a match, every earlier one is not, whatever the arrival order.
#[test]
fn a_scrambled_hub_matches_exactly_the_later_edges() {
    let mut g = GraphHunter::new();
    g.add_entity(Entity::new("alice@example.com", EntityType::User))
        .unwrap();
    g.add_entity(Entity::new("hub", EntityType::Process))
        .unwrap();
    g.add_relation(Relation::new(
        "alice@example.com",
        "hub",
        RelationType::Execute,
        500,
    ))
    .unwrap();
    // 0..40 scrambled by a fixed stride; timestamps 25 apart straddle 500.
    let mut expected = Vec::new();
    for i in 0..40u32 {
        let k = (i * 17) % 40;
        let child = format!("c{k:02}");
        let ts = i64::from(k) * 25;
        g.add_entity(Entity::new(&child, EntityType::Process))
            .unwrap();
        g.add_relation(Relation::new("hub", &child, RelationType::Spawn, ts))
            .unwrap();
        if ts >= 500 {
            expected.push(child);
        }
    }
    expected.sort();
    assert_eq!(ends(&g), expected);
}
