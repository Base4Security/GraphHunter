//! Integration tests for the auto-grouped-expansion hint on
//! `NodeDetails.recommend_grouped_expansion` and the default shape of
//! `Neighborhood.auto_grouped`. The Tauri command `cmd_expand_node`
//! consumes both; these tests nail down the engine contract it relies on.

use graph_hunter_core::{
    AUTO_GROUPED_THRESHOLD, Entity, EntityType, GraphHunter, Relation, RelationType,
};

fn graph_with_fanout(center: &str, fanout: usize) -> GraphHunter {
    let mut g = GraphHunter::new();
    g.add_entity(Entity::new(center, EntityType::Host)).unwrap();
    for i in 0..fanout {
        let leaf = format!("leaf-{i:05}");
        g.add_entity(Entity::new(leaf.clone(), EntityType::IP)).unwrap();
        g.add_relation(Relation::new(center, leaf, RelationType::Connect, 100 + i as i64))
            .unwrap();
    }
    g
}

#[test]
fn recommend_grouped_expansion_is_false_below_threshold() {
    let g = graph_with_fanout("host-a", 10);
    let details = g.get_node_details("host-a").expect("node present");
    assert_eq!(details.out_degree, 10);
    assert!(!details.recommend_grouped_expansion);
}

#[test]
fn recommend_grouped_expansion_is_true_above_threshold() {
    let fanout = AUTO_GROUPED_THRESHOLD + 50;
    let g = graph_with_fanout("host-big", fanout);
    let details = g.get_node_details("host-big").expect("node present");
    assert_eq!(details.out_degree, fanout);
    assert!(details.recommend_grouped_expansion);
}

#[test]
fn recommend_grouped_boundary_is_strict() {
    // Exactly AT the threshold should NOT trigger (we use `>` not `>=`).
    let g = graph_with_fanout("host-boundary", AUTO_GROUPED_THRESHOLD);
    let details = g.get_node_details("host-boundary").expect("node present");
    assert_eq!(details.out_degree, AUTO_GROUPED_THRESHOLD);
    assert!(!details.recommend_grouped_expansion);
}

#[test]
fn plain_neighborhood_is_not_flagged_auto_grouped() {
    // Sanity: the engine's raw neighborhood call always returns
    // auto_grouped=false; only the command layer flips it.
    let g = graph_with_fanout("host-a", 5);
    let hood = g.get_neighborhood("host-a", 1, 100, None).expect("present");
    assert!(!hood.auto_grouped);
    assert!(hood.auto_group_reason.is_none());
}
