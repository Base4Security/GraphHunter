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
        g.add_entity(Entity::new(leaf.clone(), EntityType::IP))
            .unwrap();
        g.add_relation(Relation::new(
            center,
            leaf,
            RelationType::Connect,
            100 + i as i64,
        ))
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

/// Regression: 64 unique targets sharing one (source, rel_type, target_type)
/// must collapse into ONE grouped row with count=64, not 64 rows with
/// count=1. This was the bug the analyst observed on "Carlos null" — 64
/// unique action-string leaves returning as 64 separate count=1 edges.
#[test]
fn grouped_neighborhood_collapses_same_type_fanout() {
    let g = graph_with_fanout("carlos-null", 64);
    let grouped = g
        .get_neighborhood_grouped("carlos-null", 1, 200, None)
        .expect("center present");

    // All 64 leaves are IPs reached by Connect → one group.
    assert_eq!(
        grouped.edges.len(),
        1,
        "expected 1 collapsed group, got {} edges",
        grouped.edges.len()
    );
    let edge = &grouped.edges[0];
    assert_eq!(edge.source, "carlos-null");
    assert_eq!(edge.count, 64);
    assert_eq!(edge.rel_type, "Connect");
    assert_eq!(edge.target_entity_type.as_deref(), Some("IP"));
    // `targets` is capped but must carry a representative sample.
    assert!(
        !edge.targets.is_empty(),
        "targets sample should be populated"
    );
    assert!(
        edge.targets.len() <= 20,
        "targets sample capped at 20, got {}",
        edge.targets.len()
    );
    // Back-compat: `target` is the synthetic "{type} (×N)" label when
    // distinct > 1.
    assert!(edge.target.contains("IP"));
    assert!(edge.target.contains("64"));
    assert_eq!(grouped.total_edge_count, 64);
}

#[test]
fn grouped_neighborhood_single_target_keeps_id_in_target_field() {
    // When a group covers exactly one distinct target, back-compat demands
    // the `target` field carries that id (not the synthetic label).
    let g = graph_with_fanout("host-tiny", 1);
    let grouped = g
        .get_neighborhood_grouped("host-tiny", 1, 10, None)
        .expect("center present");
    assert_eq!(grouped.edges.len(), 1);
    assert_eq!(grouped.edges[0].target, "leaf-00000");
    assert_eq!(grouped.edges[0].count, 1);
}
