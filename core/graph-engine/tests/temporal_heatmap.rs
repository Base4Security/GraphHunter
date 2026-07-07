//! Integration tests for `GraphHunter::temporal_heatmap` after the 1.D
//! densification change: bucket_size parameter and explicit zero buckets.

use graph_hunter_core::{Entity, EntityType, GraphHunter, Relation, RelationType};

fn graph_with_relations(edges: &[(&str, &str, RelationType, i64)]) -> GraphHunter {
    let mut g = GraphHunter::new();
    for (src, dst, _, _) in edges {
        for id in [*src, *dst] {
            if g.get_entity(id).is_none() {
                g.add_entity(Entity::new(id, EntityType::Host)).unwrap();
            }
        }
    }
    for (src, dst, rel, ts) in edges {
        g.add_relation(Relation::new(*src, *dst, rel.clone(), *ts))
            .unwrap();
    }
    g
}

#[test]
fn default_bucket_is_one_hour() {
    let g = graph_with_relations(&[
        ("a", "b", RelationType::Connect, 0),
        ("a", "b", RelationType::Connect, 3600),
    ]);
    let rows = g.temporal_heatmap(None);
    assert_eq!(rows.len(), 1);
    let (_rel, _bins, bucket) = &rows[0];
    assert_eq!(*bucket, 3600);
}

#[test]
fn zero_buckets_are_emitted_between_first_and_last_event() {
    // Two events 3 hours apart with a 1-hour bucket → must see 3 buckets:
    // the first, two zero-count middle buckets, then the last. This is the
    // exact behavior the post-hunt feedback said was missing.
    let g = graph_with_relations(&[
        ("a", "b", RelationType::Connect, 0),
        ("a", "b", RelationType::Connect, 3 * 3600),
    ]);
    let rows = g.temporal_heatmap(None);
    let (_, bins, _) = &rows[0];
    assert_eq!(bins.len(), 4);
    assert_eq!(bins[0], (0, 1));
    assert_eq!(bins[1], (3600, 0));
    assert_eq!(bins[2], (7200, 0));
    assert_eq!(bins[3], (10800, 1));
}

#[test]
fn custom_bucket_size_is_honored() {
    let g = graph_with_relations(&[
        ("a", "b", RelationType::Connect, 0),
        ("a", "b", RelationType::Connect, 900), // +15 min
    ]);
    // 5-minute buckets: 15min / 5min = 3 buckets, need to see 4 bins (first + 2 zeros + last).
    let rows = g.temporal_heatmap(Some(300));
    let (_, bins, bucket) = &rows[0];
    assert_eq!(*bucket, 300);
    assert_eq!(bins.len(), 4);
    assert_eq!(bins[0], (0, 1));
    assert_eq!(bins[3], (900, 1));
}

#[test]
fn bucket_size_is_clamped_to_safe_range() {
    let g = graph_with_relations(&[("a", "b", RelationType::Connect, 0)]);
    // Below minimum → clamped to 60
    let rows_low = g.temporal_heatmap(Some(1));
    assert_eq!(rows_low[0].2, 60);
    // Above maximum → clamped to 86400
    let rows_high = g.temporal_heatmap(Some(1_000_000));
    assert_eq!(rows_high[0].2, 86_400);
}

#[test]
fn empty_graph_produces_no_rows() {
    let g = GraphHunter::new();
    let rows = g.temporal_heatmap(None);
    assert!(rows.is_empty());
}
