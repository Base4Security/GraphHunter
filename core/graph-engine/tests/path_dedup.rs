//! Integration tests for `DedupMode` in `score_and_paginate_paths`.
//! Mirrors the exact scenario from the post-hunt feedback §1.3 where
//! 2,523 raw paths should collapse to ~10 rows with edge_count populated.

use graph_hunter_core::{DedupMode, Entity, EntityType, GraphHunter, Relation, RelationType};

fn tiny_graph() -> GraphHunter {
    let mut g = GraphHunter::new();
    for id in ["u", "a", "b", "x"] {
        let et = if id == "u" {
            EntityType::User
        } else {
            EntityType::Process
        };
        g.add_entity(Entity::new(id, et)).unwrap();
    }
    // Multiple edges between (u,a) and (u,b) simulating 1835 identical
    // root→/usr/bin/grep hits.
    for t in 0..5 {
        g.add_relation(Relation::new("u", "a", RelationType::Execute, 100 + t))
            .unwrap();
    }
    for t in 0..3 {
        g.add_relation(Relation::new("u", "b", RelationType::Execute, 200 + t))
            .unwrap();
    }
    g.add_relation(Relation::new("u", "x", RelationType::Execute, 300))
        .unwrap();
    g
}

#[test]
fn dedup_by_path_collapses_identical_paths() {
    let g = tiny_graph();

    // Simulate what run_hunt would return: one path per raw edge, so
    // 5 identical (u,a) paths, 3 identical (u,b) paths, 1 (u,x) path.
    let paths: Vec<Vec<String>> = std::iter::repeat(vec!["u".into(), "a".into()])
        .take(5)
        .chain(std::iter::repeat(vec!["u".into(), "b".into()]).take(3))
        .chain(std::iter::once(vec!["u".into(), "x".into()]))
        .collect();

    let (scored, total) = g.score_and_paginate_paths(&paths, 0, 50, None, DedupMode::ByPath);

    // Three distinct paths; the 9 raw rows collapsed to 3.
    assert_eq!(total, 3, "ByPath must dedup to 3 distinct rows");
    assert_eq!(scored.len(), 3);

    let find_path = |needle_last: &str| {
        scored
            .iter()
            .find(|sp| sp.path.last().map(|s| s.as_str()) == Some(needle_last))
            .unwrap_or_else(|| panic!("missing path ending in {needle_last}"))
    };
    assert_eq!(find_path("a").edge_count, 5);
    assert_eq!(find_path("b").edge_count, 3);
    assert_eq!(find_path("x").edge_count, 1);
}

#[test]
fn dedup_none_preserves_all_rows() {
    let g = tiny_graph();
    let paths: Vec<Vec<String>> = std::iter::repeat(vec!["u".into(), "a".into()])
        .take(5)
        .collect();
    let (scored, total) = g.score_and_paginate_paths(&paths, 0, 50, None, DedupMode::None);
    assert_eq!(total, 5);
    assert_eq!(scored.len(), 5);
    for sp in scored {
        assert_eq!(sp.edge_count, 1);
    }
}

#[test]
fn dedup_by_endpoints_collapses_across_different_intermediates() {
    let mut g = GraphHunter::new();
    for id in ["a", "m1", "m2", "z"] {
        g.add_entity(Entity::new(id, EntityType::Host)).unwrap();
    }
    g.add_relation(Relation::new("a", "m1", RelationType::Connect, 10))
        .unwrap();
    g.add_relation(Relation::new("m1", "z", RelationType::Connect, 20))
        .unwrap();
    g.add_relation(Relation::new("a", "m2", RelationType::Connect, 30))
        .unwrap();
    g.add_relation(Relation::new("m2", "z", RelationType::Connect, 40))
        .unwrap();

    // Two distinct paths, same endpoints (a..z).
    let paths: Vec<Vec<String>> = vec![
        vec!["a".into(), "m1".into(), "z".into()],
        vec!["a".into(), "m2".into(), "z".into()],
    ];

    let (scored, total) = g.score_and_paginate_paths(&paths, 0, 50, None, DedupMode::ByEndpoints);
    assert_eq!(total, 1);
    assert_eq!(scored.len(), 1);
    assert_eq!(scored[0].edge_count, 2);
    // The first-seen representative survives.
    assert_eq!(
        scored[0].path,
        vec!["a".to_string(), "m1".to_string(), "z".to_string()]
    );
}

#[test]
fn chain_summary_preserves_full_ids_for_emails_and_fqdns() {
    // Regression for the A.2 truncation bug: IDs longer than 20 chars
    // used to lose their first character because the label builder kept
    // the last 20 bytes (`len - 20..`). Synthetic example mirroring the
    // original 21-char ID: "analyst.a@example.com" (21 chars) used to
    // render as "nalyst.a@example.com".
    let mut g = GraphHunter::new();
    g.add_entity(Entity::new("analyst.a@example.com", EntityType::User))
        .unwrap();
    g.add_entity(Entity::new("analyst.b@example.com", EntityType::User))
        .unwrap();
    g.add_entity(Entity::new("1.2.3.4", EntityType::IP))
        .unwrap();
    g.add_relation(Relation::new(
        "analyst.a@example.com",
        "1.2.3.4",
        RelationType::Auth,
        100,
    ))
    .unwrap();
    g.add_relation(Relation::new(
        "analyst.b@example.com",
        "1.2.3.4",
        RelationType::Auth,
        200,
    ))
    .unwrap();

    let paths: Vec<Vec<String>> = vec![
        vec!["analyst.a@example.com".into(), "1.2.3.4".into()],
        vec!["analyst.b@example.com".into(), "1.2.3.4".into()],
    ];
    let (scored, _) = g.score_and_paginate_paths(&paths, 0, 50, None, DedupMode::None);
    for sp in scored {
        assert!(
            sp.chain_summary.contains("analyst.a@") || sp.chain_summary.contains("analyst.b@"),
            "chain_summary dropped the first char, got: {}",
            sp.chain_summary
        );
        assert!(
            !sp.chain_summary.starts_with("nalyst."),
            "chain_summary still left-truncates: {}",
            sp.chain_summary
        );
    }
}

#[test]
fn dedup_with_pagination_respects_page_size_on_deduped_list() {
    let g = tiny_graph();
    let paths: Vec<Vec<String>> = std::iter::repeat(vec!["u".into(), "a".into()])
        .take(5)
        .chain(std::iter::repeat(vec!["u".into(), "b".into()]).take(3))
        .chain(std::iter::once(vec!["u".into(), "x".into()]))
        .collect();

    let (page0, total) = g.score_and_paginate_paths(&paths, 0, 2, None, DedupMode::ByPath);
    assert_eq!(total, 3, "total reports deduped count, not raw");
    assert_eq!(page0.len(), 2);
    let (page1, _) = g.score_and_paginate_paths(&paths, 1, 2, None, DedupMode::ByPath);
    assert_eq!(page1.len(), 1);
}
