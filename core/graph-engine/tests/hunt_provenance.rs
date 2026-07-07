//! Integration test for PR 3 hunt-result provenance.
//!
//! Verifies that when a path crosses edges inserted from two different
//! datasets, the resulting [`ScoredPath::datasets_used`] lists both dataset
//! IDs — the signal the UI uses to show Source(s) badges.

use graph_hunter_core::{
    DedupMode, Entity, EntityType, GraphHunter, Hypothesis, HypothesisStep, Relation, RelationType,
};

#[test]
fn scored_path_reports_both_datasets_used() {
    let mut g = GraphHunter::new();

    // Dataset A: IP -[Connect]-> Host
    let triples_a = vec![(
        Entity::new("1.2.3.4", EntityType::IP),
        Relation::new("1.2.3.4", "host-01", RelationType::Connect, 100),
        Entity::new("host-01", EntityType::Host),
    )];
    g.insert_triples(triples_a, Some("dataset-alpha"))
        .expect("insert dataset-alpha");

    // Dataset B: Host -[Auth]-> User (shares host-01 with dataset A so the
    // path spans both datasets).
    let triples_b = vec![(
        Entity::new("host-01", EntityType::Host),
        Relation::new("host-01", "alice", RelationType::Auth, 200),
        Entity::new("alice", EntityType::User),
    )];
    g.insert_triples(triples_b, Some("dataset-beta"))
        .expect("insert dataset-beta");

    g.sort_edges_by_timestamp().expect("sort edges");

    let hyp = Hypothesis::new("cross-dataset")
        .add_step(HypothesisStep::new(
            EntityType::IP,
            RelationType::Connect,
            EntityType::Host,
        ))
        .add_step(HypothesisStep::new(
            EntityType::Host,
            RelationType::Auth,
            EntityType::User,
        ));

    let (paths, _) = g.search_temporal_pattern(&hyp, None, None).expect("search");
    assert!(!paths.is_empty(), "cross-dataset path must be found");

    let (scored, _) = g.score_and_paginate_paths(&paths, 0, 50, None, DedupMode::None);
    assert!(!scored.is_empty(), "ScoredPath must be produced");

    let sp = &scored[0];
    assert!(
        sp.datasets_used.contains(&"dataset-alpha".to_string()),
        "datasets_used missing dataset-alpha; got {:?}",
        sp.datasets_used
    );
    assert!(
        sp.datasets_used.contains(&"dataset-beta".to_string()),
        "datasets_used missing dataset-beta; got {:?}",
        sp.datasets_used
    );
}

#[test]
fn scored_path_datasets_used_empty_for_untagged_graph() {
    // When triples are inserted without a dataset_id, datasets_used stays
    // empty — the UI treats "no provenance" as "no badges to show" instead
    // of showing an empty chip that would look broken.
    let mut g = GraphHunter::new();
    let triples = vec![(
        Entity::new("1.2.3.4", EntityType::IP),
        Relation::new("1.2.3.4", "host-01", RelationType::Connect, 100),
        Entity::new("host-01", EntityType::Host),
    )];
    g.insert_triples(triples, None).expect("insert untagged");
    g.sort_edges_by_timestamp().expect("sort edges");

    let hyp = Hypothesis::new("untagged").add_step(HypothesisStep::new(
        EntityType::IP,
        RelationType::Connect,
        EntityType::Host,
    ));
    let (paths, _) = g.search_temporal_pattern(&hyp, None, None).expect("search");
    let (scored, _) = g.score_and_paginate_paths(&paths, 0, 50, None, DedupMode::None);
    assert!(!scored.is_empty());
    assert!(
        scored[0].datasets_used.is_empty(),
        "untagged graph must yield empty datasets_used"
    );
}
