//! Snapshot-equivalence test between `AnomalyScorer::score_path` (v1,
//! hardcoded) and `AnomalyScorer::score_path_v2` (trait-based,
//! P2-A).
//!
//! Exists to protect the migration story: v1 stays as-is for a
//! release, v2 ships in parallel, a future PR flips the default and
//! deletes v1. That flip is only safe if the two outputs are
//! bit-equivalent (modulo f64 precision) on real hypothesis graphs.
//!
//! If this test ever fails, DO NOT flip the default. First figure out
//! which component drifted and fix the component — the legacy scorer
//! is the canonical behavior until v2 fully replaces it.

use graph_hunter_core::{
    AnomalyScorer, Entity, EntityType, GraphHunter, Relation, RelationType, ScoringWeights,
};

const EPSILON: f64 = f64::EPSILON * 8.0;

/// Tiny handcrafted graph: 2 users auth to a host, host spawns cmd.exe,
/// one user runs powershell. Enough variety that every scoring
/// component contributes non-zero.
fn build_graph() -> GraphHunter {
    let mut g = GraphHunter::new();
    g.add_entity(Entity::new("alice", EntityType::User))
        .unwrap();
    g.add_entity(Entity::new("bob", EntityType::User)).unwrap();
    g.add_entity(Entity::new("web-01", EntityType::Host))
        .unwrap();
    g.add_entity(Entity::new("cmd.exe", EntityType::Process))
        .unwrap();
    g.add_entity(Entity::new("powershell.exe", EntityType::Process))
        .unwrap();

    g.add_relation(Relation::new(
        "alice".to_string(),
        "web-01".to_string(),
        RelationType::Auth,
        1_700_000_000,
    ))
    .unwrap();
    g.add_relation(Relation::new(
        "bob".to_string(),
        "web-01".to_string(),
        RelationType::Auth,
        1_700_000_100,
    ))
    .unwrap();
    g.add_relation(Relation::new(
        "web-01".to_string(),
        "cmd.exe".to_string(),
        RelationType::Execute,
        1_700_000_200,
    ))
    .unwrap();
    g.add_relation(Relation::new(
        "alice".to_string(),
        "powershell.exe".to_string(),
        RelationType::Execute,
        1_700_000_300,
    ))
    .unwrap();
    g
}

fn build_scorer(graph: &GraphHunter, weights: ScoringWeights) -> AnomalyScorer {
    let mut s = AnomalyScorer::new(weights);
    // Drive `observe_entity` / `observe_edge` the way ingestion would.
    for (_sid, entity) in graph.entities.iter() {
        s.observe_entity(&entity.id, 1_700_000_000);
    }
    // Walk every edge. Use source/dest SIDs to resolve ids.
    for (&sid, _entity) in &graph.entities {
        if let Some(arc) = graph.streaming.neighbors_arc(sid) {
            let g = arc.read();
            for edge in g.as_slice() {
                let src = graph.interner.resolve(sid).to_string();
                let dst = graph.interner.resolve(edge.dest_sid).to_string();
                s.observe_edge(&src, &dst);
            }
        }
    }
    s.finalize(graph);
    s
}

fn assert_near(label: &str, a: f64, b: f64) {
    assert!(
        (a - b).abs() <= EPSILON,
        "{label}: v1={a} vs v2={b} (|Δ|={} > ε={EPSILON})",
        (a - b).abs()
    );
}

#[test]
fn default_weights_produce_equivalent_scores() {
    let graph = build_graph();
    let scorer = build_scorer(&graph, ScoringWeights::default());

    // A handful of realistic paths the hunt engine would return.
    let paths: Vec<Vec<String>> = vec![
        vec!["alice".into(), "web-01".into(), "cmd.exe".into()],
        vec!["bob".into(), "web-01".into(), "cmd.exe".into()],
        vec!["alice".into(), "powershell.exe".into()],
        vec!["web-01".into()],
        vec![], // empty path — both must return zeros
    ];

    for path in &paths {
        let (c1, b1) = scorer.score_path(path, &graph);
        let (c2, b2) = scorer.score_path_v2(path, &graph);
        assert_near(&format!("composite for {path:?}"), c1, c2);
        assert_near("entity_rarity", b1.entity_rarity, b2.entity_rarity);
        assert_near("edge_rarity", b1.edge_rarity, b2.edge_rarity);
        assert_near(
            "neighborhood_concentration",
            b1.neighborhood_concentration,
            b2.neighborhood_concentration,
        );
        assert_near("temporal_novelty", b1.temporal_novelty, b2.temporal_novelty);
        assert_near("gnn_threat", b1.gnn_threat, b2.gnn_threat);
    }
}

#[test]
fn gnn_injected_scores_propagate_to_v2() {
    use ahash::{HashMap, HashMapExt};
    let graph = build_graph();
    let mut scorer = build_scorer(
        &graph,
        ScoringWeights {
            w1_entity_rarity: 0.2,
            w2_edge_rarity: 0.2,
            w3_neighborhood_conc: 0.2,
            w4_temporal_novelty: 0.2,
            w5_gnn_threat: 0.2,
        },
    );
    let mut gnn = HashMap::new();
    gnn.insert("alice".to_string(), 0.9);
    gnn.insert("web-01".to_string(), 0.3);
    gnn.insert("cmd.exe".to_string(), 0.1);
    scorer.set_gnn_scores(gnn);

    let path = vec!["alice".into(), "web-01".into(), "cmd.exe".into()];
    let (c1, b1) = scorer.score_path(&path, &graph);
    let (c2, b2) = scorer.score_path_v2(&path, &graph);
    assert_near("composite", c1, c2);
    assert_near("gnn_threat", b1.gnn_threat, b2.gnn_threat);
    // Sanity: the average is (0.9 + 0.3 + 0.1) / 3 = 0.4333...
    assert!(
        (b2.gnn_threat - (0.9 + 0.3 + 0.1) / 3.0).abs() < 1e-9,
        "gnn_threat unexpectedly drifted: {}",
        b2.gnn_threat
    );
}

#[test]
fn custom_weights_still_match() {
    // Non-uniform weights stress the Σ(wᵢ·cᵢ)/Σ(wᵢ) formula.
    let graph = build_graph();
    let scorer = build_scorer(
        &graph,
        ScoringWeights {
            w1_entity_rarity: 0.05,
            w2_edge_rarity: 0.60,
            w3_neighborhood_conc: 0.10,
            w4_temporal_novelty: 0.20,
            w5_gnn_threat: 0.05,
        },
    );
    let path = vec!["alice".into(), "web-01".into(), "cmd.exe".into()];
    let (c1, _) = scorer.score_path(&path, &graph);
    let (c2, _) = scorer.score_path_v2(&path, &graph);
    assert_near("composite with custom weights", c1, c2);
}

#[test]
fn non_finalized_scorer_returns_zero_in_both_paths() {
    let graph = build_graph();
    let scorer = AnomalyScorer::new(ScoringWeights::default());
    let path = vec!["alice".into(), "web-01".into()];
    // Not finalize()d — both code paths must short-circuit to 0.
    let (c1, _) = scorer.score_path(&path, &graph);
    let (c2, _) = scorer.score_path_v2(&path, &graph);
    assert_eq!(c1, 0.0);
    assert_eq!(c2, 0.0);
}
