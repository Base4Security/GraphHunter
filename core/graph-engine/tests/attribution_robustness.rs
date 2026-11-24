//! λ (records) and ρ (failure domains) for an attribution, on the shapes
//! the research protocol fixes: twin scenarios with the same topology,
//! times and verdict, whose robustness differs only in where the evidence
//! came from.

use std::sync::Arc;

use graph_hunter_core::robustness::{
    DomainBase, DomainSpec, RecordKey, RobustnessOptions, attribution_robustness,
};
use graph_hunter_core::{
    Entity, EntityType, GraphHunter, Hypothesis, HypothesisStep, Relation, RelationType,
};

fn execute_then_spawn() -> Hypothesis {
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

fn edge(s: &str, d: &str, r: RelationType, t: i64, dataset: &str) -> Relation {
    let mut rel = Relation::new(s, d, r, t);
    rel.dataset_id = Some(Arc::from(dataset));
    rel
}

/// `m` two-edge chains from alice to the target through distinct
/// processes. With `shared_first`, every first edge comes from dataset
/// "A"; otherwise all 2m edges come from their own dataset.
fn twin(m: usize, shared_first: bool) -> GraphHunter {
    let mut g = GraphHunter::new();
    g.add_entity(Entity::new("alice@example.com", EntityType::User))
        .unwrap();
    g.add_entity(Entity::new("target", EntityType::Process))
        .unwrap();
    for i in 0..m {
        let p = format!("p{i}");
        g.add_entity(Entity::new(&p, EntityType::Process)).unwrap();
        let first = if shared_first {
            "A".to_string()
        } else {
            format!("a{i}")
        };
        g.add_relation(edge(
            "alice@example.com",
            &p,
            RelationType::Execute,
            100,
            &first,
        ))
        .unwrap();
        g.add_relation(edge(
            &p,
            "target",
            RelationType::Spawn,
            200,
            &format!("b{i}"),
        ))
        .unwrap();
    }
    g
}

fn robustness(
    g: &GraphHunter,
    options: &RobustnessOptions,
) -> graph_hunter_core::robustness::AttributionRobustness {
    attribution_robustness(
        g,
        &execute_then_spawn(),
        "alice@example.com",
        "target",
        options,
    )
    .unwrap()
}

#[test]
fn twin_scenarios_separate_lambda_from_rho() {
    for m in [2usize, 4, 8, 16] {
        let shared = robustness(&twin(m, true), &RobustnessOptions::default());
        assert!(shared.holds);
        assert_eq!((shared.lambda, shared.rho()), (m, Some(1)), "shared, m={m}");
        assert_eq!(shared.single_domain_breaks, vec!["A".to_string()]);
        assert!(shared.gap(), "m={m}");

        let independent = robustness(&twin(m, false), &RobustnessOptions::default());
        assert_eq!(
            (independent.lambda, independent.rho()),
            (m, Some(m)),
            "independent, m={m}"
        );
        assert!(independent.single_domain_breaks.is_empty());
        assert!(!independent.gap());
    }
}

/// The reported cuts are real: dropping the ρ cut's datasets leaves no
/// match, and the attribution held before.
#[test]
fn removing_the_reported_domains_breaks_the_attribution() {
    let mut g = twin(4, true);
    let r = robustness(&g, &RobustnessOptions::default());
    assert_eq!(r.rho_cut, vec!["A".to_string()]);
    g.remove_entities_and_relations_by_dataset("A").unwrap();
    assert!(!robustness(&g, &RobustnessOptions::default()).holds);
}

/// The document's example: chains labelled AB, BC and AC. Every single loss
/// leaves one chain whole, any two losses cut all three, so ρ = 2, while
/// three records (one per chain) must go: λ = 3.
#[test]
fn three_chains_over_three_collectors_need_two_failures() {
    let mut g = GraphHunter::new();
    g.add_entity(Entity::new("alice@example.com", EntityType::User))
        .unwrap();
    g.add_entity(Entity::new("target", EntityType::Process))
        .unwrap();
    for (i, (x, y)) in [("A", "B"), ("B", "C"), ("A", "C")].iter().enumerate() {
        let p = format!("p{i}");
        g.add_entity(Entity::new(&p, EntityType::Process)).unwrap();
        g.add_relation(edge("alice@example.com", &p, RelationType::Execute, 100, x))
            .unwrap();
        g.add_relation(edge(&p, "target", RelationType::Spawn, 200, y))
            .unwrap();
    }
    let r = robustness(&g, &RobustnessOptions::default());
    assert_eq!(r.lambda, 3);
    assert_eq!(r.rho(), Some(2));
    assert!(r.single_domain_breaks.is_empty());
    assert_eq!(r.rho_cut.len(), 2);
}

/// A record ingested three times is one record, not three: counting edges
/// would report redundancy that is not there.
#[test]
fn identical_duplicates_count_once() {
    let mut g = GraphHunter::new();
    g.add_entity(Entity::new("alice@example.com", EntityType::User))
        .unwrap();
    for p in ["p", "target"] {
        g.add_entity(Entity::new(p, EntityType::Process)).unwrap();
    }
    for _ in 0..3 {
        g.add_relation(edge(
            "alice@example.com",
            "p",
            RelationType::Execute,
            100,
            "A",
        ))
        .unwrap();
        g.add_relation(edge("p", "target", RelationType::Spawn, 200, "A"))
            .unwrap();
    }
    let by_record = robustness(&g, &RobustnessOptions::default());
    assert_eq!(by_record.lambda, 1);
    assert_eq!(by_record.chains, 9);
    let by_edge = robustness(
        &g,
        &RobustnessOptions {
            record_key: RecordKey::Edge,
            ..Default::default()
        },
    );
    assert_eq!(by_edge.lambda, 3);
}

/// Only temporally valid chains are support: a second path whose Spawn
/// happened before the Execute does not add a record to cut.
#[test]
fn a_backwards_chain_is_not_support() {
    let mut g = twin(1, false);
    g.add_entity(Entity::new("q", EntityType::Process)).unwrap();
    g.add_relation(edge(
        "alice@example.com",
        "q",
        RelationType::Execute,
        300,
        "c",
    ))
    .unwrap();
    g.add_relation(edge("q", "target", RelationType::Spawn, 250, "d"))
        .unwrap();
    let r = robustness(&g, &RobustnessOptions::default());
    assert_eq!(r.lambda, 1);
    assert_eq!(r.chains, 1);
}

/// One event that yields edges at two steps (a process creation gives both
/// the Execute and the Spawn) is one record across steps: λ is then only an
/// upper bound, and the result says so.
#[test]
fn a_record_spanning_two_steps_is_flagged() {
    let mut g = GraphHunter::new();
    g.add_entity(Entity::new("alice@example.com", EntityType::User))
        .unwrap();
    for p in ["p", "target"] {
        g.add_entity(Entity::new(p, EntityType::Process)).unwrap();
    }
    g.add_relation(
        edge("alice@example.com", "p", RelationType::Execute, 100, "A")
            .with_metadata("EventRecordID", "7"),
    )
    .unwrap();
    g.add_relation(
        edge("p", "target", RelationType::Spawn, 200, "A").with_metadata("EventRecordID", "7"),
    )
    .unwrap();
    let r = robustness(
        &g,
        &RobustnessOptions {
            record_key: RecordKey::Metadata(vec!["EventRecordID".to_string()]),
            ..Default::default()
        },
    );
    assert!(r.holds);
    assert!(!r.lambda_exact);
    assert_eq!(r.lambda, 1);
    assert!(!r.gap());
}

/// Shared risk groups: two datasets that both arrive through one forwarder
/// fall together when it fails.
#[test]
fn a_shared_forwarder_turns_two_domains_into_one() {
    let g = twin(2, false);
    let mut groups = std::collections::HashMap::new();
    for d in ["a0", "a1"] {
        groups.insert(
            d.to_string(),
            vec![d.to_string(), "forwarder-1".to_string()],
        );
    }
    let r = robustness(
        &g,
        &RobustnessOptions {
            domains: DomainSpec {
                base: DomainBase::Dataset,
                groups,
            },
            ..Default::default()
        },
    );
    assert_eq!(r.lambda, 2);
    assert_eq!(r.rho(), Some(1));
    assert_eq!(r.single_domain_breaks, vec!["forwarder-1".to_string()]);
    assert!(r.gap());
}

/// Inside a cancelled scope the computation stops and says so.
#[test]
fn a_cancelled_scope_returns_an_error() {
    let g = twin(4, false);
    let token = graph_hunter_core::cancel::CancelToken::new();
    token.cancel();
    let r = graph_hunter_core::cancel::scope(&token, || {
        attribution_robustness(
            &g,
            &execute_then_spawn(),
            "alice@example.com",
            "target",
            &RobustnessOptions::default(),
        )
    });
    assert_eq!(r.unwrap_err(), graph_hunter_core::robustness::CANCELLED);
}

/// With nothing linking the endpoints there is no attribution to defend.
#[test]
fn no_match_reports_nothing_to_lose() {
    let g = twin(2, true);
    let r = attribution_robustness(
        &g,
        &execute_then_spawn(),
        "alice@example.com",
        "nobody",
        &RobustnessOptions::default(),
    )
    .unwrap();
    assert!(!r.holds);
    assert_eq!((r.lambda, r.rho_lower, r.rho_upper), (0, 0, 0));
}
