//! Integration test for `GraphHunterApi::check_invariants` (M2 D3).
//! Seeds a session with deliberate violations of P1/P2/P3/P4 and asserts
//! the invariant report flags each predicate by name, plus produces a
//! treewidth estimate tagged `"min-degree-quotient"`.

use graph_hunter_api::GraphHunterApi;
use graph_hunter_api::dto::invariants::CheckInvariantsRequest;
use graph_hunter_api::dto::session::CreateSessionRequest;
use graph_hunter_core::invariants::PredicateId;

fn seeded_api() -> GraphHunterApi {
    use graph_hunter_core::{Entity, EntityType, Relation, RelationType};

    let api = GraphHunterApi::new_noop();
    api.create_session(CreateSessionRequest {
        name: Some("invariants".into()),
    })
    .expect("create_session");
    let session = api
        .sessions()
        .current_session()
        .expect("current session after create");
    let mut graph = session.graph.write().expect("graph write lock");

    // ── Dataset "dsA" — clean baseline + P1/P2/P3 violations ──
    let mut alice = Entity::new("alice", EntityType::User);
    alice.dataset_id = Some(std::sync::Arc::from("dsA"));
    graph.add_entity(alice).ok();
    let mut dc = Entity::new("dc-01", EntityType::Host);
    dc.dataset_id = Some(std::sync::Arc::from("dsA"));
    graph.add_entity(dc).ok();
    let mut cmd = Entity::new("cmd.exe", EntityType::Process);
    cmd.dataset_id = Some(std::sync::Arc::from("dsA"));
    graph.add_entity(cmd).ok();
    let mut whoami = Entity::new("whoami.exe", EntityType::Process);
    whoami.dataset_id = Some(std::sync::Arc::from("dsA"));
    graph.add_entity(whoami).ok();
    let mut secret = Entity::new("C:/secret.txt", EntityType::File);
    secret.dataset_id = Some(std::sync::Arc::from("dsA"));
    graph.add_entity(secret).ok();
    let mut evil = Entity::new("C:/evil.dll", EntityType::File);
    evil.dataset_id = Some(std::sync::Arc::from("dsA"));
    graph.add_entity(evil).ok();

    // Clean causal chain.
    let mut r = Relation::new("alice", "dc-01", RelationType::Auth, 10);
    r.dataset_id = Some(std::sync::Arc::from("dsA"));
    graph.add_relation(r).ok();
    let mut r = Relation::new("alice", "cmd.exe", RelationType::Execute, 20);
    r.dataset_id = Some(std::sync::Arc::from("dsA"));
    graph.add_relation(r).ok();
    let mut r = Relation::new("cmd.exe", "whoami.exe", RelationType::Spawn, 30);
    r.dataset_id = Some(std::sync::Arc::from("dsA"));
    graph.add_relation(r).ok();

    // P1: whoami reads secret.txt at t=5, before being spawned at t=30.
    let mut r = Relation::new("whoami.exe", "C:/secret.txt", RelationType::Read, 5);
    r.dataset_id = Some(std::sync::Arc::from("dsA"));
    graph.add_relation(r).ok();

    // P2: File Execute IP is not a catalog shape.
    let mut ip = Entity::new("10.0.0.1", EntityType::IP);
    ip.dataset_id = Some(std::sync::Arc::from("dsA"));
    graph.add_entity(ip).ok();
    let mut r = Relation::new("C:/evil.dll", "10.0.0.1", RelationType::Execute, 100);
    r.dataset_id = Some(std::sync::Arc::from("dsA"));
    graph.add_relation(r).ok();

    // P3: cmd.exe Spawn cmd.exe — concrete rel_type self-loop, not whitelisted.
    let mut r = Relation::new("cmd.exe", "cmd.exe", RelationType::Spawn, 40);
    r.dataset_id = Some(std::sync::Arc::from("dsA"));
    graph.add_relation(r).ok();

    // ── Dataset "dsB" — cross-dataset referential break ──
    let mut bob = Entity::new("bob", EntityType::User);
    bob.dataset_id = Some(std::sync::Arc::from("dsB"));
    graph.add_entity(bob).ok();
    // bob authenticates to dc-01, but dc-01 lives in dsA. Under
    // scope=Dataset("dsB") P4 fires because dc-01 is out of scope.
    let mut r = Relation::new("bob", "dc-01", RelationType::Auth, 50);
    r.dataset_id = Some(std::sync::Arc::from("dsB"));
    graph.add_relation(r).ok();

    drop(graph);

    // Register the datasets the graph references so they exist in
    // `session.datasets`. `check_invariants` validates `dataset_id`
    // against this registry (a 400 instead of a fail-silent vacuum,
    // commit 6507f11) — the graph's per-row `dataset_id` tags and the
    // session registry are intentionally decoupled, so a fixture that
    // models a real ingested session must populate both.
    {
        use graph_hunter_api::state::DatasetInfo;
        let mut ds = session.datasets.write().expect("datasets write lock");
        for id in ["dsA", "dsB"] {
            ds.push(DatasetInfo {
                id: id.into(),
                name: id.into(),
                path: None,
                created_at: 0,
                entity_count: 0,
                relation_count: 0,
                field_config: None,
                ingest_stats: None,
            });
        }
    }

    api
}

#[test]
fn session_scope_flags_p1_p2_p3_and_returns_treewidth() {
    let api = seeded_api();
    let report = api
        .check_invariants(CheckInvariantsRequest {
            session: None,
            dataset_id: None,
        })
        .expect("check_invariants");

    assert!(
        report.treewidth_estimate.is_some(),
        "treewidth always populated for non-empty graphs"
    );
    let tw = report.treewidth_estimate.as_ref().unwrap();
    assert_eq!(tw.method, "min-degree-quotient");
    assert!(tw.quotient_node_count >= 4);

    let by_pred: std::collections::HashMap<
        PredicateId,
        &graph_hunter_core::invariants::PredicateResult,
    > = report.results.iter().map(|r| (r.predicate, r)).collect();

    let p1 = by_pred[&PredicateId::P1CausalMonotonicity];
    assert!(!p1.passed, "P1 should flag whoami Read before Spawn");
    assert!(p1.violated >= 1);

    let p2 = by_pred[&PredicateId::P2TypeShapePlausibility];
    assert!(!p2.passed, "P2 should flag (File, Execute, IP)");
    assert!(p2.violated >= 1);

    let p3 = by_pred[&PredicateId::P3IdentityCoherence];
    assert!(!p3.passed, "P3 should flag (cmd.exe, Spawn, cmd.exe)");
    assert!(p3.violated >= 1);

    // P4 is clean under Scope::Session because every endpoint lives in
    // *some* dataset — the cross-dataset edge only fails referential
    // closure under a narrowed scope.
    let p4 = by_pred[&PredicateId::P4ReferentialClosure];
    assert!(p4.passed, "P4 passes under Scope::Session");

    let p5 = by_pred[&PredicateId::P5RaritySanity];
    assert!(p5.skipped_reason.is_some());
    assert!(p5.passed, "skipped predicates report passed=true");
}

#[test]
fn dataset_scope_flags_p4_on_cross_dataset_edge() {
    let api = seeded_api();
    let report = api
        .check_invariants(CheckInvariantsRequest {
            session: None,
            dataset_id: Some("dsB".into()),
        })
        .expect("check_invariants");

    let by_pred: std::collections::HashMap<
        PredicateId,
        &graph_hunter_core::invariants::PredicateResult,
    > = report.results.iter().map(|r| (r.predicate, r)).collect();

    let p4 = by_pred[&PredicateId::P4ReferentialClosure];
    assert!(
        !p4.passed,
        "dsB's edge to dc-01 (in dsA) is dangling under scope=dsB"
    );
    assert_eq!(p4.violated, 1);
    let sample = &p4.samples[0];
    assert_eq!(sample.dataset_id.as_deref(), Some("dsB"));
    assert!(sample.reason.contains("dangling"));
}

#[test]
fn clean_empty_session_passes() {
    let api = GraphHunterApi::new_noop();
    api.create_session(CreateSessionRequest {
        name: Some("empty".into()),
    })
    .expect("create_session");

    let report = api
        .check_invariants(CheckInvariantsRequest {
            session: None,
            dataset_id: None,
        })
        .expect("check_invariants");

    assert!(report.all_passed());
    assert_eq!(report.entity_count, 0);
    assert_eq!(report.relation_count, 0);
    assert_eq!(report.treewidth_estimate.as_ref().unwrap().value, 0);
}
