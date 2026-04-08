#![cfg(feature = "simd")]

use std::collections::HashSet;

use graph_hunter_core::simd_matcher::ffi;
use graph_hunter_core::{
    Entity, EntityType, GraphHunter, Hypothesis, HypothesisStep, Relation, RelationType,
};

fn build_small_graph() -> GraphHunter {
    let mut g = GraphHunter::new();

    g.add_entity(Entity::new("admin-user", EntityType::User)).unwrap();
    g.add_entity(Entity::new("guest-user", EntityType::User)).unwrap();
    g.add_entity(Entity::new("cmd.exe", EntityType::Process)).unwrap();
    g.add_entity(Entity::new("powershell.exe", EntityType::Process)).unwrap();
    g.add_entity(Entity::new("notepad.exe", EntityType::Process)).unwrap();
    g.add_entity(Entity::new("payload.dll", EntityType::File)).unwrap();
    g.add_entity(Entity::new("report.txt", EntityType::File)).unwrap();

    g.add_relation(Relation::new("admin-user", "cmd.exe", RelationType::Execute, 100)).unwrap();
    g.add_relation(Relation::new("admin-user", "powershell.exe", RelationType::Execute, 150)).unwrap();
    g.add_relation(Relation::new("guest-user", "notepad.exe", RelationType::Execute, 200)).unwrap();
    g.add_relation(Relation::new("cmd.exe", "payload.dll", RelationType::Write, 300)).unwrap();
    g.add_relation(Relation::new("powershell.exe", "payload.dll", RelationType::Write, 350)).unwrap();
    g.add_relation(Relation::new("notepad.exe", "report.txt", RelationType::Write, 400)).unwrap();

    g.sort_edges_by_timestamp().unwrap();
    g
}

#[test]
fn test_simd_isa_name_returns_known_value() {
    let isa = ffi::simd_isa_name();
    let known = ["avx512", "avx2", "sse42", "neon", "scalar", "unknown", "none"];
    assert!(
        known.contains(&isa),
        "simd_isa_name returned unexpected value: {:?}",
        isa
    );
}

#[test]
fn test_simd_search_matches_pure_rust_on_tiny_graph() {
    let graph = build_small_graph();

    let hypothesis = Hypothesis::new("User Writes File via Process")
        .add_step(HypothesisStep::new(
            EntityType::User,
            RelationType::Execute,
            EntityType::Process,
        ))
        .add_step(HypothesisStep::new(
            EntityType::Process,
            RelationType::Write,
            EntityType::File,
        ));

    let (rust_results, _) = graph
        .search_temporal_pattern(&hypothesis, None, Some(1000))
        .unwrap();

    let cached = ffi::build_gm_graph(&graph);
    let simd_results = ffi::run_simd_search(&cached, &graph.interner, &hypothesis, None, Some(1000));

    assert!(
        !rust_results.is_empty(),
        "baseline Rust search produced no matches — test fixture is broken"
    );
    assert_eq!(
        rust_results.len(),
        simd_results.len(),
        "result count mismatch: rust={}, simd={}",
        rust_results.len(),
        simd_results.len()
    );

    let rust_set: HashSet<Vec<String>> = rust_results.into_iter().collect();
    let simd_set: HashSet<Vec<String>> = simd_results.into_iter().collect();
    assert_eq!(
        rust_set, simd_set,
        "SIMD and pure-Rust paths disagree on the same hypothesis"
    );
}

#[test]
fn test_simd_search_empty_graph_returns_no_results() {
    let graph = GraphHunter::new();

    let hypothesis = Hypothesis::new("Anything")
        .add_step(HypothesisStep::new(
            EntityType::User,
            RelationType::Execute,
            EntityType::Process,
        ))
        .add_step(HypothesisStep::new(
            EntityType::Process,
            RelationType::Write,
            EntityType::File,
        ));

    let cached = ffi::build_gm_graph(&graph);
    let results = ffi::run_simd_search(&cached, &graph.interner, &hypothesis, None, Some(1000));
    assert!(results.is_empty(), "empty graph produced {} results", results.len());
}
