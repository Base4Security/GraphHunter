//! Dual-impl validation harness for [`GraphRead`] / [`GraphWrite`].
//!
//! The whole point of the trait split is that adding a second backend
//! (Neo4j, remote streaming store, etc.) shouldn't require rewriting
//! the downstream consumers. This test is a generic validation
//! function parametric over `B: GraphWrite` — today it only runs
//! against `GraphHunter`, but the test compiles against any future
//! impl without edits.
//!
//! If this test grows (or starts covering the hot-path matcher), it
//! should probably move into a dedicated `backend_compat/` suite.

use graph_hunter_core::{
    Entity, EntityType, GraphHunter, GraphRead, GraphWrite, InMemoryGraph, Relation, RelationType,
};

/// Populate a deterministic mini-graph using only trait methods.
/// Returns the same shape as `graph_hunter_api::parity::fixture`
/// uses, so future tests can cross-reference expectations.
fn seed<B: GraphWrite>(b: &mut B) {
    b.add_entity(Entity::new("alice", EntityType::User))
        .unwrap();
    b.add_entity(Entity::new("bob", EntityType::User)).unwrap();
    b.add_entity(Entity::new("web-01", EntityType::Host))
        .unwrap();
    b.add_entity(Entity::new("cmd.exe", EntityType::Process))
        .unwrap();

    b.add_relation(Relation::new(
        "alice".to_string(),
        "web-01".to_string(),
        RelationType::Auth,
        1_700_000_000,
    ))
    .unwrap();
    b.add_relation(Relation::new(
        "web-01".to_string(),
        "cmd.exe".to_string(),
        RelationType::Execute,
        1_700_000_100,
    ))
    .unwrap();
    b.add_relation(Relation::new(
        "bob".to_string(),
        "web-01".to_string(),
        RelationType::Auth,
        1_700_000_200,
    ))
    .unwrap();
}

fn validate_backend<B: GraphWrite>(b: &mut B) {
    seed(b);

    // Counts
    assert_eq!(b.entity_count(), 4, "entity_count");
    assert_eq!(b.relation_count(), 3, "relation_count");

    // Entity lookup
    let alice = b.get_entity("alice").expect("alice must exist");
    assert_eq!(alice.id, "alice");
    assert!(
        b.get_entity("ghost").is_none(),
        "unknown id must return None"
    );

    // Type index
    let mut users = b.entity_ids_for_type(&EntityType::User).expect("users");
    users.sort();
    assert_eq!(users, vec!["alice".to_string(), "bob".to_string()]);

    // Type catalog (lexicographic)
    let types = b.entity_types_in_graph();
    assert_eq!(types, vec!["Host", "Process", "User"]);

    // Outgoing edges from alice: one to web-01.
    let out = b.get_compact_relations("alice");
    assert_eq!(out.len(), 1, "alice should have exactly 1 outgoing edge");
    let materialized = b.materialize_relation(&out[0]);
    assert_eq!(materialized.source_id, "alice");
    assert_eq!(materialized.dest_id, "web-01");

    // Reverse adjacency: web-01 has two inbound (alice, bob).
    let mut sources = b.get_reverse_source_ids("web-01");
    sources.sort();
    assert_eq!(sources, vec!["alice".to_string(), "bob".to_string()]);

    // Unknown node → empty reverse list (NOT an error).
    assert!(b.get_reverse_source_ids("ghost").is_empty());

    // Capability hint — InMemory returns true only if the `simd`
    // feature is compiled in; without it, the default `false` holds.
    let _ = b.supports_simd();
}

#[test]
fn graph_hunter_passes_backend_contract() {
    let mut g = GraphHunter::new();
    validate_backend(&mut g);
}

#[test]
fn in_memory_alias_is_the_same_type() {
    // The alias is what consumers should migrate to so the eventual
    // rename `GraphHunter` → `InMemoryGraph` is a free rename of the
    // struct. Sanity-check the alias points at the right type.
    let _typed: InMemoryGraph = GraphHunter::new();
}

#[test]
fn empty_backend_is_well_behaved() {
    let g = GraphHunter::new();
    assert_eq!(g.entity_count(), 0);
    assert_eq!(g.relation_count(), 0);
    assert!(GraphRead::get_entity(&g, "anything").is_none());
    assert!(g.get_compact_relations("anything").is_empty());
    assert!(g.get_reverse_source_ids("anything").is_empty());
    assert!(g.entity_ids_for_type(&EntityType::User).is_none());
    assert!(g.entity_types_in_graph().is_empty());
}
