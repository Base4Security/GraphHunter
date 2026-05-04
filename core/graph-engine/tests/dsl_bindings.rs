//! Integration tests for B.3 — DSL variable bindings. Before bindings,
//! `HAVING count(distinct X)` worked only when `X` was the first or last
//! entity-type name and unique. Bindings let an analyst name positions
//! explicitly so the same entity type appearing twice in a chain can be
//! disambiguated.

use graph_hunter_core::{Entity, EntityType, GraphHunter, Relation, RelationType, parse_dsl};

fn spray_graph() -> GraphHunter {
    let mut g = GraphHunter::new();
    for id in [
        "attacker", "normal", "1.1.1.1", "2.2.2.2", "3.3.3.3", "5.5.5.5",
    ] {
        let et = if id == "attacker" || id == "normal" {
            EntityType::User
        } else {
            EntityType::IP
        };
        g.add_entity(Entity::new(id, et)).unwrap();
    }
    for (i, ip) in ["1.1.1.1", "2.2.2.2", "3.3.3.3"].iter().enumerate() {
        g.add_relation(Relation::new(
            "attacker",
            *ip,
            RelationType::Auth,
            1_000_000 + (i as i64) * 60,
        ))
        .unwrap();
    }
    g.add_relation(Relation::new(
        "normal",
        "5.5.5.5",
        RelationType::Auth,
        1_000_000,
    ))
    .unwrap();
    g
}

#[test]
fn parse_entity_binding_optional() {
    // No binding — parses as before.
    let r = parse_dsl("User -[Auth]-> IP", None).unwrap();
    assert_eq!(r.hypothesis.steps.len(), 1);
    assert!(r.hypothesis.steps[0].origin_binding.is_none());
    assert!(r.hypothesis.steps[0].dest_binding.is_none());
}

#[test]
fn parse_captures_origin_and_dest_bindings() {
    let r = parse_dsl("User u -[Auth]-> IP i", None).unwrap();
    let step = &r.hypothesis.steps[0];
    assert_eq!(step.origin_binding.as_deref(), Some("u"));
    assert_eq!(step.dest_binding.as_deref(), Some("i"));
}

#[test]
fn having_resolves_named_binding() {
    let g = spray_graph();
    let h = parse_dsl(
        r#"User u -[Auth]-> IP i HAVING count(distinct i) >= 3"#,
        None,
    )
    .unwrap()
    .hypothesis;
    let (paths, _) = g.search_temporal_pattern(&h, None, None).unwrap();
    // attacker has 3 distinct IPs → 3 paths survive. normal has 1 → filtered out.
    assert_eq!(paths.len(), 3);
    assert!(paths.iter().all(|p| &*p[0] == "attacker"));
}

#[test]
fn having_rejects_undeclared_binding_with_clear_error() {
    // `q` is not a declared binding and doesn't match first/last types.
    // Parser must refuse at parse time rather than silently returning 0.
    let err = parse_dsl(r#"User u -[Auth]-> IP HAVING count(distinct q) >= 2"#, None).unwrap_err();
    assert!(
        err.message.contains("not a declared binding"),
        "got: {}",
        err.message
    );
}

#[test]
fn binding_respects_repeated_type_across_steps() {
    // Chain where `User` appears twice: `User u1 -[Auth]-> User u2`.
    // HAVING count(distinct u2) must refer to the dest position, not the
    // origin. Before bindings, "User" would have been ambiguous.
    let mut g = GraphHunter::new();
    for id in ["a", "b", "c", "d"] {
        g.add_entity(Entity::new(id, EntityType::User)).unwrap();
    }
    g.add_relation(Relation::new("a", "b", RelationType::Auth, 100))
        .unwrap();
    g.add_relation(Relation::new("a", "c", RelationType::Auth, 200))
        .unwrap();
    g.add_relation(Relation::new("a", "d", RelationType::Auth, 300))
        .unwrap();

    let h = parse_dsl(
        r#"User u1 -[Auth]-> User u2 HAVING count(distinct u2) >= 3"#,
        None,
    )
    .unwrap()
    .hypothesis;
    let (paths, _) = g.search_temporal_pattern(&h, None, None).unwrap();
    assert_eq!(paths.len(), 3);
    assert!(paths.iter().all(|p| &*p[0] == "a"));
}
