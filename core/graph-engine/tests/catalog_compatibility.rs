//! Integration tests for 4.A + 4.B: catalog compatibility check and the
//! new cloud-identity catalog entries. Mirrors the exact claim in the
//! post-hunt feedback — cat-001/003/012 are incompatible with AAD-style
//! datasets, cat-017..cat-021 are the new entries that match them.

use graph_hunter_core::{
    Entity, EntityType, GraphHunter, Relation, RelationType, check_catalog_compatibility,
    get_catalog, parse_dsl,
};

fn aad_like_graph() -> GraphHunter {
    // User -[Auth]-> IP and Host -[Connect]-> IP only. No Host/Auth/User
    // with Process nodes — exactly the Sentinel+AAD shape from the feedback.
    let mut g = GraphHunter::new();
    g.add_entity(Entity::new("alice", EntityType::User))
        .unwrap();
    g.add_entity(Entity::new("1.2.3.4", EntityType::IP))
        .unwrap();
    g.add_entity(Entity::new("host-a", EntityType::Host))
        .unwrap();
    g.add_relation(Relation::new("alice", "1.2.3.4", RelationType::Auth, 100))
        .unwrap();
    g.add_relation(Relation::new(
        "host-a",
        "1.2.3.4",
        RelationType::Connect,
        200,
    ))
    .unwrap();
    g
}

#[test]
fn cat_017_to_021_are_present_in_catalog() {
    let cat = get_catalog();
    for id in ["cat-017", "cat-018", "cat-019", "cat-020", "cat-021"] {
        assert!(
            cat.iter().any(|e| e.id == id),
            "catalog missing {id} (cloud-identity pattern)"
        );
    }
}

#[test]
fn cat_022_to_030_are_present_and_parse_cleanly() {
    let cat = get_catalog();
    // Post-compromise identity + endpoint modernization — every entry must
    // (a) be present, (b) parse through parse_dsl without errors.
    for id in [
        "cat-022", "cat-023", "cat-024", "cat-025", "cat-026", "cat-027", "cat-028", "cat-029",
        "cat-030",
    ] {
        let entry = cat
            .iter()
            .find(|e| e.id == id)
            .unwrap_or_else(|| panic!("catalog missing {id}"));
        parse_dsl(&entry.dsl_pattern, Some(&entry.name))
            .unwrap_or_else(|e| panic!("{id} failed to parse: {e:?}"));
    }
}

#[test]
fn post_compromise_patterns_are_incompatible_with_aad_only_dataset() {
    // The AAD-like graph has User/IP/Host only. cat-022..025 require
    // OAuthApp/ServicePrincipal/Role/MailboxRule + Consent/Create/Assign/
    // Forward rel types — none present. Compatibility check must mark
    // them incompatible and surface the missing types so the UI can
    // gray them out instead of running to zero-results.
    let g = aad_like_graph();
    let schema = g.get_relation_schema();
    for id in ["cat-022", "cat-023", "cat-024", "cat-025"] {
        let entry = get_catalog().iter().find(|e| e.id == id).unwrap();
        let status = check_catalog_compatibility(entry, &schema);
        assert!(!status.compatible, "{id} must be incompatible here");
        assert!(
            !status.missing_rel_types.is_empty() || !status.missing_entity_types.is_empty(),
            "{id} must name what's missing"
        );
    }
}

#[test]
fn darpa_style_patterns_are_incompatible_with_aad_dataset() {
    let g = aad_like_graph();
    let schema = g.get_relation_schema();

    for id in ["cat-001", "cat-003", "cat-012"] {
        let entry = get_catalog().iter().find(|e| e.id == id).unwrap();
        let status = check_catalog_compatibility(entry, &schema);
        assert!(
            !status.compatible,
            "{id} must be incompatible with AAD graph"
        );
        assert!(
            !status.missing_entity_types.is_empty() || !status.missing_rel_types.is_empty(),
            "{id} must declare what's missing",
        );
    }
}

#[test]
fn cloud_identity_patterns_are_compatible_with_aad_dataset() {
    let g = aad_like_graph();
    let schema = g.get_relation_schema();

    // cat-017 (Password Spraying) uses only User -[Auth]-> IP → compatible.
    let s17 = check_catalog_compatibility(
        get_catalog().iter().find(|e| e.id == "cat-017").unwrap(),
        &schema,
    );
    assert!(
        s17.compatible,
        "cat-017 should be compatible, got missing: {:?}",
        s17.missing_entity_types
    );
}

#[test]
fn cat_017_parses_cleanly() {
    // The catalog pattern must parse via parse_dsl (no syntax regressions
    // as we extended the grammar with predicates + HAVING + WITHIN).
    let entry = get_catalog().iter().find(|e| e.id == "cat-017").unwrap();
    let r = parse_dsl(&entry.dsl_pattern, Some(&entry.name)).unwrap();
    assert_eq!(r.hypothesis.aggregations.len(), 1);
    assert_eq!(r.hypothesis.window_seconds, Some(24 * 3600));
    assert_eq!(r.hypothesis.steps[0].edge_predicates.len(), 1);
}

#[test]
fn empty_graph_reports_every_entry_as_incompatible() {
    let g = GraphHunter::new();
    let schema = g.get_relation_schema();
    for entry in get_catalog() {
        let status = check_catalog_compatibility(entry, &schema);
        assert!(
            !status.compatible,
            "{} must be incompatible with an empty graph",
            entry.id
        );
    }
}
