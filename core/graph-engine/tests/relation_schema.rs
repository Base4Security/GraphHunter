//! Integration tests for `GraphHunter::get_relation_schema`.
//!
//! Kept as an integration test (same rationale as `graph_pattern.rs`) so the
//! public API contract is exercised end-to-end. The shape asserted here is
//! the one surfaced to analysts through `cmd_get_relation_schema`; if it
//! changes, every DSL-authoring workflow downstream is affected.

use graph_hunter_core::{Entity, EntityType, GraphHunter, Relation, RelationType};

fn schema_of(
    entities: &[(&str, EntityType)],
    edges: &[(&str, &str, RelationType, i64, &[(&str, &str)])],
) -> Vec<graph_hunter_core::RelSchemaEntry> {
    let mut g = GraphHunter::new();
    for (id, et) in entities {
        g.add_entity(Entity::new(*id, et.clone())).unwrap();
    }
    for (src, dst, rel, ts, meta) in edges {
        let mut r = Relation::new(*src, *dst, rel.clone(), *ts);
        for (k, v) in *meta {
            r = r.with_metadata(*k, *v);
        }
        g.add_relation(r).unwrap();
    }
    g.get_relation_schema()
}

#[test]
fn empty_graph_produces_empty_schema() {
    let g = GraphHunter::new();
    assert!(g.get_relation_schema().is_empty());
}

#[test]
fn groups_by_rel_type_and_endpoint_types() {
    // Mixed: three rel types, distinct endpoint types each. Matches the
    // canonical example in the post-hunt feedback: Auth (User→IP),
    // Connect (Host→IP), Execute (User→Process).
    let schema = schema_of(
        &[
            ("alice", EntityType::User),
            ("bob", EntityType::User),
            ("1.2.3.4", EntityType::IP),
            ("5.6.7.8", EntityType::IP),
            ("host-a", EntityType::Host),
            ("cmd.exe", EntityType::Process),
        ],
        &[
            (
                "alice",
                "1.2.3.4",
                RelationType::Auth,
                100,
                &[("status", "Failure")],
            ),
            (
                "alice",
                "5.6.7.8",
                RelationType::Auth,
                200,
                &[("status", "Failure"), ("app", "AAD")],
            ),
            (
                "bob",
                "1.2.3.4",
                RelationType::Auth,
                300,
                &[("status", "Success")],
            ),
            (
                "host-a",
                "1.2.3.4",
                RelationType::Connect,
                400,
                &[("protocol", "Tcp"), ("remote_port", "443")],
            ),
            ("alice", "cmd.exe", RelationType::Execute, 500, &[]),
        ],
    );

    // Three distinct (rel, src_type, dst_type) triples.
    assert_eq!(schema.len(), 3);

    // Auth is the most common (3 edges); that entry must come first.
    assert_eq!(schema[0].rel_type, "Auth");
    assert_eq!(schema[0].source_type, "User");
    assert_eq!(schema[0].target_type, "IP");
    assert_eq!(schema[0].edge_count, 3);
    // Metadata-keys union across the 3 Auth edges.
    assert_eq!(
        schema[0].metadata_keys,
        vec!["app".to_string(), "status".to_string()]
    );

    // Second and third in edge-count order; both have count 1.
    let connect = schema.iter().find(|e| e.rel_type == "Connect").unwrap();
    assert_eq!(connect.source_type, "Host");
    assert_eq!(connect.target_type, "IP");
    assert_eq!(connect.edge_count, 1);
    assert_eq!(
        connect.metadata_keys,
        vec!["protocol".to_string(), "remote_port".to_string()]
    );

    let execute = schema.iter().find(|e| e.rel_type == "Execute").unwrap();
    assert_eq!(execute.source_type, "User");
    assert_eq!(execute.target_type, "Process");
    assert_eq!(execute.edge_count, 1);
    assert!(execute.metadata_keys.is_empty());
}

#[test]
fn same_rel_type_with_different_endpoints_are_separate_entries() {
    // Same relation (Connect) but two different source→target type shapes.
    // This is exactly the case that bites analysts when they guess edge
    // direction: schema output must reveal both shapes separately.
    let schema = schema_of(
        &[
            ("host-a", EntityType::Host),
            ("1.2.3.4", EntityType::IP),
            ("5.6.7.8", EntityType::IP),
        ],
        &[
            ("host-a", "1.2.3.4", RelationType::Connect, 100, &[]),
            ("host-a", "5.6.7.8", RelationType::Connect, 200, &[]),
            // Reverse direction — same rel_type, different (src, dst) type pair.
            ("1.2.3.4", "host-a", RelationType::Connect, 300, &[]),
        ],
    );

    assert_eq!(schema.len(), 2);
    let forward = schema.iter().find(|e| e.source_type == "Host").unwrap();
    assert_eq!(forward.edge_count, 2);
    let reverse = schema.iter().find(|e| e.source_type == "IP").unwrap();
    assert_eq!(reverse.edge_count, 1);
}

#[test]
fn custom_entity_types_are_preserved_as_distinct() {
    // EntityType::Other("OAuthApp") should not collide with built-ins.
    let schema = schema_of(
        &[
            ("alice", EntityType::User),
            ("app-xyz", EntityType::Other("OAuthApp".into())),
        ],
        &[("app-xyz", "alice", RelationType::Auth, 100, &[])],
    );
    assert_eq!(schema.len(), 1);
    assert_eq!(schema[0].source_type, "OAuthApp");
    assert_eq!(schema[0].target_type, "User");
}
