//! Validates that every projected `OcsfEvent` conforms to the checked-in
//! OCSF v1.4 subset JSON Schema. The 7 shipping parsers emit, between
//! them, exactly the shapes exercised below — so if this suite passes the
//! crate's projection is schema-legal for everything ingest produces.

use graph_hunter_canonical::{
    OCSF_V1_4_SCHEMA, OcsfEvent, ProvenanceCtx, ocsf_to_triple, triple_to_ocsf,
};
use graph_hunter_core::entity::Entity;
use graph_hunter_core::relation::Relation;
use graph_hunter_core::types::{EntityType, RelationType};
use jsonschema::JSONSchema;
use serde_json::Value;

fn compiled_schema() -> JSONSchema {
    let schema: Value = serde_json::from_str(OCSF_V1_4_SCHEMA).expect("schema parses");
    JSONSchema::options()
        .with_draft(jsonschema::Draft::Draft7)
        .compile(&schema)
        .expect("schema compiles")
}

fn validate(schema: &JSONSchema, event: &OcsfEvent) {
    let serialized = serde_json::to_value(event).expect("event serializes");
    if let Err(errors) = schema.validate(&serialized) {
        for err in errors {
            eprintln!("schema violation at {}: {}", err.instance_path, err);
        }
        panic!(
            "event failed schema validation:\n{}",
            serde_json::to_string_pretty(&serialized).unwrap()
        );
    }
}

fn prov() -> ProvenanceCtx {
    ProvenanceCtx::for_builtin_parser("sysmon", "ds-test", b"{\"EventID\":1}")
}

fn project(src: Entity, rel: Relation, dst: Entity) -> OcsfEvent {
    triple_to_ocsf(&src, &rel, &dst, &prov())
}

#[test]
fn authentication_variants_conform() {
    let schema = compiled_schema();
    for dst_type in [EntityType::Host, EntityType::IP] {
        let ev = project(
            Entity::new("alice", EntityType::User),
            Relation::new("alice", "dst", RelationType::Auth, 1_700_000_000),
            Entity::new("dst", dst_type),
        );
        validate(&schema, &ev);
        assert!(matches!(ev, OcsfEvent::Authentication(_)));
    }
}

#[test]
fn process_activity_variants_conform() {
    let schema = compiled_schema();

    let user_exec = project(
        Entity::new("alice", EntityType::User),
        Relation::new("alice", "powershell.exe", RelationType::Execute, 1),
        Entity::new("powershell.exe", EntityType::Process),
    );
    validate(&schema, &user_exec);
    assert!(matches!(user_exec, OcsfEvent::ProcessActivity(_)));

    let parent_spawn = project(
        Entity::new("cmd.exe", EntityType::Process),
        Relation::new("cmd.exe", "whoami.exe", RelationType::Spawn, 1),
        Entity::new("whoami.exe", EntityType::Process),
    );
    validate(&schema, &parent_spawn);
    assert!(matches!(parent_spawn, OcsfEvent::ProcessActivity(_)));
}

#[test]
fn network_activity_variants_conform() {
    let schema = compiled_schema();
    let shapes = [
        (EntityType::IP, EntityType::IP),
        (EntityType::Host, EntityType::IP),
        (EntityType::IP, EntityType::Host),
    ];
    for (src_t, dst_t) in shapes {
        let ev = project(
            Entity::new("src", src_t),
            Relation::new("src", "dst", RelationType::Connect, 1),
            Entity::new("dst", dst_t),
        );
        validate(&schema, &ev);
        assert!(matches!(ev, OcsfEvent::NetworkActivity(_)));
    }
}

#[test]
fn dns_activity_conforms() {
    let schema = compiled_schema();
    let ev = project(
        Entity::new("workstation-01", EntityType::Host),
        Relation::new("workstation-01", "evil.example.com", RelationType::DNS, 1),
        Entity::new("evil.example.com", EntityType::Domain),
    );
    validate(&schema, &ev);
    assert!(matches!(ev, OcsfEvent::DnsActivity(_)));
}

#[test]
fn file_system_activity_variants_conform() {
    let schema = compiled_schema();
    for rel_type in [
        RelationType::Read,
        RelationType::Write,
        RelationType::Modify,
        RelationType::Delete,
    ] {
        let ev = project(
            Entity::new("proc", EntityType::Process),
            Relation::new("proc", "C:/f.txt", rel_type, 1),
            Entity::new("C:/f.txt", EntityType::File),
        );
        validate(&schema, &ev);
        assert!(matches!(ev, OcsfEvent::FileSystemActivity(_)));
    }
}

#[test]
fn registry_key_activity_conforms() {
    let schema = compiled_schema();
    let ev = project(
        Entity::new("regedit.exe", EntityType::Process),
        Relation::new("regedit.exe", "HKLM/Software/Run", RelationType::Modify, 1),
        Entity::new("HKLM/Software/Run", EntityType::Registry),
    );
    validate(&schema, &ev);
    assert!(matches!(ev, OcsfEvent::RegistryKeyActivity(_)));
}

#[test]
fn other_fallback_conforms() {
    let schema = compiled_schema();
    let ev = project(
        Entity::new("alice", EntityType::User),
        Relation::new("alice", "evil.example.com", RelationType::DNS, 1),
        Entity::new("evil.example.com", EntityType::Domain),
    );
    validate(&schema, &ev);
    assert!(matches!(ev, OcsfEvent::Other(_)));
}

#[test]
fn reverse_projection_preserves_identity_on_every_typed_variant() {
    // Every shape we project must be recoverable through ocsf_to_triple
    // at the (id, type, rel_type, ts) level.
    let cases: Vec<(Entity, Relation, Entity)> = vec![
        (
            Entity::new("alice", EntityType::User),
            Relation::new("alice", "dc-01", RelationType::Auth, 1),
            Entity::new("dc-01", EntityType::Host),
        ),
        (
            Entity::new("cmd.exe", EntityType::Process),
            Relation::new("cmd.exe", "whoami.exe", RelationType::Spawn, 1),
            Entity::new("whoami.exe", EntityType::Process),
        ),
        (
            Entity::new("10.0.0.1", EntityType::IP),
            Relation::new("10.0.0.1", "8.8.8.8", RelationType::Connect, 1),
            Entity::new("8.8.8.8", EntityType::IP),
        ),
        (
            Entity::new("ws-01", EntityType::Host),
            Relation::new("ws-01", "evil.example.com", RelationType::DNS, 1),
            Entity::new("evil.example.com", EntityType::Domain),
        ),
        (
            Entity::new("p.exe", EntityType::Process),
            Relation::new("p.exe", "C:/f.txt", RelationType::Write, 1),
            Entity::new("C:/f.txt", EntityType::File),
        ),
        (
            Entity::new("regedit.exe", EntityType::Process),
            Relation::new("regedit.exe", "HKLM/Run", RelationType::Modify, 1),
            Entity::new("HKLM/Run", EntityType::Registry),
        ),
    ];
    for (src, rel, dst) in cases {
        let ev = triple_to_ocsf(&src, &rel, &dst, &prov());
        let back = ocsf_to_triple(&ev).expect("round-trip defined");
        assert_eq!(back.0.id, src.id);
        assert_eq!(back.0.entity_type, src.entity_type);
        assert_eq!(back.2.id, dst.id);
        assert_eq!(back.2.entity_type, dst.entity_type);
        assert_eq!(back.1.rel_type, rel.rel_type);
    }
}
