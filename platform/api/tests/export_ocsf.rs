//! End-to-end test for `GraphHunterApi::export_ocsf`. Seeds a small
//! graph with a known mix of shapes, exports to NDJSON, and asserts
//! every event conforms to the checked-in OCSF v1.4 subset schema and
//! that each line carries a Provenance Extension.

use graph_hunter_api::GraphHunterApi;
use graph_hunter_api::dto::export::ExportOcsfRequest;
use graph_hunter_api::dto::session::CreateSessionRequest;
use graph_hunter_canonical::OCSF_V1_4_SCHEMA;
use jsonschema::JSONSchema;
use serde_json::Value;

fn seeded_api() -> GraphHunterApi {
    use graph_hunter_core::{Entity, EntityType, Relation, RelationType};

    let api = GraphHunterApi::new_noop();
    api.create_session(CreateSessionRequest {
        name: Some("export-ocsf".into()),
    })
    .expect("create_session");
    let session = api
        .sessions()
        .current_session()
        .expect("current session after create");
    let mut graph = session.graph.write().expect("graph write lock");

    // One triple per shipping OCSF class so the NDJSON exercises each
    // projection arm.
    graph
        .add_entity(Entity::new("alice", EntityType::User))
        .ok();
    graph
        .add_entity(Entity::new("dc-01", EntityType::Host))
        .ok();
    graph
        .add_entity(Entity::new("cmd.exe", EntityType::Process))
        .ok();
    graph
        .add_entity(Entity::new("whoami.exe", EntityType::Process))
        .ok();
    graph
        .add_entity(Entity::new("10.0.0.1", EntityType::IP))
        .ok();
    graph
        .add_entity(Entity::new("8.8.8.8", EntityType::IP))
        .ok();
    graph
        .add_entity(Entity::new("evil.example.com", EntityType::Domain))
        .ok();
    graph
        .add_entity(Entity::new("C:/loot.dat", EntityType::File))
        .ok();
    graph
        .add_entity(Entity::new("HKLM/Software/Run", EntityType::Registry))
        .ok();
    graph
        .add_entity(Entity::new("ws-01", EntityType::Host))
        .ok();

    let adds = [
        ("alice", "dc-01", RelationType::Auth),
        ("alice", "cmd.exe", RelationType::Execute),
        ("cmd.exe", "whoami.exe", RelationType::Spawn),
        ("10.0.0.1", "8.8.8.8", RelationType::Connect),
        ("ws-01", "evil.example.com", RelationType::DNS),
        ("cmd.exe", "C:/loot.dat", RelationType::Write),
        ("cmd.exe", "HKLM/Software/Run", RelationType::Modify),
    ];
    for (i, (src, dst, rel)) in adds.iter().enumerate() {
        graph
            .add_relation(Relation::new(
                src.to_string(),
                dst.to_string(),
                rel.clone(),
                1_700_000_000 + i as i64,
            ))
            .ok();
    }
    drop(graph);
    api
}

#[test]
fn ndjson_export_covers_every_shipping_class_and_validates_against_schema() {
    let api = seeded_api();
    let out = api
        .export_ocsf(ExportOcsfRequest {
            session: None,
            dataset_id: None,
            format: "ndjson".into(),
            page_size: None,
            offset: None,
        })
        .expect("export_ocsf");

    // The ndjson stream leads with a `_meta` pagination envelope line
    // (added in 6507f11); drop it so the body assertion counts only the
    // one-event-per-relation projection.
    let lines: Vec<&str> = out
        .lines()
        .filter(|line| {
            let v: Value = serde_json::from_str(line).expect("each line is JSON");
            v.get("_meta").is_none()
        })
        .collect();
    assert_eq!(lines.len(), 7, "one event per seeded relation");

    let schema: Value = serde_json::from_str(OCSF_V1_4_SCHEMA).expect("schema parses");
    let compiled = JSONSchema::options()
        .with_draft(jsonschema::Draft::Draft7)
        .compile(&schema)
        .expect("schema compiles");

    let mut seen_classes = std::collections::HashSet::new();
    for line in &lines {
        let v: Value = serde_json::from_str(line).expect("each line is JSON");
        if let Err(errors) = compiled.validate(&v) {
            for err in errors {
                eprintln!("schema error at {}: {}", err.instance_path, err);
            }
            panic!("event failed schema validation: {line}");
        }
        let class = v["class_name"]
            .as_str()
            .expect("class_name present")
            .to_string();
        seen_classes.insert(class);

        let prov = &v["provenance"];
        assert!(prov.is_object(), "every event carries provenance");
        assert_eq!(
            prov["schema_version"].as_str(),
            Some("ocsf-1.4+gh-prov-0.1"),
            "schema_version tag on every event"
        );
    }

    for expected in [
        "authentication",
        "process_activity",
        "network_activity",
        "dns_activity",
        "file_system_activity",
        "registry_key_activity",
    ] {
        assert!(
            seen_classes.contains(expected),
            "expected class {expected} in NDJSON; got {:?}",
            seen_classes
        );
    }
}

#[test]
fn json_array_format_returns_a_valid_array() {
    let api = seeded_api();
    let out = api
        .export_ocsf(ExportOcsfRequest {
            session: None,
            dataset_id: None,
            format: "json".into(),
            page_size: None,
            offset: None,
        })
        .expect("export_ocsf json");
    let v: Value = serde_json::from_str(&out).expect("json envelope parses");
    let arr = v["events"].as_array().expect("events array");
    assert_eq!(arr.len(), 7);
    assert_eq!(v["_meta"]["returned"].as_u64(), Some(7));
    assert_eq!(v["_meta"]["total_in_session"].as_u64(), Some(7));
    assert_eq!(v["_meta"]["has_more"].as_bool(), Some(false));
}

/// M3.d acceptance: when a dataset has a FieldConfig, the
/// `mapping_hash` stamped onto every emitted event must be the
/// deterministic `sha256(vrl_source)` from `field_config_to_vrl`,
/// not the placeholder `builtin:<parser>` tag.
#[test]
fn dataset_with_field_config_stamps_real_vrl_hash() {
    use graph_hunter_api::state::session_types::DatasetInfo;
    use graph_hunter_core::field_preview::{FieldConfig, FieldMapping, FieldRole};
    use graph_hunter_core::{Entity, EntityType, Relation, RelationType};

    let api = GraphHunterApi::new_noop();
    api.create_session(CreateSessionRequest {
        name: Some("vrl-hash".into()),
    })
    .expect("create_session");
    let session = api.sessions().current_session().expect("current session");

    let dataset_id = "ds-with-vrl".to_string();
    let cfg = FieldConfig {
        mappings: vec![
            FieldMapping {
                raw_name: "User".into(),
                role: FieldRole::Node,
                entity_type: Some("User".into()),
                timestamp_format: None,
                locale: None,
            },
            FieldMapping {
                raw_name: "Image".into(),
                role: FieldRole::Node,
                entity_type: Some("Process".into()),
                timestamp_format: None,
                locale: None,
            },
        ],
    };
    let expected_hash = graph_hunter_vrl::field_config_to_vrl(&cfg).mapping_hash;

    {
        let mut datasets = session.datasets.write().expect("datasets lock");
        datasets.push(DatasetInfo {
            id: dataset_id.clone(),
            name: "ds-with-vrl".into(),
            path: None,
            created_at: 0,
            entity_count: 0,
            relation_count: 0,
            field_config: Some(cfg),
            ingest_stats: None,
        });
    }
    {
        let mut graph = session.graph.write().expect("graph lock");
        graph
            .add_entity(Entity::new("alice", EntityType::User))
            .ok();
        graph
            .add_entity(Entity::new("cmd.exe", EntityType::Process))
            .ok();
        let mut rel = Relation::new(
            "alice".to_string(),
            "cmd.exe".to_string(),
            RelationType::Execute,
            1,
        );
        rel.dataset_id = Some(std::sync::Arc::from(dataset_id.as_str()));
        graph.add_relation(rel).ok();
    }

    let out = api
        .export_ocsf(ExportOcsfRequest {
            session: None,
            dataset_id: Some(dataset_id.clone()),
            format: "ndjson".into(),
            page_size: None,
            offset: None,
        })
        .expect("export_ocsf");

    // The ndjson stream leads with a `_meta` pagination envelope line
    // (added in 6507f11); the first real event is the second line.
    let line = out.lines().nth(1).expect("at least one event");
    let v: Value = serde_json::from_str(line).expect("event parses");
    let prov = &v["provenance"];
    let stamped_hash = prov["mapping_hash"].as_str().expect("mapping_hash str");
    assert_eq!(
        stamped_hash, expected_hash,
        "mapping_hash must be sha256(vrl_source), not a placeholder"
    );
    assert!(
        !stamped_hash.starts_with("builtin:"),
        "must not fall back to builtin:* placeholder"
    );
    let mapping_id = prov["mapping_id"].as_str().expect("mapping_id str");
    assert!(
        mapping_id.starts_with("vrl-v"),
        "mapping_id should encode the compiler version: {mapping_id}"
    );
    assert_eq!(prov["parser_name"].as_str(), Some("vrl"));
}

#[test]
fn unsupported_format_is_rejected() {
    let api = seeded_api();
    let err = api
        .export_ocsf(ExportOcsfRequest {
            session: None,
            dataset_id: None,
            format: "xml".into(),
            page_size: None,
            offset: None,
        })
        .expect_err("xml must be rejected");
    let msg = err.to_string();
    assert!(msg.contains("unsupported format"), "got: {msg}");
}
