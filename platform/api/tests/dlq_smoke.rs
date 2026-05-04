//! DLQ smoke test (M5.c).
//!
//! Ingest an NDJSON file whose rows cannot yield triples under the
//! provided FieldConfig (no matching `Node` fields). Every such row
//! must land in the DLQ with `failure_kind = ParseFailure` and the
//! original `raw_event` preserved.

use std::io::Write;

use graph_hunter_api::GraphHunterApi;
use graph_hunter_api::dto::dlq::ListDeadLettersRequest;
use graph_hunter_api::dto::ingestion::LoadDataWithConfigRequest;
use graph_hunter_api::dto::session::CreateSessionRequest;
use graph_hunter_core::dlq::{DlqStore, FailureKind};
use graph_hunter_core::field_preview::{FieldConfig, FieldMapping, FieldRole};

fn api_with_dlq() -> (GraphHunterApi, tempfile::TempDir) {
    let dlq_dir = tempfile::tempdir().expect("dlq tempdir");
    let store = DlqStore::open(dlq_dir.path()).expect("open dlq store");
    let api = GraphHunterApi::new_noop();
    *api.dlq_store_handle().lock().unwrap() = Some(std::sync::Arc::new(store));
    (api, dlq_dir)
}

#[test]
fn parse_failures_from_load_data_with_config_land_in_dlq() {
    let (api, _dlq_dir) = api_with_dlq();
    api.create_session(CreateSessionRequest {
        name: Some("dlq-smoke".into()),
    })
    .expect("create_session");

    // Two rows that DO have the mapped fields (should yield triples) and
    // two rows that DON'T (should land in the DLQ).
    let tmp = tempfile::NamedTempFile::new().expect("tempfile");
    {
        let mut f = tmp.as_file();
        writeln!(f, r#"{{"User":"alice","Image":"cmd.exe"}}"#).unwrap();
        writeln!(f, r#"{{"User":"bob","Image":"notepad.exe"}}"#).unwrap();
        writeln!(f, r#"{{"unrelated":"ignore-me"}}"#).unwrap();
        writeln!(f, r#"{{"noise":"nothing-to-parse"}}"#).unwrap();
    }
    let path = tmp.path().to_string_lossy().to_string();

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

    api.load_data_with_config(LoadDataWithConfigRequest {
        session: None,
        path,
        config: cfg,
    })
    .expect("load_data_with_config");

    let resp = api
        .list_dead_letters(ListDeadLettersRequest {
            session: None,
            dataset_id: None,
            failure_kind: None,
            offset: None,
            limit: None,
        })
        .expect("list_dead_letters");

    assert_eq!(
        resp.total, 2,
        "two rows lacked mapped Node fields and should be in DLQ; got entries={:?}",
        resp.entries
    );
    for entry in &resp.entries {
        assert!(
            matches!(entry.failure_kind, FailureKind::ParseFailure),
            "failure kind should be ParseFailure; got {:?}",
            entry.failure_kind
        );
        assert!(
            entry.raw_event.contains("unrelated") || entry.raw_event.contains("noise"),
            "raw_event should carry the original row; got {}",
            entry.raw_event
        );
        assert!(
            entry.dataset_id.is_some(),
            "dataset_id should be stamped on parse-skip entries"
        );
    }
}

/// F4 — end-to-end reingest roundtrip. Ingests canonical rows under a
/// deliberately-wrong FieldConfig that marks every canonical field
/// `Ignore` (so the `ConfigurableParser` strips them pre-parse and the
/// rows skip as `no_canonical_fields` into the DLQ), patches the
/// dataset's `field_config` to an empty mapping (restoring default
/// canonical behavior), calls `reingest_dead_letter`, and verifies:
///   1. the response reports every submitted id as reingested,
///   2. the DLQ is drained afterwards,
///   3. entities actually appeared in the session graph.
/// This closes the "bad mapping → fix → retry" workflow the UI exposes
/// through the dead-letter drawer.
#[test]
fn reingest_roundtrip_fix_config_then_drain() {
    use graph_hunter_api::dto::dlq::ReingestDeadLetterRequest;

    let (api, _dlq_dir) = api_with_dlq();
    api.create_session(CreateSessionRequest {
        name: Some("dlq-reingest".into()),
    })
    .expect("create_session");

    // Canonical fields only, so that under a passthrough FieldConfig
    // `GenericParser` produces triples without help. Under the wrong
    // config below, every field is Ignored → stripped → no canonical
    // residue → row classified `no_canonical_fields` → DLQ.
    let tmp = tempfile::NamedTempFile::new().expect("tempfile");
    {
        let mut f = tmp.as_file();
        writeln!(f, r#"{{"User":"alice","Image":"cmd.exe"}}"#).unwrap();
        writeln!(f, r#"{{"User":"bob","Image":"notepad.exe"}}"#).unwrap();
    }
    let path = tmp.path().to_string_lossy().to_string();

    let wrong_cfg = FieldConfig {
        mappings: vec![
            FieldMapping {
                raw_name: "User".into(),
                role: FieldRole::Ignore,
                entity_type: None,
                timestamp_format: None,
                locale: None,
            },
            FieldMapping {
                raw_name: "Image".into(),
                role: FieldRole::Ignore,
                entity_type: None,
                timestamp_format: None,
                locale: None,
            },
        ],
    };

    api.load_data_with_config(LoadDataWithConfigRequest {
        session: None,
        path,
        config: wrong_cfg,
    })
    .expect("load_data_with_config (wrong config)");

    let before = api
        .list_dead_letters(ListDeadLettersRequest {
            session: None,
            dataset_id: None,
            failure_kind: None,
            offset: None,
            limit: None,
        })
        .expect("list_dead_letters");
    assert_eq!(
        before.total, 2,
        "both rows should land in DLQ under all-Ignore mapping; got {:?}",
        before.entries
    );
    let dlq_ids: Vec<String> = before.entries.iter().map(|e| e.dlq_id.clone()).collect();

    // Patch the dataset's FieldConfig in-place to an empty mapping, so
    // canonical processing runs unimpeded on replay. The production UI
    // does this via a mapping-promotion op; here we go through the
    // session handle directly because that's exactly what reingest
    // reads when looking up a dataset's current config.
    let session = api
        .sessions()
        .current_session()
        .expect("current session exists after ingest");
    {
        let mut datasets = session.datasets.write().expect("datasets write");
        assert_eq!(datasets.len(), 1, "exactly one dataset tracked");
        datasets[0].field_config = Some(FieldConfig {
            mappings: Vec::new(),
        });
    }

    let resp = api
        .reingest_dead_letter(ReingestDeadLetterRequest {
            session: None,
            dlq_ids: dlq_ids.clone(),
        })
        .expect("reingest_dead_letter");

    assert_eq!(
        resp.reingested.len(),
        dlq_ids.len(),
        "all ids should reingest cleanly; failed={:?}, not_found={:?}",
        resp.failed,
        resp.not_found
    );
    assert!(resp.failed.is_empty(), "no entry should fail reingest");
    assert!(resp.not_found.is_empty(), "no id should be missing");

    let after = api
        .list_dead_letters(ListDeadLettersRequest {
            session: None,
            dataset_id: None,
            failure_kind: None,
            offset: None,
            limit: None,
        })
        .expect("list_dead_letters after reingest");
    assert_eq!(
        after.total, 0,
        "DLQ must be drained after successful reingest; still has {:?}",
        after.entries
    );

    // The replay should have produced canonical triples — at least two
    // User entities (alice, bob) and two Process entities.
    let graph = session.graph.read().expect("graph read");
    assert!(
        graph.entities.len() >= 2,
        "expected entities to appear after reingest; got {}",
        graph.entities.len()
    );
}

#[test]
fn no_dlq_entries_when_store_is_unconfigured() {
    // Same payload as the first test, but without a DlqStore on the API.
    // The ingest must succeed AND list_dead_letters must return empty
    // under the graceful-degradation contract.
    let api = GraphHunterApi::new_noop();
    api.create_session(CreateSessionRequest {
        name: Some("dlq-unconfigured".into()),
    })
    .expect("create_session");

    let tmp = tempfile::NamedTempFile::new().expect("tempfile");
    {
        let mut f = tmp.as_file();
        writeln!(f, r#"{{"noise":"x"}}"#).unwrap();
    }
    let path = tmp.path().to_string_lossy().to_string();

    let cfg = FieldConfig {
        mappings: vec![FieldMapping {
            raw_name: "User".into(),
            role: FieldRole::Node,
            entity_type: Some("User".into()),
            timestamp_format: None,
            locale: None,
        }],
    };

    api.load_data_with_config(LoadDataWithConfigRequest {
        session: None,
        path,
        config: cfg,
    })
    .expect("load_data_with_config");

    let resp = api
        .list_dead_letters(ListDeadLettersRequest {
            session: None,
            dataset_id: None,
            failure_kind: None,
            offset: None,
            limit: None,
        })
        .expect("list_dead_letters");
    assert_eq!(resp.total, 0);
    assert!(resp.entries.is_empty());
}
