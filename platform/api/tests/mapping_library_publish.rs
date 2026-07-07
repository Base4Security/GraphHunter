//! M5.d publish-hook smoke test. Approves an IngestNegotiator draft
//! with a mapping library attached; asserts the library grew by one
//! entry whose fingerprint matches the approved FieldConfig and whose
//! `origin_draft_id` points back at the draft.

use graph_hunter_api::GraphHunterApi;
use graph_hunter_api::dto::agentic::{IngestNegotiateRequest, ResolveDraftRequest};
use graph_hunter_api::dto::session::CreateSessionRequest;
use graph_hunter_api::state::DatasetInfo;
use graph_hunter_core::mapping_library::{MappingLibraryStore, PublishSource, fingerprint};

fn api_with_library() -> (GraphHunterApi, tempfile::TempDir) {
    let dir = tempfile::tempdir().expect("tempdir");
    let store = MappingLibraryStore::open(dir.path()).expect("open library");
    let api = GraphHunterApi::new_noop();
    *api.mapping_library_handle().lock().unwrap() = Some(std::sync::Arc::new(store));
    api.create_session(CreateSessionRequest {
        name: Some("ml-publish".into()),
    })
    .expect("create_session");
    let session = api.sessions().current_session().unwrap();
    session.datasets.write().unwrap().push(DatasetInfo {
        id: "ds-1".into(),
        name: "ds-1".into(),
        path: None,
        created_at: 0,
        entity_count: 0,
        relation_count: 0,
        field_config: None,
        ingest_stats: None,
    });
    (api, dir)
}

#[test]
fn approving_negotiator_draft_publishes_to_library() {
    let (api, _dir) = api_with_library();
    let csv = "User,Image\nalice,cmd.exe\nbob,notepad.exe\n";

    let negotiate_resp = api
        .ingest_negotiate(IngestNegotiateRequest {
            session: None,
            dataset_id: None,
            raw_sample: csv.into(),
            hint_format: Some("csv".into()),
            max_rounds: None,
        })
        .expect("negotiate");
    let expected_fp = fingerprint(&negotiate_resp.proposed_field_config);

    api.agentic_review_approve(ResolveDraftRequest {
        session: None,
        draft_id: negotiate_resp.draft_id.clone(),
        reason: None,
    })
    .expect("approve");

    let library = api.mapping_library().expect("library attached");
    let all = library.list().expect("list");
    assert_eq!(
        all.len(),
        1,
        "exactly one publication after a single approve"
    );
    let entry = &all[0];
    assert_eq!(entry.fingerprint, expected_fp);
    assert_eq!(entry.source, PublishSource::IngestNegotiator);
    assert_eq!(
        entry.origin_draft_id.as_deref(),
        Some(negotiate_resp.draft_id.as_str())
    );
    assert!(
        entry.mapping_id.starts_with("ml-fp-"),
        "got: {}",
        entry.mapping_id
    );
    assert!(entry.vrl_source.is_none(), "negotiator drafts have no VRL");

    // find_by_fingerprint should surface the same entry.
    let hits = library.find_by_fingerprint(&expected_fp).expect("lookup");
    assert_eq!(hits.len(), 1);
    assert_eq!(hits[0].mapping_id, entry.mapping_id);
}

#[test]
fn rejecting_a_draft_does_not_publish() {
    let (api, _dir) = api_with_library();
    let csv = "User,Image\nalice,cmd.exe\n";

    let draft = api
        .ingest_negotiate(IngestNegotiateRequest {
            session: None,
            dataset_id: None,
            raw_sample: csv.into(),
            hint_format: Some("csv".into()),
            max_rounds: None,
        })
        .expect("negotiate");

    api.agentic_review_reject(ResolveDraftRequest {
        session: None,
        draft_id: draft.draft_id,
        reason: Some("not fit for purpose".into()),
    })
    .expect("reject");

    let library = api.mapping_library().unwrap();
    assert_eq!(library.list().unwrap().len(), 0, "reject must not publish");
}

#[test]
fn approving_with_no_library_is_graceful_noop() {
    // No library attached — approval still works; publication is skipped.
    let api = GraphHunterApi::new_noop();
    api.create_session(CreateSessionRequest {
        name: Some("ml-missing".into()),
    })
    .expect("create_session");
    let session = api.sessions().current_session().unwrap();
    session.datasets.write().unwrap().push(DatasetInfo {
        id: "ds-1".into(),
        name: "ds-1".into(),
        path: None,
        created_at: 0,
        entity_count: 0,
        relation_count: 0,
        field_config: None,
        ingest_stats: None,
    });

    let draft = api
        .ingest_negotiate(IngestNegotiateRequest {
            session: None,
            dataset_id: None,
            raw_sample: "User,Image\nalice,cmd.exe\n".into(),
            hint_format: Some("csv".into()),
            max_rounds: None,
        })
        .unwrap();
    api.agentic_review_approve(ResolveDraftRequest {
        session: None,
        draft_id: draft.draft_id,
        reason: None,
    })
    .expect("approve without library must succeed");
    assert!(api.mapping_library().is_none());
}
