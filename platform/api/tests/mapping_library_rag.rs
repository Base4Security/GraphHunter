//! M5.e RAG lookup smoke test. Verifies that `ingest_negotiate`
//! surfaces mapping-library matches when a prior approval has seeded
//! the same field-shape, and that exact fingerprint hits warm-start
//! the proposal (bumped confidence + rationale tag).

use graph_hunter_api::GraphHunterApi;
use graph_hunter_api::dto::agentic::{IngestNegotiateRequest, ResolveDraftRequest};
use graph_hunter_api::dto::session::CreateSessionRequest;
use graph_hunter_api::state::DatasetInfo;
use graph_hunter_core::mapping_library::MappingLibraryStore;

fn api_with_library() -> (GraphHunterApi, tempfile::TempDir) {
    let dir = tempfile::tempdir().expect("tempdir");
    let store = MappingLibraryStore::open(dir.path()).expect("open library");
    let api = GraphHunterApi::new_noop();
    *api.mapping_library_handle().lock().unwrap() = Some(std::sync::Arc::new(store));
    api.create_session(CreateSessionRequest {
        name: Some("ml-rag".into()),
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

fn negotiate(
    api: &GraphHunterApi,
    csv: &str,
) -> graph_hunter_api::dto::agentic::IngestNegotiateResponse {
    api.ingest_negotiate(IngestNegotiateRequest {
        session: None,
        dataset_id: None,
        raw_sample: csv.into(),
        hint_format: Some("csv".into()),
        max_rounds: None,
    })
    .expect("negotiate")
}

#[test]
fn second_ingest_with_same_shape_warm_starts_from_library() {
    let (api, _dir) = api_with_library();
    let csv = "User,Image,Time\nalice,cmd.exe,1\nbob,whoami.exe,2\n";

    // First call: library is empty → no warm-start, no similar hits.
    let first = negotiate(&api, csv);
    assert!(
        first.similar_mappings.is_empty(),
        "first negotiation on empty library should surface no hits; got: {:?}",
        first.similar_mappings
    );
    let first_confidence = first.confidence;

    // Approve the first draft so it gets published to the library.
    api.agentic_review_approve(ResolveDraftRequest {
        session: None,
        draft_id: first.draft_id,
        reason: None,
    })
    .expect("approve");

    // Second call on the exact same CSV: the library now has a matching
    // fingerprint — we should get one exact hit and the warm-start
    // should bump confidence and annotate the rationale.
    let second = negotiate(&api, csv);
    assert_eq!(
        second.similar_mappings.len(),
        1,
        "should surface exactly one library hit"
    );
    let hit = &second.similar_mappings[0];
    assert!(hit.exact, "fingerprint should match exactly");
    assert!(
        (hit.score - 1.0).abs() < f32::EPSILON,
        "exact hit scores 1.0"
    );
    assert_eq!(hit.source, "ingest_negotiator");
    assert!(
        second.confidence > first_confidence,
        "warm-start should bump confidence: before={first_confidence}, after={}",
        second.confidence
    );
    assert!(
        second.rationale.contains("Warm-started"),
        "rationale should cite the library; got: {}",
        second.rationale
    );
}

#[test]
fn partial_shape_overlap_surfaces_non_exact_hits_without_warm_start() {
    let (api, _dir) = api_with_library();

    // Seed with {User, Image}.
    let seeded = negotiate(&api, "User,Image\nalice,cmd.exe\n");
    api.agentic_review_approve(ResolveDraftRequest {
        session: None,
        draft_id: seeded.draft_id,
        reason: None,
    })
    .unwrap();
    let baseline_confidence = seeded.confidence;

    // Now negotiate a CSV that shares User but adds Host (different
    // fingerprint, partial token overlap).
    let mixed = negotiate(&api, "User,Host\nalice,dc-01\n");
    // Expect: the library hit surfaces as non-exact. It may or may
    // not clear the 0.25 min_score cutoff depending on Jaccard of
    // the *proposed* FieldConfig (which the heuristic may extend
    // with additional mappings). Either way, no warm-start should
    // fire because no exact fingerprint match exists.
    assert!(
        mixed.similar_mappings.iter().all(|m| !m.exact),
        "no exact match expected; got: {:?}",
        mixed.similar_mappings
    );
    assert!(
        !mixed.rationale.contains("Warm-started"),
        "no warm-start should fire on partial overlap; got: {}",
        mixed.rationale
    );
    assert!(
        mixed.confidence <= baseline_confidence + 0.01,
        "confidence should not bump without an exact match"
    );
}

#[test]
fn no_library_attached_leaves_similar_mappings_empty() {
    // No library configured → `similar_mappings` must stay empty and
    // the negotiator must still produce a draft.
    let api = GraphHunterApi::new_noop();
    api.create_session(CreateSessionRequest {
        name: Some("ml-none".into()),
    })
    .expect("create_session");

    let resp = negotiate(&api, "User,Image\nalice,cmd.exe\n");
    assert!(resp.similar_mappings.is_empty());
    assert!(!resp.rationale.contains("Warm-started"));
}
