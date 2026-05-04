//! M4.g — full agentic round-trip through the canonical API:
//! `ingest_negotiate` → `agentic_review_list` → `agentic_review_approve`.
//!
//! No transport layer in scope — we drive `GraphHunterApi` directly,
//! the same way the HTTP/MCP/Tauri transports will once M4.f wires
//! them. The intent is to lock down the contract: a draft is pending
//! after `negotiate`, listing surfaces it, approving promotes its
//! FieldConfig onto the most recent dataset, and a second list call
//! shows the resolved draft only when `include_resolved=true`.

use graph_hunter_api::GraphHunterApi;
use graph_hunter_api::dto::agentic::{
    DraftSource, DraftStatus, IngestNegotiateRequest, ListDraftsRequest, ResolveDraftRequest,
};
use graph_hunter_api::dto::session::CreateSessionRequest;
use graph_hunter_api::state::DatasetInfo;

fn fresh_api_with_dataset() -> (GraphHunterApi, String) {
    let api = GraphHunterApi::new_noop();
    api.create_session(CreateSessionRequest {
        name: Some("agentic-loop".into()),
    })
    .expect("create_session");
    let session = api.sessions().current_session().expect("current session");
    let dataset_id = "ds-loop".to_string();
    {
        let mut datasets = session.datasets.write().expect("datasets lock");
        datasets.push(DatasetInfo {
            id: dataset_id.clone(),
            name: "ds-loop".into(),
            path: None,
            created_at: 0,
            entity_count: 0,
            relation_count: 0,
            field_config: None,
            ingest_stats: None,
        });
    }
    (api, dataset_id)
}

#[test]
fn negotiate_then_review_then_approve_round_trips() {
    let (api, dataset_id) = fresh_api_with_dataset();

    // 1. Negotiate a FieldConfig from a tiny CSV sample.
    let csv = "User,Image,Time\nalice,cmd.exe,1\nbob,whoami.exe,2\n";
    let neg = api
        .ingest_negotiate(IngestNegotiateRequest {
            session: None,
            dataset_id: Some(dataset_id.clone()),
            raw_sample: csv.into(),
            hint_format: Some("csv".into()),
            max_rounds: None,
        })
        .expect("negotiate");
    assert!(neg.draft_id.starts_with("draft-"));
    assert!(
        !neg.proposed_field_config.mappings.is_empty(),
        "deterministic heuristic should propose at least one mapping for CSV"
    );
    assert!(neg.confidence > 0.0);

    // 2. List pending — exactly one entry, the draft we just created,
    //    sourced from the negotiator and still pending.
    let pending = api
        .agentic_review_list(ListDraftsRequest {
            session: None,
            include_resolved: false,
        })
        .expect("list pending");
    assert_eq!(pending.drafts.len(), 1);
    assert_eq!(pending.drafts[0].draft_id, neg.draft_id);
    assert_eq!(pending.drafts[0].source, DraftSource::IngestNegotiator);
    assert!(matches!(pending.drafts[0].status, DraftStatus::Pending));

    // 3. Approve. The draft must promote its FieldConfig onto the
    //    dataset, flipping the dataset's `field_config` from None to
    //    Some(_) and leaving the draft as Approved.
    let approved = api
        .agentic_review_approve(ResolveDraftRequest {
            session: None,
            draft_id: neg.draft_id.clone(),
            reason: None,
        })
        .expect("approve");
    assert_eq!(
        approved.promoted_dataset_id.as_deref(),
        Some(dataset_id.as_str())
    );
    assert!(matches!(
        approved.draft.status,
        DraftStatus::Approved { .. }
    ));

    // 4. The dataset's FieldConfig now matches the draft's proposal —
    //    end-to-end provenance for the next ingest of this dataset.
    let session = api.sessions().current_session().unwrap();
    let datasets = session.datasets.read().unwrap();
    let ds = datasets.iter().find(|d| d.id == dataset_id).unwrap();
    let stamped = ds.field_config.as_ref().expect("field_config promoted");
    assert_eq!(
        stamped.mappings.len(),
        neg.proposed_field_config.mappings.len()
    );

    // 5. Pending list is now empty, but the resolved view shows the
    //    approved draft. This is the audit affordance the UI relies on.
    let still_pending = api
        .agentic_review_list(ListDraftsRequest {
            session: None,
            include_resolved: false,
        })
        .expect("list after approve");
    assert!(still_pending.drafts.is_empty());

    let with_resolved = api
        .agentic_review_list(ListDraftsRequest {
            session: None,
            include_resolved: true,
        })
        .expect("list resolved");
    assert_eq!(with_resolved.drafts.len(), 1);
    assert!(matches!(
        with_resolved.drafts[0].status,
        DraftStatus::Approved { .. }
    ));
}

#[test]
fn rejecting_a_draft_records_the_reason() {
    let (api, dataset_id) = fresh_api_with_dataset();
    let csv = "User,Image\nalice,cmd.exe\n";
    let neg = api
        .ingest_negotiate(IngestNegotiateRequest {
            session: None,
            dataset_id: Some(dataset_id),
            raw_sample: csv.into(),
            hint_format: Some("csv".into()),
            max_rounds: None,
        })
        .expect("negotiate");

    let resolved = api
        .agentic_review_reject(ResolveDraftRequest {
            session: None,
            draft_id: neg.draft_id.clone(),
            reason: Some("user disagrees with the User → User mapping".into()),
        })
        .expect("reject");
    match resolved.draft.status {
        DraftStatus::Rejected { ref reason, .. } => {
            assert!(reason.contains("disagrees"));
        }
        other => panic!("expected Rejected, got {:?}", other),
    }
    assert!(resolved.promoted_dataset_id.is_none());
}
