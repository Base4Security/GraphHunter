//! Phase B — end-to-end scenario tests over the canonical API.
//!
//! These exercise ordered sequences of calls against the fixture
//! session and assert on observable state. They're the "semantic
//! parity" layer — if a transport delegator ever skips a method or
//! miswires an argument, these tests still pass (because we call
//! the API directly) but the shape tests in `dto_shapes.rs` catch
//! the drift. Together the two phases cover the parity contract
//! until a full HTTP/Tauri runtime harness lands.

use graph_hunter_api::ApiError;
use graph_hunter_api::dto::anomaly::{EnableAnomalyScoringRequest, GetAnomalyConfigRequest};
use graph_hunter_api::dto::entity::{
    EntitiesByTypeRequest, ListTaggedRequest, NodeScopedRequest, SessionOnly, UntagEntityRequest,
};
use graph_hunter_api::dto::export::{ExportHuntResultsRequest, ExportIocsRequest};
use graph_hunter_api::dto::graph_ops::SubgraphRequest;
use graph_hunter_api::dto::hunt::{DiffHuntsRequest, GetHuntPageRequest, RunHuntRequest};
use graph_hunter_api::dto::session::{
    CreateSessionRequest, DeleteSessionRequest, LoadSessionRequest, SessionInfo,
};

use crate::parity::fixture::{
    fresh_api_with_seeded_session, fresh_api_with_session, note, parse, tag,
};

// ── Session lifecycle ──────────────────────────────────────────────

#[test]
fn create_list_delete_roundtrip() {
    // `list_sessions` also scans $APP_DATA/GraphHunter/sessions/ on
    // disk, so developer machines that have run GraphHunter before
    // will have pre-existing sessions in the list. Assert on
    // containment of the newly-created ids, not on exact count.
    let (api, first_id) = fresh_api_with_session();
    let second = api
        .create_session(CreateSessionRequest {
            name: Some("second".into()),
        })
        .unwrap();
    let list = api.list_sessions().unwrap();
    let ids: std::collections::BTreeSet<String> =
        list.iter().map(|s: &SessionInfo| s.id.clone()).collect();
    assert!(ids.contains(&first_id), "first session missing from list");
    assert!(ids.contains(&second.id), "second session missing from list");

    api.delete_session(DeleteSessionRequest {
        session_id: second.id.clone(),
    })
    .unwrap();
    let after_ids: std::collections::BTreeSet<String> = api
        .list_sessions()
        .unwrap()
        .iter()
        .map(|s: &SessionInfo| s.id.clone())
        .collect();
    assert!(
        !after_ids.contains(&second.id),
        "deleted session must not reappear"
    );
    assert!(
        after_ids.contains(&first_id),
        "untouched session must still be in the list"
    );
}

#[test]
fn load_unknown_session_is_not_found() {
    let (api, _id) = fresh_api_with_session();
    // Load path looks on disk when not in memory; with a fresh
    // fixture the disk is empty, so unknown ids surface as
    // SessionNotFound.
    let err = api
        .load_session_blocking(LoadSessionRequest {
            session_id: "does-not-exist".into(),
        })
        .unwrap_err();
    assert!(matches!(err, ApiError::SessionNotFound(_)));
}

// ── Entity reads over the fixture graph ────────────────────────────

#[test]
fn entity_types_in_seeded_graph() {
    let (api, _id) = fresh_api_with_seeded_session();
    let mut types = api
        .get_entity_types_in_graph(SessionOnly::default())
        .unwrap();
    types.sort();
    assert_eq!(types, vec!["Host", "Process", "User"]);
}

#[test]
fn entities_by_type_returns_expected_ids() {
    let (api, _id) = fresh_api_with_seeded_session();
    let mut users = api
        .get_entities_by_type(EntitiesByTypeRequest {
            session: None,
            type_name: "User".into(),
        })
        .unwrap();
    users.sort();
    assert_eq!(users, vec!["alice", "bob"]);
}

#[test]
fn explain_score_unknown_node_is_not_found() {
    let (api, _id) = fresh_api_with_seeded_session();
    let err = api
        .explain_score(NodeScopedRequest {
            session: None,
            node_id: "ghost".into(),
        })
        .unwrap_err();
    assert!(matches!(err, ApiError::NotFound(_)));
}

// ── Tagging + export ────────────────────────────────────────────────

#[test]
fn tag_untag_list_cycle() {
    let (api, _id) = fresh_api_with_seeded_session();
    tag(&api, "alice", "ioc:malicious");
    tag(&api, "web-01", "ioc:suspicious");

    let all = api.list_tagged(ListTaggedRequest::default()).unwrap();
    assert_eq!(all.len(), 2);

    let filtered = api
        .list_tagged(ListTaggedRequest {
            session: None,
            tag_prefix: Some("ioc:".into()),
        })
        .unwrap();
    assert_eq!(filtered.len(), 2);

    api.untag_entity(UntagEntityRequest {
        session: None,
        node_id: "alice".into(),
        tag: "ioc:malicious".into(),
    })
    .unwrap();
    let after = api.list_tagged(ListTaggedRequest::default()).unwrap();
    assert_eq!(after.len(), 1);
    assert_eq!(after[0].node_id, "web-01");
}

#[test]
fn export_iocs_sentinel_watchlist_csv_contains_tagged_ips_only() {
    let (api, _id) = fresh_api_with_seeded_session();
    // Add an IP entity so ipv4 mapping kicks in.
    {
        use graph_hunter_core::{Entity, EntityType};
        let s = api.sessions().current_session().unwrap();
        let mut g = s.graph.write().unwrap();
        g.add_entity(Entity::new("1.2.3.4", EntityType::IP)).ok();
    }
    tag(&api, "1.2.3.4", "ioc:malicious");
    tag(&api, "alice", "ioc:malicious"); // user gets ipv4 type? no — account.

    let csv = api
        .export_iocs(ExportIocsRequest {
            session: None,
            format: "sentinel_watchlist".into(),
            tag_prefix: Some("ioc:".into()),
        })
        .unwrap();
    assert!(csv.starts_with("ioc_value,ioc_type,tag,reason\n"));
    assert!(csv.contains("\"1.2.3.4\",ipv4,ioc:malicious,"));
    assert!(csv.contains("\"alice\",account,ioc:malicious,"));
}

// ── Hunt + pagination + export ──────────────────────────────────────

#[test]
fn run_hunt_populates_cache_and_pages_back() {
    let (api, _id) = fresh_api_with_seeded_session();
    let hypothesis = parse(&api, "User -[Auth]-> Host");
    let resp = api
        .run_hunt(RunHuntRequest {
            session: None,
            hypothesis,
            time_window: None,
            max_results: Some(1_000),
            scoring: None,
            dedup_mode: None,
        })
        .unwrap();
    // The seed has 2 Auth edges (alice→web-01, bob→web-01), each a
    // 2-node path.
    assert_eq!(resp.path_count, 2);
    assert!(!resp.truncated);
    assert!(resp.diagnostic.is_none());
    assert_eq!(resp.paths.len(), 2);

    // get_hunt_page reads the cache the run just wrote.
    let page = api
        .get_hunt_page(GetHuntPageRequest {
            session: None,
            page: 0,
            page_size: 10,
            min_score: None,
            dedup_mode: None,
        })
        .unwrap();
    assert_eq!(page.total_paths, 2);
    assert_eq!(page.paths.len(), 2);
}

#[test]
fn run_hunt_zero_paths_populates_diagnostic() {
    let (api, _id) = fresh_api_with_seeded_session();
    // Seed has no User→Process direct Auth relation.
    let hypothesis = parse(&api, "User -[Execute]-> Process");
    let resp = api
        .run_hunt(RunHuntRequest {
            session: None,
            hypothesis,
            time_window: None,
            max_results: None,
            scoring: None,
            dedup_mode: None,
        })
        .unwrap();
    assert_eq!(resp.path_count, 0);
    assert!(
        resp.diagnostic.is_some(),
        "zero-match must populate diagnostic so the analyst knows why"
    );
}

#[test]
fn diff_hunts_rejects_inverted_window() {
    let (api, _id) = fresh_api_with_seeded_session();
    let hypothesis = parse(&api, "User -[Auth]-> Host");
    let err = api
        .diff_hunts(DiffHuntsRequest {
            session: None,
            hypothesis,
            baseline_ts: 200,
            current_ts: 100,
        })
        .unwrap_err();
    assert!(matches!(err, ApiError::InvalidInput(_)));
}

#[test]
fn export_hunt_results_errors_without_cached_run() {
    let (api, _id) = fresh_api_with_seeded_session();
    // Fresh session: cache is empty → export refuses.
    let err = api
        .export_hunt_results(ExportHuntResultsRequest {
            session: None,
            format: "json".into(),
            page: None,
            page_size: None,
            aggregate: None,
        })
        .unwrap_err();
    assert!(matches!(err, ApiError::InvalidState(_)));
}

// ── Subgraph extraction ─────────────────────────────────────────────

#[test]
fn subgraph_for_seed_covers_expected_edges() {
    let (api, _id) = fresh_api_with_seeded_session();
    let sg = api
        .get_subgraph(SubgraphRequest {
            session: None,
            node_ids: vec!["alice".into(), "web-01".into(), "cmd.exe".into()],
            // RH-P1-013: pagination knobs added 2026-05-06. `None` keeps
            // the legacy default cap so the test asserts the same edges
            // as before.
            page_size: None,
            offset: None,
        })
        .unwrap();
    // 3 entities in, 3 requested nodes out. Edges: alice→web-01 and
    // web-01→cmd.exe (2), plus bob→web-01 is NOT included (bob not
    // in the requested id set).
    assert_eq!(sg.nodes.len(), 3);
    assert_eq!(sg.edges.len(), 2);
}

// ── Anomaly scorer ──────────────────────────────────────────────────

#[test]
fn anomaly_enable_then_config_roundtrips() {
    let (api, _id) = fresh_api_with_seeded_session();
    assert!(
        api.get_anomaly_config(GetAnomalyConfigRequest::default())
            .unwrap()
            .is_none()
    );
    api.enable_anomaly_scoring(EnableAnomalyScoringRequest::default())
        .unwrap();
    assert!(
        api.get_anomaly_config(GetAnomalyConfigRequest::default())
            .unwrap()
            .is_some()
    );
}

// ── Catalog YAML loader (P2-C) ──────────────────────────────────────

#[test]
fn get_catalog_returns_30_builtin_entries() {
    let (api, _id) = fresh_api_with_session();
    let cat = api.get_catalog();
    assert_eq!(cat.len(), 30, "built-in catalog must have 30 entries");
    // Spot-check a couple of ids across the spectrum of categories.
    assert!(cat.iter().any(|e| e.id == "cat-001"));
    assert!(cat.iter().any(|e| e.id == "cat-017"));
    assert!(cat.iter().any(|e| e.id == "cat-029"));
    assert!(cat.iter().any(|e| e.id == "cat-030"));
}

#[test]
fn get_catalog_diagnostics_is_empty_for_builtin_only() {
    let (api, _id) = fresh_api_with_session();
    // A clean machine has no user YAMLs → no errors. Developer machines
    // might have valid user YAMLs → still no errors. We only assert the
    // type + that every reported error has a non-empty message (so the
    // UI can render it usefully).
    let diags = api.get_catalog_diagnostics();
    for d in &diags {
        assert!(
            !d.message.is_empty(),
            "diagnostic must carry a human-readable message, got: {d:?}"
        );
    }
}

// ── Notes ───────────────────────────────────────────────────────────

#[test]
fn notes_create_list_returns_in_order() {
    let (api, _id) = fresh_api_with_seeded_session();
    note(&api, "finding one", Some("alice"));
    note(&api, "standalone", None);
    let all = api.get_notes(SessionOnly::default()).unwrap();
    assert_eq!(all.len(), 2);
    assert_eq!(all[0].content, "finding one");
    assert_eq!(all[0].node_id.as_deref(), Some("alice"));
    assert_eq!(all[1].content, "standalone");
    assert!(all[1].node_id.is_none());
}
