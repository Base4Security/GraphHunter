//! Phase A — DTO shape parity tests.
//!
//! Every Request/Response DTO that flows between the canonical API
//! and a transport must keep its JSON shape stable. A field rename
//! or enum tag change is a breaking contract for the three
//! transports simultaneously — these tests catch that drift at
//! compile / test time.
//!
//! Strategy: build a DTO value in Rust, serialize to JSON, assert
//! on the top-level field names. For DTOs that are also
//! `Deserialize`, roundtrip and assert structural equality.

use graph_hunter_api::dto::*;
use graph_hunter_api::state::SessionHandle;
use serde_json::Value;

/// Assert that `value` serializes to a JSON object with exactly the
/// expected top-level keys (order-independent, ignoring keys marked
/// `skip_serializing_if` that happen to be absent).
fn assert_keys<T: serde::Serialize>(value: &T, expected: &[&str]) {
    let v = serde_json::to_value(value).expect("serialize");
    let obj = v
        .as_object()
        .unwrap_or_else(|| panic!("expected object, got: {v}"));
    let actual: std::collections::BTreeSet<&str> = obj.keys().map(|s| s.as_str()).collect();
    let expected_set: std::collections::BTreeSet<&str> = expected.iter().copied().collect();
    assert_eq!(
        actual, expected_set,
        "DTO key drift — expected {expected:?}, got {actual:?}"
    );
}

// ── Session ─────────────────────────────────────────────────────────

#[test]
fn session_info_shape() {
    let info = session::SessionInfo {
        id: "s1".into(),
        name: "test".into(),
        created_at: 1_700_000_000,
    };
    assert_keys(&info, &["id", "name", "created_at"]);
}

#[test]
fn create_session_request_omits_none() {
    let empty = session::CreateSessionRequest { name: None };
    let v = serde_json::to_value(&empty).unwrap();
    assert!(
        v.as_object().unwrap().is_empty(),
        "None name must skip serializing, got: {v}"
    );
}

#[test]
fn session_handle_serializes_transparent() {
    let h = SessionHandle::from_string("abc-123");
    let v = serde_json::to_value(&h).unwrap();
    assert_eq!(v, Value::String("abc-123".into()));
    let back: SessionHandle = serde_json::from_value(v).unwrap();
    assert_eq!(back.as_str(), "abc-123");
}

// ── DSL / catalog ───────────────────────────────────────────────────

#[test]
fn parse_dsl_response_shape() {
    use graph_hunter_core::{Hypothesis, parse_dsl};
    let parsed = parse_dsl("User -[Auth]-> Host", None).unwrap();
    let steps = parsed.hypothesis.steps.len();
    let resp = dsl::ParseDslResponse {
        hypothesis: parsed.hypothesis,
        formatted: parsed.formatted,
        steps,
    };
    assert_keys(&resp, &["hypothesis", "formatted", "steps"]);
    let _: Hypothesis =
        serde_json::from_value(serde_json::to_value(&resp).unwrap()["hypothesis"].clone())
            .expect("hypothesis roundtrip");
}

// ── Hunt ────────────────────────────────────────────────────────────

#[test]
fn run_hunt_request_shape() {
    use graph_hunter_core::parse_dsl;
    let h = parse_dsl("User -[Auth]-> Host", None).unwrap().hypothesis;
    let req = hunt::RunHuntRequest {
        session: None,
        hypothesis: h,
        time_window: Some((0, 100)),
        max_results: Some(500),
        scoring: None,
        dedup_mode: None,
    };
    assert_keys(&req, &["hypothesis", "time_window", "max_results"]);
}

#[test]
fn run_hunt_response_shape_with_inline_paths() {
    let resp = hunt::RunHuntResponse {
        paths: vec![vec!["a".into(), "b".into()]],
        path_count: 1,
        truncated: false,
        diagnostic: None,
        live_tail_coverage: None,
    };
    assert_keys(&resp, &["paths", "path_count", "truncated"]);
}

// ── Sentinel ────────────────────────────────────────────────────────

#[test]
fn connector_status_enum_tag_is_state() {
    use graph_hunter_api::sentinel_connector::ConnectorStatus;
    let s = ConnectorStatus::Connected {
        last_data_at: "now".into(),
        total_entities: 1,
        total_relations: 2,
    };
    let v = serde_json::to_value(&s).unwrap();
    assert_eq!(v["state"], "Connected");
    assert_eq!(v["total_entities"], 1);
}

#[test]
fn connector_status_disconnected_is_unit_variant() {
    use graph_hunter_api::sentinel_connector::ConnectorStatus;
    let v = serde_json::to_value(ConnectorStatus::Disconnected).unwrap();
    assert_eq!(v["state"], "Disconnected");
}

// ── Error ───────────────────────────────────────────────────────────

#[test]
fn api_error_struct_variant_serializes_with_kind_tag() {
    use graph_hunter_api::ApiError;
    // Upstream is a struct variant — serializes cleanly under the
    // `tag = "kind"` attribute.
    let e = ApiError::Upstream {
        service: "sentinel".into(),
        message: "429".into(),
    };
    let v = serde_json::to_value(&e).unwrap();
    assert_eq!(v["kind"], "upstream");
    assert_eq!(v["service"], "sentinel");
    assert_eq!(v["message"], "429");

    // Roundtrip via text so we catch any `#[serde(rename_all)]` drift.
    let back: ApiError = serde_json::from_value(v).unwrap();
    assert_eq!(format!("{e}"), format!("{back}"));
}

#[test]
fn api_error_display_format_is_stable() {
    use graph_hunter_api::ApiError;
    // Newtype variants of `ApiError` don't roundtrip through internal
    // tagging (serde limitation), so we verify the user-facing
    // `Display` contract stays stable instead. Transports use
    // `e.to_string()` to map the error message into their own
    // envelope (HTTP: `{"error": "<display>"}`; Tauri: `CommandError`
    // `message` field).
    assert_eq!(
        ApiError::SessionNotFound("sess-1".into()).to_string(),
        "session not found: sess-1"
    );
    assert_eq!(
        ApiError::NoCurrentSession.to_string(),
        "no current session selected"
    );
    assert_eq!(
        ApiError::InvalidInput("bad dsl".into()).to_string(),
        "invalid input: bad dsl"
    );
}

// ── Catalog (P2-C) ──────────────────────────────────────────────────

#[test]
fn catalog_entry_shape_excludes_source() {
    // `source` is populated by the loader but `#[serde(skip)]` so the
    // JSON shape the three transports emit matches the pre-P2-C
    // contract in `app/src/types.ts::CatalogEntry`. A drift here
    // breaks both the Tauri frontend and the MCP schema.
    use graph_hunter_core::{CatalogEntry, CatalogSource};
    let e = CatalogEntry {
        id: "cat-001".into(),
        name: "Lateral Auth".into(),
        mitre_id: "T1078".into(),
        description: "test".into(),
        dsl_pattern: "User -[Auth]-> Host".into(),
        k_simplicity: 1,
        source: CatalogSource::BuiltIn,
    };
    assert_keys(
        &e,
        &[
            "id",
            "name",
            "mitre_id",
            "description",
            "dsl_pattern",
            "k_simplicity",
        ],
    );
}

#[test]
fn catalog_entry_with_status_includes_source() {
    use graph_hunter_core::{CatalogEntry, CatalogEntryWithStatus, CatalogSource};
    let e = CatalogEntry {
        id: "cat-001".into(),
        name: "n".into(),
        mitre_id: "T1078".into(),
        description: "d".into(),
        dsl_pattern: "User -[Auth]-> Host".into(),
        k_simplicity: 1,
        source: CatalogSource::BuiltIn,
    };
    let status = CatalogEntryWithStatus {
        entry: e,
        compatible: true,
        missing_entity_types: Vec::new(),
        missing_rel_types: Vec::new(),
        failed_step_index: None,
        source: CatalogSource::BuiltIn,
    };
    let v = serde_json::to_value(&status).unwrap();
    // CatalogEntry fields flatten in, PLUS the new `source` and
    // `compatible` fields. `missing_*` and `failed_step_index` are
    // absent because they use `skip_serializing_if`.
    let keys: std::collections::BTreeSet<&str> =
        v.as_object().unwrap().keys().map(|s| s.as_str()).collect();
    for expected in [
        "id",
        "name",
        "mitre_id",
        "description",
        "dsl_pattern",
        "k_simplicity",
        "compatible",
        "source",
    ] {
        assert!(keys.contains(expected), "missing {expected} in {keys:?}");
    }
}

#[test]
fn catalog_source_builtin_serializes_with_kind_tag() {
    use graph_hunter_core::CatalogSource;
    let v = serde_json::to_value(CatalogSource::BuiltIn).unwrap();
    assert_eq!(v["kind"], "built_in");
}

#[test]
fn catalog_source_user_file_serializes_path() {
    use graph_hunter_core::CatalogSource;
    let v = serde_json::to_value(CatalogSource::UserFile {
        path: "/tmp/my.yaml".into(),
    })
    .unwrap();
    assert_eq!(v["kind"], "user_file");
    assert_eq!(v["path"], "/tmp/my.yaml");
}

#[test]
fn catalog_load_error_shape() {
    use graph_hunter_core::CatalogLoadError;
    let e = CatalogLoadError {
        source_path: Some(std::path::PathBuf::from("/tmp/bad.yaml")),
        entry_id: Some("cat-bad".into()),
        message: "yaml parse error".into(),
    };
    assert_keys(&e, &["source_path", "entry_id", "message"]);
}

// ── Entity / tag / note ─────────────────────────────────────────────

#[test]
fn tag_entity_request_shape() {
    let req = entity::TagEntityRequest {
        session: None,
        node_id: "alice".into(),
        tag: "ioc:malicious".into(),
        reason: Some("password spray".into()),
    };
    assert_keys(&req, &["node_id", "tag", "reason"]);
}

#[test]
fn note_shape() {
    use graph_hunter_api::state::Note;
    let note = Note {
        id: "n1".into(),
        content: "something".into(),
        node_id: Some("alice".into()),
        created_at: 1,
    };
    assert_keys(&note, &["id", "content", "node_id", "created_at"]);
}

// ── Subgraph ────────────────────────────────────────────────────────

#[test]
fn subgraph_shape() {
    use graph_hunter_api::dto::graph_ops::{Subgraph, SubgraphEdge, SubgraphNode};
    use std::collections::HashMap;
    let sg = Subgraph {
        nodes: vec![SubgraphNode::new(
            "alice".into(),
            "User".into(),
            0.0,
            HashMap::new(),
        )],
        edges: vec![SubgraphEdge {
            source: "alice".into(),
            target: "web-01".into(),
            rel_type: "Auth".into(),
            timestamp: 1,
            metadata: HashMap::new(),
            dataset_id: None,
        }],
        // RH-P1-013: pagination envelope present in the wire shape since
        // 2026-05-06. Tests must include it so frontends/transports stay
        // aware that these keys exist on the JSON object.
        ..Default::default()
    };
    assert_keys(
        &sg,
        &[
            "nodes",
            "edges",
            "total_edges",
            "returned_edges",
            "offset",
            "page_size",
            "has_more",
        ],
    );
    let v = serde_json::to_value(&sg).unwrap();
    assert_eq!(v["nodes"][0]["id"], "alice");
    // `ip_class` is skipped when None.
    assert!(v["nodes"][0].get("ip_class").is_none());
    // `dataset_id` is skipped when None.
    assert!(v["edges"][0].get("dataset_id").is_none());
}

#[test]
fn subgraph_node_ip_class_populated_for_ip() {
    use graph_hunter_api::dto::graph_ops::SubgraphNode;
    use std::collections::HashMap;
    let n = SubgraphNode::new("10.0.0.1".into(), "IP".into(), 0.0, HashMap::new());
    let v = serde_json::to_value(&n).unwrap();
    assert_eq!(v["ip_class"], "Private");
}
