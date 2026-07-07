//! Fixture session builder. Deterministic, in-memory only — no disk
//! reads, no network. Populates a small graph with a handful of
//! entities and relations so scenario tests can exercise `run_hunt`,
//! `diff_hunts`, `export`, `tag_entity`, etc. against a known shape.

use graph_hunter_api::GraphHunterApi;
use graph_hunter_api::dto::dsl::ParseDslRequest;
use graph_hunter_api::dto::entity::{CreateNoteRequest, TagEntityRequest};
use graph_hunter_api::dto::session::CreateSessionRequest;

/// Build a fresh API façade, create a single session, and return the
/// API + the session id. No graph content yet — scenarios populate
/// as needed.
pub fn fresh_api_with_session() -> (GraphHunterApi, String) {
    let api = GraphHunterApi::new_noop();
    let info = api
        .create_session(CreateSessionRequest {
            name: Some("parity-fixture".into()),
        })
        .expect("create_session should succeed on a fresh API");
    (api, info.id)
}

/// Same as [`fresh_api_with_session`] but also seeds a tiny known
/// subgraph so `expand_node`, `search_entities`, `tag_entity` etc.
/// have something to return.
///
/// The graph:
///   User:"alice"  -[Auth]->   Host:"web-01"
///   Host:"web-01" -[Execute]-> Process:"cmd.exe"
///   User:"bob"    -[Auth]->   Host:"web-01"
///
/// Deterministic timestamps starting at `1_700_000_000`.
pub fn fresh_api_with_seeded_session() -> (GraphHunterApi, String) {
    use graph_hunter_core::{Entity, EntityType, Relation, RelationType};

    let (api, id) = fresh_api_with_session();
    let session = api
        .sessions()
        .current_session()
        .expect("session was just created");
    let mut graph = session.graph.write().expect("graph lock");

    // Entities
    graph
        .add_entity(Entity::new("alice", EntityType::User))
        .ok();
    graph.add_entity(Entity::new("bob", EntityType::User)).ok();
    graph
        .add_entity(Entity::new("web-01", EntityType::Host))
        .ok();
    graph
        .add_entity(Entity::new("cmd.exe", EntityType::Process))
        .ok();

    // Relations (timestamps ascending)
    graph
        .add_relation(Relation::new(
            "alice".to_string(),
            "web-01".to_string(),
            RelationType::Auth,
            1_700_000_000,
        ))
        .ok();
    graph
        .add_relation(Relation::new(
            "web-01".to_string(),
            "cmd.exe".to_string(),
            RelationType::Execute,
            1_700_000_010,
        ))
        .ok();
    graph
        .add_relation(Relation::new(
            "bob".to_string(),
            "web-01".to_string(),
            RelationType::Auth,
            1_700_000_020,
        ))
        .ok();

    graph
        .sort_edges_by_timestamp()
        .expect("sort edges after seed");
    drop(graph);

    session.set_phase(graph_hunter_api::state::SessionPhase::Ready);

    (api, id)
}

/// Tag an entity to exercise `export_iocs`, `list_tagged`, etc.
pub fn tag(api: &GraphHunterApi, node_id: &str, tag: &str) {
    api.tag_entity(TagEntityRequest {
        session: None,
        node_id: node_id.to_string(),
        tag: tag.to_string(),
        reason: None,
    })
    .expect("tag_entity");
}

/// Attach a note so `get_notes` / `create_note` scenarios have
/// something to return.
pub fn note(api: &GraphHunterApi, content: &str, node_id: Option<&str>) {
    api.create_note(CreateNoteRequest {
        session: None,
        content: content.to_string(),
        node_id: node_id.map(|s| s.to_string()),
    })
    .expect("create_note");
}

/// Parse a DSL pattern via the API (same code path every transport
/// uses). Panics on failure — fixtures should never pass invalid
/// DSL.
pub fn parse(api: &GraphHunterApi, dsl: &str) -> graph_hunter_core::Hypothesis {
    api.parse_dsl(ParseDslRequest {
        input: dsl.to_string(),
        name: Some("fixture".into()),
    })
    .expect("parse_dsl")
    .hypothesis
}
