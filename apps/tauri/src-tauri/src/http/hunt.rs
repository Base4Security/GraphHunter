//! Hunt execution, hunt-result paging, diffing, DSL parsing, explain_score.

use axum::{
    extract::{Query, State},
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use serde::Deserialize;
use std::collections::HashSet;
use std::sync::Arc;
use std::time::Duration;

use crate::{AppState, PaginatedHuntResults, Subgraph};
use graph_hunter_api::GraphHunterApi;
use graph_hunter_core::Hypothesis;

use super::helpers::{build_subgraph_for_ids, err_json, mcp_emit_view, ok_json};

#[derive(Debug, Deserialize)]
pub(super) struct ExplainScoreQuery {
    node_id: String,
}

pub(super) async fn handler_explain_score(
    State(api): State<Arc<GraphHunterApi>>,
    Query(q): Query<ExplainScoreQuery>,
) -> Response {
    super::helpers::api_response(api.explain_score(
        graph_hunter_api::dto::entity::NodeScopedRequest {
            session: None,
            node_id: q.node_id,
        },
    ))
}

#[derive(Debug, Deserialize)]
pub(super) struct HuntResultsQuery {
    page: Option<usize>,
    page_size: Option<usize>,
    min_score: Option<f64>,
}

pub(super) async fn handler_hunt_results(
    State(api): State<Arc<GraphHunterApi>>,
    Query(q): Query<HuntResultsQuery>,
) -> Response {
    let page = q.page.unwrap_or(0);
    let page_size = q.page_size.unwrap_or(20);
    match api.get_hunt_page(graph_hunter_api::dto::hunt::GetHuntPageRequest {
        session: None,
        page,
        page_size,
        min_score: q.min_score,
        dedup_mode: Some(graph_hunter_core::DedupMode::ByPath),
    }) {
        Ok(resp) => ok_json(PaginatedHuntResults {
            total_paths: resp.total_paths,
            filtered_paths: resp.filtered_paths,
            page: resp.page,
            page_size: resp.page_size,
            paths: resp.paths,
        }),
        Err(e) => {
            let code = StatusCode::from_u16(e.status_code())
                .unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
            (code, Json(serde_json::json!({ "error": e.to_string() }))).into_response()
        }
    }
}

#[derive(Debug, Deserialize)]
pub(super) struct RunHuntBody {
    hypothesis_dsl: String,
    /// v2 follow-up: per-call scoring override. Snake-case strings
    /// (`structural` | `anomaly` | `gnn`); maps to
    /// [`graph_hunter_api::dto::hunt::HuntScoring`]. Omit (or pass
    /// `null`) to keep v1 behavior — whatever scorer the session has
    /// decides which DFS runs.
    #[serde(default)]
    scoring: Option<graph_hunter_api::dto::hunt::HuntScoring>,
}

#[derive(serde::Serialize)]
pub(super) struct RunHuntResponse {
    path_count: usize,
    truncated: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    diagnostic: Option<graph_hunter_core::HuntDiagnostic>,
    #[serde(skip_serializing_if = "Option::is_none")]
    live_tail_coverage: Option<graph_hunter_core::LiveTailCoverage>,
    // Fase D/E: carry the core's answer-coverage across the transport so
    // the MCP consumer sees Fase F's missing_sources/source_watermarks.
    // Default coverage is omitted -> byte-identical wire when the flag is off.
    #[serde(skip_serializing_if = "is_default_coverage")]
    coverage: graph_hunter_api::coverage::AnswerCoverage,
}

fn is_default_coverage(c: &graph_hunter_api::coverage::AnswerCoverage) -> bool {
    *c == graph_hunter_api::coverage::AnswerCoverage::default()
}

/// Pure core->http projection. `paths` is intentionally not inlined
/// (the MCP pages results via /hunt_results); `coverage` MUST cross.
fn project_run_hunt_response(
    resp: &graph_hunter_api::dto::hunt::RunHuntResponse,
) -> RunHuntResponse {
    RunHuntResponse {
        path_count: resp.path_count,
        truncated: resp.truncated,
        diagnostic: resp.diagnostic.clone(),
        live_tail_coverage: resp.live_tail_coverage.clone(),
        coverage: resp.coverage.clone(),
    }
}

/// Write-heavy handler: uses spawn_blocking + timeout to avoid holding the async runtime.
pub(super) async fn handler_run_hunt(
    State(state): State<Arc<AppState>>,
    State(api): State<Arc<GraphHunterApi>>,
    Json(body): Json<RunHuntBody>,
) -> Response {
    let hypothesis: Hypothesis = match graph_hunter_core::parse_dsl(
        body.hypothesis_dsl.trim(),
        Some("MCP Hunt"),
    ) {
        Ok(r) => r.hypothesis,
        Err(e) => return err_json(e.to_string()),
    };
    let api_clone = api.clone();
    let hypothesis_for_search = hypothesis.clone();
    let scoring = body.scoring;
    let result = tokio::time::timeout(
        Duration::from_secs(30),
        tokio::task::spawn_blocking(move || {
            api_clone.run_hunt(graph_hunter_api::dto::hunt::RunHuntRequest {
                session: None,
                hypothesis: hypothesis_for_search,
                time_window: None,
                max_results: Some(10_000),
                scoring,
                dedup_mode: None,
            })
        }),
    )
    .await;

    match result {
        Ok(Ok(Ok(resp))) => {
            // The cache is already populated by api.run_hunt; we just
            // need to emit the mcp-view-update for the matched nodes.
            // Build `node_ids` from cache (resp.paths is empty when > 100).
            let paths = if resp.paths.is_empty() {
                // Pull from the shared hunt-cache handle (same Arc the
                // API just wrote to). Using the API's `hunt_cache_handle`
                // keeps every transport on the exact same state.
                api.hunt_cache_handle()
                    .read()
                    .ok()
                    .map(|g| g.clone())
                    .unwrap_or_default()
            } else {
                resp.paths.clone()
            };
            let node_ids: Vec<String> = paths
                .iter()
                .flat_map(|p| p.iter().map(|s| s.to_string()))
                .collect::<HashSet<_>>()
                .into_iter()
                .collect();
            if !node_ids.is_empty() {
                if let Ok(sg) = build_subgraph_for_ids(api.as_ref(), &node_ids) {
                    mcp_emit_view(state.as_ref(), sg);
                }
            } else if resp.path_count == 0 {
                mcp_emit_view(
                    state.as_ref(),
                    Subgraph {
                        nodes: vec![],
                        edges: vec![],
                        total_edges: 0,
                        returned_edges: 0,
                        offset: 0,
                        page_size: 0,
                        has_more: false,
                    },
                );
            }
            ok_json(project_run_hunt_response(&resp))
        }
        Ok(Ok(Err(e))) => {
            let code = StatusCode::from_u16(e.status_code())
                .unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
            (code, Json(serde_json::json!({ "error": e.to_string() }))).into_response()
        }
        Ok(Err(e)) => err_json(format!("Task error: {}", e)),
        Err(_) => err_json("Hunt timed out after 30 seconds".to_string()),
    }
}

#[derive(Debug, Deserialize)]
pub(super) struct DiffHuntsBody {
    hypothesis_dsl: String,
    baseline_ts: i64,
    current_ts: i64,
}

pub(super) async fn handler_diff_hunts(
    State(api): State<Arc<GraphHunterApi>>,
    Json(body): Json<DiffHuntsBody>,
) -> Response {
    let hypothesis: Hypothesis = match graph_hunter_core::parse_dsl(
        body.hypothesis_dsl.trim(),
        Some("MCP Diff Hunt"),
    ) {
        Ok(r) => r.hypothesis,
        Err(e) => return err_json(e.to_string()),
    };
    let api_clone = api.clone();
    let result = tokio::time::timeout(
        Duration::from_secs(60),
        tokio::task::spawn_blocking(move || {
            api_clone.diff_hunts(graph_hunter_api::dto::hunt::DiffHuntsRequest {
                session: None,
                hypothesis,
                baseline_ts: body.baseline_ts,
                current_ts: body.current_ts,
            })
        }),
    )
    .await;

    match result {
        Ok(Ok(Ok(v))) => ok_json(v),
        Ok(Ok(Err(e))) => {
            let code = StatusCode::from_u16(e.status_code())
                .unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
            (code, Json(serde_json::json!({ "error": e.to_string() }))).into_response()
        }
        Ok(Err(e)) => err_json(format!("Task error: {}", e)),
        Err(_) => err_json("Diff timed out after 60 seconds".to_string()),
    }
}

#[derive(Debug, Deserialize)]
pub(super) struct ParseDslBody {
    dsl: String,
    name: Option<String>,
}

pub(super) async fn handler_parse_dsl(
    State(api): State<Arc<GraphHunterApi>>,
    Json(body): Json<ParseDslBody>,
) -> Response {
    // Preserve the legacy `{valid, formatted, steps}` / `{valid:false, error}`
    // shape for existing MCP clients. The canonical error path
    // (`ApiError::InvalidInput` → 400) will become the default when MCP
    // clients are migrated in a later phase; for now, adapt.
    match api.parse_dsl(graph_hunter_api::dto::dsl::ParseDslRequest {
        input: body.dsl,
        name: body.name,
    }) {
        Ok(resp) => ok_json(serde_json::json!({
            "valid": true,
            "formatted": resp.formatted,
            "steps": resp.steps,
        })),
        Err(e) => ok_json(serde_json::json!({
            "valid": false,
            "error": e.to_string(),
        })),
    }
}

/// Test-only fixture builder, kept `pub(crate)` (not nested inside `mod
/// tests`) so the oneshot equivalence test below can reach it via
/// `crate::http::hunt::tests_support::seeded_hunt_fixture()`.
#[cfg(test)]
pub(crate) mod tests_support {
    use super::*;
    use graph_hunter_api::state::{Session, SessionPhase};
    use graph_hunter_core::{Entity, EntityType, GraphHunter, Relation, RelationType};
    use std::sync::RwLock;

    /// Build a seeded `AppState` + `GraphHunterApi` + current session id +
    /// a DSL hypothesis that matches the seeded graph, shared by both
    /// transports in the cross-transport equivalence test.
    ///
    /// Deterministic, in-memory only:
    /// - `app_handle` stays `None` — there is no Tauri runtime in a unit
    ///   test, and `mcp_emit_view` (see `http/helpers.rs`) already
    ///   tolerates a `None` handle by skipping the `emit` call.
    /// - `journal` points at a fresh, uniquely-named directory under the
    ///   OS temp dir — the mandatory capture middleware (`http/mod.rs`)
    ///   writes an event there for every non-exempt route, `/run_hunt`
    ///   included, so the journal needs somewhere real to write.
    pub(crate) fn seeded_hunt_fixture() -> (Arc<AppState>, GraphHunterApi, String, String) {
        let api = GraphHunterApi::new_noop();

        // Graph: alice/bob (User) --Auth--> web-01 (Host). Matches the
        // parity fixture shape in `platform/api/tests/parity/fixture.rs`.
        let mut graph = GraphHunter::new();
        graph
            .add_entity(Entity::new("alice", EntityType::User))
            .ok();
        graph.add_entity(Entity::new("bob", EntityType::User)).ok();
        graph
            .add_entity(Entity::new("web-01", EntityType::Host))
            .ok();
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
                "bob".to_string(),
                "web-01".to_string(),
                RelationType::Auth,
                1_700_000_010,
            ))
            .ok();
        graph
            .sort_edges_by_timestamp()
            .expect("sort edges after seed");

        let session_id = "t-session".to_string();
        let session = Arc::new(Session::new(session_id.clone(), "t", graph, 0));
        session.set_phase(SessionPhase::Ready);
        api.sessions().insert(session);
        api.sessions().set_current(Some(session_id.clone()));

        let journal_dir = std::env::temp_dir().join(format!(
            "graphhunter-test-journal-{}",
            uuid::Uuid::new_v4()
        ));
        let journal = Arc::new(crate::journal::store::JournalStore::new(journal_dir));

        let app_state = Arc::new(AppState {
            sessions: api.sessions().map_handle(),
            current_session_id: api.sessions().current_handle(),
            app_handle: Arc::new(RwLock::new(None)),
            last_mcp_subgraph: RwLock::new(None),
            api_token: "test-token".to_string(),
            journal,
        });

        (
            app_state,
            api,
            session_id,
            "User -[Auth]-> Host".to_string(),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use graph_hunter_api::coverage::AnswerCoverage;

    // A core response with a populated coverage (Fase F: a blind source)
    // must survive the core->http projection and appear on the wire.
    #[test]
    fn coverage_survives_core_to_http_projection() {
        let mut cov = AnswerCoverage::default();
        cov.possibly_incomplete = true;
        cov.missing_sources = vec!["sentinel".to_string()];
        cov.source_watermarks.insert("elastic".to_string(), 42);

        let core = graph_hunter_api::dto::hunt::RunHuntResponse {
            paths: vec![],
            path_count: 7,
            truncated: false,
            diagnostic: None,
            live_tail_coverage: None,
            coverage: cov,
        };

        let http = project_run_hunt_response(&core);
        let v = serde_json::to_value(&http).unwrap();
        assert_eq!(v["path_count"], 7);
        assert_eq!(v["coverage"]["missing_sources"][0], "sentinel");
        assert_eq!(v["coverage"]["source_watermarks"]["elastic"], 42);
        assert_eq!(v["coverage"]["possibly_incomplete"], true);
    }

    // No-op when off: a default coverage must be omitted entirely so
    // flag-off callers see byte-identical JSON to the pre-coverage wire.
    #[test]
    fn default_coverage_is_omitted_from_http_wire() {
        let core = graph_hunter_api::dto::hunt::RunHuntResponse {
            paths: vec![],
            path_count: 0,
            truncated: false,
            diagnostic: None,
            live_tail_coverage: None,
            coverage: AnswerCoverage::default(),
        };
        let http = project_run_hunt_response(&core);
        let v = serde_json::to_value(&http).unwrap();
        assert!(v.get("coverage").is_none(), "default coverage must be omitted from the wire");
    }

    // §25.11 cross-transport certificate: the same hypothesis, run once
    // directly through `GraphHunterApi::run_hunt` and once through the
    // real axum router via `/run_hunt`, must produce the same answer.
    // A full seeded `AppState` turned out to be constructible in a unit
    // test (see `tests_support::seeded_hunt_fixture`): `app_handle` is an
    // `Option` that `mcp_emit_view` already tolerates as `None`, and the
    // journal only needs a writable directory, not a running Tauri
    // instance. So this lands as the full form, not the reduced
    // 200-against-an-empty-session fallback.
    #[tokio::test]
    async fn same_hypothesis_same_result_core_vs_http() {
        use tower::ServiceExt; // oneshot
        use axum::body::Body;
        use axum::http::{Request, StatusCode};

        let (app_state, api, _session_id, dsl) = tests_support::seeded_hunt_fixture();

        // (a) direct core call.
        let core = api
            .run_hunt(graph_hunter_api::dto::hunt::RunHuntRequest {
                session: None,
                hypothesis: graph_hunter_core::parse_dsl(&dsl, Some("t")).unwrap().hypothesis,
                time_window: None,
                max_results: Some(10_000),
                scoring: None,
                dedup_mode: None,
            })
            .unwrap();
        // Sanity: the fixture's DSL must actually match the seeded graph,
        // otherwise this test would trivially "pass" by comparing two
        // empty answers.
        assert!(core.path_count > 0, "fixture DSL matched nothing");

        // (b) through the real router. The auth middleware requires a
        // Bearer token matching `AppState.api_token` for every route
        // except `/`, `/health`, `/metrics`, `/v1/schema`.
        let token = app_state.api_token.clone();
        let app = crate::http::build_app(app_state, Arc::new(api.clone()));
        let req = Request::builder()
            .method("POST")
            .uri("/run_hunt")
            .header("content-type", "application/json")
            .header("authorization", format!("Bearer {token}"))
            .body(Body::from(serde_json::json!({ "hypothesis_dsl": dsl }).to_string()))
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let http: serde_json::Value = serde_json::from_slice(&bytes).unwrap();

        // Same hypothesis => same answer across transports.
        assert_eq!(http["path_count"].as_u64().unwrap() as usize, core.path_count);
        assert_eq!(http["truncated"].as_bool().unwrap(), core.truncated);
    }
}
