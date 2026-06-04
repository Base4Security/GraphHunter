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
            ok_json(RunHuntResponse {
                path_count: resp.path_count,
                truncated: resp.truncated,
                diagnostic: resp.diagnostic,
                live_tail_coverage: resp.live_tail_coverage,
            })
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
