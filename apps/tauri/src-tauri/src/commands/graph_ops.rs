use std::sync::Arc;

use graph_hunter_api::dto::entity::{NodeScopedRequest, SessionOnly};
use graph_hunter_api::dto::graph_ops::{
    ComputeScoresRequest, EventsForNodeRequest, EventsPaginatedRequest, ExpandNodeRequest,
    PreviewFieldsRequest, SearchEntitiesRequest, SubgraphRequest,
};
use graph_hunter_api::dto::hunt::{
    DiffHuntsRequest, GetHuntPageRequest, RunHuntBatchRequest, RunHuntBatchResponse,
    RunHuntRequest,
};
use graph_hunter_api::GraphHunterApi;
use graph_hunter_core::{
    DedupMode, FieldConfig, FieldInfo, Hypothesis, Neighborhood,
};
use tauri::State;

use crate::error::CommandError;
// All graph access goes through `Arc<GraphHunterApi>` — legacy
// `with_current_graph*` helpers, direct scoring, and EVTX helpers
// are no longer needed in this module.
use crate::types::{
    ExpandFilter, HuntResults, LoadResult, PaginatedHuntResults, Subgraph, SubgraphEdge,
};

// `GraphStats` moved to `graph_hunter_api::dto::graph_ops`. Re-export
// here so call sites that `use crate::types::GraphStats` keep compiling
// (and the frontend JSON shape is unchanged).
pub use graph_hunter_api::dto::graph_ops::GraphStats;

/// Returns current graph statistics (node and edge counts).
#[tauri::command]
pub fn cmd_get_graph_stats(api: State<Arc<GraphHunterApi>>) -> Result<GraphStats, CommandError> {
    api.get_graph_stats(SessionOnly::default())
        .map_err(CommandError::from)
}

/// Executes a temporal pattern search using the provided hypothesis.
/// Tauri receives `hypothesis_json` (stringified — frontend quirk) so we
/// parse it here before delegating to the canonical `run_hunt`.
#[tauri::command]
pub fn cmd_run_hunt(
    api: State<Arc<GraphHunterApi>>,
    hypothesis_json: String,
    time_window: Option<(i64, i64)>,
) -> Result<HuntResults, CommandError> {
    let hypothesis: Hypothesis = serde_json::from_str(&hypothesis_json)
        .map_err(|e| CommandError::ParseError(format!("Invalid hypothesis JSON: {}", e)))?;
    let resp = api
        .run_hunt(RunHuntRequest {
            session: None,
            hypothesis,
            time_window,
            max_results: Some(10_000),
            // Tauri command keeps v1 semantics — sticky session scorer
            // decides. The MCP `hunt.run` is the path that exposes the
            // per-call override.
            scoring: None,
            // Dedup is exposed only via the MCP API path for now; the
            // Tauri UI relies on get_hunt_page's own dedup_mode.
            dedup_mode: None,
        })
        .map_err(CommandError::from)?;
    Ok(HuntResults {
        paths: resp.paths,
        path_count: resp.path_count,
        truncated: resp.truncated,
        diagnostic: resp.diagnostic,
        live_tail_coverage: resp.live_tail_coverage,
    })
}

/// L2 — execute a batch of hypotheses against the current session.
/// Pre-warms NLF + k-hop reachability indexes once, then runs each
/// hypothesis through the same planner dispatch as `cmd_run_hunt`.
/// Per-hypothesis errors are isolated; a malformed query in
/// position k fails its entry but does not poison the rest.
///
/// Plug-and-play: no env flag, no toggle. Frontend callers that
/// want to ship a battery of templates (ATT&CK preset, saved
/// hunt list) call this instead of calling `cmd_run_hunt` in a
/// loop, and benefit from the shared index pre-warm.
#[tauri::command]
pub fn cmd_run_hunt_batch(
    api: State<Arc<GraphHunterApi>>,
    hypotheses_json: String,
    time_window: Option<(i64, i64)>,
    max_results: Option<usize>,
) -> Result<RunHuntBatchResponse, CommandError> {
    let hypotheses: Vec<Hypothesis> = serde_json::from_str(&hypotheses_json)
        .map_err(|e| CommandError::ParseError(format!("Invalid hypothesis batch JSON: {}", e)))?;
    api.run_hunt_batch(RunHuntBatchRequest {
        session: None,
        hypotheses,
        time_window,
        max_results: max_results.or(Some(10_000)),
        dedup_mode: None,
    })
    .map_err(CommandError::from)
}

/// Returns a paginated, scored, and optionally filtered page of cached hunt results.
#[tauri::command]
pub fn cmd_get_hunt_page(
    api: State<Arc<GraphHunterApi>>,
    page: usize,
    page_size: usize,
    min_score: Option<f64>,
    dedup_mode: Option<DedupMode>,
) -> Result<PaginatedHuntResults, CommandError> {
    let resp = api
        .get_hunt_page(GetHuntPageRequest {
            session: None,
            page,
            page_size,
            min_score,
            dedup_mode,
        })
        .map_err(CommandError::from)?;
    Ok(PaginatedHuntResults {
        total_paths: resp.total_paths,
        filtered_paths: resp.filtered_paths,
        page: resp.page,
        page_size: resp.page_size,
        paths: resp.paths,
    })
}

/// Run the same hunt at two upper time bounds and return the diff.
#[tauri::command]
pub fn cmd_diff_hunts(
    api: State<Arc<GraphHunterApi>>,
    hypothesis_json: String,
    baseline_ts: i64,
    current_ts: i64,
) -> Result<graph_hunter_core::HuntDiff, CommandError> {
    let hypothesis: Hypothesis = serde_json::from_str(&hypothesis_json)
        .map_err(|e| CommandError::ParseError(format!("Invalid hypothesis JSON: {}", e)))?;
    api.diff_hunts(DiffHuntsRequest {
        session: None,
        hypothesis,
        baseline_ts,
        current_ts,
    })
    .map_err(CommandError::from)
}

/// Returns all relations (events) where the given node is source or
/// target. Caps at 500; use `cmd_get_events_paginated` for deeper browsing.
#[tauri::command]
pub fn cmd_get_events_for_node(
    api: State<Arc<GraphHunterApi>>,
    node_id: String,
) -> Result<Vec<SubgraphEdge>, CommandError> {
    api.get_events_for_node(EventsForNodeRequest {
        session: None,
        node_id,
    })
    .map_err(CommandError::from)
}

/// Paginated events for a node with optional `sort_by` key.
#[tauri::command]
pub fn cmd_get_events_paginated(
    api: State<Arc<GraphHunterApi>>,
    node_id: String,
    page: usize,
    page_size: Option<usize>,
    sort_by: Option<String>,
) -> Result<crate::types::PaginatedEvents, CommandError> {
    api.get_events_paginated(EventsPaginatedRequest {
        session: None,
        node_id,
        page,
        page_size,
        sort_by,
    })
    .map_err(CommandError::from)
}

/// Returns the complete subgraph (nodes + edges) induced by the given IDs.
#[tauri::command]
pub fn cmd_get_subgraph(
    api: State<Arc<GraphHunterApi>>,
    node_ids: Vec<String>,
    page_size: Option<usize>,
    offset: Option<usize>,
) -> Result<Subgraph, CommandError> {
    api.get_subgraph(SubgraphRequest {
        session: None,
        node_ids,
        page_size,
        offset,
    })
    .map_err(CommandError::from)
}

/// Searches entities by substring match. When `query` is empty the
/// engine operates in list-mode — a `type_filter` is required in that
/// case to avoid unbounded enumeration.
#[tauri::command]
pub fn cmd_search_entities(
    api: State<Arc<GraphHunterApi>>,
    query: String,
    type_filter: Option<String>,
    limit: Option<usize>,
) -> Result<Vec<graph_hunter_core::SearchResult>, CommandError> {
    api.search_entities(SearchEntitiesRequest {
        session: None,
        query,
        type_filter,
        limit,
    })
    .map_err(CommandError::from)
}

/// Expands a node's neighborhood for interactive exploration.
/// High-degree nodes auto-fall-back to grouped expansion (see
/// `cmd_expand_node_grouped`). Pinned path nodes from the current session
/// are merged into the result so the analyst's workspace stays visible.
/// `live` and `time_window` are optional — absent callers receive the
/// existing static-graph behaviour unchanged.
#[tauri::command]
pub async fn cmd_expand_node(
    api: State<'_, Arc<GraphHunterApi>>,
    node_id: String,
    max_hops: Option<usize>,
    max_nodes: Option<usize>,
    filter: Option<ExpandFilter>,
    live: Option<bool>,
    time_window: Option<graph_hunter_api::dto::sentinel::TimeWindow>,
) -> Result<Neighborhood, CommandError> {
    let req = ExpandNodeRequest {
        session: None,
        node_id,
        max_hops,
        max_nodes,
        filter,
        live: live.unwrap_or(false),
        time_window,
    };
    if req.live {
        api.expand_node_live(req).await.map_err(CommandError::from)
    } else {
        api.expand_node(req).map_err(CommandError::from)
    }
}

/// Expands a node's neighborhood with grouped edges (for high-degree
/// nodes). Collapses parallel edges into summary entries with count and
/// time range.
#[tauri::command]
pub fn cmd_expand_node_grouped(
    api: State<Arc<GraphHunterApi>>,
    node_id: String,
    max_hops: Option<usize>,
    max_nodes: Option<usize>,
    filter: Option<ExpandFilter>,
) -> Result<graph_hunter_core::GroupedNeighborhood, CommandError> {
    api.expand_node_grouped(ExpandNodeRequest {
        session: None,
        node_id,
        max_hops,
        max_nodes,
        filter,
        live: false,
        time_window: None,
    })
    .map_err(CommandError::from)
}

// Legacy `cmd_expand_node` / `cmd_expand_node_grouped` bodies removed —
// their logic now lives in `GraphHunterApi::expand_node` and
// `expand_node_grouped`. The delegation-only replacements are defined
// above.

/// Returns detailed information about a specific node.
#[tauri::command]
pub fn cmd_get_node_details(
    api: State<Arc<GraphHunterApi>>,
    node_id: String,
) -> Result<graph_hunter_core::NodeDetails, CommandError> {
    api.get_node_details(NodeScopedRequest {
        session: None,
        node_id,
    })
    .map_err(CommandError::from)
}

/// Returns a summary of the entire graph plus runtime capabilities.
/// Delegates to the canonical API.
#[tauri::command]
pub fn cmd_get_graph_summary(
    api: State<Arc<GraphHunterApi>>,
) -> Result<GraphSummaryWithCapabilities, CommandError> {
    api.get_graph_summary(graph_hunter_api::dto::geoip::GraphSummaryRequest::default())
        .map_err(CommandError::from)
}

/// Re-export the canonical response shape so external consumers
/// (e.g., http_api.rs) keep using `crate::commands::graph_ops::GraphSummaryWithCapabilities`.
pub use graph_hunter_api::dto::geoip::GraphSummaryWithCapabilities;

/// Recalculates scores for all entities.
#[tauri::command]
pub fn cmd_compute_scores(api: State<Arc<GraphHunterApi>>) -> Result<(), CommandError> {
    api.compute_scores(ComputeScoresRequest::default())
        .map_err(CommandError::from)
}

/// Previews all fields in a log file by sampling the first N events.
#[tauri::command]
pub fn cmd_preview_fields(
    api: State<Arc<GraphHunterApi>>,
    path: String,
    sample_size: Option<usize>,
) -> Result<Vec<FieldInfo>, CommandError> {
    api.preview_fields(PreviewFieldsRequest { path, sample_size })
        .map_err(CommandError::from)
}

/// Ingests logs using a user-configured field mapping. Delegates to
/// the canonical API.
#[tauri::command]
pub fn cmd_load_data_with_config(
    api: State<Arc<GraphHunterApi>>,
    path: String,
    config: FieldConfig,
) -> Result<LoadResult, CommandError> {
    api.load_data_with_config(graph_hunter_api::dto::ingestion::LoadDataWithConfigRequest {
        session: None,
        path,
        config,
    })
    .map_err(CommandError::from)
}

/// Returns the runtime-detected SIMD ISA name (e.g. "avx2", "scalar", or "none").
/// Frontend can display a "SIMD: AVX2" badge based on this.
#[tauri::command]
pub fn cmd_get_simd_isa(api: State<Arc<GraphHunterApi>>) -> String {
    api.runtime_info().simd_isa
}
