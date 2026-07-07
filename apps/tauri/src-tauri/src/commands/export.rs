//! Export commands — all three delegate to the canonical API.
//! Helpers and format builders now live in `graph_hunter_api::operations::export`.

use std::sync::Arc;

use tauri::State;

use graph_hunter_api::dto::export::{
    ExportHuntResultsRequest, ExportIocsRequest, ExportOcsfRequest, ExportSubgraphRequest,
};
use graph_hunter_api::GraphHunterApi;

use crate::error::CommandError;

/// Re-export the IoC format helpers so `http_api.rs::handler_export_iocs`
/// and `sentinel_publish.rs` keep working via
/// `crate::commands::export::{format_ioc_feed, build_sentinel_watchlist_csv}`.
pub use graph_hunter_api::operations::export::{build_sentinel_watchlist_csv, format_ioc_feed};

#[tauri::command]
pub fn cmd_export_subgraph(
    api: State<Arc<GraphHunterApi>>,
    format: String,
    nodes: Vec<String>,
) -> Result<String, CommandError> {
    api.export_subgraph(ExportSubgraphRequest {
        session: None,
        format,
        nodes,
    })
    .map_err(CommandError::from)
}

/// Exports cached hunt results as CSV or JSON. `aggregate=true` collapses
/// identical paths (DedupMode::ByPath) — critical for exporting
/// thousands of paths without overflowing transport response budgets.
#[tauri::command]
pub fn cmd_export_hunt_results(
    api: State<Arc<GraphHunterApi>>,
    format: String,
    page: Option<usize>,
    page_size: Option<usize>,
    aggregate: Option<bool>,
) -> Result<String, CommandError> {
    api.export_hunt_results(ExportHuntResultsRequest {
        session: None,
        format,
        page,
        page_size,
        aggregate,
    })
    .map_err(CommandError::from)
}

/// Export the session (or a single dataset) as OCSF v1.4 events with the
/// GraphHunter Provenance Extension. `format` is `"json"` (single array)
/// or `"ndjson"` (newline-delimited).
#[tauri::command]
pub fn cmd_export_ocsf(
    api: State<Arc<GraphHunterApi>>,
    format: String,
    dataset_id: Option<String>,
    page_size: Option<usize>,
    offset: Option<usize>,
) -> Result<String, CommandError> {
    api.export_ocsf(ExportOcsfRequest {
        session: None,
        dataset_id,
        format,
        page_size,
        offset,
    })
    .map_err(CommandError::from)
}

/// Export the session's tagged entities as a consumable IoC feed:
/// STIX 2.1, MISP CSV, KQL IoC set, Sigma stub, or Sentinel Watchlist.
#[tauri::command]
pub fn cmd_export_iocs(
    api: State<Arc<GraphHunterApi>>,
    format: String,
    tag_prefix: Option<String>,
) -> Result<String, CommandError> {
    api.export_iocs(ExportIocsRequest {
        session: None,
        format,
        tag_prefix,
    })
    .map_err(CommandError::from)
}
