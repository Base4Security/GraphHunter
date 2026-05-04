//! Tauri command for the invariant checker (M2 D3).

use std::sync::Arc;

use graph_hunter_api::dto::invariants::CheckInvariantsRequest;
use graph_hunter_api::GraphHunterApi;
use graph_hunter_core::invariants::InvariantReport;
use tauri::State;

use crate::error::CommandError;

/// Run the P1/P2/P3/P4 predicates plus the treewidth heuristic over the
/// current session (or a single dataset when `dataset_id` is provided).
#[tauri::command]
pub fn cmd_check_invariants(
    api: State<Arc<GraphHunterApi>>,
    dataset_id: Option<String>,
) -> Result<InvariantReport, CommandError> {
    api.check_invariants(CheckInvariantsRequest {
        session: None,
        dataset_id,
    })
    .map_err(CommandError::from)
}
