//! C.3 — Save a hypothesis as a Sigma rule stub. Delegates to the
//! canonical API; the Sigma builder lives in
//! `graph_hunter_api::operations::sigma`.

use std::sync::Arc;

use tauri::State;

use graph_hunter_api::dto::sigma::SaveHypothesisAsSigmaRequest;
use graph_hunter_api::GraphHunterApi;

use crate::error::CommandError;

/// Re-exports so `http_api.rs` and any external callers keep compiling
/// without being rewritten in this step.
pub use graph_hunter_api::dto::sigma::SigmaRuleResponse;
pub use graph_hunter_api::operations::sigma::build_sigma_from_hypothesis;

#[tauri::command]
pub fn cmd_save_hypothesis_as_sigma(
    api: State<Arc<GraphHunterApi>>,
    hypothesis_dsl: String,
    title: String,
    tag_prefix: Option<String>,
    level: Option<String>,
) -> Result<SigmaRuleResponse, CommandError> {
    api.save_hypothesis_as_sigma(SaveHypothesisAsSigmaRequest {
        session: None,
        hypothesis_dsl,
        title,
        tag_prefix,
        level,
    })
    .map_err(CommandError::from)
}
