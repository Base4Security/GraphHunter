//! DSL and catalog commands.
//!
//! All four commands delegate to the canonical API. The Tauri command
//! bodies are the minimum glue needed to unwrap Tauri's payload style
//! (positional params instead of a Request struct) and adapt
//! [`ApiError`] → [`CommandError`].

use std::sync::Arc;

use graph_hunter_api::dto::dsl::{
    GetCatalogWithStatusRequest, LoadCatalogHypothesisRequest, ParseDslRequest, ParseDslResponse,
};
use graph_hunter_api::{ApiError, GraphHunterApi};
use graph_hunter_core::{CatalogEntry, CatalogEntryWithStatus, CatalogLoadError};
use tauri::State;

use crate::error::CommandError;
use crate::types::DslResult;

impl From<ApiError> for CommandError {
    fn from(e: ApiError) -> Self {
        match e {
            ApiError::SessionNotFound(m) => CommandError::SessionNotFound(m),
            ApiError::NoCurrentSession => {
                CommandError::SessionNotFound("no current session".to_string())
            }
            ApiError::NotFound(m) | ApiError::InvalidState(m) => CommandError::InvalidInput(m),
            ApiError::Conflict(m) => CommandError::GraphLocked(m),
            ApiError::InvalidInput(m) => CommandError::InvalidInput(m),
            ApiError::Upstream { service, message } => {
                CommandError::Internal(format!("{service}: {message}"))
            }
            ApiError::Io(m) => CommandError::IoError(m),
            ApiError::Internal(m) => CommandError::Internal(m),
        }
    }
}

/// Adapt the canonical [`ParseDslResponse`] to the Tauri-facing
/// [`DslResult`] shape expected by the existing frontend. The canonical
/// shape is a strict superset; `steps` is dropped because the frontend
/// doesn't read it today.
fn to_dsl_result(resp: ParseDslResponse) -> DslResult {
    DslResult {
        hypothesis: resp.hypothesis,
        formatted: resp.formatted,
    }
}

/// Parses a DSL string into a Hypothesis.
///
/// Edge direction matters: `User -[Auth]-> IP` and `IP -[Auth]-> User` are
/// distinct hypotheses. Call `cmd_get_relation_schema` first to enumerate
/// the (rel_type, source_type, target_type) triples actually present in
/// the current graph — cheapest way to avoid zero-match runs caused by
/// authoring the pattern in the wrong direction.
#[tauri::command]
pub fn cmd_parse_dsl(
    api: State<Arc<GraphHunterApi>>,
    input: String,
    name: Option<String>,
) -> Result<DslResult, CommandError> {
    api.parse_dsl(ParseDslRequest { input, name })
        .map(to_dsl_result)
        .map_err(CommandError::from)
}

/// Returns the ATT&CK hypothesis catalog.
#[tauri::command]
pub fn cmd_get_catalog(api: State<Arc<GraphHunterApi>>) -> Vec<CatalogEntry> {
    api.get_catalog()
}

/// Returns the ATT&CK hypothesis catalog with per-entry compatibility
/// computed against the currently loaded graph. Incompatible entries
/// carry the list of `missing_entity_types`/`missing_rel_types` so the UI
/// can gray them out and tell the analyst why.
#[tauri::command]
pub fn cmd_get_catalog_with_status(
    api: State<Arc<GraphHunterApi>>,
) -> Result<Vec<CatalogEntryWithStatus>, CommandError> {
    api.get_catalog_with_status(GetCatalogWithStatusRequest::default())
        .map_err(CommandError::from)
}

/// Returns any YAML-load diagnostics the catalog loader collected at
/// startup. Empty when every built-in and user YAML was fine; non-empty
/// entries carry the offending file path and a human-readable message.
#[tauri::command]
pub fn cmd_get_catalog_diagnostics(api: State<Arc<GraphHunterApi>>) -> Vec<CatalogLoadError> {
    api.get_catalog_diagnostics()
}

/// Parses a catalog entry's DSL pattern into a Hypothesis.
#[tauri::command]
pub fn cmd_load_catalog_hypothesis(
    api: State<Arc<GraphHunterApi>>,
    catalog_id: String,
) -> Result<DslResult, CommandError> {
    api.load_catalog_hypothesis(LoadCatalogHypothesisRequest { catalog_id })
        .map(to_dsl_result)
        .map_err(CommandError::from)
}
