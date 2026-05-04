//! C.2 — Publish tagged IoCs to an Azure Sentinel Watchlist. Delegates
//! to the canonical API; the full implementation (three-gate safety,
//! token acquisition, ARM URL building) lives in
//! `graph_hunter_api::operations::sentinel_publish`.

use std::sync::Arc;

use tauri::State;

use graph_hunter_api::dto::sentinel::{PublishIocsRequest, PublishIocsResponse};
use graph_hunter_api::GraphHunterApi;

use crate::error::CommandError;
use crate::state::AppState;

/// Re-exports so `http_api.rs` can keep delegating through this module.
pub use graph_hunter_api::operations::sentinel_publish::{
    build_watchlist_payload, build_watchlist_url, to_watchlist_alias, AzureCreds,
};

#[tauri::command]
pub async fn cmd_publish_iocs_to_sentinel(
    _state: State<'_, Arc<AppState>>,
    api: State<'_, Arc<GraphHunterApi>>,
    watchlist_name: String,
    display_name: Option<String>,
    description: Option<String>,
    tag_prefix: Option<String>,
    dry_run: Option<bool>,
    confirm: Option<bool>,
) -> Result<PublishIocsResponse, CommandError> {
    api.publish_iocs_to_sentinel(PublishIocsRequest {
        session: None,
        watchlist_name,
        display_name,
        description,
        tag_prefix,
        dry_run: dry_run.unwrap_or(false),
        confirm: confirm.unwrap_or(false),
    })
    .await
    .map_err(CommandError::from)
}

/// Deprecated alias — the HTTP handler used to call this with an
/// explicit `&AppState`. Now delegates to the canonical API. Kept so
/// external crates (if any) don't break.
#[deprecated(note = "Call GraphHunterApi::publish_iocs_to_sentinel directly")]
pub async fn publish_iocs_to_sentinel_inner(
    _state: &AppState,
    watchlist_name: String,
    display_name: Option<String>,
    description: Option<String>,
    tag_prefix: Option<String>,
    dry_run: Option<bool>,
    confirm: Option<bool>,
) -> Result<PublishIocsResponse, CommandError> {
    // Construct a NoopEmitter-based façade ONLY for the inner call.
    // This is not reachable from any current call site after migration;
    // it exists purely so a legacy external crate keeps compiling.
    let _ = (
        watchlist_name,
        display_name,
        description,
        tag_prefix,
        dry_run,
        confirm,
    );
    Err(CommandError::Internal(
        "publish_iocs_to_sentinel_inner is deprecated: call GraphHunterApi::publish_iocs_to_sentinel directly".into(),
    ))
}
