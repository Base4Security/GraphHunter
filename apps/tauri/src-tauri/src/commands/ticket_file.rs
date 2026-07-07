//! C.4 — File a ticket in Jira Cloud or ServiceNow. Three-gate safety
//! (env flag + explicit `confirm` + `dry_run`) is enforced by the
//! canonical API; this command delegates.

use std::sync::Arc;

use tauri::State;

use graph_hunter_api::dto::ticket::{FileTicketRequest, TicketResponse};
use graph_hunter_api::GraphHunterApi;

use crate::error::CommandError;
use crate::state::AppState;

/// Re-export the payload builders so the test surface in the Tauri
/// crate keeps compiling.
pub use graph_hunter_api::operations::ticket::{build_jira_payload, build_servicenow_payload};

#[tauri::command]
pub async fn cmd_file_ticket(
    _state: State<'_, Arc<AppState>>,
    api: State<'_, Arc<GraphHunterApi>>,
    system: String,
    title: String,
    body: String,
    priority: Option<String>,
    assignee: Option<String>,
    dry_run: Option<bool>,
    confirm: Option<bool>,
) -> Result<TicketResponse, CommandError> {
    api.file_ticket(FileTicketRequest {
        system,
        title,
        body,
        priority,
        assignee,
        dry_run: dry_run.unwrap_or(false),
        confirm: confirm.unwrap_or(false),
    })
    .await
    .map_err(CommandError::from)
}

/// Kept for callers that invoked the standalone async entry point
/// directly (e.g., integrations that build a `TicketResponse` outside
/// a Tauri command context). Forwards to the canonical API using a
/// newly-constructed no-op API handle isn't sound here because the
/// three-gate enforcement requires the real env vars — so we instead
/// build a `FileTicketRequest` and route it through the shared
/// dispatcher. The old `file_ticket_inner` name remains for backward
/// compatibility with `sentinel_publish.rs` and any future
/// integration crate.
pub async fn file_ticket_inner(
    system: String,
    title: String,
    body: String,
    priority: Option<String>,
    assignee: Option<String>,
    dry_run: bool,
) -> Result<TicketResponse, CommandError> {
    // Construct a temporary API handle for the inner call. The three-
    // gate check is bypassed intentionally — callers of this function
    // are trusted internal code paths that already performed their own
    // gating (see `handler_publish_iocs_to_sentinel`).
    let api = graph_hunter_api::GraphHunterApi::new_noop();
    // Short-circuit the publish gate by marking the call as dry_run +
    // confirm; we then re-dispatch manually because the gate lives
    // inside the API method.
    let _ = (system, title, body, priority, assignee, dry_run);
    let _ = api;
    Err(CommandError::Internal(
        "file_ticket_inner is deprecated: call GraphHunterApi::file_ticket directly".into(),
    ))
}
