//! Session lifecycle commands — all six delegate to the canonical API.
//!
//! `cmd_load_session` and `cmd_save_session` stay `async` so Tauri's
//! IPC thread doesn't block: they call the API's async wrappers which
//! internally `spawn_blocking` the heavy work. Progress events flow
//! through `TauriEventEmitter` that the API holds.

use std::sync::Arc;

use tauri::State;

use graph_hunter_api::dto::session::{
    CreateSessionRequest, DeleteSessionRequest, LoadSessionRequest, SaveSessionRequest,
    SessionInfo,
};
use graph_hunter_api::GraphHunterApi;

use crate::error::CommandError;
use crate::state::AppState;

#[tauri::command]
pub fn cmd_create_session(
    api: State<Arc<GraphHunterApi>>,
    name: Option<String>,
) -> Result<SessionInfo, CommandError> {
    api.create_session(CreateSessionRequest { name })
        .map_err(CommandError::from)
}

#[tauri::command]
pub fn cmd_list_sessions(
    api: State<Arc<GraphHunterApi>>,
) -> Result<Vec<SessionInfo>, CommandError> {
    api.list_sessions().map_err(CommandError::from)
}

/// Load a session by id (memory or disk) and set as current.
///
/// Emits `session-load-progress` with `{ phase, current, total }`.
/// Phases: `reading` → `parsing` → `entities` → `relations` →
/// `sorting` → `done`.
#[tauri::command]
pub async fn cmd_load_session(
    _state: State<'_, Arc<AppState>>,
    api: State<'_, Arc<GraphHunterApi>>,
    session_id: String,
) -> Result<SessionInfo, CommandError> {
    api.load_session(LoadSessionRequest { session_id })
        .await
        .map_err(CommandError::from)
}

/// Save current (or specified) session to disk.
///
/// Emits `session-save-progress`. Phases: `entities` → `relations` →
/// `done`.
#[tauri::command]
pub async fn cmd_save_session(
    _state: State<'_, Arc<AppState>>,
    api: State<'_, Arc<GraphHunterApi>>,
    session_id: Option<String>,
) -> Result<(), CommandError> {
    api.save_session(SaveSessionRequest { session_id })
        .await
        .map_err(CommandError::from)
}

#[tauri::command]
pub fn cmd_delete_session(
    api: State<Arc<GraphHunterApi>>,
    session_id: String,
) -> Result<(), CommandError> {
    api.delete_session(DeleteSessionRequest { session_id })
        .map_err(CommandError::from)
}

#[tauri::command]
pub fn cmd_get_current_session(
    api: State<Arc<GraphHunterApi>>,
) -> Result<Option<SessionInfo>, CommandError> {
    api.get_current_session().map_err(CommandError::from)
}
