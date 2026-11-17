//! Tauri-side state. In P1, most domain types moved to
//! `graph_hunter_api::state`; they are re-exported here so existing call
//! sites (commands, helpers, HTTP handlers) keep compiling unchanged.
//!
//! After P1 Fase 2, [`AppState`] is a minimal sidecar:
//! - **AppHandle slot** — Tauri needs this for `AppHandle::emit`
//!   (shared with the canonical `TauriEventEmitter`).
//! - **Session handles** — still shared with the API's `SessionStore`
//!   for the one remaining legacy helper (`with_current_session*`)
//!   used by `cmd_load_data_streaming`.
//!
//! Everything else moved to the canonical API's `ApiState`; the HTTP
//! auth token and the hunt journal belong to the HTTP transport
//! (`graph_hunter_server::ServerState`).

use std::collections::HashMap;
use std::sync::{Arc, RwLock};

// Re-exports: types that moved to the canonical API crate. `SessionState`
// keeps its legacy name here; in the canonical crate it is `Session`.
pub use graph_hunter_api::state::{
    DatasetInfo, EntityTag, Note, Session as SessionState, SessionFile, ensure_session_dir,
    session_data_dir, session_file_path, validate_session_id,
};

/// Minimal Tauri-side sidecar state. Everything app-wide that the
/// canonical API owns is reached through `State<Arc<GraphHunterApi>>`;
/// the fields below are only the ones that make sense Tauri-side or
/// that legacy helpers still read.
pub struct AppState {
    /// Session map — shared with `GraphHunterApi::sessions()`. Still
    /// exposed here because `cmd_load_data_streaming` (the only
    /// non-migrated command) uses the legacy `with_current_session*`
    /// helpers that read from `AppState`.
    pub sessions: Arc<RwLock<HashMap<String, Arc<SessionState>>>>,
    /// Current-session pointer — same sharing rationale as `sessions`.
    pub current_session_id: Arc<RwLock<Option<String>>>,
    /// Set in `setup()`. Read by `TauriEventEmitter` to forward
    /// canonical API events (e.g. `session-load-progress`,
    /// `mcp-view-update`) into the frontend. Shared `Arc<RwLock<_>>`
    /// with the emitter so both sides see the same handle.
    pub app_handle: Arc<RwLock<Option<tauri::AppHandle>>>,
}
