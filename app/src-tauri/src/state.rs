//! Tauri-side state. In P1, most domain types moved to
//! `graph_hunter_api::state`; they are re-exported here so existing call
//! sites (commands, helpers, HTTP handlers) keep compiling unchanged.
//!
//! After P1 Fase 2, [`AppState`] is a minimal sidecar:
//! - **HTTP auth token** — stays in `AppState` because the axum
//!   middleware needs a stable `Arc<AppState>` handle for auth.
//! - **AppHandle slot** — Tauri needs this for `AppHandle::emit`
//!   (shared with the canonical `TauriEventEmitter`).
//! - **MCP view cache** — the frontend map is a Tauri concern.
//! - **Session handles** — still shared with the API's `SessionStore`
//!   for the one remaining legacy helper (`with_current_session*`)
//!   used by `cmd_load_data_streaming`.
//!
//! Everything else moved to the canonical API's `ApiState`.

use std::collections::HashMap;
use std::sync::{Arc, RwLock};

// Re-exports: types that moved to the canonical API crate. `SessionState`
// keeps its legacy name here; in the canonical crate it is `Session`.
pub use graph_hunter_api::state::{
    ensure_session_dir, session_data_dir, session_file_path, validate_session_id, DatasetInfo,
    EntityTag, Note, Session as SessionState, SessionFile,
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
    /// Set in `setup()`. Used by HTTP API to emit `mcp-view-update`
    /// and by `TauriEventEmitter` to forward canonical API events
    /// (e.g. `session-load-progress`) into the frontend. Shared
    /// `Arc<RwLock<_>>` with the emitter so both sides see the same
    /// handle.
    pub app_handle: Arc<RwLock<Option<tauri::AppHandle>>>,
    /// Last subgraph set by MCP (expand or subgraph); emitted to the
    /// frontend as `mcp-view-update`. Pure Tauri concern — not in the
    /// canonical API.
    pub last_mcp_subgraph: RwLock<Option<crate::types::Subgraph>>,
    /// Bearer token for HTTP API auth (generated at startup). Stays
    /// here because the axum auth middleware extracts it via the
    /// `State<Arc<AppState>>` FromRef.
    pub api_token: String,
}
