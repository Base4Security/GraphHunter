//! Tauri-side bridge that satisfies `graph_hunter_api::EventEmitter`.
//!
//! The `GraphHunterApi` owns an `Arc<dyn EventEmitter>`; the Tauri app
//! plugs in this concrete emitter so `api.emit("session-load-progress",
//! …)` reaches the frontend via `AppHandle::emit`. HTTP / MCP transports
//! keep using `NoopEmitter` (they have no frontend to notify).
//!
//! The `AppHandle` is populated inside the Tauri `setup()` callback
//! (after the builder finishes), so the emitter reads it lazily through
//! an `Arc<RwLock<Option<AppHandle>>>` that is ALSO held by `AppState`
//! — one shared handle, two views.

use std::sync::{Arc, RwLock};

use graph_hunter_api::EventEmitter;
use tauri::{AppHandle, Emitter};

/// Forwards API emissions into `AppHandle::emit`. No-op until setup()
/// populates the inner `Option<AppHandle>`.
pub struct TauriEventEmitter {
    handle: Arc<RwLock<Option<AppHandle>>>,
}

impl TauriEventEmitter {
    /// Build the emitter around a shared handle slot. Pass the same
    /// `Arc` to `AppState.app_handle` so `setup()` only has to write
    /// once.
    pub fn new(handle: Arc<RwLock<Option<AppHandle>>>) -> Self {
        Self { handle }
    }
}

impl EventEmitter for TauriEventEmitter {
    fn emit(&self, event: &str, payload: serde_json::Value) {
        if let Ok(guard) = self.handle.read() {
            if let Some(h) = guard.as_ref() {
                // Best-effort: dropped events are acceptable (the UI
                // reconciles next tick). Failing here would corrupt a
                // long-running load for a single dropped frame.
                let _ = h.emit(event, payload);
            }
        }
    }
}
