//! Transport-agnostic event emitter.
//!
//! Today Tauri commands call `AppHandle::emit("session-load-progress", …)`
//! directly to push progress events to the frontend. That couples the core
//! logic to `tauri::AppHandle`. Here we abstract the surface so the API
//! crate emits into a trait and each transport decides what to do.
//!
//! - Tauri provides a concrete emitter that forwards to `AppHandle::emit`.
//! - HTTP / MCP / CLI use [`NoopEmitter`] (events are dropped).
//! - A future HTTP SSE transport could buffer events and stream them.
//!
//! Event names and payload shapes are part of the public contract and live
//! in this module as constants / typed helpers, so drift between
//! transports is caught at compile time.

use std::sync::Arc;

/// Any type that can accept an emitted event. `Send + Sync` so the API
/// can hold it inside `Arc<ApiState>` and share across tasks.
pub trait EventEmitter: Send + Sync {
    fn emit(&self, event: &str, payload: serde_json::Value);
}

/// Drops all events. Used by HTTP, MCP, CLI, tests.
pub struct NoopEmitter;

impl EventEmitter for NoopEmitter {
    fn emit(&self, _event: &str, _payload: serde_json::Value) {
        // intentional no-op
    }
}

/// Emitter that forwards every call to a closure. Handy for tests that
/// want to record events without mocking a whole struct.
pub struct FnEmitter<F: Fn(&str, serde_json::Value) + Send + Sync>(pub F);

impl<F: Fn(&str, serde_json::Value) + Send + Sync> EventEmitter for FnEmitter<F> {
    fn emit(&self, event: &str, payload: serde_json::Value) {
        (self.0)(event, payload)
    }
}

/// Shared handle used throughout the API crate.
pub type EmitterHandle = Arc<dyn EventEmitter>;

/// Canonical event names. Transports must use these constants — never
/// raw strings — so renaming is a compile error, not a runtime bug.
pub mod events {
    pub const SESSION_LOAD_PROGRESS: &str = "session-load-progress";
    pub const SESSION_SAVE_PROGRESS: &str = "session-save-progress";
    pub const INGEST_PROGRESS: &str = "ingest-progress";
    pub const INGEST_COMPLETE: &str = "ingest-complete";
    pub const INGEST_ERROR: &str = "ingest-error";
    /// Emitted by the LLM-as-compiler dispatcher when the heuristic
    /// produced a low-confidence config and the LLM offers a refined
    /// alternative. Streaming halts before any triples are inserted;
    /// the frontend renders a confirm banner with the diff and
    /// re-triggers ingest with the analyst's chosen config.
    pub const INGEST_LLM_PROPOSAL: &str = "ingest-llm-proposal";
    /// Emitted on every dispatcher decision (heuristic confident, LLM
    /// proposal, LLM unavailable). The frontend renders a status-log
    /// line so the analyst always sees which path the dispatcher took
    /// — without this, a silent fall-back to heuristic that produces
    /// zero triples looks identical to a parser bug. Distinct from
    /// `ingest-llm-proposal` because the proposal carries the diff
    /// payload + halts streaming, while the diagnostic is fire-and-
    /// forget telemetry.
    pub const INGEST_LLM_DIAGNOSTIC: &str = "ingest-llm-diagnostic";
    pub const SENTINEL_DATA: &str = "sentinel-data";
    pub const SENTINEL_STATUS: &str = "sentinel-status";
    pub const MCP_VIEW_UPDATE: &str = "mcp-view-update";
    pub const NOTES_CHANGED: &str = "notes-changed";
    pub const HUNT_PROGRESS: &str = "hunt-progress";
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    #[test]
    fn noop_emitter_drops_events() {
        let e = NoopEmitter;
        e.emit("whatever", serde_json::json!({"x": 1}));
        // nothing to assert; it just must not panic
    }

    #[test]
    fn fn_emitter_records() {
        let log: Arc<Mutex<Vec<(String, serde_json::Value)>>> = Arc::new(Mutex::new(Vec::new()));
        let log_clone = log.clone();
        let e = FnEmitter(move |ev, pl| {
            log_clone.lock().unwrap().push((ev.to_string(), pl));
        });
        e.emit("x", serde_json::json!({"a": 1}));
        e.emit("y", serde_json::json!(null));
        let got = log.lock().unwrap();
        assert_eq!(got.len(), 2);
        assert_eq!(got[0].0, "x");
        assert_eq!(got[1].0, "y");
    }

    #[test]
    fn can_hold_as_arc_dyn() {
        let _: Arc<dyn EventEmitter> = Arc::new(NoopEmitter);
    }
}
