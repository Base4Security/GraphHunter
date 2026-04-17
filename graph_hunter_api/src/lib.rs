//! graph_hunter_api — canonical, transport-agnostic API for Graph Hunter.
//!
//! The three transports (Tauri commands, HTTP handlers, MCP tools) become
//! thin serializers over the methods exposed by [`GraphHunterApi`]. State
//! that used to live in `app/src-tauri/src/state.rs::AppState` (sessions,
//! hunt cache, AI, sentinel connector, GNN scorer, GeoIP) is owned here
//! inside [`ApiState`].
//!
//! Fase 0 of the P1 refactor introduces the crate skeleton. Subsequent
//! phases migrate the 91 Tauri commands, 29 HTTP endpoints, and 31 MCP
//! tools to delegate to methods on this struct. See
//! `~/.claude/plans/eager-bubbling-mochi.md` for the overall plan.

pub mod ai;
pub mod dto;
pub mod error;
pub mod events;
pub mod evtx;
pub mod format_registry;
pub mod operations;
pub mod scoring;
pub mod sentinel_connector;
pub mod state;
pub mod util;

pub use error::{ApiError, ApiResult};
pub use events::{EventEmitter, NoopEmitter};
pub use state::{
    DatasetInfo, EntityTag, Note, Session, SessionFile, SessionHandle, SessionStore,
};

use std::sync::{Arc, Mutex, RwLock};

/// Shared runtime state of the API.
///
/// Held behind `Arc<ApiState>` in [`GraphHunterApi`] so the façade is cheap
/// to clone across tasks / transports. Uses `std::sync::RwLock` inside the
/// [`SessionStore`] so the existing Tauri helpers that do
/// `lock.read().map_err(...)` keep working unchanged during migration.
pub(crate) struct ApiState {
    /// Session registry (create / load / save / drop). Cloneable — the
    /// internal map + current-ptr live behind `Arc<RwLock<_>>` so the
    /// legacy Tauri `AppState` can share the same locked state during P1
    /// migration.
    pub(crate) sessions: SessionStore,
    /// Cached path list from the most recent hunt, used by
    /// `get_hunt_page` to paginate/score without re-running. Shared
    /// `Arc<RwLock<_>>` so `AppState.cached_hunt_paths` sees the same
    /// cache and can coexist with non-migrated commands during P1.
    pub(crate) hunt_cache: Arc<RwLock<Vec<Vec<String>>>>,
    /// GNN scorer (ONNX model) loaded on demand by `load_gnn_model`.
    /// Shared `Arc<RwLock<_>>` so `AppState.npu_scorer` sees the same
    /// handle during P1 migration.
    #[cfg(feature = "ml-scoring")]
    pub(crate) npu_scorer: Arc<RwLock<Option<graph_hunter_core::NpuScorer>>>,
    /// Offline MaxMind GeoIP provider. Populated at startup if the
    /// `GeoLite2-*.mmdb` files are present; `None` otherwise. Shared
    /// with `AppState.geoip_provider` so non-migrated commands keep
    /// working.
    pub(crate) geoip_provider:
        Arc<Mutex<Option<graph_hunter_core::geoip::maxmind::MaxMindProvider>>>,
    /// HTTP GeoIP client (ip-api.com fallback). Mutex holds an
    /// `Option<Arc<dyn HttpClient>>` so populating it later doesn't
    /// require re-wiring locks.
    pub(crate) http_geoip_client:
        Arc<Mutex<Option<Arc<dyn graph_hunter_core::HttpClient>>>>,
    /// Real-time Sentinel connector handle. `None` when disconnected;
    /// `Some` while a background polling task is running. Shared with
    /// `AppState.sentinel_connector` so both views see connect/
    /// disconnect transitions atomically.
    pub(crate) sentinel_connector:
        Arc<RwLock<Option<sentinel_connector::SentinelConnectorHandle>>>,
    /// AI provider config (OpenAI / Anthropic / Google credentials
    /// plus chosen model). `None` = fall back to env vars. Process-
    /// wide (credentials don't change per session).
    pub(crate) ai_config: Arc<RwLock<Option<ai::ProviderConfig>>>,
    // ai_conversation is NOT stored here — each `Session` owns its
    // own via `Session.ai_conversation`. Fixes the bug documented in
    // the feedback where switching sessions reused a global history.
    /// Emitter for progress events back to the frontend. Tauri wires up a
    /// real emitter; HTTP / MCP / CLI use [`NoopEmitter`].
    #[allow(dead_code)] // consumed once transports start emitting
    pub(crate) emitter: Arc<dyn EventEmitter>,
}

/// Canonical API façade. Cheap to clone (wraps `Arc<ApiState>`).
///
/// All three transports hold an `Arc<GraphHunterApi>` and call methods on
/// it. Methods accept DTOs defined in [`dto`] and return DTOs or domain
/// types re-exported from `graph_hunter_core`. Each method is the single
/// authoritative implementation of its operation — transports contain no
/// business logic.
#[derive(Clone)]
pub struct GraphHunterApi {
    pub(crate) inner: Arc<ApiState>,
}

impl GraphHunterApi {
    /// Construct a fresh API with no sessions loaded.
    ///
    /// `emitter` receives progress events. Pass [`NoopEmitter`] from
    /// transports that have no frontend to push to (HTTP, MCP, CLI).
    pub fn new(emitter: Arc<dyn EventEmitter>) -> Self {
        Self {
            inner: Arc::new(ApiState {
                sessions: SessionStore::new(),
                hunt_cache: Arc::new(RwLock::new(Vec::new())),
                #[cfg(feature = "ml-scoring")]
                npu_scorer: Arc::new(RwLock::new(None)),
                geoip_provider: Arc::new(Mutex::new(None)),
                http_geoip_client: Arc::new(Mutex::new(None)),
                sentinel_connector: Arc::new(RwLock::new(None)),
                ai_config: Arc::new(RwLock::new(None)),
                emitter,
            }),
        }
    }

    /// Convenience constructor for unit tests and headless transports.
    pub fn new_noop() -> Self {
        Self::new(Arc::new(NoopEmitter))
    }

    /// Handle to the event emitter. Internal callers emit via this.
    #[allow(dead_code)] // consumed once transports start emitting
    pub(crate) fn emitter(&self) -> &Arc<dyn EventEmitter> {
        &self.inner.emitter
    }

    /// Access the session registry. Callers can also go through the
    /// higher-level session operations; direct store access is exposed for
    /// transport bootstrap (sharing the map/current handles with Tauri's
    /// legacy `AppState` during P1 migration).
    pub fn sessions(&self) -> &SessionStore {
        &self.inner.sessions
    }

    /// Handle to the shared hunt-path cache. `AppState.cached_hunt_paths`
    /// pulls this same `Arc` at startup so legacy and canonical code see
    /// the same cache during P1 migration.
    pub fn hunt_cache_handle(&self) -> Arc<RwLock<Vec<Vec<String>>>> {
        self.inner.hunt_cache.clone()
    }

    /// Handle to the shared GNN scorer. Only compiled when the
    /// `ml-scoring` feature is on; legacy `AppState.npu_scorer` pulls
    /// this same `Arc` so both see model load / status calls.
    #[cfg(feature = "ml-scoring")]
    pub fn npu_scorer_handle(&self) -> Arc<RwLock<Option<graph_hunter_core::NpuScorer>>> {
        self.inner.npu_scorer.clone()
    }

    /// Handle to the shared offline MaxMind provider slot. The Tauri
    /// bootstrap populates it; `AppState.geoip_provider` pulls the
    /// same `Arc<Mutex<_>>` so non-migrated commands see the same
    /// backend.
    pub fn geoip_provider_handle(
        &self,
    ) -> Arc<Mutex<Option<graph_hunter_core::geoip::maxmind::MaxMindProvider>>> {
        self.inner.geoip_provider.clone()
    }

    /// Handle to the HTTP GeoIP client slot (ip-api.com fallback).
    pub fn http_geoip_client_handle(
        &self,
    ) -> Arc<Mutex<Option<Arc<dyn graph_hunter_core::HttpClient>>>> {
        self.inner.http_geoip_client.clone()
    }

    /// Handle to the Sentinel connector slot. Shared with the legacy
    /// `AppState.sentinel_connector` so both views see the handle.
    pub fn sentinel_connector_handle(
        &self,
    ) -> Arc<RwLock<Option<sentinel_connector::SentinelConnectorHandle>>> {
        self.inner.sentinel_connector.clone()
    }

    /// Handle to the shared AI provider config slot (process-wide).
    pub fn ai_config_handle(&self) -> Arc<RwLock<Option<ai::ProviderConfig>>> {
        self.inner.ai_config.clone()
    }

    /// Handle to the canonical event emitter. `Arc<dyn EventEmitter>`
    /// so callers can pass it to helpers that need to emit progress
    /// events (e.g., `evtx_ingest_streaming` takes one). Tauri
    /// commands that still do their own background work use this to
    /// bridge into the canonical channel without re-wrapping the
    /// AppHandle.
    pub fn emitter_arc(&self) -> Arc<dyn EventEmitter> {
        self.inner.emitter.clone()
    }
}

impl std::fmt::Debug for GraphHunterApi {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GraphHunterApi")
            .field("session_count", &self.inner.sessions.len())
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn smoke_new_noop_zero_sessions() {
        let api = GraphHunterApi::new_noop();
        assert_eq!(api.sessions().len(), 0);
    }

    #[test]
    fn api_is_clone_and_send() {
        fn assert_send_sync<T: Send + Sync + Clone>() {}
        assert_send_sync::<GraphHunterApi>();
    }
}
