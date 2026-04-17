//! Parity harness — Phase A + Phase B.
//!
//! The canonical `GraphHunterApi` is the single source of truth for
//! every operation exposed by the 3 transports (Tauri commands,
//! HTTP handlers, MCP tools). Because Tauri commands and HTTP
//! handlers are thin delegators over the same `api.method(req)`
//! calls, "3-way parity" collapses into two concerns:
//!
//! 1. **Shape parity** (Phase A) — every Request/Response DTO used
//!    across transports keeps its JSON field names and enum tags
//!    stable. A DTO drift here breaks every transport at once. We
//!    test this with Serialize + Deserialize roundtrips on hand-
//!    crafted JSON fixtures.
//!
//! 2. **Semantic parity** (Phase B) — the same ordered sequence of
//!    API calls produces the same visible state. We test this by
//!    running end-to-end scenarios over a fixture session and
//!    snapshotting the observable output.
//!
//! Phase C (HTTP + Tauri runtime integration) is deferred to a
//! dedicated session — it requires spinning up axum in tests and
//! wiring a Tauri IPC harness.

use graph_hunter_api::GraphHunterApi;

mod parity {
    pub mod dto_shapes;
    pub mod fixture;
    pub mod scenarios;
}

/// Shared setup for Phase B tests: fresh API + a single session with
/// a minimal graph populated via direct API calls (no file I/O, no
/// Tauri runtime needed).
pub fn fresh_api_with_session() -> (GraphHunterApi, String) {
    parity::fixture::fresh_api_with_session()
}

// Re-export integration-test cases at the crate level so `cargo test
// --test parity <pattern>` can filter them by name.
pub use parity::dto_shapes::*;
pub use parity::scenarios::*;
