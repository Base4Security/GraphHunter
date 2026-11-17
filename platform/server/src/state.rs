//! State the HTTP transport owns. Everything about sessions and graphs
//! lives in `graph_hunter_api::GraphHunterApi`; this is only what the
//! transport itself needs.

use std::sync::Arc;

use graph_hunter_api::EventEmitter;

use crate::journal::store::JournalStore;

pub struct ServerState {
    /// Bearer token the auth middleware compares against.
    pub api_token: String,
    /// Hunt journal store, shared with the mandatory capture middleware.
    pub journal: Arc<JournalStore>,
    /// Where `notes-changed` / `mcp-view-update` go. The desktop app
    /// passes the emitter that reaches its frontend; headless passes
    /// `NoopEmitter`, since there is no map to refresh.
    pub emitter: Arc<dyn EventEmitter>,
}
