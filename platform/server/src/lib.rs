//! HTTP transport for the canonical Graph Hunter API, plus the hunt
//! journal that captures every request made through it.
//!
//! This crate has no UI dependency. The desktop app embeds it (see
//! `apps/tauri/src-tauri/src/lib.rs`) and `graph-hunter-server` runs it
//! standalone, so an MCP client can drive a hunt end to end without the
//! app open. Both go through [`bootstrap`], which is what keeps the two
//! from drifting: a store wired up in only one of them fails silently in
//! the other.

pub mod bootstrap;
pub mod http;
pub mod journal;
pub mod state;
pub mod types;

pub use state::ServerState;
pub use types::PaginatedHuntResults;
