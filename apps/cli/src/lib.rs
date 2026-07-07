//! Library re-exports for use by the Tauri app (SIEM ingest).
//!
//! `siem` now lives in the platform/siem crate. Kept re-exported here
//! under the old path so callers that import `graph_hunter_cli::siem`
//! keep compiling while downstream migration is in flight.

pub use graph_hunter_siem as siem;
