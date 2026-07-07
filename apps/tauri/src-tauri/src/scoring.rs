//! Thin shim: scoring helpers moved to `graph_hunter_api::scoring`.
//! Re-exported here so existing `crate::scoring::*` imports keep
//! compiling while the remaining Tauri-side users (currently only
//! `cmd_load_data_streaming`) are migrated.

pub use graph_hunter_api::scoring::{run_full_scoring, run_scoring_adaptive, run_scoring_incremental};
