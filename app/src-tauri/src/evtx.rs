//! Thin shim: the EVTX helpers moved to `graph_hunter_api::evtx`.
//! Everything here is a re-export so existing imports
//! (`crate::evtx::path_is_evtx`, etc.) keep compiling without touching
//! call sites.
//!
//! `cmd_load_data_streaming` still lives Tauri-side and calls the
//! streaming helper through `graph_hunter_api::evtx::evtx_ingest_streaming`
//! with the Tauri `EventEmitter` wrapped as an `Arc<dyn EventEmitter>`.
//! The streaming command itself is slated for migration in a focused
//! session (see Task #3 notes).

pub use graph_hunter_api::evtx::{
    evtx_ingest_streaming, evtx_preview_sample, evtx_record_to_sysmon_like,
    evtx_to_sysmon_ndjson, file_looks_like_evtx, path_is_evtx,
};
