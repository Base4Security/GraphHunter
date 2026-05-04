//! Re-exports from the canonical API so legacy Tauri imports keep
//! compiling. The real implementation lives in
//! `graph_hunter_api::sentinel_connector`.

pub use graph_hunter_api::sentinel_connector::{
    default_tables, polling_loop, ConnectorStatus, SentinelConnectorHandle,
};
