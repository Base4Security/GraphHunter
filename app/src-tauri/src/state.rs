use std::collections::HashMap;
use std::fs;
use std::path::PathBuf;
use std::sync::{Arc, Mutex, RwLock};

use graph_hunter_core::{Entity, GraphHunter, Relation};
use serde::{Deserialize, Serialize};

/// A note: standalone or linked to a node.
#[derive(Clone, Serialize, Deserialize)]
pub struct Note {
    pub id: String,
    pub content: String,
    #[serde(default)]
    pub node_id: Option<String>,
    pub created_at: i64,
}

/// Info for one ingested dataset (tracked per session for remove/rename).
#[derive(Clone, Serialize, Deserialize)]
pub struct DatasetInfo {
    pub id: String,
    pub name: String,
    #[serde(default)]
    pub path: Option<String>,
    pub created_at: i64,
    pub entity_count: usize,
    pub relation_count: usize,
}

/// In-memory session state: one graph per session.
pub struct SessionState {
    pub id: String,
    pub name: String,
    pub created_at: i64,
    pub graph: RwLock<GraphHunter>,
    /// Node IDs pinned as path nodes (fixed in graph, persisted with session).
    pub path_node_ids: RwLock<Vec<String>>,
    /// Notes (standalone or linked to a node), persisted with session.
    pub notes: RwLock<Vec<Note>>,
    /// Ingested datasets (for lateral menu: list, remove, rename types).
    pub datasets: RwLock<Vec<DatasetInfo>>,
}

/// Serializable session file format for disk persistence.
#[derive(Serialize, Deserialize)]
pub struct SessionFile {
    pub id: String,
    pub name: String,
    pub created_at: i64,
    pub entities: Vec<Entity>,
    pub relations: Vec<Relation>,
    #[serde(default)]
    pub path_node_ids: Vec<String>,
    #[serde(default)]
    pub notes: Vec<Note>,
    #[serde(default)]
    pub datasets: Vec<DatasetInfo>,
}

/// Global application state: sessions map and current session.
pub struct AppState {
    pub sessions: RwLock<HashMap<String, Arc<SessionState>>>,
    pub current_session_id: RwLock<Option<String>>,
    pub cached_hunt_paths: RwLock<Vec<Vec<String>>>,
    /// Set in setup; used by HTTP API to emit mcp-view-update so the frontend map reflects MCP expand/subgraph.
    pub app_handle: RwLock<Option<tauri::AppHandle>>,
    /// Last subgraph set by MCP (expand or subgraph); emitted to frontend as mcp-view-update.
    pub last_mcp_subgraph: RwLock<Option<crate::types::Subgraph>>,
    /// AI provider configuration (set via UI or env var fallback).
    pub ai_config: RwLock<Option<crate::ai::ProviderConfig>>,
    /// AI conversation history for the current session.
    pub ai_conversation: RwLock<crate::ai::AiConversation>,
    /// Bearer token for HTTP API auth (generated at startup).
    pub api_token: String,
    /// GNN model scorer (loaded on demand via cmd_load_gnn_model).
    pub npu_scorer: RwLock<Option<graph_hunter_core::NpuScorer>>,
    /// Real-time Sentinel connector handle. None = not connected.
    pub sentinel_connector: RwLock<Option<crate::sentinel_connector::SentinelConnectorHandle>>,
    /// Offline MaxMind GeoIP provider (loaded on startup if .mmdb files found).
    pub geoip_provider: Mutex<Option<graph_hunter_core::geoip::maxmind::MaxMindProvider>>,
    /// HTTP client for GeoIP fallback (cloned out of lock before async calls).
    pub http_geoip_client: Mutex<Option<Arc<dyn graph_hunter_core::HttpClient>>>,
}

pub fn session_data_dir() -> Result<PathBuf, String> {
    dirs::data_dir()
        .ok_or_else(|| "Could not resolve app data directory".to_string())
        .map(|p| p.join("GraphHunter").join("sessions"))
}

pub fn ensure_session_dir() -> Result<PathBuf, String> {
    let dir = session_data_dir()?;
    fs::create_dir_all(&dir).map_err(|e| format!("Failed to create session dir: {}", e))?;
    Ok(dir)
}

/// Validates that a session_id is safe to use as a filename component.
///
/// Session IDs are generated server-side as UUIDs, but we accept them from
/// the frontend over IPC, so a compromised frontend could send
/// `../../etc/passwd` or similar. Restrict to `[A-Za-z0-9_-]` to neutralize
/// path traversal and NUL-byte injection at the boundary.
pub fn validate_session_id(session_id: &str) -> Result<(), String> {
    if session_id.is_empty() || session_id.len() > 128 {
        return Err(format!("session_id must be 1..=128 chars; got {}", session_id.len()));
    }
    if !session_id
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
    {
        return Err("session_id must contain only [A-Za-z0-9_-]".into());
    }
    Ok(())
}

pub fn session_file_path(session_id: &str) -> Result<PathBuf, String> {
    validate_session_id(session_id)?;
    Ok(ensure_session_dir()?.join(format!("{}.json", session_id)))
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── validate_session_id ──

    #[test]
    fn valid_uuid_style() {
        assert!(validate_session_id("550e8400-e29b-41d4-a716-446655440000").is_ok());
    }

    #[test]
    fn valid_alphanumeric_underscore() {
        assert!(validate_session_id("my_session_01").is_ok());
    }

    #[test]
    fn valid_single_char() {
        assert!(validate_session_id("a").is_ok());
    }

    #[test]
    fn valid_max_length() {
        let id = "a".repeat(128);
        assert!(validate_session_id(&id).is_ok());
    }

    #[test]
    fn reject_empty() {
        assert!(validate_session_id("").is_err());
    }

    #[test]
    fn reject_too_long() {
        let id = "a".repeat(129);
        assert!(validate_session_id(&id).is_err());
    }

    #[test]
    fn reject_path_traversal() {
        assert!(validate_session_id("../../etc/passwd").is_err());
        assert!(validate_session_id("..").is_err());
    }

    #[test]
    fn reject_dots() {
        assert!(validate_session_id("session.json").is_err());
    }

    #[test]
    fn reject_spaces() {
        assert!(validate_session_id("my session").is_err());
    }

    #[test]
    fn reject_nul_byte() {
        assert!(validate_session_id("session\0id").is_err());
    }

    #[test]
    fn reject_slashes() {
        assert!(validate_session_id("a/b").is_err());
        assert!(validate_session_id("a\\b").is_err());
    }

    #[test]
    fn reject_special_chars() {
        assert!(validate_session_id("session;rm -rf").is_err());
        assert!(validate_session_id("<script>").is_err());
        assert!(validate_session_id("id&cmd").is_err());
    }

    #[test]
    fn accept_hyphens_and_underscores() {
        assert!(validate_session_id("a-b_c-d").is_ok());
    }

    #[test]
    fn reject_unicode() {
        assert!(validate_session_id("sesion_\u{00e9}").is_err()); // é
        assert!(validate_session_id("\u{1F600}").is_err()); // emoji
    }
}
