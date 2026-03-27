use std::collections::HashMap;
use std::fs;
use std::path::PathBuf;
use std::sync::{Arc, RwLock};

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

pub fn session_file_path(session_id: &str) -> Result<PathBuf, String> {
    Ok(ensure_session_dir()?.join(format!("{}.json", session_id)))
}
