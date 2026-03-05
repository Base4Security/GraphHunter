mod ai;
mod http_api;

use std::collections::HashMap;
use std::error::Error;
use std::fs;
use std::io::BufReader;
use std::path::PathBuf;
use std::sync::{Arc, RwLock};

use graph_hunter_core::{
    CatalogEntry, CompactionStats, ConfigurableParser, CsvParser,
    Entity, EntityType, FieldConfig, FieldInfo, GenericParser,
    GraphHunter, Hypothesis, LogParser, NeighborEdge, NeighborNode, Neighborhood, NeighborhoodFilter,
    Relation, ScoredPath, ScoringWeights, SentinelJsonParser, SysmonJsonParser,
    preview_fields, get_catalog, parse_dsl,
};
use graph_hunter_core::{preview_generic_from_keys, preview_sentinel, preview_sysmon};
use std::collections::HashSet;
use serde::{Deserialize, Serialize};
use tauri::{Emitter, Manager, State};
use uuid::Uuid;

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
struct SessionFile {
    id: String,
    name: String,
    created_at: i64,
    entities: Vec<Entity>,
    relations: Vec<Relation>,
    #[serde(default)]
    path_node_ids: Vec<String>,
    #[serde(default)]
    notes: Vec<Note>,
    #[serde(default)]
    datasets: Vec<DatasetInfo>,
}

/// Global application state: sessions map and current session.
pub struct AppState {
    pub sessions: RwLock<HashMap<String, Arc<SessionState>>>,
    pub current_session_id: RwLock<Option<String>>,
    pub cached_hunt_paths: RwLock<Vec<Vec<String>>>,
    /// Set in setup; used by HTTP API to emit mcp-view-update so the frontend map reflects MCP expand/subgraph.
    pub app_handle: RwLock<Option<tauri::AppHandle>>,
    /// Last subgraph set by MCP (expand or subgraph); emitted to frontend as mcp-view-update.
    pub last_mcp_subgraph: RwLock<Option<Subgraph>>,
    /// AI provider configuration (set via UI or env var fallback).
    pub ai_config: RwLock<Option<ai::ProviderConfig>>,
    /// AI conversation history for the current session.
    pub ai_conversation: RwLock<ai::AiConversation>,
    /// Bearer token for HTTP API auth (generated at startup).
    pub api_token: String,
    /// GNN model scorer (loaded on demand via cmd_load_gnn_model).
    pub npu_scorer: RwLock<Option<graph_hunter_core::NpuScorer>>,
}

fn session_data_dir() -> Result<PathBuf, String> {
    dirs::data_dir()
        .ok_or_else(|| "Could not resolve app data directory".to_string())
        .map(|p| p.join("GraphHunter").join("sessions"))
}

fn ensure_session_dir() -> Result<PathBuf, String> {
    let dir = session_data_dir()?;
    fs::create_dir_all(&dir).map_err(|e| format!("Failed to create session dir: {}", e))?;
    Ok(dir)
}

fn session_file_path(session_id: &str) -> Result<PathBuf, String> {
    Ok(ensure_session_dir()?.join(format!("{}.json", session_id)))
}

/// Extract a JSON string value from a partial JSON prefix (e.g. first 4KB).
fn extract_json_string(text: &str, key: &str) -> Option<String> {
    let pattern = format!("\"{}\"", key);
    let idx = text.find(&pattern)?;
    let after_key = &text[idx + pattern.len()..];
    let colon = after_key.find(':')?;
    let after_colon = after_key[colon + 1..].trim_start();
    if !after_colon.starts_with('"') {
        return None;
    }
    let content = &after_colon[1..];
    let end = content.find('"')?;
    Some(content[..end].to_string())
}

/// Extract a JSON integer value from a partial JSON prefix.
fn extract_json_i64(text: &str, key: &str) -> Option<i64> {
    let pattern = format!("\"{}\"", key);
    let idx = text.find(&pattern)?;
    let after_key = &text[idx + pattern.len()..];
    let colon = after_key.find(':')?;
    let after_colon = after_key[colon + 1..].trim_start();
    let end = after_colon.find(|c: char| !c.is_ascii_digit() && c != '-')?;
    after_colon[..end].parse().ok()
}

// ── Serializable response types for the frontend ──

#[derive(Serialize)]
pub struct GraphStats {
    pub entity_count: usize,
    pub relation_count: usize,
}

#[derive(Clone, Serialize)]
pub struct LoadResult {
    pub new_entities: usize,
    pub new_relations: usize,
    pub total_entities: usize,
    pub total_relations: usize,
}

/// One row in the preview: log field name and suggested node type (or "Skip").
#[derive(Serialize)]
pub struct DetectedField {
    pub field_name: String,
    pub suggested_entity_type: String,
}

/// Result of preview_ingest: detected format and proposed field -> entity type mapping.
#[derive(Serialize)]
pub struct PreviewIngestResult {
    pub format: String,
    pub detected_fields: Vec<DetectedField>,
}

#[derive(Serialize)]
pub struct HuntResults {
    pub paths: Vec<Vec<String>>,
    pub path_count: usize,
    pub truncated: bool,
}

#[derive(Serialize)]
pub struct PaginatedHuntResults {
    pub total_paths: usize,
    pub filtered_paths: usize,
    pub page: usize,
    pub page_size: usize,
    pub paths: Vec<ScoredPath>,
}

#[derive(Clone, Serialize)]
pub struct SubgraphNode {
    pub id: String,
    pub entity_type: String,
    pub score: f64,
    pub metadata: std::collections::HashMap<String, String>,
}

#[derive(Clone, Serialize)]
pub struct SubgraphEdge {
    pub source: String,
    pub target: String,
    pub rel_type: String,
    pub timestamp: i64,
    pub metadata: std::collections::HashMap<String, String>,
    /// Dataset this event came from (for UI tooltip in Events view).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dataset_id: Option<String>,
}

#[derive(Clone, Serialize)]
pub struct Subgraph {
    pub nodes: Vec<SubgraphNode>,
    pub edges: Vec<SubgraphEdge>,
}

/// Filter struct received from the frontend for neighborhood expansion.
#[derive(Deserialize, Default)]
pub struct ExpandFilter {
    pub entity_types: Option<Vec<String>>,
    pub relation_types: Option<Vec<String>>,
    pub time_start: Option<i64>,
    pub time_end: Option<i64>,
    pub min_score: Option<f64>,
}

/// Converts a string like "IP", "Host", etc. to EntityType. Unknown non-empty strings become Other(name).
pub(crate) fn parse_entity_type(s: &str) -> Option<EntityType> {
    let t = s.trim();
    if t.is_empty() {
        return None;
    }
    match t {
        "IP" => Some(EntityType::IP),
        "Host" => Some(EntityType::Host),
        "User" => Some(EntityType::User),
        "Process" => Some(EntityType::Process),
        "File" => Some(EntityType::File),
        "Domain" => Some(EntityType::Domain),
        "Registry" => Some(EntityType::Registry),
        "URL" => Some(EntityType::URL),
        "Service" => Some(EntityType::Service),
        "*" | "Any" => Some(EntityType::Any),
        _ => Some(EntityType::Other(t.to_string())),
    }
}

/// Converts a string to RelationType.
fn parse_relation_type(s: &str) -> Option<graph_hunter_core::RelationType> {
    match s {
        "Auth" => Some(graph_hunter_core::RelationType::Auth),
        "Connect" => Some(graph_hunter_core::RelationType::Connect),
        "Execute" => Some(graph_hunter_core::RelationType::Execute),
        "Read" => Some(graph_hunter_core::RelationType::Read),
        "Write" => Some(graph_hunter_core::RelationType::Write),
        "DNS" => Some(graph_hunter_core::RelationType::DNS),
        "Modify" => Some(graph_hunter_core::RelationType::Modify),
        "Spawn" => Some(graph_hunter_core::RelationType::Spawn),
        "Delete" => Some(graph_hunter_core::RelationType::Delete),
        "*" | "Any" => Some(graph_hunter_core::RelationType::Any),
        _ => None,
    }
}

/// Converts frontend ExpandFilter to core NeighborhoodFilter.
fn to_core_filter(f: &ExpandFilter) -> NeighborhoodFilter {
    NeighborhoodFilter {
        entity_types: f.entity_types.as_ref().map(|types| {
            types.iter().filter_map(|s| parse_entity_type(s)).collect()
        }),
        relation_types: f.relation_types.as_ref().map(|types| {
            types
                .iter()
                .filter_map(|s| parse_relation_type(s))
                .collect()
        }),
        time_start: f.time_start,
        time_end: f.time_end,
        min_score: f.min_score,
    }
}

/// Helper: run a closure with the current session and its graph (both read).
pub(crate) fn with_current_session_and_graph<T, F>(state: &AppState, f: F) -> Result<T, String>
where
    F: FnOnce(&SessionState, &GraphHunter) -> Result<T, String>,
{
    let current_id = state
        .current_session_id
        .read()
        .map_err(|e| format!("Lock poisoned: {}", e))?
        .clone();
    let id = current_id.as_ref().ok_or("No session selected")?;
    let sessions = state
        .sessions
        .read()
        .map_err(|e| format!("Lock poisoned: {}", e))?;
    let session = sessions.get(id).ok_or("Session not found")?;
    let graph = session
        .graph
        .read()
        .map_err(|e| format!("Lock poisoned: {}", e))?;
    f(session, &graph)
}

/// Helper: run a closure with a read guard on the current session's graph.
pub(crate) fn with_current_graph<T, F>(state: &AppState, f: F) -> Result<T, String>
where
    F: FnOnce(&GraphHunter) -> Result<T, String>,
{
    with_current_session_and_graph(state, |_, graph| f(graph))
}

/// Helper: run a closure with a write guard on the current session's graph.
pub(crate) fn with_current_graph_mut<T, F>(state: &AppState, f: F) -> Result<T, String>
where
    F: FnOnce(&mut GraphHunter) -> Result<T, String>,
{
    let current_id = state
        .current_session_id
        .read()
        .map_err(|e| format!("Lock poisoned: {}", e))?
        .clone();
    let id = current_id.as_ref().ok_or("No session selected")?;
    let sessions = state
        .sessions
        .read()
        .map_err(|e| format!("Lock poisoned: {}", e))?;
    let session = sessions.get(id).ok_or("Session not found")?;
    let mut graph = session
        .graph
        .write()
        .map_err(|e| format!("Lock poisoned: {}", e))?;
    f(&mut graph)
}

// ── Session commands ──

#[derive(Serialize)]
pub struct SessionInfo {
    pub id: String,
    pub name: String,
    pub created_at: i64,
}

/// Create a new empty session and set it as current.
#[tauri::command]
fn cmd_create_session(state: State<Arc<AppState>>, name: Option<String>) -> Result<SessionInfo, String> {
    let id = Uuid::new_v4().to_string();
    let name = name.unwrap_or_else(|| "Untitled".to_string());
    let created_at = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|e| e.to_string())?
        .as_secs() as i64;

    let session = Arc::new(SessionState {
        id: id.clone(),
        name: name.clone(),
        created_at,
        graph: RwLock::new(GraphHunter::new()),
        path_node_ids: RwLock::new(Vec::new()),
        notes: RwLock::new(Vec::new()),
        datasets: RwLock::new(Vec::new()),
    });

    {
        let mut sessions = state
            .sessions
            .write()
            .map_err(|e| format!("Lock poisoned: {}", e))?;
        sessions.insert(id.clone(), session);
    }
    {
        let mut current = state
            .current_session_id
            .write()
            .map_err(|e| format!("Lock poisoned: {}", e))?;
        *current = Some(id.clone());
    }
    {
        let mut cache = state
            .cached_hunt_paths
            .write()
            .map_err(|e| format!("Lock poisoned: {}", e))?;
        *cache = Vec::new();
    }

    Ok(SessionInfo {
        id,
        name,
        created_at,
    })
}

/// List all sessions from memory and disk (merged, no duplicates).
#[tauri::command]
fn cmd_list_sessions(state: State<Arc<AppState>>) -> Result<Vec<SessionInfo>, String> {
    let sessions = state
        .sessions
        .read()
        .map_err(|e| format!("Lock poisoned: {}", e))?;
    let mut seen: HashSet<String> = HashSet::new();
    let mut list: Vec<SessionInfo> = sessions
        .values()
        .map(|s| {
            seen.insert(s.id.clone());
            SessionInfo {
                id: s.id.clone(),
                name: s.name.clone(),
                created_at: s.created_at,
            }
        })
        .collect();

    // Also scan disk for saved sessions not yet loaded into memory.
    // Read only the first 4KB of each file to extract metadata without
    // loading potentially huge entity/relation arrays.
    if let Ok(dir) = session_data_dir() {
        if let Ok(entries) = fs::read_dir(&dir) {
            for entry in entries.flatten() {
                let path = entry.path();
                if path.extension().and_then(|e| e.to_str()) == Some("json") {
                    // Read a small prefix to get id, name, created_at
                    if let Ok(file) = fs::File::open(&path) {
                        use std::io::Read;
                        let mut buf = vec![0u8; 4096];
                        let mut reader = std::io::BufReader::new(file);
                        let n = reader.read(&mut buf).unwrap_or(0);
                        let prefix = String::from_utf8_lossy(&buf[..n]);
                        // Extract fields from the JSON prefix
                        if let (Some(id), Some(name), Some(created_at)) = (
                            extract_json_string(&prefix, "id"),
                            extract_json_string(&prefix, "name"),
                            extract_json_i64(&prefix, "created_at"),
                        ) {
                            if !seen.contains(&id) {
                                seen.insert(id.clone());
                                list.push(SessionInfo { id, name, created_at });
                            }
                        }
                    }
                }
            }
        }
    }

    list.sort_by(|a, b| a.created_at.cmp(&b.created_at));
    Ok(list)
}

/// Load a session by id (from memory or from disk) and set as current.
#[tauri::command]
fn cmd_load_session(state: State<Arc<AppState>>, session_id: String) -> Result<SessionInfo, String> {
    let dir = session_data_dir()?;
    let path = dir.join(format!("{}.json", session_id));

    let mut sessions = state
        .sessions
        .write()
        .map_err(|e| format!("Lock poisoned: {}", e))?;

    if !sessions.contains_key(&session_id) && path.exists() {
        let contents = fs::read_to_string(&path)
            .map_err(|e| format!("Failed to read session file: {}", e))?;
        let file: SessionFile = serde_json::from_str(&contents)
            .map_err(|e| format!("Invalid session file: {}", e))?;
        let graph = GraphHunter::load_snapshot(file.entities, file.relations)
            .map_err(|e| format!("Failed to load graph: {}", e))?;
        let session = Arc::new(SessionState {
            id: file.id.clone(),
            name: file.name.clone(),
            created_at: file.created_at,
            graph: RwLock::new(graph),
            path_node_ids: RwLock::new(file.path_node_ids.clone()),
            notes: RwLock::new(file.notes.clone()),
            datasets: RwLock::new(file.datasets.clone()),
        });
        sessions.insert(file.id.clone(), session);
    }

    let session = sessions
        .get(&session_id)
        .ok_or("Session not found")?;

    {
        let mut current = state
            .current_session_id
            .write()
            .map_err(|e| format!("Lock poisoned: {}", e))?;
        *current = Some(session_id.clone());
    }
    {
        let mut cache = state
            .cached_hunt_paths
            .write()
            .map_err(|e| format!("Lock poisoned: {}", e))?;
        *cache = Vec::new();
    }

    Ok(SessionInfo {
        id: session.id.clone(),
        name: session.name.clone(),
        created_at: session.created_at,
    })
}

/// Save current (or specified) session to disk.
#[tauri::command]
fn cmd_save_session(state: State<Arc<AppState>>, session_id: Option<String>) -> Result<(), String> {
    let id = session_id
        .or_else(|| {
            state
                .current_session_id
                .read()
                .ok()
                .and_then(|g| g.clone())
        })
        .ok_or("No session to save")?;

    let (name, created_at, entities, relations, path_node_ids, notes, datasets) = {
        let sessions = state
            .sessions
            .read()
            .map_err(|e| format!("Lock poisoned: {}", e))?;
        let session = sessions.get(&id).ok_or("Session not found")?;
        let graph = session
            .graph
            .read()
            .map_err(|e| format!("Lock poisoned: {}", e))?;
        let (entities, relations) = graph.to_snapshot();
        let path_node_ids = session
            .path_node_ids
            .read()
            .map_err(|e| format!("Lock poisoned: {}", e))?
            .clone();
        let notes = session
            .notes
            .read()
            .map_err(|e| format!("Lock poisoned: {}", e))?
            .clone();
        let datasets = session
            .datasets
            .read()
            .map_err(|e| format!("Lock poisoned: {}", e))?
            .clone();
        (
            session.name.clone(),
            session.created_at,
            entities,
            relations,
            path_node_ids,
            notes,
            datasets,
        )
    };

    let path = session_file_path(&id)?;
    let file = SessionFile {
        id: id.clone(),
        name,
        created_at,
        entities,
        relations,
        path_node_ids,
        notes,
        datasets,
    };
    let json = serde_json::to_string_pretty(&file).map_err(|e| e.to_string())?;
    fs::write(&path, json).map_err(|e| format!("Failed to write session file: {}", e))?;
    Ok(())
}

/// Delete a session from memory and disk.
#[tauri::command]
fn cmd_delete_session(state: State<Arc<AppState>>, session_id: String) -> Result<(), String> {
    {
        let mut sessions = state
            .sessions
            .write()
            .map_err(|e| format!("Lock poisoned: {}", e))?;
        sessions.remove(&session_id);
    }
    if let Ok(path) = session_file_path(&session_id) {
        let _ = fs::remove_file(&path);
    }
    {
        let mut current = state
            .current_session_id
            .write()
            .map_err(|e| format!("Lock poisoned: {}", e))?;
        if *current == Some(session_id.clone()) {
            *current = None;
        }
    }
    Ok(())
}

/// Get current session id, if any.
#[tauri::command]
fn cmd_get_current_session(state: State<Arc<AppState>>) -> Result<Option<SessionInfo>, String> {
    let current_id = state
        .current_session_id
        .read()
        .map_err(|e| format!("Lock poisoned: {}", e))?
        .clone();
    let id = match &current_id {
        Some(i) => i,
        None => return Ok(None),
    };
    let sessions = state
        .sessions
        .read()
        .map_err(|e| format!("Lock poisoned: {}", e))?;
    let session = sessions.get(id);
    Ok(session.map(|s| SessionInfo {
        id: s.id.clone(),
        name: s.name.clone(),
        created_at: s.created_at,
    }))
}

/// Get entity type names that exist in the current session's graph (no fixed list).
#[tauri::command]
fn cmd_get_entity_types_in_graph(state: State<Arc<AppState>>) -> Result<Vec<String>, String> {
    with_current_graph(state.as_ref(), |graph| Ok(graph.entity_types_in_graph()))
}

/// Get entity type names that are neighbours of the given node (for "Show neighbours > By type").
#[tauri::command]
fn cmd_get_entity_types_for_node_neighbours(
    state: State<Arc<AppState>>,
    node_id: String,
) -> Result<Vec<String>, String> {
    with_current_graph(state.as_ref(), |graph| Ok(graph.entity_types_of_neighbours(&node_id)))
}

/// Response item for entity type counts.
#[derive(Serialize)]
pub struct EntityTypeCount {
    pub entity_type: String,
    pub count: usize,
}

/// Get (entity_type, count) for each type present in the graph.
#[tauri::command]
fn cmd_get_entity_type_counts(state: State<Arc<AppState>>) -> Result<Vec<EntityTypeCount>, String> {
    with_current_graph(state.as_ref(), |graph| {
        Ok(graph
            .entity_type_counts()
            .into_iter()
            .map(|(entity_type, count)| EntityTypeCount { entity_type, count })
            .collect())
    })
}

/// Get all entity IDs of a given type.
#[tauri::command]
fn cmd_get_entities_by_type(
    state: State<Arc<AppState>>,
    type_name: String,
) -> Result<Vec<String>, String> {
    with_current_graph(state.as_ref(), |graph| {
        let et = parse_entity_type(&type_name).ok_or_else(|| format!("Unknown type: {}", type_name))?;
        graph
            .entity_ids_for_type(&et)
            .ok_or_else(|| format!("No entities for type: {}", type_name))
    })
}

/// Paginated response for entity lists.
#[derive(Serialize)]
pub struct PaginatedEntities {
    pub entities: Vec<String>,
    pub total_count: usize,
}

/// Get entity IDs of a given type with pagination (offset + limit).
#[tauri::command]
fn cmd_get_entities_by_type_paginated(
    state: State<Arc<AppState>>,
    type_name: String,
    offset: usize,
    limit: usize,
) -> Result<PaginatedEntities, String> {
    with_current_graph(state.as_ref(), |graph| {
        let et = parse_entity_type(&type_name).ok_or_else(|| format!("Unknown type: {}", type_name))?;
        let all = graph
            .entity_ids_for_type(&et)
            .ok_or_else(|| format!("No entities for type: {}", type_name))?;
        let total_count = all.len();
        let entities = all.into_iter().skip(offset).take(limit).collect();
        Ok(PaginatedEntities { entities, total_count })
    })
}

/// Get all node IDs that participate in at least one relation of the given type (source or target).
#[tauri::command]
fn cmd_get_node_ids_by_relation_type(
    state: State<Arc<AppState>>,
    relation_type: String,
) -> Result<Vec<String>, String> {
    with_current_graph(state.as_ref(), |graph| {
        let rt = parse_relation_type(&relation_type)
            .ok_or_else(|| format!("Unknown relation type: {}", relation_type))?;
        let mut node_ids = HashSet::new();
        for (&source_sid, relations) in &graph.adjacency_list {
            for rel in relations {
                if rel.rel_type == rt {
                    node_ids.insert(graph.interner.resolve(source_sid).to_string());
                    node_ids.insert(rel.dest_id.clone());
                }
            }
        }
        Ok(node_ids.into_iter().collect())
    })
}

/// Get path node IDs (pinned nodes) for the current session.
#[tauri::command]
fn cmd_get_path_nodes(state: State<Arc<AppState>>) -> Result<Vec<String>, String> {
    let current_id = state
        .current_session_id
        .read()
        .map_err(|e| format!("Lock poisoned: {}", e))?
        .clone();
    let id = current_id.as_ref().ok_or("No session selected")?;
    let sessions = state
        .sessions
        .read()
        .map_err(|e| format!("Lock poisoned: {}", e))?;
    let session = sessions.get(id).ok_or("Session not found")?;
    let path_node_ids = session
        .path_node_ids
        .read()
        .map_err(|e| format!("Lock poisoned: {}", e))?;
    Ok(path_node_ids.clone())
}

/// Add a node to path nodes (pin in graph) for the current session.
#[tauri::command]
fn cmd_add_path_node(state: State<Arc<AppState>>, node_id: String) -> Result<(), String> {
    let current_id = state
        .current_session_id
        .read()
        .map_err(|e| format!("Lock poisoned: {}", e))?
        .clone();
    let id = current_id.as_ref().ok_or("No session selected")?;
    let sessions = state
        .sessions
        .read()
        .map_err(|e| format!("Lock poisoned: {}", e))?;
    let session = sessions.get(id).ok_or("Session not found")?;
    let mut path_node_ids = session
        .path_node_ids
        .write()
        .map_err(|e| format!("Lock poisoned: {}", e))?;
    if !path_node_ids.contains(&node_id) {
        path_node_ids.push(node_id);
    }
    Ok(())
}

/// Remove a node from path nodes for the current session.
#[tauri::command]
fn cmd_remove_path_node(state: State<Arc<AppState>>, node_id: String) -> Result<(), String> {
    let current_id = state
        .current_session_id
        .read()
        .map_err(|e| format!("Lock poisoned: {}", e))?
        .clone();
    let id = current_id.as_ref().ok_or("No session selected")?;
    let sessions = state
        .sessions
        .read()
        .map_err(|e| format!("Lock poisoned: {}", e))?;
    let session = sessions.get(id).ok_or("Session not found")?;
    let mut path_node_ids = session
        .path_node_ids
        .write()
        .map_err(|e| format!("Lock poisoned: {}", e))?;
    path_node_ids.retain(|n| n != &node_id);
    Ok(())
}

/// Get all notes for the current session.
#[tauri::command]
fn cmd_get_notes(state: State<Arc<AppState>>) -> Result<Vec<Note>, String> {
    let current_id = state
        .current_session_id
        .read()
        .map_err(|e| format!("Lock poisoned: {}", e))?
        .clone();
    let id = current_id.as_ref().ok_or("No session selected")?;
    let sessions = state
        .sessions
        .read()
        .map_err(|e| format!("Lock poisoned: {}", e))?;
    let session = sessions.get(id).ok_or("Session not found")?;
    let notes = session
        .notes
        .read()
        .map_err(|e| format!("Lock poisoned: {}", e))?;
    Ok(notes.clone())
}

/// Shared implementation for creating a note in the current session (used by Tauri command and HTTP API).
pub(crate) fn create_note_impl(
    state: &AppState,
    content: String,
    node_id: Option<String>,
) -> Result<Note, String> {
    let current_id = state
        .current_session_id
        .read()
        .map_err(|e| format!("Lock poisoned: {}", e))?
        .clone();
    let id = current_id.as_ref().ok_or("No session selected")?;
    let sessions = state
        .sessions
        .read()
        .map_err(|e| format!("Lock poisoned: {}", e))?;
    let session = sessions.get(id).ok_or("Session not found")?;
    let created_at = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|e| e.to_string())?
        .as_secs() as i64;
    let note = Note {
        id: Uuid::new_v4().to_string(),
        content,
        node_id,
        created_at,
    };
    let mut notes = session
        .notes
        .write()
        .map_err(|e| format!("Lock poisoned: {}", e))?;
    notes.push(note.clone());
    Ok(note)
}

/// Create a note (optionally linked to a node). Returns the created note.
#[tauri::command]
fn cmd_create_note(
    state: State<Arc<AppState>>,
    content: String,
    node_id: Option<String>,
) -> Result<Note, String> {
    create_note_impl(state.as_ref(), content, node_id)
}

/// Update a note's content by id.
#[tauri::command]
fn cmd_update_note(state: State<Arc<AppState>>, note_id: String, content: String) -> Result<(), String> {
    let current_id = state
        .current_session_id
        .read()
        .map_err(|e| format!("Lock poisoned: {}", e))?
        .clone();
    let id = current_id.as_ref().ok_or("No session selected")?;
    let sessions = state
        .sessions
        .read()
        .map_err(|e| format!("Lock poisoned: {}", e))?;
    let session = sessions.get(id).ok_or("Session not found")?;
    let mut notes = session
        .notes
        .write()
        .map_err(|e| format!("Lock poisoned: {}", e))?;
    if let Some(n) = notes.iter_mut().find(|n| n.id == note_id) {
        n.content = content;
        Ok(())
    } else {
        Err("Note not found".to_string())
    }
}

/// Delete a note by id.
#[tauri::command]
fn cmd_delete_note(state: State<Arc<AppState>>, note_id: String) -> Result<(), String> {
    let current_id = state
        .current_session_id
        .read()
        .map_err(|e| format!("Lock poisoned: {}", e))?
        .clone();
    let id = current_id.as_ref().ok_or("No session selected")?;
    let sessions = state
        .sessions
        .read()
        .map_err(|e| format!("Lock poisoned: {}", e))?;
    let session = sessions.get(id).ok_or("Session not found")?;
    let mut notes = session
        .notes
        .write()
        .map_err(|e| format!("Lock poisoned: {}", e))?;
    notes.retain(|n| n.id != note_id);
    Ok(())
}

// ── Tauri Commands (graph operations use current session) ──

/// Runs the full scoring pipeline: degree centrality, temporal PageRank,
/// betweenness centrality, then composite score with equal weights.
fn run_full_scoring(graph: &mut GraphHunter) {
    graph.compute_scores();
    graph.compute_temporal_pagerank(None, None, None, None, None);
    graph.compute_betweenness(None);
    graph.compute_composite_score(1.0, 1.0, 1.0);
    graph.finalize_anomaly_scorer();
}

/// Adaptive scoring: skips expensive betweenness for large graphs.
fn run_scoring_adaptive(graph: &mut GraphHunter) {
    graph.compute_scores();
    graph.compute_temporal_pagerank(None, None, None, None, None);
    let n = graph.entity_count();
    if n <= 5_000 {
        graph.compute_betweenness(None);          // Full: default sample
    } else if n <= 10_000 {
        graph.compute_betweenness(Some(100));     // Reduced sample
    }
    // Skip betweenness entirely for >10K entities
    graph.compute_composite_score(1.0, 1.0, 1.0);
    graph.finalize_anomaly_scorer();
}

/// Resolves "auto" format from file contents (same heuristic as cmd_load_data).
fn resolve_format(contents: &str, format_param: &str) -> String {
    let f = format_param.to_lowercase();
    if f != "auto" {
        return f;
    }
    let trimmed = contents.trim();
    if trimmed.starts_with('[') || trimmed.starts_with('{') {
        if (contents.contains("EventID") || contents.contains("event_id"))
            && (contents.contains("UtcTime")
                || contents.contains("Sysmon")
                || contents.contains("Security-Auditing")
                || contents.contains("event_data"))
        {
            return "sysmon".to_string();
        }
        if contents.contains("\"Type\"")
            && (contents.contains("SecurityEvent")
                || contents.contains("SigninLogs")
                || contents.contains("DeviceProcessEvents")
                || contents.contains("DeviceNetworkEvents")
                || contents.contains("DeviceFileEvents")
                || contents.contains("CommonSecurityLog"))
        {
            return "sentinel".to_string();
        }
        return "generic".to_string();
    }
    "csv".to_string()
}

/// Extracts JSON object keys from the first record (array[0] or first NDJSON line or single object).
fn extract_json_keys(contents: &str) -> Vec<String> {
    let trimmed = contents.trim();
    if trimmed.is_empty() {
        return vec![];
    }
    // Try array first
    if trimmed.starts_with('[') {
        if let Ok(v) = serde_json::from_str::<serde_json::Value>(trimmed) {
            if let Some(arr) = v.as_array() {
                if let Some(first) = arr.first() {
                    if let Some(obj) = first.as_object() {
                        return obj.keys().cloned().collect();
                    }
                }
            }
        }
    }
    // Single object
    if trimmed.starts_with('{') {
        if let Ok(v) = serde_json::from_str::<serde_json::Value>(trimmed) {
            if let Some(obj) = v.as_object() {
                return obj.keys().cloned().collect();
            }
        }
    }
    // NDJSON: first line
    if let Some(first_line) = trimmed.lines().next() {
        let line = first_line.trim();
        if line.starts_with('{') {
            if let Ok(v) = serde_json::from_str::<serde_json::Value>(line) {
                if let Some(obj) = v.as_object() {
                    return obj.keys().cloned().collect();
                }
            }
        }
    }
    vec![]
}

/// Converts a Windows EVTX file to Sysmon-style NDJSON (one JSON object per line)
/// so the existing Sysmon parser can ingest it. Normalizes Event/System/EventData
/// structure to flat EventID, UtcTime, Computer, and EventData name/value pairs.
fn evtx_to_sysmon_ndjson(path: &str) -> Result<String, String> {
    use evtx::EvtxParser;

    let mut parser = EvtxParser::from_path(path)
        .map_err(|e| format!("Failed to open EVTX file: {}", e))?;

    let mut lines: Vec<String> = Vec::new();
    for record in parser.records_json_value() {
        let serialized = record.map_err(|e| format!("EVTX record error: {}", e))?;
        let ev = &serialized.data;
        let normalized = evtx_record_to_sysmon_like(ev);
        if let Some(obj) = normalized {
            if let Ok(s) = serde_json::to_string(&obj) {
                lines.push(s);
            }
        }
    }
    Ok(lines.join("\n"))
}

/// Normalizes a single EVTX JSON record (evtx crate output) to Sysmon-like flat object:
/// EventID, UtcTime, Computer, plus EventData name/value pairs.
/// Handles multiple shapes: Event wrapper, root-level System/EventData, and case variants.
fn evtx_record_to_sysmon_like(ev: &serde_json::Value) -> Option<serde_json::Value> {
    use serde_json::{Map, Number, Value};

    let obj = ev.as_object()?;
    // Event may be under "Event" or root may be the event (has System or EventData)
    let event = obj
        .get("Event")
        .and_then(|v| v.as_object())
        .or_else(|| {
            if obj.contains_key("System")
                || obj.contains_key("EventData")
                || obj.contains_key("system")
                || obj.contains_key("eventdata")
            {
                Some(obj)
            } else {
                None
            }
        })
        .or(Some(obj)); // fallback: use root as event (flatten whatever we have)
    let event = event.expect("event is always Some after or(Some(obj))");

    let system = event
        .get("System")
        .and_then(|v| v.as_object())
        .or_else(|| event.get("system").and_then(|v| v.as_object()));

    let event_id = system
        .and_then(|s| extract_event_id(s.get("EventID")))
        .or_else(|| extract_event_id(event.get("EventID")))
        .unwrap_or(0);

    let time_created = system
        .and_then(|s| extract_timestamp_str(s.get("TimeCreated")))
        .or_else(|| extract_timestamp_str(event.get("TimeCreated")))
        .unwrap_or_else(|| "".to_string());

    let computer = system
        .and_then(|s| extract_str_value(s.get("Computer")))
        .or_else(|| extract_str_value(event.get("Computer")))
        .unwrap_or_else(|| "".to_string());

    let mut out = Map::new();
    out.insert(
        "EventID".to_string(),
        Value::Number(Number::from(event_id)),
    );
    out.insert("UtcTime".to_string(), Value::String(time_created));
    out.insert("Computer".to_string(), Value::String(computer));

    let event_data = event
        .get("EventData")
        .or_else(|| event.get("eventdata"));
    if let Some(ed) = event_data {
        if let Some(data_arr) = ed.get("Data").or_else(|| ed.get("data")).and_then(|v| v.as_array()) {
            for item in data_arr {
                if let Some(o) = item.as_object() {
                    let name = o
                        .get("@Name")
                        .or_else(|| o.get("Name"))
                        .and_then(|v| v.as_str())
                        .or_else(|| o.get("#text").and_then(|v| v.as_str()));
                    let value = o.get("#text").and_then(|v| v.as_str()).unwrap_or("");
                    if let Some(name) = name {
                        out.insert(name.to_string(), Value::String(value.to_string()));
                    }
                }
            }
        } else if let Some(data_obj) = ed.get("Data").or_else(|| ed.get("data")).and_then(|v| v.as_object()) {
            for (k, v) in data_obj {
                if let Some(s) = v.as_str() {
                    out.insert(k.clone(), Value::String(s.to_string()));
                }
            }
        }
        // EventData itself can be key-value (evtx sometimes flattens)
        if let Some(ed_obj) = ed.as_object() {
            for (k, v) in ed_obj {
                if k != "Data" && k != "data" {
                    if let Some(s) = v.as_str() {
                        out.insert(k.clone(), Value::String(s.to_string()));
                    }
                }
            }
        }
    }

    // If event is the root and we have no EventData, flatten all string/number fields from event (evtx may output flat)
    if !out.contains_key("NewProcessName") && !out.contains_key("TargetUserName") && !out.contains_key("Image") {
        for (k, v) in event.iter() {
            if out.contains_key(k) {
                continue;
            }
            match v {
                Value::String(s) => {
                    out.insert(k.clone(), Value::String(s.clone()));
                }
                Value::Number(n) => {
                    out.insert(k.clone(), Value::Number(n.clone()));
                }
                _ => {}
            }
        }
    }

    Some(Value::Object(out))
}

fn extract_event_id(v: Option<&serde_json::Value>) -> Option<u64> {
    let v = v?;
    v.as_u64()
        .or_else(|| v.as_i64().map(|i| i as u64))
        .or_else(|| v.get("#text").and_then(|t| t.as_str()).and_then(|s| s.parse().ok()))
}

fn extract_timestamp_str(v: Option<&serde_json::Value>) -> Option<String> {
    let v = v?;
    v.as_str()
        .map(String::from)
        .or_else(|| v.get("@SystemTime").and_then(|t| t.as_str()).map(String::from))
        .or_else(|| v.get("#text").and_then(|t| t.as_str()).map(String::from))
}

fn extract_str_value(v: Option<&serde_json::Value>) -> Option<String> {
    let v = v?;
    v.as_str()
        .map(String::from)
        .or_else(|| v.get("#text").and_then(|t| t.as_str()).map(String::from))
}

/// Extracts CSV header names (first line, simple split by comma).
fn extract_csv_headers(contents: &str) -> Vec<String> {
    let trimmed = contents.trim();
    trimmed
        .lines()
        .next()
        .map(|line| {
            line.split(',')
                .map(|s| s.trim().trim_matches('"').to_string())
                .filter(|s| !s.is_empty())
                .collect()
        })
        .unwrap_or_default()
}

fn path_is_evtx(path: &str) -> bool {
    std::path::Path::new(path)
        .extension()
        .map(|e| e.eq_ignore_ascii_case("evtx"))
        .unwrap_or(false)
}

/// EVTX files start with magic "ElfFile" (7 bytes). Detect so we don't read binary as UTF-8.
fn file_looks_like_evtx(path: &str) -> bool {
    use std::io::Read;
    let mut f = match std::fs::File::open(path) {
        Ok(f) => f,
        Err(_) => return false,
    };
    let mut buf = [0u8; 8];
    if f.read_exact(&mut buf).is_err() {
        return false;
    }
    buf.starts_with(b"ElfFile")
}

/// Preview ingestion: detect format and proposed field -> entity type mapping (no ingest).
#[tauri::command]
fn cmd_preview_ingest(path: String, format: String) -> Result<PreviewIngestResult, String> {
    let use_evtx = format.to_lowercase() == "evtx"
        || path_is_evtx(&path)
        || (format.to_lowercase() == "auto" && file_looks_like_evtx(&path));
    let (contents, resolved) = if use_evtx {
        let contents = evtx_to_sysmon_ndjson(&path)?;
        (contents, "sysmon".to_string())
    } else {
        let contents = std::fs::read_to_string(&path)
            .map_err(|e| format!("Failed to read file '{}': {}", path, e))?;
        let resolved = resolve_format(&contents, &format);
        (contents, resolved)
    };

    let detected_fields: Vec<DetectedField> = match resolved.as_str() {
        "sysmon" => preview_sysmon()
            .into_iter()
            .map(|(a, b)| DetectedField {
                field_name: a,
                suggested_entity_type: b,
            })
            .collect(),
        "sentinel" => preview_sentinel()
            .into_iter()
            .map(|(a, b)| DetectedField {
                field_name: a,
                suggested_entity_type: b,
            })
            .collect(),
        "generic" => {
            let keys = extract_json_keys(&contents);
            preview_generic_from_keys(&keys)
                .into_iter()
                .map(|(a, b)| DetectedField {
                    field_name: a,
                    suggested_entity_type: b,
                })
                .collect()
        }
        "csv" => {
            let keys = extract_csv_headers(&contents);
            preview_generic_from_keys(&keys)
                .into_iter()
                .map(|(a, b)| DetectedField {
                    field_name: a,
                    suggested_entity_type: b,
                })
                .collect()
        }
        _ => vec![],
    };

    Ok(PreviewIngestResult {
        format: resolved,
        detected_fields,
    })
}

/// Reads a file from disk and ingests its log events into the current session's graph.
/// Tags all new entities/relations with a new dataset id for the datasets lateral menu.
/// Auto-computes scores after loading.
#[tauri::command]
fn cmd_load_data(
    state: State<Arc<AppState>>,
    path: String,
    format: String,
) -> Result<LoadResult, String> {
    let use_evtx = format.to_lowercase() == "evtx"
        || path_is_evtx(&path)
        || (format.to_lowercase() == "auto" && file_looks_like_evtx(&path));
    let (contents, format_for_parser) = if use_evtx {
        let contents = evtx_to_sysmon_ndjson(&path)?;
        (contents, "generic".to_string()) // Use generic parser so any EVTX event produces entities (Host, User, etc.)
    } else {
        let contents = std::fs::read_to_string(&path)
            .map_err(|e| format!("Failed to read file '{}': {}", path, e))?;
        (contents, format)
    };

    let session_id = state
        .current_session_id
        .read()
        .map_err(|e| format!("Lock poisoned: {}", e))?
        .clone()
        .ok_or("No current session")?;

    let session = {
        let sessions = state
            .sessions
            .read()
            .map_err(|e| format!("Lock poisoned: {}", e))?;
        Arc::clone(sessions.get(&session_id).ok_or("Session not found")?)
    };

    let dataset_id = Uuid::new_v4().to_string();
    let name = std::path::Path::new(&path)
        .file_name()
        .and_then(|p| p.to_str())
        .unwrap_or("ingest")
        .to_string();
    let created_at = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|e| e.to_string())?
        .as_secs() as i64;

    {
        let mut datasets = session
            .datasets
            .write()
            .map_err(|e| format!("Lock poisoned: {}", e))?;
        datasets.push(DatasetInfo {
            id: dataset_id.clone(),
            name: name.clone(),
            path: Some(path.clone()),
            created_at,
            entity_count: 0,
            relation_count: 0,
        });
    }

    let (new_entities, new_relations) = {
        let mut graph = session
            .graph
            .write()
            .map_err(|e| format!("Lock poisoned: {}", e))?;
        let result = match format_for_parser.to_lowercase().as_str() {
            "sysmon" => graph.ingest_logs(&contents, &SysmonJsonParser, Some(dataset_id.clone())),
            "sentinel" => {
                graph.ingest_logs(&contents, &SentinelJsonParser, Some(dataset_id.clone()))
            }
            "generic" => graph.ingest_logs(&contents, &GenericParser, Some(dataset_id.clone())),
            "csv" => graph.ingest_logs(&contents, &CsvParser, Some(dataset_id.clone())),
            "auto" => {
                let trimmed = contents.trim();
                if trimmed.starts_with('[') || trimmed.starts_with('{') {
                    if (contents.contains("EventID") || contents.contains("event_id"))
                        && (contents.contains("UtcTime")
                            || contents.contains("Sysmon")
                            || contents.contains("Security-Auditing")
                            || contents.contains("event_data"))
                    {
                        graph.ingest_logs(&contents, &SysmonJsonParser, Some(dataset_id.clone()))
                    } else if contents.contains("\"Type\"")
                        && (contents.contains("SecurityEvent")
                            || contents.contains("SigninLogs")
                            || contents.contains("DeviceProcessEvents")
                            || contents.contains("DeviceNetworkEvents")
                            || contents.contains("DeviceFileEvents")
                            || contents.contains("CommonSecurityLog"))
                    {
                        graph.ingest_logs(&contents, &SentinelJsonParser, Some(dataset_id.clone()))
                    } else {
                        graph.ingest_logs(&contents, &GenericParser, Some(dataset_id.clone()))
                    }
                } else {
                    graph.ingest_logs(&contents, &CsvParser, Some(dataset_id.clone()))
                }
            }
            other => {
                return Err(format!(
                    "Unsupported format: '{}'. Use 'auto', 'evtx', 'sysmon', 'sentinel', 'generic', or 'csv'.",
                    other
                ));
            }
        };
        run_full_scoring(&mut graph);
        result
    };

    {
        let mut datasets = session
            .datasets
            .write()
            .map_err(|e| format!("Lock poisoned: {}", e))?;
        if let Some(last) = datasets.last_mut() {
            last.entity_count = new_entities;
            last.relation_count = new_relations;
        }
    }

    let (total_entities, total_relations) = {
        let graph = session
            .graph
            .read()
            .map_err(|e| format!("Lock poisoned: {}", e))?;
        (graph.entity_count(), graph.relation_count())
    };

    Ok(LoadResult {
        new_entities,
        new_relations,
        total_entities,
        total_relations,
    })
}

/// Returns list of ingested datasets for the current session.
#[tauri::command]
fn cmd_list_datasets(state: State<Arc<AppState>>) -> Result<Vec<DatasetInfo>, String> {
    let session_id = state
        .current_session_id
        .read()
        .map_err(|e| format!("Lock poisoned: {}", e))?
        .clone()
        .ok_or("No current session")?;
    let sessions = state
        .sessions
        .read()
        .map_err(|e| format!("Lock poisoned: {}", e))?;
    let session = sessions.get(&session_id).ok_or("Session not found")?;
    let datasets = session
        .datasets
        .read()
        .map_err(|e| format!("Lock poisoned: {}", e))?;
    Ok(datasets.clone())
}

/// Removes a dataset from the current session. Order of operations:
/// 1. Remove all entities and relations that belong to this dataset from the graph.
/// 2. Clean path nodes and unlink notes that reference removed entity IDs.
/// 3. Remove the dataset from the session's dataset list.
#[tauri::command]
fn cmd_remove_dataset(state: State<Arc<AppState>>, dataset_id: String) -> Result<(usize, usize), String> {
    let session_id = state
        .current_session_id
        .read()
        .map_err(|e| format!("Lock poisoned: {}", e))?
        .clone()
        .ok_or("No current session")?;

    let session = {
        let sessions = state
            .sessions
            .read()
            .map_err(|e| format!("Lock poisoned: {}", e))?;
        Arc::clone(sessions.get(&session_id).ok_or("Session not found")?)
    };

    // Collect entity IDs that belong to this dataset (for path/notes cleanup).
    let removed_entity_ids: Vec<String> = {
        let graph = session
            .graph
            .read()
            .map_err(|e| format!("Lock poisoned: {}", e))?;
        graph
            .entities
            .iter()
            .filter(|(_, e)| e.dataset_id.as_deref() == Some(&dataset_id))
            .map(|(&sid, _)| graph.interner.resolve(sid).to_string())
            .collect()
    };
    let removed_set: std::collections::HashSet<&str> =
        removed_entity_ids.iter().map(String::as_str).collect();

    // 1. Remove entities and relations from the graph.
    let (entities_removed, relations_removed) = {
        let mut graph = session
            .graph
            .write()
            .map_err(|e| format!("Lock poisoned: {}", e))?;
        graph.remove_entities_and_relations_by_dataset(&dataset_id)
    };

    // 2. Clean path nodes and unlink notes that reference removed entities.
    {
        let mut path_node_ids = session
            .path_node_ids
            .write()
            .map_err(|e| format!("Lock poisoned: {}", e))?;
        path_node_ids.retain(|id| !removed_set.contains(id.as_str()));
    }
    {
        let mut notes = session
            .notes
            .write()
            .map_err(|e| format!("Lock poisoned: {}", e))?;
        for note in notes.iter_mut() {
            if let Some(ref nid) = note.node_id {
                if removed_set.contains(nid.as_str()) {
                    note.node_id = None;
                }
            }
        }
    }

    // 3. Remove the dataset from the session's dataset list.
    session
        .datasets
        .write()
        .map_err(|e| format!("Lock poisoned: {}", e))?
        .retain(|d| d.id != dataset_id);

    Ok((entities_removed, relations_removed))
}

/// For the given dataset, renames all entities of type from_type to to_type.
#[tauri::command]
fn cmd_rename_type_in_dataset(
    state: State<Arc<AppState>>,
    dataset_id: String,
    from_type: String,
    to_type: String,
) -> Result<usize, String> {
    let from_et = parse_entity_type(&from_type)
        .ok_or_else(|| format!("Invalid entity type: {}", from_type))?;
    let to_et = parse_entity_type(&to_type)
        .ok_or_else(|| format!("Invalid entity type: {}", to_type))?;

    let session_id = state
        .current_session_id
        .read()
        .map_err(|e| format!("Lock poisoned: {}", e))?
        .clone()
        .ok_or("No current session")?;

    let session = {
        let sessions = state
            .sessions
            .read()
            .map_err(|e| format!("Lock poisoned: {}", e))?;
        Arc::clone(sessions.get(&session_id).ok_or("Session not found")?)
    };

    let count = {
        let mut graph = session
            .graph
            .write()
            .map_err(|e| format!("Lock poisoned: {}", e))?;
        graph.rename_entity_type_in_dataset(&dataset_id, from_et, to_et)
    };

    Ok(count)
}

/// Returns entity type names that have at least one entity in the given dataset.
#[tauri::command]
fn cmd_dataset_entity_types(
    state: State<Arc<AppState>>,
    dataset_id: String,
) -> Result<Vec<String>, String> {
    let session_id = state
        .current_session_id
        .read()
        .map_err(|e| format!("Lock poisoned: {}", e))?
        .clone()
        .ok_or("No current session")?;

    let sessions = state
        .sessions
        .read()
        .map_err(|e| format!("Lock poisoned: {}", e))?;
    let session = sessions.get(&session_id).ok_or("Session not found")?;

    let graph = session
        .graph
        .read()
        .map_err(|e| format!("Lock poisoned: {}", e))?;

    Ok(graph.entity_types_in_dataset(&dataset_id))
}

/// Returns current graph statistics (node and edge counts).
#[tauri::command]
fn cmd_get_graph_stats(state: State<Arc<AppState>>) -> Result<GraphStats, String> {
    with_current_graph(state.as_ref(), |graph| {
        Ok(GraphStats {
            entity_count: graph.entity_count(),
            relation_count: graph.relation_count(),
        })
    })
}

/// Executes a temporal pattern search using the provided hypothesis.
/// Caches all paths in AppState. For large result sets (>100 paths),
/// returns empty paths — the frontend uses cmd_get_hunt_page for pagination.
/// Caps results at 10,000 to prevent combinatorial explosion on large graphs.
#[tauri::command]
fn cmd_run_hunt(
    state: State<Arc<AppState>>,
    hypothesis_json: String,
    time_window: Option<(i64, i64)>,
) -> Result<HuntResults, String> {
    let hypothesis: Hypothesis = serde_json::from_str(&hypothesis_json)
        .map_err(|e| format!("Invalid hypothesis JSON: {}", e))?;

    let (paths, truncated) = with_current_graph_mut(state.as_ref(), |graph| {
        // Use smart anomaly-guided search when scorer is finalized, otherwise classic search
        let scorer_ready = graph
            .anomaly_scorer
            .as_ref()
            .map(|s| s.is_finalized())
            .unwrap_or(false);
        if scorer_ready {
            graph.search_temporal_pattern_smart(&hypothesis, time_window, 10_000)
                .map_err(|e| format!("Search failed: {}", e))
        } else {
            graph.search_temporal_pattern(&hypothesis, time_window, Some(10_000))
                .map_err(|e| format!("Search failed: {}", e))
        }
    })?;

    let path_count = paths.len();

    let mut cache = state
        .cached_hunt_paths
        .write()
        .map_err(|e| format!("Lock poisoned: {}", e))?;

    if path_count <= 100 {
        let result = HuntResults {
            paths: paths.clone(),
            path_count,
            truncated,
        };
        *cache = paths; // move into cache
        Ok(result)
    } else {
        *cache = paths; // move into cache (no clone)
        Ok(HuntResults {
            paths: Vec::new(),
            path_count,
            truncated,
        })
    }
}

/// Returns a paginated, scored, and optionally filtered page of cached hunt results.
#[tauri::command]
fn cmd_get_hunt_page(
    state: State<Arc<AppState>>,
    page: usize,
    page_size: usize,
    min_score: Option<f64>,
) -> Result<PaginatedHuntResults, String> {
    let cache = state
        .cached_hunt_paths
        .read()
        .map_err(|e| format!("Lock poisoned: {}", e))?;
    let total_paths = cache.len();

    with_current_graph(state.as_ref(), |graph| {
        let (scored_page, filtered_count) =
            graph.score_and_paginate_paths(&cache, page, page_size, min_score);
        Ok(PaginatedHuntResults {
            total_paths,
            filtered_paths: filtered_count,
            page,
            page_size,
            paths: scored_page,
        })
    })
}

/// Returns all relations (events) where the given node is source or target.
/// Used by the Events view tab to show log/event lines corresponding to the selection.
#[tauri::command]
fn cmd_get_events_for_node(state: State<Arc<AppState>>, node_id: String) -> Result<Vec<SubgraphEdge>, String> {
    with_current_graph(state.as_ref(), |graph| {
        let mut edges: Vec<SubgraphEdge> = Vec::new();

        // Outgoing relations
        for rel in graph.get_relations(&node_id) {
            edges.push(SubgraphEdge {
                source: rel.source_id.clone(),
                target: rel.dest_id.clone(),
                rel_type: format!("{}", rel.rel_type),
                timestamp: rel.timestamp,
                metadata: rel.metadata.clone(),
                dataset_id: rel.dataset_id.as_deref().map(|s| s.to_string()),
            });
        }

        // Incoming relations (node is target)
        for &source_sid in graph.get_reverse_source_sids(&node_id) {
            let source_str = graph.interner.resolve(source_sid);
            for rel in graph.get_relations(source_str) {
                if rel.dest_id == node_id {
                    edges.push(SubgraphEdge {
                        source: rel.source_id.clone(),
                        target: rel.dest_id.clone(),
                        rel_type: format!("{}", rel.rel_type),
                        timestamp: rel.timestamp,
                        metadata: rel.metadata.clone(),
                        dataset_id: rel.dataset_id.as_deref().map(|s| s.to_string()),
                    });
                    break;
                }
            }
        }

        edges.sort_by_key(|e| e.timestamp);
        Ok(edges)
    })
}

/// Returns the complete subgraph (nodes + edges) for the given entity IDs.
#[tauri::command]
fn cmd_get_subgraph(state: State<Arc<AppState>>, node_ids: Vec<String>) -> Result<Subgraph, String> {
    with_current_graph(state.as_ref(), |graph| {
        let id_set: std::collections::HashSet<&str> =
            node_ids.iter().map(|s| s.as_str()).collect();

        let nodes: Vec<SubgraphNode> = node_ids
            .iter()
            .filter_map(|id| graph.get_entity(id))
            .map(|e| SubgraphNode {
                id: e.id.clone(),
                entity_type: format!("{}", e.entity_type),
                score: e.score,
                metadata: e.metadata.clone(),
            })
            .collect();

        let mut edges: Vec<SubgraphEdge> = Vec::new();
        for source_id in &node_ids {
            for rel in graph.get_relations(source_id) {
                if id_set.contains(rel.dest_id.as_str()) {
                    edges.push(SubgraphEdge {
                        source: rel.source_id.clone(),
                        target: rel.dest_id.clone(),
                        rel_type: format!("{}", rel.rel_type),
                        timestamp: rel.timestamp,
                        metadata: rel.metadata.clone(),
                        dataset_id: rel.dataset_id.as_deref().map(|s| s.to_string()),
                    });
                }
            }
        }

        Ok(Subgraph { nodes, edges })
    })
}

/// Searches entities by substring match. Used for IOC search in Explorer mode.
#[tauri::command]
fn cmd_search_entities(
    state: State<Arc<AppState>>,
    query: String,
    type_filter: Option<String>,
    limit: Option<usize>,
) -> Result<Vec<graph_hunter_core::SearchResult>, String> {
    with_current_graph(state.as_ref(), |graph| {
        let et = type_filter.as_deref().and_then(parse_entity_type);
        Ok(graph.search_entities(&query, et.as_ref(), limit.unwrap_or(50)))
    })
}

/// Expands a node's neighborhood for interactive exploration.
/// Path nodes (pinned) are always included so they stay visible when exploring neighbours.
#[tauri::command]
fn cmd_expand_node(
    state: State<Arc<AppState>>,
    node_id: String,
    max_hops: Option<usize>,
    max_nodes: Option<usize>,
    filter: Option<ExpandFilter>,
) -> Result<Neighborhood, String> {
    with_current_session_and_graph(state.as_ref(), |session, graph| {
        let core_filter = filter.as_ref().map(to_core_filter);
        let mut hood = graph
            .get_neighborhood(
                &node_id,
                max_hops.unwrap_or(1),
                max_nodes.unwrap_or(50),
                core_filter.as_ref(),
            )
            .ok_or_else(|| format!("Entity not found: {}", node_id))?;

        let path_ids: Vec<String> = session
            .path_node_ids
            .read()
            .map_err(|e| format!("Lock poisoned: {}", e))?
            .clone();
        let mut in_hood: HashSet<String> = hood.nodes.iter().map(|n| n.id.clone()).collect();

        for path_id in path_ids {
            if in_hood.contains(&path_id) {
                continue;
            }
            let Some(entity) = graph.get_entity(&path_id) else {
                continue;
            };
            hood.nodes.push(NeighborNode {
                id: entity.id.clone(),
                entity_type: format!("{}", entity.entity_type),
                score: entity.score,
                metadata: entity.metadata.clone(),
            });
            in_hood.insert(path_id.clone());

            // Edges from path node to nodes already in hood (neighborhood or other path nodes)
            for rel in graph.get_relations(&path_id) {
                if in_hood.contains(&rel.dest_id) {
                    hood.edges.push(NeighborEdge {
                        source: rel.source_id.clone(),
                        target: rel.dest_id.clone(),
                        rel_type: format!("{}", rel.rel_type),
                        timestamp: rel.timestamp,
                        metadata: rel.metadata.clone(),
                    });
                }
            }
            // Incoming edges from nodes already in hood to this path node
            for &source_sid in graph.get_reverse_source_sids(&path_id) {
                let source_str = graph.interner.resolve(source_sid);
                if !in_hood.contains(source_str) {
                    continue;
                }
                for rel in graph.get_relations(source_str) {
                    if rel.dest_id == path_id {
                        hood.edges.push(NeighborEdge {
                            source: rel.source_id.clone(),
                            target: rel.dest_id.clone(),
                            rel_type: format!("{}", rel.rel_type),
                            timestamp: rel.timestamp,
                            metadata: rel.metadata.clone(),
                        });
                        break;
                    }
                }
            }
        }

        Ok(hood)
    })
}

/// Returns detailed information about a specific node.
#[tauri::command]
fn cmd_get_node_details(
    state: State<Arc<AppState>>,
    node_id: String,
) -> Result<graph_hunter_core::NodeDetails, String> {
    with_current_graph(state.as_ref(), |graph| {
        graph
            .get_node_details(&node_id)
            .ok_or_else(|| format!("Entity not found: {}", node_id))
    })
}

/// Returns a summary of the entire graph.
#[tauri::command]
fn cmd_get_graph_summary(
    state: State<Arc<AppState>>,
) -> Result<graph_hunter_core::GraphSummary, String> {
    with_current_graph(state.as_ref(), |graph| Ok(graph.get_graph_summary()))
}

/// Recalculates scores for all entities.
#[tauri::command]
fn cmd_compute_scores(state: State<Arc<AppState>>) -> Result<(), String> {
    with_current_graph_mut(state.as_ref(), |graph| {
        graph.compute_scores();
        Ok(())
    })
}

/// Previews all fields in a log file by sampling the first N events.
/// Reads only the first 10MB to handle very large files efficiently.
#[tauri::command]
fn cmd_preview_fields(path: String, sample_size: Option<usize>) -> Result<Vec<FieldInfo>, String> {
    let limit = sample_size.unwrap_or(500);

    // Read only first 10MB for performance on large files
    let file = std::fs::File::open(&path)
        .map_err(|e| format!("Failed to open file '{}': {}", path, e))?;
    let mut reader = std::io::BufReader::new(file);
    let mut buf = vec![0u8; 10 * 1024 * 1024]; // 10MB
    use std::io::Read;
    let bytes_read = reader.read(&mut buf)
        .map_err(|e| format!("Failed to read file: {}", e))?;
    buf.truncate(bytes_read);

    let contents = String::from_utf8_lossy(&buf).to_string();
    Ok(preview_fields(&contents, limit))
}

/// Ingests logs using a user-configured field mapping.
/// Creates ConfigurableParser with the provided config, then ingests.
/// If the file is EVTX (binary), converts to Sysmon NDJSON first and uses Sysmon parser.
#[tauri::command]
fn cmd_load_data_with_config(
    state: State<Arc<AppState>>,
    path: String,
    config: FieldConfig,
) -> Result<LoadResult, String> {
    let use_evtx = path_is_evtx(&path) || file_looks_like_evtx(&path);
    let contents = if use_evtx {
        evtx_to_sysmon_ndjson(&path)?
    } else {
        std::fs::read_to_string(&path)
            .map_err(|e| format!("Failed to read file '{}': {}", path, e))?
    };

    with_current_graph_mut(state.as_ref(), |graph| {
        let (new_entities, new_relations) = if use_evtx {
            graph.ingest_logs(&contents, &GenericParser, None)
        } else {
            let parser = ConfigurableParser::new(config);
            graph.ingest_logs(&contents, &parser, None)
        };
        run_full_scoring(graph);

        Ok(LoadResult {
            new_entities,
            new_relations,
            total_entities: graph.entity_count(),
            total_relations: graph.relation_count(),
        })
    })
}

/// SIEM ingest (Sentinel or Elastic): fetch via API then ingest into current session.
/// Runs the API call in a blocking task to avoid blocking the UI.
#[tauri::command]
async fn cmd_ingest_siem(
    state: State<'_, Arc<AppState>>,
    params: serde_json::Value,
) -> Result<LoadResult, String> {
    let source = params
        .get("source")
        .and_then(|v| v.as_str())
        .ok_or("missing param: source (sentinel | elastic)")?;

    let data = match source {
        "sentinel" => {
            let workspace_id = params
                .get("workspace_id")
                .and_then(|v| v.as_str())
                .ok_or("missing param: workspace_id")?
                .to_string();
            let query = params
                .get("query")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            let auth = match (
                params.get("azure_tenant_id").and_then(|v| v.as_str()),
                params.get("azure_client_id").and_then(|v| v.as_str()),
                params.get("azure_client_secret").and_then(|v| v.as_str()),
            ) {
                (Some(t), Some(c), Some(s)) => Some(graph_hunter_cli::siem::SentinelAuth {
                    tenant_id: t.to_string(),
                    client_id: c.to_string(),
                    client_secret: s.to_string(),
                }),
                _ => None,
            };
            let res = tauri::async_runtime::spawn_blocking(move || {
                graph_hunter_cli::siem::run_sentinel_query(&workspace_id, &query, auth)
            })
            .await
            .map_err(|e| format!("task join error: {}", e))??;
            res.data
        }
        "elastic" => {
            let url = params
                .get("url")
                .and_then(|v| v.as_str())
                .ok_or("missing param: url")?
                .to_string();
            let index = params
                .get("index")
                .and_then(|v| v.as_str())
                .unwrap_or("_all")
                .to_string();
            let query = params
                .get("query")
                .and_then(|v| v.as_str())
                .unwrap_or("{}")
                .to_string();
            let size = params.get("size").and_then(|v| v.as_u64()).map(|n| n as u32);
            let auth = match (
                params.get("elastic_api_key").and_then(|v| v.as_str()),
                params.get("elastic_user").and_then(|v| v.as_str()),
                params.get("elastic_password").and_then(|v| v.as_str()),
            ) {
                (Some(k), _, _) if !k.is_empty() => Some(graph_hunter_cli::siem::ElasticAuth {
                    api_key: Some(k.to_string()),
                    user: None,
                    password: None,
                }),
                (_, Some(u), p) if !u.is_empty() => Some(graph_hunter_cli::siem::ElasticAuth {
                    api_key: None,
                    user: Some(u.to_string()),
                    password: p.map(|s| s.to_string()),
                }),
                _ => None,
            };
            let res = tauri::async_runtime::spawn_blocking(move || {
                graph_hunter_cli::siem::run_elastic_query(&url, &index, &query, size, None, auth)
            })
            .await
            .map_err(|e| format!("task join error: {}", e))??;
            res.data
        }
        _ => return Err(format!("unsupported source: '{}'. Use 'sentinel' or 'elastic'.", source)),
    };

    let session_id = state
        .current_session_id
        .read()
        .map_err(|e| format!("Lock poisoned: {}", e))?
        .clone()
        .ok_or("No current session")?;

    let session = {
        let sessions = state
            .sessions
            .read()
            .map_err(|e| format!("Lock poisoned: {}", e))?;
        Arc::clone(sessions.get(&session_id).ok_or("Session not found")?)
    };

    let dataset_id = Uuid::new_v4().to_string();
    let name = match source {
        "sentinel" => "Sentinel ingest",
        _ => "Elasticsearch ingest",
    }
    .to_string();
    let created_at = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|e| e.to_string())?
        .as_secs() as i64;

    {
        let mut datasets = session
            .datasets
            .write()
            .map_err(|e| format!("Lock poisoned: {}", e))?;
        datasets.push(DatasetInfo {
            id: dataset_id.clone(),
            name: name.clone(),
            path: None,
            created_at,
            entity_count: 0,
            relation_count: 0,
        });
    }

    let (new_entities, new_relations) = {
        let mut graph = session
            .graph
            .write()
            .map_err(|e| format!("Lock poisoned: {}", e))?;
        let (e, r) = graph.ingest_logs(&data, &SentinelJsonParser, Some(dataset_id.clone()));
        run_full_scoring(&mut graph);
        (e, r)
    };

    {
        let mut datasets = session
            .datasets
            .write()
            .map_err(|e| format!("Lock poisoned: {}", e))?;
        if let Some(last) = datasets.last_mut() {
            last.entity_count = new_entities;
            last.relation_count = new_relations;
        }
    }

    let (total_entities, total_relations) = {
        let graph = session
            .graph
            .read()
            .map_err(|e| format!("Lock poisoned: {}", e))?;
        (graph.entity_count(), graph.relation_count())
    };

    Ok(LoadResult {
        new_entities,
        new_relations,
        total_entities,
        total_relations,
    })
}

// ── DSL commands ──

#[derive(Serialize)]
pub struct DslResult {
    pub hypothesis: Hypothesis,
    pub formatted: String,
}

/// Parses a DSL string into a Hypothesis.
#[tauri::command]
fn cmd_parse_dsl(input: String, name: Option<String>) -> Result<DslResult, String> {
    let result = parse_dsl(&input, name.as_deref()).map_err(|e| e.to_string())?;
    Ok(DslResult {
        hypothesis: result.hypothesis,
        formatted: result.formatted,
    })
}

// ── Catalog commands ──

/// Returns the ATT&CK hypothesis catalog.
#[tauri::command]
fn cmd_get_catalog() -> Vec<CatalogEntry> {
    get_catalog().to_vec()
}

/// Parses a catalog entry's DSL pattern into a Hypothesis.
/// Sets k_simplicity from the catalog entry (DSL may already include {k=N}, but
/// the catalog field is the authoritative source).
#[tauri::command]
fn cmd_load_catalog_hypothesis(catalog_id: String) -> Result<DslResult, String> {
    let catalog = get_catalog();
    let entry = catalog.iter().find(|e| e.id == catalog_id)
        .ok_or_else(|| format!("Catalog entry not found: {}", catalog_id))?;
    let result = parse_dsl(entry.dsl_pattern, Some(entry.name))
        .map_err(|e| format!("Failed to parse catalog pattern: {}", e))?;
    let mut hypothesis = result.hypothesis;
    hypothesis.k_simplicity = entry.k_simplicity;
    let formatted = graph_hunter_core::format_hypothesis(&hypothesis);
    Ok(DslResult {
        hypothesis,
        formatted,
    })
}

// ── AI commands ──

/// Get the AI config from AppState (set by user) or None for env fallback.
fn get_ai_config(state: &AppState) -> Option<ai::ProviderConfig> {
    state.ai_config.read().ok().and_then(|g| g.clone())
}

/// Check AI configuration: is API key set, which provider/model/base_url.
#[tauri::command]
fn cmd_ai_check_config(state: State<Arc<AppState>>) -> ai::AiConfig {
    let cfg = get_ai_config(state.as_ref());
    ai::check_config(cfg.as_ref())
}

/// Set the AI API key in AppState (legacy, for backward compat — defaults to OpenAI).
#[tauri::command]
fn cmd_ai_set_key(state: State<Arc<AppState>>, key: String) -> Result<(), String> {
    let mut guard = state.ai_config.write().map_err(|e| format!("Lock poisoned: {}", e))?;
    if key.trim().is_empty() {
        *guard = None;
    } else {
        *guard = Some(ai::ProviderConfig {
            provider: ai::AiProvider::OpenAI,
            api_key: key.trim().to_string(),
            model: None,
            base_url: None,
        });
    }
    Ok(())
}

/// Set the AI provider configuration (provider, api_key, model, base_url).
/// Pass provider="auto" or "" to auto-detect from API key format.
/// Returns the detected provider name.
#[tauri::command]
fn cmd_ai_set_provider(
    state: State<Arc<AppState>>,
    provider: String,
    api_key: String,
    model: Option<String>,
    base_url: Option<String>,
) -> Result<String, String> {
    let mut guard = state.ai_config.write().map_err(|e| format!("Lock poisoned: {}", e))?;
    if api_key.trim().is_empty() {
        *guard = None;
        return Ok("none".to_string());
    }
    let ai_provider = match provider.to_lowercase().as_str() {
        "auto" | "" => {
            ai::detect_provider(&api_key)
                .ok_or_else(|| "Could not detect provider from API key format. Please select a provider manually.".to_string())?
        }
        "openai" => ai::AiProvider::OpenAI,
        "anthropic" => ai::AiProvider::Anthropic,
        "google" => ai::AiProvider::Google,
        other => return Err(format!("Unknown provider: '{}'. Use 'openai', 'anthropic', or 'google'.", other)),
    };
    let provider_name = ai_provider.to_string();
    *guard = Some(ai::ProviderConfig {
        provider: ai_provider,
        api_key: api_key.trim().to_string(),
        model,
        base_url,
    });
    Ok(provider_name)
}

/// Propose a hypothesis from a natural-language situation.
#[tauri::command]
async fn cmd_ai_propose_hypothesis(state: State<'_, Arc<AppState>>, situation: String) -> Result<DslResult, String> {
    let cfg = get_ai_config(state.as_ref());
    let result = ai::propose_hypothesis(&situation, cfg.as_ref()).await?;
    Ok(DslResult {
        hypothesis: result.hypothesis,
        formatted: result.formatted,
    })
}

/// Analyze the current subgraph (one-shot, no history). Returns structured response.
#[tauri::command]
async fn cmd_ai_analyze_graph(
    state: State<'_, Arc<AppState>>,
    nodes_json: String,
    edges_json: String,
    selected_node_id: Option<String>,
    question_override: Option<String>,
) -> Result<ai::AiAnalysisResponse, String> {
    let cfg = get_ai_config(state.as_ref());
    ai::analyze_graph(
        &nodes_json,
        &edges_json,
        selected_node_id,
        question_override,
        cfg.as_ref(),
    )
    .await
}

/// Analyze subgraph with conversation history (chat-style). Maintains context.
#[tauri::command]
async fn cmd_ai_analyze_graph_conversation(
    state: State<'_, Arc<AppState>>,
    nodes_json: String,
    edges_json: String,
    selected_node_id: Option<String>,
    user_message: String,
) -> Result<ai::AiAnalysisResponse, String> {
    let cfg = get_ai_config(state.as_ref());

    let conversation = state.ai_conversation.read()
        .map_err(|e| format!("Lock poisoned: {}", e))?
        .clone();

    let (raw_response, parsed) = ai::analyze_graph_conversation(
        &nodes_json,
        &edges_json,
        selected_node_id.as_deref(),
        &user_message,
        &conversation,
        cfg.as_ref(),
    )
    .await?;

    // Update conversation history
    {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as i64;

        let mut conv = state.ai_conversation.write()
            .map_err(|e| format!("Lock poisoned: {}", e))?;

        conv.messages.push(ai::ConversationMessage {
            role: "user".to_string(),
            content: user_message,
            timestamp: now,
        });
        conv.messages.push(ai::ConversationMessage {
            role: "assistant".to_string(),
            content: raw_response,
            timestamp: now,
        });

        // Auto-summarize when conversation gets long (>10 messages)
        if conv.messages.len() > 10 {
            let drain_end = conv.messages.len() - 4;
            let old_messages: Vec<ai::ConversationMessage> =
                conv.messages.drain(..drain_end).collect();
            let summary_parts: Vec<String> = old_messages.iter()
                .map(|m| format!("[{}]: {}", m.role,
                    if m.content.len() > 200 { format!("{}...", &m.content[..200]) } else { m.content.clone() }
                ))
                .collect();
            conv.context_summary = Some(summary_parts.join("\n"));
        }
    }

    Ok(parsed)
}

/// Execute a single AI tool call against the graph.
fn execute_ai_tool(tool_call: &ai::ToolCall, graph: &mut GraphHunter) -> ai::ToolResult {
    let result: Result<String, String> = match tool_call.tool.as_str() {
        "search_entities" => {
            let query = tool_call.params.get("query")
                .and_then(|v| v.as_str())
                .unwrap_or("");
            let type_filter = tool_call.params.get("entity_type")
                .and_then(|v| v.as_str())
                .and_then(parse_entity_type);
            let limit = tool_call.params.get("limit")
                .and_then(|v| v.as_u64())
                .unwrap_or(20) as usize;
            let results = graph.search_entities(query, type_filter.as_ref(), limit);
            serde_json::to_string(&results).map_err(|e| e.to_string())
        }
        "get_node_details" => {
            let node_id = tool_call.params.get("node_id")
                .and_then(|v| v.as_str())
                .unwrap_or("");
            match graph.get_node_details(node_id) {
                Some(details) => serde_json::to_string(&details).map_err(|e| e.to_string()),
                None => Err(format!("Entity not found: {}", node_id)),
            }
        }
        "expand_node" => {
            let node_id = tool_call.params.get("node_id")
                .and_then(|v| v.as_str())
                .unwrap_or("");
            let max_hops = tool_call.params.get("max_hops")
                .and_then(|v| v.as_u64())
                .unwrap_or(2) as usize;
            let max_nodes = tool_call.params.get("max_nodes")
                .and_then(|v| v.as_u64())
                .unwrap_or(50) as usize;
            match graph.get_neighborhood(node_id, max_hops, max_nodes, None) {
                Some(hood) => serde_json::to_string(&hood).map_err(|e| e.to_string()),
                None => Err(format!("Entity not found: {}", node_id)),
            }
        }
        "run_hunt" => {
            let dsl = tool_call.params.get("hypothesis_dsl")
                .and_then(|v| v.as_str())
                .unwrap_or("");
            match parse_dsl(dsl, Some("AI")) {
                Ok(parsed) => {
                    match graph.search_temporal_pattern(&parsed.hypothesis, None, Some(100)) {
                        Ok((paths, truncated)) => {
                            let summary = serde_json::json!({
                                "path_count": paths.len(),
                                "truncated": truncated,
                                "paths": paths.iter().take(20).collect::<Vec<_>>(),
                            });
                            Ok(summary.to_string())
                        }
                        Err(e) => Err(format!("Hunt failed: {}", e)),
                    }
                }
                Err(e) => Err(format!("Invalid DSL: {}", e)),
            }
        }
        "get_graph_stats" => {
            let summary = graph.get_graph_summary();
            serde_json::to_string(&summary).map_err(|e| e.to_string())
        }
        other => Err(format!("Unknown tool: {}", other)),
    };

    match result {
        Ok(mut data) => {
            // Truncate large results to prevent context overflow
            if data.len() > 8000 {
                data.truncate(8000);
                data.push_str("...(truncated)");
            }
            ai::ToolResult { tool: tool_call.tool.clone(), success: true, data }
        }
        Err(e) => ai::ToolResult { tool: tool_call.tool.clone(), success: false, data: e },
    }
}

/// Build a short graph stats string for the agentic system prompt.
fn build_graph_stats_for_prompt(graph: &GraphHunter) -> String {
    let summary = graph.get_graph_summary();
    let mut parts = vec![
        format!("{} entities, {} relations", summary.entity_count, summary.relation_count),
    ];
    if !summary.type_distribution.is_empty() {
        let types: Vec<String> = summary.type_distribution.iter()
            .map(|t| format!("{}: {}", t.entity_type, t.count))
            .collect();
        parts.push(format!("Types: {}", types.join(", ")));
    }
    if let Some((min, max)) = summary.time_range {
        parts.push(format!("Time range: {} to {}", min, max));
    }
    if !summary.top_anomalies.is_empty() {
        let top: Vec<String> = summary.top_anomalies.iter().take(5)
            .map(|a| format!("{} ({}, score={:.2})", a.id, a.entity_type, a.score))
            .collect();
        parts.push(format!("Top anomalies: {}", top.join("; ")));
    }
    parts.join("\n")
}

/// Agentic AI chat: LLM can call tools in a loop to query the graph.
#[tauri::command]
async fn cmd_ai_chat(
    state: State<'_, Arc<AppState>>,
    user_message: String,
) -> Result<ai::AiAnalysisResponse, String> {
    let cfg = get_ai_config(state.as_ref())
        .ok_or_else(|| "No AI provider configured. Set API key in AI Settings.".to_string())?;
    let resolved_cfg = ai::resolve_config(Some(&cfg))?;

    // Build graph stats (read lock, release immediately)
    let graph_stats = with_current_graph(state.as_ref(), |graph| {
        Ok(build_graph_stats_for_prompt(graph))
    })?;

    let system_prompt = ai::build_agentic_system_prompt(&graph_stats);

    // Load conversation history
    let conversation = state.ai_conversation.read()
        .map_err(|e| format!("Lock poisoned: {}", e))?
        .clone();

    let mut working_history = ai::build_messages_with_history(&conversation, &user_message);

    let mut final_response = String::new();
    const MAX_ITERATIONS: usize = 5;

    for _iteration in 0..MAX_ITERATIONS {
        // Call LLM (no locks held during this call)
        let raw = ai::call_llm_with_history(
            &resolved_cfg,
            &system_prompt,
            &working_history,
            Some(16384),
        ).await?;

        // Parse tool calls
        let tool_calls = ai::parse_tool_calls(&raw);

        if tool_calls.is_empty() {
            // No tools → this is the final answer
            final_response = raw;
            break;
        }

        // Execute tools (brief write lock per tool)
        let mut tool_results: Vec<ai::ToolResult> = Vec::new();
        for tc in &tool_calls {
            let result = with_current_graph_mut(state.as_ref(), |graph| {
                Ok(execute_ai_tool(tc, graph))
            })?;
            tool_results.push(result);
        }

        // Append assistant response + tool results to working history
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as i64;

        working_history.push(ai::ConversationMessage {
            role: "assistant".to_string(),
            content: raw,
            timestamp: now,
        });

        let tool_results_text = tool_results.iter()
            .map(|r| {
                if r.success {
                    format!("Tool `{}` result:\n{}", r.tool, r.data)
                } else {
                    format!("Tool `{}` error: {}", r.tool, r.data)
                }
            })
            .collect::<Vec<_>>()
            .join("\n\n");

        working_history.push(ai::ConversationMessage {
            role: "user".to_string(),
            content: format!("[Tool Results]\n{}", tool_results_text),
            timestamp: now,
        });

        // If this is the last iteration, set the raw as final response
        if _iteration == MAX_ITERATIONS - 1 {
            // Force one more call without expecting tools
            let final_raw = ai::call_llm_with_history(
                &resolved_cfg,
                &system_prompt,
                &working_history,
                Some(16384),
            ).await?;
            final_response = final_raw;
        }
    }

    // Parse the final response for suggestions
    let parsed = ai::parse_ai_response(&final_response);

    // Save only user message + final response to persistent conversation history
    {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as i64;

        let mut conv = state.ai_conversation.write()
            .map_err(|e| format!("Lock poisoned: {}", e))?;

        conv.messages.push(ai::ConversationMessage {
            role: "user".to_string(),
            content: user_message,
            timestamp: now,
        });
        conv.messages.push(ai::ConversationMessage {
            role: "assistant".to_string(),
            content: parsed.text.clone(),
            timestamp: now,
        });

        // Auto-summarize when conversation gets long
        if conv.messages.len() > 10 {
            let drain_end = conv.messages.len() - 4;
            let old_messages: Vec<ai::ConversationMessage> =
                conv.messages.drain(..drain_end).collect();
            let summary_parts: Vec<String> = old_messages.iter()
                .map(|m| format!("[{}]: {}", m.role,
                    if m.content.len() > 200 { format!("{}...", &m.content[..200]) } else { m.content.clone() }
                ))
                .collect();
            conv.context_summary = Some(summary_parts.join("\n"));
        }
    }

    Ok(parsed)
}

/// Clear the AI conversation history.
#[tauri::command]
fn cmd_ai_clear_conversation(state: State<Arc<AppState>>) -> Result<(), String> {
    let mut conv = state.ai_conversation.write()
        .map_err(|e| format!("Lock poisoned: {}", e))?;
    conv.clear();
    Ok(())
}

/// Get the current AI conversation messages (for frontend display).
#[tauri::command]
fn cmd_ai_get_conversation(state: State<Arc<AppState>>) -> Result<Vec<ai::ConversationMessage>, String> {
    let conv = state.ai_conversation.read()
        .map_err(|e| format!("Lock poisoned: {}", e))?;
    Ok(conv.messages.clone())
}

// ── Streaming ingestion (async) ──

/// Response returned immediately when ingestion starts.
#[derive(Clone, Serialize)]
pub struct IngestJobStarted {
    pub job_id: String,
    pub dataset_id: String,
}

/// Emitted when background ingestion completes successfully.
#[derive(Clone, Serialize)]
struct IngestComplete {
    job_id: String,
    dataset_id: String,
    result: LoadResult,
}

/// Emitted when background ingestion fails.
#[derive(Clone, Serialize)]
struct IngestError {
    job_id: String,
    dataset_id: String,
    error: String,
}

/// Starts file ingestion in the background and returns immediately.
/// Progress is emitted via "ingest-progress" events.
/// Completion is emitted via "ingest-complete" or "ingest-error" events.
#[tauri::command]
async fn cmd_load_data_streaming(
    state: State<'_, Arc<AppState>>,
    app: tauri::AppHandle,
    path: String,
    format: String,
    config: Option<FieldConfig>,
) -> Result<IngestJobStarted, String> {
    let job_id = Uuid::new_v4().to_string();

    let session_id = state
        .current_session_id
        .read()
        .map_err(|e| format!("Lock poisoned: {}", e))?
        .clone()
        .ok_or("No current session")?;

    // Clone the Arc<SessionState> under a brief read lock, then release
    let session = {
        let sessions = state
            .sessions
            .read()
            .map_err(|e| format!("Lock poisoned: {}", e))?;
        Arc::clone(sessions.get(&session_id).ok_or("Session not found")?)
    };

    let dataset_id = Uuid::new_v4().to_string();
    let file_name = std::path::Path::new(&path)
        .file_name()
        .and_then(|p| p.to_str())
        .unwrap_or("ingest")
        .to_string();
    let created_at = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|e| e.to_string())?
        .as_secs() as i64;

    // Create dataset entry under brief lock
    {
        let mut datasets = session
            .datasets
            .write()
            .map_err(|e| format!("Lock poisoned: {}", e))?;
        datasets.push(DatasetInfo {
            id: dataset_id.clone(),
            name: file_name.clone(),
            path: Some(path.clone()),
            created_at,
            entity_count: 0,
            relation_count: 0,
        });
    }

    // Validate format before spawning (fail fast for bad format)
    let pre_check = format.to_lowercase();
    if !["auto", "evtx", "sysmon", "sentinel", "generic", "csv"].contains(&pre_check.as_str()) {
        return Err(format!(
            "Unsupported format: '{}'. Use 'auto', 'evtx', 'sysmon', 'sentinel', 'generic', or 'csv'.",
            format
        ));
    }

    let result_to_return = IngestJobStarted {
        job_id: job_id.clone(),
        dataset_id: dataset_id.clone(),
    };

    // Spawn the heavy work in a background thread
    let bg_job_id = job_id.clone();
    let bg_dataset_id = dataset_id.clone();
    let bg_path = path.clone();
    let bg_format = format.clone();
    let bg_app = app.clone();
    let bg_session = Arc::clone(&session);
    let bg_config = config.clone();

    tauri::async_runtime::spawn_blocking(move || {
        let panic_app = bg_app.clone();
        let panic_job_id = bg_job_id.clone();
        let panic_dataset_id = bg_dataset_id.clone();

        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(move || {
        const BATCH_LINES: usize = 50_000;
        const BUF_CAPACITY: usize = 8 * 1024 * 1024; // 8 MB

        // 1. Open file and check for EVTX (binary) before any UTF-8 read
        let use_evtx = path_is_evtx(&bg_path)
            || bg_format.to_lowercase() == "evtx"
            || (bg_format.to_lowercase() == "auto" && file_looks_like_evtx(&bg_path));

        if use_evtx {
            // EVTX path: convert to Sysmon NDJSON, then parse in memory (no mmap/UTF-8 on binary)
            let contents = match evtx_to_sysmon_ndjson(&bg_path) {
                Ok(s) => s,
                Err(e) => {
                    let _ = bg_app.emit("ingest-error", IngestError {
                        job_id: bg_job_id,
                        dataset_id: bg_dataset_id,
                        error: e,
                    });
                    return;
                }
            };
            let bytes_total = contents.len() as u64;
            // When user provided a field mapping (e.g. custom node types), use ConfigurableParser so mapping is applied.
            // Otherwise use GenericParser so any EVTX event produces entities.
            let parser: Box<dyn LogParser + Send> = if let Some(cfg) = &bg_config {
                Box::new(ConfigurableParser::new(cfg.clone()))
            } else {
                Box::new(GenericParser)
            };
            let mut total_new_entities = 0usize;
            let mut total_new_relations = 0usize;
            let mut lines_in_batch = 0usize;
            let mut batch_start = 0usize;
            let data = contents.as_str();

            for (pos, _) in data.char_indices().filter(|&(_, c)| c == '\n') {
                lines_in_batch += 1;
                let bytes_read = (pos + 1) as u64;

                if lines_in_batch >= BATCH_LINES {
                    let batch_slice = &data[batch_start..pos + 1];
                    let triples = parser.parse(batch_slice);
                    let (ne, nr) = {
                        let mut graph = match bg_session.graph.write() {
                            Ok(g) => g,
                            Err(_) => break,
                        };
                        graph.insert_triples(triples, Some(&bg_dataset_id))
                    };
                    total_new_entities += ne;
                    total_new_relations += nr;

                    let _ = bg_app.emit("ingest-progress", serde_json::json!({
                        "phase": "parsing",
                        "bytes_read": bytes_read,
                        "bytes_total": bytes_total,
                        "entities": total_new_entities,
                        "relations": total_new_relations,
                    }));

                    batch_start = pos + 1;
                    lines_in_batch = 0;
                }
            }

            if batch_start < data.len() {
                let batch_slice = &data[batch_start..];
                if !batch_slice.trim().is_empty() {
                    let triples = parser.parse(batch_slice);
                    let (ne, nr) = match bg_session.graph.write() {
                        Ok(mut graph) => graph.insert_triples(triples, Some(&bg_dataset_id)),
                        Err(_) => (0, 0),
                    };
                    total_new_entities += ne;
                    total_new_relations += nr;
                }
            }

            // Run scoring and emit complete (same as normal path below)
            let _ = bg_app.emit("ingest-progress", serde_json::json!({
                "phase": "scoring",
                "bytes_read": bytes_total,
                "bytes_total": bytes_total,
                "entities": total_new_entities,
                "relations": total_new_relations,
            }));

            if let Ok(mut graph) = bg_session.graph.write() {
                graph.compute_composite_score(1.0, 1.0, 1.0);
                graph.finalize_anomaly_scorer();
            }

            {
                let mut datasets = match bg_session.datasets.write() {
                    Ok(d) => d,
                    Err(_) => return,
                };
                if let Some(last) = datasets.last_mut() {
                    last.entity_count = total_new_entities;
                    last.relation_count = total_new_relations;
                }
            }

            let (total_entities, total_relations) = {
                let graph = match bg_session.graph.read() {
                    Ok(g) => g,
                    Err(_) => return,
                };
                (graph.entity_count(), graph.relation_count())
            };

            let _ = bg_app.emit("ingest-complete", IngestComplete {
                job_id: bg_job_id,
                dataset_id: bg_dataset_id,
                result: LoadResult {
                    new_entities: total_new_entities,
                    new_relations: total_new_relations,
                    total_entities,
                    total_relations,
                },
            });
            return;
        }

        // 2. Open file (or reopen) and get size for progress reporting
        let file = match std::fs::File::open(&bg_path) {
            Ok(f) => f,
            Err(e) => {
                let _ = bg_app.emit("ingest-error", IngestError {
                    job_id: bg_job_id,
                    dataset_id: bg_dataset_id,
                    error: format!("Failed to open file '{}': {}", bg_path, e),
                });
                return;
            }
        };
        let bytes_total = file.metadata().map(|m| m.len()).unwrap_or(0);

        // 3. Read first 8KB for format detection
        let mut reader = BufReader::with_capacity(BUF_CAPACITY, file);
        let peek_buf = {
            let mut peek_bytes = [0u8; 8192];
            let n = std::io::Read::read(&mut reader, &mut peek_bytes).unwrap_or(0);
            String::from_utf8_lossy(&peek_bytes[..n]).to_string()
        };
        let resolved = resolve_format(&peek_buf, &bg_format);

        // Determine if the file is NDJSON (lines starting with '{') vs JSON array (starts with '[')
        let trimmed_peek = peek_buf.trim_start();
        let is_ndjson = trimmed_peek.starts_with('{');

        // Helper: select parser as trait object
        let parser: Box<dyn LogParser + Send + Sync> = match resolved.as_str() {
            "sysmon" => Box::new(SysmonJsonParser),
            "sentinel" => Box::new(SentinelJsonParser),
            "generic" => Box::new(GenericParser),
            "csv" => Box::new(CsvParser),
            other => {
                let _ = bg_app.emit("ingest-error", IngestError {
                    job_id: bg_job_id,
                    dataset_id: bg_dataset_id,
                    error: format!(
                        "Unsupported format: '{}'. Use 'auto', 'sysmon', 'sentinel', 'generic', or 'csv'.",
                        other
                    ),
                });
                return;
            }
        };

        // Pre-allocate graph capacity based on file size heuristics (capped to avoid OOM)
        {
            let estimated_entities = ((bytes_total / 400) as usize).min(2_000_000);
            let estimated_relations = ((bytes_total / 200) as usize).min(4_000_000);
            if let Ok(mut graph) = bg_session.graph.write() {
                graph.reserve(estimated_entities, estimated_relations);
            }
        }

        let ingest_result: Result<(usize, usize), String> = (|| -> Result<(usize, usize), String> {
            if is_ndjson {
                // ── NDJSON streaming path: mmap + line-batch parsing ──
                let _ = bg_app.emit("ingest-progress", serde_json::json!({
                    "phase": "reading",
                    "bytes_read": 0u64,
                    "bytes_total": bytes_total,
                    "entities": 0,
                    "relations": 0,
                }));

                let file2 = std::fs::File::open(&bg_path)
                    .map_err(|e| format!("Failed to re-open file '{}': {}", bg_path, e))?;
                let mmap = unsafe { memmap2::Mmap::map(&file2) }
                    .map_err(|e| format!("Failed to mmap file '{}': {}", bg_path, e))?;
                let data = std::str::from_utf8(&mmap)
                    .map_err(|e| format!("File is not valid UTF-8: {}", e))?;

                let mut total_new_entities = 0usize;
                let mut total_new_relations = 0usize;
                let mut bytes_read: u64;
                let mut lines_in_batch = 0usize;
                let mut batch_start = 0usize;

                // Iterate lines by scanning for newlines in the mmap
                for (pos, _) in data.char_indices().filter(|&(_, c)| c == '\n') {
                    lines_in_batch += 1;
                    bytes_read = (pos + 1) as u64;

                    if lines_in_batch >= BATCH_LINES {
                        let batch_slice = &data[batch_start..pos + 1];
                        let triples = parser.parse(batch_slice);

                        let (ne, nr) = {
                            let mut graph = bg_session
                                .graph
                                .write()
                                .map_err(|e| format!("Lock poisoned: {}", e))?;
                            graph.insert_triples(triples, Some(&bg_dataset_id))
                        };
                        total_new_entities += ne;
                        total_new_relations += nr;

                        let _ = bg_app.emit("ingest-progress", serde_json::json!({
                            "phase": "parsing",
                            "bytes_read": bytes_read,
                            "bytes_total": bytes_total,
                            "entities": total_new_entities,
                            "relations": total_new_relations,
                        }));

                        batch_start = pos + 1;
                        lines_in_batch = 0;
                    }
                }

                // Final batch (remaining lines after last newline)
                if batch_start < data.len() {
                    let batch_slice = &data[batch_start..];
                    if !batch_slice.trim().is_empty() {
                        let triples = parser.parse(batch_slice);
                        let (ne, nr) = {
                            let mut graph = bg_session
                                .graph
                                .write()
                                .map_err(|e| format!("Lock poisoned: {}", e))?;
                            graph.insert_triples(triples, Some(&bg_dataset_id))
                        };
                        total_new_entities += ne;
                        total_new_relations += nr;
                    }
                }

                Ok((total_new_entities, total_new_relations))
            } else {
                // ── JSON array / small file: memory-mapped parse + insert ──
                let file = std::fs::File::open(&bg_path)
                    .map_err(|e| format!("Failed to open file '{}': {}", bg_path, e))?;
                let mmap = unsafe { memmap2::Mmap::map(&file) }
                    .map_err(|e| format!("Failed to mmap file '{}': {}", bg_path, e))?;
                let contents = std::str::from_utf8(&mmap)
                    .map_err(|e| format!("File is not valid UTF-8: {}", e))?;

                let _ = bg_app.emit("ingest-progress", serde_json::json!({
                    "phase": "parsing",
                    "bytes_read": bytes_total,
                    "bytes_total": bytes_total,
                    "entities": 0,
                    "relations": 0,
                }));

                let triples = parser.parse(contents);

                let mut graph = bg_session
                    .graph
                    .write()
                    .map_err(|e| format!("Lock poisoned: {}", e))?;

                let result = graph.insert_triples(triples, Some(&bg_dataset_id));
                Ok(result)
            }
        })();

        match ingest_result {
            Ok((new_entities, new_relations)) => {
                // Run adaptive scoring (emits scoring phase)
                let _ = bg_app.emit("ingest-progress", serde_json::json!({
                    "phase": "scoring",
                    "bytes_read": bytes_total,
                    "bytes_total": bytes_total,
                    "entities": new_entities,
                    "relations": new_relations,
                }));

                {
                    let mut graph = match bg_session.graph.write() {
                        Ok(g) => g,
                        Err(e) => {
                            let _ = bg_app.emit("ingest-error", IngestError {
                                job_id: bg_job_id,
                                dataset_id: bg_dataset_id,
                                error: format!("Lock poisoned during scoring: {}", e),
                            });
                            return;
                        }
                    };
                    graph.rebuild_rel_index();
                    run_scoring_adaptive(&mut graph);
                }

                // Update dataset counts
                if let Ok(mut datasets) = bg_session.datasets.write() {
                    if let Some(ds) = datasets.iter_mut().find(|d| d.id == bg_dataset_id) {
                        ds.entity_count = new_entities;
                        ds.relation_count = new_relations;
                    }
                }

                // Get totals
                let (total_entities, total_relations) = bg_session
                    .graph
                    .read()
                    .map(|g| (g.entity_count(), g.relation_count()))
                    .unwrap_or((0, 0));

                let _ = bg_app.emit("ingest-complete", IngestComplete {
                    job_id: bg_job_id,
                    dataset_id: bg_dataset_id,
                    result: LoadResult {
                        new_entities,
                        new_relations,
                        total_entities,
                        total_relations,
                    },
                });
            }
            Err(e) => {
                let _ = bg_app.emit("ingest-error", IngestError {
                    job_id: bg_job_id,
                    dataset_id: bg_dataset_id,
                    error: e,
                });
            }
        }
        })); // end catch_unwind

        if let Err(panic_info) = result {
            let msg = if let Some(s) = panic_info.downcast_ref::<&str>() {
                s.to_string()
            } else if let Some(s) = panic_info.downcast_ref::<String>() {
                s.clone()
            } else {
                "Unknown panic during ingestion".to_string()
            };
            let _ = panic_app.emit("ingest-error", IngestError {
                job_id: panic_job_id,
                dataset_id: panic_dataset_id,
                error: format!("Internal error: {}", msg),
            });
        }
    });

    Ok(result_to_return)
}

// ── Temporal heatmap ──

#[derive(Serialize)]
pub struct HeatmapRow {
    pub relation_type: String,
    pub bins: Vec<(i64, usize)>,
}

/// Returns hourly-bucketed relation counts grouped by relation type.
#[tauri::command]
fn cmd_get_temporal_heatmap(state: State<Arc<AppState>>) -> Result<Vec<HeatmapRow>, String> {
    with_current_graph(state.as_ref(), |graph| {
        Ok(graph.temporal_heatmap()
            .into_iter()
            .map(|(relation_type, bins)| HeatmapRow { relation_type, bins })
            .collect())
    })
}

// ── Timeline sparkline ──

#[derive(Serialize)]
pub struct TimelineRow {
    pub entity_type: String,
    pub min_time: i64,
    pub max_time: i64,
    pub bins: Vec<(i64, usize)>,
}

/// Returns timestamp distribution per entity type for sparkline visualization.
#[tauri::command]
fn cmd_get_timeline_data(state: State<Arc<AppState>>) -> Result<Vec<TimelineRow>, String> {
    with_current_graph(state.as_ref(), |graph| {
        Ok(graph.timeline_data()
            .into_iter()
            .map(|(entity_type, min_time, max_time, bins)| {
                TimelineRow { entity_type, min_time, max_time, bins }
            })
            .collect())
    })
}

// ── Analytics commands ──

/// Computes betweenness centrality (Brandes algorithm).
#[tauri::command]
fn cmd_compute_betweenness(state: State<Arc<AppState>>, sample_limit: Option<usize>) -> Result<(), String> {
    with_current_graph_mut(state.as_ref(), |graph| {
        graph.compute_betweenness(sample_limit);
        Ok(())
    })
}

/// Computes temporal PageRank with exponential decay.
#[tauri::command]
fn cmd_compute_pagerank(
    state: State<Arc<AppState>>,
    lambda: Option<f64>,
    damping: Option<f64>,
    max_iter: Option<usize>,
    reference_time: Option<i64>,
) -> Result<(), String> {
    with_current_graph_mut(state.as_ref(), |graph| {
        graph.compute_temporal_pagerank(lambda, damping, max_iter, None, reference_time);
        Ok(())
    })
}

/// Computes composite score from weighted combination of degree, pagerank, betweenness.
#[tauri::command]
fn cmd_compute_composite_scores(
    state: State<Arc<AppState>>,
    degree_weight: f64,
    pagerank_weight: f64,
    betweenness_weight: f64,
) -> Result<(), String> {
    with_current_graph_mut(state.as_ref(), |graph| {
        graph.compute_composite_score(degree_weight, pagerank_weight, betweenness_weight);
        Ok(())
    })
}

/// Compacts old edges before a cutoff timestamp.
#[tauri::command]
fn cmd_compact(state: State<Arc<AppState>>, cutoff_timestamp: i64) -> Result<CompactionStats, String> {
    with_current_graph_mut(state.as_ref(), |graph| {
        Ok(graph.compact_before(cutoff_timestamp))
    })
}

/// Result of testing the HTTP API health endpoint (for the "Test API" button).
#[derive(Serialize)]
pub struct ApiTestResult {
    pub ok: bool,
    pub status: Option<u16>,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub body: Option<String>,
}

/// Build a full error description from reqwest::Error (including cause chain).
fn reqwest_error_message(e: &reqwest::Error) -> String {
    let mut msg = e.to_string();
    if let Some(source) = e.source() {
        msg.push_str(" (");
        msg.push_str(&source.to_string());
        msg.push(')');
    }
    msg
}

/// Test the local HTTP API by GET /health. Runs in a thread so the UI does not block.
/// First checks if the port is reachable (TCP), then tries HTTP with reqwest.
#[tauri::command]
fn cmd_test_http_api() -> Result<ApiTestResult, String> {
    let port = std::env::var("GRAPHHUNTER_API_PORT")
        .ok()
        .and_then(|s| s.parse::<u16>().ok())
        .unwrap_or(37891);
    let url = format!("http://127.0.0.1:{}/health", port);
    let result = std::thread::scope(|s| {
        s.spawn(|| {
            // 1) Quick TCP check: can we reach the port at all?
            let addr = std::net::SocketAddr::from(([127, 0, 0, 1], port));
            let tcp_ok = std::net::TcpStream::connect_timeout(
                &addr,
                std::time::Duration::from_secs(2),
            ).is_ok();
            if !tcp_ok {
                return Ok(ApiTestResult {
                    ok: false,
                    status: None,
                    message: format!(
                        "Cannot connect to 127.0.0.1:{} — connection refused. Is the HTTP API thread running? Check the terminal for \"GraphHunter HTTP API listening\".",
                        port
                    ),
                    body: None,
                });
            }
            // 2) Port is open; try HTTP. Use a client with no proxy to avoid Windows proxy issues on localhost.
            let client = reqwest::blocking::Client::builder()
                .timeout(std::time::Duration::from_secs(3))
                .no_proxy()
                .build()
                .map_err(|e| e.to_string())?;
            match client.get(&url).send() {
                Ok(resp) => {
                    let status = resp.status();
                    let code = status.as_u16();
                    let body = resp.text().ok();
                    let ok = status.is_success();
                    Ok(ApiTestResult {
                        ok,
                        status: Some(code),
                        message: if ok {
                            "API responded OK.".to_string()
                        } else {
                            format!("API returned HTTP {}", code)
                        },
                        body,
                    })
                }
                Err(e) => Ok(ApiTestResult {
                    ok: false,
                    status: None,
                    message: format!(
                        "Port {} is open but HTTP request failed: {}",
                        port,
                        reqwest_error_message(&e)
                    ),
                    body: None,
                }),
            }
        })
        .join()
        .map_err(|_| "Test thread panicked".to_string())?
    });
    result
}

// ── Anomaly Scoring Commands ──

/// Enable anomaly scoring with optional custom weights.
#[tauri::command]
fn cmd_enable_anomaly_scoring(
    state: State<Arc<AppState>>,
    weights: Option<ScoringWeights>,
) -> Result<(), String> {
    with_current_graph_mut(state.as_ref(), |graph| {
        let w = weights.unwrap_or_default();
        graph.enable_anomaly_scoring(w);
        Ok(())
    })
}

/// Update anomaly scoring weights without re-finalizing observations.
#[tauri::command]
fn cmd_update_anomaly_weights(
    state: State<Arc<AppState>>,
    weights: ScoringWeights,
) -> Result<(), String> {
    with_current_graph_mut(state.as_ref(), |graph| {
        if let Some(ref mut scorer) = graph.anomaly_scorer {
            scorer.set_weights(weights);
            Ok(())
        } else {
            Err("Anomaly scoring is not enabled".to_string())
        }
    })
}

/// Get current anomaly scoring configuration (None if not enabled).
#[tauri::command]
fn cmd_get_anomaly_config(
    state: State<Arc<AppState>>,
) -> Result<Option<ScoringWeights>, String> {
    with_current_graph(state.as_ref(), |graph| {
        Ok(graph.anomaly_scorer.as_ref().map(|s| s.weights().clone()))
    })
}

/// Load a GNN ONNX model for ML-based threat scoring.
/// The model file must be a valid ONNX exported from GraphOS-APT.
#[tauri::command]
fn cmd_load_gnn_model(
    state: State<Arc<AppState>>,
    model_path: String,
) -> Result<String, String> {
    match graph_hunter_core::NpuScorer::load(&model_path) {
        Ok(scorer) => {
            *state.npu_scorer.write().map_err(|e| e.to_string())? = Some(scorer);
            Ok("GNN model loaded successfully".to_string())
        }
        Err(e) => Err(format!("Failed to load GNN model: {}", e)),
    }
}

/// Compute GNN threat scores for all entities in the current graph.
/// Requires: anomaly scoring enabled + GNN model loaded.
/// Returns the number of entities scored.
#[tauri::command]
fn cmd_compute_gnn_scores(
    state: State<Arc<AppState>>,
    k_hops: Option<usize>,
) -> Result<usize, String> {
    let hops = k_hops.unwrap_or(2);

    // Get graph access and scorer access separately to avoid lock ordering issues
    let current_id = state
        .current_session_id
        .read()
        .map_err(|e| format!("Lock poisoned: {}", e))?
        .clone();
    let id = current_id.as_ref().ok_or("No session selected")?.clone();

    let sessions = state
        .sessions
        .read()
        .map_err(|e| format!("Lock poisoned: {}", e))?;
    let session = sessions.get(&id).ok_or("Session not found")?.clone();

    let mut graph = session
        .graph
        .write()
        .map_err(|e| format!("Lock poisoned: {}", e))?;

    if graph.anomaly_scorer.is_none() {
        return Err("Anomaly scoring must be enabled first".to_string());
    }

    let mut npu_guard = state.npu_scorer.write().map_err(|e| e.to_string())?;
    let npu = npu_guard
        .as_mut()
        .ok_or("GNN model not loaded. Call cmd_load_gnn_model first.")?;

    Ok(graph.compute_gnn_scores(npu, hops))
}

/// Check if a GNN model is currently loaded.
#[tauri::command]
fn cmd_gnn_model_status(
    state: State<Arc<AppState>>,
) -> Result<bool, String> {
    let guard = state.npu_scorer.read().map_err(|e| e.to_string())?;
    Ok(guard.is_some())
}

/// Entry point for the Tauri application.
#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    let api_token = std::env::var("GRAPHHUNTER_API_TOKEN")
        .unwrap_or_else(|_| Uuid::new_v4().to_string());
    eprintln!("GRAPHHUNTER_API_TOKEN={}", api_token);
    let _ = std::io::Write::flush(&mut std::io::stderr());
    let app_state = Arc::new(AppState {
        sessions: RwLock::new(HashMap::new()),
        current_session_id: RwLock::new(None),
        cached_hunt_paths: RwLock::new(Vec::new()),
        app_handle: RwLock::new(None),
        last_mcp_subgraph: RwLock::new(None),
        ai_config: RwLock::new(None),
        ai_conversation: RwLock::new(ai::AiConversation::new()),
        api_token,
        npu_scorer: RwLock::new(None),
    });
    let http_port = std::env::var("GRAPHHUNTER_API_PORT")
        .ok()
        .and_then(|s| s.parse::<u16>().ok())
        .unwrap_or(37891);
    let state_for_http = Arc::clone(&app_state);
    tauri::Builder::default()
        .plugin(tauri_plugin_dialog::init())
        .manage(app_state)
        .setup(move |app| {
            if let Some(state) = app.try_state::<Arc<AppState>>() {
                if let Ok(mut h) = state.app_handle.write() {
                    *h = Some(app.handle().clone());
                }
            }
            eprintln!("GraphHunter HTTP API starting on Tauri async runtime (port {})", http_port);
            let _ = std::io::Write::flush(&mut std::io::stderr());
            tauri::async_runtime::spawn(async move {
                if let Err(e) = http_api::run_async(state_for_http, http_port).await {
                    eprintln!("GraphHunter HTTP API error: {}", e);
                } else {
                    eprintln!("GraphHunter HTTP API exited (serve returned)");
                }
            });
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            cmd_create_session,
            cmd_list_sessions,
            cmd_load_session,
            cmd_save_session,
            cmd_delete_session,
            cmd_get_current_session,
            cmd_get_entity_types_in_graph,
            cmd_get_entity_types_for_node_neighbours,
            cmd_get_entity_type_counts,
            cmd_get_entities_by_type,
            cmd_get_entities_by_type_paginated,
            cmd_get_node_ids_by_relation_type,
            cmd_get_events_for_node,
            cmd_get_path_nodes,
            cmd_add_path_node,
            cmd_remove_path_node,
            cmd_get_notes,
            cmd_create_note,
            cmd_update_note,
            cmd_delete_note,
            cmd_preview_ingest,
            cmd_load_data,
            cmd_list_datasets,
            cmd_remove_dataset,
            cmd_rename_type_in_dataset,
            cmd_dataset_entity_types,
            cmd_preview_fields,
            cmd_load_data_with_config,
            cmd_ingest_siem,
            cmd_get_graph_stats,
            cmd_run_hunt,
            cmd_get_hunt_page,
            cmd_get_subgraph,
            cmd_search_entities,
            cmd_expand_node,
            cmd_get_node_details,
            cmd_get_graph_summary,
            cmd_compute_scores,
            cmd_parse_dsl,
            cmd_get_catalog,
            cmd_load_catalog_hypothesis,
            cmd_ai_check_config,
            cmd_ai_set_key,
            cmd_ai_set_provider,
            cmd_ai_propose_hypothesis,
            cmd_ai_analyze_graph,
            cmd_ai_analyze_graph_conversation,
            cmd_ai_chat,
            cmd_ai_clear_conversation,
            cmd_ai_get_conversation,
            cmd_load_data_streaming,
            cmd_get_temporal_heatmap,
            cmd_get_timeline_data,
            cmd_compute_betweenness,
            cmd_compute_pagerank,
            cmd_compute_composite_scores,
            cmd_compact,
            cmd_test_http_api,
            cmd_enable_anomaly_scoring,
            cmd_update_anomaly_weights,
            cmd_get_anomaly_config,
            cmd_load_gnn_model,
            cmd_compute_gnn_scores,
            cmd_gnn_model_status,
        ])
        .run(tauri::generate_context!())
        .expect("error while running Graph Hunter");
}
