use std::collections::HashSet;
use std::fs;
use std::sync::{Arc, RwLock};

use graph_hunter_core::GraphHunter;
use tauri::{AppHandle, Emitter, State};
use uuid::Uuid;

use crate::error::CommandError;
use crate::helpers::{extract_json_i64, extract_json_string};
use crate::state::{
    AppState, SessionFile, SessionState,
    session_data_dir, session_file_path,
};
use crate::types::SessionInfo;

/// Computes a sensible "emit every N items" stride so we send at most ~100
/// progress events for any payload size (and never less than every 1000
/// items, so small loads still feel responsive instead of jumping 0→100%).
#[inline]
fn progress_stride(total: usize) -> usize {
    let pct1 = total / 100;
    if pct1 > 1000 { pct1 } else { 1000 }
}

/// Emits a session-load progress event. Failures are ignored — progress is
/// best-effort and must not abort the load.
fn emit_load_progress(app: &AppHandle, phase: &str, current: usize, total: usize) {
    let _ = app.emit(
        "session-load-progress",
        serde_json::json!({
            "phase": phase,
            "current": current,
            "total": total,
        }),
    );
}

/// Emits a session-save progress event. See `emit_load_progress`.
fn emit_save_progress(app: &AppHandle, phase: &str, current: usize, total: usize) {
    let _ = app.emit(
        "session-save-progress",
        serde_json::json!({
            "phase": phase,
            "current": current,
            "total": total,
        }),
    );
}

/// Create a new empty session and set it as current.
#[tauri::command]
pub fn cmd_create_session(state: State<Arc<AppState>>, name: Option<String>) -> Result<SessionInfo, CommandError> {
    let id = Uuid::new_v4().to_string();
    let name = name.unwrap_or_else(|| "Untitled".to_string());
    let created_at = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|e| CommandError::Internal(e.to_string()))?
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
            .map_err(|e| CommandError::GraphLocked(format!("Lock poisoned: {}", e)))?;
        sessions.insert(id.clone(), session);
    }
    {
        let mut current = state
            .current_session_id
            .write()
            .map_err(|e| CommandError::GraphLocked(format!("Lock poisoned: {}", e)))?;
        *current = Some(id.clone());
    }
    {
        let mut cache = state
            .cached_hunt_paths
            .write()
            .map_err(|e| CommandError::GraphLocked(format!("Lock poisoned: {}", e)))?;
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
pub fn cmd_list_sessions(state: State<Arc<AppState>>) -> Result<Vec<SessionInfo>, CommandError> {
    let sessions = state
        .sessions
        .read()
        .map_err(|e| CommandError::GraphLocked(format!("Lock poisoned: {}", e)))?;
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
    if let Ok(dir) = session_data_dir() {
        if let Ok(entries) = fs::read_dir(&dir) {
            for entry in entries.flatten() {
                let path = entry.path();
                if path.extension().and_then(|e| e.to_str()) == Some("json") {
                    if let Ok(file) = fs::File::open(&path) {
                        use std::io::Read;
                        let mut buf = vec![0u8; 4096];
                        let mut reader = std::io::BufReader::new(file);
                        let n = reader.read(&mut buf).unwrap_or(0);
                        let prefix = String::from_utf8_lossy(&buf[..n]);
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
///
/// Async wrapper: the heavy work — file I/O, JSON parsing, graph rebuild —
/// runs on a `spawn_blocking` worker so the Tauri IPC thread (and therefore
/// the WebView UI) stays responsive. Big sessions used to freeze Windows
/// and trigger "Not Responding" because the sync version blocked the
/// runtime for the entire `serde_json::from_reader` + `add_entity` loop.
///
/// Emits `session-load-progress` events with `{ phase, current, total }`
/// throughout the load so the frontend can show a progress bar. Phases:
/// `reading` (file open) → `parsing` (serde_json) → `entities` (add loop)
/// → `relations` (add loop) → `sorting` (sort_edges) → `done`.
#[tauri::command]
pub async fn cmd_load_session(
    state: State<'_, Arc<AppState>>,
    app: AppHandle,
    session_id: String,
) -> Result<SessionInfo, CommandError> {
    let app_state: Arc<AppState> = (*state).clone();
    tauri::async_runtime::spawn_blocking(move || load_session_blocking(&app_state, &app, session_id))
        .await
        .map_err(|e| CommandError::Internal(format!("spawn_blocking join error: {}", e)))?
}

fn load_session_blocking(
    state: &Arc<AppState>,
    app: &AppHandle,
    session_id: String,
) -> Result<SessionInfo, CommandError> {
    let dir = session_data_dir().map_err(|e| CommandError::IoError(e))?;
    let path = dir.join(format!("{}.json", session_id));

    let mut sessions = state
        .sessions
        .write()
        .map_err(|e| CommandError::GraphLocked(format!("Lock poisoned: {}", e)))?;

    if !sessions.contains_key(&session_id) && path.exists() {
        emit_load_progress(app, "reading", 0, 0);
        let file_handle = fs::File::open(&path)
            .map_err(|e| CommandError::IoError(format!("Failed to open session file: {}", e)))?;
        let reader = std::io::BufReader::with_capacity(8 * 1024 * 1024, file_handle);

        emit_load_progress(app, "parsing", 0, 0);
        let file: SessionFile = serde_json::from_reader(reader)
            .map_err(|e| CommandError::ParseError(format!("Invalid session file: {}", e)))?;

        let mut graph = GraphHunter::new();
        let entity_count = file.entities.len();
        let relation_count = file.relations.len();
        graph.reserve(entity_count, relation_count);

        // Entities phase: emit at most every `stride` inserts to keep the
        // event channel from being flooded on >100K-entity sessions.
        let entity_stride = progress_stride(entity_count);
        emit_load_progress(app, "entities", 0, entity_count);
        for (i, entity) in file.entities.into_iter().enumerate() {
            let _ = graph.add_entity(entity);
            if (i + 1) % entity_stride == 0 {
                emit_load_progress(app, "entities", i + 1, entity_count);
            }
        }
        emit_load_progress(app, "entities", entity_count, entity_count);

        let relation_stride = progress_stride(relation_count);
        emit_load_progress(app, "relations", 0, relation_count);
        for (i, relation) in file.relations.into_iter().enumerate() {
            let _ = graph.add_relation(relation);
            if (i + 1) % relation_stride == 0 {
                emit_load_progress(app, "relations", i + 1, relation_count);
            }
        }
        emit_load_progress(app, "relations", relation_count, relation_count);

        emit_load_progress(app, "sorting", 0, 0);
        graph.sort_edges_by_timestamp()
            .map_err(|e| CommandError::Internal(e.to_string()))?;

        tracing::info!("SESSION LOAD: {} entities, {} relations loaded", entity_count, relation_count);

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
        .ok_or_else(|| CommandError::SessionNotFound(format!("Session '{}' not found", session_id)))?;

    {
        let mut current = state
            .current_session_id
            .write()
            .map_err(|e| CommandError::GraphLocked(format!("Lock poisoned: {}", e)))?;
        *current = Some(session_id.clone());
    }
    {
        let mut cache = state
            .cached_hunt_paths
            .write()
            .map_err(|e| CommandError::GraphLocked(format!("Lock poisoned: {}", e)))?;
        *cache = Vec::new();
    }

    emit_load_progress(app, "done", 1, 1);

    Ok(SessionInfo {
        id: session.id.clone(),
        name: session.name.clone(),
        created_at: session.created_at,
    })
}

/// Save current (or specified) session to disk.
///
/// Async wrapper: see the rationale on `cmd_load_session`. Save is just as
/// blocking — we iterate every entity + relation and stream them through
/// `serde_json::to_writer`, which can take seconds for large graphs.
///
/// Emits `session-save-progress` events with `{ phase, current, total }`.
/// Phases: `entities` (single big serde_json::to_writer call) →
/// `relations` (per-edge loop, throttled) → `done`.
#[tauri::command]
pub async fn cmd_save_session(
    state: State<'_, Arc<AppState>>,
    app: AppHandle,
    session_id: Option<String>,
) -> Result<(), CommandError> {
    let app_state: Arc<AppState> = (*state).clone();
    tauri::async_runtime::spawn_blocking(move || save_session_blocking(&app_state, &app, session_id))
        .await
        .map_err(|e| CommandError::Internal(format!("spawn_blocking join error: {}", e)))?
}

fn save_session_blocking(
    state: &Arc<AppState>,
    app: &AppHandle,
    session_id: Option<String>,
) -> Result<(), CommandError> {
    let id = session_id
        .or_else(|| {
            state
                .current_session_id
                .read()
                .ok()
                .and_then(|g| g.clone())
        })
        .ok_or_else(|| CommandError::SessionNotFound("No session to save".into()))?;

    let path = session_file_path(&id).map_err(|e| CommandError::IoError(e))?;

    let sessions = state
        .sessions
        .read()
        .map_err(|e| CommandError::GraphLocked(format!("Lock poisoned: {}", e)))?;
    let session = sessions.get(&id).ok_or_else(|| CommandError::SessionNotFound("Session not found".into()))?;

    let graph = session
        .graph
        .read()
        .map_err(|e| CommandError::GraphLocked(format!("Lock poisoned: {}", e)))?;
    let path_node_ids = session
        .path_node_ids
        .read()
        .map_err(|e| CommandError::GraphLocked(format!("Lock poisoned: {}", e)))?
        .clone();
    let notes = session
        .notes
        .read()
        .map_err(|e| CommandError::GraphLocked(format!("Lock poisoned: {}", e)))?
        .clone();
    let datasets = session
        .datasets
        .read()
        .map_err(|e| CommandError::GraphLocked(format!("Lock poisoned: {}", e)))?
        .clone();

    // Stream JSON directly to file
    let f = fs::File::create(&path).map_err(|e| CommandError::IoError(format!("Failed to create session file: {}", e)))?;
    let mut w = std::io::BufWriter::with_capacity(8 * 1024 * 1024, f);

    use std::io::Write;
    write!(w, "{{\"id\":{},\"name\":{},\"created_at\":{},\"entities\":",
        serde_json::to_string(&id).unwrap(),
        serde_json::to_string(&session.name).unwrap(),
        session.created_at,
    ).map_err(|e| CommandError::IoError(e.to_string()))?;

    let entity_count = graph.entities.len();
    let relation_count = graph.edge_store.len();

    // Entities phase: single big to_writer call. We can't progress mid-call,
    // so we just bracket it with a 0/total and total/total emit.
    emit_save_progress(app, "entities", 0, entity_count);
    let entities: Vec<_> = graph.entities.values().cloned().collect();
    serde_json::to_writer(&mut w, &entities).map_err(|e| CommandError::IoError(e.to_string()))?;
    emit_save_progress(app, "entities", entity_count, entity_count);

    write!(w, ",\"relations\":[").map_err(|e| CommandError::IoError(e.to_string()))?;
    let relation_stride = progress_stride(relation_count);
    emit_save_progress(app, "relations", 0, relation_count);
    let mut first = true;
    for (i, compact) in graph.edge_store.iter_all().enumerate() {
        if !first { write!(w, ",").map_err(|e| CommandError::IoError(e.to_string()))?; }
        first = false;
        let rel = graph.materialize_relation(compact);
        serde_json::to_writer(&mut w, &rel).map_err(|e| CommandError::IoError(e.to_string()))?;
        if (i + 1) % relation_stride == 0 {
            emit_save_progress(app, "relations", i + 1, relation_count);
        }
    }
    emit_save_progress(app, "relations", relation_count, relation_count);
    write!(w, "]").map_err(|e| CommandError::IoError(e.to_string()))?;

    write!(w, ",\"path_node_ids\":").map_err(|e| CommandError::IoError(e.to_string()))?;
    serde_json::to_writer(&mut w, &path_node_ids).map_err(|e| CommandError::IoError(e.to_string()))?;
    write!(w, ",\"notes\":").map_err(|e| CommandError::IoError(e.to_string()))?;
    serde_json::to_writer(&mut w, &notes).map_err(|e| CommandError::IoError(e.to_string()))?;
    write!(w, ",\"datasets\":").map_err(|e| CommandError::IoError(e.to_string()))?;
    serde_json::to_writer(&mut w, &datasets).map_err(|e| CommandError::IoError(e.to_string()))?;
    write!(w, "}}").map_err(|e| CommandError::IoError(e.to_string()))?;

    w.flush().map_err(|e| CommandError::IoError(e.to_string()))?;

    emit_save_progress(app, "done", 1, 1);
    Ok(())
}

/// Delete a session from memory and disk.
#[tauri::command]
pub fn cmd_delete_session(state: State<Arc<AppState>>, session_id: String) -> Result<(), CommandError> {
    {
        let mut sessions = state
            .sessions
            .write()
            .map_err(|e| CommandError::GraphLocked(format!("Lock poisoned: {}", e)))?;
        sessions.remove(&session_id);
    }
    if let Ok(path) = session_file_path(&session_id) {
        let _ = fs::remove_file(&path);
    }
    {
        let mut current = state
            .current_session_id
            .write()
            .map_err(|e| CommandError::GraphLocked(format!("Lock poisoned: {}", e)))?;
        if *current == Some(session_id.clone()) {
            *current = None;
        }
    }
    Ok(())
}

/// Get current session id, if any.
#[tauri::command]
pub fn cmd_get_current_session(state: State<Arc<AppState>>) -> Result<Option<SessionInfo>, CommandError> {
    let current_id = state
        .current_session_id
        .read()
        .map_err(|e| CommandError::GraphLocked(format!("Lock poisoned: {}", e)))?
        .clone();
    let id = match &current_id {
        Some(i) => i,
        None => return Ok(None),
    };
    let sessions = state
        .sessions
        .read()
        .map_err(|e| CommandError::GraphLocked(format!("Lock poisoned: {}", e)))?;
    let session = sessions.get(id);
    Ok(session.map(|s| SessionInfo {
        id: s.id.clone(),
        name: s.name.clone(),
        created_at: s.created_at,
    }))
}
