use graph_hunter_core::{EntityType, GraphHunter, NeighborhoodFilter};
use uuid::Uuid;

use crate::error::CommandError;
use crate::state::{AppState, Note, SessionState};
use crate::types::ExpandFilter;

/// Extract a JSON string value from a partial JSON prefix (e.g. first 4KB).
pub fn extract_json_string(text: &str, key: &str) -> Option<String> {
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
pub fn extract_json_i64(text: &str, key: &str) -> Option<i64> {
    let pattern = format!("\"{}\"", key);
    let idx = text.find(&pattern)?;
    let after_key = &text[idx + pattern.len()..];
    let colon = after_key.find(':')?;
    let after_colon = after_key[colon + 1..].trim_start();
    let end = after_colon.find(|c: char| !c.is_ascii_digit() && c != '-')?;
    after_colon[..end].parse().ok()
}

/// Extracts JSON object keys from the first record (array[0] or first NDJSON line or single object).
pub fn extract_json_keys(contents: &str) -> Vec<String> {
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

/// Extracts CSV header names (first line, simple split by comma).
pub fn extract_csv_headers(contents: &str) -> Vec<String> {
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

/// Converts a string like "IP", "Host", etc. to EntityType. Unknown non-empty strings become Other(name).
pub fn parse_entity_type(s: &str) -> Option<EntityType> {
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
pub fn parse_relation_type(s: &str) -> Option<graph_hunter_core::RelationType> {
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
pub fn to_core_filter(f: &ExpandFilter) -> NeighborhoodFilter {
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

/// Helper: run a closure with the current session (no graph lock).
pub fn with_current_session<T, F>(state: &AppState, f: F) -> Result<T, CommandError>
where
    F: FnOnce(&SessionState) -> Result<T, CommandError>,
{
    let current_id = state
        .current_session_id
        .read()
        .map_err(|e| CommandError::GraphLocked(format!("Lock poisoned: {}", e)))?
        .clone();
    let id = current_id.as_ref().ok_or_else(|| CommandError::SessionNotFound("No session selected".into()))?;
    let sessions = state
        .sessions
        .read()
        .map_err(|e| CommandError::GraphLocked(format!("Lock poisoned: {}", e)))?;
    let session = sessions.get(id).ok_or_else(|| CommandError::SessionNotFound("Session not found".into()))?;
    f(session)
}

/// Helper: run a closure with the current session and its graph (both read).
pub fn with_current_session_and_graph<T, F>(state: &AppState, f: F) -> Result<T, CommandError>
where
    F: FnOnce(&SessionState, &GraphHunter) -> Result<T, CommandError>,
{
    let current_id = state
        .current_session_id
        .read()
        .map_err(|e| CommandError::GraphLocked(format!("Lock poisoned: {}", e)))?
        .clone();
    let id = current_id.as_ref().ok_or_else(|| CommandError::SessionNotFound("No session selected".into()))?;
    let sessions = state
        .sessions
        .read()
        .map_err(|e| CommandError::GraphLocked(format!("Lock poisoned: {}", e)))?;
    let session = sessions.get(id).ok_or_else(|| CommandError::SessionNotFound("Session not found".into()))?;
    let graph = session
        .graph
        .read()
        .map_err(|e| CommandError::GraphLocked(format!("Lock poisoned: {}", e)))?;
    f(session, &graph)
}

/// Helper: run a closure with a read guard on the current session's graph.
pub fn with_current_graph<T, F>(state: &AppState, f: F) -> Result<T, CommandError>
where
    F: FnOnce(&GraphHunter) -> Result<T, CommandError>,
{
    with_current_session_and_graph(state, |_, graph| f(graph))
}

/// Helper: run a closure with a write guard on the current session's graph.
pub fn with_current_graph_mut<T, F>(state: &AppState, f: F) -> Result<T, CommandError>
where
    F: FnOnce(&mut GraphHunter) -> Result<T, CommandError>,
{
    let current_id = state
        .current_session_id
        .read()
        .map_err(|e| CommandError::GraphLocked(format!("Lock poisoned: {}", e)))?
        .clone();
    let id = current_id.as_ref().ok_or_else(|| CommandError::SessionNotFound("No session selected".into()))?;
    let sessions = state
        .sessions
        .read()
        .map_err(|e| CommandError::GraphLocked(format!("Lock poisoned: {}", e)))?;
    let session = sessions.get(id).ok_or_else(|| CommandError::SessionNotFound("Session not found".into()))?;
    let mut graph = session
        .graph
        .write()
        .map_err(|e| CommandError::GraphLocked(format!("Lock poisoned: {}", e)))?;
    f(&mut graph)
}

/// Shared implementation for creating a note in the current session (used by Tauri command and HTTP API).
pub fn create_note_impl(
    state: &AppState,
    content: String,
    node_id: Option<String>,
) -> Result<Note, CommandError> {
    let current_id = state
        .current_session_id
        .read()
        .map_err(|e| CommandError::GraphLocked(format!("Lock poisoned: {}", e)))?
        .clone();
    let id = current_id.as_ref().ok_or_else(|| CommandError::SessionNotFound("No session selected".into()))?;
    let sessions = state
        .sessions
        .read()
        .map_err(|e| CommandError::GraphLocked(format!("Lock poisoned: {}", e)))?;
    let session = sessions.get(id).ok_or_else(|| CommandError::SessionNotFound("Session not found".into()))?;
    let created_at = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|e| CommandError::Internal(e.to_string()))?
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
        .map_err(|e| CommandError::GraphLocked(format!("Lock poisoned: {}", e)))?;
    notes.push(note.clone());
    Ok(note)
}
