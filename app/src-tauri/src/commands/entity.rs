use std::collections::HashSet;
use std::sync::Arc;

use tauri::State;

use crate::helpers::{
    create_note_impl, parse_entity_type, parse_relation_type,
    with_current_graph,
};
use crate::state::{AppState, Note};
use crate::types::EntityTypeCount;
use crate::types::PaginatedEntities;

/// Get entity type names that exist in the current session's graph.
#[tauri::command]
pub fn cmd_get_entity_types_in_graph(state: State<Arc<AppState>>) -> Result<Vec<String>, String> {
    with_current_graph(state.as_ref(), |graph| Ok(graph.entity_types_in_graph()))
}

/// Get entity type names that are neighbours of the given node.
#[tauri::command]
pub fn cmd_get_entity_types_for_node_neighbours(
    state: State<Arc<AppState>>,
    node_id: String,
) -> Result<Vec<String>, String> {
    with_current_graph(state.as_ref(), |graph| Ok(graph.entity_types_of_neighbours(&node_id)))
}

/// Get (entity_type, count) for each type present in the graph.
#[tauri::command]
pub fn cmd_get_entity_type_counts(state: State<Arc<AppState>>) -> Result<Vec<EntityTypeCount>, String> {
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
pub fn cmd_get_entities_by_type(
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

/// Get entity IDs of a given type with pagination (offset + limit).
#[tauri::command]
pub fn cmd_get_entities_by_type_paginated(
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

/// Get all node IDs that participate in at least one relation of the given type.
#[tauri::command]
pub fn cmd_get_node_ids_by_relation_type(
    state: State<Arc<AppState>>,
    relation_type: String,
) -> Result<Vec<String>, String> {
    with_current_graph(state.as_ref(), |graph| {
        let rt = parse_relation_type(&relation_type)
            .ok_or_else(|| format!("Unknown relation type: {}", relation_type))?;
        let mut node_ids = HashSet::new();
        for compact in graph.edge_store.iter_all() {
            if compact.rel_type() == rt {
                node_ids.insert(graph.interner.resolve(compact.source_sid).to_string());
                node_ids.insert(graph.interner.resolve(compact.dest_sid).to_string());
            }
        }
        Ok(node_ids.into_iter().collect())
    })
}

/// Get path node IDs (pinned nodes) for the current session.
#[tauri::command]
pub fn cmd_get_path_nodes(state: State<Arc<AppState>>) -> Result<Vec<String>, String> {
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
pub fn cmd_add_path_node(state: State<Arc<AppState>>, node_id: String) -> Result<(), String> {
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
pub fn cmd_remove_path_node(state: State<Arc<AppState>>, node_id: String) -> Result<(), String> {
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
pub fn cmd_get_notes(state: State<Arc<AppState>>) -> Result<Vec<Note>, String> {
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

/// Create a note (optionally linked to a node). Returns the created note.
#[tauri::command]
pub fn cmd_create_note(
    state: State<Arc<AppState>>,
    content: String,
    node_id: Option<String>,
) -> Result<Note, String> {
    create_note_impl(state.as_ref(), content, node_id)
}

/// Update a note's content by id.
#[tauri::command]
pub fn cmd_update_note(state: State<Arc<AppState>>, note_id: String, content: String) -> Result<(), String> {
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
pub fn cmd_delete_note(state: State<Arc<AppState>>, note_id: String) -> Result<(), String> {
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
