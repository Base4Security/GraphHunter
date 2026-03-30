use std::sync::Arc;

use tauri::State;

use crate::error::CommandError;
use crate::helpers::parse_entity_type;
use crate::state::{AppState, DatasetInfo};

/// Returns list of ingested datasets for the current session.
#[tauri::command]
pub fn cmd_list_datasets(state: State<Arc<AppState>>) -> Result<Vec<DatasetInfo>, CommandError> {
    let session_id = state
        .current_session_id
        .read()
        .map_err(|e| CommandError::GraphLocked(format!("Lock poisoned: {}", e)))?
        .clone()
        .ok_or_else(|| CommandError::SessionNotFound("No current session".into()))?;
    let sessions = state
        .sessions
        .read()
        .map_err(|e| CommandError::GraphLocked(format!("Lock poisoned: {}", e)))?;
    let session = sessions.get(&session_id).ok_or_else(|| CommandError::SessionNotFound("Session not found".into()))?;
    let datasets = session
        .datasets
        .read()
        .map_err(|e| CommandError::GraphLocked(format!("Lock poisoned: {}", e)))?;
    Ok(datasets.clone())
}

/// Removes a dataset from the current session.
#[tauri::command]
pub fn cmd_remove_dataset(state: State<Arc<AppState>>, dataset_id: String) -> Result<(usize, usize), CommandError> {
    let session_id = state
        .current_session_id
        .read()
        .map_err(|e| CommandError::GraphLocked(format!("Lock poisoned: {}", e)))?
        .clone()
        .ok_or_else(|| CommandError::SessionNotFound("No current session".into()))?;

    let session = {
        let sessions = state
            .sessions
            .read()
            .map_err(|e| CommandError::GraphLocked(format!("Lock poisoned: {}", e)))?;
        Arc::clone(sessions.get(&session_id).ok_or_else(|| CommandError::SessionNotFound("Session not found".into()))?)
    };

    // Collect entity IDs that belong to this dataset (for path/notes cleanup).
    let removed_entity_ids: Vec<String> = {
        let graph = session
            .graph
            .read()
            .map_err(|e| CommandError::GraphLocked(format!("Lock poisoned: {}", e)))?;
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
            .map_err(|e| CommandError::GraphLocked(format!("Lock poisoned: {}", e)))?;
        graph.remove_entities_and_relations_by_dataset(&dataset_id)
            .map_err(|e| e.to_string())?
    };

    // 2. Clean path nodes and unlink notes that reference removed entities.
    {
        let mut path_node_ids = session
            .path_node_ids
            .write()
            .map_err(|e| CommandError::GraphLocked(format!("Lock poisoned: {}", e)))?;
        path_node_ids.retain(|id| !removed_set.contains(id.as_str()));
    }
    {
        let mut notes = session
            .notes
            .write()
            .map_err(|e| CommandError::GraphLocked(format!("Lock poisoned: {}", e)))?;
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
        .map_err(|e| CommandError::GraphLocked(format!("Lock poisoned: {}", e)))?
        .retain(|d| d.id != dataset_id);

    Ok((entities_removed, relations_removed))
}

/// For the given dataset, renames all entities of type from_type to to_type.
#[tauri::command]
pub fn cmd_rename_type_in_dataset(
    state: State<Arc<AppState>>,
    dataset_id: String,
    from_type: String,
    to_type: String,
) -> Result<usize, CommandError> {
    let from_et = parse_entity_type(&from_type)
        .ok_or_else(|| CommandError::InvalidInput(format!("Invalid entity type: {}", from_type)))?;
    let to_et = parse_entity_type(&to_type)
        .ok_or_else(|| CommandError::InvalidInput(format!("Invalid entity type: {}", to_type)))?;

    let session_id = state
        .current_session_id
        .read()
        .map_err(|e| CommandError::GraphLocked(format!("Lock poisoned: {}", e)))?
        .clone()
        .ok_or_else(|| CommandError::SessionNotFound("No current session".into()))?;

    let session = {
        let sessions = state
            .sessions
            .read()
            .map_err(|e| CommandError::GraphLocked(format!("Lock poisoned: {}", e)))?;
        Arc::clone(sessions.get(&session_id).ok_or_else(|| CommandError::SessionNotFound("Session not found".into()))?)
    };

    let count = {
        let mut graph = session
            .graph
            .write()
            .map_err(|e| CommandError::GraphLocked(format!("Lock poisoned: {}", e)))?;
        graph.rename_entity_type_in_dataset(&dataset_id, from_et, to_et)
    };

    Ok(count)
}

/// Returns entity type names that have at least one entity in the given dataset.
#[tauri::command]
pub fn cmd_dataset_entity_types(
    state: State<Arc<AppState>>,
    dataset_id: String,
) -> Result<Vec<String>, CommandError> {
    let session_id = state
        .current_session_id
        .read()
        .map_err(|e| CommandError::GraphLocked(format!("Lock poisoned: {}", e)))?
        .clone()
        .ok_or_else(|| CommandError::SessionNotFound("No current session".into()))?;

    let sessions = state
        .sessions
        .read()
        .map_err(|e| CommandError::GraphLocked(format!("Lock poisoned: {}", e)))?;
    let session = sessions.get(&session_id).ok_or_else(|| CommandError::SessionNotFound("Session not found".into()))?;

    let graph = session
        .graph
        .read()
        .map_err(|e| CommandError::GraphLocked(format!("Lock poisoned: {}", e)))?;

    Ok(graph.entity_types_in_dataset(&dataset_id))
}
