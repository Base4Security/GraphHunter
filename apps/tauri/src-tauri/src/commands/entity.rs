//! Entity / path-node / note / tag commands.
//!
//! All 18 commands delegate to the canonical [`graph_hunter_api`]. Each
//! Tauri command is a one-liner adapter: construct the request DTO from
//! positional params and return the API's response. The command layer
//! contains no business logic.

use std::sync::Arc;

use tauri::State;

use graph_hunter_api::dto::entity::{
    CreateNoteRequest, CreatedNote, DeleteNoteRequest, EntitiesByTypeRequest, EntityTypeCount,
    ListTaggedRequest, NodeIdsByRelationRequest, NodeScopedRequest, PaginatedEntities,
    PaginatedEntitiesByTypeRequest, PathNodeMutateRequest, SessionOnly, TagEntityRequest,
    UntagEntityRequest, UpdateNoteRequest,
};
use graph_hunter_api::GraphHunterApi;
use graph_hunter_core::{ExplainedScore, RelSchemaEntry};

use crate::error::CommandError;
use crate::state::{EntityTag, Note};

// ── Graph reads ──────────────────────────────────────────────────────────

#[tauri::command]
pub fn cmd_get_entity_types_in_graph(
    api: State<Arc<GraphHunterApi>>,
) -> Result<Vec<String>, CommandError> {
    api.get_entity_types_in_graph(SessionOnly::default())
        .map_err(CommandError::from)
}

/// Get the relation schema: distinct (rel_type, source_type, target_type)
/// triples observed in the graph with edge counts and metadata key union.
/// Call this immediately after `cmd_get_graph_summary` when authoring a
/// hunt — it tells you the allowed edge directions and the metadata keys
/// available for filtering, which otherwise have to be discovered through
/// failed `cmd_run_hunt` calls.
#[tauri::command]
pub fn cmd_get_relation_schema(
    api: State<Arc<GraphHunterApi>>,
) -> Result<Vec<RelSchemaEntry>, CommandError> {
    api.get_relation_schema(SessionOnly::default())
        .map_err(CommandError::from)
}

/// Explain why a node has the score it has: four-dimension breakdown,
/// composite + degree percentiles, and peers of the same entity type.
#[tauri::command]
pub fn cmd_explain_score(
    api: State<Arc<GraphHunterApi>>,
    node_id: String,
) -> Result<ExplainedScore, CommandError> {
    api.explain_score(NodeScopedRequest {
        session: None,
        node_id,
    })
    .map_err(CommandError::from)
}

#[tauri::command]
pub fn cmd_get_entity_types_for_node_neighbours(
    api: State<Arc<GraphHunterApi>>,
    node_id: String,
) -> Result<Vec<String>, CommandError> {
    api.get_entity_types_for_node_neighbours(NodeScopedRequest {
        session: None,
        node_id,
    })
    .map_err(CommandError::from)
}

#[tauri::command]
pub fn cmd_get_entity_type_counts(
    api: State<Arc<GraphHunterApi>>,
) -> Result<Vec<EntityTypeCount>, CommandError> {
    api.get_entity_type_counts(SessionOnly::default())
        .map_err(CommandError::from)
}

#[tauri::command]
pub fn cmd_get_entities_by_type(
    api: State<Arc<GraphHunterApi>>,
    type_name: String,
) -> Result<Vec<String>, CommandError> {
    api.get_entities_by_type(EntitiesByTypeRequest {
        session: None,
        type_name,
    })
    .map_err(CommandError::from)
}

#[tauri::command]
pub fn cmd_get_entities_by_type_paginated(
    api: State<Arc<GraphHunterApi>>,
    type_name: String,
    offset: usize,
    limit: usize,
) -> Result<PaginatedEntities, CommandError> {
    api.get_entities_by_type_paginated(PaginatedEntitiesByTypeRequest {
        session: None,
        type_name,
        offset,
        limit,
    })
    .map_err(CommandError::from)
}

#[tauri::command]
pub fn cmd_get_node_ids_by_relation_type(
    api: State<Arc<GraphHunterApi>>,
    relation_type: String,
) -> Result<Vec<String>, CommandError> {
    api.get_node_ids_by_relation_type(NodeIdsByRelationRequest {
        session: None,
        relation_type,
    })
    .map_err(CommandError::from)
}

// ── Path nodes ───────────────────────────────────────────────────────────

#[tauri::command]
pub fn cmd_get_path_nodes(
    api: State<Arc<GraphHunterApi>>,
) -> Result<Vec<String>, CommandError> {
    api.get_path_nodes(SessionOnly::default())
        .map_err(CommandError::from)
}

#[tauri::command]
pub fn cmd_add_path_node(
    api: State<Arc<GraphHunterApi>>,
    node_id: String,
) -> Result<(), CommandError> {
    api.add_path_node(PathNodeMutateRequest {
        session: None,
        node_id,
    })
    .map_err(CommandError::from)
}

#[tauri::command]
pub fn cmd_remove_path_node(
    api: State<Arc<GraphHunterApi>>,
    node_id: String,
) -> Result<(), CommandError> {
    api.remove_path_node(PathNodeMutateRequest {
        session: None,
        node_id,
    })
    .map_err(CommandError::from)
}

// ── Notes ────────────────────────────────────────────────────────────────

#[tauri::command]
pub fn cmd_get_notes(api: State<Arc<GraphHunterApi>>) -> Result<Vec<Note>, CommandError> {
    api.get_notes(SessionOnly::default())
        .map_err(CommandError::from)
}

/// Create a note (optionally linked to a node). Returns the created note
/// and an `url` pointing to the HTTP `/notes/:id` endpoint so external
/// ticketing systems can reference it directly.
#[tauri::command]
pub fn cmd_create_note(
    api: State<Arc<GraphHunterApi>>,
    content: String,
    node_id: Option<String>,
) -> Result<CreatedNote, CommandError> {
    api.create_note(CreateNoteRequest {
        session: None,
        content,
        node_id,
    })
    .map_err(CommandError::from)
}

#[tauri::command]
pub fn cmd_update_note(
    api: State<Arc<GraphHunterApi>>,
    note_id: String,
    content: String,
) -> Result<(), CommandError> {
    api.update_note(UpdateNoteRequest {
        session: None,
        note_id,
        content,
    })
    .map_err(CommandError::from)
}

#[tauri::command]
pub fn cmd_delete_note(
    api: State<Arc<GraphHunterApi>>,
    note_id: String,
) -> Result<(), CommandError> {
    api.delete_note(DeleteNoteRequest {
        session: None,
        note_id,
    })
    .map_err(CommandError::from)
}

// ── Tags ─────────────────────────────────────────────────────────────────

/// Tag an entity with a label (e.g. `ioc:malicious`, `benign:confirmed`).
/// Multiple tags per node are supported; repeating the same
/// `(node_id, tag)` pair updates the reason in place — not a duplicate.
#[tauri::command]
pub fn cmd_tag_entity(
    api: State<Arc<GraphHunterApi>>,
    node_id: String,
    tag: String,
    reason: Option<String>,
) -> Result<EntityTag, CommandError> {
    api.tag_entity(TagEntityRequest {
        session: None,
        node_id,
        tag,
        reason,
    })
    .map_err(CommandError::from)
}

/// Returns the number of (node_id, tag) rows that were actually
/// removed — `0` means the pair was never tagged. Replaces the v1
/// `()` return that hid misspelled IDs.
#[tauri::command]
pub fn cmd_untag_entity(
    api: State<Arc<GraphHunterApi>>,
    node_id: String,
    tag: String,
) -> Result<usize, CommandError> {
    api.untag_entity(UntagEntityRequest {
        session: None,
        node_id,
        tag,
    })
    .map_err(CommandError::from)
}

#[tauri::command]
pub fn cmd_list_tagged(
    api: State<Arc<GraphHunterApi>>,
    tag_prefix: Option<String>,
) -> Result<Vec<EntityTag>, CommandError> {
    api.list_tagged(ListTaggedRequest {
        session: None,
        tag_prefix,
    })
    .map_err(CommandError::from)
}
