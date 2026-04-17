//! DTOs for entity, path-node, note, and tag operations.
//!
//! All session-scoped requests carry a `session: Option<SessionHandle>`
//! that resolves against the current session when omitted.

use crate::state::{EntityTag, Note, SessionHandle};
use serde::{Deserialize, Serialize};

// ── Scoping ─────────────────────────────────────────────────────────────

/// Minimal request shape for session-scoped operations that take no
/// further arguments.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct SessionOnly {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session: Option<SessionHandle>,
}

// ── Entity / schema reads ───────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodeScopedRequest {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session: Option<SessionHandle>,
    pub node_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EntitiesByTypeRequest {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session: Option<SessionHandle>,
    pub type_name: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PaginatedEntitiesByTypeRequest {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session: Option<SessionHandle>,
    pub type_name: String,
    pub offset: usize,
    pub limit: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodeIdsByRelationRequest {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session: Option<SessionHandle>,
    pub relation_type: String,
}

/// Mirrors `app/src-tauri/src/types.rs::EntityTypeCount`. Ownership
/// shifts here so the canonical API returns it directly.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EntityTypeCount {
    pub entity_type: String,
    pub count: usize,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PaginatedEntities {
    pub entities: Vec<String>,
    pub total_count: usize,
}

// ── Path nodes ──────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PathNodeMutateRequest {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session: Option<SessionHandle>,
    pub node_id: String,
}

// ── Notes ───────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateNoteRequest {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session: Option<SessionHandle>,
    pub content: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub node_id: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpdateNoteRequest {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session: Option<SessionHandle>,
    pub note_id: String,
    pub content: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeleteNoteRequest {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session: Option<SessionHandle>,
    pub note_id: String,
}

/// Response from `create_note`: the created note plus an absolute URL
/// pointing to the HTTP `/notes/:id` endpoint for external workflows to
/// reference.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CreatedNote {
    #[serde(flatten)]
    pub note: Note,
    pub url: String,
}

// ── Tags ────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TagEntityRequest {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session: Option<SessionHandle>,
    pub node_id: String,
    pub tag: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UntagEntityRequest {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session: Option<SessionHandle>,
    pub node_id: String,
    pub tag: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ListTaggedRequest {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session: Option<SessionHandle>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tag_prefix: Option<String>,
}

// ── Response aliases ────────────────────────────────────────────────────

pub type NotesResponse = Vec<Note>;
pub type TagsResponse = Vec<EntityTag>;
