//! Per-session domain types (notes, tags, dataset info, on-disk format).
//!
//! These used to live in `app/src-tauri/src/state.rs`; P1 moves them here
//! so the canonical API owns the shapes. Tauri's `state.rs` re-exports
//! them via `pub use` so existing call sites keep compiling unchanged.

use graph_hunter_core::{Entity, Relation};
use serde::{Deserialize, Serialize};

/// A note: standalone or linked to a node.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Note {
    pub id: String,
    pub content: String,
    #[serde(default)]
    pub node_id: Option<String>,
    pub created_at: i64,
}

/// A tag applied to a node — typically an IoC marker (`ioc:malicious`,
/// `benign:confirmed`, etc.). Persisted with the session so the analyst's
/// IoC list survives a restart.
#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct EntityTag {
    pub node_id: String,
    pub tag: String,
    #[serde(default)]
    pub reason: Option<String>,
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

/// Serializable session file format for disk persistence. Holds the
/// flattened entity / relation lists plus the per-session metadata
/// collections — everything needed to reconstruct a [`crate::state::Session`]
/// on load.
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
    #[serde(default)]
    pub tags: Vec<EntityTag>,
}
