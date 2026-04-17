//! Session registry.
//!
//! A [`Session`] owns the per-workspace `GraphHunter` instance plus the
//! analyst's annotations (tags, notes, path pins, datasets). The
//! [`SessionStore`] is the registry: create / look up / remove / switch
//! current. Its internal locks are exposed behind `Arc` handles so the
//! legacy Tauri `AppState` can share the same `HashMap` during P1
//! migration — there is exactly one store, not a dual-write between
//! legacy and canonical.
//!
//! Locking:
//! - Outer map + current ptr use `std::sync::RwLock` (same API as the
//!   existing Tauri helpers — `read().map_err(...)` — so migration of
//!   `with_current_graph` et al. doesn't need to change error handling).
//! - Per-session inner locks (`graph`, `notes`, `tags`, `datasets`,
//!   `path_node_ids`) also use `std::sync::RwLock` for the same reason.

use std::collections::HashMap;
use std::sync::{Arc, RwLock};

use graph_hunter_core::GraphHunter;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::ai::AiConversation;
use crate::state::session_types::{DatasetInfo, EntityTag, Note};

/// Opaque identifier for a loaded session.
///
/// Wraps a `String` (not a `Uuid`) because existing session IDs are
/// validated as `[A-Za-z0-9_-]` and are not always UUIDs in practice
/// (tests and CLI tooling use descriptive IDs). Serializes transparently
/// so over-the-wire the handle is just the plain ID string.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct SessionHandle(String);

impl SessionHandle {
    /// Fresh UUID-v4 handle. Use for new sessions created server-side.
    pub fn new() -> Self {
        Self(Uuid::new_v4().to_string())
    }

    /// Wrap an existing id string (e.g. loaded from disk).
    pub fn from_string(s: impl Into<String>) -> Self {
        Self(s.into())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn into_string(self) -> String {
        self.0
    }
}

impl Default for SessionHandle {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Display for SessionHandle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.fmt(f)
    }
}

impl From<String> for SessionHandle {
    fn from(s: String) -> Self {
        Self(s)
    }
}

impl From<&str> for SessionHandle {
    fn from(s: &str) -> Self {
        Self(s.to_string())
    }
}

/// In-memory session state: one graph per session plus the analyst's
/// workspace annotations.
///
/// Was `app/src-tauri/src/state.rs::SessionState`; Tauri re-exports this
/// type as `SessionState` for backwards compat during P1 migration.
pub struct Session {
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
    /// Entity tags — primarily used for IoC marking (`ioc:malicious`,
    /// `benign:confirmed`, etc.). Exported via the canonical `export_iocs`.
    pub tags: RwLock<Vec<EntityTag>>,
    /// AI conversation history. Per-session (fixes the bug from the
    /// feedback: switching sessions used to reuse a global history).
    /// NOT persisted in `SessionFile` — chat transcripts are ephemeral
    /// by design.
    pub ai_conversation: RwLock<AiConversation>,
}

impl Session {
    pub fn new(
        id: impl Into<String>,
        name: impl Into<String>,
        graph: GraphHunter,
        created_at: i64,
    ) -> Self {
        Self {
            id: id.into(),
            name: name.into(),
            created_at,
            graph: RwLock::new(graph),
            path_node_ids: RwLock::new(Vec::new()),
            notes: RwLock::new(Vec::new()),
            datasets: RwLock::new(Vec::new()),
            tags: RwLock::new(Vec::new()),
            ai_conversation: RwLock::new(AiConversation::new()),
        }
    }
}

/// Registry of loaded sessions.
///
/// Internal state is wrapped in `Arc<RwLock<_>>` so it can be shared with
/// the legacy Tauri `AppState.sessions` / `current_session_id` fields
/// during P1 migration — both refer to the same map and pointer, no
/// dual-write or divergence possible.
#[derive(Clone)]
pub struct SessionStore {
    inner: Arc<RwLock<HashMap<String, Arc<Session>>>>,
    current: Arc<RwLock<Option<String>>>,
}

impl SessionStore {
    pub fn new() -> Self {
        Self {
            inner: Arc::new(RwLock::new(HashMap::new())),
            current: Arc::new(RwLock::new(None)),
        }
    }

    /// Handle to the shared map, for consumers that need to hold the same
    /// locked `HashMap` the store uses internally (e.g. the Tauri
    /// `AppState` re-export path during migration). The lock semantics
    /// are `std::sync::RwLock` (poisoning).
    pub fn map_handle(&self) -> Arc<RwLock<HashMap<String, Arc<Session>>>> {
        self.inner.clone()
    }

    /// Handle to the current-session pointer. Same sharing rationale as
    /// [`Self::map_handle`].
    pub fn current_handle(&self) -> Arc<RwLock<Option<String>>> {
        self.current.clone()
    }

    pub fn insert(&self, session: Arc<Session>) {
        let id = session.id.clone();
        let mut map = self.inner.write().expect("session map write");
        map.insert(id, session);
    }

    pub fn get(&self, id: &str) -> Option<Arc<Session>> {
        self.inner.read().expect("session map read").get(id).cloned()
    }

    pub fn remove(&self, id: &str) -> Option<Arc<Session>> {
        self.inner.write().expect("session map write").remove(id)
    }

    pub fn list(&self) -> Vec<Arc<Session>> {
        self.inner
            .read()
            .expect("session map read")
            .values()
            .cloned()
            .collect()
    }

    pub fn len(&self) -> usize {
        self.inner.read().expect("session map read").len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub fn contains(&self, id: &str) -> bool {
        self.inner.read().expect("session map read").contains_key(id)
    }

    pub fn current_id(&self) -> Option<String> {
        self.current.read().expect("current read").clone()
    }

    pub fn set_current(&self, id: Option<String>) {
        *self.current.write().expect("current write") = id;
    }

    /// Resolve the current session, if any. Cheap — the `Arc<Session>` is
    /// cloned so callers don't hold the map lock.
    pub fn current_session(&self) -> Option<Arc<Session>> {
        let id = self.current_id()?;
        self.get(&id)
    }

    /// Convenience: resolve either an explicit handle or fall back to
    /// current. Returns `None` when neither resolves to a live session.
    pub fn resolve(&self, handle: Option<&SessionHandle>) -> Option<Arc<Session>> {
        match handle {
            Some(h) => self.get(h.as_str()),
            None => self.current_session(),
        }
    }
}

impl Default for SessionStore {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fresh_session(id: &str) -> Arc<Session> {
        Arc::new(Session::new(id, id, GraphHunter::new(), 0))
    }

    #[test]
    fn handle_roundtrips() {
        let h = SessionHandle::new();
        let s = h.to_string();
        let back = SessionHandle::from_string(s.clone());
        assert_eq!(h, back);
        assert_eq!(back.as_str(), s);
    }

    #[test]
    fn handle_serializes_as_plain_string() {
        let h = SessionHandle::from_string("my-sess-01");
        let j = serde_json::to_string(&h).unwrap();
        assert_eq!(j, "\"my-sess-01\"");
        let back: SessionHandle = serde_json::from_str(&j).unwrap();
        assert_eq!(back, h);
    }

    #[test]
    fn store_starts_empty() {
        let s = SessionStore::new();
        assert!(s.is_empty());
        assert_eq!(s.current_id(), None);
        assert!(s.current_session().is_none());
    }

    #[test]
    fn insert_then_get() {
        let store = SessionStore::new();
        store.insert(fresh_session("s1"));
        assert_eq!(store.len(), 1);
        assert!(store.contains("s1"));
        assert!(store.get("s1").is_some());
        assert!(store.get("s2").is_none());
    }

    #[test]
    fn set_current_and_resolve() {
        let store = SessionStore::new();
        store.insert(fresh_session("s1"));
        store.set_current(Some("s1".to_string()));
        assert!(store.current_session().is_some());

        let h = SessionHandle::from_string("s1");
        assert!(store.resolve(Some(&h)).is_some());
        assert!(store.resolve(None).is_some()); // falls through to current
    }

    #[test]
    fn resolve_missing_returns_none() {
        let store = SessionStore::new();
        let h = SessionHandle::from_string("does-not-exist");
        assert!(store.resolve(Some(&h)).is_none());
        assert!(store.resolve(None).is_none());
    }

    #[test]
    fn map_handle_is_the_same_arc() {
        let store = SessionStore::new();
        let handle_a = store.map_handle();
        let handle_b = store.map_handle();
        // Same Arc underneath — inserting through one is visible via the
        // other, proving the handle-sharing invariant for Tauri AppState.
        handle_a
            .write()
            .unwrap()
            .insert("x".to_string(), fresh_session("x"));
        assert!(handle_b.read().unwrap().contains_key("x"));
    }
}
