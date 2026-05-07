//! Entity / schema / path-nodes / notes / tags operations.
//!
//! These are the 18 methods behind the Tauri `entity.rs` commands and
//! their HTTP equivalents. Everything here is either a graph read or a
//! per-session annotation read/write; no long-running or side-effecting
//! work.

use std::collections::HashSet;
use std::sync::Arc;

use graph_hunter_core::{ExplainedScore, GraphHunter, RelSchemaEntry};

use crate::dto::entity::{
    CreateNoteRequest, CreatedNote, DeleteNoteRequest, EntitiesByTypeRequest, EntityTypeCount,
    ListTaggedRequest, NodeIdsByRelationRequest, NodeScopedRequest, NotesResponse,
    PaginatedEntities, PaginatedEntitiesByTypeRequest, PathNodeMutateRequest, SessionOnly,
    TagEntityRequest, TagsResponse, UntagEntityRequest, UpdateNoteRequest,
};
use crate::state::{EntityTag, Note, Session, SessionHandle};
use crate::util::{now_secs, parse_entity_type, parse_relation_type, resolve_api_port};
use crate::{ApiError, ApiResult, GraphHunterApi};

impl GraphHunterApi {
    /// Resolve the session for a scoped request. Central helper — one
    /// place to change if the ownership model evolves.
    pub(crate) fn resolve_session(
        &self,
        handle: Option<&SessionHandle>,
    ) -> ApiResult<Arc<Session>> {
        match handle {
            Some(h) => self
                .sessions()
                .get(h.as_str())
                .ok_or_else(|| ApiError::SessionNotFound(h.as_str().to_string())),
            None => self
                .sessions()
                .current_session()
                .ok_or(ApiError::NoCurrentSession),
        }
    }

    /// Run a closure with a read guard on the resolved session's graph.
    pub(crate) fn with_graph_read<T>(
        &self,
        handle: Option<&SessionHandle>,
        f: impl FnOnce(&GraphHunter) -> ApiResult<T>,
    ) -> ApiResult<T> {
        let session = self.resolve_session(handle)?;
        let graph = session
            .graph
            .read()
            .map_err(|e| ApiError::Internal(format!("graph lock poisoned: {e}")))?;
        f(&graph)
    }

    /// Run a closure with a write guard on the resolved session's graph.
    /// Use sparingly — mutations block all concurrent readers for the
    /// duration of the closure.
    pub(crate) fn with_graph_write<T>(
        &self,
        handle: Option<&SessionHandle>,
        f: impl FnOnce(&mut GraphHunter) -> ApiResult<T>,
    ) -> ApiResult<T> {
        let session = self.resolve_session(handle)?;
        let mut graph = session
            .graph
            .write()
            .map_err(|e| ApiError::Internal(format!("graph lock poisoned: {e}")))?;
        f(&mut graph)
    }

    // ── Graph-only reads ────────────────────────────────────────────────

    pub fn get_entity_types_in_graph(&self, req: SessionOnly) -> ApiResult<Vec<String>> {
        self.with_graph_read(req.session.as_ref(), |g| Ok(g.entity_types_in_graph()))
    }

    pub fn get_relation_schema(&self, req: SessionOnly) -> ApiResult<Vec<RelSchemaEntry>> {
        self.with_graph_read(req.session.as_ref(), |g| Ok(g.get_relation_schema()))
    }

    /// Like [`Self::get_relation_schema`] but also reports whether the
    /// result came from the memoized cache. Used by the HTTP transport
    /// to surface `_meta.cache_hit` in the response body.
    pub fn get_relation_schema_with_cache_info(
        &self,
        req: SessionOnly,
    ) -> ApiResult<(Vec<RelSchemaEntry>, bool)> {
        self.with_graph_read(req.session.as_ref(), |g| {
            Ok(g.get_relation_schema_with_cache_info())
        })
    }

    pub fn explain_score(&self, req: NodeScopedRequest) -> ApiResult<ExplainedScore> {
        self.with_graph_read(req.session.as_ref(), |g| {
            g.explain_score(&req.node_id)
                .ok_or_else(|| ApiError::NotFound(format!("entity: {}", req.node_id)))
        })
    }

    pub fn get_entity_types_for_node_neighbours(
        &self,
        req: NodeScopedRequest,
    ) -> ApiResult<Vec<String>> {
        self.with_graph_read(req.session.as_ref(), |g| {
            Ok(g.entity_types_of_neighbours(&req.node_id))
        })
    }

    pub fn get_entity_type_counts(&self, req: SessionOnly) -> ApiResult<Vec<EntityTypeCount>> {
        self.with_graph_read(req.session.as_ref(), |g| {
            Ok(g.entity_type_counts()
                .into_iter()
                .map(|(entity_type, count)| EntityTypeCount { entity_type, count })
                .collect())
        })
    }

    pub fn get_entities_by_type(&self, req: EntitiesByTypeRequest) -> ApiResult<Vec<String>> {
        self.with_graph_read(req.session.as_ref(), |g| {
            let et = parse_entity_type(&req.type_name).ok_or_else(|| {
                ApiError::InvalidInput(format!("unknown type: {}", req.type_name))
            })?;
            g.entity_ids_for_type(&et).ok_or_else(|| {
                ApiError::NotFound(format!("no entities for type: {}", req.type_name))
            })
        })
    }

    pub fn get_entities_by_type_paginated(
        &self,
        req: PaginatedEntitiesByTypeRequest,
    ) -> ApiResult<PaginatedEntities> {
        self.with_graph_read(req.session.as_ref(), |g| {
            let et = parse_entity_type(&req.type_name).ok_or_else(|| {
                ApiError::InvalidInput(format!("unknown type: {}", req.type_name))
            })?;
            let all = g.entity_ids_for_type(&et).ok_or_else(|| {
                ApiError::NotFound(format!("no entities for type: {}", req.type_name))
            })?;
            let total_count = all.len();
            let entities = all.into_iter().skip(req.offset).take(req.limit).collect();
            Ok(PaginatedEntities {
                entities,
                total_count,
            })
        })
    }

    pub fn get_node_ids_by_relation_type(
        &self,
        req: NodeIdsByRelationRequest,
    ) -> ApiResult<Vec<String>> {
        self.with_graph_read(req.session.as_ref(), |g| {
            let rt = parse_relation_type(&req.relation_type).ok_or_else(|| {
                ApiError::InvalidInput(format!("unknown relation type: {}", req.relation_type))
            })?;
            let mut node_ids: HashSet<String> = HashSet::new();
            g.streaming.for_each_edge(|src_sid, edge| {
                if edge.rel_type() == rt {
                    node_ids.insert(g.interner.resolve(src_sid).to_string());
                    node_ids.insert(g.interner.resolve(edge.dest_sid).to_string());
                }
            });
            Ok(node_ids.into_iter().collect())
        })
    }

    // ── Path nodes ──────────────────────────────────────────────────────

    pub fn get_path_nodes(&self, req: SessionOnly) -> ApiResult<Vec<String>> {
        let session = self.resolve_session(req.session.as_ref())?;
        let pins = session
            .path_node_ids
            .read()
            .map_err(|e| ApiError::Internal(format!("path_node_ids poisoned: {e}")))?;
        Ok(pins.clone())
    }

    pub fn add_path_node(&self, req: PathNodeMutateRequest) -> ApiResult<()> {
        let session = self.resolve_session(req.session.as_ref())?;
        let mut pins = session
            .path_node_ids
            .write()
            .map_err(|e| ApiError::Internal(format!("path_node_ids poisoned: {e}")))?;
        if !pins.contains(&req.node_id) {
            pins.push(req.node_id);
        }
        Ok(())
    }

    pub fn remove_path_node(&self, req: PathNodeMutateRequest) -> ApiResult<()> {
        let session = self.resolve_session(req.session.as_ref())?;
        let mut pins = session
            .path_node_ids
            .write()
            .map_err(|e| ApiError::Internal(format!("path_node_ids poisoned: {e}")))?;
        pins.retain(|n| n != &req.node_id);
        Ok(())
    }

    // ── Notes ───────────────────────────────────────────────────────────

    pub fn get_notes(&self, req: SessionOnly) -> ApiResult<NotesResponse> {
        let session = self.resolve_session(req.session.as_ref())?;
        let notes = session
            .notes
            .read()
            .map_err(|e| ApiError::Internal(format!("notes lock poisoned: {e}")))?;
        Ok(notes.clone())
    }

    pub fn create_note(&self, req: CreateNoteRequest) -> ApiResult<CreatedNote> {
        let session = self.resolve_session(req.session.as_ref())?;
        let note = Note {
            id: uuid::Uuid::new_v4().to_string(),
            content: req.content,
            node_id: req.node_id,
            created_at: now_secs(),
        };
        let mut notes = session
            .notes
            .write()
            .map_err(|e| ApiError::Internal(format!("notes lock poisoned: {e}")))?;
        notes.push(note.clone());
        let url = format!("http://127.0.0.1:{}/notes/{}", resolve_api_port(), note.id);
        Ok(CreatedNote { note, url })
    }

    pub fn update_note(&self, req: UpdateNoteRequest) -> ApiResult<()> {
        let session = self.resolve_session(req.session.as_ref())?;
        let mut notes = session
            .notes
            .write()
            .map_err(|e| ApiError::Internal(format!("notes lock poisoned: {e}")))?;
        let note = notes
            .iter_mut()
            .find(|n| n.id == req.note_id)
            .ok_or_else(|| ApiError::NotFound(format!("note: {}", req.note_id)))?;
        note.content = req.content;
        Ok(())
    }

    pub fn delete_note(&self, req: DeleteNoteRequest) -> ApiResult<()> {
        let session = self.resolve_session(req.session.as_ref())?;
        let mut notes = session
            .notes
            .write()
            .map_err(|e| ApiError::Internal(format!("notes lock poisoned: {e}")))?;
        notes.retain(|n| n.id != req.note_id);
        Ok(())
    }

    // ── Tags ────────────────────────────────────────────────────────────

    pub fn tag_entity(&self, req: TagEntityRequest) -> ApiResult<EntityTag> {
        if req.tag.is_empty() {
            return Err(ApiError::InvalidInput("tag cannot be empty".into()));
        }
        let session = self.resolve_session(req.session.as_ref())?;
        // 2026-05-06: validate the node exists before tagging. Used
        // to silently accept any string — that meant a misspelled
        // node_id contaminated the IoC export with a phantom entry.
        // For a tool whose output is published to Sentinel/Jira, the
        // wrong default is "trust the caller". Now we 400.
        {
            let graph = session
                .graph
                .read()
                .map_err(|e| ApiError::Internal(format!("graph lock poisoned: {e}")))?;
            if graph.get_entity(&req.node_id).is_none() {
                return Err(ApiError::InvalidInput(format!(
                    "tag_entity: node_id `{}` does not exist in the current graph",
                    req.node_id
                )));
            }
        }
        let mut tags = session
            .tags
            .write()
            .map_err(|e| ApiError::Internal(format!("tags lock poisoned: {e}")))?;
        // Same (node_id, tag) → update reason in place, not duplicate.
        if let Some(existing) = tags
            .iter_mut()
            .find(|t| t.node_id == req.node_id && t.tag == req.tag)
        {
            existing.reason = req.reason;
            return Ok(existing.clone());
        }
        let entry = EntityTag {
            node_id: req.node_id,
            tag: req.tag,
            reason: req.reason,
            created_at: now_secs(),
        };
        tags.push(entry.clone());
        Ok(entry)
    }

    /// Remove every entry matching `(node_id, tag)`. Returns the
    /// number of removed rows so callers can distinguish "tag was
    /// there and is now gone" from "no-op, never tagged".
    /// 2026-05-06: previously returned `()` and the MCP wrapper
    /// always reported `{ok: true}`, hiding misspelled IDs / tags.
    pub fn untag_entity(&self, req: UntagEntityRequest) -> ApiResult<usize> {
        let session = self.resolve_session(req.session.as_ref())?;
        let mut tags = session
            .tags
            .write()
            .map_err(|e| ApiError::Internal(format!("tags lock poisoned: {e}")))?;
        let before = tags.len();
        tags.retain(|t| !(t.node_id == req.node_id && t.tag == req.tag));
        Ok(before - tags.len())
    }

    pub fn list_tagged(&self, req: ListTaggedRequest) -> ApiResult<TagsResponse> {
        let session = self.resolve_session(req.session.as_ref())?;
        let tags = session
            .tags
            .read()
            .map_err(|e| ApiError::Internal(format!("tags lock poisoned: {e}")))?;
        Ok(match req.tag_prefix {
            Some(prefix) if !prefix.is_empty() => tags
                .iter()
                .filter(|t| t.tag.starts_with(&prefix))
                .cloned()
                .collect(),
            _ => tags.clone(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn api_with_empty_session() -> (GraphHunterApi, String) {
        let api = GraphHunterApi::new_noop();
        let id = "t1".to_string();
        let session = Arc::new(Session::new(id.clone(), "test", GraphHunter::new(), 0));
        api.sessions().insert(session);
        api.sessions().set_current(Some(id.clone()));
        (api, id)
    }

    /// Seed `node_ids` as User entities in the current session's
    /// graph. Used by tag-related tests after the 2026-05-06
    /// existence check on `tag_entity` started rejecting tags
    /// against unseen nodes (which used to silently contaminate
    /// the IoC export).
    fn seed_users(api: &GraphHunterApi, node_ids: &[&str]) {
        if let Some(session) = api.sessions().current_session() {
            if let Ok(mut graph) = session.graph.write() {
                for id in node_ids {
                    use graph_hunter_core::EntityType;
                    let entity = graph_hunter_core::entity::Entity::new(
                        id.to_string(),
                        EntityType::User,
                    );
                    let _ = graph.add_entity(entity);
                }
            }
        }
    }

    #[test]
    fn path_nodes_add_is_idempotent() {
        let (api, _id) = api_with_empty_session();
        api.add_path_node(PathNodeMutateRequest {
            session: None,
            node_id: "n1".to_string(),
        })
        .unwrap();
        api.add_path_node(PathNodeMutateRequest {
            session: None,
            node_id: "n1".to_string(),
        })
        .unwrap();
        let pins = api.get_path_nodes(SessionOnly::default()).unwrap();
        assert_eq!(pins, vec!["n1".to_string()]);
    }

    #[test]
    fn path_nodes_remove_works() {
        let (api, _id) = api_with_empty_session();
        api.add_path_node(PathNodeMutateRequest {
            session: None,
            node_id: "n1".to_string(),
        })
        .unwrap();
        api.remove_path_node(PathNodeMutateRequest {
            session: None,
            node_id: "n1".to_string(),
        })
        .unwrap();
        let pins = api.get_path_nodes(SessionOnly::default()).unwrap();
        assert!(pins.is_empty());
    }

    #[test]
    fn create_note_roundtrip() {
        let (api, _id) = api_with_empty_session();
        let created = api
            .create_note(CreateNoteRequest {
                session: None,
                content: "initial finding".to_string(),
                node_id: Some("alice".to_string()),
            })
            .unwrap();
        assert!(created.url.contains(&created.note.id));
        let all = api.get_notes(SessionOnly::default()).unwrap();
        assert_eq!(all.len(), 1);
        assert_eq!(all[0].content, "initial finding");
    }

    #[test]
    fn update_note_not_found_is_404() {
        let (api, _id) = api_with_empty_session();
        let err = api
            .update_note(UpdateNoteRequest {
                session: None,
                note_id: "missing".to_string(),
                content: "x".to_string(),
            })
            .unwrap_err();
        assert!(matches!(err, ApiError::NotFound(_)));
    }

    #[test]
    fn tag_entity_rejects_empty_tag() {
        let (api, _id) = api_with_empty_session();
        let err = api
            .tag_entity(TagEntityRequest {
                session: None,
                node_id: "alice".to_string(),
                tag: "".to_string(),
                reason: None,
            })
            .unwrap_err();
        assert!(matches!(err, ApiError::InvalidInput(_)));
    }

    #[test]
    fn tag_entity_idempotent_updates_reason_in_place() {
        let (api, _id) = api_with_empty_session();
        seed_users(&api, &["alice"]);
        let first = api
            .tag_entity(TagEntityRequest {
                session: None,
                node_id: "alice".to_string(),
                tag: "ioc:malicious".to_string(),
                reason: Some("initial".to_string()),
            })
            .unwrap();
        let second = api
            .tag_entity(TagEntityRequest {
                session: None,
                node_id: "alice".to_string(),
                tag: "ioc:malicious".to_string(),
                reason: Some("revised".to_string()),
            })
            .unwrap();
        assert_eq!(first.node_id, second.node_id);
        let all = api.list_tagged(ListTaggedRequest::default()).unwrap();
        assert_eq!(
            all.len(),
            1,
            "duplicate (node_id, tag) must not insert twice"
        );
        assert_eq!(all[0].reason, Some("revised".to_string()));
    }

    #[test]
    fn list_tagged_filters_by_prefix() {
        let (api, _id) = api_with_empty_session();
        seed_users(&api, &["alice", "bob"]);
        api.tag_entity(TagEntityRequest {
            session: None,
            node_id: "alice".to_string(),
            tag: "ioc:malicious".to_string(),
            reason: None,
        })
        .unwrap();
        api.tag_entity(TagEntityRequest {
            session: None,
            node_id: "bob".to_string(),
            tag: "benign:confirmed".to_string(),
            reason: None,
        })
        .unwrap();
        let iocs = api
            .list_tagged(ListTaggedRequest {
                session: None,
                tag_prefix: Some("ioc:".to_string()),
            })
            .unwrap();
        assert_eq!(iocs.len(), 1);
        assert_eq!(iocs[0].node_id, "alice");
    }

    #[test]
    fn untag_missing_pair_is_noop() {
        let (api, _id) = api_with_empty_session();
        // Does not error on an unknown (node, tag) pair, but reports
        // 0 removed so callers can distinguish no-op from success.
        let removed = api
            .untag_entity(UntagEntityRequest {
                session: None,
                node_id: "nobody".to_string(),
                tag: "x".to_string(),
            })
            .unwrap();
        assert_eq!(removed, 0, "untag for nonexistent pair must report 0 removed");
    }

    /// 2026-05-06: tag_entity must reject node_ids absent from the
    /// graph. Pre-fix, the call silently accepted any string, which
    /// then leaked phantom IoCs into export_iocs / publish.
    #[test]
    fn tag_entity_rejects_unknown_node_id() {
        let (api, _id) = api_with_empty_session();
        let err = api
            .tag_entity(TagEntityRequest {
                session: None,
                node_id: "ghost-node-not-in-graph".to_string(),
                tag: "ioc:test".to_string(),
                reason: None,
            })
            .unwrap_err();
        match err {
            ApiError::InvalidInput(msg) => {
                assert!(
                    msg.contains("does not exist"),
                    "expected 'does not exist' message, got: {msg}"
                );
            }
            other => panic!("expected InvalidInput, got {other:?}"),
        }
    }

    /// untag_entity returns the number of (node_id, tag) rows
    /// actually removed — was `()` in v1, hiding misspelled IDs.
    #[test]
    fn untag_entity_returns_removed_count() {
        let (api, _id) = api_with_empty_session();
        seed_users(&api, &["alice"]);
        api.tag_entity(TagEntityRequest {
            session: None,
            node_id: "alice".to_string(),
            tag: "ioc:test".to_string(),
            reason: None,
        })
        .unwrap();
        let removed = api
            .untag_entity(UntagEntityRequest {
                session: None,
                node_id: "alice".to_string(),
                tag: "ioc:test".to_string(),
            })
            .unwrap();
        assert_eq!(removed, 1, "tag was present, should have removed 1 row");
        let removed_again = api
            .untag_entity(UntagEntityRequest {
                session: None,
                node_id: "alice".to_string(),
                tag: "ioc:test".to_string(),
            })
            .unwrap();
        assert_eq!(removed_again, 0, "second untag is a no-op");
    }

    #[test]
    fn empty_graph_no_entity_types() {
        let (api, _id) = api_with_empty_session();
        let types = api
            .get_entity_types_in_graph(SessionOnly::default())
            .unwrap();
        assert!(types.is_empty());
    }

    #[test]
    fn get_entities_by_type_unknown_is_invalid() {
        let (api, _id) = api_with_empty_session();
        let err = api
            .get_entities_by_type(EntitiesByTypeRequest {
                session: None,
                type_name: "".to_string(),
            })
            .unwrap_err();
        assert!(matches!(err, ApiError::InvalidInput(_)));
    }
}
