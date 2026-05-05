//! Session lifecycle: create / list / load / save / delete / current.
//!
//! `load_session` and `save_session` are the only genuinely heavy ops
//! in the whole API — they can stream tens of millions of entities +
//! relations through `serde_json`. Both variants are exposed: a sync
//! blocking method for callers that control their own threadpool
//! (`tauri::async_runtime::spawn_blocking`, HTTP's `tokio::task::spawn_blocking`)
//! and an async wrapper that does the spawning internally for simple
//! callers.
//!
//! Progress events (`session-load-progress`, `session-save-progress`)
//! flow through the canonical [`EventEmitter`](crate::EventEmitter).

use std::collections::HashSet;
use std::fs;
use std::sync::Arc;

use graph_hunter_core::GraphHunter;

use crate::dto::session::{
    CreateSessionRequest, DeleteSessionRequest, LoadSessionRequest, SaveSessionRequest, SessionInfo,
};
use crate::events::events as event_names;
use crate::state::{Session, SessionFile, session_data_dir, session_file_path};
use crate::util::now_secs;
use crate::{ApiError, ApiResult, GraphHunterApi};

/// Compute a sensible "emit every N items" stride so progress events
/// are bounded to ~100 per payload (but at least every 1000 items so
/// small loads still animate smoothly).
#[inline]
fn progress_stride(total: usize) -> usize {
    let pct1 = total / 100;
    if pct1 > 1000 { pct1 } else { 1000 }
}

impl GraphHunterApi {
    /// Create a new empty session, set it as current, clear the hunt
    /// cache. Returns the session info.
    pub fn create_session(&self, req: CreateSessionRequest) -> ApiResult<SessionInfo> {
        let id = uuid::Uuid::new_v4().to_string();
        let name = req.name.unwrap_or_else(|| "Untitled".to_string());
        let created_at = now_secs();

        let session = Arc::new(Session::new(
            id.clone(),
            name.clone(),
            GraphHunter::new(),
            created_at,
        ));
        self.sessions().insert(session);
        self.sessions().set_current(Some(id.clone()));

        // Clear hunt cache — switching sessions invalidates it.
        let mut cache = self
            .inner
            .hunt_cache
            .write()
            .map_err(|e| ApiError::Internal(format!("hunt cache poisoned: {e}")))?;
        *cache = Vec::new();

        Ok(SessionInfo {
            id,
            name,
            created_at,
        })
    }

    /// List sessions: in-memory + disk scan. Duplicate IDs are
    /// deduplicated with in-memory winning over disk.
    pub fn list_sessions(&self) -> ApiResult<Vec<SessionInfo>> {
        let mut seen: HashSet<String> = HashSet::new();
        let mut list: Vec<SessionInfo> = self
            .sessions()
            .list()
            .into_iter()
            .map(|s| {
                seen.insert(s.id.clone());
                SessionInfo {
                    id: s.id.clone(),
                    name: s.name.clone(),
                    created_at: s.created_at,
                }
            })
            .collect();

        if let Ok(dir) = session_data_dir() {
            if let Ok(entries) = fs::read_dir(&dir) {
                for entry in entries.flatten() {
                    let path = entry.path();
                    if path.extension().and_then(|e| e.to_str()) != Some("json") {
                        continue;
                    }
                    let Ok(file) = fs::File::open(&path) else {
                        continue;
                    };
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
                            list.push(SessionInfo {
                                id,
                                name,
                                created_at,
                            });
                        }
                    }
                }
            }
        }

        list.sort_by(|a, b| a.created_at.cmp(&b.created_at));
        Ok(list)
    }

    /// Load a session by id from disk (if not already in memory) and
    /// set it as current. Emits `session-load-progress` throughout.
    ///
    /// Synchronous / blocking — callers in async contexts should wrap
    /// in `spawn_blocking`. See [`Self::load_session`] for an async
    /// convenience wrapper.
    pub fn load_session_blocking(&self, req: LoadSessionRequest) -> ApiResult<SessionInfo> {
        let session_id = req.session_id;
        let _ = session_data_dir().map_err(ApiError::Io)?;
        let path = session_file_path(&session_id).map_err(ApiError::Io)?;
        let emitter = self.inner.emitter.clone();

        // If not in memory and a disk file exists, read it.
        if !self.sessions().contains(&session_id) && path.exists() {
            emitter.emit(
                event_names::SESSION_LOAD_PROGRESS,
                json_progress("reading", 0, 0),
            );
            let file_handle = fs::File::open(&path)
                .map_err(|e| ApiError::Io(format!("open session file: {e}")))?;
            let mut reader = std::io::BufReader::with_capacity(8 * 1024 * 1024, file_handle);

            // Heavy-logs #3: peek magic bytes to dispatch between
            // the new binary GHS1 format and the legacy JSON
            // format. The buffered reader's `fill_buf` lets us
            // inspect without consuming.
            use std::io::BufRead;
            let prefix_is_binary = {
                let buf = reader.fill_buf().map_err(|e| ApiError::Io(e.to_string()))?;
                crate::state::session_binary::is_binary_session(buf)
            };

            let (mut graph, file, entity_count, relation_count) = if prefix_is_binary {
                load_binary_into_graph(&mut reader, &emitter)?
            } else {
                emitter.emit(
                    event_names::SESSION_LOAD_PROGRESS,
                    json_progress("parsing", 0, 0),
                );
                let file: SessionFile = serde_json::from_reader(reader)
                    .map_err(|e| ApiError::InvalidInput(format!("invalid session file: {e}")))?;
                load_json_into_graph(file, &emitter)?
            };

            emitter.emit(
                event_names::SESSION_LOAD_PROGRESS,
                json_progress("sorting", 0, 0),
            );
            graph
                .sort_edges_by_timestamp()
                .map_err(|e| ApiError::Internal(e.to_string()))?;

            // Reconcile persisted `entity.score` with the current scoring
            // algorithm. Sessions saved before the rarity-aware composite
            // shipped carry pre-rarity scores on disk; without this
            // refresh, `top_anomalies` would surface centrality-dominant
            // hot assets (logos, hub URLs) even though every other code
            // path uses the hunt-oriented composite. Cheap — one O(V+E)
            // pass over the freshly-loaded graph.
            emitter.emit(
                event_names::SESSION_LOAD_PROGRESS,
                json_progress("scoring", 0, 0),
            );
            graph.compute_scores();
            graph.compute_composite_score_hunt_default();

            tracing::info!(
                "SESSION LOAD: {} entities, {} relations loaded",
                entity_count,
                relation_count
            );

            let session = Arc::new(Session {
                id: file.id.clone(),
                name: file.name.clone(),
                created_at: file.created_at,
                graph: std::sync::RwLock::new(graph),
                path_node_ids: std::sync::RwLock::new(file.path_node_ids.clone()),
                notes: std::sync::RwLock::new(file.notes.clone()),
                datasets: std::sync::RwLock::new(file.datasets.clone()),
                tags: std::sync::RwLock::new(file.tags.clone()),
                ai_conversation: std::sync::RwLock::new(crate::ai::AiConversation::new()),
                agentic_review: std::sync::RwLock::new(
                    crate::state::agentic::MappingReviewQueue::new(),
                ),
                lftj_cache: std::sync::RwLock::new(None),
                yannakakis_cache: std::sync::RwLock::new(None),
            });
            self.sessions().insert(session);
        }

        // Resolve (must now be in memory).
        let session = self
            .sessions()
            .get(&session_id)
            .ok_or_else(|| ApiError::SessionNotFound(session_id.clone()))?;

        self.sessions().set_current(Some(session_id));

        // Clear hunt cache: switching sessions invalidates it.
        let mut cache = self
            .inner
            .hunt_cache
            .write()
            .map_err(|e| ApiError::Internal(format!("hunt cache poisoned: {e}")))?;
        *cache = Vec::new();
        drop(cache);

        emitter.emit(
            event_names::SESSION_LOAD_PROGRESS,
            json_progress("done", 1, 1),
        );

        Ok(SessionInfo {
            id: session.id.clone(),
            name: session.name.clone(),
            created_at: session.created_at,
        })
    }

    /// Async convenience wrapper around [`Self::load_session_blocking`].
    pub async fn load_session(&self, req: LoadSessionRequest) -> ApiResult<SessionInfo> {
        let api = self.clone();
        tokio::task::spawn_blocking(move || api.load_session_blocking(req))
            .await
            .map_err(|e| ApiError::Internal(format!("spawn_blocking join: {e}")))?
    }

    /// Save the current (or specified) session to disk. Streams JSON
    /// so memory stays flat even for million-edge graphs. Emits
    /// `session-save-progress` throughout.
    pub fn save_session_blocking(&self, req: SaveSessionRequest) -> ApiResult<()> {
        let id = req
            .session_id
            .or_else(|| self.sessions().current_id())
            .ok_or_else(|| ApiError::NoCurrentSession)?;
        let path = session_file_path(&id).map_err(ApiError::Io)?;
        let session = self
            .sessions()
            .get(&id)
            .ok_or_else(|| ApiError::SessionNotFound(id.clone()))?;
        let emitter = self.inner.emitter.clone();

        let graph = session
            .graph
            .read()
            .map_err(|e| ApiError::Internal(format!("graph lock poisoned: {e}")))?;
        let path_node_ids = session
            .path_node_ids
            .read()
            .map_err(|e| ApiError::Internal(format!("path_node_ids poisoned: {e}")))?
            .clone();
        let notes = session
            .notes
            .read()
            .map_err(|e| ApiError::Internal(format!("notes lock poisoned: {e}")))?
            .clone();
        let datasets = session
            .datasets
            .read()
            .map_err(|e| ApiError::Internal(format!("datasets lock poisoned: {e}")))?
            .clone();
        let tags = session
            .tags
            .read()
            .map_err(|e| ApiError::Internal(format!("tags lock poisoned: {e}")))?
            .clone();

        let f = fs::File::create(&path)
            .map_err(|e| ApiError::Io(format!("create session file: {e}")))?;
        let mut w = std::io::BufWriter::with_capacity(8 * 1024 * 1024, f);

        use std::io::Write;

        // Heavy-logs #3: binary GHS1 format with streaming entity
        // and relation records. ~5x smaller on disk and ~5-10x
        // faster save+load than the previous JSON format. Old
        // sessions saved as JSON still load fine — `load_session`
        // sniffs the magic bytes and dispatches.
        let entity_count = graph.entities.len();
        let relation_count = graph.streaming_edge_count();
        let header = crate::state::session_binary::SessionHeader {
            id: id.clone(),
            name: session.name.clone(),
            created_at: session.created_at,
            path_node_ids,
            notes,
            datasets,
            tags,
        };
        crate::state::session_binary::write_header(&mut w, &header)
            .map_err(|e| ApiError::Io(e.to_string()))?;

        emitter.emit(
            event_names::SESSION_SAVE_PROGRESS,
            json_progress("entities", 0, entity_count),
        );
        let entity_stride = progress_stride(entity_count);
        // The streaming writer doesn't expose a per-record callback
        // so we drive the iteration here and emit progress inline.
        // `write_entities` is fed an iterator that ticks the
        // progress emitter at each stride.
        crate::state::session_binary::write_entities(
            &mut w,
            entity_count as u64,
            graph.entities.values().enumerate().map(|(i, entity)| {
                if (i + 1) % entity_stride == 0 {
                    emitter.emit(
                        event_names::SESSION_SAVE_PROGRESS,
                        json_progress("entities", i + 1, entity_count),
                    );
                }
                entity
            }),
        )
        .map_err(|e| ApiError::Io(e.to_string()))?;
        emitter.emit(
            event_names::SESSION_SAVE_PROGRESS,
            json_progress("entities", entity_count, entity_count),
        );

        let relation_stride = progress_stride(relation_count);
        emitter.emit(
            event_names::SESSION_SAVE_PROGRESS,
            json_progress("relations", 0, relation_count),
        );
        // Materialize a flat Vec of (source_sid, StreamEdge) tuples
        // from the streaming backend so the serializer's iterator
        // contract is honored. ~36 B/edge — manageable up to a few
        // tens of millions of edges; a future rewrite of
        // write_relations to take a closure callback would let this
        // skip the temp Vec for unbounded sessions.
        let mut edge_tuples: Vec<(graph_hunter_core::StrId, graph_hunter_core::CompactRelation)> =
            Vec::with_capacity(relation_count);
        graph.streaming.for_each_edge(|src_sid, edge| {
            // SAFETY: StreamEdge is layout-compatible with
            // CompactRelation (both #[repr(C)] with identical
            // field order). Read through a transmute so the
            // existing materialize_relation() path is reused
            // unchanged.
            let compact: graph_hunter_core::CompactRelation = unsafe {
                std::ptr::read(edge as *const _ as *const graph_hunter_core::CompactRelation)
            };
            edge_tuples.push((src_sid, compact));
        });
        crate::state::session_binary::write_relations(
            &mut w,
            relation_count as u64,
            edge_tuples.iter().enumerate().map(|(i, (_src, compact))| {
                let rel = graph.materialize_relation(compact);
                if (i + 1) % relation_stride == 0 {
                    emitter.emit(
                        event_names::SESSION_SAVE_PROGRESS,
                        json_progress("relations", i + 1, relation_count),
                    );
                }
                rel
            }),
        )
        .map_err(|e| ApiError::Io(e.to_string()))?;
        emitter.emit(
            event_names::SESSION_SAVE_PROGRESS,
            json_progress("relations", relation_count, relation_count),
        );

        w.flush().map_err(|e| ApiError::Io(e.to_string()))?;

        emitter.emit(
            event_names::SESSION_SAVE_PROGRESS,
            json_progress("done", 1, 1),
        );
        Ok(())
    }

    /// Async convenience wrapper around [`Self::save_session_blocking`].
    pub async fn save_session(&self, req: SaveSessionRequest) -> ApiResult<()> {
        let api = self.clone();
        tokio::task::spawn_blocking(move || api.save_session_blocking(req))
            .await
            .map_err(|e| ApiError::Internal(format!("spawn_blocking join: {e}")))?
    }

    /// Delete a session from memory AND disk. Clears the current
    /// pointer if it referenced the deleted id.
    pub fn delete_session(&self, req: DeleteSessionRequest) -> ApiResult<()> {
        self.sessions().remove(&req.session_id);
        if let Ok(path) = session_file_path(&req.session_id) {
            let _ = fs::remove_file(&path);
        }
        if self.sessions().current_id().as_deref() == Some(req.session_id.as_str()) {
            self.sessions().set_current(None);
        }
        Ok(())
    }

    /// Return info about the current session, or `None` when no
    /// session is selected.
    pub fn get_current_session(&self) -> ApiResult<Option<SessionInfo>> {
        Ok(self.sessions().current_session().map(|s| SessionInfo {
            id: s.id.clone(),
            name: s.name.clone(),
            created_at: s.created_at,
        }))
    }
}

/// Build a `{phase, current, total}` JSON payload for progress events.
fn json_progress(phase: &str, current: usize, total: usize) -> serde_json::Value {
    serde_json::json!({
        "phase": phase,
        "current": current,
        "total": total,
    })
}

/// Build a graph + metadata `SessionFile` shell from a binary GHS1
/// reader. Streams entities and relations into the graph one record
/// at a time so peak memory during load is bounded by the reader's
/// buffer plus the graph itself, no intermediate `Vec<Entity>` /
/// `Vec<Relation>` materialization. The returned `SessionFile`
/// keeps `entities` / `relations` empty on purpose — the data
/// already lives in the graph; downstream code only reads metadata.
fn load_binary_into_graph<R: std::io::Read>(
    reader: &mut R,
    emitter: &Arc<dyn crate::EventEmitter>,
) -> ApiResult<(GraphHunter, SessionFile, usize, usize)> {
    use crate::state::session_binary::{EntityReader, RelationReader, read_header};

    emitter.emit(
        event_names::SESSION_LOAD_PROGRESS,
        json_progress("parsing", 0, 0),
    );
    let header = read_header(reader)
        .map_err(|e| ApiError::InvalidInput(format!("invalid binary session header: {e}")))?;

    let mut graph = GraphHunter::new();

    let mut entity_iter = EntityReader::new(reader)
        .map_err(|e| ApiError::InvalidInput(format!("entity stream: {e}")))?;
    let entity_count = entity_iter.count() as usize;
    let entity_stride = progress_stride(entity_count);
    emitter.emit(
        event_names::SESSION_LOAD_PROGRESS,
        json_progress("entities", 0, entity_count),
    );
    graph.reserve(entity_count, 0);
    let mut i = 0usize;
    while let Some(entity) = entity_iter
        .next()
        .map_err(|e| ApiError::InvalidInput(format!("entity record: {e}")))?
    {
        let _ = graph.add_entity(entity);
        i += 1;
        if i % entity_stride == 0 {
            emitter.emit(
                event_names::SESSION_LOAD_PROGRESS,
                json_progress("entities", i, entity_count),
            );
        }
    }
    emitter.emit(
        event_names::SESSION_LOAD_PROGRESS,
        json_progress("entities", entity_count, entity_count),
    );

    let mut relation_iter = RelationReader::new(reader)
        .map_err(|e| ApiError::InvalidInput(format!("relation stream: {e}")))?;
    let relation_count = relation_iter.count() as usize;
    let relation_stride = progress_stride(relation_count);
    emitter.emit(
        event_names::SESSION_LOAD_PROGRESS,
        json_progress("relations", 0, relation_count),
    );
    let mut i = 0usize;
    while let Some(rel) = relation_iter
        .next()
        .map_err(|e| ApiError::InvalidInput(format!("relation record: {e}")))?
    {
        let _ = graph.add_relation(rel);
        i += 1;
        if i % relation_stride == 0 {
            emitter.emit(
                event_names::SESSION_LOAD_PROGRESS,
                json_progress("relations", i, relation_count),
            );
        }
    }
    emitter.emit(
        event_names::SESSION_LOAD_PROGRESS,
        json_progress("relations", relation_count, relation_count),
    );

    let file = SessionFile {
        id: header.id,
        name: header.name,
        created_at: header.created_at,
        entities: Vec::new(),
        relations: Vec::new(),
        path_node_ids: header.path_node_ids,
        notes: header.notes,
        datasets: header.datasets,
        tags: header.tags,
    };
    Ok((graph, file, entity_count, relation_count))
}

/// Build a graph from an already-parsed legacy JSON `SessionFile`,
/// emitting progress events along the way. Mirrors the binary
/// loader's signature so the caller can dispatch uniformly.
fn load_json_into_graph(
    mut file: SessionFile,
    emitter: &Arc<dyn crate::EventEmitter>,
) -> ApiResult<(GraphHunter, SessionFile, usize, usize)> {
    let entity_count = file.entities.len();
    let relation_count = file.relations.len();
    let mut graph = GraphHunter::new();
    graph.reserve(entity_count, relation_count);

    let entity_stride = progress_stride(entity_count);
    emitter.emit(
        event_names::SESSION_LOAD_PROGRESS,
        json_progress("entities", 0, entity_count),
    );
    let entities = std::mem::take(&mut file.entities);
    for (i, entity) in entities.into_iter().enumerate() {
        let _ = graph.add_entity(entity);
        if (i + 1) % entity_stride == 0 {
            emitter.emit(
                event_names::SESSION_LOAD_PROGRESS,
                json_progress("entities", i + 1, entity_count),
            );
        }
    }
    emitter.emit(
        event_names::SESSION_LOAD_PROGRESS,
        json_progress("entities", entity_count, entity_count),
    );

    let relation_stride = progress_stride(relation_count);
    emitter.emit(
        event_names::SESSION_LOAD_PROGRESS,
        json_progress("relations", 0, relation_count),
    );
    let relations = std::mem::take(&mut file.relations);
    for (i, rel) in relations.into_iter().enumerate() {
        let _ = graph.add_relation(rel);
        if (i + 1) % relation_stride == 0 {
            emitter.emit(
                event_names::SESSION_LOAD_PROGRESS,
                json_progress("relations", i + 1, relation_count),
            );
        }
    }
    emitter.emit(
        event_names::SESSION_LOAD_PROGRESS,
        json_progress("relations", relation_count, relation_count),
    );

    Ok((graph, file, entity_count, relation_count))
}

/// Extract a JSON string value from a partial prefix (first 4KB of a
/// session file). Used by `list_sessions` disk scan to avoid parsing
/// the entire file just for the header.
fn extract_json_string(text: &str, key: &str) -> Option<String> {
    let pattern = format!("\"{key}\"");
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

/// Extract a JSON integer value from a partial prefix.
fn extract_json_i64(text: &str, key: &str) -> Option<i64> {
    let pattern = format!("\"{key}\"");
    let idx = text.find(&pattern)?;
    let after_key = &text[idx + pattern.len()..];
    let colon = after_key.find(':')?;
    let after_colon = after_key[colon + 1..].trim_start();
    let end = after_colon.find(|c: char| !c.is_ascii_digit() && c != '-')?;
    after_colon[..end].parse().ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn create_session_sets_current_and_clears_cache() {
        let api = GraphHunterApi::new_noop();
        // Prime the cache so we can prove create clears it.
        *api.hunt_cache_handle().write().unwrap() = vec![vec!["a".into()]];
        assert_eq!(api.hunt_cache_handle().read().unwrap().len(), 1);

        let info = api.create_session(CreateSessionRequest::default()).unwrap();
        assert_eq!(info.name, "Untitled");
        assert_eq!(api.sessions().current_id(), Some(info.id.clone()));
        assert_eq!(api.hunt_cache_handle().read().unwrap().len(), 0);
    }

    #[test]
    fn get_current_is_none_when_unset() {
        let api = GraphHunterApi::new_noop();
        assert!(api.get_current_session().unwrap().is_none());
    }

    #[test]
    fn delete_session_removes_and_clears_current() {
        let api = GraphHunterApi::new_noop();
        let info = api.create_session(CreateSessionRequest::default()).unwrap();
        api.delete_session(DeleteSessionRequest {
            session_id: info.id.clone(),
        })
        .unwrap();
        assert!(!api.sessions().contains(&info.id));
        assert_eq!(api.sessions().current_id(), None);
    }

    #[test]
    fn save_without_current_errors() {
        let api = GraphHunterApi::new_noop();
        let err = api
            .save_session_blocking(SaveSessionRequest::default())
            .unwrap_err();
        assert!(matches!(err, ApiError::NoCurrentSession));
    }

    #[test]
    fn extract_helpers_work() {
        let text = r#"{"id":"abc-123","name":"test","created_at":1700000000,"#;
        assert_eq!(extract_json_string(text, "id").as_deref(), Some("abc-123"));
        assert_eq!(extract_json_string(text, "name").as_deref(), Some("test"));
        assert_eq!(extract_json_i64(text, "created_at"), Some(1_700_000_000));
        assert!(extract_json_string(text, "missing").is_none());
    }
}
