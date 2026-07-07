//! Dataset management operations. All four are session-bound; only
//! `remove_dataset` and `rename_type_in_dataset` mutate the graph.

use std::collections::HashSet;

use crate::dto::dataset::{
    DatasetEntityTypesRequest, ListDatasetsRequest, ListDatasetsResponse, RemoveDatasetRequest,
    RemoveDatasetResponse, RenameTypeInDatasetRequest,
};
use crate::util::parse_entity_type;
use crate::{ApiError, ApiResult, GraphHunterApi};

impl GraphHunterApi {
    /// List datasets ingested into the resolved session.
    pub fn list_datasets(&self, req: ListDatasetsRequest) -> ApiResult<ListDatasetsResponse> {
        let session = self.resolve_session(req.session.as_ref())?;
        let datasets = session
            .datasets
            .read()
            .map_err(|e| ApiError::Internal(format!("datasets lock poisoned: {e}")))?;
        Ok(datasets.clone())
    }

    /// Remove a dataset, its entities/relations, and clean up references
    /// in path_node_ids and notes. Returns `(entities_removed,
    /// relations_removed)`.
    pub fn remove_dataset(&self, req: RemoveDatasetRequest) -> ApiResult<RemoveDatasetResponse> {
        let session = self.resolve_session(req.session.as_ref())?;

        // Snapshot the IDs that belong to this dataset so we can clean up
        // path_node_ids / notes AFTER the graph write returns.
        let removed_ids: Vec<String> = {
            let graph = session
                .graph
                .read()
                .map_err(|e| ApiError::Internal(format!("graph lock poisoned: {e}")))?;
            graph
                .entities
                .iter()
                .filter(|(_, e)| e.dataset_id.as_deref() == Some(&req.dataset_id))
                .map(|(&sid, _)| graph.interner.resolve(sid).to_string())
                .collect()
        };
        let removed_set: HashSet<&str> = removed_ids.iter().map(String::as_str).collect();

        // Mutate the graph.
        let (entities_removed, relations_removed) = {
            let mut graph = session
                .graph
                .write()
                .map_err(|e| ApiError::Internal(format!("graph lock poisoned: {e}")))?;
            graph
                .remove_entities_and_relations_by_dataset(&req.dataset_id)
                .map_err(|e| ApiError::Internal(e.to_string()))?
        };

        // Clean path node pins.
        {
            let mut pins = session
                .path_node_ids
                .write()
                .map_err(|e| ApiError::Internal(format!("path_node_ids poisoned: {e}")))?;
            pins.retain(|id| !removed_set.contains(id.as_str()));
        }
        // Unlink notes that reference removed entities (don't delete the
        // note — analysts may still want the prose).
        {
            let mut notes = session
                .notes
                .write()
                .map_err(|e| ApiError::Internal(format!("notes lock poisoned: {e}")))?;
            for note in notes.iter_mut() {
                if let Some(nid) = &note.node_id {
                    if removed_set.contains(nid.as_str()) {
                        note.node_id = None;
                    }
                }
            }
        }
        // Drop the dataset from the session metadata last.
        session
            .datasets
            .write()
            .map_err(|e| ApiError::Internal(format!("datasets lock poisoned: {e}")))?
            .retain(|d| d.id != req.dataset_id);

        Ok(RemoveDatasetResponse {
            entities_removed,
            relations_removed,
        })
    }

    /// Rename all entities of `from_type` to `to_type` within a single
    /// dataset. Returns the count of entities renamed.
    pub fn rename_type_in_dataset(&self, req: RenameTypeInDatasetRequest) -> ApiResult<usize> {
        let from_et = parse_entity_type(&req.from_type).ok_or_else(|| {
            ApiError::InvalidInput(format!("invalid entity type: {}", req.from_type))
        })?;
        let to_et = parse_entity_type(&req.to_type).ok_or_else(|| {
            ApiError::InvalidInput(format!("invalid entity type: {}", req.to_type))
        })?;
        self.with_graph_write(req.session.as_ref(), |g| {
            Ok(g.rename_entity_type_in_dataset(&req.dataset_id, from_et, to_et))
        })
    }

    /// Return the distinct entity type names observed in `dataset_id`.
    pub fn dataset_entity_types(&self, req: DatasetEntityTypesRequest) -> ApiResult<Vec<String>> {
        self.with_graph_read(req.session.as_ref(), |g| {
            Ok(g.entity_types_in_dataset(&req.dataset_id))
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state::Session;
    use graph_hunter_core::GraphHunter;
    use std::sync::Arc;

    fn api_with_empty_session() -> GraphHunterApi {
        let api = GraphHunterApi::new_noop();
        let s = Arc::new(Session::new("s1", "t", GraphHunter::new(), 0));
        api.sessions().insert(s);
        api.sessions().set_current(Some("s1".to_string()));
        api
    }

    #[test]
    fn list_datasets_empty_ok() {
        let api = api_with_empty_session();
        let ds = api
            .list_datasets(ListDatasetsRequest::default())
            .expect("empty list ok");
        assert!(ds.is_empty());
    }

    #[test]
    fn remove_dataset_nonexistent_returns_zero_counts() {
        let api = api_with_empty_session();
        let r = api
            .remove_dataset(RemoveDatasetRequest {
                session: None,
                dataset_id: "missing".to_string(),
            })
            .expect("removing non-existent dataset is a no-op, not an error");
        assert_eq!(r.entities_removed, 0);
        assert_eq!(r.relations_removed, 0);
    }

    #[test]
    fn rename_type_invalid_type_is_invalid_input() {
        let api = api_with_empty_session();
        let err = api
            .rename_type_in_dataset(RenameTypeInDatasetRequest {
                session: None,
                dataset_id: "d1".to_string(),
                from_type: "".to_string(),
                to_type: "Host".to_string(),
            })
            .unwrap_err();
        assert!(matches!(err, ApiError::InvalidInput(_)));
    }
}
