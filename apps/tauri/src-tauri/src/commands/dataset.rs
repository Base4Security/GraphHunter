//! Dataset management commands. Delegate to the canonical API.

use std::sync::Arc;

use tauri::State;

use graph_hunter_api::dto::dataset::{
    DatasetEntityTypesRequest, ListDatasetsRequest, RemoveDatasetRequest,
    RenameTypeInDatasetRequest,
};
use graph_hunter_api::GraphHunterApi;

use crate::error::CommandError;
use crate::state::DatasetInfo;

#[tauri::command]
pub fn cmd_list_datasets(
    api: State<Arc<GraphHunterApi>>,
) -> Result<Vec<DatasetInfo>, CommandError> {
    api.list_datasets(ListDatasetsRequest::default())
        .map_err(CommandError::from)
}

/// Returns `(entities_removed, relations_removed)` — kept as a tuple for
/// backward compatibility with the frontend's existing destructure.
#[tauri::command]
pub fn cmd_remove_dataset(
    api: State<Arc<GraphHunterApi>>,
    dataset_id: String,
) -> Result<(usize, usize), CommandError> {
    let resp = api
        .remove_dataset(RemoveDatasetRequest {
            session: None,
            dataset_id,
        })
        .map_err(CommandError::from)?;
    Ok((resp.entities_removed, resp.relations_removed))
}

#[tauri::command]
pub fn cmd_rename_type_in_dataset(
    api: State<Arc<GraphHunterApi>>,
    dataset_id: String,
    from_type: String,
    to_type: String,
) -> Result<usize, CommandError> {
    api.rename_type_in_dataset(RenameTypeInDatasetRequest {
        session: None,
        dataset_id,
        from_type,
        to_type,
    })
    .map_err(CommandError::from)
}

#[tauri::command]
pub fn cmd_dataset_entity_types(
    api: State<Arc<GraphHunterApi>>,
    dataset_id: String,
) -> Result<Vec<String>, CommandError> {
    api.dataset_entity_types(DatasetEntityTypesRequest {
        session: None,
        dataset_id,
    })
    .map_err(CommandError::from)
}
