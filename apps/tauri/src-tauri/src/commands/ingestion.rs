//! Tauri ingestion commands.
//!
//! Every command here is a thin delegator to the canonical API — all
//! business logic (format detection, streaming parse, batch dispatch,
//! scoring, event emission) lives in
//! `graph_hunter_api::operations::ingestion`. The streaming variant
//! was moved in F2.16; before that, this file carried a ~600-line
//! background-task handler that duplicated the API's infrastructure.
//! Tauri now only converts State + arguments into the canonical DTOs
//! and maps `ApiError` onto `CommandError`.

use std::sync::Arc;

use graph_hunter_core::FieldConfig;
use tauri::State;

use crate::error::CommandError;
use crate::types::{IngestJobStarted, LoadResult, PcapPreviewResult, PreviewIngestResult};

/// Preview ingestion: detect format and proposed field → entity type mapping.
#[tauri::command]
pub fn cmd_preview_ingest(
    api: State<Arc<graph_hunter_api::GraphHunterApi>>,
    path: String,
    format: String,
) -> Result<PreviewIngestResult, CommandError> {
    api.preview_ingest(graph_hunter_api::dto::ingestion::PreviewIngestRequest { path, format })
        .map_err(CommandError::from)
}

/// PCAP / PCAPNG offline preview. Separate from `cmd_preview_ingest`
/// because the binary content can't survive a UTF-8 `read_to_string`
/// pass and the response shape is richer (top-N IPs / ports / proto
/// mix) than the tabular `detected_fields` model. Frontend dispatches
/// by extension: `.pcap` / `.pcapng` / `.cap` → here; everything else
/// → `cmd_preview_ingest`.
#[tauri::command]
pub fn cmd_pcap_preview(
    api: State<Arc<graph_hunter_api::GraphHunterApi>>,
    path: String,
) -> Result<PcapPreviewResult, CommandError> {
    api.pcap_preview(graph_hunter_api::dto::ingestion::PcapPreviewRequest { path })
        .map_err(CommandError::from)
}

/// Reads a file from disk and ingests its log events into the
/// current session's graph.
#[tauri::command]
pub fn cmd_load_data(
    api: State<Arc<graph_hunter_api::GraphHunterApi>>,
    path: String,
    format: String,
) -> Result<LoadResult, CommandError> {
    api.load_data(graph_hunter_api::dto::ingestion::LoadDataRequest {
        session: None,
        path,
        format,
    })
    .map_err(CommandError::from)
}

/// SIEM ingest (Sentinel or Elastic): fetch via CLI helper then
/// ingest into current session.
#[tauri::command]
pub async fn cmd_ingest_siem(
    api: State<'_, Arc<graph_hunter_api::GraphHunterApi>>,
    params: serde_json::Value,
) -> Result<LoadResult, CommandError> {
    api.ingest_siem(graph_hunter_api::dto::ingestion::IngestSiemRequest {
        session: None,
        params,
    })
    .await
    .map_err(CommandError::from)
}

/// Kicks off a background streaming ingestion and returns the
/// `job_id` / `dataset_id` synchronously. Progress/completion/error
/// events land on the frontend via the canonical `EventEmitter`
/// (wired through `TauriEventEmitter` in `lib.rs`), preserving the
/// `ingest-progress` / `ingest-complete` / `ingest-error` surface the
/// UI already listens on.
#[tauri::command]
pub fn cmd_load_data_streaming(
    api: State<Arc<graph_hunter_api::GraphHunterApi>>,
    path: String,
    format: String,
    config: Option<FieldConfig>,
    date_from: Option<String>,
    date_to: Option<String>,
) -> Result<IngestJobStarted, CommandError> {
    api.load_data_streaming(graph_hunter_api::dto::ingestion::LoadDataStreamingRequest {
        session: None,
        path,
        format,
        config,
        date_from,
        date_to,
    })
    .map_err(CommandError::from)
}
