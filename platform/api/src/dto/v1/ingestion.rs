//! DTOs for ingestion commands.

use crate::state::SessionHandle;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PreviewIngestRequest {
    pub path: String,
    pub format: String,
}

/// PCAP / PCAPNG offline preview request. PCAP files are binary and
/// don't fit the row/header model that backs [`PreviewIngestResult`],
/// so they get their own command surface. Frontend dispatches by
/// extension: `.pcap` / `.pcapng` / `.cap` → `cmd_pcap_preview`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PcapPreviewRequest {
    pub path: String,
}

/// Re-exported from [`crate::pcap_preview`] so transports see one
/// canonical name for the response shape. The struct itself lives
/// next to the parser so its `serde` derives travel with the
/// implementation.
pub use crate::pcap_preview::{
    IpCount as PcapIpCount, PcapPreviewResult, PortCount as PcapPortCount,
    ProtocolCount as PcapProtocolCount, TimeSpan as PcapTimeSpan,
};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DetectedField {
    pub field_name: String,
    pub suggested_entity_type: String,
    /// Canonical target the core recognizes for this field (e.g. `"source_user"`),
    /// or `None` for unrecognized fields the user must map manually.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub canonical_target: Option<String>,
    /// Number of sample events where this field had a non-empty value.
    #[serde(default, skip_serializing_if = "is_zero")]
    pub occurrence_count: usize,
    /// Up to 5 distinct sample values. Empty when the API couldn't sample
    /// (e.g. legacy preview path for a format that doesn't support sampling).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub sample_values: Vec<String>,
    /// Where the `suggested_entity_type` came from. One of `"name"` (matched
    /// a column-name keyword), `"values"` (value regex matched sample
    /// contents), `"canonical"` (canonical alias table's default), or
    /// `"default"` (fell through to raw column name). Lets the UI show
    /// users *why* we guessed what we guessed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub suggestion_source: Option<String>,
}

fn is_zero(v: &usize) -> bool {
    *v == 0
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PreviewIngestResult {
    pub format: String,
    pub detected_fields: Vec<DetectedField>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoadDataRequest {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session: Option<SessionHandle>,
    pub path: String,
    pub format: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct LoadResult {
    pub new_entities: usize,
    pub new_relations: usize,
    pub total_entities: usize,
    pub total_relations: usize,
    /// True when the parser saw rows but produced no triples — signal for
    /// the UI to show a remap-your-mapping warning.
    #[serde(default)]
    pub zero_triples: bool,
    /// Aggregate parse statistics for this ingest. `None` for legacy parsers
    /// that didn't report stats.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ingest_stats: Option<graph_hunter_core::ParseStats>,
    /// Post-ingest data-quality notices: shared-infra IP detection,
    /// likely-duplicate user identities, etc. Empty when no patterns
    /// fired. Surfaced read-only in DatasetCard so the analyst can see
    /// the engine flagged the structural issues without changing the
    /// ingested triples.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub warnings: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IngestSiemRequest {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session: Option<SessionHandle>,
    pub params: serde_json::Value,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoadDataWithConfigRequest {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session: Option<SessionHandle>,
    pub path: String,
    pub config: graph_hunter_core::FieldConfig,
}

/// Kicks off a background streaming ingestion. The caller gets back the
/// `job_id` / `dataset_id` synchronously; progress + completion are
/// pushed through the API's [`EventEmitter`] under the `ingest-progress`,
/// `ingest-complete`, and `ingest-error` event names.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoadDataStreamingRequest {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session: Option<SessionHandle>,
    pub path: String,
    pub format: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub config: Option<graph_hunter_core::FieldConfig>,
    /// Optional lower bound for line-based formats (IIS/CSV). Compared
    /// lexicographically against the first 10 bytes of each line
    /// (ISO `YYYY-MM-DD` sorts correctly that way).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub date_from: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub date_to: Option<String>,
}

// ── Background ingest events (consumed by `cmd_load_data_streaming`) ──

/// Response returned immediately when background ingestion starts.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct IngestJobStarted {
    pub job_id: String,
    pub dataset_id: String,
}

/// Emitted when background ingestion completes successfully.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct IngestComplete {
    pub job_id: String,
    pub dataset_id: String,
    pub result: LoadResult,
}

/// Emitted when background ingestion fails.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct IngestError {
    pub job_id: String,
    pub dataset_id: String,
    pub error: String,
}

/// Fire-and-forget telemetry emitted on every LLM-as-compiler
/// dispatcher decision so the analyst always sees which path was
/// taken. Without it, a silent fall-back to heuristic that produces
/// zero triples is indistinguishable from a parser bug. The
/// frontend renders this as a status-log entry; the analyst only
/// needs to act on it when the outcome is `llm_proposal` (which also
/// gets a separate `IngestLlmProposal` with the full diff).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct IngestLlmDiagnostic {
    pub job_id: String,
    pub dataset_id: String,
    /// One of `heuristic_ok`, `llm_proposal`, `llm_unavailable`.
    /// Stable strings so the frontend can switch on them.
    pub outcome: String,
    /// Human-readable explanation of why the dispatcher chose this
    /// path. Includes mapping counts for `heuristic_ok`, the failure
    /// mode for `llm_unavailable`, and a brief teaser for
    /// `llm_proposal` (the full diff travels in the separate
    /// `IngestLlmProposal` event).
    pub reason: String,
    /// Backend identifier (e.g. `candle-phi3-q4` or `mock`). `None`
    /// when the dispatcher short-circuited on `HeuristicOk` and never
    /// asked the backend for its id.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub backend_id: Option<String>,
}

/// Emitted by the LLM-as-compiler dispatcher (Phase C) when the
/// heuristic config was weak (zero Node mappings) and the LLM
/// produced a refined alternative. Streaming was halted before any
/// triples landed; the frontend confirm banner renders the diff and
/// re-triggers ingest with the analyst's chosen `FieldConfig` via
/// `cmd_load_data_streaming` (passing `config = chosen`).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct IngestLlmProposal {
    pub job_id: String,
    pub dataset_id: String,
    /// Original file path, so the frontend can re-trigger ingest with
    /// the chosen config. Tauri commands pass it back unchanged.
    pub source_path: String,
    /// Format the dispatcher resolved for the source.
    pub format: String,
    /// Heuristic-produced FieldConfig (zero-Node, low confidence).
    /// Serialized as `serde_json::Value` so the frontend can render
    /// it as-is without extra type duplication.
    pub heuristic: serde_json::Value,
    /// LLM-refined FieldConfig with one or more Node mappings.
    pub refined: serde_json::Value,
    /// Field-by-field diff between heuristic and refined. Shape:
    /// `{added: [...], removed: [...], changed: [...], unchanged_count: u}`.
    pub diff: serde_json::Value,
    pub confidence: f32,
    pub backend_id: String,
}
