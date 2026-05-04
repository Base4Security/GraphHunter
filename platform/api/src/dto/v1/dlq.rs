//! DTOs for the dead-letter queue API.

use graph_hunter_core::dlq::{DeadLetter, FailureKind};
use serde::{Deserialize, Serialize};

use crate::state::SessionHandle;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ListDeadLettersRequest {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session: Option<SessionHandle>,
    /// Filter to rows rejected for a specific dataset. Omit for all.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dataset_id: Option<String>,
    /// Filter to a specific failure kind. Omit for all.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub failure_kind: Option<FailureKind>,
    /// Page offset (zero-based). Defaults to 0.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub offset: Option<usize>,
    /// Page size cap. Defaults to 100; server caps at 1000.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub limit: Option<usize>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ListDeadLettersResponse {
    pub entries: Vec<DeadLetter>,
    /// Total across all shards matching the filter (ignoring paging).
    pub total: usize,
    /// `true` when the caller should refetch with `offset += limit`.
    pub has_more: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReingestDeadLetterRequest {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session: Option<SessionHandle>,
    /// IDs of DLQ entries to reingest. Each successful reingest
    /// removes the entry from the DLQ.
    pub dlq_ids: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReingestDeadLetterResponse {
    /// IDs that were reingested + removed from the DLQ.
    pub reingested: Vec<String>,
    /// IDs the caller asked about but that weren't in the DLQ (already
    /// consumed, or never existed).
    pub not_found: Vec<String>,
    /// IDs that matched but whose reingest attempt failed; the entries
    /// stay in the DLQ for another retry.
    pub failed: Vec<ReingestFailure>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReingestFailure {
    pub dlq_id: String,
    pub reason: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PurgeDeadLettersRequest {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session: Option<SessionHandle>,
    /// When true, purge every DLQ entry. When false (default), only
    /// entries matching `failure_kind` and/or `dataset_id` are purged.
    #[serde(default)]
    pub all: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dataset_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub failure_kind: Option<FailureKind>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PurgeDeadLettersResponse {
    pub removed: usize,
}
