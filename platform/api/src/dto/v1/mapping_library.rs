//! DTOs for explicit publish/consume against the mapping library.
//!
//! These ride on top of the M5 `MappingLibraryStore`. The review-queue
//! approval hook auto-publishes drafts as a side effect of
//! `agentic_review_approve`; this surface is for the analyst path —
//! force-publish a specific draft (`publish_mapping`) and browse the
//! resulting catalog (`fetch_shared_mappings`).

use serde::{Deserialize, Serialize};

use crate::state::SessionHandle;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PublishMappingRequest {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session: Option<SessionHandle>,
    /// Review-queue draft id to publish. Must reference an existing
    /// draft in the session's review queue (any status — Approved is
    /// the common case but Rejected/Pending are allowed for explicit
    /// override).
    pub draft_id: String,
    /// Optional OCSF category to stamp on the published entry. Useful
    /// when the publisher knows which canonical class the mapping
    /// targets but the draft itself didn't carry that hint.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ocsf_category: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PublishMappingResponse {
    pub mapping_id: String,
    pub fingerprint: String,
    pub published_at: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct FetchSharedMappingsRequest {
    /// Restrict to entries whose fingerprint matches exactly. When
    /// `None`, every published mapping is returned.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fingerprint: Option<String>,
    /// Restrict to entries whose `ocsf_category` matches exactly.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ocsf_category: Option<String>,
    /// Cap on the number of returned summaries. `None` = unlimited.
    /// Newest publications first when `limit` is set.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub limit: Option<usize>,
}

/// Compact summary of one published mapping. Mirrors `SimilarMapping`
/// from `agentic.rs` but is a separate type because this surface owns
/// the publish/consume contract — coupling them would force breaking
/// changes through both sites.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SharedMappingSummary {
    pub mapping_id: String,
    pub fingerprint: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mapping_hash: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ocsf_category: Option<String>,
    pub source: String,
    pub published_at: i64,
    /// Field count from the underlying FieldConfig — surface stat that
    /// lets callers triage at a glance without fetching the full entry.
    pub field_count: usize,
    pub has_vrl: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FetchSharedMappingsResponse {
    pub mappings: Vec<SharedMappingSummary>,
    /// Total entries in the library before `limit` was applied. Lets
    /// the UI render "showing N of M" without a second call.
    pub total: usize,
}
