//! DTOs for analytics over session hub nodes.
//!
//! Distinct from [`crate::dto::v1::session`], which is about the
//! *analyst's* session (load, save, current). These are about the
//! *subject's* sessions — the correlation ids threaded through the
//! ingested telemetry and materialized as graph entities.

use serde::{Deserialize, Serialize};

use crate::state::SessionHandle;

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct SharedSessionsRequest {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session: Option<SessionHandle>,
    /// Cap on rows returned. Defaults to [`DEFAULT_SHARED_SESSION_LIMIT`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub limit: Option<usize>,
}

/// Default row cap. Generous because the finding is rare by nature: on
/// the corpus this was built for, one session out of 60.145 qualified.
pub const DEFAULT_SHARED_SESSION_LIMIT: usize = 500;

/// One session that carried more than one account.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SharedSession {
    pub session_id: String,
    pub accounts: Vec<String>,
    pub addresses: Vec<String>,
    pub first_seen: i64,
    pub last_seen: i64,
    pub duration_seconds: i64,
    pub event_count: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SharedSessionsResponse {
    pub sessions: Vec<SharedSession>,
    /// Session nodes examined. Zero means the graph has no sessions at
    /// all — reported so an empty result is not read as "checked and
    /// found nothing" when the truth is "there was nothing to check".
    pub sessions_examined: usize,
    /// True when `limit` cut the list. Callers must not read a capped
    /// list as the complete answer.
    pub truncated: bool,
    /// Present when `sessions_examined` is zero: why there was nothing
    /// to look at, so the caller does not have to guess.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
}
