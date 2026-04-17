//! DTOs for hunt execution and diff.
//!
//! Hunt execution writes into a shared `hunt_cache` (see
//! [`crate::GraphHunterApi::hunt_cache_handle`]). Subsequent
//! `get_hunt_page` calls paginate/score off that cache without re-running
//! the DFS — the killer feature for interactive exploration of huge
//! result sets.

use crate::state::SessionHandle;
use graph_hunter_core::{DedupMode, HuntDiagnostic, Hypothesis, ScoredPath};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RunHuntRequest {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session: Option<SessionHandle>,
    /// The hypothesis to execute. Callers that have the raw DSL can
    /// call [`crate::GraphHunterApi::parse_dsl`] first — this type
    /// takes the parsed AST so the hunt path doesn't re-parse.
    pub hypothesis: Hypothesis,
    /// Optional `(t0, t1)` event-time window (Unix seconds).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub time_window: Option<(i64, i64)>,
    /// Cap on paths materialized before truncation. Default 10 000.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_results: Option<usize>,
}

/// Response shape matching the existing Tauri `HuntResults` for
/// backward compat. When `path_count <= 100` the paths are inlined;
/// larger result sets leave `paths` empty and callers use
/// [`GetHuntPageRequest`] to paginate.
///
/// Only `Serialize` — `HuntDiagnostic` comes from `graph_hunter_core`
/// which does not derive `Deserialize` on it. This type is
/// wire-outgoing only.
#[derive(Debug, Clone, Serialize)]
pub struct RunHuntResponse {
    pub paths: Vec<Vec<String>>,
    pub path_count: usize,
    pub truncated: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub diagnostic: Option<HuntDiagnostic>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GetHuntPageRequest {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session: Option<SessionHandle>,
    pub page: usize,
    pub page_size: usize,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub min_score: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dedup_mode: Option<DedupMode>,
}

/// Only `Serialize` — `ScoredPath` from `graph_hunter_core` is not
/// `Deserialize`. Response-only type.
#[derive(Debug, Clone, Serialize)]
pub struct GetHuntPageResponse {
    pub total_paths: usize,
    pub filtered_paths: usize,
    pub page: usize,
    pub page_size: usize,
    pub paths: Vec<ScoredPath>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiffHuntsRequest {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session: Option<SessionHandle>,
    pub hypothesis: Hypothesis,
    pub baseline_ts: i64,
    pub current_ts: i64,
}
