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
    pub paths: Vec<Vec<std::sync::Arc<str>>>,
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

/// L2 — multi-query batch request. Caller ships N hypotheses;
/// the backend pre-warms the auxiliary indexes (NLF, k-hop
/// reachability) once and then runs each hypothesis through the
/// usual planner dispatch. The first-query latency penalty that
/// the lazy build (heavy-logs #3.5) introduced disappears across
/// the batch — every hypothesis sees a hot index.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RunHuntBatchRequest {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session: Option<SessionHandle>,
    pub hypotheses: Vec<Hypothesis>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub time_window: Option<(i64, i64)>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_results: Option<usize>,
}

/// One element per hypothesis in the request, in order. Each entry
/// carries the same shape as a single `RunHuntResponse`. Errors
/// for individual hypotheses surface as a string in
/// `error` instead of failing the whole batch — partial success is
/// the right shape for SOC-style template batteries where one bad
/// query shouldn't poison the rest.
#[derive(Debug, Clone, Serialize)]
pub struct RunHuntBatchEntry {
    pub paths: Vec<Vec<std::sync::Arc<str>>>,
    pub path_count: usize,
    pub truncated: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub diagnostic: Option<HuntDiagnostic>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct RunHuntBatchResponse {
    pub entries: Vec<RunHuntBatchEntry>,
    /// Whether the auxiliary indexes were already populated when
    /// the batch started. False on the first batch after a session
    /// load (the batch itself paid the build cost); true on
    /// subsequent batches.
    pub indexes_were_warm: bool,
    /// L2 stage 2: number of times the bag cache reused a
    /// previously-materialized `Bag` for a step that another
    /// hypothesis in this batch had already materialized. High
    /// values mean the batch had a lot of shared structure;
    /// `bag_cache_hits + bag_cache_misses` equals the total step
    /// count across Yannakakis-eligible hypotheses.
    #[serde(default)]
    pub bag_cache_hits: usize,
    /// Number of bag materializations the batch ran (one per
    /// distinct (step fingerprint, time window) combination).
    #[serde(default)]
    pub bag_cache_misses: usize,
    /// L2 stage 3a: number of hypotheses that returned a cached
    /// full result (same hypothesis fingerprint + time window
    /// already executed earlier in the batch). Each hit skips
    /// the bag-cache lookup and the enumeration entirely.
    /// Useful for SOC-style template batteries where the same
    /// template is often re-fired with different
    /// `max_results` caps.
    #[serde(default)]
    pub result_cache_hits: usize,
    /// L2 stage 3b: depth at which the longest cached prefix was
    /// resumed for the most recent Yannakakis hypothesis in this
    /// batch (0 = no resume; n_steps - 1 = resumed after the
    /// penultimate step, i.e. only the final step's enumeration
    /// ran). Surfaced as a single value rather than per-entry
    /// to keep the response shape compact; the scalar value is
    /// representative of the bucket-level effectiveness.
    #[serde(default)]
    pub last_prefix_resume_depth: usize,
    /// L2 stage 3b: total number of hypotheses in the batch that
    /// resumed enumeration from a cached prefix snapshot
    /// (depth >= 1).
    #[serde(default)]
    pub prefix_cache_hits: usize,
    /// D3 stage 1: number of LFTJ trie + ts_map builds the batch
    /// performed (one per (graph, time_window) pair). Increments
    /// on the first LFTJ-routed hypothesis in a batch; subsequent
    /// LFTJ hypotheses reuse the cached trie. Reverse-trie builds
    /// (only needed for C6) are counted separately under the same
    /// budget — at most 1 forward + 1 reverse per batch.
    #[serde(default)]
    pub lftj_trie_cache_builds: usize,
    /// D3 stage 1: number of LFTJ-routed hypotheses that reused
    /// the batch's pre-built forward trie + ts_map. Each hit saves
    /// one full O(E) trie build pass plus the per-source dedup-sort.
    #[serde(default)]
    pub lftj_trie_cache_hits: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiffHuntsRequest {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session: Option<SessionHandle>,
    pub hypothesis: Hypothesis,
    pub baseline_ts: i64,
    pub current_ts: i64,
}
