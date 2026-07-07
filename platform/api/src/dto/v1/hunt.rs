//! DTOs for hunt execution and diff.
//!
//! Hunt execution writes into a shared `hunt_cache` (see
//! [`crate::GraphHunterApi::hunt_cache_handle`]). Subsequent
//! `get_hunt_page` calls paginate/score off that cache without re-running
//! the DFS — the killer feature for interactive exploration of huge
//! result sets.

use crate::state::SessionHandle;
use graph_hunter_core::{DedupMode, HuntDiagnostic, Hypothesis, LiveTailCoverage, ScoredPath};
use serde::{Deserialize, Serialize};

/// Per-call scoring mode (v2 follow-up — replaces the
/// `enable_anomaly_scoring` latch).
///
/// - `Structural`: ignore any session-installed anomaly scorer for
///   this call and run the plain DFS. Replay-stable: a transcript
///   that calls `run_hunt(scoring=Structural)` produces structural
///   scores regardless of whether prior calls enabled the scorer.
/// - `Anomaly`: ensure the per-session anomaly scorer is enabled and
///   finalized BEFORE running, then use the score-guided smart DFS.
///   Idempotent — repeat calls don't re-finalize.
/// - `Gnn`: same as `Anomaly` from the search-path perspective; the
///   GNN-threat dimension surfaces in the breakdown only when
///   `compute_gnn_scores` has previously run. Kept distinct so the
///   transcript declares intent (and a future weight-set per mode
///   could differentiate).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HuntScoring {
    Structural,
    Anomaly,
    Gnn,
}

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
    /// Per-call scoring override. When `None` (legacy), the call uses
    /// whatever scoring state the session currently has (sticky if a
    /// prior `enable_anomaly_scoring` ran). When `Some`, the value
    /// drives this call deterministically — see [`HuntScoring`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scoring: Option<HuntScoring>,
    /// Optional dedup applied to the raw path list before publishing
    /// to the hunt cache. When `None` (legacy) or `Some(DedupMode::None)`
    /// the cache holds the raw DFS output and the page-read layer can
    /// dedup on demand via [`GetHuntPageRequest::dedup_mode`]. When
    /// set to `ByPath` or `ByEndpoints`, the run-level dedup collapses
    /// duplicates immediately so the response's `path_count` reflects
    /// unique paths and the cache stores unique paths only. Trade-off:
    /// the per-row `edge_count` info that `score_and_paginate_paths`
    /// surfaces is lost (every cached path is implicitly count=1);
    /// callers that need the collapsed counts should leave this `None`
    /// and dedup at page-read instead.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dedup_mode: Option<DedupMode>,
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
    #[serde(skip_serializing_if = "Option::is_none")]
    pub live_tail_coverage: Option<LiveTailCoverage>,
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
    /// Applied to every entry in the batch. Same semantics as
    /// [`RunHuntRequest::dedup_mode`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dedup_mode: Option<DedupMode>,
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
    pub live_tail_coverage: Option<LiveTailCoverage>,
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
    /// D3 stage 2: number of LFTJ-routed hypotheses whose raw
    /// enumeration output was reused from the canonical-form cache
    /// (keyed on (DispatchPlan, time_window)). Each hit skips the
    /// O(m^ρ\*) enumerate work entirely; only per-hypothesis
    /// aggregation runs. The LFTJ enumerators are type-blind today,
    /// so two hypotheses routing to the same DispatchPlan with the
    /// same time_window produce identical raw output regardless of
    /// vertex/edge labels.
    #[serde(default)]
    pub lftj_canonical_cache_hits: usize,
    /// D3 stage 2: number of distinct (DispatchPlan, time_window)
    /// keys for which enumeration ran. Each miss populates the
    /// cache for subsequent canonically-equivalent queries.
    #[serde(default)]
    pub lftj_canonical_cache_misses: usize,
    /// D3 stage 3: true when this batch reused the session-level
    /// LFTJ trie cache (`Session::lftj_cache`) — i.e. the graph's
    /// `mutation_version` matched the cached entry, so the
    /// O(E) trie build was skipped entirely. False when this is
    /// the first LFTJ-routed batch since the last graph mutation.
    /// Distinguishes "warm session" from "cold session"; analysts
    /// or tooling can use this to decide whether the next batch
    /// is expected to be sub-millisecond or whether a build is
    /// pending.
    #[serde(default)]
    pub lftj_session_cache_reused: bool,
    /// D3 stage 4: hypotheses whose raw enumeration output was
    /// served from the *persistent* canonical cache (built in a
    /// previous batch on the same graph version). Distinct from
    /// `lftj_canonical_cache_hits` — that legacy counter captured
    /// per-batch dedup; this one captures cross-batch reuse.
    #[serde(default)]
    pub lftj_persistent_canonical_hits: usize,
    /// D3 stage 4: typed-trie lookups that resolved against the
    /// persistent typed-trie map. A single session that fires
    /// K4-Auth and C6-Connect templates back-to-back keeps both
    /// tries warm; this counts the matches.
    #[serde(default)]
    pub lftj_persistent_trie_hits: usize,
    /// D3 stage 5: bag-cache hits served from the persistent
    /// Session-level Yannakakis cache (`Session::yannakakis_cache`).
    /// Strict subset of `bag_cache_hits` — that legacy counter
    /// captures every bag reuse (within-batch + cross-batch); this
    /// one isolates the cross-batch portion. The Session cache is
    /// FIFO-bounded by total `BagRow` bytes; mutations to the graph
    /// (`add_relation` etc.) bump `mutation_version` and invalidate
    /// the whole cache atomically on the next batch.
    #[serde(default)]
    pub yannakakis_persistent_bag_hits: usize,
    /// D3 stage 5 (prefix companion): prefix-snapshot resumes
    /// served from the persistent Session-level cache. Strict
    /// subset of `prefix_cache_hits`. Same `mutation_version`
    /// invalidation as the bag cache; bounded separately by
    /// `MAX_PREFIX_BYTES`.
    #[serde(default)]
    pub yannakakis_persistent_prefix_hits: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiffHuntsRequest {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session: Option<SessionHandle>,
    pub hypothesis: Hypothesis,
    pub baseline_ts: i64,
    pub current_ts: i64,
}
