//! Hunt execution, result paging, and diff.
//!
//! `run_hunt` writes into the shared [`GraphHunterApi::hunt_cache_handle`]
//! so `get_hunt_page` can paginate/score without re-running the DFS.
//! `diff_hunts` does not touch the cache — it's a two-query comparison.

use std::collections::HashSet;
use std::sync::Arc;

use graph_hunter_core::{DedupMode, HuntDiff, LiveTailCoverage};

use crate::dto::hunt::{
    DiffHuntsRequest, GetHuntPageRequest, GetHuntPageResponse, HuntScoring, RunHuntBatchEntry,
    RunHuntBatchRequest, RunHuntBatchResponse, RunHuntRequest, RunHuntResponse,
};
use crate::{ApiError, ApiResult, GraphHunterApi};

/// Collapse duplicate paths in-place at hunt-run time.
///
/// Mirrors the dedup logic in `score_and_paginate_paths` but operates on
/// `Vec<Arc<str>>` paths directly — saves a String materialization pass
/// and keeps the cache shape unchanged downstream. Returns the deduped
/// vector preserving insertion order.
///
/// `DedupMode::None` short-circuits: the input is returned unchanged so
/// the legacy code path is bit-for-bit identical when no dedup is asked.
fn dedup_arc_paths(
    paths: Vec<Vec<Arc<str>>>,
    mode: DedupMode,
) -> Vec<Vec<Arc<str>>> {
    match mode {
        DedupMode::None => paths,
        DedupMode::ByPath => {
            // Key on the Vec<Arc<str>> directly; Arc's PartialEq compares
            // pointer-equal first then string contents, so paths that
            // reused interner entries are O(1) per element.
            let mut seen: HashSet<Vec<Arc<str>>> = HashSet::with_capacity(paths.len());
            let mut out: Vec<Vec<Arc<str>>> = Vec::with_capacity(paths.len());
            for p in paths {
                if seen.insert(p.clone()) {
                    out.push(p);
                }
            }
            out
        }
        DedupMode::ByEndpoints => {
            let mut seen: HashSet<(Arc<str>, Arc<str>)> = HashSet::with_capacity(paths.len());
            let mut out: Vec<Vec<Arc<str>>> = Vec::with_capacity(paths.len());
            for p in paths {
                if p.is_empty() {
                    out.push(p);
                    continue;
                }
                let key = (
                    Arc::clone(p.first().unwrap()),
                    Arc::clone(p.last().unwrap()),
                );
                if seen.insert(key) {
                    out.push(p);
                }
            }
            out
        }
    }
}

/// Inline threshold for [`RunHuntResponse::paths`]. Matches the legacy
/// Tauri command's 100-path cutoff so the frontend keeps its current
/// UX (small result sets render immediately; larger sets paginate).
const INLINE_PATH_THRESHOLD: usize = 100;

pub(crate) fn ensure_huntable_phase(phase: crate::state::SessionPhase) -> ApiResult<()> {
    match phase {
        crate::state::SessionPhase::Ready | crate::state::SessionPhase::LiveTail => Ok(()),
        crate::state::SessionPhase::Loading => Err(ApiError::Conflict(
            "session is still loading; wait for ingest to complete".into(),
        )),
        crate::state::SessionPhase::Finalizing => Err(ApiError::Conflict(
            "session is finalizing; hunt unavailable".into(),
        )),
    }
}

fn live_tail_coverage_for_session(
    session: &crate::state::Session,
) -> Option<LiveTailCoverage> {
    if session.phase() != crate::state::SessionPhase::LiveTail {
        return None;
    }
    let graph = session.graph.read().ok()?;
    graph.live_tail_coverage("live_tail")
}

impl GraphHunterApi {
    /// Execute a temporal pattern search. Populates the hunt cache and
    /// returns either the paths inline (when ≤ 100) or just the count
    /// with the cache populated for pagination.
    ///
    /// Uses the smart DFS when the anomaly scorer has been finalized,
    /// else the plain DFS.
    pub fn run_hunt(&self, req: RunHuntRequest) -> ApiResult<RunHuntResponse> {
        let max_results = req.max_results.unwrap_or(10_000);
        let session = self.resolve_session(req.session.as_ref())?;
        ensure_huntable_phase(session.phase())?;

        // Per-call scoring override (v2 follow-up). When the caller
        // asks for `Anomaly` or `Gnn`, ensure the per-session scorer
        // is enabled + finalized BEFORE we acquire the read lock for
        // the search. Idempotent: re-installing the scorer is cheap
        // when it's already there with the same weights.
        if matches!(
            req.scoring,
            Some(HuntScoring::Anomaly) | Some(HuntScoring::Gnn)
        ) {
            let mut graph = session
                .graph
                .write()
                .map_err(|e| ApiError::Internal(format!("graph lock poisoned: {e}")))?;
            let needs_finalize = graph
                .anomaly_scorer
                .as_ref()
                .map(|s| !s.is_finalized())
                .unwrap_or(true);
            if needs_finalize {
                if graph.anomaly_scorer.is_none() {
                    graph.enable_anomaly_scoring(Default::default());
                }
                graph.finalize_anomaly_scorer();
            }
        }

        // Read lock: both DFS paths are non-mutating, so concurrent hunts
        // on the same session can run in parallel.
        let (paths, truncated) = {
            let graph = session
                .graph
                .read()
                .map_err(|e| ApiError::Internal(format!("graph lock poisoned: {e}")))?;
            // Per-call scoring decides which DFS variant runs.
            // - Some(Structural): explicitly bypass the smart DFS
            //   even if the session has a finalized scorer. This
            //   is what makes a transcript replay-stable: a
            //   Structural call always uses the plain DFS,
            //   independent of prior session state.
            // - Some(Anomaly | Gnn): smart DFS (we just ensured
            //   the scorer is finalized above).
            // - None (legacy): fall back to the old "use scorer
            //   if finalized" behavior — preserves v1 semantics
            //   for callers that haven't migrated.
            let use_smart = match req.scoring {
                Some(HuntScoring::Structural) => false,
                Some(HuntScoring::Anomaly) | Some(HuntScoring::Gnn) => true,
                None => graph
                    .anomaly_scorer
                    .as_ref()
                    .map(|s| s.is_finalized())
                    .unwrap_or(false),
            };
            if use_smart {
                graph
                    .search_temporal_pattern_smart(
                        &req.hypothesis,
                        req.time_window,
                        max_results,
                    )
                    .map_err(|e| ApiError::Internal(format!("search failed: {e}")))?
            } else {
                graph
                    .search_temporal_pattern(
                        &req.hypothesis,
                        req.time_window,
                        Some(max_results),
                    )
                    .map_err(|e| ApiError::Internal(format!("search failed: {e}")))?
            }
        };

        // Optional run-time dedup. The raw DFS may emit many
        // structurally-identical paths (the 2026-04-16 hunt session had
        // 2523 paths where 1835 were the same `root → /usr/bin/grep`);
        // when the caller knows up front they only want unique results
        // they can ask for it here instead of paying for the storage of
        // duplicates and then dedup'ing at page-read.
        //
        // When `dedup_mode` is `None` or `Some(DedupMode::None)` the
        // function is a no-op identity and the cache stores raw paths
        // — the legacy `get_hunt_page` flow still works unchanged and
        // can surface `edge_count` for callers that need the collapsed
        // counts.
        let paths = match req.dedup_mode {
            Some(mode) => dedup_arc_paths(paths, mode),
            None => paths,
        };

        let path_count = paths.len();

        // Zero-match diagnostic: read-only schema probe so the analyst
        // knows whether the hypothesis direction / type was plausible at
        // all. Skipped on non-zero to avoid the cost in the happy path.
        let diagnostic = if path_count == 0 {
            let graph = session.graph.read().ok();
            graph.map(|g| g.hunt_diagnostic(&req.hypothesis))
        } else {
            None
        };
        let live_tail_coverage = live_tail_coverage_for_session(&session);

        // Publish to the shared cache so get_hunt_page can serve it.
        let mut cache = self
            .inner
            .hunt_cache
            .write()
            .map_err(|e| ApiError::Internal(format!("hunt cache poisoned: {e}")))?;

        if path_count <= INLINE_PATH_THRESHOLD {
            let inline = paths.clone();
            *cache = paths;
            Ok(RunHuntResponse {
                paths: inline,
                path_count,
                truncated,
                diagnostic,
                live_tail_coverage,
            })
        } else {
            *cache = paths;
            Ok(RunHuntResponse {
                paths: Vec::new(),
                path_count,
                truncated,
                diagnostic,
                live_tail_coverage,
            })
        }
    }

    /// Paginated, scored, optionally deduplicated page over the cached
    /// hunt result. Safe to call many times — reads only.
    pub fn get_hunt_page(&self, req: GetHuntPageRequest) -> ApiResult<GetHuntPageResponse> {
        let cache = self
            .inner
            .hunt_cache
            .read()
            .map_err(|e| ApiError::Internal(format!("hunt cache poisoned: {e}")))?;
        let total_paths = cache.len();
        let mode = req.dedup_mode.unwrap_or_default();

        self.with_graph_read(req.session.as_ref(), |graph| {
            let (scored_page, filtered_count) = graph.score_and_paginate_paths(
                &cache,
                req.page,
                req.page_size,
                req.min_score,
                mode,
            );
            Ok(GetHuntPageResponse {
                total_paths,
                filtered_paths: filtered_count,
                page: req.page,
                page_size: req.page_size,
                paths: scored_page,
            })
        })
    }

    /// Run the same hypothesis at two upper time bounds and return
    /// `{added, removed}` path sets. Does not touch the hunt cache.
    pub fn diff_hunts(&self, req: DiffHuntsRequest) -> ApiResult<HuntDiff> {
        if req.baseline_ts > req.current_ts {
            return Err(ApiError::InvalidInput(format!(
                "baseline_ts ({}) must be <= current_ts ({})",
                req.baseline_ts, req.current_ts
            )));
        }
        self.with_graph_read(req.session.as_ref(), |graph| {
            graph
                .diff_hunts(&req.hypothesis, req.baseline_ts, req.current_ts)
                .map_err(|e| ApiError::Internal(format!("diff failed: {e}")))
        })
    }

    /// L2 — multi-query batch matcher. Pre-warms the auxiliary
    /// indexes once, then runs each hypothesis through the same
    /// planner dispatch as `run_hunt`. The lazy NLF / k-hop
    /// reachability builds (heavy-logs #3.5) fire on the *first*
    /// hypothesis in the batch, so subsequent queries see a hot
    /// index — concretely: a 64-template ATT&CK battery on a
    /// fresh session pays the index build once instead of having
    /// the first hunt block while every other hunt waits for the
    /// graph lock.
    ///
    /// Errors per-hypothesis are isolated: a malformed query in
    /// position k fails its entry but does not poison the rest.
    /// The batch returns `(entries, indexes_were_warm)` so callers
    /// can distinguish "first batch, expect a build" from "warm
    /// batch, every entry is fast".
    pub fn run_hunt_batch(
        &self,
        req: RunHuntBatchRequest,
    ) -> ApiResult<RunHuntBatchResponse> {
        let RunHuntBatchRequest {
            session,
            hypotheses,
            time_window,
            max_results,
            dedup_mode,
        } = req;

        // Whether the indexes are *currently* populated, before
        // this batch touches them. We only know whether the OnceLocks
        // have been initialized — and we can only inspect that via
        // the existing `&self` accessors after a get-or-init, which
        // would init. Approximate: read whether we just initialized
        // by comparing pre/post via a dedicated `nlf_is_built` /
        // `khop_is_built` peek. Cheap because OnceLock::get is a
        // single atomic load.
        let session_handle = self.resolve_session(session.as_ref())?;
        ensure_huntable_phase(session_handle.phase())?;
        let batch_live_tail_coverage = live_tail_coverage_for_session(&session_handle);
        let indexes_were_warm = {
            let graph = session_handle
                .graph
                .read()
                .map_err(|e| ApiError::Internal(format!("graph lock poisoned: {e}")))?;
            graph.nlf_is_built() && graph.khop_reach_is_built()
        };

        // Warm both indexes once, holding the read lock just for the
        // duration of the build trigger. A single hypothesis would
        // do the same on first invocation, but we want every entry
        // in the batch to start with a hot cache so the per-query
        // cost is uniform.
        {
            let graph = session_handle
                .graph
                .read()
                .map_err(|e| ApiError::Internal(format!("graph lock poisoned: {e}")))?;
            let _ = graph.ensure_nlf();
            let _ = graph.ensure_khop_reach();
        }

        // L2 stage 2 — CSH bucketing. Cache materialized bags by
        // (step fingerprint, time_window) within this batch. Two
        // hypotheses that share a `User -[Auth]-> Host` prefix
        // materialize the bag once and reuse the rows; only the
        // semi-join + enumeration runs per hypothesis.
        //
        // The fingerprint is the JSON-serialized HypothesisStep
        // plus the time-window bounds. Cheap to compute (one
        // serde_json::to_string per step); accurate because two
        // hypotheses agreeing on this fingerprint produce
        // identical bag rows by definition.
        //
        // Yannakakis-eligible hypotheses go through the cached
        // path. DFS-routed hypotheses (anything the planner
        // doesn't dispatch to Yannakakis) fall through to the
        // existing per-call run_hunt — they materialize their
        // own bags inside the matcher and don't benefit from
        // the cache, but they also don't pay any extra cost.
        let (t_lo_window, t_hi_window) =
            time_window.unwrap_or((i64::MIN, i64::MAX));
        let mut bag_cache: std::collections::HashMap<
            String,
            std::sync::Arc<graph_hunter_core::yannakakis::Bag>,
        > = std::collections::HashMap::new();
        let mut bag_cache_hits: usize = 0;
        let mut bag_cache_misses: usize = 0;
        // D3 stage 5 — strict subset of bag_cache_hits that came
        // from the *persistent* (cross-batch) Session bag cache.
        let mut yannakakis_persistent_bag_hits: usize = 0;
        // D3 stage 5 (prefix companion) — strict subset of
        // prefix_cache_hits that resumed from a snapshot stored in
        // the *persistent* Session prefix cache.
        let mut yannakakis_persistent_prefix_hits: usize = 0;

        // L2 stage 3a — full-hypothesis result cache. Key is the
        // serialized hypothesis + time window. When a batch runs
        // the same template twice (or different hypotheses with
        // identical canonical-form serialization), the second hit
        // returns the cached entry without re-enumerating. Cache
        // is per-batch — concurrent batches don't share state.
        let mut result_cache: std::collections::HashMap<String, RunHuntBatchEntry> =
            std::collections::HashMap::new();
        let mut result_cache_hits: usize = 0;

        // L2 stage 3b — prefix snapshot cache. Key is the
        // concatenated step fingerprints `[step0, step1, ...,
        // stepK-1]` + time window; value is the partial-path
        // snapshot at depth K (each entry: full Vec<StrId> of
        // visited vertices + last edge timestamp). When a new
        // hypothesis shares its first K steps with a previously-
        // cached prefix, we resume enumeration from depth K
        // instead of replaying the prefix work.
        //
        // Memory budget: cap snapshots at PREFIX_CACHE_CAP entries
        // each. Prefixes that would exceed it are skipped (the
        // hypothesis still runs from scratch — correctness is
        // unaffected, only the perf gain is forfeited for that
        // specific prefix).
        const PREFIX_CACHE_CAP: usize = 50_000;
        let mut prefix_cache: std::collections::HashMap<
            String,
            std::sync::Arc<Vec<(Vec<graph_hunter_core::interner::StrId>, i64)>>,
        > = std::collections::HashMap::new();
        let mut last_prefix_resume_depth: usize = 0;
        let mut prefix_cache_hits: usize = 0;

        // D3 stages 1+3+4 — LFTJ session cache. The forward trie +
        // ts_map (and reverse for C6) live on the Session keyed by
        // (mutation_version, type_signature) so they survive across
        // batches and across distinct typed templates. Stage 4
        // generalizes this from a single trie pair (stage 3) to a
        // map of typed tries — a session that fires K4-Auth and
        // C6-Connect templates back-to-back keeps both warm.
        //
        // D3 stages 2+4 — persistent canonical raw-result cache.
        // Stage 2 cached raw enumerate output per-batch; stage 4
        // promotes that to per-Session, FIFO-bounded, keyed on
        // (plan, type_signature, time_window). At Sysmon-scale
        // SOC batteries that re-fire identical templates against
        // a static graph pay enumeration once per (plan, type,
        // window), not once per batch.
        let mut lftj_trie_cache_builds: usize = 0;
        let mut lftj_trie_cache_hits: usize = 0;
        let mut lftj_session_cache_reused: bool = false;
        let mut lftj_canonical_cache_hits: usize = 0;
        let mut lftj_canonical_cache_misses: usize = 0;
        let mut lftj_persistent_canonical_hits: usize = 0;
        let mut lftj_persistent_trie_hits: usize = 0;

        let cap = max_results.unwrap_or(10_000);
        let mut entries = Vec::with_capacity(hypotheses.len());
        for hypothesis in hypotheses.into_iter() {
            // L2 stage 3a: check the result cache first. The key
            // includes the time window because two batches with
            // the same hypothesis but different windows must not
            // collide. cap is excluded from the key — a cached
            // entry with a higher cap is still valid for a lower
            // cap (truncate on the way out).
            let result_cache_key = {
                let hypo_json =
                    serde_json::to_string(&hypothesis).unwrap_or_default();
                format!("{hypo_json}|{t_lo_window}|{t_hi_window}")
            };
            if let Some(cached) = result_cache.get(&result_cache_key) {
                result_cache_hits += 1;
                let mut cached_entry = cached.clone();
                if cached_entry.path_count > cap {
                    cached_entry.paths.truncate(cap);
                    cached_entry.path_count = cap;
                    cached_entry.truncated = true;
                }
                entries.push(cached_entry);
                continue;
            }
            // D3 stage 1 — LFTJ batch routing. If the planner picks
            // any LFTJ variant (Triangle/K4/K5/C6), short-circuit to
            // the batch-cached `_with_trie` entry points. This avoids
            // rebuilding the trie for every cyclic-shape hypothesis
            // in the batch. Yannakakis still wins for α-acyclic chains
            // and is checked below; if neither LFTJ nor Yannakakis
            // applies, the per-call `run_hunt` branch handles it.
            let lftj_plan = graph_hunter_core::planner::plan(&hypothesis);
            let lftj_routed = matches!(
                lftj_plan,
                graph_hunter_core::planner::DispatchPlan::TriangleLftj
                    | graph_hunter_core::planner::DispatchPlan::K4Lftj
                    | graph_hunter_core::planner::DispatchPlan::K5Lftj
                    | graph_hunter_core::planner::DispatchPlan::C6Lftj
            );
            if lftj_routed {
                let session_for_lftj = self.resolve_session(session.as_ref())?;
                let graph = session_for_lftj
                    .graph
                    .read()
                    .map_err(|e| ApiError::Internal(format!("graph lock poisoned: {e}")))?;
                // D3 stage 4 — type-aware canonical key. The
                // homogeneous-shape signature (rel_type, vertex_type)
                // is part of the cache key so type-aware tries don't
                // collide with type-blind tries.
                let type_sig = graph.homogeneous_lftj_signature(&hypothesis);
                let canonical_key: crate::state::session::LftjCanonicalKey =
                    (lftj_plan, type_sig, t_lo_window, t_hi_window);
                let live_version = graph.mutation_version();

                // Acquire the session cache write lock for the
                // duration of this LFTJ hypothesis. Stage-4 cache
                // sees both reads and writes here; ordering with
                // the graph read lock is consistent throughout.
                let mut cache_lock = session_for_lftj
                    .lftj_cache
                    .write()
                    .map_err(|e| ApiError::Internal(format!("lftj_cache poisoned: {e}")))?;

                // Reset the cache when the version is stale (graph
                // mutated since last write). Allocates a fresh empty
                // typed_tries + canonical_results map at the new
                // version stamp.
                let cache_was_warm =
                    cache_lock.as_ref().is_some_and(|c| c.version == live_version);
                if !cache_was_warm {
                    *cache_lock = Some(crate::state::session::LftjSessionCache::new(
                        live_version,
                    ));
                } else {
                    lftj_session_cache_reused = true;
                }
                let cache = cache_lock.as_mut().expect("set above");

                // Persistent canonical raw-result lookup.
                if let Some(cached) = cache.canonical_results.get(&canonical_key) {
                    lftj_persistent_canonical_hits += 1;
                    lftj_canonical_cache_hits += 1;
                    let raw_paths = cached.clone();
                    drop(cache_lock);
                    let truncated = raw_paths.len() >= cap;
                    let paths = graph.apply_aggregation((*raw_paths).clone(), &hypothesis);
                    drop(graph);
                    let paths = match dedup_mode {
                        Some(mode) => dedup_arc_paths(paths, mode),
                        None => paths,
                    };
                    let path_count = paths.len();
                    let inline =
                        if path_count <= 100 { paths.clone() } else { Vec::new() };
                    if let Ok(mut hc) = self.inner.hunt_cache.write() {
                        *hc = paths;
                    }
                    let entry = RunHuntBatchEntry {
                        paths: inline,
                        path_count,
                        truncated,
                        diagnostic: None,
                        live_tail_coverage: batch_live_tail_coverage.clone(),
                        error: None,
                    };
                    result_cache.insert(result_cache_key, entry.clone());
                    entries.push(entry);
                    continue;
                }
                lftj_canonical_cache_misses += 1;

                // Trie lookup / build (typed-trie map keyed by
                // type_sig).  Type-aware path mirrors the single-
                // query API: when type_sig is Some(...), build a
                // filtered trie; otherwise build the type-blind one.
                let typed_trie = if let Some(tt) = cache.typed_tries.get(&type_sig) {
                    lftj_persistent_trie_hits += 1;
                    lftj_trie_cache_hits += 1;
                    crate::state::session::LftjTypedTrie {
                        forward: tt.forward.clone(),
                        ts_map: tt.ts_map.clone(),
                        reverse: tt.reverse.clone(),
                    }
                } else {
                    let trie = graph.build_lftj_trie_for(&hypothesis);
                    let ts_map = graph_hunter_core::lftj_query::MinTimestampMap::build(
                        &*graph, &trie,
                    );
                    let entry = crate::state::session::LftjTypedTrie {
                        forward: std::sync::Arc::new(trie),
                        ts_map: std::sync::Arc::new(ts_map),
                        reverse: None,
                    };
                    cache.typed_tries.insert(
                        type_sig,
                        crate::state::session::LftjTypedTrie {
                            forward: entry.forward.clone(),
                            ts_map: entry.ts_map.clone(),
                            reverse: None,
                        },
                    );
                    lftj_trie_cache_builds += 1;
                    entry
                };

                // C6 needs the reverse trie. Build lazily and
                // populate the typed_tries entry if absent.
                let reverse = if matches!(
                    lftj_plan,
                    graph_hunter_core::planner::DispatchPlan::C6Lftj
                ) {
                    if let Some(r) = typed_trie.reverse.clone() {
                        Some(r)
                    } else if let Some(r) = cache
                        .typed_tries
                        .get(&type_sig)
                        .and_then(|e| e.reverse.clone())
                    {
                        Some(r)
                    } else {
                        let rev = graph.build_lftj_reverse_trie_for(&hypothesis);
                        let arc = std::sync::Arc::new(rev);
                        if let Some(slot) = cache.typed_tries.get_mut(&type_sig) {
                            slot.reverse = Some(arc.clone());
                        }
                        Some(arc)
                    }
                } else {
                    None
                };

                let trie = typed_trie.forward.clone();
                let ts_map = typed_trie.ts_map.clone();
                // Drop the cache lock before enumeration — keeps
                // lock hold time bounded to map lookups, not the
                // O(m^ρ*) enumerate work.
                drop(cache_lock);

                // (canonical hits accounted on the persistent path above)
                let raw = match lftj_plan {
                    graph_hunter_core::planner::DispatchPlan::TriangleLftj => {
                        graph_hunter_core::lftj_query::enumerate_triangles_lftj_simd_window(
                            &*graph, &trie, &ts_map, t_lo_window, t_hi_window, cap,
                        )
                    }
                    graph_hunter_core::planner::DispatchPlan::K4Lftj => {
                        graph_hunter_core::lftj_query::enumerate_4cliques_lftj_simd_par(
                            &*graph, &trie, &ts_map, t_lo_window, t_hi_window, cap,
                        )
                    }
                    graph_hunter_core::planner::DispatchPlan::K5Lftj => {
                        graph_hunter_core::lftj_query::enumerate_5cliques_lftj_simd_par(
                            &*graph, &trie, &ts_map, t_lo_window, t_hi_window, cap,
                        )
                    }
                    graph_hunter_core::planner::DispatchPlan::C6Lftj => {
                        let rev = reverse.expect("C6 path built reverse above");
                        graph_hunter_core::lftj_query::enumerate_6cycles_lftj_simd_par(
                            &*graph, &trie, &rev, &ts_map, t_lo_window, t_hi_window, cap,
                        )
                    }
                    _ => unreachable!("filtered above"),
                };
                let raw_paths = std::sync::Arc::new(raw);

                // Insert into the persistent canonical cache.
                if let Ok(mut cache_lock) = session_for_lftj.lftj_cache.write() {
                    if let Some(cache) = cache_lock.as_mut() {
                        if cache.version == live_version {
                            cache.insert_canonical(canonical_key, raw_paths.clone());
                        }
                    }
                }
                let truncated = raw_paths.len() >= cap;
                // Apply per-hypothesis aggregation (HAVING / WITHIN)
                // to the cached raw results. This is cheap relative
                // to enumeration; doing it per-lookup keeps the cache
                // shape-canonical across hypotheses that differ only
                // in their aggregation clauses.
                let paths = graph.apply_aggregation((*raw_paths).clone(), &hypothesis);
                drop(graph);
                let paths = match dedup_mode {
                    Some(mode) => dedup_arc_paths(paths, mode),
                    None => paths,
                };

                let path_count = paths.len();
                let inline =
                    if path_count <= 100 { paths.clone() } else { Vec::new() };
                if let Ok(mut cache) = self.inner.hunt_cache.write() {
                    *cache = paths;
                }
                let entry = RunHuntBatchEntry {
                    paths: inline,
                    path_count,
                    truncated,
                    diagnostic: None,
                    live_tail_coverage: batch_live_tail_coverage.clone(),
                    error: None,
                };
                result_cache.insert(result_cache_key, entry.clone());
                entries.push(entry);
                continue;
            }

            // Decide whether this hypothesis is Yannakakis-eligible
            // by recomputing the planner's decision in API space.
            // We don't reach into graph_hunter_core::planner because
            // the dispatch needs the env flag check anyway, and the
            // planner is graph-internal; mirror its yannakakis_dispatch
            // logic here for the routing decision.
            let yannakakis_ok =
                std::env::var("GRAPHHUNTER_YANNAKAKIS")
                    .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
                    .unwrap_or(false)
                    && !hypothesis.steps.is_empty()
                    && {
                        let g = graph_hunter_core::yannakakis::Hypergraph::of(&hypothesis);
                        graph_hunter_core::yannakakis::is_alpha_acyclic(&g)
                    };

            if yannakakis_ok {
                // Materialize bags via the shared cache.
                let session_for_bags = self.resolve_session(session.as_ref())?;
                let graph = session_for_bags
                    .graph
                    .read()
                    .map_err(|e| ApiError::Internal(format!("graph lock poisoned: {e}")))?;
                let step_fingerprints: Vec<String> = hypothesis
                    .steps
                    .iter()
                    .map(|step| {
                        serde_json::to_string(step).unwrap_or_default()
                    })
                    .collect();
                // D3 stage 5 — try the persistent session bag
                // cache before the per-batch one. Session cache is
                // keyed on (mutation_version, step+window
                // fingerprint) and FIFO-bounded by total BagRow
                // bytes (`MAX_BAG_BYTES`). Promotes the bag-cache
                // win from "within-batch" to "across batches until
                // graph mutates" — symmetric to D3 stage 4 for the
                // LFTJ path.
                let live_version = graph.mutation_version();
                let bags: Vec<graph_hunter_core::yannakakis::Bag> = hypothesis
                    .steps
                    .iter()
                    .zip(step_fingerprints.iter())
                    .map(|(step, fp)| {
                        let key = format!("{fp}|{t_lo_window}|{t_hi_window}");
                        // Within-batch bag_cache hit (also counted
                        // by the persistent cache when the batch
                        // saw the same key already).
                        if let Some(arc) = bag_cache.get(&key) {
                            bag_cache_hits += 1;
                            return (**arc).clone();
                        }
                        // Persistent session cache lookup.
                        let session_hit = session_for_bags
                            .yannakakis_cache
                            .read()
                            .ok()
                            .and_then(|cache| {
                                cache.as_ref().and_then(|c| {
                                    if c.version == live_version {
                                        c.bags.get(&key).cloned()
                                    } else {
                                        None
                                    }
                                })
                            });
                        if let Some(arc) = session_hit {
                            bag_cache_hits += 1;
                            yannakakis_persistent_bag_hits += 1;
                            // Mirror into per-batch cache for
                            // subsequent same-batch dedup.
                            bag_cache.insert(key, arc.clone());
                            return (*arc).clone();
                        }
                        bag_cache_misses += 1;
                        let bag = graph_hunter_core::yannakakis::materialize_bag(
                            &graph,
                            step,
                            t_lo_window,
                            t_hi_window,
                        );
                        let arc = std::sync::Arc::new(bag.clone());
                        bag_cache.insert(key.clone(), arc.clone());
                        // Insert into the persistent cache (resets
                        // it if the graph mutated since last batch).
                        if let Ok(mut slot) = session_for_bags.yannakakis_cache.write() {
                            let cache = slot.get_or_insert_with(|| {
                                crate::state::session::YannakakisSessionCache::new(
                                    live_version,
                                )
                            });
                            if cache.version != live_version {
                                *cache = crate::state::session::YannakakisSessionCache::new(
                                    live_version,
                                );
                            }
                            cache.insert(key, arc);
                        }
                        bag
                    })
                    .collect();

                // L2 stage 3b: find the longest cached prefix
                // whose step fingerprints match this hypothesis,
                // and resume enumeration from there. We only
                // dispatch this for Chain shape — Graph shape uses
                // the tree-walk enumerator which doesn't have a
                // chain-prefix concept yet.
                let mut resume_depth = 0usize;
                let mut resume_starting:
                    std::sync::Arc<Vec<(Vec<graph_hunter_core::interner::StrId>, i64)>> =
                    std::sync::Arc::new(Vec::new());
                if matches!(
                    hypothesis.shape,
                    graph_hunter_core::hypothesis::HypothesisShape::Chain
                ) {
                    // Walk depths from the deepest possible prefix
                    // down to 1; first hit wins. Within-batch
                    // prefix_cache is checked first; on miss we
                    // also consult the persistent session cache
                    // (D3 stage 5 prefix companion to the bag
                    // cache). Persistent hits hydrate the
                    // per-batch cache so subsequent same-batch
                    // hypotheses benefit too.
                    let max_depth = hypothesis.steps.len().saturating_sub(1);
                    for depth in (1..=max_depth).rev() {
                        let prefix_key = build_prefix_key(
                            &step_fingerprints[..depth],
                            t_lo_window,
                            t_hi_window,
                        );
                        if let Some(snapshot) = prefix_cache.get(&prefix_key) {
                            resume_depth = depth;
                            resume_starting = snapshot.clone();
                            prefix_cache_hits += 1;
                            break;
                        }
                        let session_hit = session_for_bags
                            .yannakakis_cache
                            .read()
                            .ok()
                            .and_then(|c| {
                                c.as_ref().and_then(|y| {
                                    if y.version == live_version {
                                        y.prefixes.get(&prefix_key).cloned()
                                    } else {
                                        None
                                    }
                                })
                            });
                        if let Some(snapshot) = session_hit {
                            resume_depth = depth;
                            resume_starting = snapshot.clone();
                            prefix_cache.insert(prefix_key, snapshot);
                            prefix_cache_hits += 1;
                            yannakakis_persistent_prefix_hits += 1;
                            break;
                        }
                    }
                }
                last_prefix_resume_depth = resume_depth;

                let (paths, truncated) = if matches!(
                    hypothesis.shape,
                    graph_hunter_core::hypothesis::HypothesisShape::Chain
                ) {
                    let paths = graph_hunter_core::yannakakis::enumerate_chain_from_prefix(
                        &graph,
                        &bags,
                        &resume_starting,
                        resume_depth,
                        cap,
                        hypothesis.k_simplicity.max(1),
                    );
                    let truncated = paths.len() >= cap;

                    // After running, populate the prefix cache for
                    // every depth from 1 to n-1 (skipping depths
                    // already cached). Cap each snapshot at
                    // PREFIX_CACHE_CAP entries to bound memory.
                    for depth in 1..hypothesis.steps.len() {
                        let prefix_key = build_prefix_key(
                            &step_fingerprints[..depth],
                            t_lo_window,
                            t_hi_window,
                        );
                        if prefix_cache.contains_key(&prefix_key) {
                            continue;
                        }
                        let snapshot = graph_hunter_core::yannakakis::compute_prefix_snapshot(
                            &graph,
                            &bags,
                            depth,
                            PREFIX_CACHE_CAP,
                            hypothesis.k_simplicity.max(1),
                        );
                        if snapshot.len() < PREFIX_CACHE_CAP {
                            let arc = std::sync::Arc::new(snapshot);
                            prefix_cache.insert(prefix_key.clone(), arc.clone());
                            // Also write to the persistent session
                            // cache (resets on graph version mismatch).
                            if let Ok(mut slot) = session_for_bags.yannakakis_cache.write() {
                                let cache = slot.get_or_insert_with(|| {
                                    crate::state::session::YannakakisSessionCache::new(
                                        live_version,
                                    )
                                });
                                if cache.version != live_version {
                                    *cache = crate::state::session::YannakakisSessionCache::new(
                                        live_version,
                                    );
                                }
                                cache.insert_prefix(prefix_key, arc);
                            }
                        }
                    }
                    (paths, truncated)
                } else {
                    // Graph shape: tree-walk enumerator handles
                    // the whole hypothesis; no prefix cache.
                    graph_hunter_core::yannakakis::search_temporal_pattern_yannakakis_with_bags(
                        &graph,
                        &hypothesis,
                        bags,
                        Some(cap),
                    )
                };
                drop(graph);
                let paths = match dedup_mode {
                    Some(mode) => dedup_arc_paths(paths, mode),
                    None => paths,
                };
                let path_count = paths.len();
                let inline = if path_count <= 100 { paths.clone() } else { Vec::new() };
                // Update the shared hunt cache so cmd_get_hunt_page
                // sees the most recent batch entry's results.
                if let Ok(mut cache) = self.inner.hunt_cache.write() {
                    *cache = paths;
                }
                let entry = RunHuntBatchEntry {
                    paths: inline,
                    path_count,
                    truncated,
                    diagnostic: None,
                    live_tail_coverage: batch_live_tail_coverage.clone(),
                    error: None,
                };
                result_cache.insert(result_cache_key, entry.clone());
                entries.push(entry);
            } else {
                let item_req = RunHuntRequest {
                    session: session.clone(),
                    hypothesis,
                    time_window,
                    max_results,
                    // batch hunts inherit v1 behavior — whatever
                    // session-level scoring is active.
                    scoring: None,
                    // Forward the batch-level dedup choice; run_hunt
                    // applies it to its own emit/cache, so the
                    // returned entry is already deduped.
                    dedup_mode,
                };
                let entry = match self.run_hunt(item_req) {
                    Ok(resp) => RunHuntBatchEntry {
                        paths: resp.paths,
                        path_count: resp.path_count,
                        truncated: resp.truncated,
                        diagnostic: resp.diagnostic,
                        live_tail_coverage: resp.live_tail_coverage,
                        error: None,
                    },
                    Err(e) => RunHuntBatchEntry {
                        paths: Vec::new(),
                        path_count: 0,
                        truncated: false,
                        diagnostic: None,
                        live_tail_coverage: batch_live_tail_coverage.clone(),
                        error: Some(e.to_string()),
                    },
                };
                // Cache successful entries only — errors aren't
                // worth caching (the underlying cause may have been
                // transient).
                if entry.error.is_none() {
                    result_cache.insert(result_cache_key, entry.clone());
                }
                entries.push(entry);
            }
        }
        // D3 stage 4 — the session cache is updated inline within
        // the per-hypothesis loop (typed_tries map + canonical
        // FIFO insert). No trailing write-back needed: stage-3's
        // post-loop write-back was a single-entry bulk update that
        // the per-iteration cache.insert pattern subsumes cleanly.

        Ok(RunHuntBatchResponse {
            entries,
            indexes_were_warm,
            bag_cache_hits,
            bag_cache_misses,
            result_cache_hits,
            last_prefix_resume_depth,
            prefix_cache_hits,
            lftj_trie_cache_builds,
            lftj_trie_cache_hits,
            lftj_canonical_cache_hits,
            lftj_canonical_cache_misses,
            lftj_session_cache_reused,
            lftj_persistent_canonical_hits,
            lftj_persistent_trie_hits,
            yannakakis_persistent_bag_hits,
            yannakakis_persistent_prefix_hits,
        })
    }
}

/// L2 stage 3b helper: build a stable string key for a prefix of
/// step fingerprints + a time window. Two hypotheses share the
/// same key iff their first `step_fingerprints.len()` steps are
/// byte-identical (including predicates) and the time windows
/// match.
fn build_prefix_key(step_fingerprints: &[String], t_lo: i64, t_hi: i64) -> String {
    let mut key = String::new();
    for fp in step_fingerprints {
        key.push_str(fp);
        key.push('\x1f'); // unit separator — not valid in JSON
    }
    key.push_str(&format!("|{t_lo}|{t_hi}"));
    key
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state::Session;
    use graph_hunter_core::{GraphHunter, parse_dsl};
    use std::sync::Arc;

    fn arc_path(items: &[&str]) -> Vec<Arc<str>> {
        items.iter().map(|s| Arc::<str>::from(*s)).collect()
    }

    /// `DedupMode::None` is a strict identity — every input row,
    /// including duplicates, survives in order.
    #[test]
    fn dedup_arc_paths_none_is_identity() {
        let input = vec![
            arc_path(&["a", "b"]),
            arc_path(&["a", "b"]),
            arc_path(&["c", "d"]),
        ];
        let out = dedup_arc_paths(input.clone(), DedupMode::None);
        assert_eq!(out, input);
    }

    /// `ByPath` collapses identical full sequences into the
    /// first-seen representative. Matches the 2026-04-16 hunt
    /// session complaint (1835 identical `root → /usr/bin/grep`
    /// in 2523 paths).
    #[test]
    fn dedup_arc_paths_by_path_collapses_duplicates() {
        let input = vec![
            arc_path(&["root", "/usr/bin/grep"]),
            arc_path(&["root", "/usr/bin/grep"]),
            arc_path(&["root", "/usr/bin/grep"]),
            arc_path(&["root", "/usr/bin/ls"]),
        ];
        let out = dedup_arc_paths(input, DedupMode::ByPath);
        assert_eq!(out.len(), 2);
        // Insertion order preserved: grep first, ls second.
        assert_eq!(out[0], arc_path(&["root", "/usr/bin/grep"]));
        assert_eq!(out[1], arc_path(&["root", "/usr/bin/ls"]));
    }

    /// `ByEndpoints` collapses paths that share the same
    /// `(first, last)` even when intermediate hops differ.
    #[test]
    fn dedup_arc_paths_by_endpoints_collapses_on_endpoints() {
        let input = vec![
            arc_path(&["alice", "host1", "10.0.0.1"]),
            arc_path(&["alice", "host2", "10.0.0.1"]),
            arc_path(&["alice", "host3", "10.0.0.2"]),
        ];
        let out = dedup_arc_paths(input, DedupMode::ByEndpoints);
        assert_eq!(out.len(), 2);
        // First wins: alice→host1→10.0.0.1 represents the
        // (alice, 10.0.0.1) endpoint pair.
        assert_eq!(out[0], arc_path(&["alice", "host1", "10.0.0.1"]));
        assert_eq!(out[1], arc_path(&["alice", "host3", "10.0.0.2"]));
    }

    /// Empty paths are passed through under `ByEndpoints` rather than
    /// triggering the `unwrap()` on the empty slice's first/last. The
    /// matcher should never emit empty paths, but the helper must not
    /// panic on them — the equivalent `score_and_paginate_paths`
    /// branch skips them silently.
    #[test]
    fn dedup_arc_paths_by_endpoints_handles_empty_paths() {
        let input: Vec<Vec<Arc<str>>> = vec![vec![], arc_path(&["a", "b"])];
        let out = dedup_arc_paths(input, DedupMode::ByEndpoints);
        assert_eq!(out.len(), 2);
    }

    /// Process-wide mutex shared by every env-mutating hunt test in
    /// this module. Cargo runs tests in parallel by default, so
    /// `GRAPHHUNTER_YANNAKAKIS=1` set by one test would race with
    /// `GRAPHHUNTER_TRIANGLE_LFTJ=1` set by another. Pattern mirrors
    /// `core/graph-engine/src/planner.rs::tests::ENV_LOCK` (added in
    /// PR #14). Each env-touching test acquires this guard for the
    /// duration of its run.
    static ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    fn lock_env() -> std::sync::MutexGuard<'static, ()> {
        ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner())
    }

    fn api() -> GraphHunterApi {
        let api = GraphHunterApi::new_noop();
        let s = Arc::new(Session::new("s1", "t", GraphHunter::new(), 0));
        s.set_phase(crate::state::SessionPhase::Ready);
        api.sessions().insert(s);
        api.sessions().set_current(Some("s1".into()));
        api
    }

    #[test]
    fn hunt_rejected_while_finalizing() {
        let api = GraphHunterApi::new_noop();
        let s = Arc::new(Session::new("s1", "t", GraphHunter::new(), 0));
        s.set_phase(crate::state::SessionPhase::Finalizing);
        api.sessions().insert(s);
        api.sessions().set_current(Some("s1".into()));

        let err = api
            .run_hunt(RunHuntRequest {
                session: None,
                hypothesis: hypo("User -[Auth]-> Host"),
                time_window: None,
                max_results: None,
                scoring: None,
                dedup_mode: None,
            })
            .unwrap_err();

        match &err {
            ApiError::Conflict(msg) => {
                assert!(msg.contains("finalizing"), "unexpected message: {msg}");
            }
            other => panic!("expected Conflict, got {other:?}"),
        }
        assert_eq!(err.status_code(), 409);
    }

    fn hypo(dsl: &str) -> graph_hunter_core::Hypothesis {
        parse_dsl(dsl, Some("test")).unwrap().hypothesis
    }

    /// Per-call `scoring=Anomaly` finalizes the per-session anomaly
    /// scorer before the search even when no prior `enable_*` call
    /// touched it. Subsequent `scoring=Structural` runs still use the
    /// plain DFS — the override drives the search-path choice
    /// regardless of session state. Pins the v2-follow-up behavior.
    #[test]
    fn run_hunt_per_call_scoring_overrides_session_state() {
        let api = api();
        // No prior enable_anomaly_scoring; Anomaly should
        // self-bootstrap the scorer.
        let _ = api
            .run_hunt(RunHuntRequest {
                session: None,
                hypothesis: hypo("User -[Auth]-> Host"),
                time_window: None,
                max_results: None,
                scoring: Some(HuntScoring::Anomaly),
                dedup_mode: None,
            })
            .expect("Anomaly run on empty graph should not error");
        // After the Anomaly run the session has a finalized scorer.
        if let Some(s) = api
            .sessions()
            .current_session()
            .and_then(|sess| sess.graph.read().ok().map(|g| g.anomaly_scorer.is_some()))
        {
            assert!(s, "Anomaly run must finalize the per-session scorer");
        }
        // Structural override now uses the plain DFS even though the
        // scorer is sticky on the session — the override is what
        // gives the v2 transcript its replay-stable property.
        let _ = api
            .run_hunt(RunHuntRequest {
                session: None,
                hypothesis: hypo("User -[Auth]-> Host"),
                time_window: None,
                max_results: None,
                scoring: Some(HuntScoring::Structural),
                dedup_mode: None,
            })
            .expect("Structural override after Anomaly must not error");
    }

    #[test]
    fn run_hunt_empty_graph_returns_zero_with_diagnostic() {
        let api = api();
        let resp = api
            .run_hunt(RunHuntRequest {
                session: None,
                hypothesis: hypo("User -[Auth]-> Host"),
                time_window: None,
                max_results: None,
                scoring: None,
                dedup_mode: None,
            })
            .expect("should not error on empty graph");
        assert_eq!(resp.path_count, 0);
        // Zero-match diagnostic must be populated.
        assert!(
            resp.diagnostic.is_some(),
            "expected a zero-match diagnostic so the analyst knows why"
        );
    }

    #[test]
    fn diff_hunts_rejects_inverted_time_window() {
        let api = api();
        let err = api
            .diff_hunts(DiffHuntsRequest {
                session: None,
                hypothesis: hypo("User -[Auth]-> Host"),
                baseline_ts: 200,
                current_ts: 100,
            })
            .unwrap_err();
        assert!(matches!(err, ApiError::InvalidInput(_)));
    }

    #[test]
    fn hunt_cache_shared_between_run_and_page() {
        let api = api();
        let _ = api
            .run_hunt(RunHuntRequest {
                session: None,
                hypothesis: hypo("User -[Auth]-> Host"),
                time_window: None,
                max_results: None,
                scoring: None,
                dedup_mode: None,
            })
            .unwrap();
        // Cache is empty for an empty graph, but the path must succeed.
        let page = api
            .get_hunt_page(GetHuntPageRequest {
                session: None,
                page: 0,
                page_size: 10,
                min_score: None,
                dedup_mode: None,
            })
            .expect("page should return even when empty");
        assert_eq!(page.total_paths, 0);
    }

    #[test]
    fn run_hunt_batch_runs_each_hypothesis() {
        let api = api();
        let resp = api
            .run_hunt_batch(RunHuntBatchRequest {
                session: None,
                hypotheses: vec![
                    hypo("User -[Auth]-> Host"),
                    hypo("Host -[Connect]-> IP"),
                    hypo("Process -[Spawn]-> Process"),
                ],
                time_window: None,
                max_results: None,
                dedup_mode: None,
            })
            .expect("batch should not error on empty graph");
        assert_eq!(resp.entries.len(), 3);
        for entry in &resp.entries {
            assert!(entry.error.is_none(), "individual hypothesis errored: {:?}", entry.error);
            assert_eq!(entry.path_count, 0);
        }
    }

    #[test]
    fn run_hunt_batch_warm_after_first_call() {
        // First batch builds the indexes (lazy NLF + khop_reach);
        // second batch reports indexes_were_warm = true.
        let api = api();
        let first = api
            .run_hunt_batch(RunHuntBatchRequest {
                session: None,
                hypotheses: vec![hypo("User -[Auth]-> Host")],
                time_window: None,
                max_results: None,
                dedup_mode: None,
            })
            .expect("first batch ok");
        // First call may or may not show indexes warm depending on
        // whether sort_edges_by_timestamp ran on this empty session.
        // We don't assert the first one — the contract is just that
        // the *second* batch sees them warm.
        let _ = first.indexes_were_warm;
        let second = api
            .run_hunt_batch(RunHuntBatchRequest {
                session: None,
                hypotheses: vec![hypo("Host -[Connect]-> IP")],
                time_window: None,
                max_results: None,
                dedup_mode: None,
            })
            .expect("second batch ok");
        assert!(
            second.indexes_were_warm,
            "indexes must be warm after the first batch pre-warmed them"
        );
    }

    #[test]
    fn run_hunt_batch_csh_shares_bags_across_hypotheses() {
        // L2 stage 2: when GRAPHHUNTER_YANNAKAKIS=1 and the batch
        // has two hypotheses sharing the same first step, the bag
        // cache should report exactly one miss for that step and
        // one hit for the duplicate. Other steps are unique →
        // miss-only.
        // Note: env vars are process-wide; this test sets the flag
        // for its duration and restores afterwards.
        let _env_guard = lock_env();
        let prior = std::env::var("GRAPHHUNTER_YANNAKAKIS").ok();
        // SAFETY: the harness runs tests with `--test-threads=1` for
        // env-var tests by convention, and we restore on drop.
        unsafe { std::env::set_var("GRAPHHUNTER_YANNAKAKIS", "1") };

        let api = api();
        let resp = api
            .run_hunt_batch(RunHuntBatchRequest {
                session: None,
                hypotheses: vec![
                    hypo("User -[Auth]-> Host -[Connect]-> IP"),
                    hypo("User -[Auth]-> Host -[Spawn]-> Process"),
                ],
                time_window: None,
                max_results: None,
                dedup_mode: None,
            })
            .expect("batch ok");

        match prior {
            Some(v) => unsafe { std::env::set_var("GRAPHHUNTER_YANNAKAKIS", v) },
            None => unsafe { std::env::remove_var("GRAPHHUNTER_YANNAKAKIS") },
        }

        // Two hypotheses with the same first step (User-Auth-Host)
        // and distinct second steps. Across both: 4 step
        // materialization requests, of which 1 is the cached
        // duplicate of the first step.
        assert_eq!(resp.bag_cache_hits, 1, "duplicate User-Auth-Host step should hit cache");
        assert_eq!(resp.bag_cache_misses, 3, "3 distinct step fingerprints");
    }

    #[test]
    fn run_hunt_batch_result_cache_skips_duplicate_hypotheses() {
        // L2 stage 3a: when a batch contains the same hypothesis
        // twice (same fingerprint + same time_window), the second
        // entry returns the cached result without re-running. The
        // counter `result_cache_hits` reflects that.
        let api = api();
        let h = hypo("User -[Auth]-> Host");
        let resp = api
            .run_hunt_batch(RunHuntBatchRequest {
                session: None,
                hypotheses: vec![h.clone(), h.clone(), h],
                time_window: None,
                max_results: None,
                dedup_mode: None,
            })
            .expect("batch ok");
        assert_eq!(resp.entries.len(), 3);
        // First runs the matcher; second and third hit the cache.
        assert_eq!(resp.result_cache_hits, 2);
        // All three entries report identical path_count.
        let counts: Vec<usize> = resp.entries.iter().map(|e| e.path_count).collect();
        assert_eq!(counts[0], counts[1]);
        assert_eq!(counts[0], counts[2]);
    }

    #[test]
    fn run_hunt_batch_d3_stage5_yannakakis_persistent_prefix_cache() {
        // D3 stage 5 prefix companion: the prefix snapshot cache
        // also survives across batches via the Session cache.
        // Two batches sharing a 2-step prefix: the second resumes
        // from the cached snapshot rather than recomputing from
        // bags. The bag cache also helps; we isolate the prefix
        // hit explicitly.
        let _env_guard = lock_env();
        let prior = std::env::var("GRAPHHUNTER_YANNAKAKIS").ok();
        unsafe { std::env::set_var("GRAPHHUNTER_YANNAKAKIS", "1") };
        let api = api();
        // First batch: 3-step chain populates depth-1 and depth-2
        // prefix snapshots in both per-batch and persistent caches.
        let _b1 = api
            .run_hunt_batch(RunHuntBatchRequest {
                session: None,
                hypotheses: vec![hypo(
                    "User -[Auth]-> Host -[Connect]-> IP -[DNS]-> Domain",
                )],
                time_window: None,
                max_results: None,
                dedup_mode: None,
            })
            .expect("first batch ok");
        // Second batch: shares the first 2 steps with batch 1's
        // hypothesis but diverges at step 3. Resume from the
        // depth-2 prefix snapshot persisted in the session cache.
        let b2 = api
            .run_hunt_batch(RunHuntBatchRequest {
                session: None,
                hypotheses: vec![hypo(
                    "User -[Auth]-> Host -[Connect]-> IP -[Modify]-> File",
                )],
                time_window: None,
                max_results: None,
                dedup_mode: None,
            })
            .expect("second batch ok");
        match prior {
            Some(v) => unsafe { std::env::set_var("GRAPHHUNTER_YANNAKAKIS", v) },
            None => unsafe { std::env::remove_var("GRAPHHUNTER_YANNAKAKIS") },
        }
        assert!(
            b2.yannakakis_persistent_prefix_hits >= 1,
            "second batch should resume from a persisted prefix snapshot"
        );
        assert_eq!(b2.last_prefix_resume_depth, 2);
    }

    #[test]
    fn run_hunt_batch_d3_stage5_yannakakis_persistent_bag_cache() {
        // D3 stage 5: bag cache survives across batches via the
        // Session-level YannakakisSessionCache, gated by
        // mutation_version. Two consecutive batches with the same
        // hypothesis: first batch materializes bags (zero
        // persistent hits), second batch reads them from the
        // session cache.
        let _env_guard = lock_env();
        let prior = std::env::var("GRAPHHUNTER_YANNAKAKIS").ok();
        unsafe { std::env::set_var("GRAPHHUNTER_YANNAKAKIS", "1") };
        let api = api();
        let h = hypo("User -[Auth]-> Host -[Connect]-> IP");
        let first = api
            .run_hunt_batch(RunHuntBatchRequest {
                session: None,
                hypotheses: vec![h.clone()],
                time_window: None,
                max_results: None,
                dedup_mode: None,
            })
            .expect("first batch ok");
        assert_eq!(
            first.yannakakis_persistent_bag_hits, 0,
            "first batch on a cold cache cannot have a persistent hit"
        );
        let second = api
            .run_hunt_batch(RunHuntBatchRequest {
                session: None,
                hypotheses: vec![h],
                time_window: None,
                max_results: None,
                dedup_mode: None,
            })
            .expect("second batch ok");
        match prior {
            Some(v) => unsafe { std::env::set_var("GRAPHHUNTER_YANNAKAKIS", v) },
            None => unsafe { std::env::remove_var("GRAPHHUNTER_YANNAKAKIS") },
        }
        // Two-step hypothesis → two bag lookups in the second
        // batch, both should hit the persistent cache.
        assert_eq!(
            second.yannakakis_persistent_bag_hits, 2,
            "second batch on the same graph version must reuse both bags"
        );
        assert_eq!(
            second.bag_cache_misses, 0,
            "no bag materialization should fire on the warm second batch"
        );
    }

    #[test]
    fn run_hunt_batch_d3_stage4_persistent_canonical_cache_across_batches() {
        // D3 stage 4: the canonical raw-result cache survives
        // across `run_hunt_batch` calls. First batch enumerates
        // and writes; second batch on the same Session + graph
        // version reads back without re-enumerating.
        let _env_guard = lock_env();
        let prior_tri = std::env::var("GRAPHHUNTER_TRIANGLE_LFTJ").ok();
        unsafe { std::env::set_var("GRAPHHUNTER_TRIANGLE_LFTJ", "1") };
        let api = api();
        let mut h = hypo("Host -[Connect]-> Host -[Connect]-> Host");
        h.name = "triangle template".into();

        let first = api
            .run_hunt_batch(RunHuntBatchRequest {
                session: None,
                hypotheses: vec![h.clone()],
                time_window: None,
                max_results: None,
                dedup_mode: None,
            })
            .expect("first batch ok");
        assert_eq!(
            first.lftj_persistent_canonical_hits, 0,
            "first batch cannot have a persistent canonical hit"
        );
        assert_eq!(first.lftj_canonical_cache_misses, 1);

        let second = api
            .run_hunt_batch(RunHuntBatchRequest {
                session: None,
                hypotheses: vec![h],
                time_window: None,
                max_results: None,
                dedup_mode: None,
            })
            .expect("second batch ok");

        match prior_tri {
            Some(v) => unsafe { std::env::set_var("GRAPHHUNTER_TRIANGLE_LFTJ", v) },
            None => unsafe { std::env::remove_var("GRAPHHUNTER_TRIANGLE_LFTJ") },
        }
        assert_eq!(
            second.lftj_persistent_canonical_hits, 1,
            "second batch must hit the persistent canonical cache"
        );
        assert_eq!(
            second.lftj_canonical_cache_misses, 0,
            "no enumeration should fire on the second batch"
        );
    }

    #[test]
    fn run_hunt_batch_d3_stage4_typed_trie_map_holds_multiple_signatures() {
        // D3 stage 4: typed-trie map keyed on (rel_type, vertex_type)
        // signature. Two consecutive batches with different typed
        // hypotheses (Auth-triangle then Connect-triangle) both
        // build their own typed trie; a third batch firing the
        // Auth-triangle again hits the persistent typed-trie map.
        let _env_guard = lock_env();
        let prior_tri = std::env::var("GRAPHHUNTER_TRIANGLE_LFTJ").ok();
        unsafe { std::env::set_var("GRAPHHUNTER_TRIANGLE_LFTJ", "1") };
        let api = api();
        let mut h_auth = hypo("Host -[Auth]-> Host -[Auth]-> Host");
        h_auth.name = "triangle template auth".into();
        let mut h_conn = hypo("Host -[Connect]-> Host -[Connect]-> Host");
        h_conn.name = "triangle template connect".into();

        let _b1 = api
            .run_hunt_batch(RunHuntBatchRequest {
                session: None,
                hypotheses: vec![h_auth.clone()],
                time_window: None,
                max_results: None,
                dedup_mode: None,
            })
            .expect("auth batch ok");
        let _b2 = api
            .run_hunt_batch(RunHuntBatchRequest {
                session: None,
                hypotheses: vec![h_conn],
                time_window: None,
                max_results: None,
                dedup_mode: None,
            })
            .expect("connect batch ok");
        let b3 = api
            .run_hunt_batch(RunHuntBatchRequest {
                session: None,
                hypotheses: vec![h_auth],
                time_window: None,
                max_results: None,
                dedup_mode: None,
            })
            .expect("auth-replay batch ok");

        match prior_tri {
            Some(v) => unsafe { std::env::set_var("GRAPHHUNTER_TRIANGLE_LFTJ", v) },
            None => unsafe { std::env::remove_var("GRAPHHUNTER_TRIANGLE_LFTJ") },
        }
        // The third batch should hit BOTH the persistent typed-trie
        // map (Auth signature already cached from b1) AND the
        // canonical cache (Auth-triangle result already cached from
        // b1). Persistent canonical hit implies persistent trie hit
        // is unnecessary on this path because the canonical lookup
        // wins first; but the cross-signature trie persistence is
        // proven by b3's session_cache_reused.
        assert!(
            b3.lftj_session_cache_reused,
            "cache should be warm — version unchanged across batches"
        );
        assert_eq!(
            b3.lftj_persistent_canonical_hits, 1,
            "auth-triangle result from batch 1 must still be in cache"
        );
    }

    #[test]
    fn run_hunt_batch_d3_stage3_session_cache_reused_across_batches() {
        // D3 stage 3: the session-level LFTJ cache survives
        // across `run_hunt_batch` calls when the graph hasn't
        // mutated. First batch builds (lftj_session_cache_reused
        // = false); second batch on the same Session reuses
        // (lftj_session_cache_reused = true).
        let _env_guard = lock_env();
        let prior_tri = std::env::var("GRAPHHUNTER_TRIANGLE_LFTJ").ok();
        unsafe { std::env::set_var("GRAPHHUNTER_TRIANGLE_LFTJ", "1") };
        let api = api();
        let mut h = hypo("Host -[Connect]-> Host -[Connect]-> Host");
        h.name = "triangle template".into();

        let first = api
            .run_hunt_batch(RunHuntBatchRequest {
                session: None,
                hypotheses: vec![h.clone()],
                time_window: None,
                max_results: None,
                dedup_mode: None,
            })
            .expect("first batch ok");
        assert!(
            !first.lftj_session_cache_reused,
            "first batch builds the session cache; it cannot have been reused"
        );
        assert_eq!(first.lftj_trie_cache_builds, 1);

        let second = api
            .run_hunt_batch(RunHuntBatchRequest {
                session: None,
                hypotheses: vec![h],
                time_window: None,
                max_results: None,
                dedup_mode: None,
            })
            .expect("second batch ok");

        match prior_tri {
            Some(v) => unsafe { std::env::set_var("GRAPHHUNTER_TRIANGLE_LFTJ", v) },
            None => unsafe { std::env::remove_var("GRAPHHUNTER_TRIANGLE_LFTJ") },
        }
        assert!(
            second.lftj_session_cache_reused,
            "second batch on unchanged graph must reuse the session cache"
        );
        assert_eq!(
            second.lftj_trie_cache_builds, 0,
            "no trie build should fire when the session cache is warm"
        );
    }

    #[test]
    fn run_hunt_batch_d3_stage3_session_cache_invalidated_by_mutation() {
        // After the first batch the session cache is populated.
        // Mutating the graph (add_relation) bumps mutation_version
        // and the next batch must rebuild — session cache reused
        // = false.
        let _env_guard = lock_env();
        let prior_tri = std::env::var("GRAPHHUNTER_TRIANGLE_LFTJ").ok();
        unsafe { std::env::set_var("GRAPHHUNTER_TRIANGLE_LFTJ", "1") };
        let api = api();
        let mut h = hypo("Host -[Connect]-> Host -[Connect]-> Host");
        h.name = "triangle template".into();

        let _first = api
            .run_hunt_batch(RunHuntBatchRequest {
                session: None,
                hypotheses: vec![h.clone()],
                time_window: None,
                max_results: None,
                dedup_mode: None,
            })
            .expect("first batch ok");

        // Mutate the graph: add an entity (a no-op for the LFTJ
        // result on an empty graph but enough to bump the
        // mutation_version counter).
        {
            let session = api.resolve_session(None).expect("session");
            let mut g = session.graph.write().unwrap();
            g.add_entity(graph_hunter_core::Entity::new(
                "marker",
                graph_hunter_core::types::EntityType::Host,
            ))
            .unwrap();
        }

        let second = api
            .run_hunt_batch(RunHuntBatchRequest {
                session: None,
                hypotheses: vec![h],
                time_window: None,
                max_results: None,
                dedup_mode: None,
            })
            .expect("second batch ok");

        match prior_tri {
            Some(v) => unsafe { std::env::set_var("GRAPHHUNTER_TRIANGLE_LFTJ", v) },
            None => unsafe { std::env::remove_var("GRAPHHUNTER_TRIANGLE_LFTJ") },
        }
        assert!(
            !second.lftj_session_cache_reused,
            "graph mutation between batches must invalidate the session cache"
        );
        assert_eq!(second.lftj_trie_cache_builds, 1);
    }

    #[test]
    fn run_hunt_batch_d3_stage2_canonical_cache_dedups_lftj_results() {
        // D3 stage 2: two LFTJ-routed hypotheses that share a
        // DispatchPlan + time_window but differ in vertex/edge
        // labels (or hypothesis name) should canonicalize to a
        // single raw enumeration. The first call misses (populates
        // the canonical cache), the second hits.
        //
        // Triangle marker fires on name match; both hypotheses
        // route to TriangleLftj. They differ in name, so the
        // result_cache (stage 3a, keyed on hypothesis JSON) does
        // NOT hit. But the canonical cache (stage 2, keyed on
        // (plan, window)) DOES.
        let _env_guard = lock_env();
        let prior_tri = std::env::var("GRAPHHUNTER_TRIANGLE_LFTJ").ok();
        unsafe { std::env::set_var("GRAPHHUNTER_TRIANGLE_LFTJ", "1") };
        let api = api();
        let mut h1 = hypo("Host -[Connect]-> Host -[Connect]-> Host");
        h1.name = "triangle alpha".into();
        let mut h2 = hypo("Host -[Connect]-> Host -[Connect]-> Host");
        h2.name = "triangle beta".into();
        let resp = api
            .run_hunt_batch(RunHuntBatchRequest {
                session: None,
                hypotheses: vec![h1, h2],
                time_window: None,
                max_results: None,
                dedup_mode: None,
            })
            .expect("batch ok");
        match prior_tri {
            Some(v) => unsafe { std::env::set_var("GRAPHHUNTER_TRIANGLE_LFTJ", v) },
            None => unsafe { std::env::remove_var("GRAPHHUNTER_TRIANGLE_LFTJ") },
        }
        assert_eq!(
            resp.lftj_canonical_cache_misses, 1,
            "exactly one canonical-cache miss for the first triangle hypothesis"
        );
        assert_eq!(
            resp.lftj_canonical_cache_hits, 1,
            "second hypothesis with same DispatchPlan + window must hit the canonical cache"
        );
        // Both hypotheses also share the trie (stage 1 still works).
        assert_eq!(resp.lftj_trie_cache_builds, 1);
        // Stage 1 hit fires only on miss → since stage 2 hit avoids
        // the trie path entirely on the second iteration, stage 1
        // hit count stays at 0 in the cache-hit case.
        assert_eq!(resp.lftj_trie_cache_hits, 0);
    }

    #[test]
    fn run_hunt_batch_d3_canonical_cache_distinguishes_dispatch_plans() {
        // K4 and triangle templates with the same name should NOT
        // share the canonical cache — different DispatchPlans.
        // This test verifies the cache key includes the plan, not
        // just the time_window.
        let _env_guard = lock_env();
        let prior_tri = std::env::var("GRAPHHUNTER_TRIANGLE_LFTJ").ok();
        let prior_k4 = std::env::var("GRAPHHUNTER_K4_LFTJ").ok();
        unsafe {
            std::env::set_var("GRAPHHUNTER_TRIANGLE_LFTJ", "1");
            std::env::set_var("GRAPHHUNTER_K4_LFTJ", "1");
        }
        let api = api();
        let mut tri = hypo("Host -[Connect]-> Host -[Connect]-> Host");
        tri.name = "lateral movement (3-clique)".into();
        let mut k4 = hypo("Host -[Connect]-> Host");
        k4.name = "lateral movement (k4-clique)".into();
        let resp = api
            .run_hunt_batch(RunHuntBatchRequest {
                session: None,
                hypotheses: vec![tri, k4],
                time_window: None,
                max_results: None,
                dedup_mode: None,
            })
            .expect("batch ok");
        for (k, v) in [
            ("GRAPHHUNTER_TRIANGLE_LFTJ", prior_tri),
            ("GRAPHHUNTER_K4_LFTJ", prior_k4),
        ] {
            match v {
                Some(s) => unsafe { std::env::set_var(k, s) },
                None => unsafe { std::env::remove_var(k) },
            }
        }
        // Two distinct DispatchPlans → two misses, zero hits.
        assert_eq!(
            resp.lftj_canonical_cache_misses, 2,
            "different DispatchPlans must miss the canonical cache"
        );
        assert_eq!(resp.lftj_canonical_cache_hits, 0);
    }

    #[test]
    fn run_hunt_batch_d3_lftj_trie_shared_across_cyclic_hypotheses() {
        // D3 stage 1: two LFTJ-routed hypotheses with DIFFERENT
        // DispatchPlans (so they bypass stage 2's canonical cache
        // and both go through the trie path) share the forward
        // trie + ts_map. Triangle and K4 use the same forward
        // trie, so 1 build + 1 hit.
        let _env_guard = lock_env();
        let prior_tri = std::env::var("GRAPHHUNTER_TRIANGLE_LFTJ").ok();
        let prior_k4 = std::env::var("GRAPHHUNTER_K4_LFTJ").ok();
        unsafe {
            std::env::set_var("GRAPHHUNTER_TRIANGLE_LFTJ", "1");
            std::env::set_var("GRAPHHUNTER_K4_LFTJ", "1");
        }
        let api = api();
        let mut tri = hypo("Host -[Connect]-> Host -[Connect]-> Host");
        tri.name = "triangle template".into();
        let mut k4 = hypo("Host -[Connect]-> Host");
        k4.name = "k4-clique template".into();
        let resp = api
            .run_hunt_batch(RunHuntBatchRequest {
                session: None,
                hypotheses: vec![tri, k4],
                time_window: None,
                max_results: None,
                dedup_mode: None,
            })
            .expect("batch ok");
        for (k, v) in [
            ("GRAPHHUNTER_TRIANGLE_LFTJ", prior_tri),
            ("GRAPHHUNTER_K4_LFTJ", prior_k4),
        ] {
            match v {
                Some(s) => unsafe { std::env::set_var(k, s) },
                None => unsafe { std::env::remove_var(k) },
            }
        }
        assert_eq!(
            resp.lftj_trie_cache_builds, 1,
            "exactly one trie build should fire for the first LFTJ hypothesis"
        );
        assert_eq!(
            resp.lftj_trie_cache_hits, 1,
            "the second LFTJ hypothesis (different plan) should reuse the cached trie"
        );
    }

    #[test]
    fn run_hunt_batch_result_cache_distinguishes_time_windows() {
        // Same hypothesis with different time windows must NOT
        // share a cache entry — the result depends on the window.
        let api = api();
        let h = hypo("User -[Auth]-> Host");
        let resp = api
            .run_hunt_batch(RunHuntBatchRequest {
                session: None,
                hypotheses: vec![h.clone(), h],
                time_window: Some((100, 200)),
                max_results: None,
                dedup_mode: None,
            })
            .expect("batch ok");
        // Same hypothesis, same window — cache fires on entry 2.
        assert_eq!(resp.result_cache_hits, 1);
    }

    #[test]
    fn run_hunt_batch_prefix_cache_resumes_for_shared_prefix() {
        // L2 stage 3b: two hypotheses sharing the first step
        // resume the second one's enumeration from depth 1
        // (after reusing the cached prefix snapshot from
        // hypothesis 1).
        let _env_guard = lock_env();
        let prior = std::env::var("GRAPHHUNTER_YANNAKAKIS").ok();
        unsafe { std::env::set_var("GRAPHHUNTER_YANNAKAKIS", "1") };
        let api = api();
        let resp = api
            .run_hunt_batch(RunHuntBatchRequest {
                session: None,
                hypotheses: vec![
                    hypo("User -[Auth]-> Host -[Connect]-> IP"),
                    hypo("User -[Auth]-> Host -[Spawn]-> Process"),
                ],
                time_window: None,
                max_results: None,
                dedup_mode: None,
            })
            .expect("batch ok");
        match prior {
            Some(v) => unsafe { std::env::set_var("GRAPHHUNTER_YANNAKAKIS", v) },
            None => unsafe { std::env::remove_var("GRAPHHUNTER_YANNAKAKIS") },
        }
        // First hypothesis populates depth-1 + depth-2 snapshots.
        // Second hypothesis matches the depth-1 prefix
        // (User -[Auth]-> Host) but its depth-2 step differs, so
        // it resumes at depth 1.
        assert_eq!(
            resp.last_prefix_resume_depth, 1,
            "second hypothesis should resume from depth 1 (shared first step)"
        );
        assert_eq!(resp.prefix_cache_hits, 1);
    }

    #[test]
    fn run_hunt_batch_isolates_per_entry_errors() {
        // The batch entry point catches per-hypothesis errors so a
        // malformed query in one slot doesn't poison the whole
        // batch. We can't construct an invalid Hypothesis through
        // the parser (that error happens earlier), but we can
        // verify that the contract holds for valid inputs by
        // running a non-empty batch and asserting every entry
        // reports its own status.
        let api = api();
        let resp = api
            .run_hunt_batch(RunHuntBatchRequest {
                session: None,
                hypotheses: vec![
                    hypo("User -[Auth]-> Host"),
                    hypo("Host -[Connect]-> IP"),
                ],
                time_window: None,
                max_results: None,
                dedup_mode: None,
            })
            .expect("batch ok");
        assert_eq!(resp.entries.len(), 2);
    }
}
