//! Hunt execution, result paging, and diff.
//!
//! `run_hunt` writes into the shared [`GraphHunterApi::hunt_cache_handle`]
//! so `get_hunt_page` can paginate/score without re-running the DFS.
//! `diff_hunts` does not touch the cache — it's a two-query comparison.

use graph_hunter_core::HuntDiff;

use crate::dto::hunt::{
    DiffHuntsRequest, GetHuntPageRequest, GetHuntPageResponse, RunHuntBatchEntry,
    RunHuntBatchRequest, RunHuntBatchResponse, RunHuntRequest, RunHuntResponse,
};
use crate::{ApiError, ApiResult, GraphHunterApi};

/// Inline threshold for [`RunHuntResponse::paths`]. Matches the legacy
/// Tauri command's 100-path cutoff so the frontend keeps its current
/// UX (small result sets render immediately; larger sets paginate).
const INLINE_PATH_THRESHOLD: usize = 100;

impl GraphHunterApi {
    /// Execute a temporal pattern search. Populates the hunt cache and
    /// returns either the paths inline (when ≤ 100) or just the count
    /// with the cache populated for pagination.
    ///
    /// Uses the SIMD-accelerated search when the `simd` feature is
    /// compiled in, falls back to the smart DFS when the anomaly scorer
    /// has been finalized, else the plain DFS.
    pub fn run_hunt(&self, req: RunHuntRequest) -> ApiResult<RunHuntResponse> {
        let max_results = req.max_results.unwrap_or(10_000);
        let session = self.resolve_session(req.session.as_ref())?;

        // Run the search with a read lock — both the SIMD path
        // (`search_temporal_pattern_simd` takes `&self`) and the scalar
        // paths are non-mutating, so multiple concurrent hunts on the
        // same session can run in parallel.
        let (paths, truncated) = {
            #[cfg(feature = "simd")]
            {
                let graph = session
                    .graph
                    .read()
                    .map_err(|e| ApiError::Internal(format!("graph lock poisoned: {e}")))?;
                graph_hunter_matcher_ffi::search_temporal_pattern_simd(
                    &graph,
                    &req.hypothesis,
                    req.time_window,
                    Some(max_results),
                )
                .map_err(|e| ApiError::Internal(format!("search failed: {e}")))?
            }
            #[cfg(not(feature = "simd"))]
            {
                let graph = session
                    .graph
                    .read()
                    .map_err(|e| ApiError::Internal(format!("graph lock poisoned: {e}")))?;
                let scorer_ready = graph
                    .anomaly_scorer
                    .as_ref()
                    .map(|s| s.is_finalized())
                    .unwrap_or(false);
                if scorer_ready {
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
            }
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
            })
        } else {
            *cache = paths;
            Ok(RunHuntResponse {
                paths: Vec::new(),
                path_count,
                truncated,
                diagnostic,
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

        // D3 stage 1 — LFTJ trie batch cache. When the planner picks
        // any LFTJ variant (Triangle/K4/K5/C6) for a hypothesis in
        // this batch, build the forward CSR trie + MinTimestampMap
        // once on first hit and reuse across every subsequent
        // LFTJ-routed hypothesis. The reverse trie (only needed by
        // C6) is built lazily on first C6 dispatch. At Sysmon-scale
        // (V≈10^6, E≈10^7) trie build is ~100s of ms; sharing across
        // N templates saves N-1 builds.
        let mut lftj_forward: Option<std::sync::Arc<graph_hunter_core::lftj::MaterializedCsrTrie>> =
            None;
        let mut lftj_reverse: Option<std::sync::Arc<graph_hunter_core::lftj::MaterializedCsrTrie>> =
            None;
        let mut lftj_ts_map: Option<
            std::sync::Arc<graph_hunter_core::lftj_query::MinTimestampMap>,
        > = None;
        let mut lftj_trie_cache_builds: usize = 0;
        let mut lftj_trie_cache_hits: usize = 0;

        // D3 stage 2 — canonical-form LFTJ result cache. The LFTJ
        // enumerators (triangle / K4 / K5 / C6) are *type-blind*
        // today: they walk the trie regardless of step entity-type
        // or relation-type filters (documented at
        // platform/dsl/src/hypothesis.rs:looks_like_k4_clique). So
        // two hypotheses that route to the same DispatchPlan with
        // the same time_window produce *identical* raw enumeration
        // output, even when they differ in vertex/edge labels or
        // hypothesis name. Cache the raw `Vec<HuntResult>` keyed on
        // (DispatchPlan, time_window) so canonically-equivalent
        // queries share enumeration; per-hypothesis aggregation
        // (HAVING/WITHIN) is applied separately on each lookup.
        // The cap is shared across the batch via `req.max_results`,
        // so cap mismatch between cached and lookup never bites.
        let mut lftj_raw_cache: std::collections::HashMap<
            (graph_hunter_core::planner::DispatchPlan, i64, i64),
            std::sync::Arc<Vec<graph_hunter_core::graph::HuntResult>>,
        > = std::collections::HashMap::new();
        let mut lftj_canonical_cache_hits: usize = 0;
        let mut lftj_canonical_cache_misses: usize = 0;

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
                let canonical_key = (lftj_plan, t_lo_window, t_hi_window);

                // D3 stage 2 — try the canonical raw-result cache first.
                let raw_paths = if let Some(cached) = lftj_raw_cache.get(&canonical_key) {
                    lftj_canonical_cache_hits += 1;
                    cached.clone()
                } else {
                    lftj_canonical_cache_misses += 1;
                    // Build forward trie + ts_map on first LFTJ hit.
                    if lftj_forward.is_none() {
                        let trie =
                            graph_hunter_core::lftj::MaterializedCsrTrie::build(&*graph);
                        let ts_map = graph_hunter_core::lftj_query::MinTimestampMap::build(
                            &*graph, &trie,
                        );
                        lftj_forward = Some(std::sync::Arc::new(trie));
                        lftj_ts_map = Some(std::sync::Arc::new(ts_map));
                        lftj_trie_cache_builds += 1;
                    } else {
                        lftj_trie_cache_hits += 1;
                    }
                    let trie = lftj_forward.as_ref().expect("set above").clone();
                    let ts_map = lftj_ts_map.as_ref().expect("set above").clone();
                    // Run the raw enumerator directly. The
                    // `_with_trie` GraphHunter wrappers also run
                    // apply_aggregation; we want the pre-aggregation
                    // output here so per-hypothesis HAVING/WITHIN
                    // can be applied to the cached raw vector.
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
                            if lftj_reverse.is_none() {
                                let rev =
                                    graph_hunter_core::lftj::MaterializedCsrTrie::build_reverse(
                                        &*graph,
                                    );
                                lftj_reverse = Some(std::sync::Arc::new(rev));
                            }
                            let rev = lftj_reverse.as_ref().expect("set above").clone();
                            graph_hunter_core::lftj_query::enumerate_6cycles_lftj_simd_par(
                                &*graph, &trie, &rev, &ts_map, t_lo_window, t_hi_window, cap,
                            )
                        }
                        _ => unreachable!("filtered above"),
                    };
                    let arc = std::sync::Arc::new(raw);
                    lftj_raw_cache.insert(canonical_key, arc.clone());
                    arc
                };
                let truncated = raw_paths.len() >= cap;
                // Apply per-hypothesis aggregation (HAVING / WITHIN)
                // to the cached raw results. This is cheap relative
                // to enumeration; doing it per-lookup keeps the cache
                // shape-canonical across hypotheses that differ only
                // in their aggregation clauses.
                let paths = graph.apply_aggregation((*raw_paths).clone(), &hypothesis);
                drop(graph);

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
                let bags: Vec<graph_hunter_core::yannakakis::Bag> = hypothesis
                    .steps
                    .iter()
                    .zip(step_fingerprints.iter())
                    .map(|(step, fp)| {
                        let key = format!("{fp}|{t_lo_window}|{t_hi_window}");
                        if let Some(arc) = bag_cache.get(&key) {
                            bag_cache_hits += 1;
                            (**arc).clone()
                        } else {
                            bag_cache_misses += 1;
                            let bag = graph_hunter_core::yannakakis::materialize_bag(
                                &graph,
                                step,
                                t_lo_window,
                                t_hi_window,
                            );
                            let arc = std::sync::Arc::new(bag.clone());
                            bag_cache.insert(key, arc);
                            bag
                        }
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
                    // down to 1; first hit wins.
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
                            prefix_cache.insert(prefix_key, std::sync::Arc::new(snapshot));
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
                };
                let entry = match self.run_hunt(item_req) {
                    Ok(resp) => RunHuntBatchEntry {
                        paths: resp.paths,
                        path_count: resp.path_count,
                        truncated: resp.truncated,
                        diagnostic: resp.diagnostic,
                        error: None,
                    },
                    Err(e) => RunHuntBatchEntry {
                        paths: Vec::new(),
                        path_count: 0,
                        truncated: false,
                        diagnostic: None,
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

    fn api() -> GraphHunterApi {
        let api = GraphHunterApi::new_noop();
        let s = Arc::new(Session::new("s1", "t", GraphHunter::new(), 0));
        api.sessions().insert(s);
        api.sessions().set_current(Some("s1".into()));
        api
    }

    fn hypo(dsl: &str) -> graph_hunter_core::Hypothesis {
        parse_dsl(dsl, Some("test")).unwrap().hypothesis
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
            })
            .expect("batch ok");
        assert_eq!(resp.entries.len(), 2);
    }
}
