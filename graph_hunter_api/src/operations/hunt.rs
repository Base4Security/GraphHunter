//! Hunt execution, result paging, and diff.
//!
//! `run_hunt` writes into the shared [`GraphHunterApi::hunt_cache_handle`]
//! so `get_hunt_page` can paginate/score without re-running the DFS.
//! `diff_hunts` does not touch the cache — it's a two-query comparison.

use graph_hunter_core::HuntDiff;

use crate::dto::hunt::{
    DiffHuntsRequest, GetHuntPageRequest, GetHuntPageResponse, RunHuntRequest, RunHuntResponse,
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
                let graph = session.graph.read().map_err(|e| {
                    ApiError::Internal(format!("graph lock poisoned: {e}"))
                })?;
                graph
                    .search_temporal_pattern_simd(
                        &req.hypothesis,
                        req.time_window,
                        Some(max_results),
                    )
                    .map_err(|e| ApiError::Internal(format!("search failed: {e}")))?
            }
            #[cfg(not(feature = "simd"))]
            {
                let graph = session.graph.read().map_err(|e| {
                    ApiError::Internal(format!("graph lock poisoned: {e}"))
                })?;
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
            let (scored_page, filtered_count) =
                graph.score_and_paginate_paths(&cache, req.page, req.page_size, req.min_score, mode);
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
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state::Session;
    use graph_hunter_core::{parse_dsl, GraphHunter};
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
}
