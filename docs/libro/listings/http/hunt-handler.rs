    /// Execute a temporal pattern search. Populates the hunt cache and
    /// returns either the paths inline (when ≤ 100) or just the count
    /// with the cache populated for pagination.
    ///
    /// Uses the smart DFS when the anomaly scorer has been finalized,
    /// else the plain DFS.
    pub fn run_hunt(&self, req: RunHuntRequest) -> ApiResult<RunHuntResponse> {
        let max_results = req.max_results.unwrap_or(10_000);
        let session = self.resolve_session(req.session.as_ref())?;

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
