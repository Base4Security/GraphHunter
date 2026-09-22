    fn dfs_match_iterative(
        &self,
        start_sid: StrId,
        steps: &[crate::hypothesis::HypothesisStep],
        time_window: Option<(i64, i64)>,
        k: usize,
        cap: usize,
        result_count: &AtomicUsize,
        results: &mut Vec<HuntResult>,
        path: &mut DfsPath,
        stack: &mut Vec<DfsFrame>,
        symmetry_hint: crate::symmetry::SymmetryHint,
    ) {
        // Reset scratch state. The DFS leaves them empty on a normal exit, but
        // an early break on `cap` reached can leave residue — clear defensively.
        path.clear();
        stack.clear();

        path.push(start_sid);

        let (lo, hi) = if !steps.is_empty() {
            self.edge_range_sid(start_sid, &steps[0], i64::MIN, time_window)
        } else {
            (0, 0)
        };

        stack.push(DfsFrame {
            sid: start_sid,
            step_idx: 0,
            edge_hi: hi,
            edge_cursor: lo,
        });

        // Hoist the streaming snapshot above the per-frame loop —
        // see dfs_match_smart for rationale.
        let snap = self.streaming_snapshot();
