        // D5 — k-hop reachability prune: drop starts that cannot reach
        // a vertex of the hypothesis's *final* dest_type within MAX_DEPTH
        // hops. Multi-hop generalization of NLF — only meaningful when
        // the hypothesis is at least 2 steps deep, since NLF already
        // covers the 1-hop case. M2 — when a `time_window` is supplied,
        // additionally reject starts whose first-edge timestamps to the
        // required label can never fit inside the window. Heavy-logs
        // #3.5: also lazy-built.
        let khop_mask = crate::khop_reach::end_type_mask(hypothesis);
        if self.edges_sorted && !crate::khop_reach::is_trivial(khop_mask, hypothesis) {
            let reach = self.ensure_khop_reach();
            start_sids.retain(|&sid| reach.can_reach_in_window(sid, khop_mask, time_window));
        }
