        // B2 — NLF prune: drop starts that can't satisfy the first step's
        // `dest_type` requirement. Skipped when the requirement is trivial
        // (Any / Other dest_type). Heavy-logs #3.5: NLF builds lazily on
        // first non-trivial query — this avoids paying the O(E) index
        // cost for queries that wouldn't use it.
        let nlf_req = crate::nlf::requirement_from_first_step(first_step);
        if self.edges_sorted && !crate::nlf::is_trivial(&nlf_req) {
            let nlf = self.ensure_nlf();
            start_sids.retain(|&sid| nlf.can_match(sid, &nlf_req));
        }
