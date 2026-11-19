    pub fn build(graph: &crate::graph::GraphHunter) -> Self {
        let n = graph.entity_type_tags.len();
        let mut bits = vec![0u16; n];

        // Round 0: structural type-bit seed (no temporal contribution
        // — the matrices only encode paths that traverse ≥1 edge).
        for (i, &tag) in graph.entity_type_tags.iter().enumerate() {
            if (tag as usize) < NLF_TYPE_COUNT {
                bits[i] |= 1u16 << tag;
            }
        }

        // First pass: assign ranks to vertices with at least one
        // outgoing edge. Ranks are sequential `0..n_ranked` and live
        // in `min_first` / `max_first` as parallel sparse rows. The
        // single edge_store iter is O(E) and sequential — much
        // friendlier to L2 than the previous HashMap walk.
        let mut rank = vec![NO_RANK; n];
        let mut n_ranked: u32 = 0;
        graph.streaming.for_each_edge(|src_sid, _edge| {
            let s = src_sid.index();
            if s >= n {
                return;
            }
            if rank[s] == NO_RANK {
                rank[s] = n_ranked;
                n_ranked += 1;
            }
        });
        let n_ranked = n_ranked as usize;
