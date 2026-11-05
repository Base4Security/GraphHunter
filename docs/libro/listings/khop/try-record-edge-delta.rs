    pub fn try_record_edge_delta(
        &mut self,
        u: StrId,
        streaming: &crate::streaming::InMemoryStreamingBackend,
        reverse_adj: &ahash::HashMap<StrId, Vec<StrId>>,
        budget: usize,
    ) -> bool {
        // Mmap-spilled temporal arrays are read-only.
        if self.min_first.is_spilled() || self.max_first.is_spilled() {
            return false;
        }
        if u.index() >= self.bits.len() {
            return false;
        }

        // Track which vertex indices we've already processed so the
        // cascade is a BFS — every vertex pays at most one
        // re-build step.
        let mut visited: std::collections::HashSet<u32> =
            std::collections::HashSet::new();
        let mut frontier: Vec<StrId> = vec![u];
        visited.insert(u.index() as u32);

        // Cascade depth = MAX_DEPTH - 1: round 0 is `u`'s own
        // re-build, rounds 1..MAX_DEPTH-1 cover the
        // (MAX_DEPTH-1)-hop reverse neighborhood. A vertex `MAX_DEPTH`
        // hops away from `u` could only reach the new edge through
        // a >MAX_DEPTH-hop path, which the index doesn't track
        // anyway.
        for _round in 0..MAX_DEPTH {
            if frontier.is_empty() {
                break;
            }
            let mut next_frontier: Vec<StrId> = Vec::new();

            for &x in &frontier {
                let x_idx = x.index();
                if x_idx >= self.bits.len() {
                    continue;
                }
                let x_rank_raw = self
                    .rank
                    .get(x_idx)
                    .copied()
                    .unwrap_or(NO_RANK);

                // Walk x's outgoing edges via the streaming
                // backend (which already has the just-appended
                // edge from add_relation's dual-write). Borrow
                // the per-vertex read lock for the iteration —
                // cheaper than `neighbors_snapshot`'s NeighborList
                // clone, which dominated the cascade cost at hub
                // vertices in earlier profiling.
                enum DeltaStep {
                    NoEdges,
                    Done { changed: bool },
                    Abort,
                }

                let step = streaming
                    .with_neighbors(x, |snap| {
                        let mut changed = false;
                        for edge in snap.iter() {
                            let dst_idx = edge.dest_sid.index();
                            if dst_idx >= self.bits.len() {
                                continue;
                            }
                            let target_bits = self.bits[dst_idx];
                            let new_bits = self.bits[x_idx] | target_bits;
                            let bits_grew = new_bits != self.bits[x_idx];
                            if bits_grew {
                                self.bits[x_idx] = new_bits;
                                changed = true;
                            }

                            // Soundness gate: if bits grew but no
                            // rank slot, we'd have to grow the
                            // sparse temporal arrays — out of
                            // scope here, so abort the delta.
                            if x_rank_raw == NO_RANK {
                                if bits_grew {
                                    return DeltaStep::Abort;
                                }
                                continue;
                            }
                            let r = x_rank_raw as usize;
                            let mins = self
                                .min_first
                                .heap_slice_mut()
                                .expect("checked is_spilled at function entry");
                            let maxs = self
                                .max_first
                                .heap_slice_mut()
                                .expect("checked is_spilled at function entry");
                            let mut m = target_bits as u32;
                            while m != 0 {
                                let l = m.trailing_zeros() as usize;
                                m &= m - 1;
                                if l >= NLF_TYPE_COUNT {
                                    continue;
                                }
                                if edge.timestamp < mins[r][l] {
                                    mins[r][l] = edge.timestamp;
                                    changed = true;
                                }
                                if edge.timestamp > maxs[r][l] {
                                    maxs[r][l] = edge.timestamp;
                                    changed = true;
                                }
                            }
                        }
                        DeltaStep::Done { changed }
                    })
                    .unwrap_or(DeltaStep::NoEdges);

                let x_changed = match step {
                    DeltaStep::NoEdges => continue,
                    DeltaStep::Abort => return false,
                    DeltaStep::Done { changed } => changed,
                };

                if x_changed {
                    // Cascade backward: enqueue x's predecessors.
                    if let Some(preds) = reverse_adj.get(&x) {
                        for &w in preds {
                            let w_key = w.index() as u32;
                            if visited.contains(&w_key) {
                                continue;
                            }
                            if visited.len() >= budget {
                                return false;
                            }
                            visited.insert(w_key);
                            next_frontier.push(w);
                        }
                    }
                }
            }

            frontier = next_frontier;
        }

        true
    }
