        while let Some(frame) = stack.last_mut() {
            if result_count.load(Ordering::Relaxed) >= cap {
                break;
            }

            if frame.step_idx >= steps.len() {
                // B9 — symmetry-breaking filter at emission. For
                // palindromic patterns we keep only canonical-direction
                // matches (path[0] < path[last]); the reverse path is
                // emitted from the mirror start and would be a duplicate.
                if symmetry_hint.keep_match(path) {
                    let prev = result_count.fetch_add(1, Ordering::Relaxed);
                    if prev < cap {
                        // C2: refcount-bump clone instead of `String::from`.
                        // resolve_arc returns an `Arc<str>` already alive in
                        // the interner's storage; per-result work drops from
                        // path.len() heap allocations to path.len() atomic
                        // increments.
                        results.push(
                            path.iter()
                                .map(|&sid| self.interner.resolve_arc(sid))
                                .collect(),
                        );
                    }
                }
                path.pop();
                stack.pop();
                continue;
            }

            let step = &steps[frame.step_idx];
            // Stage 2c part 2 — same parking_lot fast-path migration
            // as dfs_match_smart: arc + guard + slice live for the
            // inner edge loop, drop on next outer iteration.
            let _ = step.relation_type;
            let edges: &[crate::streaming::StreamEdge] = snap
                .neighbors(frame.sid)
                .map(|n| n.as_slice())
                .unwrap_or(&[]);

            let mut found = false;
            while frame.edge_cursor < frame.edge_hi {
                let idx = frame.edge_cursor;
                frame.edge_cursor += 1;
                let edge = &edges[idx];

                // B4: software prefetch of entity_type_tags for dest_sids
                // LOOKAHEAD iterations downstream. The per-edge cache miss
                // is entity_type_tags[edge.dest_sid.index()] inside
                // fast_type_matches; dest_sids are scattered (CSR layout
                // points at arbitrary vertices) so the prefetch target is
                // unpredictable to the HW prefetcher. T0 targets L1.
                #[cfg(target_arch = "x86_64")]
                {
                    const LOOKAHEAD: usize = 8;
                    let probe = idx + LOOKAHEAD;
                    if probe < frame.edge_hi {
                        let probe_dst = edges[probe].dest_sid.index();
                        if probe_dst < self.entity_type_tags.len() {
                            unsafe {
                                use std::arch::x86_64::{_MM_HINT_T0, _mm_prefetch};
                                _mm_prefetch::<_MM_HINT_T0>(
                                    self.entity_type_tags.as_ptr().add(probe_dst) as *const i8,
                                );
                            }
                        }
                    }
                }

                if !relation_type_tag_matches(&step.relation_type, edge.rel_type_tag) {
                    continue;
                }

                let dest_sid = edge.dest_sid;
                if !self.fast_type_matches(&step.dest_type, dest_sid) {
                    continue;
                }

                // Metadata predicates (3.A, iterative DFS path).
                if !step.edge_predicates.is_empty() {
                    let metadata = if edge.metadata_offset != 0 {
                        self.meta_store.get(edge.metadata_offset)
                    } else {
                        std::collections::HashMap::new()
                    };
                    if !crate::hypothesis::all_predicates_match(&step.edge_predicates, &metadata) {
                        continue;
                    }
                }

                // Destination-node predicates (B.2).
                if !step.dest_predicates.is_empty() {
                    let entity = match self.entities.get(&dest_sid) {
                        Some(e) => e,
                        None => continue,
                    };
                    if !crate::hypothesis::all_predicates_match(
                        &step.dest_predicates,
                        &entity.metadata,
                    ) {
                        continue;
                    }
                }

                // C0: linear scan over `path` replaces the visit_count
                // HashMap. For depth ≤ 8 (DfsPath SmallVec inline cap)
                // the scan fits in one L1 cache line; HashMap.get on
                // the hot path was hash + bucket chase per check, plus
                // entry/insert/remove on every push/pop. Early-exit
                // once we hit `k` matches so the scan cost is bounded
                // regardless of `path` length.
                let mut count = 0usize;
                for &s in path.iter() {
                    if s == dest_sid {
                        count += 1;
                        if count >= k {
                            break;
                        }
                    }
                }
                if count >= k {
                    continue;
                }

                path.push(dest_sid);

                let next_step_idx = frame.step_idx + 1;
                let (next_lo, next_hi) = if next_step_idx < steps.len() {
                    self.edge_range_sid(
                        dest_sid,
                        &steps[next_step_idx],
                        edge.timestamp,
                        time_window,
                    )
                } else {
                    (0, 0)
                };

                stack.push(DfsFrame {
                    sid: dest_sid,
                    step_idx: next_step_idx,
                    edge_hi: next_hi,
                    edge_cursor: next_lo,
                });
                found = true;
                break;
            }

            if !found {
                path.pop();
                stack.pop();
            }
        }
    }
