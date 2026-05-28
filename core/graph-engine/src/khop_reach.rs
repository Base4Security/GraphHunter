//! D5 — k-hop label reachability index.
//!
//! For every vertex `v` we precompute a 16-bit bitmap of entity types
//! reachable from `v` within at most `MAX_DEPTH` outgoing hops (ignoring
//! time order). At query entry, the matcher checks whether each
//! `start_sid` can reach a vertex of the type required by the
//! hypothesis's *last* step's `dest_type`; vertices that fail are pruned
//! before they ever enter `dfs_match_iterative`.
//!
//! This complements B2's NLF table, which prunes by *one-hop* neighbor
//! histograms. NLF catches "this vertex has no IP neighbor" in O(1); D5
//! catches "this vertex cannot reach any IP within MAX_DEPTH hops"
//! after `MAX_DEPTH` rounds of label propagation.
//!
//! M2 — time-aware extension. On top of the static bitmap we now track
//! two parallel matrices `min_first[v][L]` and `max_first[v][L]`: the
//! *minimum* and *maximum* first-edge timestamp on any structural path
//! of length ≤ MAX_DEPTH from `v` ending at a vertex of type `L`. With
//! a query time window `[lo, hi)` the prune additionally rejects `v`
//! when `min_first[v][L] ≥ hi` (no useful first edge ever fits before
//! the window closes) or when `max_first[v][L] < lo` (every useful
//! first edge happens before the window opens). The bitmap remains the
//! authoritative *structural* reachability check; the temporal bounds
//! are an additional necessary condition layered on top.
//!
//! Honest scope: this is *not* full time-respecting reachability
//! (HR-Index style — Akiba-Iwata-Yoshida SIGMOD 2013 + temporal
//! extensions): we don't enforce the strict t1<t2<...<tk chain at build
//! time, only the first-edge bound. The DFS proper still validates the
//! complete chain. A miss prune is a perf loss, never a correctness
//! bug, so the conservative pass-through is safe.
//!
//! Build cost: O(MAX_DEPTH × E × |Σ|) over the whole graph; runs once
//! inside `sort_edges_by_timestamp` after NLF. Memory: `2 + 2·9·8 = 146
//! bytes/vertex` — 146 MB for 1M vertices, dominated by NLF's 36 MB
//! plus this matrix.

use crate::hypothesis::Hypothesis;
use crate::interner::StrId;
use crate::nlf::NLF_TYPE_COUNT;

/// Maximum hop depth tracked. Hypotheses deeper than this fall back to
/// the union-of-all-types bitmap (i.e. the prune is a no-op for those
/// queries — still correct, just no help). Set to 4 because the bench
/// workloads top out at 4-hop and most ATT&CK kill chains fit in 4–6
/// hops.
pub const MAX_DEPTH: usize = 4;

/// Sentinel rank value meaning "this vertex has no temporal entry".
/// Vertices without outgoing edges contribute nothing to the temporal
/// matrices (their min/max-first arrays would be all-default), so we
/// don't allocate slots for them.
const NO_RANK: u32 = u32::MAX;

/// Per-vertex bitmap of entity types reachable within `MAX_DEPTH` hops,
/// plus a sparse temporal extension that bounds the timestamp of the
/// first edge on any reachable path.
///
/// **Storage layout (integral 28GB-class redesign).**
///
/// * `bits` is dense (2 B/vertex) and tracks structural reachability
///   regardless of timestamps. Cheap enough to keep dense even at
///   100M vertices (200 MB).
///
/// * `rank` is dense u32/vertex; for each vertex it gives the row
///   index into `min_first` / `max_first`, or `NO_RANK` when the
///   vertex has no outgoing edges (and therefore no useful temporal
///   contribution). At 100M vertices this is 400 MB.
///
/// * `min_first` and `max_first` are **sparse** — one row per vertex
///   that has at least one outgoing edge. On Sysmon/EVTX-shaped
///   graphs this is typically 30–50% of vertices, so we save 50–70%
///   on the temporal matrices versus the dense layout. Each row is
///   `NLF_TYPE_COUNT` `i64` slots (72 B) instead of pure bytes
///   because we need to retain absolute-timestamp precision over the
///   full retention window (i32 deltas would overflow ms-resolution
///   timestamps after 25 days).
///
/// On a 28 GB EVTX (~100M vertices, ~30M with outgoing edges,
/// ~200M edges) the total footprint is roughly:
///   bits 200 MB + rank 400 MB + min/max 30M × 144 B ≈ 4.9 GB,
/// versus the previous dense layout's 14.6 GB. The build cost is
/// also lower because the per-vertex inner loop only walks ranked
/// vertices and avoids the HashMap iteration over `entities.keys()`.
#[derive(Clone, Default, Debug)]
pub struct KHopReach {
    pub bits: Vec<u16>,
    rank: Vec<u32>,
    min_first: crate::index_storage::IndexBacking<[i64; NLF_TYPE_COUNT]>,
    max_first: crate::index_storage::IndexBacking<[i64; NLF_TYPE_COUNT]>,
}

impl KHopReach {
    /// Build the reachability bitmap by `MAX_DEPTH` rounds of label
    /// propagation. Round 0 seeds each vertex with its own type bit;
    /// each subsequent round ORs in every outgoing neighbor's bitmap.
    /// Reads adjacency via `get_relations_by_sid` (bypasses time-window
    /// gating — we want unconditional reachability for the prune).
    ///
    /// In the same passes we accumulate `min_first[v][L]` /
    /// `max_first[v][L]`. A round-1 edge `(u, v, t)` with `type(v) = L`
    /// directly contributes `t` to `(u, L)`. Subsequent rounds propagate
    /// through pass-through neighbors: when `(u, v, t)` exists and
    /// `bits[v]` already has `L` set in the previous round's snapshot,
    /// `(u, L)` inherits the timestamp `t` (the first edge on the
    /// extended path is `t`, regardless of how `v` reaches `L`
    /// internally). This is a pessimistic over-approximation — a miss
    /// is a structural-vs-temporal mismatch and the DFS will still
    /// validate the chain.
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

        // Heap-or-mmap backings for the temporal arrays. Build phase
        // gets `&mut [[i64; 9]]` either way; the auto-spill threshold
        // (default 1 GiB per array, configurable via
        // GRAPHHUNTER_INDEX_HEAP_BUDGET) decides where the bytes
        // live. On a 100M-vertex EVTX with ~30M ranked entries each
        // array is ~2.16 GB, so it spills to disk by default.
        //
        // We need to do all `MAX_DEPTH` rounds of propagation inside
        // a single `build_with_writer` call so we can mutate the
        // rows in place without an intermediate Vec. Because both
        // arrays need writing, we build them sequentially: the inner
        // closure for `min_first` does the bitmap propagation and
        // writes min/max in a temporary heap-side `max_first_buf`
        // first, then we materialize `max_first` from that buffer.
        //
        // This trades one transient `Vec<[i64; 9]>` for the build
        // window — but it's still the right shape because the build
        // is one-shot and the transient is freed before queries
        // start. Total peak during build = bits + rank + bits_snap +
        // min_first (mmap'd) + max_first transient ≈ 2.6 GB instead
        // of the dense 14.4 GB.
        let mut max_first_buf = vec![[i64::MIN; NLF_TYPE_COUNT]; n_ranked];
        let min_first = crate::index_storage::IndexBacking::build_with_writer(
            n_ranked,
            [i64::MAX; NLF_TYPE_COUNT],
            |min_first| {
                for _ in 0..MAX_DEPTH {
                    let bits_snapshot = bits.clone();
                    for v_idx in 0..n {
                        let r = rank[v_idx];
                        if r == NO_RANK {
                            continue;
                        }
                        let r = r as usize;
                        let sid = StrId::from_raw(v_idx as u32);
                        let mut acc = bits[v_idx];
                        let mut row_min = min_first[r];
                        let mut row_max = max_first_buf[r];
                        if let Some(arc) = graph.streaming.neighbors_arc(sid) {
                            let g = arc.read();
                            for edge in g.as_slice() {
                                let dst = edge.dest_sid.index();
                                if dst >= bits_snapshot.len() {
                                    continue;
                                }
                                acc |= bits_snapshot[dst];

                                // Temporal contribution: this edge's
                                // timestamp is the candidate "first edge"
                                // for every label `L` that the destination
                                // already reaches in the previous round
                                // (or trivially: its own type).
                                let t = edge.timestamp;
                                let dst_bits = bits_snapshot[dst];
                                let mut m = dst_bits as u32;
                                while m != 0 {
                                    let l = m.trailing_zeros() as usize;
                                    m &= m - 1;
                                    if l < NLF_TYPE_COUNT {
                                        if t < row_min[l] {
                                            row_min[l] = t;
                                        }
                                        if t > row_max[l] {
                                            row_max[l] = t;
                                        }
                                    }
                                }
                            }
                        }
                        bits[v_idx] = acc;
                        min_first[r] = row_min;
                        max_first_buf[r] = row_max;
                    }
                }
            },
        )
        .expect("temp file for min_first index");
        let max_first = crate::index_storage::IndexBacking::build_with_writer(
            n_ranked,
            [i64::MIN; NLF_TYPE_COUNT],
            |max_first| {
                max_first.copy_from_slice(&max_first_buf);
            },
        )
        .expect("temp file for max_first index");
        drop(max_first_buf);

        Self {
            bits,
            rank,
            min_first,
            max_first,
        }
    }

    /// Memory footprint in bytes — useful for the `/metrics` endpoint
    /// and for diagnosing post-ingest RAM spikes on large graphs.
    /// Note: when the temporal arrays are mmap-spilled, `bytes()`
    /// reports the on-disk size; resident RAM is bounded by the OS
    /// page cache instead.
    pub fn memory_bytes(&self) -> usize {
        self.bits.capacity() * std::mem::size_of::<u16>()
            + self.rank.capacity() * std::mem::size_of::<u32>()
            + self.min_first.bytes()
            + self.max_first.bytes()
    }

    /// True iff the temporal arrays were spilled to a memory-mapped
    /// temp file. Surfaced through the perf-status command so the
    /// UI can show "indexes spilled" when relevant.
    pub fn is_spilled(&self) -> bool {
        self.min_first.is_spilled() || self.max_first.is_spilled()
    }

    /// Test/diagnostic accessor: read the (min, max) first-edge
    /// timestamps for `sid` toward label slot `label_slot`. Returns
    /// `None` when the vertex has no temporal rank (no outgoing
    /// edges) or when `label_slot` is out of range.
    pub fn temporal_bounds(&self, sid: StrId, label_slot: usize) -> Option<(i64, i64)> {
        if label_slot >= NLF_TYPE_COUNT {
            return None;
        }
        let r = *self.rank.get(sid.index())?;
        if r == NO_RANK {
            return None;
        }
        let r = r as usize;
        let mins = self.min_first.as_slice();
        let maxs = self.max_first.as_slice();
        Some((mins[r][label_slot], maxs[r][label_slot]))
    }

    /// L3 stage 2b — incremental delta-update for a newly-added
    /// edge whose origin is `u`.
    ///
    /// Algorithm (reverse-frontier propagation, soundness-preserving
    /// over-approximation):
    ///
    /// * Round 0: re-apply one build step for `u`. Walk every
    ///   outgoing edge (`u`, `v`, `t`) — including the one that
    ///   just got pushed — and propagate `bits[v]` into `bits[u]`,
    ///   updating `min_first[u]` / `max_first[u]` for each label
    ///   in `bits[v]` using `t`.
    /// * Rounds 1..MAX\_DEPTH-1: cascade backward. For every
    ///   vertex `x` whose row changed in the previous round, walk
    ///   its predecessors (`reverse_adj`) and re-apply the same
    ///   build step for each predecessor `w`. Repeat up to
    ///   `MAX_DEPTH-1` rounds — that's enough to reach every
    ///   vertex within `MAX_DEPTH` hops of `u`.
    ///
    /// Soundness. The update only ORs bits and only lowers
    /// `min_first` / raises `max_first`. The post-update index is
    /// always a super-set of the true reachability — the matcher's
    /// prune stays sound.
    ///
    /// Returns `true` when the cascade completed without exceeding
    /// `budget` (max distinct vertices visited). Returns `false`
    /// when:
    ///   * the temporal arrays are mmap-spilled (read-only post-build);
    ///   * a vertex without a rank slot needs a temporal update
    ///     (we'd have to grow the sparse `min_first`/`max_first`
    ///     IndexBackings — left for a future stage);
    ///   * the cascade visited > `budget` distinct vertices
    ///     (hub blowout — caller falls back to invalidate).
    ///
    /// On `false`, the index may be partially updated; the caller
    /// must invalidate to regain a clean state.
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

    /// True iff vertex `sid` can reach (within `MAX_DEPTH` hops) at least
    /// one vertex matching every bit set in `required_mask`. Vertices
    /// outside the bitmap range conservatively pass — a missed prune is a
    /// perf loss, not a correctness bug.
    #[inline]
    pub fn can_reach(&self, sid: StrId, required_mask: u16) -> bool {
        match self.bits.get(sid.index()) {
            Some(&b) => (b & required_mask) == required_mask,
            None => required_mask == 0,
        }
    }

    /// M2 — time-aware predicate. Returns `true` iff `sid` can reach
    /// every label in `required_mask` *and*, when a `time_window` is
    /// provided, at least one structural path's first edge could plausibly
    /// fall inside `[lo, hi)`. When `time_window` is `None` this reduces
    /// to `can_reach`. Out-of-range `sid` conservatively passes; vertices
    /// with no rank (no outgoing edges) also pass — they have no
    /// temporal info to refute the predicate.
    #[inline]
    pub fn can_reach_in_window(
        &self,
        sid: StrId,
        required_mask: u16,
        time_window: Option<(i64, i64)>,
    ) -> bool {
        let idx = sid.index();
        let bits = match self.bits.get(idx) {
            Some(&b) => b,
            None => return required_mask == 0,
        };
        if (bits & required_mask) != required_mask {
            return false;
        }
        if let Some((lo, hi)) = time_window {
            // Skip the bound check when the window is the unbounded
            // sentinel — same answer as the static path, no cycles
            // wasted iterating bits.
            if lo == i64::MIN && hi == i64::MAX {
                return true;
            }
            // Sparse temporal rows: vertices without outgoing edges
            // have rank == NO_RANK, no entry to consult, so we
            // conservatively pass.
            let r = match self.rank.get(idx) {
                Some(&r) if r != NO_RANK => r as usize,
                _ => return true,
            };
            let mins = &self.min_first.as_slice()[r];
            let maxs = &self.max_first.as_slice()[r];
            let mut m = required_mask as u32;
            while m != 0 {
                let l = m.trailing_zeros() as usize;
                m &= m - 1;
                if l >= NLF_TYPE_COUNT {
                    continue;
                }
                if mins[l] >= hi || maxs[l] < lo {
                    return false;
                }
            }
        }
        true
    }
}

/// Compute the reachability requirement at the start vertex from the
/// hypothesis's final-step `dest_type`. A concrete dest type contributes
/// one bit; `Any` and `Other(_)` produce a zero mask, in which case
/// callers should skip the prune (every vertex trivially passes).
pub fn end_type_mask(hypothesis: &Hypothesis) -> u16 {
    let last_step = match hypothesis.steps.last() {
        Some(s) => s,
        None => return 0,
    };
    let tag = last_step.dest_type.to_u8();
    if (tag as usize) < NLF_TYPE_COUNT {
        1u16 << tag
    } else {
        0
    }
}

/// Skip the prune pass when the requirement is trivial (zero mask, or
/// hypothesis is single-step — NLF B2 already handles 1-hop).
#[inline]
pub fn is_trivial(mask: u16, hypothesis: &Hypothesis) -> bool {
    mask == 0 || hypothesis.steps.len() <= 1
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::graph::GraphHunter;
    use crate::hypothesis::HypothesisStep;
    use crate::types::{EntityType, RelationType};
    use crate::{Entity, Relation};

    /// Three-hop chain: User → Host → Process → IP.
    fn three_hop_chain() -> GraphHunter {
        let mut g = GraphHunter::new();
        g.add_entity(Entity::new("u1", EntityType::User)).unwrap();
        g.add_entity(Entity::new("h1", EntityType::Host)).unwrap();
        g.add_entity(Entity::new("p1", EntityType::Process)).unwrap();
        g.add_entity(Entity::new("ip1", EntityType::IP)).unwrap();
        g.add_relation(Relation::new("u1", "h1", RelationType::Auth, 100))
            .unwrap();
        g.add_relation(Relation::new("h1", "p1", RelationType::Spawn, 110))
            .unwrap();
        g.add_relation(Relation::new("p1", "ip1", RelationType::Connect, 120))
            .unwrap();
        g.sort_edges_by_timestamp().unwrap();
        g
    }

    #[test]
    fn build_propagates_through_chain() {
        let g = three_hop_chain();
        let reach = KHopReach::build(&g);
        let u_sid = g.interner.get("u1").unwrap();
        let bits = reach.bits[u_sid.index()];
        // u1 should reach Host, Process, and IP within MAX_DEPTH=4.
        assert!(bits & (1 << EntityType::Host.to_u8()) != 0);
        assert!(bits & (1 << EntityType::Process.to_u8()) != 0);
        assert!(bits & (1 << EntityType::IP.to_u8()) != 0);
        // ...and itself.
        assert!(bits & (1 << EntityType::User.to_u8()) != 0);
    }

    #[test]
    fn can_reach_concrete_endpoint() {
        let g = three_hop_chain();
        let reach = KHopReach::build(&g);
        let u_sid = g.interner.get("u1").unwrap();
        let mask = 1u16 << EntityType::IP.to_u8();
        assert!(reach.can_reach(u_sid, mask));
    }

    #[test]
    fn cannot_reach_disconnected_type() {
        let mut g = three_hop_chain();
        // Add an isolated Domain vertex with no edges from the chain.
        g.add_entity(Entity::new("d1", EntityType::Domain)).unwrap();
        g.sort_edges_by_timestamp().unwrap();
        let reach = KHopReach::build(&g);
        let u_sid = g.interner.get("u1").unwrap();
        let mask = 1u16 << EntityType::Domain.to_u8();
        assert!(!reach.can_reach(u_sid, mask));
    }

    #[test]
    fn end_type_mask_concrete() {
        let h = Hypothesis::new("test").add_step(HypothesisStep::new(
            EntityType::User,
            RelationType::Auth,
            EntityType::IP,
        ));
        let mask = end_type_mask(&h);
        assert_eq!(mask, 1u16 << EntityType::IP.to_u8());
    }

    #[test]
    fn end_type_mask_any_is_zero() {
        let h = Hypothesis::new("test").add_step(HypothesisStep::new(
            EntityType::User,
            RelationType::Auth,
            EntityType::Any,
        ));
        assert_eq!(end_type_mask(&h), 0);
    }

    #[test]
    fn is_trivial_for_single_step() {
        let h = Hypothesis::new("test").add_step(HypothesisStep::new(
            EntityType::User,
            RelationType::Auth,
            EntityType::Host,
        ));
        // Single-step hypotheses are trivial — NLF (B2) already handles 1-hop.
        assert!(is_trivial(end_type_mask(&h), &h));
    }

    // ── M2 — temporal-aware predicate tests ───────────────────────────

    #[test]
    fn temporal_min_first_matches_first_edge_on_chain() {
        // u1 -t=100-> h1 -t=110-> p1 -t=120-> ip1
        // The min first-edge timestamp from u1 toward IP is 100 (the
        // u1→h1 edge that opens any path to ip1).
        let g = three_hop_chain();
        let reach = KHopReach::build(&g);
        let u_sid = g.interner.get("u1").unwrap();
        let ip_slot = EntityType::IP.to_u8() as usize;
        let (mn, mx) = reach.temporal_bounds(u_sid, ip_slot).unwrap();
        assert_eq!(mn, 100);
        assert_eq!(mx, 100);
    }

    #[test]
    fn temporal_window_passes_when_first_edge_inside() {
        let g = three_hop_chain();
        let reach = KHopReach::build(&g);
        let u_sid = g.interner.get("u1").unwrap();
        let mask = 1u16 << EntityType::IP.to_u8();
        // Window covers t=100 (the u1→h1 edge).
        assert!(reach.can_reach_in_window(u_sid, mask, Some((50, 200))));
    }

    #[test]
    fn temporal_window_rejects_when_first_edge_after_window() {
        let g = three_hop_chain();
        let reach = KHopReach::build(&g);
        let u_sid = g.interner.get("u1").unwrap();
        let mask = 1u16 << EntityType::IP.to_u8();
        // Window closes before t=100, so the only first edge that can
        // open a path to IP is unreachable inside [0, 50).
        assert!(!reach.can_reach_in_window(u_sid, mask, Some((0, 50))));
    }

    #[test]
    fn temporal_window_rejects_when_first_edge_before_window() {
        let g = three_hop_chain();
        let reach = KHopReach::build(&g);
        let u_sid = g.interner.get("u1").unwrap();
        let mask = 1u16 << EntityType::IP.to_u8();
        // Window opens after t=100, so every relevant first edge fired
        // before lo and the prune fires correctly.
        assert!(!reach.can_reach_in_window(u_sid, mask, Some((150, 300))));
    }

    #[test]
    fn temporal_window_falls_back_to_static_when_no_window() {
        let g = three_hop_chain();
        let reach = KHopReach::build(&g);
        let u_sid = g.interner.get("u1").unwrap();
        let mask = 1u16 << EntityType::IP.to_u8();
        assert!(reach.can_reach_in_window(u_sid, mask, None));
    }

    #[test]
    fn temporal_window_unbounded_sentinel_is_static() {
        // The matcher passes (i64::MIN, i64::MAX) when callers omit the
        // window. The fast-path skips the bound check entirely in that
        // case to keep the predicate as cheap as the static one.
        let g = three_hop_chain();
        let reach = KHopReach::build(&g);
        let u_sid = g.interner.get("u1").unwrap();
        let mask = 1u16 << EntityType::IP.to_u8();
        assert!(reach.can_reach_in_window(u_sid, mask, Some((i64::MIN, i64::MAX))));
    }

    #[test]
    fn temporal_window_disconnected_label_still_rejected() {
        // Same chain plus an isolated Domain vertex: even with a wide
        // window, the structural check fails first.
        let mut g = three_hop_chain();
        g.add_entity(Entity::new("d1", EntityType::Domain)).unwrap();
        g.sort_edges_by_timestamp().unwrap();
        let reach = KHopReach::build(&g);
        let u_sid = g.interner.get("u1").unwrap();
        let mask = 1u16 << EntityType::Domain.to_u8();
        assert!(!reach.can_reach_in_window(u_sid, mask, Some((0, i64::MAX))));
    }

    #[test]
    fn temporal_branching_keeps_min_and_max() {
        // u1 has two first edges to two paths reaching IP at t=10 and
        // t=200. The min/max should bracket the window correctly.
        let mut g = GraphHunter::new();
        g.add_entity(Entity::new("u1", EntityType::User)).unwrap();
        g.add_entity(Entity::new("h1", EntityType::Host)).unwrap();
        g.add_entity(Entity::new("h2", EntityType::Host)).unwrap();
        g.add_entity(Entity::new("ip1", EntityType::IP)).unwrap();
        g.add_relation(Relation::new("u1", "h1", RelationType::Auth, 10))
            .unwrap();
        g.add_relation(Relation::new("u1", "h2", RelationType::Auth, 200))
            .unwrap();
        g.add_relation(Relation::new("h1", "ip1", RelationType::Connect, 50))
            .unwrap();
        g.add_relation(Relation::new("h2", "ip1", RelationType::Connect, 250))
            .unwrap();
        g.sort_edges_by_timestamp().unwrap();
        let reach = KHopReach::build(&g);
        let u_sid = g.interner.get("u1").unwrap();
        let ip_slot = EntityType::IP.to_u8() as usize;
        let (mn, mx) = reach.temporal_bounds(u_sid, ip_slot).unwrap();
        assert_eq!(mn, 10);
        assert_eq!(mx, 200);
        // Mid window covers the t=10 path's first edge but not the
        // t=200 one — still passes because at least one path fits.
        let mask = 1u16 << EntityType::IP.to_u8();
        assert!(reach.can_reach_in_window(u_sid, mask, Some((0, 100))));
        // Window way after every first edge — both paths excluded.
        assert!(!reach.can_reach_in_window(u_sid, mask, Some((300, 400))));
    }

    // L3 stage 2b — delta-update tests.

    #[test]
    fn delta_update_after_new_edge_matches_full_rebuild() {
        // C2 fix: after finalization, a post-finalize append INVALIDATES the
        // khop_reach index instead of applying an incremental delta (which
        // would read BASE neighbors only and miss the tail). The index is then
        // rebuilt tail-inclusively on the next ensure_khop_reach call.
        let mut g = three_hop_chain();
        // Force an eager build via ensure_khop_reach.
        let _ = g.ensure_khop_reach();
        assert!(g.khop_reach_is_built());

        // Add a new edge u1 -> ip1 directly (skipping the chain).
        // three_hop_chain() called sort_edges_by_timestamp() → finalized.
        // After the C2 fix, on_streaming_edge_appended fires the finalized-gate
        // and invalidates khop_reach instead of applying a delta.
        g.add_relation(Relation::new("u1", "ip1", RelationType::Connect, 50))
            .unwrap();

        // Post-finalize append must INVALIDATE the index.
        assert!(
            !g.khop_reach_is_built(),
            "post-finalize append must invalidate khop_reach (C2 fix)"
        );

        // After invalidation, ensure_khop_reach rebuilds against the full
        // base+tail graph and the rebuilt index must be correct.
        let rebuilt = g.ensure_khop_reach().clone();
        let fresh = KHopReach::build(&g);

        for sid_str in ["u1", "h1", "p1", "ip1"] {
            let sid = g.interner.get(sid_str).unwrap();
            let rebuilt_bits =
                rebuilt.bits.get(sid.index()).copied().unwrap_or(0);
            let fresh_bits = fresh.bits.get(sid.index()).copied().unwrap_or(0);
            // Rebuilt index must be bit-equivalent to a fresh build.
            assert_eq!(
                rebuilt_bits,
                fresh_bits,
                "{sid_str}: rebuilt bits 0x{rebuilt_bits:x} must equal fresh bits 0x{fresh_bits:x}",
            );
        }

        // Specifically, u1 should reach IP in the rebuilt index.
        let u_sid = g.interner.get("u1").unwrap();
        let ip_mask = 1u16 << EntityType::IP.to_u8();
        assert!(rebuilt.can_reach_in_window(u_sid, ip_mask, None));
    }

    #[test]
    fn delta_update_returns_true_on_redundant_edge() {
        // C2 fix: after finalization, even a "redundant" post-finalize append
        // INVALIDATES the index. The pre-fix behaviour (delta returns true →
        // index stays live) was unsound for finalized graphs because the delta
        // read BASE neighbors only and could miss tail edges.
        let mut g = three_hop_chain();
        let _ = g.ensure_khop_reach();
        // Add a "duplicate" edge (different timestamp but same structural reach).
        // three_hop_chain() is finalized, so on_streaming_edge_appended fires
        // the finalized-gate → invalidation.
        g.add_relation(Relation::new("u1", "h1", RelationType::Auth, 100))
            .unwrap();
        assert!(
            !g.khop_reach_is_built(),
            "post-finalize append must invalidate khop_reach even for redundant edges (C2 fix)"
        );
    }

    #[test]
    fn post_finalize_append_on_high_fanin_vertex_invalidates_khop() {
        // Repurposed from the old `delta_update_invalidates_when_budget_exceeded`
        // test which exercised `try_record_edge_delta` directly — a path that is
        // no longer reached in production after the C2 fix.
        //
        // Production path (post-C2): `add_relation` → `on_streaming_edge_appended`
        // → sees `streaming.is_finalized()` → drops the khop_reach OnceLock
        // unconditionally, regardless of fan-in. The budget fallback inside
        // `try_record_edge_delta` is therefore never reached on a finalized graph.
        //
        // This test verifies the REAL production behaviour: a post-finalize append
        // on a high-fan-in vertex (200 predecessors) must invalidate the khop
        // index via the finalized-gate, not via a budget check.
        let mut g = GraphHunter::new();
        // Star: 200 hosts all pointing at the same IP, plus a Process node that
        // will be wired in post-finalize.
        for i in 0..200 {
            g.add_entity(Entity::new(
                &format!("h{i}"),
                EntityType::Host,
            ))
            .unwrap();
        }
        g.add_entity(Entity::new("ip1", EntityType::IP)).unwrap();
        g.add_entity(Entity::new("p1", EntityType::Process)).unwrap();
        for i in 0..200 {
            g.add_relation(Relation::new(
                &format!("h{i}"),
                "ip1",
                RelationType::Connect,
                100 + i,
            ))
            .unwrap();
        }
        // Finalize (sort) and build the k-hop index.
        g.sort_edges_by_timestamp().unwrap();
        let _ = g.ensure_khop_reach();
        assert!(g.khop_reach_is_built(), "khop_reach must be built after ensure_khop_reach");

        // Post-finalize append via the production path: add_relation fires
        // on_streaming_edge_appended → finalized-gate → OnceLock reset.
        g.add_relation(Relation::new("ip1", "p1", RelationType::Auth, 999))
            .unwrap();

        assert!(
            !g.khop_reach_is_built(),
            "post-finalize append on high-fan-in vertex must invalidate khop_reach (C2 finalized-gate)"
        );
    }
}
