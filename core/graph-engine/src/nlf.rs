//! B2 — Neighborhood Label Frequency (NLF) index.
//!
//! For every vertex `v` we precompute a 9-slot histogram of its outgoing
//! neighbor entity types. At query entry, the matcher checks whether each
//! `start_sid` has at least one neighbor of the type required by the first
//! hypothesis step's `dest_type`; vertices that fail this check are pruned
//! before they ever enter `dfs_match_iterative`.
//!
//! The slot space mirrors `EntityType::to_u8()`: 0..=8 for the nine
//! concrete variants (IP, Host, User, Process, File, Domain, Registry,
//! URL, Service). `Any` (254) and `Other(_)` (255) are not tracked
//! because they would require an unbounded side table — vertices whose
//! neighbors are `Other(_)` simply don't contribute to any slot, and the
//! prune pass then conservatively passes them through (a missed prune is
//! a perf regression, not a correctness bug).
//!
//! Build cost is O(E) and runs once inside `sort_edges_by_timestamp`.
//! Memory is `9 × u32 = 36 bytes/vertex` — 36 MB for 1M vertices.

use crate::hypothesis::HypothesisStep;
use crate::interner::StrId;

/// Number of concrete `EntityType` variants tracked. Must stay in sync
/// with `EntityType::to_u8()`.
pub const NLF_TYPE_COUNT: usize = 9;

/// Per-vertex outgoing-neighbor type histogram. Saturating-add at u32 so
/// pathological hubs (millions of neighbors of one type) stay representable.
///
/// Storage backed by `IndexBacking<[u32; 9]>`: heap-resident for small
/// graphs, mmap-spilled for graphs whose NLF would exceed the
/// configured budget (default 1 GiB ≈ 28M vertices). Lookups go
/// through `can_match` and are uniform across both backings.
#[derive(Clone, Default, Debug)]
pub struct NlfTable {
    counts: crate::index_storage::IndexBacking<[u32; NLF_TYPE_COUNT]>,
}

impl NlfTable {
    /// Walk the graph once and accumulate per-source neighbor-type counts.
    /// Reads `entity_type_tags` (SoA) for the destination tag; an O(1) load.
    pub fn build(graph: &crate::graph::GraphHunter) -> Self {
        let n = graph.entity_type_tags.len();
        let counts = crate::index_storage::IndexBacking::build_with_writer(
            n,
            [0u32; NLF_TYPE_COUNT],
            |counts| {
                for sid in graph.entities.keys().copied() {
                    let s_idx = sid.index();
                    if s_idx >= counts.len() {
                        continue;
                    }
                    let arc = match graph.streaming.neighbors_arc(sid) {
                        Some(a) => a,
                        None => continue,
                    };
                    let guard = arc.read();
                    for edge in guard.as_slice() {
                        let dst_idx = edge.dest_sid.index();
                        let tag = match graph.entity_type_tags.get(dst_idx) {
                            Some(&t) => t,
                            None => continue,
                        };
                        if (tag as usize) < NLF_TYPE_COUNT {
                            let row = &mut counts[s_idx];
                            row[tag as usize] = row[tag as usize].saturating_add(1);
                        }
                    }
                }
            },
        )
        .expect("temp file for NLF index");
        Self { counts }
    }

    /// True iff `sid` has at least `requirement[ℓ]` outgoing neighbors of
    /// every concrete type `ℓ`. Vertices outside the range default to
    /// "passes" only for an all-zero requirement — i.e. a vertex with no
    /// row is conservatively considered a candidate when no constraint
    /// applies.
    #[inline]
    pub fn can_match(&self, sid: StrId, requirement: &[u32; NLF_TYPE_COUNT]) -> bool {
        let counts = self.counts.as_slice();
        let row = match counts.get(sid.index()) {
            Some(r) => r,
            None => return requirement.iter().all(|&c| c == 0),
        };
        for i in 0..NLF_TYPE_COUNT {
            if row[i] < requirement[i] {
                return false;
            }
        }
        true
    }

    /// Memory footprint in bytes — heap-resident or on-disk
    /// depending on whether the table was spilled.
    pub fn memory_bytes(&self) -> usize {
        self.counts.bytes()
    }

    /// True iff the NLF counts are mmap-spilled to disk.
    pub fn is_spilled(&self) -> bool {
        self.counts.is_spilled()
    }

    /// L3 stage 2 — incremental delta update. Bumps
    /// `counts[src][dst_tag]` by 1 (saturating) when the backing
    /// is heap-resident. Returns `false` when the backing is
    /// mmap-spilled (read-only after build) — callers must
    /// invalidate the table and let the next read rebuild from
    /// scratch.
    ///
    /// `dst_tag` values outside `[0, NLF_TYPE_COUNT)` are ignored
    /// (those entity types don't get an NLF slot) and return `true`.
    /// An out-of-range `src_sid` (a vertex added after the last NLF
    /// build) returns `false` to force a full rebuild — a silent no-op
    /// would leave the new vertex with an all-zero row and prune it
    /// from every hunt (C4).
    pub fn try_record_edge(&mut self, src_sid: StrId, dst_tag: u8) -> bool {
        let tag = dst_tag as usize;
        if tag >= NLF_TYPE_COUNT {
            // Out-of-range tag has no NLF slot — treat as a no-op
            // success (no rebuild needed).
            return true;
        }
        let counts = match self.counts.heap_slice_mut() {
            Some(s) => s,
            None => return false,
        };
        // C4 fix: if src_sid is beyond the table's allocated rows the vertex
        // was added after the last NLF build. A silent no-op would leave
        // the new start vertex with an all-zero row, causing it to be pruned
        // on every hunt. Force a full rebuild instead.
        match counts.get_mut(src_sid.index()) {
            Some(row) => {
                row[tag] = row[tag].saturating_add(1);
                true
            }
            None => false,
        }
    }
}

/// Compute the NLF requirement at the start vertex from the first
/// hypothesis step's `dest_type`. Concrete dest types contribute `1` to
/// the matching slot; `Any` and `Other(_)` produce an all-zero
/// requirement, in which case `is_trivial` is true and callers skip the
/// prune pass entirely.
pub fn requirement_from_first_step(step: &HypothesisStep) -> [u32; NLF_TYPE_COUNT] {
    let mut req = [0u32; NLF_TYPE_COUNT];
    let tag = step.dest_type.to_u8();
    if (tag as usize) < NLF_TYPE_COUNT {
        req[tag as usize] = 1;
    }
    req
}

/// Skip the prune pass when the requirement is all zeros.
#[inline]
pub fn is_trivial(requirement: &[u32; NLF_TYPE_COUNT]) -> bool {
    requirement.iter().all(|&c| c == 0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::graph::GraphHunter;
    use crate::types::{EntityType, RelationType};
    use crate::{Entity, HypothesisStep, Relation};

    fn small_graph() -> GraphHunter {
        let mut g = GraphHunter::new();
        g.add_entity(Entity::new("u1", EntityType::User)).unwrap();
        g.add_entity(Entity::new("h1", EntityType::Host)).unwrap();
        g.add_entity(Entity::new("ip1", EntityType::IP)).unwrap();
        g.add_relation(Relation::new("u1", "h1", RelationType::Auth, 100))
            .unwrap();
        g.add_relation(Relation::new("u1", "ip1", RelationType::Auth, 101))
            .unwrap();
        g
    }

    #[test]
    fn add_relation_after_nlf_built_keeps_nlf_live_via_incremental_update() {
        // L3 stage 2: ingest a few edges, force the NLF to build
        // (via ensure_nlf), then add another relation. The NLF
        // should reflect the new count without being invalidated.
        use crate::Entity;
        use crate::Relation;

        let mut g = small_graph();
        let _ = g.ensure_nlf(); // forces lazy build
        assert!(g.nlf_is_built());

        // Add another User and another Auth edge from u1 to it.
        g.add_entity(Entity::new("u3", EntityType::User)).unwrap();
        g.add_relation(Relation::new("u1", "u3", RelationType::Auth, 999))
            .unwrap();

        // NLF should still be built (incremental update path took
        // effect), and the count reflects the new User-typed edge.
        assert!(
            g.nlf_is_built(),
            "incremental update must NOT invalidate the heap-backed NLF"
        );
        let u_sid = g.interner.get("u1").unwrap();
        let nlf = g.ensure_nlf();
        let mut req = [0u32; NLF_TYPE_COUNT];
        req[EntityType::User.to_u8() as usize] = 1;
        assert!(
            nlf.can_match(u_sid, &req),
            "u1 must show ≥1 outgoing User after the incremental update"
        );
    }

    #[test]
    fn build_counts_outgoing_neighbor_types() {
        let g = small_graph();
        let nlf = NlfTable::build(&g);
        let u_sid = g.interner.get("u1").unwrap();
        // can_match probes individual slots; assert via the public
        // API rather than reaching into the storage backing.
        let mut req_one = [0u32; NLF_TYPE_COUNT];
        req_one[EntityType::Host.to_u8() as usize] = 1;
        assert!(nlf.can_match(u_sid, &req_one));
        let mut req_one_ip = [0u32; NLF_TYPE_COUNT];
        req_one_ip[EntityType::IP.to_u8() as usize] = 1;
        assert!(nlf.can_match(u_sid, &req_one_ip));
        let mut req_user = [0u32; NLF_TYPE_COUNT];
        req_user[EntityType::User.to_u8() as usize] = 1;
        assert!(!nlf.can_match(u_sid, &req_user));
    }

    #[test]
    fn can_match_dominance() {
        let g = small_graph();
        let nlf = NlfTable::build(&g);
        let u_sid = g.interner.get("u1").unwrap();
        let h_sid = g.interner.get("h1").unwrap();

        let mut req = [0u32; NLF_TYPE_COUNT];
        req[EntityType::IP.to_u8() as usize] = 1;
        assert!(nlf.can_match(u_sid, &req));
        assert!(!nlf.can_match(h_sid, &req));
    }

    #[test]
    fn requirement_from_concrete_dest_type() {
        let step = HypothesisStep::new(EntityType::User, RelationType::Auth, EntityType::IP);
        let req = requirement_from_first_step(&step);
        assert_eq!(req[EntityType::IP.to_u8() as usize], 1);
        assert!(!is_trivial(&req));
    }

    #[test]
    fn requirement_from_any_is_trivial() {
        let step = HypothesisStep::new(EntityType::User, RelationType::Auth, EntityType::Any);
        let req = requirement_from_first_step(&step);
        assert!(is_trivial(&req));
    }

    /// C4 regression: `try_record_edge` with a `src_sid` whose index is beyond
    /// the NLF table's allocated rows must return `false` (force rebuild) rather
    /// than silently succeeding with a no-op. A silent no-op leaves the new
    /// start vertex with an all-zero NLF row and causes it to be wrongly pruned
    /// on every subsequent hunt.
    #[test]
    fn try_record_edge_out_of_range() {
        // Build an NLF table for a 1-vertex graph (rows 0..=0 allocated).
        let g = small_graph();
        let mut nlf = NlfTable::build(&g);

        // src_sid with index 999 is far beyond the table's size.
        let oob_sid = crate::interner::StrId::from_raw(999);
        let in_range_tag = EntityType::Host.to_u8(); // valid tag < NLF_TYPE_COUNT

        // Before the C4 fix this returned `true` (silent no-op).
        // After the fix it returns `false` so the caller knows to rebuild.
        assert!(
            !nlf.try_record_edge(oob_sid, in_range_tag),
            "try_record_edge with out-of-range src_sid must return false (C4 fix)"
        );
    }
}
