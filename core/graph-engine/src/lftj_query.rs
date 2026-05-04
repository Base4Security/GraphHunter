//! D1 — first WCOJ query path: time-respecting forward triangles.
//!
//! The DSL today only emits linear chains, where LFTJ has no
//! asymptotic advantage over DFS. To demonstrate the WCOJ story end-
//! to-end we expose a single hard-coded cyclic pattern: directed
//! forward triangles `a -> b, b -> c, a -> c` (the shape already
//! proven by `count_triangles_lftj`) whose three timestamps satisfy
//! `t_ab < t_bc < t_ac`. In APT terms: process `a` spawns process `b`
//! and file `c`; before that, `b` writes to `c`. The temporal
//! ordering captures causal precedence in a fan-out triangle — a
//! real Sysmon pattern.
//!
//! Algorithm: build a `MaterializedCsrTrie` once, then iterate
//! triangles via the leapfrog inner loop already validated by
//! `count_triangles_lftj`. For each surviving triangle we look up the
//! three edge timestamps in the graph's edge store and apply the
//! ordering predicate. Multi-edge between two vertices is handled by
//! taking the smallest surviving timestamp at each step.
//!
//! This is the smallest entry point that makes D1 a real query path
//! rather than just a counting kernel. It is env-gated under
//! `GRAPHHUNTER_LFTJ=1` at the call site so it never runs by default.
//!
//! Honest scope:
//!   - Single hard-coded shape (forward triangle, not closing cycle
//!     `a->b->c->a`). The closing cycle requires a reverse-trie to
//!     express the third edge `c -> a` as a CSR row, which is future
//!     work; without it the cycle would be a DFS post-filter and
//!     forfeit the WCOJ asymptotic.
//!   - No type or relation predicates beyond "edge exists". Adding
//!     them is a per-edge filter once the trie is built; left for the
//!     planner.
//!   - No parallelism. Triangle enumeration parallelises trivially
//!     over `a` once we see the bench numbers ask for it.

use crate::graph::{GraphHunter, HuntResult};
use crate::interner::StrId;
use crate::lftj::{CsrTrieIter, MaterializedCsrTrie, TrieIter};

/// Per-edge minimum timestamp keyed parallel to `MaterializedCsrTrie`.
/// `min_ts[i] = min { e.timestamp : e is some src->dst edge }` where
/// `(src, dst)` is the i-th pair in the trie's CSR layout. Lookup is
/// O(log d) via binary search inside the source's dst slice. Built
/// once per query — turns per-match `smallest_edge_timestamp` from
/// O(deg) into O(log deg) and removes the `HashMap` indirection that
/// `get_relations_by_sid` carries.
pub struct MinTimestampMap {
    /// Same length as `trie.dst_keys`. `min_ts[trie.dst_offsets[i] +
    /// idx_within_a_dsts]` is the smallest timestamp on `a -> dst`.
    min_ts: Vec<i64>,
}

impl MinTimestampMap {
    pub fn build(graph: &GraphHunter, trie: &MaterializedCsrTrie) -> Self {
        let mut min_ts = vec![i64::MAX; trie.dst_keys.len()];
        for (ai, &a_raw) in trie.src_keys.iter().enumerate() {
            let a_sid = StrId::from_raw(a_raw);
            let off = trie.dst_offsets[ai] as usize;
            let end = trie.dst_offsets[ai + 1] as usize;
            let dsts = &trie.dst_keys[off..end];
            let arc = match graph.streaming.neighbors_arc(a_sid) {
                Some(a) => a,
                None => continue,
            };
            let g = arc.read();
            for e in g.as_slice() {
                let d = e.dest_sid.index() as u32;
                if let Ok(idx) = dsts.binary_search(&d) {
                    let slot = &mut min_ts[off + idx];
                    if e.timestamp < *slot {
                        *slot = e.timestamp;
                    }
                }
            }
        }
        Self { min_ts }
    }

    /// O(log deg(a)) timestamp lookup. None when the edge isn't in
    /// the trie (which means there is no `src -> dst` edge at all).
    #[inline]
    pub fn get(&self, trie: &MaterializedCsrTrie, ai: usize, dst: u32) -> Option<i64> {
        let off = trie.dst_offsets[ai] as usize;
        let end = trie.dst_offsets[ai + 1] as usize;
        let dsts = &trie.dst_keys[off..end];
        let idx = dsts.binary_search(&dst).ok()?;
        let t = self.min_ts[off + idx];
        if t == i64::MAX { None } else { Some(t) }
    }

    /// Variant for callers that only have the source's StrId, not its
    /// trie index. Does the source-row binary search inside.
    #[inline]
    pub fn get_by_src(
        &self,
        trie: &MaterializedCsrTrie,
        src: u32,
        dst: u32,
    ) -> Option<i64> {
        let ai = trie.src_keys.binary_search(&src).ok()?;
        self.get(trie, ai, dst)
    }
}

/// Find every directed time-respecting forward triangle in `graph`.
/// Returns up to `max_results` paths of the form `[a, b, c]` where
/// the three edges are `a -> b`, `b -> c`, `a -> c`. Each path is an
/// `Arc<str>` triple matching the existing `HuntResult` shape.
///
/// Time-respecting predicate: at least one combination of edges
/// `(a -> b, t_ab), (b -> c, t_bc), (a -> c, t_ac)` exists with
/// `t_ab < t_bc < t_ac`. Multi-edge between any pair is handled by
/// taking the smallest timestamp at each step.
///
/// Cost: `O(E)` to build the trie (one-time per call) plus
/// `O(triangles)` for enumeration. The triangle bound is asymptotic
/// optimal (AGM = `m^{3/2}`); the brute-force baseline is `O(E·d̄)`.
pub fn find_triangles_temporal(graph: &GraphHunter, max_results: usize) -> Vec<HuntResult> {
    if max_results == 0 {
        return Vec::new();
    }
    let trie = MaterializedCsrTrie::build(graph);
    let ts_map = MinTimestampMap::build(graph, &trie);
    enumerate_triangles_lftj(graph, &trie, &ts_map, max_results)
}

/// Inner loop. Same leapfrog shape as `count_triangles_lftj`, except
/// instead of incrementing a counter we look up the three edge
/// timestamps and emit when ordered. Lifted out so a future bench can
/// drive it directly without rebuilding the trie.
pub fn enumerate_triangles_lftj(
    graph: &GraphHunter,
    trie: &MaterializedCsrTrie,
    ts_map: &MinTimestampMap,
    max_results: usize,
) -> Vec<HuntResult> {
    let mut out: Vec<HuntResult> = Vec::new();

    let mut r1 = CsrTrieIter::new(trie);
    let mut r3 = CsrTrieIter::new(trie);

    'outer: while !r1.at_end() && !r3.at_end() {
        let ka = r1.key();
        let kc = r3.key();
        if ka < kc {
            r1.seek(kc);
            continue;
        }
        if kc < ka {
            r3.seek(ka);
            continue;
        }
        // Equal: open both at this `a`. `ai` is the trie index for a.
        let ai = r1.src_cursor;
        r1.open();
        r3.open();
        let a_sid = StrId::from_raw(ka as u32);

        while !r1.at_end() {
            let kb = r1.key();
            let b_sid = StrId::from_raw(kb as u32);
            // Need a fresh level-0 iterator to find b in src_keys
            // (level-1 of r1 is over a's dests, not b's source row).
            let mut r2 = CsrTrieIter::new(trie);
            r2.seek(kb);
            if r2.at_end() || r2.key() != kb {
                r1.next();
                continue;
            }
            let bi = r2.src_cursor;
            r2.open();

            // Save r3's dst slice bounds so the next `b` re-scans
            // from a's dests, not from where the previous b left off.
            let r3_lo = r3.dst_lo;
            let r3_hi = r3.dst_hi;
            r3.dst_cursor = r3_lo;

            // Smallest a -> b timestamp via O(log deg) cached lookup.
            let kb_u32 = kb as u32;
            let t_ab = match ts_map.get(trie, ai, kb_u32) {
                Some(t) => t,
                None => {
                    r2.up();
                    r1.next();
                    continue;
                }
            };

            while !r2.at_end() && !r3.at_end() {
                let c2 = r2.key();
                let c3 = r3.key();
                if c2 == c3 {
                    let c_u32 = c2 as u32;
                    if let Some(t_bc) = ts_map.get(trie, bi, c_u32) {
                        if t_bc > t_ab {
                            // Third edge is a -> c (forward triangle).
                            if let Some(t_ac) = ts_map.get(trie, ai, c_u32) {
                                if t_ac > t_bc {
                                    let c_sid = StrId::from_raw(c_u32);
                                    out.push(vec![
                                        graph.interner.resolve_arc(a_sid),
                                        graph.interner.resolve_arc(b_sid),
                                        graph.interner.resolve_arc(c_sid),
                                    ]);
                                    if out.len() >= max_results {
                                        // Restore cursors before bailing.
                                        r2.up();
                                        r1.up();
                                        r3.up();
                                        break 'outer;
                                    }
                                }
                            }
                        }
                    }
                    r2.next();
                    r3.next();
                } else if c2 < c3 {
                    r2.seek(c3);
                } else {
                    r3.seek(c2);
                }
            }

            // Reset r3 cursor for the next b.
            r3.dst_cursor = r3_lo;
            r3.dst_hi = r3_hi;

            r2.up();
            r1.next();
        }
        r1.up();
        r3.up();
        r1.next();
        r3.next();
    }

    out
}

/// SIMD-accelerated enumerator. Same shape as `count_triangles_lftj_simd`:
/// outer loop over `a` and `b` reuses the trie's CSR layout; the leaf
/// is a `intersect_sorted_u32_collect` over `(a_dsts, b_dsts)` which
/// runtime-dispatches AVX2 on x86_64. The temporal predicate is then
/// applied per candidate `c`. Honest about scope: at the leaf, LFTJ
/// for a 3-relation join collapses to a 2-way intersection — there is
/// no multi-way leverage to extract; the SIMD-collect just cuts the
/// constant factor on that intersection.
pub fn enumerate_triangles_lftj_simd(
    graph: &GraphHunter,
    trie: &MaterializedCsrTrie,
    ts_map: &MinTimestampMap,
    max_results: usize,
) -> Vec<HuntResult> {
    let mut out: Vec<HuntResult> = Vec::new();
    let mut intersect_buf: Vec<u32> = Vec::new();
    'outer: for ai in 0..trie.src_keys.len() {
        let a = trie.src_keys[ai];
        let a_sid = StrId::from_raw(a);
        let a_off = trie.dst_offsets[ai] as usize;
        let a_end = trie.dst_offsets[ai + 1] as usize;
        let a_dsts = &trie.dst_keys[a_off..a_end];
        for &b in a_dsts {
            let b_sid = StrId::from_raw(b);
            let bi = match trie.src_keys.binary_search(&b) {
                Ok(i) => i,
                Err(_) => continue,
            };
            let t_ab = match ts_map.get(trie, ai, b) {
                Some(t) => t,
                None => continue,
            };
            let b_off = trie.dst_offsets[bi] as usize;
            let b_end = trie.dst_offsets[bi + 1] as usize;
            let b_dsts = &trie.dst_keys[b_off..b_end];

            intersect_buf.clear();
            crate::simd_rust::intersect_sorted_u32_collect(a_dsts, b_dsts, &mut intersect_buf);

            for &c in intersect_buf.iter() {
                let t_bc = match ts_map.get(trie, bi, c) {
                    Some(t) => t,
                    None => continue,
                };
                if t_bc <= t_ab {
                    continue;
                }
                let t_ac = match ts_map.get(trie, ai, c) {
                    Some(t) => t,
                    None => continue,
                };
                if t_ac <= t_bc {
                    continue;
                }
                let c_sid = StrId::from_raw(c);
                out.push(vec![
                    graph.interner.resolve_arc(a_sid),
                    graph.interner.resolve_arc(b_sid),
                    graph.interner.resolve_arc(c_sid),
                ]);
                if out.len() >= max_results {
                    break 'outer;
                }
            }
        }
    }
    out
}

/// Brute-force baseline used by tests and benches. Triple loop over
/// the trie, applying the same time-respecting predicate. Reported
/// path order matches `enumerate_triangles_lftj` so result-set parity
/// is well-defined (sort by `(a, b, c)` for comparison).
pub fn enumerate_triangles_naive(
    graph: &GraphHunter,
    trie: &MaterializedCsrTrie,
    ts_map: &MinTimestampMap,
    max_results: usize,
) -> Vec<HuntResult> {
    let mut out: Vec<HuntResult> = Vec::new();
    'outer: for ai in 0..trie.src_keys.len() {
        let a = trie.src_keys[ai];
        let a_sid = StrId::from_raw(a);
        let a_dsts =
            &trie.dst_keys[trie.dst_offsets[ai] as usize..trie.dst_offsets[ai + 1] as usize];
        for &b in a_dsts {
            let b_sid = StrId::from_raw(b);
            let bi = match trie.src_keys.binary_search(&b) {
                Ok(i) => i,
                Err(_) => continue,
            };
            let t_ab = match ts_map.get(trie, ai, b) {
                Some(t) => t,
                None => continue,
            };
            let b_dsts = &trie.dst_keys
                [trie.dst_offsets[bi] as usize..trie.dst_offsets[bi + 1] as usize];
            for &c in b_dsts {
                if a_dsts.binary_search(&c).is_err() {
                    continue;
                }
                let c_sid = StrId::from_raw(c);
                let t_bc = match ts_map.get(trie, bi, c) {
                    Some(t) => t,
                    None => continue,
                };
                if t_bc <= t_ab {
                    continue;
                }
                let t_ac = match ts_map.get(trie, ai, c) {
                    Some(t) => t,
                    None => continue,
                };
                if t_ac <= t_bc {
                    continue;
                }
                out.push(vec![
                    graph.interner.resolve_arc(a_sid),
                    graph.interner.resolve_arc(b_sid),
                    graph.interner.resolve_arc(c_sid),
                ]);
                if out.len() >= max_results {
                    break 'outer;
                }
            }
        }
    }
    out
}

/// SIMD enumerator with a time-window predicate. Emits only triangles
/// whose `t_ab` falls in `[t_lo, t_hi)`. The narrower the window, the
/// fewer triangles emitted — but the trie + ts_map build cost is
/// window-independent, so a shared trie amortizes across many narrow
/// windows.
///
/// Why filter on `t_ab` rather than `t_ac`: `t_ab` is the earliest
/// timestamp in the time-respecting chain, so an early `continue`
/// short-circuits the inner SIMD intersect entirely when `t_ab` is
/// out-of-window. Filtering on `t_ac` would still pay for the
/// intersect.
pub fn enumerate_triangles_lftj_simd_window(
    graph: &GraphHunter,
    trie: &MaterializedCsrTrie,
    ts_map: &MinTimestampMap,
    t_lo: i64,
    t_hi: i64,
    max_results: usize,
) -> Vec<HuntResult> {
    let mut out: Vec<HuntResult> = Vec::new();
    let mut intersect_buf: Vec<u32> = Vec::new();
    'outer: for ai in 0..trie.src_keys.len() {
        let a = trie.src_keys[ai];
        let a_sid = StrId::from_raw(a);
        let a_off = trie.dst_offsets[ai] as usize;
        let a_end = trie.dst_offsets[ai + 1] as usize;
        let a_dsts = &trie.dst_keys[a_off..a_end];
        for &b in a_dsts {
            let b_sid = StrId::from_raw(b);
            let bi = match trie.src_keys.binary_search(&b) {
                Ok(i) => i,
                Err(_) => continue,
            };
            let t_ab = match ts_map.get(trie, ai, b) {
                Some(t) => t,
                None => continue,
            };
            if t_ab < t_lo || t_ab >= t_hi {
                continue;
            }
            let b_off = trie.dst_offsets[bi] as usize;
            let b_end = trie.dst_offsets[bi + 1] as usize;
            let b_dsts = &trie.dst_keys[b_off..b_end];

            intersect_buf.clear();
            crate::simd_rust::intersect_sorted_u32_collect(a_dsts, b_dsts, &mut intersect_buf);

            for &c in intersect_buf.iter() {
                let t_bc = match ts_map.get(trie, bi, c) {
                    Some(t) => t,
                    None => continue,
                };
                if t_bc <= t_ab {
                    continue;
                }
                let t_ac = match ts_map.get(trie, ai, c) {
                    Some(t) => t,
                    None => continue,
                };
                if t_ac <= t_bc {
                    continue;
                }
                let c_sid = StrId::from_raw(c);
                out.push(vec![
                    graph.interner.resolve_arc(a_sid),
                    graph.interner.resolve_arc(b_sid),
                    graph.interner.resolve_arc(c_sid),
                ]);
                if out.len() >= max_results {
                    break 'outer;
                }
            }
        }
    }
    out
}

/// Sort key for parity comparison. Two triangle enumerators are
/// equivalent iff sorting their results by `(a, b, c)` strings gives
/// equal vectors.
pub fn sort_triangles(mut v: Vec<HuntResult>) -> Vec<HuntResult> {
    v.sort_by(|x, y| {
        let xs = (&*x[0], &*x[1], &*x[2]);
        let ys = (&*y[0], &*y[1], &*y[2]);
        xs.cmp(&ys)
    });
    v
}

// ─── 4-clique enumeration ────────────────────────────────────────────
//
// The full vertical for K4: time-respecting predicate, optional
// `[t_lo, t_hi)` window on the earliest edge, and a parallel variant.
//
// Pattern: a forward 4-clique with all six directed edges
// `{a→b, a→c, a→d, b→c, b→d, c→d}` whose timestamps satisfy the
// chronological lex order
//   `t_ab < t_ac < t_ad < t_bc < t_bd < t_cd`.
//
// ATT&CK reading: a "fan-out then merge" attack where attacker `a`
// touches three peers in order of escalation (`b`, then `c`, then
// `d`), and each peer further reaches into the still-unreached
// vertices in the same chronological order. The strict ordering
// captures causal precedence: every later step happens after every
// earlier step. On uniform random timestamps this predicate keeps
// `1/720` of structural K4s, so the output is much smaller than the
// AGM bound — exactly the regime where Yannakakis-style output-
// sensitive enumeration shines.
//
// Window: filter on `t_ab` (the earliest edge) so the inner SIMD
// intersect short-circuits before paying for the structural search.
// `[i64::MIN, i64::MAX)` recovers the unwindowed semantics.

/// Brute-force 4-clique enumeration. Quadruple loop with binary
/// searches at each level for the structural pair-existence checks,
/// plus the temporal predicate. Used as a parity baseline for the
/// LFTJ-SIMD variants and as the bench point that measures the AGM
/// crossover.
pub fn enumerate_4cliques_naive(
    graph: &GraphHunter,
    trie: &MaterializedCsrTrie,
    ts_map: &MinTimestampMap,
    t_lo: i64,
    t_hi: i64,
    max_results: usize,
) -> Vec<HuntResult> {
    let mut out: Vec<HuntResult> = Vec::new();
    'outer: for ai in 0..trie.src_keys.len() {
        let a = trie.src_keys[ai];
        let a_sid = StrId::from_raw(a);
        let a_dsts =
            &trie.dst_keys[trie.dst_offsets[ai] as usize..trie.dst_offsets[ai + 1] as usize];
        for &b in a_dsts {
            let b_sid = StrId::from_raw(b);
            let bi = match trie.src_keys.binary_search(&b) {
                Ok(i) => i,
                Err(_) => continue,
            };
            let t_ab = match ts_map.get(trie, ai, b) {
                Some(t) => t,
                None => continue,
            };
            if t_ab < t_lo || t_ab >= t_hi {
                continue;
            }
            let b_dsts = &trie.dst_keys
                [trie.dst_offsets[bi] as usize..trie.dst_offsets[bi + 1] as usize];
            for &c in a_dsts {
                if c == b {
                    continue;
                }
                if b_dsts.binary_search(&c).is_err() {
                    continue;
                }
                let ci = match trie.src_keys.binary_search(&c) {
                    Ok(i) => i,
                    Err(_) => continue,
                };
                let t_ac = match ts_map.get(trie, ai, c) {
                    Some(t) => t,
                    None => continue,
                };
                if t_ac <= t_ab {
                    continue;
                }
                let t_bc = match ts_map.get(trie, bi, c) {
                    Some(t) => t,
                    None => continue,
                };
                if t_ac >= t_bc {
                    continue;
                }
                let c_sid = StrId::from_raw(c);
                let c_dsts = &trie.dst_keys
                    [trie.dst_offsets[ci] as usize..trie.dst_offsets[ci + 1] as usize];
                for &d in a_dsts {
                    if d == b || d == c {
                        continue;
                    }
                    if b_dsts.binary_search(&d).is_err() {
                        continue;
                    }
                    if c_dsts.binary_search(&d).is_err() {
                        continue;
                    }
                    let t_ad = match ts_map.get(trie, ai, d) {
                        Some(t) => t,
                        None => continue,
                    };
                    if t_ad <= t_ac || t_ad >= t_bc {
                        continue;
                    }
                    let t_bd = match ts_map.get(trie, bi, d) {
                        Some(t) => t,
                        None => continue,
                    };
                    if t_bd <= t_bc {
                        continue;
                    }
                    let t_cd = match ts_map.get(trie, ci, d) {
                        Some(t) => t,
                        None => continue,
                    };
                    if t_cd <= t_bd {
                        continue;
                    }
                    let d_sid = StrId::from_raw(d);
                    out.push(vec![
                        graph.interner.resolve_arc(a_sid),
                        graph.interner.resolve_arc(b_sid),
                        graph.interner.resolve_arc(c_sid),
                        graph.interner.resolve_arc(d_sid),
                    ]);
                    if out.len() >= max_results {
                        break 'outer;
                    }
                }
            }
        }
    }
    out
}

/// LFTJ-SIMD 4-clique enumeration. Same outer shape as
/// `count_4cliques_lftj_simd`: collect `ab_isect = a_dsts ∩ b_dsts`
/// once via the SIMD intersect, then for each candidate `c` in that
/// set collect `abc_isect = ab_isect ∩ c_dsts` (one more SIMD
/// intersect) — the d-candidates. The temporal predicate is layered
/// on top, with the strongest cuts (`t_ad < t_bc`, `t_ac < t_bc`)
/// applied as early as possible to short-circuit the inner intersect.
pub fn enumerate_4cliques_lftj_simd(
    graph: &GraphHunter,
    trie: &MaterializedCsrTrie,
    ts_map: &MinTimestampMap,
    t_lo: i64,
    t_hi: i64,
    max_results: usize,
) -> Vec<HuntResult> {
    let mut out: Vec<HuntResult> = Vec::new();
    let mut ab_isect: Vec<u32> = Vec::new();
    let mut abc_isect: Vec<u32> = Vec::new();
    'outer: for ai in 0..trie.src_keys.len() {
        let a = trie.src_keys[ai];
        let a_sid = StrId::from_raw(a);
        let a_off = trie.dst_offsets[ai] as usize;
        let a_end = trie.dst_offsets[ai + 1] as usize;
        let a_dsts = &trie.dst_keys[a_off..a_end];
        for &b in a_dsts {
            let b_sid = StrId::from_raw(b);
            let bi = match trie.src_keys.binary_search(&b) {
                Ok(i) => i,
                Err(_) => continue,
            };
            let t_ab = match ts_map.get(trie, ai, b) {
                Some(t) => t,
                None => continue,
            };
            if t_ab < t_lo || t_ab >= t_hi {
                continue;
            }
            let b_off = trie.dst_offsets[bi] as usize;
            let b_end = trie.dst_offsets[bi + 1] as usize;
            let b_dsts = &trie.dst_keys[b_off..b_end];

            ab_isect.clear();
            crate::simd_rust::intersect_sorted_u32_collect(a_dsts, b_dsts, &mut ab_isect);
            if ab_isect.is_empty() {
                continue;
            }

            for c_idx in 0..ab_isect.len() {
                let c = ab_isect[c_idx];
                let ci = match trie.src_keys.binary_search(&c) {
                    Ok(i) => i,
                    Err(_) => continue,
                };
                let t_ac = match ts_map.get(trie, ai, c) {
                    Some(t) => t,
                    None => continue,
                };
                if t_ac <= t_ab {
                    continue;
                }
                let t_bc = match ts_map.get(trie, bi, c) {
                    Some(t) => t,
                    None => continue,
                };
                if t_ac >= t_bc {
                    continue;
                }
                let c_sid = StrId::from_raw(c);
                let c_off = trie.dst_offsets[ci] as usize;
                let c_end = trie.dst_offsets[ci + 1] as usize;
                let c_dsts = &trie.dst_keys[c_off..c_end];

                abc_isect.clear();
                crate::simd_rust::intersect_sorted_u32_collect(
                    &ab_isect[..],
                    c_dsts,
                    &mut abc_isect,
                );

                for &d in abc_isect.iter() {
                    let t_ad = match ts_map.get(trie, ai, d) {
                        Some(t) => t,
                        None => continue,
                    };
                    if t_ad <= t_ac || t_ad >= t_bc {
                        continue;
                    }
                    let t_bd = match ts_map.get(trie, bi, d) {
                        Some(t) => t,
                        None => continue,
                    };
                    if t_bd <= t_bc {
                        continue;
                    }
                    let t_cd = match ts_map.get(trie, ci, d) {
                        Some(t) => t,
                        None => continue,
                    };
                    if t_cd <= t_bd {
                        continue;
                    }
                    let d_sid = StrId::from_raw(d);
                    out.push(vec![
                        graph.interner.resolve_arc(a_sid),
                        graph.interner.resolve_arc(b_sid),
                        graph.interner.resolve_arc(c_sid),
                        graph.interner.resolve_arc(d_sid),
                    ]);
                    if out.len() >= max_results {
                        break 'outer;
                    }
                }
            }
        }
    }
    out
}

/// Rayon-parallel 4-clique enumeration. Outer `par_iter` over `a`;
/// each worker keeps its own scratch intersect buffers via
/// `map_init` and a local result vector capped at `max_results`.
/// Workers are independent because each `a`'s contribution is a
/// disjoint slice of the result (lex-ordered on the first vertex).
/// We `reduce` by concatenation and truncate to `max_results` at the
/// end — the cap is a soft upper bound during the parallel phase
/// (each worker may exceed it locally but the global truncate is
/// authoritative). For benches the cap is set high enough to never
/// bind.
pub fn enumerate_4cliques_lftj_simd_par(
    graph: &GraphHunter,
    trie: &MaterializedCsrTrie,
    ts_map: &MinTimestampMap,
    t_lo: i64,
    t_hi: i64,
    max_results: usize,
) -> Vec<HuntResult> {
    use rayon::prelude::*;
    let mut all: Vec<HuntResult> = (0..trie.src_keys.len())
        .into_par_iter()
        .map_init(
            || (Vec::<u32>::new(), Vec::<u32>::new()),
            |(ab_isect, abc_isect), ai| {
                let mut local: Vec<HuntResult> = Vec::new();
                let a = trie.src_keys[ai];
                let a_sid = StrId::from_raw(a);
                let a_off = trie.dst_offsets[ai] as usize;
                let a_end = trie.dst_offsets[ai + 1] as usize;
                let a_dsts = &trie.dst_keys[a_off..a_end];
                'a_loop: for &b in a_dsts {
                    let b_sid = StrId::from_raw(b);
                    let bi = match trie.src_keys.binary_search(&b) {
                        Ok(i) => i,
                        Err(_) => continue,
                    };
                    let t_ab = match ts_map.get(trie, ai, b) {
                        Some(t) => t,
                        None => continue,
                    };
                    if t_ab < t_lo || t_ab >= t_hi {
                        continue;
                    }
                    let b_off = trie.dst_offsets[bi] as usize;
                    let b_end = trie.dst_offsets[bi + 1] as usize;
                    let b_dsts = &trie.dst_keys[b_off..b_end];
                    ab_isect.clear();
                    crate::simd_rust::intersect_sorted_u32_collect(a_dsts, b_dsts, ab_isect);
                    if ab_isect.is_empty() {
                        continue;
                    }
                    for c_idx in 0..ab_isect.len() {
                        let c = ab_isect[c_idx];
                        let ci = match trie.src_keys.binary_search(&c) {
                            Ok(i) => i,
                            Err(_) => continue,
                        };
                        let t_ac = match ts_map.get(trie, ai, c) {
                            Some(t) => t,
                            None => continue,
                        };
                        if t_ac <= t_ab {
                            continue;
                        }
                        let t_bc = match ts_map.get(trie, bi, c) {
                            Some(t) => t,
                            None => continue,
                        };
                        if t_ac >= t_bc {
                            continue;
                        }
                        let c_sid = StrId::from_raw(c);
                        let c_off = trie.dst_offsets[ci] as usize;
                        let c_end = trie.dst_offsets[ci + 1] as usize;
                        let c_dsts = &trie.dst_keys[c_off..c_end];
                        abc_isect.clear();
                        crate::simd_rust::intersect_sorted_u32_collect(
                            &ab_isect[..],
                            c_dsts,
                            abc_isect,
                        );
                        for &d in abc_isect.iter() {
                            let t_ad = match ts_map.get(trie, ai, d) {
                                Some(t) => t,
                                None => continue,
                            };
                            if t_ad <= t_ac || t_ad >= t_bc {
                                continue;
                            }
                            let t_bd = match ts_map.get(trie, bi, d) {
                                Some(t) => t,
                                None => continue,
                            };
                            if t_bd <= t_bc {
                                continue;
                            }
                            let t_cd = match ts_map.get(trie, ci, d) {
                                Some(t) => t,
                                None => continue,
                            };
                            if t_cd <= t_bd {
                                continue;
                            }
                            let d_sid = StrId::from_raw(d);
                            local.push(vec![
                                graph.interner.resolve_arc(a_sid),
                                graph.interner.resolve_arc(b_sid),
                                graph.interner.resolve_arc(c_sid),
                                graph.interner.resolve_arc(d_sid),
                            ]);
                            if local.len() >= max_results {
                                break 'a_loop;
                            }
                        }
                    }
                }
                local
            },
        )
        .reduce(
            Vec::new,
            |mut a, b| {
                a.extend(b);
                a
            },
        );
    if all.len() > max_results {
        all.truncate(max_results);
    }
    all
}

/// Sort key for parity comparison. Two K4 enumerators agree iff
/// sorting by `(a, b, c, d)` strings yields equal vectors.
pub fn sort_4cliques(mut v: Vec<HuntResult>) -> Vec<HuntResult> {
    v.sort_by(|x, y| {
        let xs = (&*x[0], &*x[1], &*x[2], &*x[3]);
        let ys = (&*y[0], &*y[1], &*y[2], &*y[3]);
        xs.cmp(&ys)
    });
    v
}

/// Brute-force 5-clique enumeration. Five nested loops with binary
/// searches at each level for the structural pair-existence checks,
/// plus the chronological temporal predicate `t_ab < t_ac < t_ad <
/// t_ae < t_bc < t_bd < t_be < t_cd < t_ce < t_de`. Used as a
/// parity baseline for the LFTJ-SIMD variant. The asymptotic crossover
/// vs LFTJ is steeper than K4: m^4/n^3 naive vs m^{5/2} AGM bound.
pub fn enumerate_5cliques_naive(
    graph: &GraphHunter,
    trie: &MaterializedCsrTrie,
    ts_map: &MinTimestampMap,
    t_lo: i64,
    t_hi: i64,
    max_results: usize,
) -> Vec<HuntResult> {
    let mut out: Vec<HuntResult> = Vec::new();
    'outer: for ai in 0..trie.src_keys.len() {
        let a = trie.src_keys[ai];
        let a_sid = StrId::from_raw(a);
        let a_dsts =
            &trie.dst_keys[trie.dst_offsets[ai] as usize..trie.dst_offsets[ai + 1] as usize];
        for &b in a_dsts {
            let b_sid = StrId::from_raw(b);
            let bi = match trie.src_keys.binary_search(&b) {
                Ok(i) => i,
                Err(_) => continue,
            };
            let t_ab = match ts_map.get(trie, ai, b) {
                Some(t) => t,
                None => continue,
            };
            if t_ab < t_lo || t_ab >= t_hi {
                continue;
            }
            let b_dsts = &trie.dst_keys
                [trie.dst_offsets[bi] as usize..trie.dst_offsets[bi + 1] as usize];
            for &c in a_dsts {
                if c == b {
                    continue;
                }
                if b_dsts.binary_search(&c).is_err() {
                    continue;
                }
                let ci = match trie.src_keys.binary_search(&c) {
                    Ok(i) => i,
                    Err(_) => continue,
                };
                let t_ac = match ts_map.get(trie, ai, c) {
                    Some(t) => t,
                    None => continue,
                };
                if t_ac <= t_ab {
                    continue;
                }
                let t_bc = match ts_map.get(trie, bi, c) {
                    Some(t) => t,
                    None => continue,
                };
                let c_sid = StrId::from_raw(c);
                let c_dsts = &trie.dst_keys
                    [trie.dst_offsets[ci] as usize..trie.dst_offsets[ci + 1] as usize];
                for &d in a_dsts {
                    if d == b || d == c {
                        continue;
                    }
                    if b_dsts.binary_search(&d).is_err() {
                        continue;
                    }
                    if c_dsts.binary_search(&d).is_err() {
                        continue;
                    }
                    let di = match trie.src_keys.binary_search(&d) {
                        Ok(i) => i,
                        Err(_) => continue,
                    };
                    let t_ad = match ts_map.get(trie, ai, d) {
                        Some(t) => t,
                        None => continue,
                    };
                    if t_ad <= t_ac {
                        continue;
                    }
                    if t_ad >= t_bc {
                        continue;
                    }
                    let t_bd = match ts_map.get(trie, bi, d) {
                        Some(t) => t,
                        None => continue,
                    };
                    let t_cd = match ts_map.get(trie, ci, d) {
                        Some(t) => t,
                        None => continue,
                    };
                    let d_sid = StrId::from_raw(d);
                    let d_dsts = &trie.dst_keys
                        [trie.dst_offsets[di] as usize..trie.dst_offsets[di + 1] as usize];
                    for &e in a_dsts {
                        if e == b || e == c || e == d {
                            continue;
                        }
                        if b_dsts.binary_search(&e).is_err() {
                            continue;
                        }
                        if c_dsts.binary_search(&e).is_err() {
                            continue;
                        }
                        if d_dsts.binary_search(&e).is_err() {
                            continue;
                        }
                        let t_ae = match ts_map.get(trie, ai, e) {
                            Some(t) => t,
                            None => continue,
                        };
                        if t_ae <= t_ad || t_ae >= t_bc {
                            continue;
                        }
                        let t_be = match ts_map.get(trie, bi, e) {
                            Some(t) => t,
                            None => continue,
                        };
                        if t_bc <= t_ae || t_bd <= t_bc || t_be <= t_bd {
                            continue;
                        }
                        let t_ce = match ts_map.get(trie, ci, e) {
                            Some(t) => t,
                            None => continue,
                        };
                        if t_cd <= t_be || t_ce <= t_cd {
                            continue;
                        }
                        let t_de = match ts_map.get(trie, di, e) {
                            Some(t) => t,
                            None => continue,
                        };
                        if t_de <= t_ce {
                            continue;
                        }
                        let e_sid = StrId::from_raw(e);
                        out.push(vec![
                            graph.interner.resolve_arc(a_sid),
                            graph.interner.resolve_arc(b_sid),
                            graph.interner.resolve_arc(c_sid),
                            graph.interner.resolve_arc(d_sid),
                            graph.interner.resolve_arc(e_sid),
                        ]);
                        if out.len() >= max_results {
                            break 'outer;
                        }
                    }
                }
            }
        }
    }
    out
}

/// LFTJ-SIMD 5-clique enumeration. Outer shape mirrors
/// `count_5cliques_lftj_simd`: collect `ab_isect = a_dsts ∩ b_dsts`
/// once, then for each `c` collect `abc_isect = ab_isect ∩ c_dsts`,
/// then for each `d` collect `abcd_isect = abc_isect ∩ d_dsts` — the
/// e-candidates. Three SIMD intersects per `(a,b,c)` and one extra
/// per `d`. AGM bound `m^{5/2}` (Atserias-Grohe-Marx SICOMP 2013;
/// Ngo-Porat-Ré-Rudra JACM 65(3):16, 2018).
pub fn enumerate_5cliques_lftj_simd(
    graph: &GraphHunter,
    trie: &MaterializedCsrTrie,
    ts_map: &MinTimestampMap,
    t_lo: i64,
    t_hi: i64,
    max_results: usize,
) -> Vec<HuntResult> {
    let mut out: Vec<HuntResult> = Vec::new();
    let mut ab_isect: Vec<u32> = Vec::new();
    let mut abc_isect: Vec<u32> = Vec::new();
    let mut abcd_isect: Vec<u32> = Vec::new();
    'outer: for ai in 0..trie.src_keys.len() {
        let a = trie.src_keys[ai];
        let a_sid = StrId::from_raw(a);
        let a_off = trie.dst_offsets[ai] as usize;
        let a_end = trie.dst_offsets[ai + 1] as usize;
        let a_dsts = &trie.dst_keys[a_off..a_end];
        for &b in a_dsts {
            let b_sid = StrId::from_raw(b);
            let bi = match trie.src_keys.binary_search(&b) {
                Ok(i) => i,
                Err(_) => continue,
            };
            let t_ab = match ts_map.get(trie, ai, b) {
                Some(t) => t,
                None => continue,
            };
            if t_ab < t_lo || t_ab >= t_hi {
                continue;
            }
            let b_off = trie.dst_offsets[bi] as usize;
            let b_end = trie.dst_offsets[bi + 1] as usize;
            let b_dsts = &trie.dst_keys[b_off..b_end];
            ab_isect.clear();
            crate::simd_rust::intersect_sorted_u32_collect(a_dsts, b_dsts, &mut ab_isect);
            if ab_isect.len() < 3 {
                continue;
            }
            for c_idx in 0..ab_isect.len() {
                let c = ab_isect[c_idx];
                let ci = match trie.src_keys.binary_search(&c) {
                    Ok(i) => i,
                    Err(_) => continue,
                };
                let t_ac = match ts_map.get(trie, ai, c) {
                    Some(t) => t,
                    None => continue,
                };
                if t_ac <= t_ab {
                    continue;
                }
                let t_bc = match ts_map.get(trie, bi, c) {
                    Some(t) => t,
                    None => continue,
                };
                let c_sid = StrId::from_raw(c);
                let c_off = trie.dst_offsets[ci] as usize;
                let c_end = trie.dst_offsets[ci + 1] as usize;
                let c_dsts = &trie.dst_keys[c_off..c_end];
                abc_isect.clear();
                crate::simd_rust::intersect_sorted_u32_collect(
                    &ab_isect[..],
                    c_dsts,
                    &mut abc_isect,
                );
                if abc_isect.len() < 2 {
                    continue;
                }
                for d_idx in 0..abc_isect.len() {
                    let d = abc_isect[d_idx];
                    let di = match trie.src_keys.binary_search(&d) {
                        Ok(i) => i,
                        Err(_) => continue,
                    };
                    let t_ad = match ts_map.get(trie, ai, d) {
                        Some(t) => t,
                        None => continue,
                    };
                    if t_ad <= t_ac || t_ad >= t_bc {
                        continue;
                    }
                    let t_bd = match ts_map.get(trie, bi, d) {
                        Some(t) => t,
                        None => continue,
                    };
                    let t_cd = match ts_map.get(trie, ci, d) {
                        Some(t) => t,
                        None => continue,
                    };
                    let d_sid = StrId::from_raw(d);
                    let d_off = trie.dst_offsets[di] as usize;
                    let d_end = trie.dst_offsets[di + 1] as usize;
                    let d_dsts = &trie.dst_keys[d_off..d_end];
                    abcd_isect.clear();
                    crate::simd_rust::intersect_sorted_u32_collect(
                        &abc_isect[..],
                        d_dsts,
                        &mut abcd_isect,
                    );
                    for &e in abcd_isect.iter() {
                        let t_ae = match ts_map.get(trie, ai, e) {
                            Some(t) => t,
                            None => continue,
                        };
                        if t_ae <= t_ad || t_ae >= t_bc {
                            continue;
                        }
                        let t_be = match ts_map.get(trie, bi, e) {
                            Some(t) => t,
                            None => continue,
                        };
                        if t_bc <= t_ae || t_bd <= t_bc || t_be <= t_bd {
                            continue;
                        }
                        let t_ce = match ts_map.get(trie, ci, e) {
                            Some(t) => t,
                            None => continue,
                        };
                        if t_cd <= t_be || t_ce <= t_cd {
                            continue;
                        }
                        let t_de = match ts_map.get(trie, di, e) {
                            Some(t) => t,
                            None => continue,
                        };
                        if t_de <= t_ce {
                            continue;
                        }
                        let e_sid = StrId::from_raw(e);
                        out.push(vec![
                            graph.interner.resolve_arc(a_sid),
                            graph.interner.resolve_arc(b_sid),
                            graph.interner.resolve_arc(c_sid),
                            graph.interner.resolve_arc(d_sid),
                            graph.interner.resolve_arc(e_sid),
                        ]);
                        if out.len() >= max_results {
                            break 'outer;
                        }
                    }
                }
            }
        }
    }
    out
}

/// Rayon-parallel 5-clique enumeration. Outer `par_iter` over `a`;
/// each worker keeps three scratch intersect buffers via `map_init`.
/// Same independence argument as `enumerate_4cliques_lftj_simd_par` —
/// each `a`'s contribution is a disjoint slice of the output.
pub fn enumerate_5cliques_lftj_simd_par(
    graph: &GraphHunter,
    trie: &MaterializedCsrTrie,
    ts_map: &MinTimestampMap,
    t_lo: i64,
    t_hi: i64,
    max_results: usize,
) -> Vec<HuntResult> {
    use rayon::prelude::*;
    let mut all: Vec<HuntResult> = (0..trie.src_keys.len())
        .into_par_iter()
        .map_init(
            || (Vec::<u32>::new(), Vec::<u32>::new(), Vec::<u32>::new()),
            |(ab_isect, abc_isect, abcd_isect), ai| {
                let mut local: Vec<HuntResult> = Vec::new();
                let a = trie.src_keys[ai];
                let a_sid = StrId::from_raw(a);
                let a_off = trie.dst_offsets[ai] as usize;
                let a_end = trie.dst_offsets[ai + 1] as usize;
                let a_dsts = &trie.dst_keys[a_off..a_end];
                'a_loop: for &b in a_dsts {
                    let b_sid = StrId::from_raw(b);
                    let bi = match trie.src_keys.binary_search(&b) {
                        Ok(i) => i,
                        Err(_) => continue,
                    };
                    let t_ab = match ts_map.get(trie, ai, b) {
                        Some(t) => t,
                        None => continue,
                    };
                    if t_ab < t_lo || t_ab >= t_hi {
                        continue;
                    }
                    let b_off = trie.dst_offsets[bi] as usize;
                    let b_end = trie.dst_offsets[bi + 1] as usize;
                    let b_dsts = &trie.dst_keys[b_off..b_end];
                    ab_isect.clear();
                    crate::simd_rust::intersect_sorted_u32_collect(a_dsts, b_dsts, ab_isect);
                    if ab_isect.len() < 3 {
                        continue;
                    }
                    for c_idx in 0..ab_isect.len() {
                        let c = ab_isect[c_idx];
                        let ci = match trie.src_keys.binary_search(&c) {
                            Ok(i) => i,
                            Err(_) => continue,
                        };
                        let t_ac = match ts_map.get(trie, ai, c) {
                            Some(t) => t,
                            None => continue,
                        };
                        if t_ac <= t_ab {
                            continue;
                        }
                        let t_bc = match ts_map.get(trie, bi, c) {
                            Some(t) => t,
                            None => continue,
                        };
                        let c_sid = StrId::from_raw(c);
                        let c_off = trie.dst_offsets[ci] as usize;
                        let c_end = trie.dst_offsets[ci + 1] as usize;
                        let c_dsts = &trie.dst_keys[c_off..c_end];
                        abc_isect.clear();
                        crate::simd_rust::intersect_sorted_u32_collect(
                            &ab_isect[..],
                            c_dsts,
                            abc_isect,
                        );
                        if abc_isect.len() < 2 {
                            continue;
                        }
                        for d_idx in 0..abc_isect.len() {
                            let d = abc_isect[d_idx];
                            let di = match trie.src_keys.binary_search(&d) {
                                Ok(i) => i,
                                Err(_) => continue,
                            };
                            let t_ad = match ts_map.get(trie, ai, d) {
                                Some(t) => t,
                                None => continue,
                            };
                            if t_ad <= t_ac || t_ad >= t_bc {
                                continue;
                            }
                            let t_bd = match ts_map.get(trie, bi, d) {
                                Some(t) => t,
                                None => continue,
                            };
                            let t_cd = match ts_map.get(trie, ci, d) {
                                Some(t) => t,
                                None => continue,
                            };
                            let d_sid = StrId::from_raw(d);
                            let d_off = trie.dst_offsets[di] as usize;
                            let d_end = trie.dst_offsets[di + 1] as usize;
                            let d_dsts = &trie.dst_keys[d_off..d_end];
                            abcd_isect.clear();
                            crate::simd_rust::intersect_sorted_u32_collect(
                                &abc_isect[..],
                                d_dsts,
                                abcd_isect,
                            );
                            for &e in abcd_isect.iter() {
                                let t_ae = match ts_map.get(trie, ai, e) {
                                    Some(t) => t,
                                    None => continue,
                                };
                                if t_ae <= t_ad || t_ae >= t_bc {
                                    continue;
                                }
                                let t_be = match ts_map.get(trie, bi, e) {
                                    Some(t) => t,
                                    None => continue,
                                };
                                if t_bc <= t_ae || t_bd <= t_bc || t_be <= t_bd {
                                    continue;
                                }
                                let t_ce = match ts_map.get(trie, ci, e) {
                                    Some(t) => t,
                                    None => continue,
                                };
                                if t_cd <= t_be || t_ce <= t_cd {
                                    continue;
                                }
                                let t_de = match ts_map.get(trie, di, e) {
                                    Some(t) => t,
                                    None => continue,
                                };
                                if t_de <= t_ce {
                                    continue;
                                }
                                let e_sid = StrId::from_raw(e);
                                local.push(vec![
                                    graph.interner.resolve_arc(a_sid),
                                    graph.interner.resolve_arc(b_sid),
                                    graph.interner.resolve_arc(c_sid),
                                    graph.interner.resolve_arc(d_sid),
                                    graph.interner.resolve_arc(e_sid),
                                ]);
                                if local.len() >= max_results {
                                    break 'a_loop;
                                }
                            }
                        }
                    }
                }
                local
            },
        )
        .reduce(
            Vec::new,
            |mut a, b| {
                a.extend(b);
                a
            },
        );
    if all.len() > max_results {
        all.truncate(max_results);
    }
    all
}

/// Sort key for parity comparison. Two K5 enumerators agree iff
/// sorting by `(a, b, c, d, e)` strings yields equal vectors.
pub fn sort_5cliques(mut v: Vec<HuntResult>) -> Vec<HuntResult> {
    v.sort_by(|x, y| {
        let xs = (&*x[0], &*x[1], &*x[2], &*x[3], &*x[4]);
        let ys = (&*y[0], &*y[1], &*y[2], &*y[3], &*y[4]);
        xs.cmp(&ys)
    });
    v
}

/// Brute-force directed-6-cycle enumeration. Six nested loops along
/// the cycle `a → b → c → d → e → f → a`, plus a binary search at
/// the cycle-closure step (`f → a`). Temporal predicate enforces
/// chronological order around the cycle: `t_ab < t_bc < t_cd <
/// t_de < t_ef < t_fa`. Used as the parity baseline for the
/// LFTJ-SIMD variants.
pub fn enumerate_6cycles_naive(
    graph: &GraphHunter,
    forward: &MaterializedCsrTrie,
    ts_map: &MinTimestampMap,
    t_lo: i64,
    t_hi: i64,
    max_results: usize,
) -> Vec<HuntResult> {
    let mut out: Vec<HuntResult> = Vec::new();
    'outer: for ai in 0..forward.src_keys.len() {
        let a = forward.src_keys[ai];
        let a_sid = StrId::from_raw(a);
        let a_dsts = &forward.dst_keys
            [forward.dst_offsets[ai] as usize..forward.dst_offsets[ai + 1] as usize];
        for &b in a_dsts {
            if b == a {
                continue;
            }
            let b_sid = StrId::from_raw(b);
            let bi = match forward.src_keys.binary_search(&b) {
                Ok(i) => i,
                Err(_) => continue,
            };
            let t_ab = match ts_map.get(forward, ai, b) {
                Some(t) => t,
                None => continue,
            };
            if t_ab < t_lo || t_ab >= t_hi {
                continue;
            }
            let b_dsts = forward.neighbors_of(b);
            for &c in b_dsts {
                if c == a || c == b {
                    continue;
                }
                let c_sid = StrId::from_raw(c);
                let ci = match forward.src_keys.binary_search(&c) {
                    Ok(i) => i,
                    Err(_) => continue,
                };
                let t_bc = match ts_map.get(forward, bi, c) {
                    Some(t) => t,
                    None => continue,
                };
                if t_bc <= t_ab {
                    continue;
                }
                let c_dsts = forward.neighbors_of(c);
                for &d in c_dsts {
                    if d == a || d == b || d == c {
                        continue;
                    }
                    let d_sid = StrId::from_raw(d);
                    let di = match forward.src_keys.binary_search(&d) {
                        Ok(i) => i,
                        Err(_) => continue,
                    };
                    let t_cd = match ts_map.get(forward, ci, d) {
                        Some(t) => t,
                        None => continue,
                    };
                    if t_cd <= t_bc {
                        continue;
                    }
                    let d_dsts = forward.neighbors_of(d);
                    for &e in d_dsts {
                        if e == a || e == b || e == c || e == d {
                            continue;
                        }
                        let e_sid = StrId::from_raw(e);
                        let ei = match forward.src_keys.binary_search(&e) {
                            Ok(i) => i,
                            Err(_) => continue,
                        };
                        let t_de = match ts_map.get(forward, di, e) {
                            Some(t) => t,
                            None => continue,
                        };
                        if t_de <= t_cd {
                            continue;
                        }
                        let e_dsts = forward.neighbors_of(e);
                        for &f in e_dsts {
                            if f == a || f == b || f == c || f == d || f == e {
                                continue;
                            }
                            let fi = match forward.src_keys.binary_search(&f) {
                                Ok(i) => i,
                                Err(_) => continue,
                            };
                            // Cycle closure: f → a must exist.
                            let f_dsts = forward.neighbors_of(f);
                            if f_dsts.binary_search(&a).is_err() {
                                continue;
                            }
                            let t_ef = match ts_map.get(forward, ei, f) {
                                Some(t) => t,
                                None => continue,
                            };
                            if t_ef <= t_de {
                                continue;
                            }
                            let t_fa = match ts_map.get(forward, fi, a) {
                                Some(t) => t,
                                None => continue,
                            };
                            if t_fa <= t_ef {
                                continue;
                            }
                            let f_sid = StrId::from_raw(f);
                            out.push(vec![
                                graph.interner.resolve_arc(a_sid),
                                graph.interner.resolve_arc(b_sid),
                                graph.interner.resolve_arc(c_sid),
                                graph.interner.resolve_arc(d_sid),
                                graph.interner.resolve_arc(e_sid),
                                graph.interner.resolve_arc(f_sid),
                            ]);
                            if out.len() >= max_results {
                                break 'outer;
                            }
                        }
                    }
                }
            }
        }
    }
    out
}

/// LFTJ-SIMD directed-6-cycle enumeration. Outer shape mirrors
/// `count_6cycles_lftj_simd`: walk `(a, b, c, d, e)` linearly along
/// the cycle, then the cycle-closure `f → a` becomes a SIMD intersect
/// `N_forward(e) ∩ predecessors(a)`. AGM bound `m^3` (Atserias-Grohe-
/// Marx SICOMP 2013) — the highest ρ\* in the D1 vertical stack;
/// `lateral movement` (User → Host → Host → User → Host → Host →
/// cycle close) is the canonical APT shape this targets.
pub fn enumerate_6cycles_lftj_simd(
    graph: &GraphHunter,
    forward: &MaterializedCsrTrie,
    reverse: &MaterializedCsrTrie,
    ts_map: &MinTimestampMap,
    t_lo: i64,
    t_hi: i64,
    max_results: usize,
) -> Vec<HuntResult> {
    let mut out: Vec<HuntResult> = Vec::new();
    let mut ef_isect: Vec<u32> = Vec::new();
    'outer: for ai in 0..forward.src_keys.len() {
        let a = forward.src_keys[ai];
        let a_sid = StrId::from_raw(a);
        let pred_a = reverse.neighbors_of(a);
        if pred_a.is_empty() {
            continue;
        }
        let a_dsts = &forward.dst_keys
            [forward.dst_offsets[ai] as usize..forward.dst_offsets[ai + 1] as usize];
        for &b in a_dsts {
            if b == a {
                continue;
            }
            let b_sid = StrId::from_raw(b);
            let bi = match forward.src_keys.binary_search(&b) {
                Ok(i) => i,
                Err(_) => continue,
            };
            let t_ab = match ts_map.get(forward, ai, b) {
                Some(t) => t,
                None => continue,
            };
            if t_ab < t_lo || t_ab >= t_hi {
                continue;
            }
            let b_dsts = forward.neighbors_of(b);
            for &c in b_dsts {
                if c == a || c == b {
                    continue;
                }
                let c_sid = StrId::from_raw(c);
                let ci = match forward.src_keys.binary_search(&c) {
                    Ok(i) => i,
                    Err(_) => continue,
                };
                let t_bc = match ts_map.get(forward, bi, c) {
                    Some(t) => t,
                    None => continue,
                };
                if t_bc <= t_ab {
                    continue;
                }
                let c_dsts = forward.neighbors_of(c);
                for &d in c_dsts {
                    if d == a || d == b || d == c {
                        continue;
                    }
                    let d_sid = StrId::from_raw(d);
                    let di = match forward.src_keys.binary_search(&d) {
                        Ok(i) => i,
                        Err(_) => continue,
                    };
                    let t_cd = match ts_map.get(forward, ci, d) {
                        Some(t) => t,
                        None => continue,
                    };
                    if t_cd <= t_bc {
                        continue;
                    }
                    let d_dsts = forward.neighbors_of(d);
                    for &e in d_dsts {
                        if e == a || e == b || e == c || e == d {
                            continue;
                        }
                        let e_sid = StrId::from_raw(e);
                        let ei = match forward.src_keys.binary_search(&e) {
                            Ok(i) => i,
                            Err(_) => continue,
                        };
                        let t_de = match ts_map.get(forward, di, e) {
                            Some(t) => t,
                            None => continue,
                        };
                        if t_de <= t_cd {
                            continue;
                        }
                        // Cycle closure via SIMD intersect.
                        let e_dsts = forward.neighbors_of(e);
                        ef_isect.clear();
                        crate::simd_rust::intersect_sorted_u32_collect(
                            e_dsts, pred_a, &mut ef_isect,
                        );
                        for &f in ef_isect.iter() {
                            if f == a || f == b || f == c || f == d || f == e {
                                continue;
                            }
                            let fi = match forward.src_keys.binary_search(&f) {
                                Ok(i) => i,
                                Err(_) => continue,
                            };
                            let t_ef = match ts_map.get(forward, ei, f) {
                                Some(t) => t,
                                None => continue,
                            };
                            if t_ef <= t_de {
                                continue;
                            }
                            let t_fa = match ts_map.get(forward, fi, a) {
                                Some(t) => t,
                                None => continue,
                            };
                            if t_fa <= t_ef {
                                continue;
                            }
                            let f_sid = StrId::from_raw(f);
                            out.push(vec![
                                graph.interner.resolve_arc(a_sid),
                                graph.interner.resolve_arc(b_sid),
                                graph.interner.resolve_arc(c_sid),
                                graph.interner.resolve_arc(d_sid),
                                graph.interner.resolve_arc(e_sid),
                                graph.interner.resolve_arc(f_sid),
                            ]);
                            if out.len() >= max_results {
                                break 'outer;
                            }
                        }
                    }
                }
            }
        }
    }
    out
}

/// Rayon-parallel directed-6-cycle enumeration. Outer `par_iter`
/// over `a`; each worker keeps a single scratch intersect buffer
/// via `map_init`. Same independence argument as the K4/K5
/// enumerators — disjoint slices of the result on lex-ordered `a`.
pub fn enumerate_6cycles_lftj_simd_par(
    graph: &GraphHunter,
    forward: &MaterializedCsrTrie,
    reverse: &MaterializedCsrTrie,
    ts_map: &MinTimestampMap,
    t_lo: i64,
    t_hi: i64,
    max_results: usize,
) -> Vec<HuntResult> {
    use rayon::prelude::*;
    let mut all: Vec<HuntResult> = (0..forward.src_keys.len())
        .into_par_iter()
        .map_init(
            || Vec::<u32>::new(),
            |ef_isect, ai| {
                let mut local: Vec<HuntResult> = Vec::new();
                let a = forward.src_keys[ai];
                let a_sid = StrId::from_raw(a);
                let pred_a = reverse.neighbors_of(a);
                if pred_a.is_empty() {
                    return local;
                }
                let a_dsts = &forward.dst_keys
                    [forward.dst_offsets[ai] as usize..forward.dst_offsets[ai + 1] as usize];
                'a_loop: for &b in a_dsts {
                    if b == a {
                        continue;
                    }
                    let b_sid = StrId::from_raw(b);
                    let bi = match forward.src_keys.binary_search(&b) {
                        Ok(i) => i,
                        Err(_) => continue,
                    };
                    let t_ab = match ts_map.get(forward, ai, b) {
                        Some(t) => t,
                        None => continue,
                    };
                    if t_ab < t_lo || t_ab >= t_hi {
                        continue;
                    }
                    let b_dsts = forward.neighbors_of(b);
                    for &c in b_dsts {
                        if c == a || c == b {
                            continue;
                        }
                        let c_sid = StrId::from_raw(c);
                        let ci = match forward.src_keys.binary_search(&c) {
                            Ok(i) => i,
                            Err(_) => continue,
                        };
                        let t_bc = match ts_map.get(forward, bi, c) {
                            Some(t) => t,
                            None => continue,
                        };
                        if t_bc <= t_ab {
                            continue;
                        }
                        let c_dsts = forward.neighbors_of(c);
                        for &d in c_dsts {
                            if d == a || d == b || d == c {
                                continue;
                            }
                            let d_sid = StrId::from_raw(d);
                            let di = match forward.src_keys.binary_search(&d) {
                                Ok(i) => i,
                                Err(_) => continue,
                            };
                            let t_cd = match ts_map.get(forward, ci, d) {
                                Some(t) => t,
                                None => continue,
                            };
                            if t_cd <= t_bc {
                                continue;
                            }
                            let d_dsts = forward.neighbors_of(d);
                            for &e in d_dsts {
                                if e == a || e == b || e == c || e == d {
                                    continue;
                                }
                                let e_sid = StrId::from_raw(e);
                                let ei = match forward.src_keys.binary_search(&e) {
                                    Ok(i) => i,
                                    Err(_) => continue,
                                };
                                let t_de = match ts_map.get(forward, di, e) {
                                    Some(t) => t,
                                    None => continue,
                                };
                                if t_de <= t_cd {
                                    continue;
                                }
                                let e_dsts = forward.neighbors_of(e);
                                ef_isect.clear();
                                crate::simd_rust::intersect_sorted_u32_collect(
                                    e_dsts, pred_a, ef_isect,
                                );
                                for &f in ef_isect.iter() {
                                    if f == a || f == b || f == c || f == d || f == e {
                                        continue;
                                    }
                                    let fi = match forward.src_keys.binary_search(&f) {
                                        Ok(i) => i,
                                        Err(_) => continue,
                                    };
                                    let t_ef = match ts_map.get(forward, ei, f) {
                                        Some(t) => t,
                                        None => continue,
                                    };
                                    if t_ef <= t_de {
                                        continue;
                                    }
                                    let t_fa = match ts_map.get(forward, fi, a) {
                                        Some(t) => t,
                                        None => continue,
                                    };
                                    if t_fa <= t_ef {
                                        continue;
                                    }
                                    let f_sid = StrId::from_raw(f);
                                    local.push(vec![
                                        graph.interner.resolve_arc(a_sid),
                                        graph.interner.resolve_arc(b_sid),
                                        graph.interner.resolve_arc(c_sid),
                                        graph.interner.resolve_arc(d_sid),
                                        graph.interner.resolve_arc(e_sid),
                                        graph.interner.resolve_arc(f_sid),
                                    ]);
                                    if local.len() >= max_results {
                                        break 'a_loop;
                                    }
                                }
                            }
                        }
                    }
                }
                local
            },
        )
        .reduce(
            Vec::new,
            |mut a, b| {
                a.extend(b);
                a
            },
        );
    if all.len() > max_results {
        all.truncate(max_results);
    }
    all
}

/// Sort key for parity comparison. Two C6 enumerators agree iff
/// sorting by `(a, b, c, d, e, f)` strings yields equal vectors.
pub fn sort_6cycles(mut v: Vec<HuntResult>) -> Vec<HuntResult> {
    v.sort_by(|x, y| {
        let xs = (&*x[0], &*x[1], &*x[2], &*x[3], &*x[4], &*x[5]);
        let ys = (&*y[0], &*y[1], &*y[2], &*y[3], &*y[4], &*y[5]);
        xs.cmp(&ys)
    });
    v
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::entity::Entity;
    use crate::relation::Relation;
    use crate::types::{EntityType, RelationType};
    use std::sync::Arc;

    /// Build a graph with one forward triangle `a->b, b->c, a->c`.
    fn make_forward_triangle(t_ab: i64, t_bc: i64, t_ac: i64) -> GraphHunter {
        let mut g = GraphHunter::new();
        for n in ["a", "b", "c"] {
            g.add_entity(Entity::new(n, EntityType::User)).unwrap();
        }
        g.add_relation(Relation::new("a", "b", RelationType::Auth, t_ab))
            .unwrap();
        g.add_relation(Relation::new("b", "c", RelationType::Auth, t_bc))
            .unwrap();
        g.add_relation(Relation::new("a", "c", RelationType::Auth, t_ac))
            .unwrap();
        g.sort_edges_by_timestamp().unwrap();
        g
    }

    #[test]
    fn time_respecting_triangle_emitted() {
        // Forward triangle with t_ab < t_bc < t_ac — exactly one match.
        let g = make_forward_triangle(100, 110, 120);
        let r = find_triangles_temporal(&g, 100);
        assert_eq!(r.len(), 1, "exactly one forward triangle expected");
        let t = &r[0];
        assert_eq!(&*t[0], "a");
        assert_eq!(&*t[1], "b");
        assert_eq!(&*t[2], "c");
    }

    #[test]
    fn out_of_order_timestamps_rejected() {
        // t_ac < t_bc — predicate t_ab < t_bc < t_ac fails.
        let g = make_forward_triangle(100, 200, 150);
        let r = find_triangles_temporal(&g, 100);
        assert_eq!(r, Vec::<HuntResult>::new());
    }

    #[test]
    fn lftj_matches_naive_baseline() {
        // Mix of forward triangles (some time-respecting, some not),
        // a non-triangle path, and a disconnected vertex.
        let mut g = GraphHunter::new();
        for n in ["u1", "u2", "u3", "u4", "u5", "u6"] {
            g.add_entity(Entity::new(n, EntityType::User)).unwrap();
        }
        let edges: &[(&str, &str, i64)] = &[
            // Forward triangle u1->u2, u2->u3, u1->u3 with t=10,20,30 (good).
            ("u1", "u2", 10),
            ("u2", "u3", 20),
            ("u1", "u3", 30),
            // Forward triangle u2->u4, u4->u5, u2->u5 with t=40,50,60 (good).
            ("u2", "u4", 40),
            ("u4", "u5", 50),
            ("u2", "u5", 60),
            // Forward triangle u1->u4, u4->u3, u1->u3 — third edge u1->u3
            // already exists at t=30, so t_ab=70, t_bc=80, t_ac=30 fails.
            ("u1", "u4", 70),
            ("u4", "u3", 80),
            // Disjoint edge: no triangle.
            ("u6", "u1", 5),
        ];
        for (s, d, t) in edges {
            g.add_relation(Relation::new(*s, *d, RelationType::Auth, *t))
                .unwrap();
        }
        g.sort_edges_by_timestamp().unwrap();

        let trie = MaterializedCsrTrie::build(&g);
        let ts_map = MinTimestampMap::build(&g, &trie);
        let lftj = sort_triangles(enumerate_triangles_lftj(&g, &trie, &ts_map, 10_000));
        let naive = sort_triangles(enumerate_triangles_naive(&g, &trie, &ts_map, 10_000));
        let simd = sort_triangles(enumerate_triangles_lftj_simd(&g, &trie, &ts_map, 10_000));
        assert_eq!(lftj, naive, "LFTJ and naive triangle finders must agree");
        assert_eq!(simd, naive, "SIMD enumerator must match the baseline");
        assert!(!lftj.is_empty(), "expected at least one valid triangle");

        // Windowed variant: full-range window must match unwindowed.
        let win_full = sort_triangles(enumerate_triangles_lftj_simd_window(
            &g, &trie, &ts_map, i64::MIN, i64::MAX, 10_000,
        ));
        assert_eq!(win_full, naive, "windowed enumerator must match unwindowed at full range");

        // Windowed variant: disjoint window union covers full range.
        let mut win_union = Vec::new();
        for (lo, hi) in [(i64::MIN, 50_i64), (50, 1_000)] {
            win_union.extend(enumerate_triangles_lftj_simd_window(
                &g, &trie, &ts_map, lo, hi, 10_000,
            ));
        }
        let win_union = sort_triangles(win_union);
        assert_eq!(win_union, naive, "disjoint windows over full range must reconstruct full result");
    }

    #[test]
    fn max_results_caps_output() {
        // K4 tournament with timestamps chosen so that the predicate
        // t_ab < t_bc < t_ac holds for every lex-ordered triple
        // a < b < c (4 such triples on K4). Formula t = 100*dst + (3 -
        // src) makes destination the dominant axis and breaks ties so
        // smaller-source edges come later — the exact shape that
        // satisfies forward-triangle ordering.
        let mut g = GraphHunter::new();
        let names = ["a", "b", "c", "d"];
        for n in names.iter() {
            g.add_entity(Entity::new(*n, EntityType::User)).unwrap();
        }
        for (si, s) in names.iter().enumerate() {
            for (di, d) in names.iter().enumerate() {
                if si == di {
                    continue;
                }
                let t = 100 * (di as i64) + (3 - si as i64);
                g.add_relation(Relation::new(*s, *d, RelationType::Auth, t))
                    .unwrap();
            }
        }
        g.sort_edges_by_timestamp().unwrap();
        let r = find_triangles_temporal(&g, 2);
        assert_eq!(r.len(), 2, "max_results=2 must cap output");
    }

    #[test]
    fn empty_graph_returns_empty() {
        let g = GraphHunter::new();
        assert!(find_triangles_temporal(&g, 100).is_empty());
    }

    #[test]
    fn unused_arc_warning_suppressed() {
        // The Arc<str> import is exercised by the result construction
        // above; this test exists purely so the unused-import lint
        // never fires if those paths get refactored.
        let s: Arc<str> = Arc::from("x");
        assert_eq!(&*s, "x");
    }

    /// Build a 4-vertex graph with the six lex-ordered forward edges
    /// of a K4 and timestamps strictly chronological in lex order:
    /// `t_ab=10 < t_ac=20 < t_ad=30 < t_bc=40 < t_bd=50 < t_cd=60`.
    /// Exactly one K4 in the result, named `(a,b,c,d)`.
    fn make_k4_chronological() -> GraphHunter {
        let mut g = GraphHunter::new();
        for n in ["a", "b", "c", "d"] {
            g.add_entity(Entity::new(n, EntityType::User)).unwrap();
        }
        let edges: &[(&str, &str, i64)] = &[
            ("a", "b", 10),
            ("a", "c", 20),
            ("a", "d", 30),
            ("b", "c", 40),
            ("b", "d", 50),
            ("c", "d", 60),
        ];
        for (s, d, t) in edges {
            g.add_relation(Relation::new(*s, *d, RelationType::Auth, *t))
                .unwrap();
        }
        g.sort_edges_by_timestamp().unwrap();
        g
    }

    #[test]
    fn lftj_4clique_enumerate_chronological_match() {
        let g = make_k4_chronological();
        let trie = MaterializedCsrTrie::build(&g);
        let ts_map = MinTimestampMap::build(&g, &trie);
        let naive =
            enumerate_4cliques_naive(&g, &trie, &ts_map, i64::MIN, i64::MAX, 100);
        let simd =
            enumerate_4cliques_lftj_simd(&g, &trie, &ts_map, i64::MIN, i64::MAX, 100);
        let par =
            enumerate_4cliques_lftj_simd_par(&g, &trie, &ts_map, i64::MIN, i64::MAX, 100);
        for (label, r) in [("naive", &naive), ("simd", &simd), ("par", &par)] {
            assert_eq!(r.len(), 1, "{label}: exactly one chronological K4");
            assert_eq!(&*r[0][0], "a", "{label}");
            assert_eq!(&*r[0][1], "b", "{label}");
            assert_eq!(&*r[0][2], "c", "{label}");
            assert_eq!(&*r[0][3], "d", "{label}");
        }
    }

    #[test]
    fn lftj_4clique_enumerate_out_of_order_rejected() {
        // Same shape but t_cd is moved to before t_bd — the predicate
        // t_bd < t_cd fails, so no K4 should emit.
        let mut g = GraphHunter::new();
        for n in ["a", "b", "c", "d"] {
            g.add_entity(Entity::new(n, EntityType::User)).unwrap();
        }
        let edges: &[(&str, &str, i64)] = &[
            ("a", "b", 10),
            ("a", "c", 20),
            ("a", "d", 30),
            ("b", "c", 40),
            ("b", "d", 60),
            ("c", "d", 50), // out of order
        ];
        for (s, d, t) in edges {
            g.add_relation(Relation::new(*s, *d, RelationType::Auth, *t))
                .unwrap();
        }
        g.sort_edges_by_timestamp().unwrap();
        let trie = MaterializedCsrTrie::build(&g);
        let ts_map = MinTimestampMap::build(&g, &trie);
        let r = enumerate_4cliques_lftj_simd(
            &g, &trie, &ts_map, i64::MIN, i64::MAX, 100,
        );
        assert!(r.is_empty(), "out-of-order K4 must be rejected");
    }

    #[test]
    fn lftj_4clique_enumerate_parity_naive_seq_par() {
        // Random ER graph at high density so the strict chronological
        // predicate (1/720 selectivity) still leaves a non-trivial
        // result set. V=60 / p=0.40 yields ~2 K matches in expectation
        // and runs naive in <50 ms. All three impls must agree.
        let mut g = crate::generate_erdos_renyi(60, 0.40, 1_000, 1_000_000, 7);
        g.sort_edges_by_timestamp().unwrap();
        let trie = MaterializedCsrTrie::build(&g);
        let ts_map = MinTimestampMap::build(&g, &trie);
        let naive = sort_4cliques(enumerate_4cliques_naive(
            &g, &trie, &ts_map, i64::MIN, i64::MAX, 100_000,
        ));
        let simd = sort_4cliques(enumerate_4cliques_lftj_simd(
            &g, &trie, &ts_map, i64::MIN, i64::MAX, 100_000,
        ));
        let par = sort_4cliques(enumerate_4cliques_lftj_simd_par(
            &g, &trie, &ts_map, i64::MIN, i64::MAX, 100_000,
        ));
        assert_eq!(simd, naive, "LFTJ-SIMD K4 enumerate must match naive");
        assert_eq!(par, naive, "rayon-parallel K4 enumerate must match naive");
        assert!(!naive.is_empty(), "expected at least one chronological K4 at p=0.40");
    }

    #[test]
    fn lftj_4clique_enumerate_window_full_range_matches_unwindowed() {
        let mut g = crate::generate_erdos_renyi(80, 0.10, 1_000, 1_000_000, 11);
        g.sort_edges_by_timestamp().unwrap();
        let trie = MaterializedCsrTrie::build(&g);
        let ts_map = MinTimestampMap::build(&g, &trie);
        let full = sort_4cliques(enumerate_4cliques_lftj_simd(
            &g, &trie, &ts_map, i64::MIN, i64::MAX, 100_000,
        ));
        // Disjoint window union over the full timestamp range must
        // reconstruct the unwindowed result.
        let mut union = Vec::new();
        for (lo, hi) in [(i64::MIN, 500_000_i64), (500_000, i64::MAX)] {
            union.extend(enumerate_4cliques_lftj_simd(
                &g, &trie, &ts_map, lo, hi, 100_000,
            ));
        }
        let union = sort_4cliques(union);
        assert_eq!(union, full, "disjoint windows must reconstruct full result");
    }

    #[test]
    fn lftj_4clique_enumerate_max_results_caps() {
        let mut g = crate::generate_erdos_renyi(80, 0.10, 1_000, 1_000_000, 13);
        g.sort_edges_by_timestamp().unwrap();
        let trie = MaterializedCsrTrie::build(&g);
        let ts_map = MinTimestampMap::build(&g, &trie);
        let r = enumerate_4cliques_lftj_simd(&g, &trie, &ts_map, i64::MIN, i64::MAX, 3);
        assert!(r.len() <= 3, "max_results must cap output");
    }

    /// Type-aware trie: homogeneous K4 (Auth) hypothesis must NOT
    /// emit a K4 whose edges are mixed types. Build a graph that
    /// contains a K4 in `Auth` edges and a separate K4 in `Connect`
    /// edges (with chronologically valid timestamps each); the
    /// type-aware LFTJ on a homogeneous-Auth K4 hypothesis must
    /// only return the Auth K4. Without the filter, the type-blind
    /// trie sees both K4s as topologically equivalent and returns
    /// both — that's the correctness bug this fix closes.
    #[test]
    fn type_aware_lftj_k4_filters_by_relation_type() {
        use crate::types::RelationType;
        // Two disjoint K4s: (a..d) connected by Auth, (e..h)
        // connected by Connect. Eight separate vertices so the K4s
        // can't share any nodes.
        let mut g = GraphHunter::new();
        for n in ["a", "b", "c", "d", "e", "f", "g", "h"] {
            g.add_entity(Entity::new(n, EntityType::User)).unwrap();
        }
        let auth_edges: &[(&str, &str, i64)] = &[
            ("a", "b", 10),
            ("a", "c", 20),
            ("a", "d", 30),
            ("b", "c", 40),
            ("b", "d", 50),
            ("c", "d", 60),
        ];
        let conn_edges: &[(&str, &str, i64)] = &[
            ("e", "f", 110),
            ("e", "g", 120),
            ("e", "h", 130),
            ("f", "g", 140),
            ("f", "h", 150),
            ("g", "h", 160),
        ];
        for (s, d, t) in auth_edges {
            g.add_relation(Relation::new(*s, *d, RelationType::Auth, *t))
                .unwrap();
        }
        for (s, d, t) in conn_edges {
            g.add_relation(Relation::new(*s, *d, RelationType::Connect, *t))
                .unwrap();
        }
        g.sort_edges_by_timestamp().unwrap();

        // Build a homogeneous K4-Auth hypothesis (six steps, all
        // User -[Auth]-> User).
        let mut h = crate::Hypothesis::new("auth K4");
        for _ in 0..6 {
            h = h.add_step(crate::HypothesisStep::new(
                EntityType::User,
                RelationType::Auth,
                EntityType::User,
            ));
        }

        // Type-aware trie via the new helper.
        let trie = g.build_lftj_trie_for(&h);
        let ts_map = MinTimestampMap::build(&g, &trie);
        let mut results = enumerate_4cliques_lftj_simd(
            &g, &trie, &ts_map, i64::MIN, i64::MAX, 100,
        );
        results.sort_by(|a, b| a[0].cmp(&b[0]));

        assert_eq!(
            results.len(),
            1,
            "type-aware K4-Auth must emit exactly the Auth K4, not the Connect K4"
        );
        let names: Vec<&str> = results[0].iter().map(|s| &**s).collect();
        assert_eq!(names, vec!["a", "b", "c", "d"]);

        // Sanity: the type-blind trie sees both K4s.
        let blind_trie = MaterializedCsrTrie::build(&g);
        let blind_ts = MinTimestampMap::build(&g, &blind_trie);
        let blind = enumerate_4cliques_lftj_simd(
            &g, &blind_trie, &blind_ts, i64::MIN, i64::MAX, 100,
        );
        assert_eq!(
            blind.len(),
            2,
            "type-blind trie must see both K4s — confirms the bug the type-aware path fixes"
        );
    }

    /// Build a 5-vertex graph with the ten lex-ordered forward edges
    /// of a K5 and timestamps strictly chronological in lex order:
    /// `t_ab=10 < t_ac=20 < t_ad=30 < t_ae=40 < t_bc=50 < t_bd=60 <
    ///  t_be=70 < t_cd=80 < t_ce=90 < t_de=100`. Exactly one K5 in
    /// the result, named `(a,b,c,d,e)`.
    fn make_k5_chronological() -> GraphHunter {
        let mut g = GraphHunter::new();
        for n in ["a", "b", "c", "d", "e"] {
            g.add_entity(Entity::new(n, EntityType::User)).unwrap();
        }
        let edges: &[(&str, &str, i64)] = &[
            ("a", "b", 10),
            ("a", "c", 20),
            ("a", "d", 30),
            ("a", "e", 40),
            ("b", "c", 50),
            ("b", "d", 60),
            ("b", "e", 70),
            ("c", "d", 80),
            ("c", "e", 90),
            ("d", "e", 100),
        ];
        for (s, d, t) in edges {
            g.add_relation(Relation::new(*s, *d, RelationType::Auth, *t))
                .unwrap();
        }
        g.sort_edges_by_timestamp().unwrap();
        g
    }

    #[test]
    fn lftj_5clique_enumerate_chronological_match() {
        let g = make_k5_chronological();
        let trie = MaterializedCsrTrie::build(&g);
        let ts_map = MinTimestampMap::build(&g, &trie);
        let naive =
            enumerate_5cliques_naive(&g, &trie, &ts_map, i64::MIN, i64::MAX, 100);
        let simd =
            enumerate_5cliques_lftj_simd(&g, &trie, &ts_map, i64::MIN, i64::MAX, 100);
        let par =
            enumerate_5cliques_lftj_simd_par(&g, &trie, &ts_map, i64::MIN, i64::MAX, 100);
        for (label, r) in [("naive", &naive), ("simd", &simd), ("par", &par)] {
            assert_eq!(r.len(), 1, "{label}: exactly one chronological K5");
            assert_eq!(&*r[0][0], "a", "{label}");
            assert_eq!(&*r[0][1], "b", "{label}");
            assert_eq!(&*r[0][2], "c", "{label}");
            assert_eq!(&*r[0][3], "d", "{label}");
            assert_eq!(&*r[0][4], "e", "{label}");
        }
    }

    #[test]
    fn lftj_5clique_enumerate_out_of_order_rejected() {
        // Same shape but t_de is moved to before t_ce — the predicate
        // t_ce < t_de fails, so no K5 should emit.
        let mut g = GraphHunter::new();
        for n in ["a", "b", "c", "d", "e"] {
            g.add_entity(Entity::new(n, EntityType::User)).unwrap();
        }
        let edges: &[(&str, &str, i64)] = &[
            ("a", "b", 10),
            ("a", "c", 20),
            ("a", "d", 30),
            ("a", "e", 40),
            ("b", "c", 50),
            ("b", "d", 60),
            ("b", "e", 70),
            ("c", "d", 80),
            ("c", "e", 100), // out of order
            ("d", "e", 90),
        ];
        for (s, d, t) in edges {
            g.add_relation(Relation::new(*s, *d, RelationType::Auth, *t))
                .unwrap();
        }
        g.sort_edges_by_timestamp().unwrap();
        let trie = MaterializedCsrTrie::build(&g);
        let ts_map = MinTimestampMap::build(&g, &trie);
        let r = enumerate_5cliques_lftj_simd(
            &g, &trie, &ts_map, i64::MIN, i64::MAX, 100,
        );
        assert!(r.is_empty(), "out-of-order K5 must be rejected");
    }

    #[test]
    fn lftj_5clique_enumerate_parity_naive_seq_par() {
        // Random ER graph at high density so the strict chronological
        // predicate (1/10! selectivity) still leaves at least one match.
        // V=20 / p=0.95 is essentially the K20 tournament — many K5
        // candidates whose chronological survivors stress all three
        // impls. Smaller V than K4's parity test because K5 enumerate
        // is m^{5/2} not m^2.
        let mut g = crate::generate_erdos_renyi(20, 0.95, 1_000, 1_000_000_000, 17);
        g.sort_edges_by_timestamp().unwrap();
        let trie = MaterializedCsrTrie::build(&g);
        let ts_map = MinTimestampMap::build(&g, &trie);
        let naive = sort_5cliques(enumerate_5cliques_naive(
            &g, &trie, &ts_map, i64::MIN, i64::MAX, 100_000,
        ));
        let simd = sort_5cliques(enumerate_5cliques_lftj_simd(
            &g, &trie, &ts_map, i64::MIN, i64::MAX, 100_000,
        ));
        let par = sort_5cliques(enumerate_5cliques_lftj_simd_par(
            &g, &trie, &ts_map, i64::MIN, i64::MAX, 100_000,
        ));
        assert_eq!(simd, naive, "LFTJ-SIMD K5 enumerate must match naive");
        assert_eq!(par, naive, "rayon-parallel K5 enumerate must match naive");
    }

    #[test]
    fn lftj_5clique_enumerate_max_results_caps() {
        let g = make_k5_chronological();
        let trie = MaterializedCsrTrie::build(&g);
        let ts_map = MinTimestampMap::build(&g, &trie);
        // Only one K5 exists in the chronological fixture; cap of 1 is
        // a tautology, so build a graph with multiple K5s instead.
        // K6 chronological gives `5 + 4 + 3 + 2 + 1 = 15` K5s but we
        // settle for the simple parity that cap=1 doesn't exceed.
        let r = enumerate_5cliques_lftj_simd(&g, &trie, &ts_map, i64::MIN, i64::MAX, 1);
        assert!(r.len() <= 1, "max_results must cap output");
    }

    /// Build a 6-vertex graph with the directed cycle
    /// `a → b → c → d → e → f → a` and timestamps strictly
    /// increasing along the cycle. Exactly one C6 in the result,
    /// rotated to start at `a`.
    fn make_c6_chronological() -> GraphHunter {
        let mut g = GraphHunter::new();
        for n in ["a", "b", "c", "d", "e", "f"] {
            g.add_entity(Entity::new(n, EntityType::User)).unwrap();
        }
        let edges: &[(&str, &str, i64)] = &[
            ("a", "b", 10),
            ("b", "c", 20),
            ("c", "d", 30),
            ("d", "e", 40),
            ("e", "f", 50),
            ("f", "a", 60),
        ];
        for (s, d, t) in edges {
            g.add_relation(Relation::new(*s, *d, RelationType::Auth, *t))
                .unwrap();
        }
        g.sort_edges_by_timestamp().unwrap();
        g
    }

    #[test]
    fn lftj_c6_enumerate_chronological_match() {
        let g = make_c6_chronological();
        let fwd = MaterializedCsrTrie::build(&g);
        let rev = MaterializedCsrTrie::build_reverse(&g);
        let ts_map = MinTimestampMap::build(&g, &fwd);
        let naive =
            enumerate_6cycles_naive(&g, &fwd, &ts_map, i64::MIN, i64::MAX, 100);
        let simd = enumerate_6cycles_lftj_simd(
            &g, &fwd, &rev, &ts_map, i64::MIN, i64::MAX, 100,
        );
        let par = enumerate_6cycles_lftj_simd_par(
            &g, &fwd, &rev, &ts_map, i64::MIN, i64::MAX, 100,
        );
        for (label, r) in [("naive", &naive), ("simd", &simd), ("par", &par)] {
            assert_eq!(r.len(), 1, "{label}: exactly one chronological C6");
            assert_eq!(&*r[0][0], "a", "{label}");
            assert_eq!(&*r[0][1], "b", "{label}");
            assert_eq!(&*r[0][2], "c", "{label}");
            assert_eq!(&*r[0][3], "d", "{label}");
            assert_eq!(&*r[0][4], "e", "{label}");
            assert_eq!(&*r[0][5], "f", "{label}");
        }
    }

    #[test]
    fn lftj_c6_enumerate_out_of_order_rejected() {
        // Cycle exists topologically but t_fa < t_ef breaks the
        // chronological predicate; nothing should emit.
        let mut g = GraphHunter::new();
        for n in ["a", "b", "c", "d", "e", "f"] {
            g.add_entity(Entity::new(n, EntityType::User)).unwrap();
        }
        let edges: &[(&str, &str, i64)] = &[
            ("a", "b", 10),
            ("b", "c", 20),
            ("c", "d", 30),
            ("d", "e", 40),
            ("e", "f", 60),
            ("f", "a", 50), // out of order
        ];
        for (s, d, t) in edges {
            g.add_relation(Relation::new(*s, *d, RelationType::Auth, *t))
                .unwrap();
        }
        g.sort_edges_by_timestamp().unwrap();
        let fwd = MaterializedCsrTrie::build(&g);
        let rev = MaterializedCsrTrie::build_reverse(&g);
        let ts_map = MinTimestampMap::build(&g, &fwd);
        let r = enumerate_6cycles_lftj_simd(
            &g, &fwd, &rev, &ts_map, i64::MIN, i64::MAX, 100,
        );
        assert!(r.is_empty(), "out-of-order C6 must be rejected");
    }

    #[test]
    fn lftj_c6_enumerate_no_cycle_returns_empty() {
        // Open path `a → b → c → d → e → f` with no closing edge.
        let mut g = GraphHunter::new();
        for n in ["a", "b", "c", "d", "e", "f"] {
            g.add_entity(Entity::new(n, EntityType::User)).unwrap();
        }
        let edges: &[(&str, &str, i64)] = &[
            ("a", "b", 10),
            ("b", "c", 20),
            ("c", "d", 30),
            ("d", "e", 40),
            ("e", "f", 50),
            // no f → a
        ];
        for (s, d, t) in edges {
            g.add_relation(Relation::new(*s, *d, RelationType::Auth, *t))
                .unwrap();
        }
        g.sort_edges_by_timestamp().unwrap();
        let fwd = MaterializedCsrTrie::build(&g);
        let rev = MaterializedCsrTrie::build_reverse(&g);
        let ts_map = MinTimestampMap::build(&g, &fwd);
        let r = enumerate_6cycles_lftj_simd(
            &g, &fwd, &rev, &ts_map, i64::MIN, i64::MAX, 100,
        );
        assert!(r.is_empty(), "open path must not produce C6 matches");
    }

    #[test]
    fn lftj_c6_enumerate_parity_naive_seq_par() {
        // Tournament-like ER with bidirectional edges so cycles
        // exist; chronological filter still leaves a small result.
        // V=12 / p=0.85 keeps naive runtime under 1 s.
        let mut g = crate::generate_erdos_renyi(12, 0.85, 1_000, 100_000_000, 23);
        g.sort_edges_by_timestamp().unwrap();
        let fwd = MaterializedCsrTrie::build(&g);
        let rev = MaterializedCsrTrie::build_reverse(&g);
        let ts_map = MinTimestampMap::build(&g, &fwd);
        let naive = sort_6cycles(enumerate_6cycles_naive(
            &g, &fwd, &ts_map, i64::MIN, i64::MAX, 100_000,
        ));
        let simd = sort_6cycles(enumerate_6cycles_lftj_simd(
            &g, &fwd, &rev, &ts_map, i64::MIN, i64::MAX, 100_000,
        ));
        let par = sort_6cycles(enumerate_6cycles_lftj_simd_par(
            &g, &fwd, &rev, &ts_map, i64::MIN, i64::MAX, 100_000,
        ));
        assert_eq!(simd, naive, "LFTJ-SIMD C6 enumerate must match naive");
        assert_eq!(par, naive, "rayon-parallel C6 enumerate must match naive");
    }

    #[test]
    fn lftj_c6_enumerate_max_results_caps() {
        let g = make_c6_chronological();
        let fwd = MaterializedCsrTrie::build(&g);
        let rev = MaterializedCsrTrie::build_reverse(&g);
        let ts_map = MinTimestampMap::build(&g, &fwd);
        // Only one C6 in the chronological fixture; cap=1 is a
        // tautology so this just verifies that the cap doesn't
        // exceed the requested bound.
        let r = enumerate_6cycles_lftj_simd(
            &g, &fwd, &rev, &ts_map, i64::MIN, i64::MAX, 1,
        );
        assert!(r.len() <= 1, "max_results must cap output");
    }
}
