//! D1 (scaffold) — Leapfrog Triejoin algebraic core.
//!
//! Worst-case optimal join (WCOJ) algorithm of Veldhuizen (ICDT 2014):
//! given `k` sorted relations indexed as tries, enumerates their join
//! result in time `O(|D|^{ρ*})` where `ρ*` is the fractional edge cover
//! of the join hypergraph. For cyclic patterns (lateral movement,
//! triangles) this is asymptotically optimal — the AGM bound (Atserias,
//! Grohe, Marx, SICOMP 2013) proves no algorithm can do better.
//!
//! This file is the *algebraic core* only:
//!   - the `TrieIter` trait (open/up/seek/key/next/at_end) every input
//!     relation must implement;
//!   - `LeapfrogJoin`, the multi-way intersection that drives one
//!     join level;
//!   - `SortedVecTrieIter`, a reference implementation over a single
//!     sorted `Vec<u64>` (one-level trie) — useful for tests and as a
//!     model for what the eventual graph-CSR-backed iterator must do.
//!
//! What is NOT here yet:
//!   - Multi-level tries (the trie over `(src, dst, t)` for the
//!     temporal multigraph). Will live in a `lftj/csr_trie.rs` once
//!     the API surface settles.
//!   - The DSL → query plan translator. The hypothesis chain compiles
//!     to a sequence of one-attribute joins; cyclic patterns
//!     (post-join syntax) will need an explicit attribute order.
//!   - The integration with `search_temporal_pattern`. Until LFTJ is
//!     proven on real workloads, the existing DFS remains the only
//!     production path.
//!
//! Honest scope: this is *infrastructure* for D1. The headline 2-100×
//! gains in the literature (EmptyHeaded TODS 2017, Umbra PVLDB 2020)
//! kick in only once the trie storage, planner, and a SIMD-accelerated
//! intersection are all in place. This module ships the trait the rest
//! must implement.

/// One level of a trie iterator. The conceptual model: a trie has `k`
/// levels (one per attribute), and `TrieIter` walks one level at a
/// time. `open` descends from the parent's current key into its
/// children sublist; `up` returns. At any level, `key`/`next`/`seek`
/// scan the level's sorted keys.
///
/// All keys are `u64` to keep the trait monomorphic; for graph use we
/// pack `(StrId.index() as u32) | (timestamp_bucket as u32) << 32` or
/// similar. The packing is the caller's responsibility.
pub trait TrieIter {
    /// True if the cursor is past the end of the current level. Once
    /// at end, `key` is undefined; call `up` to ascend or restart.
    fn at_end(&self) -> bool;

    /// Read the current key at this level. Precondition: `!at_end()`.
    fn key(&self) -> u64;

    /// Advance to the next key at this level. May set `at_end` true.
    fn next(&mut self);

    /// Advance forward to the smallest key `>= target` at this level.
    /// May set `at_end` true if no such key exists. The classic
    /// leapfrog optimization is exponential gallop + binary search;
    /// the reference implementation here uses linear scan because the
    /// initial use sites are small. SIMD acceleration (galloping
    /// intersection à la Schlegel/Lemire) goes here.
    fn seek(&mut self, target: u64);

    /// Descend one level. The level below is rooted at the current
    /// `key` of this level. Precondition: `!at_end()`. Postcondition:
    /// the new level's cursor is at its first key.
    fn open(&mut self);

    /// Ascend one level. Restores the cursor at the parent level to
    /// the position it had before `open`.
    fn up(&mut self);
}

/// Reference implementation: a one-level trie over a sorted, deduped
/// `Vec<u64>`. `open`/`up` are no-ops because there is only one level;
/// for tests this is enough to drive the leapfrog intersection.
pub struct SortedVecTrieIter {
    keys: Vec<u64>,
    cursor: usize,
}

impl SortedVecTrieIter {
    /// Build from a vec that the caller guarantees is sorted ascending
    /// and free of duplicates. Debug builds verify; release trusts.
    pub fn new(keys: Vec<u64>) -> Self {
        debug_assert!(
            keys.windows(2).all(|w| w[0] < w[1]),
            "SortedVecTrieIter requires strictly-sorted input"
        );
        Self { keys, cursor: 0 }
    }
}

impl TrieIter for SortedVecTrieIter {
    #[inline]
    fn at_end(&self) -> bool {
        self.cursor >= self.keys.len()
    }

    #[inline]
    fn key(&self) -> u64 {
        self.keys[self.cursor]
    }

    #[inline]
    fn next(&mut self) {
        self.cursor += 1;
    }

    fn seek(&mut self, target: u64) {
        // Exponential gallop then binary search — same shape Veldhuizen
        // describes. For small relations (Vec<u64> with len < 32) the
        // linear path dominates anyway; we keep the gallop for the
        // benefit of large CSR-backed levels later.
        if self.at_end() {
            return;
        }
        if self.keys[self.cursor] >= target {
            return;
        }
        let mut step = 1usize;
        let mut hi = self.cursor + step;
        while hi < self.keys.len() && self.keys[hi] < target {
            self.cursor = hi;
            step *= 2;
            hi = self.cursor + step;
        }
        let bound = hi.min(self.keys.len());
        match self.keys[self.cursor..bound].binary_search(&target) {
            Ok(pos) => self.cursor += pos,
            Err(pos) => self.cursor += pos,
        }
    }

    fn open(&mut self) {
        // Single-level trie: no-op. A multi-level CSR-backed iterator
        // would push the current cursor onto a stack and reset to the
        // children slice.
    }

    fn up(&mut self) {
        // Single-level trie: no-op.
    }
}

/// Leapfrog multi-way intersection over `k` `TrieIter`s positioned at
/// the *same level*. Yields each `u64` that appears as a key in every
/// iterator. The intersection drives one level of the triejoin; the
/// caller composes levels by alternating `open` / leapfrog / `up`.
///
/// The classic algorithm (Veldhuizen ICDT 2014):
///   1. Sort the `k` iterators by current key.
///   2. If all keys are equal, emit the key and advance the iterator
///      with the smallest key by one position. Re-sort.
///   3. Otherwise, the iterator with the smallest key `seek`s past
///      the largest key. Re-sort.
///   4. Repeat until any iterator hits `at_end`.
///
/// Complexity: each emitted match costs `O(k log k)` (the sort) plus
/// however much `seek` walks; for randomized inputs the total work is
/// the AGM bound times `O(log m)` per gallop. SIMD-accelerated
/// galloping intersection (Schlegel/Lemire/Inoue-Ohara-Nakatani SIGMOD
/// 2014) is the natural drop-in for `seek` once we move to graph CSRs.
pub struct LeapfrogJoin<'a, I: TrieIter> {
    iters: &'a mut [I],
    /// Permutation of indices into `iters`, sorted by current key.
    /// Recomputed lazily.
    order: Vec<usize>,
    done: bool,
}

impl<'a, I: TrieIter> LeapfrogJoin<'a, I> {
    pub fn new(iters: &'a mut [I]) -> Self {
        let k = iters.len();
        let mut s = Self {
            iters,
            order: (0..k).collect(),
            done: false,
        };
        // If any input is empty, the join is empty.
        if s.iters.iter().any(|it| it.at_end()) {
            s.done = true;
        } else {
            s.sort_order();
        }
        s
    }

    fn sort_order(&mut self) {
        // Stable sort by current key. For k <= 8 (typical join arity)
        // an insertion sort would beat the std sort; left as TODO.
        let iters = &self.iters;
        self.order.sort_by_key(|&i| iters[i].key());
    }

    /// Returns the next intersection value, or `None` when the join is
    /// exhausted. Mirrors `Iterator::next` but takes `&mut self` —
    /// the inner iterator slice is borrowed for the lifetime of `self`.
    pub fn next_match(&mut self) -> Option<u64> {
        if self.done {
            return None;
        }
        let k = self.iters.len();
        loop {
            // After sort_order, iters[order[0]] has the smallest key,
            // iters[order[k-1]] has the largest.
            let min_i = self.order[0];
            let max_i = self.order[k - 1];
            let min_key = self.iters[min_i].key();
            let max_key = self.iters[max_i].key();

            if min_key == max_key {
                // All k keys equal — emit. Advance the first iterator
                // (any one would do; advancing the smallest preserves
                // the sorted-ish-order for the next iteration).
                let emitted = min_key;
                self.iters[min_i].next();
                if self.iters[min_i].at_end() {
                    self.done = true;
                } else {
                    self.sort_order();
                }
                return Some(emitted);
            }

            // Smallest seeks past the largest.
            self.iters[min_i].seek(max_key);
            if self.iters[min_i].at_end() {
                self.done = true;
                return None;
            }
            self.sort_order();
        }
    }
}

/// Triangle enumeration over a `MaterializedCsrTrie` via LFTJ. A
/// triangle is a triple `(a, b, c)` with edges `a→b`, `b→c`, `a→c`.
/// We run the join `R(a,b) ⋈ R(b,c) ⋈ R(a,c)` with attribute order
/// `[a, b, c]`:
///   * Level `a`: leapfrog over `R₁.src ∩ R₃.src` (the sources of the
///     first and third copy of R must agree on `a`).
///   * Level `b`: leapfrog over `R₁.dst | a ∩ R₂.src`.
///   * Level `c`: leapfrog over `R₂.dst | b ∩ R₃.dst | a`.
///
/// Returns the triangle count. The actual triples are not materialized
/// — keeping the test focused on the join correctness and on the WCOJ
/// asymptotic shape (vs an O(n³) baseline).
///
/// This mirrors the canonical example from EmptyHeaded (TODS 2017) and
/// is the smallest end-to-end exercise for the trie/leapfrog stack on
/// real graph data.
pub fn count_triangles_lftj(trie: &MaterializedCsrTrie) -> usize {
    let mut count = 0usize;

    // Level `a`: open both R₁ (for level-1 b lookup) and R₃ (for
    // level-2 c lookup) against the same source.
    let mut r1 = CsrTrieIter::new(trie);
    let mut r3 = CsrTrieIter::new(trie);

    // Manual leapfrog at level a — we need the value to drive opens
    // on both sides, so the borrow-mut shape doesn't fit the generic
    // LeapfrogJoin (which borrows the slice for its lifetime). The
    // logic is the same.
    while !r1.at_end() && !r3.at_end() {
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
        // Equal: open both at this `a`.
        r1.open();
        r3.open();
        // Level b: walk r1's dests; for each b, check that R₂(b, _) is
        // non-empty (b is a source) and intersect r2's dests with r3's
        // dests-at-a (those are the c candidates).
        while !r1.at_end() {
            let kb = r1.key();
            // R₂.src is the same `src_keys` as the trie. Use a fresh
            // CsrTrieIter at level 0 to find where `b` lives, then
            // open it.
            let mut r2 = CsrTrieIter::new(trie);
            r2.seek(kb as u64);
            if r2.at_end() || r2.key() != kb as u64 {
                // b has no outgoing edges → no c can complete.
                r1.next();
                continue;
            }
            r2.open();

            // Level c: leapfrog r2.dsts ∩ r3.dsts.
            // Save r3's dst position so the next b doesn't lose it.
            let r3_saved = (r3.dst_cursor, r3.dst_lo, r3.dst_hi);

            while !r2.at_end() && !r3.at_end() {
                let c2 = r2.key();
                let c3 = r3.key();
                if c2 == c3 {
                    count += 1;
                    r2.next();
                    r3.next();
                } else if c2 < c3 {
                    r2.seek(c3);
                } else {
                    r3.seek(c2);
                }
            }

            // Restore r3 dst cursor for the next b.
            r3.dst_cursor = r3_saved.0;
            r3.dst_lo = r3_saved.1;
            r3.dst_hi = r3_saved.2;
            // Restart r3 dst scan from the beginning of this `a`'s
            // dests for the next iteration.
            r3.dst_cursor = r3.dst_lo;

            r2.up();
            r1.next();
        }
        r1.up();
        r3.up();
        r1.next();
        r3.next();
    }

    count
}

/// SIMD-accelerated triangle count over a `MaterializedCsrTrie`. The
/// outer two levels (`a` and `b`) walk the trie scalar — they're tiny
/// for typical EDR graphs (deg ~20, src count ~1M) so the SIMD setup
/// cost would dominate. The leaf level (`c`) is the bulk work:
/// intersecting two sorted dest slices to count common elements. We
/// route that to `simd_rust::intersect_sorted_u32_count`, which
/// runtime-dispatches AVX2 on x86_64 and falls back to a scalar
/// two-pointer merge on smaller inputs or non-x86 hosts.
///
/// Result-set parity with `count_triangles_lftj` is enforced by a
/// dedicated test below.
pub fn count_triangles_lftj_simd(trie: &MaterializedCsrTrie) -> usize {
    let mut count = 0usize;

    for ai in 0..trie.src_keys.len() {
        let a_dsts =
            &trie.dst_keys[trie.dst_offsets[ai] as usize..trie.dst_offsets[ai + 1] as usize];
        for &b in a_dsts {
            let bi = match trie.src_keys.binary_search(&b) {
                Ok(i) => i,
                Err(_) => continue,
            };
            let b_dsts = &trie.dst_keys
                [trie.dst_offsets[bi] as usize..trie.dst_offsets[bi + 1] as usize];
            // Triangle iff a→c and b→c for some c. The set of valid c
            // is exactly `a_dsts ∩ b_dsts`. Hand both sorted slices to
            // the SIMD-aware intersector.
            count += crate::simd_rust::intersect_sorted_u32_count(a_dsts, b_dsts);
        }
    }
    count
}

/// Canonical triangle count: chain `a < b < c` on StrId order. Same
/// design as the K_4/K_5 canonical variants — `Aut(K_3) = S_3`, so any
/// total order canonicalizes each triangle to 1 of the 6 ordered
/// triples that the over-counted variant emits.
///
/// Scope. Both this and `count_triangles_lftj_simd` check the same
/// three directed edges `a→b, a→c, b→c`. On a bidirectional host
/// graph `canonical * 6 == count_triangles_lftj_simd`. On directed-
/// edge-independent hosts (ER) most of the 6 orderings of a 3-vertex
/// set fail the directed pattern, so canonical is a strict subset of
/// the over-counted form. The unit-test fixture covers the parity on
/// a bidirectional triangle.
pub fn count_triangles_canonical_lftj_simd(trie: &MaterializedCsrTrie) -> usize {
    let mut count = 0usize;
    for ai in 0..trie.src_keys.len() {
        let a = trie.src_keys[ai];
        let a_dsts =
            &trie.dst_keys[trie.dst_offsets[ai] as usize..trie.dst_offsets[ai + 1] as usize];
        let a_lo = a_dsts.partition_point(|&x| x <= a);
        let a_dsts_b = &a_dsts[a_lo..];
        for &b in a_dsts_b {
            let bi = match trie.src_keys.binary_search(&b) {
                Ok(i) => i,
                Err(_) => continue,
            };
            let b_dsts = &trie.dst_keys
                [trie.dst_offsets[bi] as usize..trie.dst_offsets[bi + 1] as usize];
            // c > b: tail-slice b_dsts past b before SIMD intersect.
            let c_lo_b = b_dsts.partition_point(|&x| x <= b);
            let b_dsts_c = &b_dsts[c_lo_b..];
            // c also needs to be in N(a) and > b. Tail-slice a_dsts
            // similarly before the intersect so both inputs are
            // already constrained to the chain suffix.
            let c_lo_a = a_dsts.partition_point(|&x| x <= b);
            let a_dsts_c = &a_dsts[c_lo_a..];
            count += crate::simd_rust::intersect_sorted_u32_count(a_dsts_c, b_dsts_c);
        }
    }
    count
}

/// Rayon-parallel canonical triangle count. Outer `par_iter` over
/// `ai`; the chain `a < b < c` is enforced via partition_point on
/// each worker's local view of the trie. Same independence story as
/// `count_triangles_lftj_simd`'s sequential canonical sibling.
pub fn count_triangles_canonical_lftj_simd_par(trie: &MaterializedCsrTrie) -> usize {
    use rayon::prelude::*;
    (0..trie.src_keys.len())
        .into_par_iter()
        .map(|ai| {
            let a = trie.src_keys[ai];
            let a_dsts = &trie.dst_keys
                [trie.dst_offsets[ai] as usize..trie.dst_offsets[ai + 1] as usize];
            let a_lo = a_dsts.partition_point(|&x| x <= a);
            let a_dsts_b = &a_dsts[a_lo..];
            let mut local = 0usize;
            for &b in a_dsts_b {
                let bi = match trie.src_keys.binary_search(&b) {
                    Ok(i) => i,
                    Err(_) => continue,
                };
                let b_dsts = &trie.dst_keys
                    [trie.dst_offsets[bi] as usize..trie.dst_offsets[bi + 1] as usize];
                let c_lo_b = b_dsts.partition_point(|&x| x <= b);
                let b_dsts_c = &b_dsts[c_lo_b..];
                let c_lo_a = a_dsts.partition_point(|&x| x <= b);
                let a_dsts_c = &a_dsts[c_lo_a..];
                local += crate::simd_rust::intersect_sorted_u32_count(a_dsts_c, b_dsts_c);
            }
            local
        })
        .sum()
}

/// Brute-force 4-clique counter. Counts ordered tuples `(a, b, c, d)`
/// where all six directed forward edges exist in the trie:
/// `a→b, a→c, a→d, b→c, b→d, c→d`. Triple-nested scan over `a`'s
/// destinations checking edge presence via binary search — O(deg^3)
/// per source.
///
/// This is the AGM-violating baseline: at large `m` it scales as
/// `m·deg^2 ≈ m^3/n^2`, while the LFTJ path collapses to the AGM
/// bound `m^ρ* = m^2` for K4 (ρ*=2, Ngo-Porat-Ré-Rudra JACM 65(3),
/// Atserias-Grohe-Marx SICOMP 2013). The crossover is what makes
/// WCOJ relevant for cyclic patterns at production scale.
pub fn count_4cliques_naive(trie: &MaterializedCsrTrie) -> usize {
    let mut count = 0usize;
    for ai in 0..trie.src_keys.len() {
        let a_dsts =
            &trie.dst_keys[trie.dst_offsets[ai] as usize..trie.dst_offsets[ai + 1] as usize];
        for &b in a_dsts {
            let bi = match trie.src_keys.binary_search(&b) {
                Ok(i) => i,
                Err(_) => continue,
            };
            let b_dsts = &trie.dst_keys
                [trie.dst_offsets[bi] as usize..trie.dst_offsets[bi + 1] as usize];
            for &c in a_dsts {
                if b_dsts.binary_search(&c).is_err() {
                    continue;
                }
                let ci = match trie.src_keys.binary_search(&c) {
                    Ok(i) => i,
                    Err(_) => continue,
                };
                let c_dsts = &trie.dst_keys
                    [trie.dst_offsets[ci] as usize..trie.dst_offsets[ci + 1] as usize];
                for &d in a_dsts {
                    if b_dsts.binary_search(&d).is_err() {
                        continue;
                    }
                    if c_dsts.binary_search(&d).is_err() {
                        continue;
                    }
                    count += 1;
                }
            }
        }
    }
    count
}

/// Worst-case-optimal 4-clique count via LFTJ. Three nested
/// intersections, the inner two SIMD-accelerated:
///
///   - `a` scans the source list (scalar; sources are usually sparse).
///   - `b` scans `a`'s destinations (scalar).
///   - `ab_isect = N(a) ∩ N(b)` — the candidate set for `c` *and* `d`
///     (both must be neighbors of `a` and `b`). One SIMD intersect.
///   - For each `c ∈ ab_isect`, the answer is
///     `|ab_isect ∩ N(c)|` — a second SIMD intersect, this time
///     counting only.
///
/// Total intersections per (a,b): one collect of size `|ab_isect|`,
/// followed by `|ab_isect|` count-only intersects. Asymptotically the
/// work matches the AGM bound for K4 (`m^ρ* = m^2`).
pub fn count_4cliques_lftj_simd(trie: &MaterializedCsrTrie) -> usize {
    let mut count = 0usize;
    let mut ab_isect: Vec<u32> = Vec::new();
    for ai in 0..trie.src_keys.len() {
        let a_dsts =
            &trie.dst_keys[trie.dst_offsets[ai] as usize..trie.dst_offsets[ai + 1] as usize];
        for &b in a_dsts {
            let bi = match trie.src_keys.binary_search(&b) {
                Ok(i) => i,
                Err(_) => continue,
            };
            let b_dsts = &trie.dst_keys
                [trie.dst_offsets[bi] as usize..trie.dst_offsets[bi + 1] as usize];

            ab_isect.clear();
            crate::simd_rust::intersect_sorted_u32_collect(a_dsts, b_dsts, &mut ab_isect);
            if ab_isect.is_empty() {
                continue;
            }
            for &c in ab_isect.iter() {
                let ci = match trie.src_keys.binary_search(&c) {
                    Ok(i) => i,
                    Err(_) => continue,
                };
                let c_dsts = &trie.dst_keys
                    [trie.dst_offsets[ci] as usize..trie.dst_offsets[ci + 1] as usize];
                count += crate::simd_rust::intersect_sorted_u32_count(&ab_isect, c_dsts);
            }
        }
    }
    count
}

/// Canonical 4-clique count: enumerate each K_4 instance **exactly
/// once** by enforcing the chain `a < b < c < d` on StrId order (the
/// trie's u32 keys give a total order, any total order works).
///
/// Why chain works for K_4. `Aut(K_4) = S_4` is the full symmetric
/// group on 4 vertices, so every permutation of a clique's vertices
/// is an automorphism. The 24 ordered tuples `count_4cliques_lftj_simd`
/// produces per K_4 instance collapse to 1 under any total-order chain.
/// Compare with directed C_n where `Aut = Z/n` (rotations only) — there
/// chain over-constrains and `count_6cycles_canonical_lftj_simd` uses
/// "star from min" instead.
///
/// Performance. The chain is enforced at zero asymptotic cost via
/// `partition_point` on the already-sorted neighbor lists and intersect
/// outputs (one `O(log n)` per level). The inner SIMD intersect runs
/// against tail-slices of `ab_isect`, so the work per (a,b) drops by
/// roughly the chain factor — the same multiplicative `|Aut|×` cut the
/// over-counted variant pays for redundantly.
///
/// Scope. Both `count_4cliques_naive` and this canonical variant check
/// the **same six directed edges** `a→b, a→c, a→d, b→c, b→d, c→d`.
/// On a bidirectional host graph (every undirected edge represented by
/// both directed pairs) every ordering of a 4-vertex set produces those
/// six directed edges and `canonical * 24 == count_4cliques_naive`. On
/// a directed graph where edge directions are independent (Erdős-Rényi
/// random direction), most orderings of a 4-vertex set fail the
/// directed pattern and canonical is a strict subset of naive. The
/// equality assertion is therefore exercised on bidirectional fixtures
/// only; ER bench harnesses use canonical for runtime measurement
/// without count comparison.
pub fn count_4cliques_canonical_lftj_simd(trie: &MaterializedCsrTrie) -> usize {
    let mut count = 0usize;
    let mut ab_isect: Vec<u32> = Vec::new();
    for ai in 0..trie.src_keys.len() {
        let a = trie.src_keys[ai];
        let a_dsts =
            &trie.dst_keys[trie.dst_offsets[ai] as usize..trie.dst_offsets[ai + 1] as usize];
        let a_lo = a_dsts.partition_point(|&x| x <= a);
        let a_dsts_b = &a_dsts[a_lo..];
        for &b in a_dsts_b {
            let bi = match trie.src_keys.binary_search(&b) {
                Ok(i) => i,
                Err(_) => continue,
            };
            let b_dsts = &trie.dst_keys
                [trie.dst_offsets[bi] as usize..trie.dst_offsets[bi + 1] as usize];

            ab_isect.clear();
            crate::simd_rust::intersect_sorted_u32_collect(a_dsts, b_dsts, &mut ab_isect);
            if ab_isect.is_empty() {
                continue;
            }
            let c_lo = ab_isect.partition_point(|&x| x <= b);
            let ab_isect_c = &ab_isect[c_lo..];
            for (idx, &c) in ab_isect_c.iter().enumerate() {
                let ci = match trie.src_keys.binary_search(&c) {
                    Ok(i) => i,
                    Err(_) => continue,
                };
                let c_dsts = &trie.dst_keys
                    [trie.dst_offsets[ci] as usize..trie.dst_offsets[ci + 1] as usize];
                let d_pool = &ab_isect_c[idx + 1..];
                count += crate::simd_rust::intersect_sorted_u32_count(d_pool, c_dsts);
            }
        }
    }
    count
}

/// Rayon-parallel variant of `count_4cliques_lftj_simd`. The outer
/// loop over `ai` is the natural parallelism axis: each source is
/// independent, the trie is read-only, and each worker accumulates a
/// local count then sums. No sharing, no contention. Composes
/// multiplicatively with the AGM win — at $V=1000, p=0.10$ where the
/// sequential LFTJ already wins $3.25\times$, the parallel variant
/// adds another $\sim N_{\mathrm{cores}}\times$.
pub fn count_4cliques_lftj_simd_par(trie: &MaterializedCsrTrie) -> usize {
    use rayon::prelude::*;
    (0..trie.src_keys.len())
        .into_par_iter()
        .map_init(Vec::<u32>::new, |ab_isect, ai| {
            let mut local = 0usize;
            let a_dsts = &trie.dst_keys
                [trie.dst_offsets[ai] as usize..trie.dst_offsets[ai + 1] as usize];
            for &b in a_dsts {
                let bi = match trie.src_keys.binary_search(&b) {
                    Ok(i) => i,
                    Err(_) => continue,
                };
                let b_dsts = &trie.dst_keys
                    [trie.dst_offsets[bi] as usize..trie.dst_offsets[bi + 1] as usize];
                ab_isect.clear();
                crate::simd_rust::intersect_sorted_u32_collect(a_dsts, b_dsts, ab_isect);
                if ab_isect.is_empty() {
                    continue;
                }
                for &c in ab_isect.iter() {
                    let ci = match trie.src_keys.binary_search(&c) {
                        Ok(i) => i,
                        Err(_) => continue,
                    };
                    let c_dsts = &trie.dst_keys
                        [trie.dst_offsets[ci] as usize..trie.dst_offsets[ci + 1] as usize];
                    local += crate::simd_rust::intersect_sorted_u32_count(ab_isect, c_dsts);
                }
            }
            local
        })
        .sum()
}

/// Rayon-parallel canonical 4-clique count. Outer `par_iter` over
/// `ai` with each worker maintaining its own scratch ab_isect via
/// `map_init`. Chain `a < b < c < d` enforced identically to the
/// sequential canonical variant.
pub fn count_4cliques_canonical_lftj_simd_par(trie: &MaterializedCsrTrie) -> usize {
    use rayon::prelude::*;
    (0..trie.src_keys.len())
        .into_par_iter()
        .map_init(Vec::<u32>::new, |ab_isect, ai| {
            let a = trie.src_keys[ai];
            let a_dsts = &trie.dst_keys
                [trie.dst_offsets[ai] as usize..trie.dst_offsets[ai + 1] as usize];
            let a_lo = a_dsts.partition_point(|&x| x <= a);
            let a_dsts_b = &a_dsts[a_lo..];
            let mut local = 0usize;
            for &b in a_dsts_b {
                let bi = match trie.src_keys.binary_search(&b) {
                    Ok(i) => i,
                    Err(_) => continue,
                };
                let b_dsts = &trie.dst_keys
                    [trie.dst_offsets[bi] as usize..trie.dst_offsets[bi + 1] as usize];
                ab_isect.clear();
                crate::simd_rust::intersect_sorted_u32_collect(a_dsts, b_dsts, ab_isect);
                if ab_isect.is_empty() {
                    continue;
                }
                let c_lo = ab_isect.partition_point(|&x| x <= b);
                let ab_isect_c = &ab_isect[c_lo..];
                for (idx, &c) in ab_isect_c.iter().enumerate() {
                    let ci = match trie.src_keys.binary_search(&c) {
                        Ok(i) => i,
                        Err(_) => continue,
                    };
                    let c_dsts = &trie.dst_keys
                        [trie.dst_offsets[ci] as usize..trie.dst_offsets[ci + 1] as usize];
                    let d_pool = &ab_isect_c[idx + 1..];
                    local += crate::simd_rust::intersect_sorted_u32_count(d_pool, c_dsts);
                }
            }
            local
        })
        .sum()
}

/// Brute-force 5-clique count. Quintuple loop with binary search at
/// every level — the AGM-violating baseline scaling as `m·deg^3 ≈
/// m^4/n^3`. The LFTJ path collapses to `m^ρ* = m^{5/2}` (ρ*=5/2 for
/// K5). Used as the parity baseline for the SIMD path and as the
/// slow side of the AGM crossover bench.
pub fn count_5cliques_naive(trie: &MaterializedCsrTrie) -> usize {
    let mut count = 0usize;
    for ai in 0..trie.src_keys.len() {
        let a_dsts =
            &trie.dst_keys[trie.dst_offsets[ai] as usize..trie.dst_offsets[ai + 1] as usize];
        for &b in a_dsts {
            let bi = match trie.src_keys.binary_search(&b) {
                Ok(i) => i,
                Err(_) => continue,
            };
            let b_dsts = &trie.dst_keys
                [trie.dst_offsets[bi] as usize..trie.dst_offsets[bi + 1] as usize];
            for &c in a_dsts {
                if b_dsts.binary_search(&c).is_err() {
                    continue;
                }
                let ci = match trie.src_keys.binary_search(&c) {
                    Ok(i) => i,
                    Err(_) => continue,
                };
                let c_dsts = &trie.dst_keys
                    [trie.dst_offsets[ci] as usize..trie.dst_offsets[ci + 1] as usize];
                for &d in a_dsts {
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
                    let d_dsts = &trie.dst_keys
                        [trie.dst_offsets[di] as usize..trie.dst_offsets[di + 1] as usize];
                    for &e in a_dsts {
                        if b_dsts.binary_search(&e).is_err() {
                            continue;
                        }
                        if c_dsts.binary_search(&e).is_err() {
                            continue;
                        }
                        if d_dsts.binary_search(&e).is_err() {
                            continue;
                        }
                        count += 1;
                    }
                }
            }
        }
    }
    count
}

/// Worst-case-optimal 5-clique count via LFTJ. Three SIMD-collect
/// intersections plus a final SIMD count-only intersection:
///
///   - `a` scans sources (scalar).
///   - `b` scans `a`'s dests (scalar).
///   - `ab_isect = N(a) ∩ N(b)` — collect (candidates for c, d, e).
///   - For each `c ∈ ab_isect`, `abc_isect = ab_isect ∩ N(c)` — collect
///     (candidates for d, e).
///   - For each `d ∈ abc_isect`, the answer is `|abc_isect ∩ N(d)|`
///     — count-only intersect.
///
/// Three intersect-collects + one count per (a,b,c,d). Asymptotic
/// work matches the AGM bound `m^{5/2}` (Ngo-Porat-Ré-Rudra
/// JACM 65(3); Atserias-Grohe-Marx SICOMP 2013). Compared to K4's
/// `m^2`, K5's `m^{5/2}` widens the gap with naive `m^4/n^3` even
/// faster in average degree m/n.
pub fn count_5cliques_lftj_simd(trie: &MaterializedCsrTrie) -> usize {
    let mut count = 0usize;
    let mut ab_isect: Vec<u32> = Vec::new();
    let mut abc_isect: Vec<u32> = Vec::new();
    for ai in 0..trie.src_keys.len() {
        let a_dsts =
            &trie.dst_keys[trie.dst_offsets[ai] as usize..trie.dst_offsets[ai + 1] as usize];
        for &b in a_dsts {
            let bi = match trie.src_keys.binary_search(&b) {
                Ok(i) => i,
                Err(_) => continue,
            };
            let b_dsts = &trie.dst_keys
                [trie.dst_offsets[bi] as usize..trie.dst_offsets[bi + 1] as usize];
            ab_isect.clear();
            crate::simd_rust::intersect_sorted_u32_collect(a_dsts, b_dsts, &mut ab_isect);
            if ab_isect.len() < 2 {
                continue;
            }
            for c_idx in 0..ab_isect.len() {
                let c = ab_isect[c_idx];
                let ci = match trie.src_keys.binary_search(&c) {
                    Ok(i) => i,
                    Err(_) => continue,
                };
                let c_dsts = &trie.dst_keys
                    [trie.dst_offsets[ci] as usize..trie.dst_offsets[ci + 1] as usize];
                abc_isect.clear();
                crate::simd_rust::intersect_sorted_u32_collect(
                    &ab_isect[..],
                    c_dsts,
                    &mut abc_isect,
                );
                if abc_isect.is_empty() {
                    continue;
                }
                for &d in abc_isect.iter() {
                    let di = match trie.src_keys.binary_search(&d) {
                        Ok(i) => i,
                        Err(_) => continue,
                    };
                    let d_dsts = &trie.dst_keys
                        [trie.dst_offsets[di] as usize..trie.dst_offsets[di + 1] as usize];
                    count += crate::simd_rust::intersect_sorted_u32_count(&abc_isect, d_dsts);
                }
            }
        }
    }
    count
}

/// Canonical 5-clique count: chain `a < b < c < d < e` on StrId order.
/// Same rationale as `count_4cliques_canonical_lftj_simd` — `Aut(K_5)
/// = S_5` is the full symmetric group, so chain canonicalizes every
/// K_5 instance to exactly 1 ordered tuple.
///
/// Scope. Like the K_4 variant, both this and `count_5cliques_naive`
/// check the same ten directed edges in a fixed orientation. On
/// bidirectional fixtures `canonical * 120 == count_5cliques_naive`;
/// on directed-edge-independent host graphs canonical is a strict
/// subset. At scale the redundancy ratio is the bigger of the two
/// clique variants — K_5 pays `5! = 120×` in the over-counted form
/// vs `4! = 24×` for K_4 — so the canonical operator wins more here.
pub fn count_5cliques_canonical_lftj_simd(trie: &MaterializedCsrTrie) -> usize {
    let mut count = 0usize;
    let mut ab_isect: Vec<u32> = Vec::new();
    let mut abc_isect: Vec<u32> = Vec::new();
    for ai in 0..trie.src_keys.len() {
        let a = trie.src_keys[ai];
        let a_dsts =
            &trie.dst_keys[trie.dst_offsets[ai] as usize..trie.dst_offsets[ai + 1] as usize];
        let a_lo = a_dsts.partition_point(|&x| x <= a);
        let a_dsts_b = &a_dsts[a_lo..];
        for &b in a_dsts_b {
            let bi = match trie.src_keys.binary_search(&b) {
                Ok(i) => i,
                Err(_) => continue,
            };
            let b_dsts = &trie.dst_keys
                [trie.dst_offsets[bi] as usize..trie.dst_offsets[bi + 1] as usize];
            ab_isect.clear();
            crate::simd_rust::intersect_sorted_u32_collect(a_dsts, b_dsts, &mut ab_isect);
            if ab_isect.len() < 2 {
                continue;
            }
            let c_lo = ab_isect.partition_point(|&x| x <= b);
            let ab_isect_c = &ab_isect[c_lo..];
            for (c_idx, &c) in ab_isect_c.iter().enumerate() {
                let ci = match trie.src_keys.binary_search(&c) {
                    Ok(i) => i,
                    Err(_) => continue,
                };
                let c_dsts = &trie.dst_keys
                    [trie.dst_offsets[ci] as usize..trie.dst_offsets[ci + 1] as usize];
                abc_isect.clear();
                // d > c → only consider tail of ab_isect_c past c, then
                // intersect with c's neighbors. The tail is already a
                // sorted u32 slice so the SIMD intersect is unchanged.
                let d_pool = &ab_isect_c[c_idx + 1..];
                crate::simd_rust::intersect_sorted_u32_collect(d_pool, c_dsts, &mut abc_isect);
                if abc_isect.is_empty() {
                    continue;
                }
                for (d_idx, &d) in abc_isect.iter().enumerate() {
                    let di = match trie.src_keys.binary_search(&d) {
                        Ok(i) => i,
                        Err(_) => continue,
                    };
                    let d_dsts = &trie.dst_keys
                        [trie.dst_offsets[di] as usize..trie.dst_offsets[di + 1] as usize];
                    let e_pool = &abc_isect[d_idx + 1..];
                    count += crate::simd_rust::intersect_sorted_u32_count(e_pool, d_dsts);
                }
            }
        }
    }
    count
}

/// Rayon-parallel 5-clique count. Outer `par_iter` over `ai`; each
/// worker holds its own pair of scratch intersect buffers via
/// `map_init`. Same independence story as `count_4cliques_lftj_simd_par`.
/// Composes multiplicatively with the AGM win — at high density the
/// AGM gap is wider for K5 than K4 (`m^4/n^3` vs `m^{5/2}` instead of
/// `m^3/n^2` vs `m^2`), so the parallel speedup over naive should
/// exceed the K4 numbers at the same point.
pub fn count_5cliques_lftj_simd_par(trie: &MaterializedCsrTrie) -> usize {
    use rayon::prelude::*;
    (0..trie.src_keys.len())
        .into_par_iter()
        .map_init(
            || (Vec::<u32>::new(), Vec::<u32>::new()),
            |(ab_isect, abc_isect), ai| {
                let mut local = 0usize;
                let a_dsts = &trie.dst_keys
                    [trie.dst_offsets[ai] as usize..trie.dst_offsets[ai + 1] as usize];
                for &b in a_dsts {
                    let bi = match trie.src_keys.binary_search(&b) {
                        Ok(i) => i,
                        Err(_) => continue,
                    };
                    let b_dsts = &trie.dst_keys
                        [trie.dst_offsets[bi] as usize..trie.dst_offsets[bi + 1] as usize];
                    ab_isect.clear();
                    crate::simd_rust::intersect_sorted_u32_collect(a_dsts, b_dsts, ab_isect);
                    if ab_isect.len() < 2 {
                        continue;
                    }
                    for c_idx in 0..ab_isect.len() {
                        let c = ab_isect[c_idx];
                        let ci = match trie.src_keys.binary_search(&c) {
                            Ok(i) => i,
                            Err(_) => continue,
                        };
                        let c_dsts = &trie.dst_keys
                            [trie.dst_offsets[ci] as usize..trie.dst_offsets[ci + 1] as usize];
                        abc_isect.clear();
                        crate::simd_rust::intersect_sorted_u32_collect(
                            &ab_isect[..],
                            c_dsts,
                            abc_isect,
                        );
                        if abc_isect.is_empty() {
                            continue;
                        }
                        for &d in abc_isect.iter() {
                            let di = match trie.src_keys.binary_search(&d) {
                                Ok(i) => i,
                                Err(_) => continue,
                            };
                            let d_dsts = &trie.dst_keys[trie.dst_offsets[di] as usize
                                ..trie.dst_offsets[di + 1] as usize];
                            local += crate::simd_rust::intersect_sorted_u32_count(
                                abc_isect, d_dsts,
                            );
                        }
                    }
                }
                local
            },
        )
        .sum()
}

/// Rayon-parallel canonical 5-clique count. Same structure as the
/// over-counted `_par` sibling but with the chain a<b<c<d<e applied
/// at each level via partition_point.
pub fn count_5cliques_canonical_lftj_simd_par(trie: &MaterializedCsrTrie) -> usize {
    use rayon::prelude::*;
    (0..trie.src_keys.len())
        .into_par_iter()
        .map_init(
            || (Vec::<u32>::new(), Vec::<u32>::new()),
            |(ab_isect, abc_isect), ai| {
                let a = trie.src_keys[ai];
                let a_dsts = &trie.dst_keys
                    [trie.dst_offsets[ai] as usize..trie.dst_offsets[ai + 1] as usize];
                let a_lo = a_dsts.partition_point(|&x| x <= a);
                let a_dsts_b = &a_dsts[a_lo..];
                let mut local = 0usize;
                for &b in a_dsts_b {
                    let bi = match trie.src_keys.binary_search(&b) {
                        Ok(i) => i,
                        Err(_) => continue,
                    };
                    let b_dsts = &trie.dst_keys
                        [trie.dst_offsets[bi] as usize..trie.dst_offsets[bi + 1] as usize];
                    ab_isect.clear();
                    crate::simd_rust::intersect_sorted_u32_collect(a_dsts, b_dsts, ab_isect);
                    if ab_isect.len() < 2 {
                        continue;
                    }
                    let c_lo = ab_isect.partition_point(|&x| x <= b);
                    let ab_isect_c = &ab_isect[c_lo..];
                    for (c_idx, &c) in ab_isect_c.iter().enumerate() {
                        let ci = match trie.src_keys.binary_search(&c) {
                            Ok(i) => i,
                            Err(_) => continue,
                        };
                        let c_dsts = &trie.dst_keys
                            [trie.dst_offsets[ci] as usize..trie.dst_offsets[ci + 1] as usize];
                        abc_isect.clear();
                        let d_pool = &ab_isect_c[c_idx + 1..];
                        crate::simd_rust::intersect_sorted_u32_collect(
                            d_pool, c_dsts, abc_isect,
                        );
                        if abc_isect.is_empty() {
                            continue;
                        }
                        for (d_idx, &d) in abc_isect.iter().enumerate() {
                            let di = match trie.src_keys.binary_search(&d) {
                                Ok(i) => i,
                                Err(_) => continue,
                            };
                            let d_dsts = &trie.dst_keys[trie.dst_offsets[di] as usize
                                ..trie.dst_offsets[di + 1] as usize];
                            let e_pool = &abc_isect[d_idx + 1..];
                            local += crate::simd_rust::intersect_sorted_u32_count(
                                e_pool, d_dsts,
                            );
                        }
                    }
                }
                local
            },
        )
        .sum()
}

/// Naive 6-cycle count: nested edge-walk plus a binary-search closure
/// at the leaf. For each forward edge `(a, b)` and each path
/// `b → c → d → e → f`, ask whether `f → a`. No reverse trie needed.
/// Cost: `O(m · d^4 · log d)`.
pub fn count_6cycles_naive(forward: &MaterializedCsrTrie) -> usize {
    let mut count = 0usize;
    for ai in 0..forward.src_keys.len() {
        let a = forward.src_keys[ai];
        let a_dsts = &forward.dst_keys
            [forward.dst_offsets[ai] as usize..forward.dst_offsets[ai + 1] as usize];
        for &b in a_dsts {
            let b_dsts = forward.neighbors_of(b);
            for &c in b_dsts {
                let c_dsts = forward.neighbors_of(c);
                for &d in c_dsts {
                    let d_dsts = forward.neighbors_of(d);
                    for &e in d_dsts {
                        let e_dsts = forward.neighbors_of(e);
                        for &f in e_dsts {
                            let f_dsts = forward.neighbors_of(f);
                            if f_dsts.binary_search(&a).is_ok() {
                                count += 1;
                            }
                        }
                    }
                }
            }
        }
    }
    count
}

/// Worst-case-optimal 6-cycle count via LFTJ. The cycle closure
/// `f → a` is collapsed into a SIMD intersect: at the leaf we compute
/// `|N_forward(e) ∩ predecessors(a)|` instead of iterating each
/// candidate `f` and binary-searching `a` in its neighbor list. The
/// outer expansion still walks `(a, b, c, d, e)` linearly because no
/// pair of consecutive cycle edges share a vertex on which to
/// intersect — C6 is not a clique, so `b`'s and `c`'s neighborhoods
/// don't intersect *as a constraint* on the cycle.
///
/// Cost: `O(m · d^3 · (d_e + d_pred))` with SIMD merge — saves the
/// `log d` factor and benefits from the vectorized `intersect_count`.
pub fn count_6cycles_lftj_simd(
    forward: &MaterializedCsrTrie,
    reverse: &MaterializedCsrTrie,
) -> usize {
    let mut count = 0usize;
    for ai in 0..forward.src_keys.len() {
        let a = forward.src_keys[ai];
        let pred_a = reverse.neighbors_of(a);
        if pred_a.is_empty() {
            continue;
        }
        let a_dsts = &forward.dst_keys
            [forward.dst_offsets[ai] as usize..forward.dst_offsets[ai + 1] as usize];
        for &b in a_dsts {
            let b_dsts = forward.neighbors_of(b);
            for &c in b_dsts {
                let c_dsts = forward.neighbors_of(c);
                for &d in c_dsts {
                    let d_dsts = forward.neighbors_of(d);
                    for &e in d_dsts {
                        let e_dsts = forward.neighbors_of(e);
                        count +=
                            crate::simd_rust::intersect_sorted_u32_count(e_dsts, pred_a);
                    }
                }
            }
        }
    }
    count
}

/// Canonical 6-cycle count: enforce `a < min(b, c, d, e, f)` strictly
/// so each *simple* directed 6-cycle is counted at exactly one
/// rotation (the one starting at the smallest StrId).
///
/// Why star-from-min, not chain. `Aut(directed C_n) = Z/n` — only
/// rotations are automorphisms (reflections reverse edge direction
/// and so are not autos of a directed cycle). The chain encoding
/// `a<b<c<d<e<f` would require the cycle's traversal direction to
/// coincide with increasing-StrId order, which it generally does not
/// — the chain would miss valid cycle instances. Pinning `a` as the
/// minimum is the correct symmetry-break for the rotation group: it
/// fixes the start position uniquely without imposing structure on
/// the remaining traversal.
///
/// Scope. The strict-less filters mean this counts **simple** 6-cycles
/// only — closed 6-walks with vertex repeats (e.g. lollipops
/// `0→1→0→3→4→5→0`) are filtered out, even though
/// `count_6cycles_naive` counts every rotation of them. The
/// relationship `canonical * 6 == count_6cycles_naive` therefore
/// holds only when the host graph admits no non-simple closed
/// 6-walks; the unit-test fixture (a single 6-cycle on disjoint
/// vertices) is one such case. ER bench fixtures are not, so the
/// bench harness verifies parity only at the LFTJ-vs-naive level
/// and leaves canonical as a pure speedup measurement.
pub fn count_6cycles_canonical_lftj_simd(
    forward: &MaterializedCsrTrie,
    reverse: &MaterializedCsrTrie,
) -> usize {
    let mut count = 0usize;
    for ai in 0..forward.src_keys.len() {
        let a = forward.src_keys[ai];
        let pred_a = reverse.neighbors_of(a);
        if pred_a.is_empty() {
            continue;
        }
        // `a < f` constraint at the closure: predecessors of `a` that
        // are ≤ `a` cannot close a canonical cycle.
        let f_lo = pred_a.partition_point(|&x| x <= a);
        let pred_a_canon = &pred_a[f_lo..];
        if pred_a_canon.is_empty() {
            continue;
        }
        let a_dsts = &forward.dst_keys
            [forward.dst_offsets[ai] as usize..forward.dst_offsets[ai + 1] as usize];
        let b_lo = a_dsts.partition_point(|&x| x <= a);
        let a_dsts_b = &a_dsts[b_lo..];
        for &b in a_dsts_b {
            let b_dsts = forward.neighbors_of(b);
            let c_lo = b_dsts.partition_point(|&x| x <= a);
            let b_dsts_c = &b_dsts[c_lo..];
            for &c in b_dsts_c {
                let c_dsts = forward.neighbors_of(c);
                let d_lo = c_dsts.partition_point(|&x| x <= a);
                let c_dsts_d = &c_dsts[d_lo..];
                for &d in c_dsts_d {
                    let d_dsts = forward.neighbors_of(d);
                    let e_lo = d_dsts.partition_point(|&x| x <= a);
                    let d_dsts_e = &d_dsts[e_lo..];
                    for &e in d_dsts_e {
                        let e_dsts = forward.neighbors_of(e);
                        // `f` candidates must be in N_forward(e) ∩ pred_a
                        // *and* > a — the latter is already encoded in
                        // pred_a_canon. Apply the same partition on
                        // e_dsts before the SIMD intersect.
                        let f_lo_e = e_dsts.partition_point(|&x| x <= a);
                        let e_dsts_f = &e_dsts[f_lo_e..];
                        count += crate::simd_rust::intersect_sorted_u32_count(
                            e_dsts_f,
                            pred_a_canon,
                        );
                    }
                }
            }
        }
    }
    count
}

/// Rayon-parallel C6 count. Same outer-loop independence as the K4/K5
/// variants — each source `a` is processed against a read-only
/// `(forward, reverse)` pair and worker counts are summed.
pub fn count_6cycles_lftj_simd_par(
    forward: &MaterializedCsrTrie,
    reverse: &MaterializedCsrTrie,
) -> usize {
    use rayon::prelude::*;
    (0..forward.src_keys.len())
        .into_par_iter()
        .map(|ai| {
            let a = forward.src_keys[ai];
            let pred_a = reverse.neighbors_of(a);
            if pred_a.is_empty() {
                return 0usize;
            }
            let a_dsts = &forward.dst_keys
                [forward.dst_offsets[ai] as usize..forward.dst_offsets[ai + 1] as usize];
            let mut local = 0usize;
            for &b in a_dsts {
                let b_dsts = forward.neighbors_of(b);
                for &c in b_dsts {
                    let c_dsts = forward.neighbors_of(c);
                    for &d in c_dsts {
                        let d_dsts = forward.neighbors_of(d);
                        for &e in d_dsts {
                            let e_dsts = forward.neighbors_of(e);
                            local +=
                                crate::simd_rust::intersect_sorted_u32_count(e_dsts, pred_a);
                        }
                    }
                }
            }
            local
        })
        .sum()
}

/// Rayon-parallel canonical C6 count. Same star-from-min encoding as
/// the sequential canonical sibling — each worker filters its outer
/// `a` and the per-level neighbor lists to entries strictly greater
/// than `a`, so each simple 6-cycle is counted at exactly one
/// rotation (the one starting at the minimum vertex).
pub fn count_6cycles_canonical_lftj_simd_par(
    forward: &MaterializedCsrTrie,
    reverse: &MaterializedCsrTrie,
) -> usize {
    use rayon::prelude::*;
    (0..forward.src_keys.len())
        .into_par_iter()
        .map(|ai| {
            let a = forward.src_keys[ai];
            let pred_a = reverse.neighbors_of(a);
            if pred_a.is_empty() {
                return 0usize;
            }
            let f_lo = pred_a.partition_point(|&x| x <= a);
            let pred_a_canon = &pred_a[f_lo..];
            if pred_a_canon.is_empty() {
                return 0usize;
            }
            let a_dsts = &forward.dst_keys
                [forward.dst_offsets[ai] as usize..forward.dst_offsets[ai + 1] as usize];
            let b_lo = a_dsts.partition_point(|&x| x <= a);
            let a_dsts_b = &a_dsts[b_lo..];
            let mut local = 0usize;
            for &b in a_dsts_b {
                let b_dsts = forward.neighbors_of(b);
                let c_lo = b_dsts.partition_point(|&x| x <= a);
                let b_dsts_c = &b_dsts[c_lo..];
                for &c in b_dsts_c {
                    let c_dsts = forward.neighbors_of(c);
                    let d_lo = c_dsts.partition_point(|&x| x <= a);
                    let c_dsts_d = &c_dsts[d_lo..];
                    for &d in c_dsts_d {
                        let d_dsts = forward.neighbors_of(d);
                        let e_lo = d_dsts.partition_point(|&x| x <= a);
                        let d_dsts_e = &d_dsts[e_lo..];
                        for &e in d_dsts_e {
                            let e_dsts = forward.neighbors_of(e);
                            let f_lo_e = e_dsts.partition_point(|&x| x <= a);
                            let e_dsts_f = &e_dsts[f_lo_e..];
                            local += crate::simd_rust::intersect_sorted_u32_count(
                                e_dsts_f,
                                pred_a_canon,
                            );
                        }
                    }
                }
            }
            local
        })
        .sum()
}

// ── Two-level CSR trie over the graph's edge store ─────────────────
//
// A `MaterializedCsrTrie` is a (src, dst) relation indexed as a trie:
// level 0 walks distinct sources sorted ascending; after `open()` from
// a source, level 1 walks that source's distinct destinations sorted
// ascending. Built once from the graph; intended lifetime: per-query.
//
// This deliberately materializes — the existing CompactRelation slice
// is sorted by (src, timestamp), not by (src, dst). Re-sorting in
// place would break temporal ordering the DFS relies on. Allocating a
// dedicated CSR for LFTJ keeps the two paths independent. Memory:
// O(unique-edges) of u32 plus O(unique-sources) of u32 — for a graph
// with 1M unique edges, ~8 MB.

/// CSR-packed 2-level trie. `src_keys` is the sorted list of source
/// vertex indices that have at least one outgoing edge. For source at
/// position `i`, its destinations live in
/// `dst_keys[dst_offsets[i] .. dst_offsets[i+1]]`, sorted ascending and
/// deduplicated.
pub struct MaterializedCsrTrie {
    pub src_keys: Vec<u32>,
    pub dst_offsets: Vec<u32>,
    pub dst_keys: Vec<u32>,
}

impl MaterializedCsrTrie {
    /// Build from a graph filtering edges by a caller-supplied
    /// predicate. Used by the type-aware LFTJ path so a hypothesis
    /// like `Host -[Connect]-> Host -[Connect]-> Host` (homogeneous
    /// triangle on a specific edge type) only sees `Connect` edges
    /// in its trie, matching what the operator authored.
    ///
    /// The predicate is invoked once per (src, edge) pair. Vertices
    /// whose entire dst slice gets filtered out are dropped from
    /// `src_keys` so the trie iterator doesn't waste cycles on them.
    pub fn build_filtered<F>(graph: &crate::graph::GraphHunter, mut accept: F) -> Self
    where
        F: FnMut(crate::interner::StrId, &crate::streaming::StreamEdge) -> bool,
    {
        let mut srcs_candidate: Vec<u32> = graph
            .entities
            .keys()
            .copied()
            .map(|sid| sid.index() as u32)
            .collect();
        srcs_candidate.sort_unstable();

        let mut src_keys: Vec<u32> = Vec::with_capacity(srcs_candidate.len());
        let mut dst_offsets: Vec<u32> = Vec::with_capacity(srcs_candidate.len() + 1);
        let mut dst_keys: Vec<u32> = Vec::new();
        dst_offsets.push(0);

        for &src_idx in &srcs_candidate {
            let sid = crate::interner::StrId::from_raw(src_idx);
            let arc = match graph.streaming.neighbors_arc(sid) {
                Some(a) => a,
                None => continue,
            };
            let g = arc.read();
            let mut dsts: Vec<u32> = g
                .as_slice()
                .iter()
                .filter(|e| accept(sid, e))
                .map(|e| e.dest_sid.index() as u32)
                .collect();
            if dsts.is_empty() {
                continue;
            }
            dsts.sort_unstable();
            dsts.dedup();
            src_keys.push(src_idx);
            dst_keys.extend_from_slice(&dsts);
            dst_offsets.push(dst_keys.len() as u32);
        }

        Self {
            src_keys,
            dst_offsets,
            dst_keys,
        }
    }

    /// Build from a graph by walking every entity's outgoing-edge
    /// slice and packing the (src, dst) pairs into a CSR. Cost: O(E)
    /// for the walk plus O(deg log deg) per source for dedup-sort.
    pub fn build(graph: &crate::graph::GraphHunter) -> Self {
        let mut srcs: Vec<u32> = graph
            .entities
            .keys()
            .copied()
            .filter_map(|sid| {
                if graph.streaming.degree_of(sid) > 0 {
                    Some(sid.index() as u32)
                } else {
                    None
                }
            })
            .collect();
        srcs.sort_unstable();

        let mut dst_offsets: Vec<u32> = Vec::with_capacity(srcs.len() + 1);
        let mut dst_keys: Vec<u32> = Vec::new();
        dst_offsets.push(0);

        for &src_idx in &srcs {
            let sid = crate::interner::StrId::from_raw(src_idx);
            let arc = match graph.streaming.neighbors_arc(sid) {
                Some(a) => a,
                None => {
                    dst_offsets.push(dst_keys.len() as u32);
                    continue;
                }
            };
            let g = arc.read();
            // Dedup-sort the dest indices for this source.
            let mut dsts: Vec<u32> = g
                .as_slice()
                .iter()
                .map(|e| e.dest_sid.index() as u32)
                .collect();
            dsts.sort_unstable();
            dsts.dedup();
            dst_keys.extend_from_slice(&dsts);
            dst_offsets.push(dst_keys.len() as u32);
        }

        Self {
            src_keys: srcs,
            dst_offsets,
            dst_keys,
        }
    }

    /// Number of unique (src, dst) pairs stored.
    pub fn edge_count(&self) -> usize {
        self.dst_keys.len()
    }

    /// Type-aware variant of `build_reverse`. Same shape as
    /// `build_filtered` (forward) but emits the predecessor view.
    /// The predicate is invoked once per (src, edge) pair against
    /// the underlying graph; only matching edges contribute to the
    /// reverse trie.
    pub fn build_reverse_filtered<F>(graph: &crate::graph::GraphHunter, mut accept: F) -> Self
    where
        F: FnMut(crate::interner::StrId, &crate::streaming::StreamEdge) -> bool,
    {
        let mut pairs: Vec<(u32, u32)> = Vec::new();
        graph.streaming.for_each_edge(|src_sid, edge| {
            if !accept(src_sid, edge) {
                return;
            }
            let s = src_sid.index() as u32;
            let d = edge.dest_sid.index() as u32;
            pairs.push((d, s));
        });
        pairs.sort_unstable();
        pairs.dedup();

        let mut src_keys: Vec<u32> = Vec::new();
        let mut dst_offsets: Vec<u32> = vec![0];
        let mut dst_keys: Vec<u32> = Vec::with_capacity(pairs.len());
        let mut i = 0usize;
        while i < pairs.len() {
            let key = pairs[i].0;
            src_keys.push(key);
            while i < pairs.len() && pairs[i].0 == key {
                dst_keys.push(pairs[i].1);
                i += 1;
            }
            dst_offsets.push(dst_keys.len() as u32);
        }

        Self {
            src_keys,
            dst_offsets,
            dst_keys,
        }
    }

    /// Build the *reverse* CSR: indexed by destination, with sorted
    /// dedup'd predecessor lists in the values. Same struct, same
    /// `TrieIter`/`CsrTrieIter` works on it; `src_keys[i]` is now a
    /// destination vertex and `dst_keys[off..off+deg]` are its
    /// predecessors. Required for C6 (and any pattern with a cycle
    /// closure) so the LFTJ leaf can intersect `N(v_i)` with
    /// `predecessors(v_j)` instead of binary-searching each candidate.
    /// Cost: O(E) walk plus one O(E log E) sort of the reversed pairs.
    pub fn build_reverse(graph: &crate::graph::GraphHunter) -> Self {
        let mut pairs: Vec<(u32, u32)> = Vec::new();
        graph.streaming.for_each_edge(|src_sid, edge| {
            let s = src_sid.index() as u32;
            let d = edge.dest_sid.index() as u32;
            pairs.push((d, s));
        });
        pairs.sort_unstable();
        pairs.dedup();

        let mut src_keys: Vec<u32> = Vec::new();
        let mut dst_offsets: Vec<u32> = vec![0];
        let mut dst_keys: Vec<u32> = Vec::with_capacity(pairs.len());
        let mut i = 0usize;
        while i < pairs.len() {
            let key = pairs[i].0;
            src_keys.push(key);
            while i < pairs.len() && pairs[i].0 == key {
                dst_keys.push(pairs[i].1);
                i += 1;
            }
            dst_offsets.push(dst_keys.len() as u32);
        }

        Self {
            src_keys,
            dst_offsets,
            dst_keys,
        }
    }

    /// Lookup the predecessor (or successor, depending on which trie
    /// this is) slice for `vertex`. Returns `&[]` if `vertex` is not a
    /// key in this trie.
    pub fn neighbors_of(&self, vertex: u32) -> &[u32] {
        match self.src_keys.binary_search(&vertex) {
            Ok(i) => {
                &self.dst_keys[self.dst_offsets[i] as usize..self.dst_offsets[i + 1] as usize]
            }
            Err(_) => &[],
        }
    }
}

/// `TrieIter` over a `MaterializedCsrTrie`. Lifetime is tied to the
/// trie; the iterator does not own its keys. The cursor is two-level:
/// `src_cursor` indexes into `src_keys`; after `open()`, `dst_cursor`
/// indexes into `dst_keys[dst_offsets[src_cursor]..]`.
pub struct CsrTrieIter<'a> {
    trie: &'a MaterializedCsrTrie,
    /// Current level: 0 = src, 1 = dst.
    pub(crate) level: u8,
    pub(crate) src_cursor: usize,
    /// Saved src_cursor at the moment of `open()`; restored by `up()`.
    /// We don't *need* to save it (the cursor isn't moved during level-1
    /// scans), but storing it makes `up()` semantics explicit and lets
    /// us add invariant checks in debug builds.
    pub(crate) src_cursor_saved: usize,
    pub(crate) dst_cursor: usize,
    /// `[lo, hi)` range in `dst_keys` for the currently-open source.
    /// Valid only when `level == 1`.
    pub(crate) dst_lo: usize,
    pub(crate) dst_hi: usize,
}

impl<'a> CsrTrieIter<'a> {
    pub fn new(trie: &'a MaterializedCsrTrie) -> Self {
        Self {
            trie,
            level: 0,
            src_cursor: 0,
            src_cursor_saved: 0,
            dst_cursor: 0,
            dst_lo: 0,
            dst_hi: 0,
        }
    }
}

impl<'a> TrieIter for CsrTrieIter<'a> {
    fn at_end(&self) -> bool {
        match self.level {
            0 => self.src_cursor >= self.trie.src_keys.len(),
            1 => self.dst_cursor >= self.dst_hi,
            _ => true,
        }
    }

    fn key(&self) -> u64 {
        match self.level {
            0 => self.trie.src_keys[self.src_cursor] as u64,
            1 => self.trie.dst_keys[self.dst_cursor] as u64,
            _ => unreachable!("CsrTrieIter has only two levels"),
        }
    }

    fn next(&mut self) {
        match self.level {
            0 => self.src_cursor += 1,
            1 => self.dst_cursor += 1,
            _ => {}
        }
    }

    fn seek(&mut self, target: u64) {
        // Galloping seek (Veldhuizen ICDT 2014): exponential step from
        // the cursor until past `target`, then bounded binary search.
        // Cache-friendly when targets cluster near the cursor — the
        // common case in leapfrog where each iterator only nudges
        // slightly past the neighbour's key. See `simd_rust::gallop_ge_u32`.
        match self.level {
            0 => {
                if self.at_end() {
                    return;
                }
                let cur = self.trie.src_keys[self.src_cursor] as u64;
                if cur >= target {
                    return;
                }
                let slice = &self.trie.src_keys[self.src_cursor..];
                let probe = target.min(u32::MAX as u64) as u32;
                self.src_cursor += crate::simd_rust::gallop_ge_u32(slice, probe);
            }
            1 => {
                if self.at_end() {
                    return;
                }
                let cur = self.trie.dst_keys[self.dst_cursor] as u64;
                if cur >= target {
                    return;
                }
                let slice = &self.trie.dst_keys[self.dst_cursor..self.dst_hi];
                let probe = target.min(u32::MAX as u64) as u32;
                self.dst_cursor += crate::simd_rust::gallop_ge_u32(slice, probe);
            }
            _ => {}
        }
    }

    fn open(&mut self) {
        debug_assert_eq!(self.level, 0, "CsrTrieIter::open from level 0 only");
        debug_assert!(!self.at_end());
        self.level = 1;
        self.src_cursor_saved = self.src_cursor;
        let i = self.src_cursor;
        self.dst_lo = self.trie.dst_offsets[i] as usize;
        self.dst_hi = self.trie.dst_offsets[i + 1] as usize;
        self.dst_cursor = self.dst_lo;
    }

    fn up(&mut self) {
        debug_assert_eq!(self.level, 1, "CsrTrieIter::up from level 1 only");
        self.level = 0;
        self.src_cursor = self.src_cursor_saved;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn collect(mut it: SortedVecTrieIter) -> Vec<u64> {
        let mut out = Vec::new();
        while !it.at_end() {
            out.push(it.key());
            it.next();
        }
        out
    }

    #[test]
    fn iter_walks_all_keys() {
        let it = SortedVecTrieIter::new(vec![1, 3, 5, 7, 9]);
        assert_eq!(collect(it), vec![1, 3, 5, 7, 9]);
    }

    #[test]
    fn seek_advances_to_target_or_above() {
        let mut it = SortedVecTrieIter::new(vec![1, 3, 5, 7, 9]);
        it.seek(4);
        assert_eq!(it.key(), 5);
        it.seek(7);
        assert_eq!(it.key(), 7);
        it.seek(20);
        assert!(it.at_end());
    }

    #[test]
    fn seek_no_op_when_target_le_current() {
        let mut it = SortedVecTrieIter::new(vec![1, 3, 5]);
        it.seek(0);
        assert_eq!(it.key(), 1);
        it.seek(1);
        assert_eq!(it.key(), 1);
    }

    #[test]
    fn leapfrog_two_way_basic() {
        let mut a = SortedVecTrieIter::new(vec![1, 2, 3, 5, 8]);
        let mut b = SortedVecTrieIter::new(vec![2, 5, 6, 8, 10]);
        let mut its = [a, b];
        let mut join = LeapfrogJoin::new(&mut its);
        let mut out = Vec::new();
        while let Some(k) = join.next_match() {
            out.push(k);
        }
        assert_eq!(out, vec![2, 5, 8]);
    }

    #[test]
    fn leapfrog_three_way_triangle() {
        // Three sorted lists; the intersection is exactly the
        // common elements.
        let a = SortedVecTrieIter::new(vec![1, 2, 3, 4, 5, 6, 7]);
        let b = SortedVecTrieIter::new(vec![2, 4, 6, 8]);
        let c = SortedVecTrieIter::new(vec![1, 4, 6, 9]);
        let mut its = [a, b, c];
        let mut join = LeapfrogJoin::new(&mut its);
        let mut out = Vec::new();
        while let Some(k) = join.next_match() {
            out.push(k);
        }
        assert_eq!(out, vec![4, 6]);
    }

    #[test]
    fn leapfrog_empty_input_yields_empty() {
        let a = SortedVecTrieIter::new(vec![1, 2, 3]);
        let b = SortedVecTrieIter::new(vec![]);
        let mut its = [a, b];
        let mut join = LeapfrogJoin::new(&mut its);
        assert!(join.next_match().is_none());
    }

    #[test]
    fn leapfrog_disjoint_inputs_yield_empty() {
        let a = SortedVecTrieIter::new(vec![1, 3, 5]);
        let b = SortedVecTrieIter::new(vec![2, 4, 6]);
        let mut its = [a, b];
        let mut join = LeapfrogJoin::new(&mut its);
        assert!(join.next_match().is_none());
    }

    #[test]
    fn leapfrog_identical_inputs_yield_full() {
        let a = SortedVecTrieIter::new(vec![1, 2, 3, 4]);
        let b = SortedVecTrieIter::new(vec![1, 2, 3, 4]);
        let mut its = [a, b];
        let mut join = LeapfrogJoin::new(&mut its);
        let mut out = Vec::new();
        while let Some(k) = join.next_match() {
            out.push(k);
        }
        assert_eq!(out, vec![1, 2, 3, 4]);
    }

    // ── Two-level CSR trie tests ───────────────────────────────────

    use crate::graph::GraphHunter;
    use crate::types::{EntityType, RelationType};
    use crate::{Entity, Relation};

    fn small_triangle_graph() -> GraphHunter {
        // Three users, each connecting to the next forming a triangle:
        // u1 -> u2 -> u3 -> u1.
        let mut g = GraphHunter::new();
        g.add_entity(Entity::new("u1", EntityType::User)).unwrap();
        g.add_entity(Entity::new("u2", EntityType::User)).unwrap();
        g.add_entity(Entity::new("u3", EntityType::User)).unwrap();
        g.add_relation(Relation::new("u1", "u2", RelationType::Auth, 100))
            .unwrap();
        g.add_relation(Relation::new("u2", "u3", RelationType::Auth, 110))
            .unwrap();
        g.add_relation(Relation::new("u3", "u1", RelationType::Auth, 120))
            .unwrap();
        g.sort_edges_by_timestamp().unwrap();
        g
    }

    #[test]
    fn csr_trie_builds_correct_shape() {
        let g = small_triangle_graph();
        let trie = MaterializedCsrTrie::build(&g);

        // 3 sources, each with exactly 1 dest.
        assert_eq!(trie.src_keys.len(), 3);
        assert_eq!(trie.edge_count(), 3);
        // src_keys is sorted ascending.
        assert!(trie.src_keys.windows(2).all(|w| w[0] < w[1]));
        // dst_offsets is monotonic.
        assert!(trie.dst_offsets.windows(2).all(|w| w[0] <= w[1]));
        // Final offset matches edge count.
        assert_eq!(*trie.dst_offsets.last().unwrap() as usize, trie.edge_count());
    }

    #[test]
    fn csr_trie_iter_walks_sources() {
        let g = small_triangle_graph();
        let trie = MaterializedCsrTrie::build(&g);
        let mut it = CsrTrieIter::new(&trie);

        let mut out = Vec::new();
        while !it.at_end() {
            out.push(it.key());
            it.next();
        }
        // Three distinct source indices, sorted.
        assert_eq!(out.len(), 3);
        assert!(out.windows(2).all(|w| w[0] < w[1]));
    }

    #[test]
    fn csr_trie_iter_open_descends_to_dests() {
        let g = small_triangle_graph();
        let trie = MaterializedCsrTrie::build(&g);
        let mut it = CsrTrieIter::new(&trie);

        assert!(!it.at_end());
        it.open();
        // Each source has exactly one dest in this graph.
        let dest = it.key();
        it.next();
        assert!(it.at_end(), "single dest expected");
        it.up();
        // Back at level 0, same position.
        assert_eq!(it.level, 0);
        assert!(!it.at_end());
        // Verify the dest was a valid vertex index (≤ entity count).
        assert!((dest as usize) < g.entity_type_tags.len());
    }

    #[test]
    fn csr_trie_iter_seek_at_level_0() {
        let g = small_triangle_graph();
        let trie = MaterializedCsrTrie::build(&g);
        let mut it = CsrTrieIter::new(&trie);

        // Seek past the last source.
        let last = *trie.src_keys.last().unwrap() as u64;
        it.seek(last + 100);
        assert!(it.at_end());
    }

    /// Naive O(n^3) triangle baseline — counts directed triangles
    /// `a→b, b→c, a→c` over a `MaterializedCsrTrie` by triple loop.
    /// Reference for the LFTJ correctness test below.
    fn count_triangles_naive(trie: &MaterializedCsrTrie) -> usize {
        let mut count = 0usize;
        for ai in 0..trie.src_keys.len() {
            let a = trie.src_keys[ai];
            let a_dsts =
                &trie.dst_keys[trie.dst_offsets[ai] as usize..trie.dst_offsets[ai + 1] as usize];
            for &b in a_dsts {
                // Find b's row in the trie (if any).
                let bi = match trie.src_keys.binary_search(&b) {
                    Ok(i) => i,
                    Err(_) => continue,
                };
                let b_dsts = &trie.dst_keys
                    [trie.dst_offsets[bi] as usize..trie.dst_offsets[bi + 1] as usize];
                for &c in b_dsts {
                    // Triangle iff a also has an edge to c.
                    if a_dsts.binary_search(&c).is_ok() {
                        let _ = a; // silence unused-warning when count is hot
                        count += 1;
                    }
                }
            }
        }
        count
    }

    fn small_directed_triangles_graph() -> GraphHunter {
        // Build a graph with several directed triangles for the
        // baseline-vs-LFTJ test:
        //   u1 -> u2, u2 -> u3, u1 -> u3   (triangle a=u1)
        //   u2 -> u4, u4 -> u5, u2 -> u5   (triangle a=u2)
        //   u1 -> u6 (no triangle through u6)
        let mut g = GraphHunter::new();
        for n in ["u1", "u2", "u3", "u4", "u5", "u6"] {
            g.add_entity(Entity::new(n, EntityType::User)).unwrap();
        }
        for (s, d, t) in [
            ("u1", "u2", 100),
            ("u2", "u3", 110),
            ("u1", "u3", 105),
            ("u2", "u4", 120),
            ("u4", "u5", 130),
            ("u2", "u5", 125),
            ("u1", "u6", 140),
        ] {
            g.add_relation(Relation::new(s, d, RelationType::Auth, t))
                .unwrap();
        }
        g.sort_edges_by_timestamp().unwrap();
        g
    }

    #[test]
    fn lftj_triangle_count_matches_naive_baseline() {
        let g = small_directed_triangles_graph();
        let trie = MaterializedCsrTrie::build(&g);

        let naive = count_triangles_naive(&trie);
        let lftj = count_triangles_lftj(&trie);

        assert_eq!(naive, 2, "expected exactly 2 directed triangles");
        assert_eq!(lftj, naive, "LFTJ count must match brute-force");
    }

    #[test]
    fn lftj_triangle_simd_matches_lftj_and_naive() {
        let g = small_directed_triangles_graph();
        let trie = MaterializedCsrTrie::build(&g);
        assert_eq!(
            count_triangles_lftj_simd(&trie),
            count_triangles_lftj(&trie),
            "SIMD path must match LFTJ"
        );
        assert_eq!(
            count_triangles_lftj_simd(&trie),
            count_triangles_naive(&trie),
            "SIMD path must match brute-force baseline"
        );
    }

    /// Bidirectional triangle: every directed pair between {u1,u2,u3}
    /// in both directions. The over-counted variants enumerate all
    /// `3! = 6` orderings of the triangle's vertices.
    fn small_bidirectional_triangle_graph() -> GraphHunter {
        let mut g = GraphHunter::new();
        for n in ["u1", "u2", "u3"] {
            g.add_entity(Entity::new(n, EntityType::User)).unwrap();
        }
        let names = ["u1", "u2", "u3"];
        let mut t = 100;
        for &s in &names {
            for &d in &names {
                if s == d {
                    continue;
                }
                g.add_relation(Relation::new(s, d, RelationType::Auth, t))
                    .unwrap();
                t += 1;
            }
        }
        g.sort_edges_by_timestamp().unwrap();
        g
    }

    #[test]
    fn lftj_triangle_canonical_matches_naive_over_6() {
        let g = small_bidirectional_triangle_graph();
        let trie = MaterializedCsrTrie::build(&g);
        let canonical = count_triangles_canonical_lftj_simd(&trie);
        let naive = count_triangles_naive(&trie);
        // Aut(K_3) = S_3, |Aut| = 6. Canonical chain a<b<c emits each
        // triangle exactly once on a bidirectional host.
        assert_eq!(canonical, 1, "bidirectional triangle has one canonical instance");
        assert_eq!(canonical * 6, naive, "canonical * |Aut(K_3)| == naive");
    }

    #[test]
    fn lftj_triangle_canonical_par_matches_sequential() {
        let g = small_bidirectional_triangle_graph();
        let trie = MaterializedCsrTrie::build(&g);
        assert_eq!(
            count_triangles_canonical_lftj_simd_par(&trie),
            count_triangles_canonical_lftj_simd(&trie),
            "rayon-parallel canonical K3 must match sequential canonical"
        );
    }

    #[test]
    fn lftj_triangle_canonical_zero_on_empty() {
        let mut g = GraphHunter::new();
        for n in ["u1", "u2"] {
            g.add_entity(Entity::new(n, EntityType::User)).unwrap();
        }
        g.add_relation(Relation::new("u1", "u2", RelationType::Auth, 100))
            .unwrap();
        g.sort_edges_by_timestamp().unwrap();
        let trie = MaterializedCsrTrie::build(&g);
        assert_eq!(count_triangles_canonical_lftj_simd(&trie), 0);
    }

    /// K4 over 4 vertices: every ordered tuple of 4 distinct vertices
    /// is a 4-clique → 4! = 24 ordered tuples.
    fn small_k4_graph() -> GraphHunter {
        let mut g = GraphHunter::new();
        for n in ["u1", "u2", "u3", "u4"] {
            g.add_entity(Entity::new(n, EntityType::User)).unwrap();
        }
        // All 12 directed pairs (i,j) with i != j — turns into a K4
        // when viewed as forward edges.
        let names = ["u1", "u2", "u3", "u4"];
        let mut t = 100;
        for &s in &names {
            for &d in &names {
                if s == d {
                    continue;
                }
                g.add_relation(Relation::new(s, d, RelationType::Auth, t))
                    .unwrap();
                t += 1;
            }
        }
        g.sort_edges_by_timestamp().unwrap();
        g
    }

    #[test]
    fn lftj_4clique_count_matches_naive_baseline() {
        let g = small_k4_graph();
        let trie = MaterializedCsrTrie::build(&g);
        let lftj = count_4cliques_lftj_simd(&trie);
        let naive = count_4cliques_naive(&trie);
        assert_eq!(
            lftj, naive,
            "LFTJ 4-clique count must match brute-force baseline"
        );
        // 4! = 24 ordered tuples of distinct vertices in a complete K4.
        assert_eq!(lftj, 24, "K4 graph must yield 24 ordered 4-cliques");
    }

    #[test]
    fn lftj_4clique_count_zero_on_triangle() {
        // 3 vertices can't form a 4-clique.
        let g = small_directed_triangles_graph();
        let trie = MaterializedCsrTrie::build(&g);
        assert_eq!(count_4cliques_lftj_simd(&trie), 0);
        assert_eq!(count_4cliques_naive(&trie), 0);
        assert_eq!(count_4cliques_lftj_simd_par(&trie), 0);
    }

    #[test]
    fn lftj_4clique_par_matches_sequential() {
        let g = small_k4_graph();
        let trie = MaterializedCsrTrie::build(&g);
        assert_eq!(
            count_4cliques_lftj_simd_par(&trie),
            count_4cliques_lftj_simd(&trie),
            "rayon-parallel K4 must match sequential count"
        );
    }

    #[test]
    fn lftj_4clique_canonical_matches_naive_over_24() {
        let g = small_k4_graph();
        let trie = MaterializedCsrTrie::build(&g);
        let canonical = count_4cliques_canonical_lftj_simd(&trie);
        let naive = count_4cliques_naive(&trie);
        // Aut(K_4) = S_4, |Aut| = 24. Canonical chain a<b<c<d emits
        // each K_4 instance exactly once.
        assert_eq!(canonical, 1, "K4 fixture has exactly one canonical 4-clique");
        assert_eq!(canonical * 24, naive, "canonical * |Aut(K_4)| == naive");
    }

    #[test]
    fn lftj_4clique_canonical_par_matches_sequential() {
        let g = small_k4_graph();
        let trie = MaterializedCsrTrie::build(&g);
        assert_eq!(
            count_4cliques_canonical_lftj_simd_par(&trie),
            count_4cliques_canonical_lftj_simd(&trie),
            "rayon-parallel canonical K4 must match sequential canonical"
        );
    }

    #[test]
    fn lftj_4clique_canonical_zero_on_triangle() {
        let g = small_directed_triangles_graph();
        let trie = MaterializedCsrTrie::build(&g);
        assert_eq!(count_4cliques_canonical_lftj_simd(&trie), 0);
    }

    /// K5 over 5 vertices: every ordered tuple of 5 distinct vertices
    /// is a 5-clique → 5! = 120 ordered tuples.
    fn small_k5_graph() -> GraphHunter {
        let mut g = GraphHunter::new();
        for n in ["u1", "u2", "u3", "u4", "u5"] {
            g.add_entity(Entity::new(n, EntityType::User)).unwrap();
        }
        let names = ["u1", "u2", "u3", "u4", "u5"];
        let mut t = 100;
        for &s in &names {
            for &d in &names {
                if s == d {
                    continue;
                }
                g.add_relation(Relation::new(s, d, RelationType::Auth, t))
                    .unwrap();
                t += 1;
            }
        }
        g.sort_edges_by_timestamp().unwrap();
        g
    }

    #[test]
    fn lftj_5clique_count_matches_naive_baseline() {
        let g = small_k5_graph();
        let trie = MaterializedCsrTrie::build(&g);
        let lftj = count_5cliques_lftj_simd(&trie);
        let naive = count_5cliques_naive(&trie);
        assert_eq!(
            lftj, naive,
            "LFTJ 5-clique count must match brute-force baseline"
        );
        // 5! = 120 ordered tuples of distinct vertices in a complete K5.
        assert_eq!(lftj, 120, "K5 graph must yield 120 ordered 5-cliques");
    }

    #[test]
    fn lftj_5clique_count_zero_on_k4() {
        // 4 vertices can't form a 5-clique.
        let g = small_k4_graph();
        let trie = MaterializedCsrTrie::build(&g);
        assert_eq!(count_5cliques_lftj_simd(&trie), 0);
        assert_eq!(count_5cliques_naive(&trie), 0);
        assert_eq!(count_5cliques_lftj_simd_par(&trie), 0);
    }

    #[test]
    fn lftj_5clique_par_matches_sequential() {
        let g = small_k5_graph();
        let trie = MaterializedCsrTrie::build(&g);
        assert_eq!(
            count_5cliques_lftj_simd_par(&trie),
            count_5cliques_lftj_simd(&trie),
            "rayon-parallel K5 must match sequential count"
        );
    }

    #[test]
    fn lftj_5clique_canonical_matches_naive_over_120() {
        let g = small_k5_graph();
        let trie = MaterializedCsrTrie::build(&g);
        let canonical = count_5cliques_canonical_lftj_simd(&trie);
        let naive = count_5cliques_naive(&trie);
        // Aut(K_5) = S_5, |Aut| = 120. Canonical chain a<b<c<d<e emits
        // each K_5 instance exactly once.
        assert_eq!(canonical, 1, "K5 fixture has exactly one canonical 5-clique");
        assert_eq!(canonical * 120, naive, "canonical * |Aut(K_5)| == naive");
    }

    #[test]
    fn lftj_5clique_canonical_par_matches_sequential() {
        let g = small_k5_graph();
        let trie = MaterializedCsrTrie::build(&g);
        assert_eq!(
            count_5cliques_canonical_lftj_simd_par(&trie),
            count_5cliques_canonical_lftj_simd(&trie),
            "rayon-parallel canonical K5 must match sequential canonical"
        );
    }

    #[test]
    fn lftj_5clique_canonical_zero_on_k4() {
        let g = small_k4_graph();
        let trie = MaterializedCsrTrie::build(&g);
        assert_eq!(count_5cliques_canonical_lftj_simd(&trie), 0);
    }

    /// Six vertices in a directed 6-cycle u1 → u2 → u3 → u4 → u5 → u6
    /// → u1. The forward edge set is exactly the cycle's six edges; no
    /// other edges. Yields exactly one ordered C6 starting at each
    /// rotation of the cycle → 6 ordered 6-cycles.
    fn small_directed_c6_graph() -> GraphHunter {
        let mut g = GraphHunter::new();
        for n in ["u1", "u2", "u3", "u4", "u5", "u6"] {
            g.add_entity(Entity::new(n, EntityType::User)).unwrap();
        }
        let cycle = [
            ("u1", "u2"),
            ("u2", "u3"),
            ("u3", "u4"),
            ("u4", "u5"),
            ("u5", "u6"),
            ("u6", "u1"),
        ];
        let mut t = 100;
        for (s, d) in cycle {
            g.add_relation(Relation::new(s, d, RelationType::Auth, t))
                .unwrap();
            t += 1;
        }
        g.sort_edges_by_timestamp().unwrap();
        g
    }

    #[test]
    fn lftj_6cycle_count_matches_naive_baseline() {
        let g = small_directed_c6_graph();
        let fwd = MaterializedCsrTrie::build(&g);
        let rev = MaterializedCsrTrie::build_reverse(&g);
        let naive = count_6cycles_naive(&fwd);
        let lftj = count_6cycles_lftj_simd(&fwd, &rev);
        assert_eq!(lftj, naive, "LFTJ C6 count must match brute-force baseline");
        assert_eq!(lftj, 6, "directed C6 yields 6 rotations as ordered 6-cycles");
    }

    #[test]
    fn lftj_6cycle_count_zero_on_acyclic_chain() {
        // u1 → u2 → u3 → u4 → u5 → u6 (no closure): no C6.
        let mut g = GraphHunter::new();
        for n in ["u1", "u2", "u3", "u4", "u5", "u6"] {
            g.add_entity(Entity::new(n, EntityType::User)).unwrap();
        }
        for (s, d) in [
            ("u1", "u2"),
            ("u2", "u3"),
            ("u3", "u4"),
            ("u4", "u5"),
            ("u5", "u6"),
        ] {
            g.add_relation(Relation::new(s, d, RelationType::Auth, 100))
                .unwrap();
        }
        g.sort_edges_by_timestamp().unwrap();
        let fwd = MaterializedCsrTrie::build(&g);
        let rev = MaterializedCsrTrie::build_reverse(&g);
        assert_eq!(count_6cycles_lftj_simd(&fwd, &rev), 0);
        assert_eq!(count_6cycles_naive(&fwd), 0);
        assert_eq!(count_6cycles_lftj_simd_par(&fwd, &rev), 0);
    }

    #[test]
    fn lftj_6cycle_par_matches_sequential() {
        let g = small_directed_c6_graph();
        let fwd = MaterializedCsrTrie::build(&g);
        let rev = MaterializedCsrTrie::build_reverse(&g);
        assert_eq!(
            count_6cycles_lftj_simd_par(&fwd, &rev),
            count_6cycles_lftj_simd(&fwd, &rev),
            "rayon-parallel C6 must match sequential count"
        );
    }

    #[test]
    fn lftj_6cycle_canonical_matches_naive_over_6() {
        let g = small_directed_c6_graph();
        let fwd = MaterializedCsrTrie::build(&g);
        let rev = MaterializedCsrTrie::build_reverse(&g);
        let canonical = count_6cycles_canonical_lftj_simd(&fwd, &rev);
        let naive = count_6cycles_naive(&fwd);
        // Aut(directed C_6) = Z/6, |Aut| = 6. Canonical "a is min"
        // emits each cycle once (the rotation starting at the smallest
        // StrId).
        assert_eq!(canonical, 1, "C6 fixture has exactly one canonical cycle");
        assert_eq!(canonical * 6, naive, "canonical * |Aut(directed C_6)| == naive");
    }

    #[test]
    fn lftj_6cycle_canonical_par_matches_sequential() {
        let g = small_directed_c6_graph();
        let fwd = MaterializedCsrTrie::build(&g);
        let rev = MaterializedCsrTrie::build_reverse(&g);
        assert_eq!(
            count_6cycles_canonical_lftj_simd_par(&fwd, &rev),
            count_6cycles_canonical_lftj_simd(&fwd, &rev),
            "rayon-parallel canonical C6 must match sequential canonical"
        );
    }

    #[test]
    fn lftj_6cycle_canonical_zero_on_acyclic_chain() {
        let mut g = GraphHunter::new();
        for n in ["u1", "u2", "u3", "u4", "u5", "u6"] {
            g.add_entity(Entity::new(n, EntityType::User)).unwrap();
        }
        for (s, d) in [
            ("u1", "u2"),
            ("u2", "u3"),
            ("u3", "u4"),
            ("u4", "u5"),
            ("u5", "u6"),
        ] {
            g.add_relation(Relation::new(s, d, RelationType::Auth, 100))
                .unwrap();
        }
        g.sort_edges_by_timestamp().unwrap();
        let fwd = MaterializedCsrTrie::build(&g);
        let rev = MaterializedCsrTrie::build_reverse(&g);
        assert_eq!(count_6cycles_canonical_lftj_simd(&fwd, &rev), 0);
    }

    #[test]
    fn lftj_reverse_trie_predecessors_match_forward_successors() {
        // For every (s, d) edge in the graph, d must list s as a
        // predecessor in the reverse trie. Cross-check on K4 graph.
        let g = small_k4_graph();
        let fwd = MaterializedCsrTrie::build(&g);
        let rev = MaterializedCsrTrie::build_reverse(&g);
        for ai in 0..fwd.src_keys.len() {
            let s = fwd.src_keys[ai];
            let dsts = &fwd.dst_keys
                [fwd.dst_offsets[ai] as usize..fwd.dst_offsets[ai + 1] as usize];
            for &d in dsts {
                let preds = rev.neighbors_of(d);
                assert!(
                    preds.binary_search(&s).is_ok(),
                    "edge {s}→{d} forward but {s} not in predecessors({d})"
                );
            }
        }
    }

    #[test]
    fn lftj_triangle_count_zero_on_acyclic_chain() {
        // u1 -> u2 -> u3 -> u4: no triangles.
        let mut g = GraphHunter::new();
        for n in ["u1", "u2", "u3", "u4"] {
            g.add_entity(Entity::new(n, EntityType::User)).unwrap();
        }
        for (s, d) in [("u1", "u2"), ("u2", "u3"), ("u3", "u4")] {
            g.add_relation(Relation::new(s, d, RelationType::Auth, 100))
                .unwrap();
        }
        g.sort_edges_by_timestamp().unwrap();
        let trie = MaterializedCsrTrie::build(&g);
        assert_eq!(count_triangles_lftj(&trie), 0);
        assert_eq!(count_triangles_naive(&trie), 0);
    }

    #[test]
    fn csr_trie_into_leapfrog_self_join_yields_all_sources() {
        // Joining the same relation against itself on the source
        // attribute is a sanity check: every source appears in both,
        // so the intersection equals the source set.
        let g = small_triangle_graph();
        let trie = MaterializedCsrTrie::build(&g);

        // Build two iters over the same trie via cloned reference.
        let mut a = CsrTrieIter::new(&trie);
        let mut b = CsrTrieIter::new(&trie);
        // Keep them at level 0; we want sources only.
        let mut its = [a, b];
        let mut join = LeapfrogJoin::new(&mut its);

        let mut out = Vec::new();
        while let Some(k) = join.next_match() {
            out.push(k);
        }
        assert_eq!(out.len(), trie.src_keys.len());
    }
}
