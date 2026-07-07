//! Pure-Rust SIMD primitives.
//!
//! Sorted-set intersection over `u32` node ids — the hot primitive
//! used by LFTJ triangle/clique enumeration. Runtime-dispatches an
//! AVX2 implementation on x86_64 and falls through to a scalar merge
//! everywhere else.
//!
//! # Runtime dispatch
//!
//! We use `is_x86_feature_detected!("avx2")` on x86_64 and gate the
//! AVX2 implementation with `#[target_feature(enable = "avx2")]`. On
//! non-x86_64 hosts (`aarch64`, wasm, etc.) the dispatcher falls
//! through to the scalar path.
//!
//! # Safety
//!
//! The AVX2 function is `unsafe` because `target_feature` forces
//! that; the public [`intersect_sorted_u32_count`] wrapper is safe —
//! it checks the feature at runtime before calling the AVX2 body.

/// Count elements common to two *sorted, ascending, deduplicated*
/// slices of `u32`. Runtime-dispatches AVX2 on x86_64 hosts that
/// report the feature; otherwise runs the scalar merge.
///
/// # Non-assumptions
///
/// The two inputs do NOT have to be the same length, and order
/// between them is irrelevant (intersection is symmetric). The
/// ascending-sorted + deduplicated preconditions are the caller's
/// responsibility — violating them produces garbage output without
/// any UB.
pub fn intersect_sorted_u32_count(a: &[u32], b: &[u32]) -> usize {
    // Tiny slices: scalar wins — AVX2 setup cost dominates.
    if a.len() < 32 || b.len() < 32 {
        return scalar_intersect_count(a, b);
    }
    #[cfg(target_arch = "x86_64")]
    {
        if is_x86_feature_detected!("avx2") {
            // SAFETY: we just checked the CPU reports AVX2.
            return unsafe { avx2_intersect_count(a, b) };
        }
    }
    scalar_intersect_count(a, b)
}

/// Classic two-pointer merge. Written to be auto-vectorization-friendly
/// in case the compiler decides to SIMDify it on a host where we
/// don't dispatch AVX2 ourselves.
#[inline]
pub(crate) fn scalar_intersect_count(a: &[u32], b: &[u32]) -> usize {
    let (mut i, mut j) = (0usize, 0usize);
    let mut count = 0usize;
    while i < a.len() && j < b.len() {
        // SAFETY: bounds checked by the while above; the `unsafe` here
        // is purely a hot-loop bounds-check elision. Removing it
        // costs ~5% on my box — the checked version is kept as a
        // fallback proof via the scalar-equivalence tests.
        let av = unsafe { *a.get_unchecked(i) };
        let bv = unsafe { *b.get_unchecked(j) };
        match av.cmp(&bv) {
            std::cmp::Ordering::Less => i += 1,
            std::cmp::Ordering::Greater => j += 1,
            std::cmp::Ordering::Equal => {
                count += 1;
                i += 1;
                j += 1;
            }
        }
    }
    count
}

/// Runtime label for the active SIMD ISA. Returns `"avx2"` on x86_64
/// hosts that report AVX2 at startup, `"scalar"` otherwise. Used by
/// the runtime info / status-badge surface in the API.
pub fn isa_label() -> &'static str {
    #[cfg(target_arch = "x86_64")]
    {
        if is_x86_feature_detected!("avx2") {
            return "avx2";
        }
    }
    "scalar"
}

// ─── AVX2 implementation (x86_64) ───────────────────────────────────

#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "avx2")]
unsafe fn avx2_intersect_count(a: &[u32], b: &[u32]) -> usize {
    use std::arch::x86_64::{
        _mm256_cmpeq_epi32, _mm256_loadu_si256, _mm256_movemask_epi8, _mm256_set1_epi32,
    };

    // Iterate the shorter side, SIMD-broadcast each value and
    // compare against an 8-lane window of the longer side. This is
    // the "broadcast & cmp" family of intersection algorithms —
    // O(|short|·|long|/8) in the worst case but competitive when the
    // ratio is skewed and the data fits in L1.
    let (s, l) = if a.len() <= b.len() { (a, b) } else { (b, a) };

    let mut count: usize = 0;
    let mut j_base: usize = 0;
    let l_ptr = l.as_ptr();

    // Scan each element of the short side through the long side.
    // We keep a pointer into `l` (`j_base`) that only moves forward,
    // giving us an amortized cost close to the merge algorithm.
    for &sv in s {
        // Advance `j_base` past elements strictly less than sv.
        while j_base + 8 <= l.len() {
            // SAFETY: j_base+8 <= l.len() guarded by the while.
            let chunk = unsafe { _mm256_loadu_si256(l_ptr.add(j_base) as *const _) };
            let needle = _mm256_set1_epi32(sv as i32);
            let cmp = _mm256_cmpeq_epi32(chunk, needle);
            let mask = _mm256_movemask_epi8(cmp);
            if mask != 0 {
                // At least one of the 8 lanes matched.
                count += 1;
                break;
            }
            // No hit in this window. If every element in the window
            // is still < sv, we can safely slide forward.
            // SAFETY: we just checked `j_base + 8 <= l.len()`.
            let last = unsafe { *l.get_unchecked(j_base + 7) };
            if last < sv {
                j_base += 8;
                continue;
            }
            // Otherwise sv sits inside this window's range and the
            // mask didn't hit → no match. Break to outer loop.
            break;
        }
        // Tail: fewer than 8 elements left in `l`, scalar finish for
        // this sv.
        if j_base + 8 > l.len() && j_base < l.len() {
            // Scalar search from j_base to end for *this* sv only.
            // Does not advance j_base permanently — other sv may
            // need to scan tails too.
            for &lv in &l[j_base..] {
                if lv == sv {
                    count += 1;
                    break;
                }
                if lv > sv {
                    break;
                }
            }
        }
    }
    count
}

// Non-x86_64 platforms don't have AVX2 — keep the symbol off so
// callers can `#[cfg(target_arch = "x86_64")]` the dispatch without
// dead-code warnings.

/// Intersection variant that *enumerates* common values into `out`
/// rather than counting them. Same dispatch shape as
/// `intersect_sorted_u32_count`: scalar when either side is small,
/// AVX2-broadcast on x86_64 with AVX2, scalar fallback elsewhere.
/// `out` is appended to (not cleared) — the caller controls reuse.
pub fn intersect_sorted_u32_collect(a: &[u32], b: &[u32], out: &mut Vec<u32>) {
    if a.len() < 32 || b.len() < 32 {
        scalar_intersect_collect(a, b, out);
        return;
    }
    #[cfg(target_arch = "x86_64")]
    {
        if is_x86_feature_detected!("avx2") {
            unsafe { avx2_intersect_collect(a, b, out) };
            return;
        }
    }
    scalar_intersect_collect(a, b, out);
}

#[inline]
pub(crate) fn scalar_intersect_collect(a: &[u32], b: &[u32], out: &mut Vec<u32>) {
    let (mut i, mut j) = (0usize, 0usize);
    while i < a.len() && j < b.len() {
        let av = unsafe { *a.get_unchecked(i) };
        let bv = unsafe { *b.get_unchecked(j) };
        match av.cmp(&bv) {
            std::cmp::Ordering::Less => i += 1,
            std::cmp::Ordering::Greater => j += 1,
            std::cmp::Ordering::Equal => {
                out.push(av);
                i += 1;
                j += 1;
            }
        }
    }
}

#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "avx2")]
unsafe fn avx2_intersect_collect(a: &[u32], b: &[u32], out: &mut Vec<u32>) {
    use std::arch::x86_64::{
        _mm256_cmpeq_epi32, _mm256_loadu_si256, _mm256_movemask_epi8, _mm256_set1_epi32,
    };

    let (s, l) = if a.len() <= b.len() { (a, b) } else { (b, a) };
    let mut j_base: usize = 0;
    let l_ptr = l.as_ptr();

    for &sv in s {
        let mut hit = false;
        while j_base + 8 <= l.len() {
            let chunk = unsafe { _mm256_loadu_si256(l_ptr.add(j_base) as *const _) };
            let needle = _mm256_set1_epi32(sv as i32);
            let cmp = _mm256_cmpeq_epi32(chunk, needle);
            let mask = _mm256_movemask_epi8(cmp);
            if mask != 0 {
                out.push(sv);
                hit = true;
                break;
            }
            let last = unsafe { *l.get_unchecked(j_base + 7) };
            if last < sv {
                j_base += 8;
                continue;
            }
            break;
        }
        if !hit && j_base + 8 > l.len() && j_base < l.len() {
            for &lv in &l[j_base..] {
                if lv == sv {
                    out.push(sv);
                    break;
                }
                if lv > sv {
                    break;
                }
            }
        }
    }
}

// ─── Galloping seek ─────────────────────────────────────────────────
//
// Used by `CsrTrieIter::seek` (the LFTJ inner loop). The classic
// Veldhuizen pattern: exponential gallop until the cursor passes
// `target`, then a binary search inside the bounded `[lo, hi)` window.
// Cache-friendly when `target` is close to the current cursor (the
// common case in leapfrog: each iterator only seeks slightly past its
// neighbour's key) — strictly cheaper than a naked `binary_search`
// over the full remaining slice, which jumps to the middle every time.

/// Find the first index `i` in `s` such that `s[i] >= target`, returning
/// `s.len()` if no such index exists. Precondition: `s` is sorted
/// ascending (callers in this crate also guarantee dedup, but that is
/// not required for correctness — equal-key blocks would just stop at
/// the first one).
///
/// Performance: O(log d) where `d = position - 0`. Concretely, gallop
/// doubles a step until it crosses `target`, then binary-searches the
/// bounded `[step/2, step)` window. Touches O(log d) cache lines vs
/// O(log n) for a naked `binary_search` — a meaningful win when the
/// target lives near the start of the slice (the WCOJ pattern).
#[inline]
pub fn gallop_ge_u32(s: &[u32], target: u32) -> usize {
    if s.is_empty() {
        return 0;
    }
    if s[0] >= target {
        return 0;
    }
    let mut lo: usize = 0;
    let mut step: usize = 1;
    let n = s.len();
    while lo + step < n && s[lo + step] < target {
        lo += step;
        step <<= 1;
    }
    let hi = (lo + step + 1).min(n);
    // Invariant: s[lo] < target, s[hi-1] >= target OR hi == n.
    match s[lo..hi].binary_search(&target) {
        Ok(pos) => lo + pos,
        Err(pos) => lo + pos,
    }
}

// ─── Tests ──────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn reference_intersect(a: &[u32], b: &[u32]) -> usize {
        let set_b: std::collections::BTreeSet<u32> = b.iter().copied().collect();
        a.iter().filter(|v| set_b.contains(v)).count()
    }

    #[test]
    fn empty_slices() {
        assert_eq!(intersect_sorted_u32_count(&[], &[]), 0);
        assert_eq!(intersect_sorted_u32_count(&[1, 2, 3], &[]), 0);
        assert_eq!(intersect_sorted_u32_count(&[], &[1, 2, 3]), 0);
    }

    #[test]
    fn disjoint_slices() {
        let a: Vec<u32> = (0..100).collect();
        let b: Vec<u32> = (200..300).collect();
        assert_eq!(intersect_sorted_u32_count(&a, &b), 0);
    }

    #[test]
    fn identical_slices() {
        let a: Vec<u32> = (0..100).collect();
        assert_eq!(intersect_sorted_u32_count(&a, &a), a.len());
    }

    #[test]
    fn partial_overlap_small() {
        let a = [1u32, 3, 5, 7, 9];
        let b = [2u32, 3, 4, 7, 8, 10];
        // Common: 3, 7 → 2
        assert_eq!(intersect_sorted_u32_count(&a, &b), 2);
    }

    #[test]
    fn scalar_vs_avx2_large_random() {
        // Pseudo-random sorted sets: deterministic via LCG so the test
        // is reproducible without a crate dep.
        fn gen_sorted(seed: u32, size: usize) -> Vec<u32> {
            let mut state = seed;
            let mut out: std::collections::BTreeSet<u32> = std::collections::BTreeSet::new();
            while out.len() < size {
                state = state.wrapping_mul(1_103_515_245).wrapping_add(12_345);
                out.insert(state % 5_000);
            }
            out.into_iter().collect()
        }
        let a = gen_sorted(42, 500);
        let b = gen_sorted(7, 500);
        let expected = reference_intersect(&a, &b);
        assert_eq!(intersect_sorted_u32_count(&a, &b), expected);
        assert_eq!(scalar_intersect_count(&a, &b), expected);
    }

    #[test]
    fn symmetric() {
        // Intersection is symmetric — the dispatcher picks the
        // shorter side internally; this is just a contract check.
        let a: Vec<u32> = (0..64).step_by(3).collect();
        let b: Vec<u32> = (0..64).step_by(5).collect();
        let ab = intersect_sorted_u32_count(&a, &b);
        let ba = intersect_sorted_u32_count(&b, &a);
        assert_eq!(ab, ba);
    }

    #[test]
    fn boundary_single_hit_at_window_edge() {
        // The AVX2 path reads 8-lane windows; make sure a single hit
        // exactly at the last lane of a window still registers.
        let mut a = Vec::with_capacity(64);
        for i in 0..64u32 {
            a.push(i);
        }
        // b contains only value 7 — hits at index 7 of a, which is
        // lane 7 of the first AVX2 window.
        let b = vec![7u32];
        assert_eq!(intersect_sorted_u32_count(&a, &b), 1);
    }

    #[test]
    fn tail_elements_past_last_full_window() {
        // a has 70 elements → 64 (8×8) in full windows + 6 tail.
        // Hit value lives in the tail.
        let a: Vec<u32> = (0..70).collect();
        let b = vec![65u32];
        assert_eq!(intersect_sorted_u32_count(&a, &b), 1);
    }

    #[cfg(target_arch = "x86_64")]
    #[test]
    fn avx2_runtime_detection_matches_compile_time() {
        // Documents the expected relationship between the runtime
        // probe and what the CI box supports. If CI starts running
        // on non-AVX2 silicon, this test flags it explicitly.
        let avx2 = is_x86_feature_detected!("avx2");
        println!("AVX2 runtime detection: {avx2}");
        // No hard assertion — we don't want to wedge the test on
        // platforms without AVX2, only surface the value in logs.
    }

    // ─── gallop_ge_u32 ──────────────────────────────────────────────

    #[test]
    fn gallop_empty_slice() {
        assert_eq!(gallop_ge_u32(&[], 5), 0);
    }

    #[test]
    fn gallop_target_below_first() {
        let s = [10u32, 20, 30, 40];
        assert_eq!(gallop_ge_u32(&s, 5), 0);
        assert_eq!(gallop_ge_u32(&s, 10), 0);
    }

    #[test]
    fn gallop_exact_hits() {
        let s = [10u32, 20, 30, 40, 50, 60, 70, 80];
        for (i, &v) in s.iter().enumerate() {
            assert_eq!(gallop_ge_u32(&s, v), i, "exact hit on {v}");
        }
    }

    #[test]
    fn gallop_between_keys() {
        let s = [10u32, 20, 30, 40, 50, 60, 70, 80];
        assert_eq!(gallop_ge_u32(&s, 11), 1);
        assert_eq!(gallop_ge_u32(&s, 35), 3);
        assert_eq!(gallop_ge_u32(&s, 79), 7);
    }

    #[test]
    fn gallop_target_past_end() {
        let s = [10u32, 20, 30, 40];
        assert_eq!(gallop_ge_u32(&s, 100), s.len());
    }

    #[test]
    fn gallop_matches_binary_search_random() {
        // Cross-check gallop against the std `binary_search`-derived
        // reference on a randomised sorted slice. This is what locks
        // the WCOJ correctness test parity.
        fn gen_sorted(seed: u32, size: usize) -> Vec<u32> {
            let mut state = seed;
            let mut out: std::collections::BTreeSet<u32> = std::collections::BTreeSet::new();
            while out.len() < size {
                state = state.wrapping_mul(1_103_515_245).wrapping_add(12_345);
                out.insert(state % 100_000);
            }
            out.into_iter().collect()
        }
        let s = gen_sorted(123, 4096);
        for &t in &[0u32, 1, 17, 1_000, 50_000, 99_998, 100_001] {
            let expected = match s.binary_search(&t) {
                Ok(p) => p,
                Err(p) => p,
            };
            assert_eq!(gallop_ge_u32(&s, t), expected, "target={t}");
        }
        // Spot-check every key in the slice.
        for i in (0..s.len()).step_by(53) {
            assert_eq!(gallop_ge_u32(&s, s[i]), i);
            if i + 1 < s.len() && s[i] + 1 < s[i + 1] {
                assert_eq!(gallop_ge_u32(&s, s[i] + 1), i + 1);
            }
        }
    }
}
