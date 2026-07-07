# SIMD-accelerated sorted set intersection

**Implemented in:** `libgraphmatch/src/simd_intersect.cpp` — scalar, AVX2, and runtime-dispatched variants. Called from the DFS-style matcher in `libgraphmatch/src/matcher.cpp` during edge-list intersection.

## Problem statement

Given two sorted `uint32_t` arrays `A` (length `m`) and `B` (length `n`),
compute either:
- **`intersect(A, B, out)`** — write the sorted intersection `A ∩ B` to
  `out` and return the cardinality.
- **`intersect_count(A, B)`** — return `|A ∩ B|` without materializing
  the output (used when the matcher only needs the count for pruning).

Both inputs are assumed strictly ascending with no duplicates. Output
of `intersect` preserves that invariant.

A temporal variant `intersect_temporal(A_nodes, A_times, B_nodes, B_times, t_lo, t_hi, out_nodes, out_times)` additionally filters pairs where the associated edge timestamp falls outside `[t_lo, t_hi]`. Used for the hypothesis time-window pruning.

## Algorithm

Runtime CPU feature detection (`cpuid` on x86, compile-time on ARM)
selects one of:

| ISA | Variant | Lane width | Intrinsic family |
|---|---|---|---|
| AVX-512 | scalar fallback for now | — | (not yet emitted) |
| AVX2 | `intersect_avx2` | 8 × `uint32_t` | `_mm256_cmpeq_epi32`, `_mm256_movemask_epi8` |
| SSE4.2 | scalar fallback | — | — |
| NEON | scalar fallback | — | — |
| Otherwise | `intersect_scalar` | 1 | — |

### Scalar variant

Classical two-pointer merge: compare `a[i]` with `b[j]`, advance the
smaller, emit on equality. `O(m + n)` time, zero SIMD dependencies.

### AVX2 variant (Schlegel-Gubichev-Neumann, 2011)

Let `V = 8` (AVX2 vector lane count).

```
while ia + V ≤ m and ib < n:
    va = load_8x32(a + ia)           # load 8 elements from A
    max_a = va[7]                    # end of A's current block
    while ib < n and b[ib] ≤ max_a:
        vb = broadcast(b[ib])        # replicate b[ib] into 8 lanes
        cmp = va == vb               # lane-wise equality
        mask = movemask(cmp)
        if mask != 0:
            emit(b[ib])              # at most one lane can match
        ib += 1
    ia += 8
# scalar tail for ia ≥ m - 7
```

The inner loop broadcasts a single element of `B` across 8 lanes and
compares it against 8 elements of `A` in one cycle. Because both
arrays are strictly ascending, at most one lane can match per
broadcast — we can emit the matched value without extracting which
lane hit (the comparison is really "is `b[ib]` in `{a[ia], …, a[ia+7]}`?").

### Dispatch

`g_isa` is a static `SimdIsa` set exactly once by `detect_isa()` on
first call. Public entry points (`intersect`, `intersect_count`, the
sorted + temporal wrappers) branch on `g_isa` and call the specialized
variant. Branch prediction eliminates the dispatch cost after the
first few invocations.

## Invariants

1. **Input sorted + unique.** Violating this causes silent duplicates
   in the output; the matcher's adjacency-list builder guarantees the
   property upstream.
2. **Output capacity.** `out` must have room for `min(m, n)` elements.
3. **No bounds violation from SIMD overread.** The AVX2 loop processes
   only full vectors; the tail (fewer than 8 elements) falls back to
   scalar. No page-fault surface from unaligned `loadu` past the
   array.
4. **Thread-safety.** `g_isa` is initialized once via an atomic flag;
   the specialized variants are pure functions on their inputs. Safe
   to call concurrently from multiple matcher threads.
5. **Rust-C ABI stability.** `gm_abi_version()` (see ADR-002 / F3.5)
   gates the Rust caller against loading a libgraphmatch whose
   dispatch table layout has drifted.

## Complexity

Let `m, n` be the input sizes, `k = |A ∩ B|` the output size.

- **Scalar:** `O(m + n)` time, `O(1)` extra memory.
- **AVX2:** still `O(m + n)` asymptotically; constant factor drops by
  ~3–4× on uniform-density inputs and by ~6–8× when `A` is sparse
  relative to `B` (longer run of broadcasts per outer iteration).
- **Worst case for AVX2** is when every `b[ib]` is less than the next
  `max_a`, making the inner loop run the full length of `B` for each
  outer step — falls back toward `O(m · n)`. The matcher avoids this
  by invoking intersection only on edge lists of comparable size (the
  caller picks the smaller list for the outer loop).

## Equivalence with the DFS matcher

The F3.6 property test (`core/matcher-ffi/tests/equivalence_proptest.rs`)
does not test set intersection in isolation; it tests the whole
SIMD-vs-DFS result-set equality. A bug in `intersect_avx2` would
surface there as a missing path.

For a direct test of intersection primitives, see
`libgraphmatch/tests/simd_intersect_test.cpp` (if present) — the unit
tests cross-check AVX2 against scalar on randomized inputs.

## References

- Schlegel, Gubichev, Neumann. "Fast Sorted-Set Intersection using
  SIMD Instructions." *ADMS* 2011 — the broadcast-compare-movemask
  approach used by `intersect_avx2`.
- Lemire, Kurz, Rupp. "Fast random integer generation in an interval."
  *ACM TOMS* 2019 — background on `movemask` bit-manipulation for
  emit decisions.
- Intel 64 and IA-32 Architectures Software Developer's Manual, Vol.
  2B — intrinsic semantics (`_mm256_cmpeq_epi32`,
  `_mm256_movemask_epi8`).
