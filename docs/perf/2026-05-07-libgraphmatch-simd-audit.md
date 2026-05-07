# libgraphmatch SIMD primitive audit (Phase 2 of removal migration)

Date: 2026-05-07
Migration plan: `~/.claude/plans/misty-pondering-piglet.md`

## Goal

Before deleting `libgraphmatch/`, confirm that `core/graph-engine/src/simd_rust.rs` exposes parity for every SIMD primitive the C++ side ships, so the Rust-DFS-canonical path doesn't lose any capability the C++ matcher had.

## Method

1. `rg "_mm256_|_mm512_|__m256i|__m512i" libgraphmatch/` — find every file with x86 vector intrinsics.
2. For each hit, list the public functions that wrap the intrinsics.
3. Cross-reference each public function against `simd_rust.rs`.

## Files containing AVX2 intrinsics

```
libgraphmatch/src/simd_intersect.cpp    — SIMD primitives (the only file)
libgraphmatch/README.md                 — documentation (not code)
```

`pruning.cpp`, `csr_graph.cpp`, `pattern.cpp`, `scorer.cpp`, `result.cpp`,
`graphmatch_cabi.cpp`, `matcher.cpp` (stub) and `matcher.hpp` (the actual
DFS hot loop) contain **zero** `_mm256_*` calls. The C++ DFS is scalar
control flow with type/relation pruning, identical in shape to Rust's
`dfs_match_smart` in `core/graph-engine/src/graph.rs:1597`.

## Public SIMD surface in `simd_intersect.cpp`

| C++ symbol | Algorithm | Rust counterpart | Status |
|---|---|---|---|
| `gm::simd::intersect_count` | AVX2 broadcast-and-scan, scalar tail | `simd_rust::intersect_sorted_u32_count` | ✓ covered |
| `gm::simd::intersect_sorted` | Same algo, writes results to `out[]` | `simd_rust::intersect_sorted_u32_collect` | ✓ covered |
| `gm::simd::intersect_temporal` | Binary-search time window → sort+dedup → intersect | (not needed) | n/a |
| `gm::simd::detect_best_isa` / `active_isa` | Runtime CPU feature detection | `is_x86_feature_detected!("avx2")` | ✓ covered (idiomatic Rust) |
| Shuffle LUT (g_shuffle_lut, 8KB at L1) | Future use for compress-store | not used by `intersect_count`/`intersect_sorted` | n/a |

### `intersect_temporal` — why "not needed"

The C++ helper combines three steps:
1. Binary-search a `TemporalEdge[]` (sorted by timestamp) for `[t_min, t_max]`.
2. Extract `target` ids from the time-windowed slice; sort + dedup.
3. Call `intersect_sorted` against a candidate id set.

The Rust DFS doesn't need this composite primitive because time-window
enforcement happens at two different layers:

- **Inside the DFS** (`graph.rs:1685-1762`): each iterated `StreamEdge`
  is filtered by `relation_type_tag`, `dest_type` (via `entity_type_tags`
  SoA), and metadata predicates. Causal monotonicity + per-edge timestamp
  bounds are checked inline.
- **After the search** (`search_temporal_pattern`): the absolute time
  window is applied as a final filter on returned `HuntResult` paths.

Combining "find time-window slice" and "intersect with id set" into one
primitive is a pattern the C++ matcher exposed but doesn't actually use
in `dfs_match_iterative` (`matcher.hpp:110-250`). It's also not used by
the Rust LFTJ path (`lftj.rs:345-365`), which uses
`intersect_sorted_u32_count` directly on already-sorted CSR trie slices.

If a future LFTJ-style temporal join becomes hot, we can revisit. Until
then, no Rust port is needed.

## Conclusion

**No new primitives required for Phase 4 (deletion).** `simd_rust.rs` is
already a superset of `simd_intersect.cpp`'s public API:

```
intersect_sorted_u32_count   ← matches gm::simd::intersect_count
intersect_sorted_u32_collect ← matches gm::simd::intersect_sorted
gallop_ge_u32                ← bonus (no C++ counterpart, used by LFTJ)
```

All three have parity tests in the same module. AVX2 dispatch goes
through `is_x86_feature_detected!("avx2")` — same runtime probe as the
C++ `detect_best_isa` minus the SSE4.2/NEON/AVX-512 branches we
intentionally don't ship per the user's ISA-scope decision (AVX2-only).

Phase 4 deletion can proceed without any prerequisite primitive work.
