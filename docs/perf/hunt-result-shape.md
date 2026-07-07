# HuntResult shape — performance investigation (2026-04-29)

## TL;DR

On `ba-any-2hop V=10000` (cap-saturated 10K results), **string allocation
in the DFS hot loop accounts for ~55% of total bench time**. Removing
that cost requires changing `pub type HuntResult = Vec<String>` because
the inline allocation pattern and the deferred two-pass alternative
both pay the per-result `String::from` × `path.len()` price.

Quantified by patching `dfs_match_iterative` to push `Vec::new()`
instead of materializing strings (everything else identical):

| Bench (matching_powerlaw) | inline strings | empty push  | Δ      |
| ------------------------- | -------------- | ----------- | ------ |
| ba-typed-2hop V=1000      | 86 µs          | 75 µs       | −13%   |
| ba-typed-2hop V=10000     | 165 µs         | 196 µs      | +19% n |
| ba-any-2hop  V=1000       | 2.24 ms        | 854 µs      | **−62%** |
| ba-any-2hop  V=10000      | 2.38 ms        | 1.06 ms     | **−55%** |

(`n` = inside noise band on this machine.)

The `any` patterns saturate the 10K cap — every emission allocates ~3
strings + 1 Vec. With `mimalloc` (~65 ns / small alloc), 10K results ×
4 allocations ≈ 2.6 ms — matches the 2.4 ms total bench time.

## Why "deferred materialization" failed

The natural fix is to push `SmallVec<[StrId; 8]>` inside the DFS, then
materialize `Vec<String>` once at the end (parallelized via rayon).
Tried this — **regressed +48%** on `ba-any-2hop V=10000`.

Two compounding reasons:

1. **`Vec<DfsPath>` element size**: each `SmallVec<[StrId; 8]>` is
   40 bytes (max of 8×u32 inline + 8 byte len, vs. 16 byte ptr/cap +
   8 byte len). 10K elements = 400 KB intermediate buffer, busts L2
   (256 KB on the Galaxy Book4 E-cores).
2. **Two-pass cache miss**: the DFS phase produces results, the
   materialization phase reads them back. The inline version produces
   each result and immediately drops it (the writer thread keeps it in
   L1 until rayon's collect drains).

A flat `Vec<StrId>` with `chunks_exact(depth+1)` slicing would shrink
the intermediate to ~120 KB (10K × 3 × 4 bytes), but the per-result
String allocations still dominate downstream — total time would still
beat the inline by ~30% at best, and only at the cost of a worker-fold
+ concat structure that complicates the parallel branch. Not worth
shipping in isolation.

## What would actually move the needle

The win requires HuntResult itself to stop being `Vec<String>`.
Candidates considered:

- **`Vec<StrId>`**: zero-allocation in the hot path, downstream
  consumers use the interner to resolve. Cleanest internally; biggest
  blast radius (FFI, MCP, REST DTOs, Tauri TS bindings — 35 files
  reference HuntResult today).
- **`Vec<Arc<str>>` with the interner returning `Arc<str>`**: zero-copy
  clone via refcount bump. Smaller blast radius (HuntResult shape stays
  Vec-of-something) but requires an interner refactor.
- **Lazy: `HuntResult` becomes a struct that holds `Vec<StrId>` and
  resolves to `Vec<String>` on demand**: API-compatible at the call
  site that does `result[i]`, but breaks `Vec<String>`-shaped
  serialization in the FFI/REST/MCP/TS layers. Probably worst of
  both worlds.

## Recommendation

Spin this out as a multi-PR initiative under its own plan:

1. Refactor the StringInterner to back-store `Arc<str>` (or equivalent
   refcounted handle).
2. Change `HuntResult` to `Vec<Arc<str>>`. Audit the 35 call sites;
   most are `result.iter().map(|s| s.as_str())` shaped, so the
   migration is mechanical.
3. Update FFI surface — the C ABI currently expects `*mut *mut c_char`,
   and the Tauri command layer serializes via serde — both need
   small adapter changes.
4. Bench delta should land at the no-string-allocation level (≈55%
   on cap-saturated `any` patterns).

Estimated effort: 2–3 PRs, ~1 week. The Black Hat 2026 hop-bench
target (sub-10 ms @ 100K) absolutely needs this — at the projected
scale (100K starts × cap=10K results), string allocation is the
limit.

## Reproducer

```bash
# Patch (delete `path.iter().map().collect()` body, push Vec::new() instead)
# in dfs_match_iterative's `step_idx >= steps.len()` branch.

cd C:/Users/lsotomayor/GraphHunter
cargo bench --manifest-path core/graph-engine/Cargo.toml \
  --bench matching_powerlaw -- --warm-up-time 1 --measurement-time 3
```

Compare against the post-C0 baseline saved as `c0_pre`.
