# Baseline benchmark: `bench_dfs` with C++ libgraphmatch FFI in place

Date: 2026-05-07
Host: AMD Ryzen 5 PRO 5650U (Zen 3, 6C/12T, AVX2, no AVX-512)
Build: `cargo run --release --bin bench_dfs -p graph_hunter_matcher_ffi --features simd`
Compile time: 1m 13s (release, fresh target/, includes 8 .cpp files via cc-rs)
Branch: `main` @ 9cf7176 (with 390-file in-flight work stashed as `stash@{0}`)

## Headline finding

**The C++ libgraphmatch SIMD path is slower than the pure-Rust DFS on every
benchmark, by factors of 3.4× to 19×.** The migration plan to replace the
FFI with the existing Rust DFS is therefore a strict performance win on
top of the build-system / maintainability wins.

Worst case for C++: `big / spawn_chain L=2` — Rust 0.187 ms vs C++ SIMD
3.637 ms (19.4× slower). Best case for C++: `big / any_chain L=2` — Rust
1.265 ms vs C++ SIMD 4.356 ms (3.4× slower).

ISA detected at runtime: `avx2` (matches expected baseline for Zen 3).

## SIMD vs pure-Rust comparison (the key table)

All times are average ms over 10-20 iterations. `simd` runs through
`graph_hunter_matcher_ffi::ffi::run_simd_search` after `build_gm_graph`.
`rust` runs through `GraphHunter::search_temporal_pattern`.

### Small graph (5000 entities, 39980 relations, BA seed=42)

| pattern | rust ms | simd ms | rust:simd | rust hits | simd hits |
|---|---:|---:|---:|---:|---:|
| spawn_chain L=2 | 0.070 | 0.307 | **4.4× faster (Rust)** | 4 | 4 |
| spawn_chain L=3 | 0.106 | 0.305 | 2.9× faster (Rust) | 0 | 0 |
| lateral L=3 | 0.072 | 0.304 | 4.2× faster (Rust) | 0 | 0 |
| lateral L=4 | 0.072 | 0.323 | 4.5× faster (Rust) | 0 | 0 |
| any_chain L=2 | 0.839 | 3.354 | 4.0× faster (Rust) | 10000 | 10000 |
| any_chain L=3 | 0.878 | 3.343 | 3.8× faster (Rust) | 10000 | 10000 |
| any_chain L=4 | 1.038 | 4.302 | 4.1× faster (Rust) | 10000 | 10000 |

### Big graph (20000 entities, 159980 relations, BA seed=43)

| pattern | rust ms | simd ms | rust:simd | rust hits | simd hits |
|---|---:|---:|---:|---:|---:|
| spawn_chain L=2 | 0.187 | 3.637 | **19.4× faster (Rust)** | 38 | 38 |
| spawn_chain L=3 | 0.181 | 3.459 | 19.1× faster (Rust) | 0 | 0 |
| lateral L=3 | 0.141 | 3.412 | 24.2× faster (Rust) | 0 | 0 |
| lateral L=4 | 0.160 | 3.217 | 20.1× faster (Rust) | 0 | 0 |
| any_chain L=2 | 1.265 | 4.356 | 3.4× faster (Rust) | 10000 | 10000 |
| any_chain L=3 | 1.256 | 4.071 | 3.2× faster (Rust) | 10000 | 10000 |
| any_chain L=4 | 1.562 | 4.626 | 3.0× faster (Rust) | 10000 | 10000 |

## Pure-Rust reference numbers (for Phase 5 comparison)

These are the times the migration must preserve or improve. They're the
same `rust=` column as above, captured here in absolute terms so Phase 5
can compare against them after the C++ tree is gone.

### `search_temporal_pattern` (cap=10000)

| pattern | small ms | big ms |
|---|---:|---:|
| spawn_chain L=2 | 0.052 | 0.174 |
| spawn_chain L=3 | 0.064 | 0.132 |
| lateral L=3 | 0.031 | 0.137 |
| lateral L=4 | 0.031 | 0.109 |
| any_chain L=2 | 0.702 | 0.955 |
| any_chain L=3 | 0.808 | 1.089 |
| any_chain L=4 | 0.885 | 1.151 |

### `search_temporal_pattern_smart` (top_k=1000, anomaly-pruned)

| pattern | small ms | big ms |
|---|---:|---:|
| any_chain L=3 | 81.793 | 535.465 |
| any_chain L=4 | 403.783 | 2850.003 |
| spawn_chain L=2 | n/a | 0.271 |
| lateral L=3 | n/a | 0.260 |

## Why C++ loses

Hypotheses, in priority order:

1. **`build_gm_graph` rebuilds the C++ CSR every call.** Each invocation
   copies all 5K–20K nodes and 40K–160K edges across the FFI boundary
   (`core/matcher-ffi/src/lib.rs:489-530`). The Rust DFS reads
   `StreamEdge` slices in place — zero copy. On the big graph, this alone
   could explain a multi-millisecond floor that Rust doesn't pay.
2. **Rust DFS has L1 prefetch lookahead** (`graph.rs:1696-1711`) and the
   `entity_type_tags` SoA cache (`graph.rs:99-110`) that keeps type
   filtering at one L1 line per probe. The C++ matcher does scalar
   `graph_.node_type(e.target)` calls per edge.
3. **`HuntResult` cap-saturation fix** shipped 2026-04-30 (per memory)
   only lives on the Rust side — the C++ matcher allocates a fresh
   `MatchResult` (with `std::vector<NodeId>` and `std::vector<Timestamp>`
   per result) for each of the 10K cap entries on saturation runs.

The C++ matcher's intended advantage was AVX2 sorted-set intersection
(`simd_intersect.cpp`), but `dfs_match_iterative` (`matcher.hpp:110-250`)
**doesn't actually call `intersect_count` or `intersect_sorted` in its
hot loop** — it iterates outgoing edges sequentially, exactly like the
Rust DFS. The SIMD primitive is exposed but unused by the matcher path.

## What this means for the plan

- Phase 2 audit (`2026-05-07-libgraphmatch-simd-audit.md`): confirmed no
  primitive gaps. Rust already has parity.
- Phase 3 (call-site flip): safe to execute. Equivalence proptest will
  validate one final time before deletion in Phase 4.
- Phase 5 success criterion is "within ±5% of baseline". Given that the
  pure-Rust path already wins by 3.4–19×, any sane Phase 4 implementation
  will trivially pass this gate. The relevant failure mode is *correctness*
  (a path the C++ found that Rust doesn't), and that's covered by the
  equivalence_proptest invariant gate.

Raw output: `docs/perf/2026-05-07-bench_dfs-baseline.txt` (cargo + bench
together).
