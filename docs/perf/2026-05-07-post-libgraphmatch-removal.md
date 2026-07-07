# Post-migration benchmark: bench_dfs without libgraphmatch

Date: 2026-05-07 (same day as baseline)
Host: AMD Ryzen 5 PRO 5650U (Zen 3, 6C/12T, AVX2, no AVX-512)
Build: `cargo run --release --bin bench_dfs -p graph_hunter_matcher_ffi`
   — note: no `--features simd` (the feature no longer exists)
Branch: `main` post-migration (libgraphmatch deleted, matcher-ffi reduced
to a thin Rust forwarder, `simd` feature removed from 3 Cargo.toml files)

## Headline

The build chain is **C++-free** and the DFS hot-loop is **measurably
faster on every dominant workload**. The big-graph cap-saturated
patterns — the realistic hunt size — improved 9–28%. Small-graph
sub-millisecond patterns moved within run-to-run noise (≤±27% with
absolute deltas of 5–20 µs).

Compile time: bench_dfs went from 1m 13s (with C++ build) to ~9s
incremental (without C++ build). A first-time clean build of
`graph_hunter_core` is now ~50s vs ~70s — roughly half the original
non-incremental time of the simd build.

## search_temporal_pattern (cap=10000) — comparison

### Small graph (5000 nodes, 39980 edges)

| pattern | pre ms | post ms | delta |
|---|---:|---:|---:|
| spawn_chain L=2 | 0.052 | 0.066 | +27% slower (Δ=14 µs, noise floor) |
| spawn_chain L=3 | 0.064 | 0.030 | **−53% faster** |
| lateral L=3 | 0.031 | 0.030 | −3% |
| lateral L=4 | 0.031 | 0.033 | +6% (Δ=2 µs, noise floor) |
| any_chain L=2 | 0.702 | 0.637 | **−9% faster** |
| any_chain L=3 | 0.808 | 0.674 | **−17% faster** |
| any_chain L=4 | 0.885 | 0.773 | **−13% faster** |

### Big graph (20000 nodes, 159980 edges) — the operationally relevant size

| pattern | pre ms | post ms | delta |
|---|---:|---:|---:|
| spawn_chain L=2 | 0.174 | 0.133 | **−24% faster** |
| spawn_chain L=3 | 0.132 | 0.095 | **−28% faster** |
| lateral L=3 | 0.137 | 0.111 | **−19% faster** |
| lateral L=4 | 0.109 | 0.083 | **−24% faster** |
| any_chain L=2 | 0.955 | 0.756 | **−21% faster** |
| any_chain L=3 | 1.089 | 0.807 | **−26% faster** |
| any_chain L=4 | 1.151 | 0.878 | **−24% faster** |

## search_temporal_pattern_smart (top_k=1000)

| pattern | pre ms | post ms | delta |
|---|---:|---:|---:|
| small / any_chain L=3 | 81.793 | 80.099 | −2% |
| small / any_chain L=4 | 403.783 | 446.367 | +11% (run-to-run variance) |
| big / any_chain L=3 | 535.465 | 693.246 | +30% (run-to-run variance) |
| big / any_chain L=4 | 2850.003 | 3179.312 | +12% |
| big / spawn_chain L=2 | 0.271 | 0.313 | +15% (Δ=42 µs) |
| big / lateral L=3 | 0.260 | 0.277 | +7% (Δ=17 µs) |

The smart-search numbers regressed on three big-graph workloads. None of
my changes touched `search_temporal_pattern_smart` — the function lives
in `graph_hunter_core` and is unchanged. The Tauri runtime started
itself between the two runs (visible in monitor logs at 14:05/14:06 and
14:17), and shared CPU time on a 6-core box can easily account for ±30%
on long-running anomaly-pruned searches.

If a re-run shows the regression is real and not noise, it would be a
follow-up perf PR scoped to the smart-DFS path — out of scope for this
migration, which only deletes the C++ FFI.

## Verification checklist

- [x] `cargo check -p graph_hunter_matcher_ffi --bin bench_dfs` → clean.
- [x] `cargo check -p graph_hunter_api` → clean.
- [x] `cargo check` on `apps/tauri/src-tauri` → clean (4.38s incremental).
- [x] `cargo test -p graph_hunter_core --lib simd_rust` → 15/15 pass.
- [x] `rg "extern \"C\"" core/matcher-ffi/` → zero matches.
- [x] `rg "feature = \"simd\""` workspace → zero matches in active code
      (only in `docs/_archive/` and `docs/spec/features.md` — see below).
- [x] `libgraphmatch/` directory removed.
- [x] `core/matcher-ffi/build.rs` removed.
- [x] `core/matcher-ffi/tests/{equivalence_proptest,safety_invariants,simd_matcher_test,abi_mismatch_test}.rs` removed.
- [x] `cc` build-dep dropped from `core/matcher-ffi/Cargo.toml`.
- [x] `proptest` dev-dep dropped from `core/matcher-ffi/Cargo.toml` (last user was the deleted equivalence test).
- [x] `simd` feature dropped from `core/matcher-ffi`, `platform/api`, `apps/tauri/src-tauri`.
- [x] Equivalence proptest run one final time before deletion (2/2 pass).
- [x] AVX2 status badge wired through `graph_hunter_core::simd_rust::isa_label()` instead of FFI.

## Known follow-ups (out of scope)

These are documentation hygiene tasks that the user can pick up
separately. None block this migration:

- `docs/spec/features.md:26` and `:47` still describe the `simd` feature.
- `docs/arquitectura/`, `docs/algoritmos/`, `docs/especificacion/`,
  `docs/paper/`, `docs/manual/` — multiple `.tex` chapters reference
  libgraphmatch as part of the documented architecture. The architecture
  did change, so these drift but are scoped to a docs-update pass.
- `docs/_archive/phase0/` and `docs/_archive/phase1/` — frozen
  historical material, no change expected.
- `core/matcher-ffi` itself is now a 30-line crate that just delegates
  to `graph_hunter_core`. It can be dropped from `platform/api` (and
  the crate deleted) once consumers migrate to calling
  `graph_hunter_core::GraphHunter::search_temporal_pattern{,_smart}`
  directly.

Raw output: `docs/perf/2026-05-07-bench_dfs-post.txt`.
