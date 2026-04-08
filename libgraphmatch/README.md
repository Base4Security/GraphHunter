# libgraphmatch — SIMD-Accelerated Temporal Graph Pattern Matching

C++ engine for the hot path of **Graph Hunter**'s DFS-based graph pattern matching, designed for integration via FFI (C ABI → Rust).

## Architecture

```
┌─────────────────────────────────────────────────────┐
│  Rust (Graph Hunter)                                │
│  ┌───────────────────────────────────────────────┐  │
│  │  graph.rs  ──  extern "C" { gm_* bindings }  │  │
│  └───────────────────┬───────────────────────────┘  │
│                      │ FFI (C ABI)                  │
├──────────────────────┼──────────────────────────────┤
│  C++ (libgraphmatch) │                              │
│  ┌───────────────────▼───────────────────────────┐  │
│  │  graphmatch.h (C ABI)                         │  │
│  │  ┌─────────────┐  ┌──────────────┐           │  │
│  │  │ CSR Graph   │  │  Matcher     │           │  │
│  │  │  Store      │  │  (DFS+SIMD)  │           │  │
│  │  └──────┬──────┘  └──────┬───────┘           │  │
│  │         │                │                    │  │
│  │  ┌──────▼──────┐  ┌─────▼──────┐             │  │
│  │  │ SIMD        │  │ Pruning    │             │  │
│  │  │ Intersect   │  │ Engine     │             │  │
│  │  │ (AVX2)      │  │ (5 strats) │             │  │
│  │  └─────────────┘  └────────────┘             │  │
│  └───────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────┘
```

## Components

| File | Role |
|------|------|
| `types.h` | Fundamental types (NodeId, TemporalEdge, EntityType/RelType tags) |
| `simd_intersect.hpp/cpp` | AVX2/scalar sorted set intersection with runtime dispatch |
| `csr_graph.hpp` | CSR temporal multigraph with builder, finalize, temporal range queries |
| `pattern.hpp` | Pattern compiler (hypothesis → query plan with VF2++ matching order) |
| `pruning.hpp` | Five pruning strategies: rel type, entity type, causal monotonicity, time window, cycle avoidance |
| `matcher.hpp` | Iterative DFS with backtracking (port of Rust's `dfs_match_iterative`) |
| `scorer.hpp` | Endogenous anomaly scorer (5 components matching Rust's `AnomalyScorer`) |
| `result.hpp` | Match result storage and JSON serialization |
| `graphmatch.h` | C ABI — the interface Rust consumes |

## Building

```bash
# Prerequisites: CMake 3.20+, GCC 12+ or Clang 15+
cmake -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build -j$(nproc)

# Run tests
cd build && ctest --output-on-failure

# Run benchmarks
./build/bench_intersect
./build/bench_matching
```

### Compiler flags

The library compiles with `-O3 -march=native -std=c++20 -fno-exceptions -fno-rtti`.
Exceptions are disabled because C++ exceptions cannot cross the FFI boundary to Rust.
Tests re-enable exceptions for the doctest framework.

## Rust Integration

In Graph Hunter's `build.rs`:

```rust
cc::Build::new()
    .files(&[
        "libgraphmatch/src/simd_intersect.cpp",
        "libgraphmatch/src/csr_graph.cpp",
        "libgraphmatch/src/pattern.cpp",
        "libgraphmatch/src/pruning.cpp",
        "libgraphmatch/src/matcher.cpp",
        "libgraphmatch/src/scorer.cpp",
        "libgraphmatch/src/result.cpp",
        "libgraphmatch/src/graphmatch_cabi.cpp",
    ])
    .include("libgraphmatch/include")
    .cpp(true)
    .std("c++20")
    .flag("-O3")
    .flag("-fno-exceptions")
    .flag("-fno-rtti")
    .flag("-mavx2")   // or detect at build time
    .compile("graphmatch");
```

In Rust source:

```rust
extern "C" {
    fn gm_graph_new() -> *mut std::ffi::c_void;
    fn gm_graph_add_node(g: *mut c_void, id: u32, entity_type: u8);
    fn gm_graph_add_edge(g: *mut c_void, src: u32, dst: u32, rel: u8, ts: i64);
    fn gm_graph_finalize(g: *mut c_void);
    fn gm_matcher_new(g: *const c_void) -> *mut c_void;
    fn gm_matcher_add_step(m: *mut c_void, etype: u8, rel: u8, causal: i32);
    fn gm_matcher_run(m: *mut c_void, max: u32, min_score: f32) -> *mut c_void;
    fn gm_results_count(r: *const c_void) -> u32;
    fn gm_results_to_json(r: *const c_void) -> *mut std::os::raw::c_char;
    // ... etc
}
```

## SIMD Strategy

The intersection of sorted adjacency lists is the hot path (executed at every DFS step). The AVX2 implementation:

1. **Loads 8 uint32 from list A** into a YMM register
2. **Broadcasts each element from list B** to all 8 lanes
3. **Compares**: `_mm256_cmpeq_epi32` → bitmask of matches
4. **Advances pointers** based on max values

For lists < 8 elements, falls back to scalar two-pointer merge.

Runtime detection (`cpuid`) selects the best available ISA at library init.

## Pruning Strategies

Applied in order (matching Rust's DFS):

1. **Relation type** — edge must match pattern step's relation type
2. **Entity type** — target node must match expected entity type
3. **Causal monotonicity** — `timestamp >= last_timestamp`
4. **Time window** — `timestamp ∈ [window_start, window_end]`
5. **Cycle avoidance** — target not already in path (k-simplicity)

These five prunings collapse the effective branching factor to ~0.42.

## References

- Han, Zou, Yu. *Speeding Up Set Intersections in Graph Algorithms using SIMD Instructions.* SIGMOD 2018.
- Jüttner, Madarasi. *VF2++ — An improved subgraph isomorphism algorithm.* DAM, 2018.
- Semertzidis, Pitoura. *A Hybrid Approach to Temporal Pattern Matching.* 2020.

## License

Part of Graph Hunter by BASE4 Security. Internal use.
