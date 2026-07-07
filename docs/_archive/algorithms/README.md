# `docs/algorithms/` — algorithm reference for the core engine

This directory contains algorithm-level documentation for the three
numerical / graph routines that drive hunt detection in GraphHunter.
These docs exist to answer the question a future maintainer will ask
when they open an unfamiliar `.rs` file: *why is the code shaped
this way, and is it right?*

They are **specifications**, not code-walkthroughs. The code is the
code — these docs explain the math, cite the references, and state
invariants. Line numbers and function names drift; math and invariants
don't.

## Contents

| File | Algorithm | Implemented in |
|---|---|---|
| [`dfs_temporal.md`](dfs_temporal.md) | Depth-first search with causal (timestamp-monotone) constraint | `core/graph-engine/src/graph.rs :: search_temporal_pattern`, `naive_dfs_recurse` |
| [`anomaly_scoring.md`](anomaly_scoring.md) | Five-component path anomaly score with weighted composite | `core/graph-engine/src/anomaly.rs :: AnomalyScorer::score_path` |
| [`simd_set_intersection.md`](simd_set_intersection.md) | SIMD-accelerated sorted-set intersection (AVX2 / SSE4.2 / NEON) | `libgraphmatch/src/simd_intersect.cpp` via `core/matcher-ffi` |

## How to use these docs

- **Before touching the code**: read the relevant doc. Every spec lists
  the invariants the implementation must satisfy; the property tests
  (`core/graph-engine/tests/anomaly_proptest.rs`,
  `core/matcher-ffi/tests/equivalence_proptest.rs`,
  `platform/dsl/tests/roundtrip.rs`) encode a subset of those.
- **When benchmarks regress**: the complexity analysis in each doc
  gives the expected asymptotics. A regression below the expected
  curve is a real bug; a flat shift is usually a constant-factor
  issue (cache, allocator, codegen).
- **When extending**: adding a new scoring component or a new SIMD
  ISA requires updating the corresponding doc *first*. If the spec
  can't accommodate the change cleanly, the design is wrong.
