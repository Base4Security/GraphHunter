# core/ — algorithmic núcleo

Graph algorithms, SIMD matcher, GNN bridge, anomaly/scoring. The hot
code path. Optimized for performance and numerical correctness; stable
API surface; minimal churn.

**Invariants**: no network, no disk (except explicit spill/store), no
LLM. Every change here runs the `hunt_latency` / `dedup_throughput`
benchmarks (regression > 5 % → revert).

Crates that land here during Fase 2 migration: `graph-engine`,
`ffi/libgraphmatch`, `gnn`. See `docs/architecture/phase1/MIGRATION_PLAN.md`.
