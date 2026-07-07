# Ingest, Streaming & Matcher Audit — Design Spec

**Date:** 2026-05-28  
**Status:** Approved — spec and implementation plans written 2026-05-28  
**Repo baseline:** GraphHunter `code-v1.0.0` (2026-05-28 OSS release)

## Summary

This spec captures the outcome of an audit of GraphHunter’s **ingestion pipeline**, **streaming graph backend**, and **temporal pattern matcher**. It defines a three-track roadmap weighted toward hunt performance on finalized sessions, while enabling a **hybrid batch + live-tail** operating model and closing the Azure async ingest gap with operational hardening.

### Priority weights (stakeholder)

| Track | Weight | Focus |
|-------|--------|-------|
| **P — Performance** | 50% | Hunt latency and index cost across scale tiers |
| **A — Azure E2E** | 20% | Wire `SourcePoller → ParserTask → GraphWriter` in production |
| **C — Hardening** | 30% | Resilience, observability, DLQ, circuit breakers |
| **H — Hybrid substrate** | enabler | Connects P and O; required for mode **C** (batch + live) |

### Constraints

- **Scale:** All tiers matter — small (≤1M edges), medium (1–20M), large/hub-heavy (20M+).
- **Mode:** Hybrid — historical batch sessions plus live SIEM/Azure tail with graceful degradation when the graph is not fully finalized.
- **Approach:** Three parallel tracks with explicit integration points (`SessionPhase`, `GraphAccess`, `mutation_version`).

---

## Current state (audit findings)

### Code locations

There are no top-level `ingest/`, `streaming/`, or `matcher/` directories. Core logic lives under `core/graph-engine/src/`:

| Subsystem | Primary modules |
|-----------|-----------------|
| Ingest (async) | `ingest/mod.rs`, `source_poller.rs`, `parser_task.rs`, `writer.rs`, `graph_access.rs` |
| Ingest (production file) | `platform/api/src/operations/ingestion.rs`, `platform/api/src/ingestors/` |
| Streaming | `streaming.rs` (~1700 lines) — sole edge store via `InMemoryStreamingBackend` |
| Matcher | `graph.rs` (search + DFS), `planner.rs`, `nlf.rs`, `khop_reach.rs`, `lftj.rs`, `yannakakis.rs` |

### Maturity

| Path | Maturity | Production today |
|------|----------|------------------|
| File / SIEM ingest | High | `load_data_streaming`, EVTX/PCAP/Zeek/Suricata/NetFlow, DLQ, MVCC `ingested_at` |
| Azure async pipeline | Medium (components built) | **Not E2E wired** in Tauri/API; unit tests + `azure_streaming_smoke.rs` only |
| Streaming backend | High | Spill mmap, `FrozenSnapshot`, degree-adaptive storage |
| Matcher / planner | High | Multi-algorithm dispatch, extensive tests and benches |

### Key gaps

**Ingest**

- `SourcePoller`, `ParserTask`, `GraphWriter` only instantiated in unit tests.
- `ChunkEncoding::Parquet` unsupported in `ParserTask`.
- `parse_rows` fast path deferred.
- Priority preemption (`Priority::Enrichment`) tracked but FIFO only in writer.
- No circuit breaker for permanently failing sources.
- Production `GraphAccess` over session `RwLock` not wired (tests use `InMemoryGraphAccess`).

**Streaming**

- Post-`finalize` `append_edge` invalidates per-vertex sort; no tail buffer (documented in `streaming.rs:703–707`).
- `auto_spill` failure is non-fatal (`eprintln!`).
- Incremental NLF/k-hop primitives exist (`try_record_edge`, `try_record_edge_delta`) but live append path is incomplete.

**Matcher**

- `graph.rs` is monolithic (~3300+ lines).
- Planner cost model opt-in (`GRAPHHUNTER_LFTJ_AUTO=1`); calibrated on one host.
- `matcher-ffi` is a stub delegating to Rust (C++ removed).
- Hub vertices dominate finalize and DFS cost; B-tree variant was dropped for uniform slice access.

---

## Recommended approach: three parallel tracks

Alternatives considered:

1. **Performance-first (batch only)** — fast wins on finalized hunts; blocks hybrid and Azure.
2. **Pipeline-first (Azure → live)** — coherent streaming story; delays 50% perf work.
3. **Three tracks (chosen)** — parallel delivery with stable interfaces.

---

## Architecture

### SessionPhase model

Introduce **`SessionPhase`** at the API/Tauri layer (not inside the matcher core):

```
Loading → Finalizing → Ready → LiveTail
```

| Phase | Hunt behavior | Index behavior |
|-------|---------------|----------------|
| `Loading` / `Finalizing` | Reject hunt or queue with explicit user message | Do not build NLF/k-hop/snapshot |
| `Ready` | Full optimized path: `FrozenSnapshot` + NLF + k-hop + planner dispatch | Lazy build on first hunt after `sort_edges_by_timestamp()` |
| `LiveTail` | Hunt over frozen snapshot + unsorted tail; return partial coverage metadata | Incremental NLF/k-hop on append; bounded k-hop delta |

**Graceful degradation in `LiveTail`:**

- Hunts remain allowed; results include diagnostic metadata (`index_coverage`, `tail_edge_count`, `phase`).
- Temporal neighbor access: `partition_point` on sorted base slice + linear scan of per-vertex tail buffer (see `streaming.rs` constraint comments).
- `mutation_version` (existing) invalidates API-side LFTJ trie cache on graph mutation.

### Data flow (target)

```text
┌─────────────────────────────────────────────────────────────────┐
│  Ingest paths                                                    │
│  • File/SIEM (platform/api) ──► GraphHunter::insert_*           │
│  • Azure async (ingest/) ──► GraphWriter ──► GraphAccess        │
└───────────────────────────────┬─────────────────────────────────┘
                                ▼
              InMemoryStreamingBackend (append / finalize / spill)
                                │
         Loading ──finalize──► Ready (FrozenSnapshot)
                                │
                    live append ──► LiveTail (tail buffer)
                                ▼
              planner → search_temporal_pattern → HuntResult
                     (+ HuntDiagnostic when LiveTail)
```

### Integration contracts

| Contract | Owner | Consumers |
|----------|-------|-----------|
| `SessionPhase` | `platform/api` session state | Tauri UI, hunt handlers, MCP |
| `GraphAccess` | `ingest/graph_access.rs` | `GraphWriter`, Tauri session lock |
| `mutation_version` | `GraphHunter` / streaming | API LFTJ cache, future incremental indexes |
| `HuntDiagnostic` | `graph.rs` / hunt result types | UI banner, MCP hunt tools |

---

## Track P — Performance (50%)

### Goals by scale tier

| Tier | Edge count | Primary bottlenecks | Targets (Ready phase) |
|------|------------|---------------------|------------------------|
| **S** | ≤1M | Planner overhead, unnecessary index rebuild | p95 hunt < 2s (3-step hypothesis) |
| **M** | 1–20M | Finalize O(Σ d log d), index memory | p95 hunt < 30s; finalize < 60s |
| **L** | 20M+ / hubs | DFS per-frame hub scan, mmap cold start | No regression >10% vs `hunt_latency` bench; hub spray stable |

### Deliverables

1. **Tiered benchmarks in CI**
   - Extend `core/graph-engine/benches/hunt_latency.rs` with tiers S/M/L and hub-synthetic graph.
   - Gate: alert on >10% regression (already documented intent in bench header).
   - Add complementary runs: `matching_powerlaw`, `matching_hops` for hub shape.

2. **Planner cost-aware default**
   - Calibrate `CostHints` / `cost_estimate` on at least three environments (Windows desktop 16GB, Linux CI, 32GB).
   - Promote `plan_with_hints_lazy` to default when calibration variance is acceptable.
   - Keep env-flag escape hatch for one release cycle.

3. **Hub-aware finalize**
   - Parallelize `streaming.finalize()` for vertices with degree > threshold (rayon over outer table).
   - Measure on tier M/L before enabling by default.

4. **Prune passes — validated defaults**
   - Run regression suite for `GRAPHHUNTER_SEMIJOIN=1` and `GRAPHHUNTER_AMAC=1`.
   - Enable by default only after zero correctness failures in `graph_pattern`, `path_dedup`, `k4_lftj_dispatch` tests.

5. **Spatial optimizations (tier L)**
   - Document and tune `GRAPHHUNTER_INDEX_HEAP_BUDGET` defaults per tier.
   - Ensure spill + optional `GRAPHHUNTER_HUGEPAGES=1` path is tested on Windows.
   - Pilot hub range index only if bench proves win (do not reintroduce global B-tree).

6. **Cleanup**
   - Remove or deprecate `core/matcher-ffi` stub after API confirms no external consumers.
   - Update stale doc references (`docs/_archive/architecture-en/chapters/ch10-matcher.tex` libgraphmatch mention) in a docs-only follow-up.

### Out of scope (Track P)

- Splitting `graph.rs` (maintenance task, not perf blocker).
- WCOJ production path (LFTJ + Yannakakis cover current dispatch).
- Per-shard writers (wait for writer CPU metrics).

---

## Track H — Hybrid substrate

### Tail buffer

Add per-vertex **tail buffer** in `streaming.rs`:

- After global `finalize()`, new edges via `append_edge` append to `TailBuffer` (e.g. `SmallVec`) instead of mutating sorted base lists.
- Read path `neighbors_for_hunt(src, time_window)` merges sorted base + filtered tail.
- Property tests: merge correctness vs full re-sort on synthetic streams.

### Incremental indexes

Wire existing L3 primitives on live append:

- `NlfTable::try_record_edge` — already tested in `nlf.rs` (`add_relation_after_nlf_built_keeps_nlf_live_via_incremental_update`).
- `KHopReach::try_record_edge_delta` — already tested in `khop_reach.rs`.
- On mmap-spilled NLF/k-hop backing: invalidate and lazy rebuild (existing `false` return path).

### Snapshot invalidation policy

- Do not drop `streaming_snapshot` on every append.
- Bump `mutation_version`; re-freeze lazily (every N appends or on first hunt after batch).
- Avoid calling full `sort_edges_by_timestamp()` on each live batch — only on Loading→Ready transition.

### API surface

- `session.phase(): SessionPhase`
- `session.live_tail_stats(): { tail_edges, last_append_at }`
- Extend hunt response with optional `HuntDiagnostic { phase, index_coverage, tail_edge_count }`

---

## Track O — Azure E2E (20%) + Hardening (30%)

### Azure pipeline wiring

1. Implement **`GraphAccess` for `RwLock<GraphHunter>`** in Tauri (`apps/tauri` or `platform/api` session module).
2. Spawn pipeline from Tauri command:
   - `SourcePoller` per configured source → `raw_tx`
   - `ParserTask` per source → `parsed_tx`
   - Single shared `GraphWriter` → `GraphAccess`
3. Integrate existing infrastructure:
   - `WatermarkStore`, `IngestCancelTree`, `WriterMetrics`
   - Transition session to `LiveTail` on successful writer start
4. **Parser gaps:**
   - Parquet decoding in `ParserTask`
   - `parse_rows` fast path through `RawChunk`
5. **Integration test:** mock `LogSource` → full pipeline → assert edge count in graph (no live Azure required).

### Hardening checklist

| Item | Location | Action |
|------|----------|--------|
| Circuit breaker | `source_poller.rs` | After N consecutive failures, exponential backoff + surface status to UI/MCP |
| Spill errors | `streaming.rs` `auto_spill` | Propagate error to writer; increment metric; UI warning |
| Writer saturation | `ingest/writer.rs` metrics | Export `WriterMetrics` to observability panel; document shard plan if CPU >80% |
| DLQ completeness | parsers | Complete `LogParser::try_parse` migration (10/13 remaining per CHANGELOG) |
| Overflow replay | `ingest/overflow.rs` | CI integration test for shutdown spill + idempotent replay |
| Priority preemption | `ingest/writer.rs` | Defer until metrics show enrichment starvation |

### Observability (unified panel)

Expose in Tauri perf view and/or MCP:

- Channel depths (`raw_tx`, `parsed_tx`)
- Poller/parser/writer latencies and error counts
- Spill rounds, mmap bytes, `mutation_version`
- `SessionPhase` and tail stats

---

## Phased delivery

```text
Sprint 1:  P0 (tier benches + planner calibration start) + O0 (circuit breaker, spill errors)
Sprint 2:  P1 (hub parallel finalize, semijoin/AMAC gates) + H0 (SessionPhase + hunt gating)
Sprint 3:  H1 (tail buffer + HuntDiagnostic + incremental index wiring)
Sprint 4:  O1 (Azure pipeline E2E + Parquet + integration test)
Sprint 5:  Integration — LiveTail hunts under load; planner auto default; observability panel
```

### Success criteria (acceptance)

| Tier | Ready hunt p95 | LiveTail hunt p95 | Ingest |
|------|----------------|-------------------|--------|
| S ≤1M | < 2s (3-step) | < 3s if tail < 10k edges | — |
| M 1–20M | < 30s | Partial coverage flag if tail > 5% of edges | Mock Azure E2E passes |
| L 20M+ | No >10% bench regression | Tail merge property tests pass | Writer CPU < 80% or shard plan documented |

---

## Testing strategy

| Layer | Tests |
|-------|-------|
| Unit | Extend `streaming.rs` tail merge tests; circuit breaker in `source_poller.rs`; `GraphAccess` impl |
| Integration | `mvcc_ingested_at`-style test for pipeline E2E; LiveTail hunt diagnostic |
| Bench / CI | `hunt_latency` tiers; regression gate >10%; optional weekly full tier L job |
| Property | Tail + sorted base equivalence vs full sort on random append streams |

---

## Risks and mitigations

| Risk | Mitigation |
|------|------------|
| Planner auto picks wrong plan on dissimilar hardware | Multi-host calibration + env escape hatch |
| Tail buffer merge bugs | Property tests; conservative `Partial` diagnostic |
| Single writer bottleneck at Azure scale | Metrics first; shard design documented, not built until proven |
| Live hunt correctness with stale snapshot | `mutation_version` + diagnostic; document non-atomic tail visibility |

---

## References

- `core/graph-engine/src/ingest/mod.rs` — pipeline topology and backpressure design
- `core/graph-engine/src/streaming.rs` — stage 1/2 streaming backend, tail buffer constraint
- `core/graph-engine/src/planner.rs` — cost-aware dispatch (`GRAPHHUNTER_LFTJ_AUTO`)
- `core/graph-engine/benches/hunt_latency.rs` — baseline hunt benchmark
- `CHANGELOG.md` — v1.0.0 ingest backlog (try_parse migration, sidecar)

---

## Next step

Implementation plans (2026-05-28):

- [Track P — Performance](../plans/2026-05-28-track-p-performance.md)
- [Track H — Hybrid substrate](../plans/2026-05-28-track-h-hybrid-substrate.md)
- [Track O — Azure E2E + hardening](../plans/2026-05-28-track-o-azure-hardening.md)

Recommended sprint order: **Sprint 1** = Track P Task 1–3 + Track O Task 1–2 in parallel; **Sprint 2** = Track P Task 4–5 + Track H Task 1–2; etc.
