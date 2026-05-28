# Ingest / Streaming / Matcher Audit — Remediation & Hardening Design Spec

**Date:** 2026-05-28
**Status:** Draft — pending user review
**Repo baseline:** GraphHunter `feat/sprint1-ingest-audit` @ `541848f` (6 sprint commits on top of `code-v1.0.0`)
**Companion:** [Cursor's roadmap spec](2026-05-28-ingest-streaming-matcher-audit-design.md) (tracks P / H / O). This document is the **independent audit of that work** plus a remediation plan.

## Summary

An independent audit reviewed the six commits Cursor landed on `feat/sprint1-ingest-audit`
(`c4d6210..HEAD`) — Sprint 1 (tier benches + ingest hardening), Sprint 2 (`SessionPhase`
gating + perf defaults), and the partial Sprint 3 (live-tail buffer + coverage metadata) —
and took a fresh look at the ingest, streaming, and matcher engines for temporal and spatial
optimization opportunities.

The audit ran as four parallel subsystem reviews (streaming backend, async ingest pipeline,
API/session state machine, matcher/planner). The single most severe finding — a same-thread
`RwLock` self-deadlock on every file ingest — was **verified line-by-line and fixed in this
session** (see [Already fixed](#already-fixed-this-session)). The remaining findings are
organized below into a remediation roadmap covering correctness, hardening, and performance.

### Verdict

Cursor's plumbing-level work is largely sound and well-tested (spill-error propagation,
tail-merge math, 409 mapping, semijoin/AMAC default flip, watermark ordering, real Criterion
baselines). The problems are at the **integration seams**: a helper called under a held write
lock, incremental indexes that read base-only neighbors and miss the tail, a wall-clock
circuit breaker, an unbounded tail buffer, and several headline deliverables (cost-aware
planner default, Azure pipeline wiring, lazy snapshot refresh) specced but not yet wired.

## Method

| Subsystem | Files reviewed | Technique |
|-----------|----------------|-----------|
| Streaming backend | `streaming.rs`, `graph.rs` (finalize/freeze/snapshot) | static read + `git diff c4d6210..HEAD` |
| Async ingest pipeline | `ingest/source_poller.rs`, `writer.rs`, `parser_task.rs`, `graph_access.rs`, `overflow.rs` | static + diff |
| API / session phase | `state/session.rs`, `session_types.rs`, `operations/{hunt,ingestion,ai}.rs`, `error.rs`, `dto/v1/hunt.rs`, Tauri `dsl.rs`/`http/hunt.rs`/`types.ts` | static + diff |
| Matcher / planner | `planner.rs`, `nlf.rs`, `khop_reach.rs`, `graph.rs` (DFS hot path), `benches/` | static + diff |

Static-only by design (no `cargo test`/`bench` — long compiles stall the watchdog). The P0
deadlock was confirmed by reading the exact guard scopes; the k-hop tail-staleness bug was
independently surfaced by two of the four reviews.

## Findings register

Severity: **P0** correctness / data-loss · **P1** important · **P2** worthwhile · **P3** nice-to-have.
Status: **VERIFIED** (confirmed by manual read) · **CORROBORATED** (found by ≥2 reviews) · **STATIC** (single review, unverified).

### Correctness bugs

| # | Sev | Status | Location | Problem |
|---|-----|--------|----------|---------|
| C1 | P0 | VERIFIED · **FIXED** | `operations/ingestion.rs:428,633,734,1430` | `note_post_finalize_appends` called while `session.graph.write()` held; helper re-locks `graph.read()` (`session.rs:384`) → same-thread RwLock deadlock (Windows SRWLOCK). Hangs every file ingest with ≥1 relation. |
| C2 | P0 (latent) | CORROBORATED | `graph.rs:444-465`, `khop_reach.rs:356` | Incremental k-hop delta reads base-only neighbors (`streaming.with_neighbors`, `streaming.rs:649`) and ignores post-finalize tail edges → wrong LiveTail hunt results. Currently masked because the prune is gated on `edges_sorted`, which every append clears, so the incremental path is never actually exercised. |
| C3 | P0 (under spill) | VERIFIED | `graph.rs:2997-2998`, `writer.rs:187-198` | Two defects on mid-batch `GraphError::Spill`: **(a)** `reverse_adj…push` (2997) runs *before* `push_to_streaming?` (2998), so the one failing triple leaves a reverse edge with no forward edge (+ orphan `meta_store` entry, `new_relations` uncounted) — corrupts the **live sync ingest** graph today; **(b)** the async `GraphWriter` `Err` arm only bumps a metric and `return`s (writer.rs:195-198), dropping the failed chunk's un-processed tail **and** the rest of the batch — no DLQ/overflow. Prior triples in the chunk are fine (their `push_to_streaming` already succeeded). |
| C4 | P1 | STATIC | `nlf.rs:119-134`, `can_match:84-86` | `try_record_edge` for a vertex whose `index()` exceeds the built `counts` length silently no-ops and returns `true`; a brand-new source vertex gets an all-zero NLF row → valid start wrongly pruned. Same `edges_sorted` gate masks it today. |
| C5 | P1 | VERIFIED | `operations/ingestion.rs` (sync paths) | Synchronous ingest never enters `Finalizing` (only the background path does, `:1452`); it jumps `Loading → Ready`. The "hunt rejected while finalizing" protection does not exist for sync ingest. |
| C6 | P1 | STATIC | `operations/ai.rs:455` | The AI-agent `run_hunt` tool calls `search_temporal_pattern` directly, bypassing `ensure_huntable_phase` → the assistant can hunt mid-`Loading`/`Finalizing`. |
| C7 | P1 | STATIC | `ingest/source_poller.rs:89-127` | Circuit breaker uses wall-clock (`SystemTime`) for the backoff deadline; an NTP step keeps it open too long or reopens early. Plan specified monotonic `Instant`. |
| C8 | P2 | STATIC | `operations/hunt.rs:104,318` | TOCTOU: `session.phase()` is read then released before the graph read lock is taken; a background `set_phase(Finalizing)` can land in between. Advisory gate, not atomic (graph lock is the true serialization point). |
| C9 | P2 | VERIFIED | `operations/ingestion.rs` (sync `set_phase(Ready)`) | Trailing unconditional `set_phase(Ready)` clobbers a `Ready → LiveTail` transition on re-ingest; LiveTail never sticks via the sync path. (C1 fix preserves prior behavior; resolve holistically here.) |

### Hardening gaps (incomplete vs. Cursor's own plan)

| # | Sev | Location | Gap |
|---|-----|----------|-----|
| H1 | P1 | `apps/tauri/src-tauri/src/ingest/` (absent) | Azure pipeline unwired (Track O Tasks 4-7): no `SessionGraphAccess`, no `pipeline.rs` supervisor, no `azure_streaming` start/stop/status commands. Poller/parser/writer remain test-only; breaker state, spill metrics, channel depths never reach the UI. |
| H2 | P1 | `planner.rs:220-227`, `graph.rs:828` | Cost-aware planner default unwired (Track P Sprint 5): `plan_with_hints_lazy` still short-circuits to legacy `plan()` unless `GRAPHHUNTER_LFTJ_AUTO=1`. The 50%-weight deliverable is dead on the default path. |
| H3 | P1 | `writer.rs:137-147`, `overflow.rs:142` | Overflow replay: shutdown drain-to-overflow unimplemented (writer drops undrained batches on cancel); no idempotent-replay integration test; `write_batch` does not `fsync` (durability defeated). |
| H4 | P1 | `graph.rs` (`streaming_snapshot`/`mutation_version`) | Lazy snapshot refresh unimplemented (Track H Task 7): snapshot dropped on every append → full `freeze()` + tail re-sort per hunt under live tail. |
| H5 | P2 | `parser_task.rs:176` | `ChunkEncoding::Parquet` still `return None`; `parse_rows` fast path not implemented (every chunk re-parses UTF-8 + JSON). |
| H6 | P2 | `streaming.rs:1297-1305` | Infallible trait `append_edge` swallows spill errors in release builds; only `append_edge_checked` propagates. Confirm no spill-enabled production path uses the infallible method. |

### Optimization opportunities (fresh review)

**Temporal — biggest win per tier:**

| # | Tier | Location | Opportunity |
|---|------|----------|-------------|
| T-S | S (≤1M) | `planner.rs`, `graph.rs` freeze | Skip the cost model below ~50K edges and cache the frozen snapshot across hunts keyed on `mutation_version`; for small graphs planner + `freeze` deep-copy rivals the hunt itself. |
| T-M | M (1-20M) | `streaming.rs:817` `finalize_parallel`, `graph.rs:777` gate | Flip parallel finalize on by degree-threshold default (currently env-gated off); finalize is O(Σ d log d) — the M bottleneck. Skip slots with `len < 2`. |
| T-L | L (20M+/hubs) | `graph.rs:1899,2176,2361` DFS | Rel-type-bucketed neighbor layout for high-degree vertices; the per-frame DFS scans the full in-window range and filters rel/dest type inline. (Spec's "hub range index", bench-gated.) |

**Spatial — memory:**

| # | Sev | Location | Opportunity |
|---|-----|----------|-------------|
| S1 | P1 | `streaming.rs:440`, `auto_spill` | Tail buffer is unbounded and never spilled or drained back into base; `auto_spill` only rewrites `vertices`. A long LiveTail session grows RAM without limit, defeating the 28 GB spill design. Cap tail / drain into base on periodic re-finalize / include tails in the spill file. |
| S2 | P2 | `streaming.rs:712-730,858` | Tail re-sorted from scratch on every `freeze` and `neighbors_in_window`; keep per-vertex tail sorted-on-insert (tiny `SmallVec`) → O(n) merge. |
| S3 | P2 | `streaming.rs:707-714` | `freeze` builds a `FrozenNeighborList` then discards it for tailed vertices; only build when there's no tail. Reuse frozen `Arc<[StreamEdge]>` buffers across re-freezes when only tails changed. |

### Test gaps

- Missing the tail-merge-vs-full-resort property test the plan explicitly required (`streaming.rs`).
- No `Loading`-rejection test, no populated `LiveTailCoverage` test, no `index_coverage` formula test, no `run_hunt_batch` gating test (`operations/hunt.rs`).
- No overflow replay integration test; no circuit-breaker recovery (Open→Closed) test.
- `Partial` flag (tail > 5% of edges) not plumbed to engine/dto/TS — UI must derive it.
- Parity test (`tests/parity/dto_shapes.rs:108`) never asserts the populated `live_tail_coverage` shape (field is `None`, skipped).

### What Cursor got right (validated — do not redo)

- Spill-error plumbing end-to-end: `try_append_edge` → `append_edge_checked` → `Result`, `spill_errors` metric, `with_spill_fail` test hook.
- Tail-merge math: `merge_sorted_edge_slices` is a stable two-way merge; `partition_point` window bounds (`< start`, `<= end`) are correct and inclusive.
- 409 Conflict mapping complete on both HTTP and Tauri; LiveTail activation correctly post-finalize-only.
- Semijoin/AMAC default flip safe (escape hatches `=0` kept; parity tests force each on).
- Watermark advanced only after successful `raw_tx.send` and only when it moved.
- Criterion baselines are real (not placeholder); tiers M/L correctly `BENCH_LARGE`-gated.
- `finalize_parallel` is equivalence-correct; lock ordering in `freeze`/`append` is deadlock-free.

## Already fixed (this session)

**C1 — self-deadlock.** Relocated `note_post_finalize_appends` past the `graph.write()` guard
in all four unsafe sites (`ingestion.rs:428,633,734`; background mmap path `:1430` wrapped in
a sub-block mirroring the already-correct sibling sites `:1288`/`:1386`). Phase-at-call-time is
preserved (the trailing `set_phase(Ready)` still runs after), so the only behavioral change is
the removal of the hang. Holistic phase-flow correctness (C5, C9) is deferred to Track C below.

## Remediation roadmap

Four tracks, prioritized. Maps onto Cursor's P/H/O tracks; **Track C (correctness) is new and
gates everything else** — a branch that deadlocks or returns wrong hunts is not mergeable.

### Track C — Correctness (must-fix, blocks merge)

1. ~~C1 deadlock~~ (done).
2. C2 k-hop tail staleness: make the incremental delta tail-aware, **or** invalidate k-hop on
   post-finalize append instead of attempting a delta. Add a test that appends post-finalize
   then asserts k-hop reachability includes the tail edge.
3. C3 spill mid-batch data loss (two parts): **(a)** reorder `push_to_streaming?` to precede
   `reverse_adj…push` / `meta_store.append` (graph.rs:2997-2998) so a spill leaves no half-edge
   in the live sync graph; **(b)** in `GraphWriter::write_one_batch` route the un-written
   `pending` remainder to `OverflowStore` on spill error instead of `return`-dropping it (ties
   into H3). Integration test: force spill mid-batch, assert no edge-count loss + clean replay.
4. C4 NLF out-of-range row: return `false` (force rebuild) when `src_sid.index() >= counts.len()`.
5. C5 + C9 phase flow: set `Finalizing` at the start of the sync write block, `Ready` only after
   scoring completes; stop clobbering a `Ready→LiveTail` transition.
6. C6 AI gate: add the phase check before `ai.rs:455`'s direct search.
7. C7 breaker clock: switch to monotonic `tokio::time::Instant`.
8. C8 (optional) re-check `session.phase()` after acquiring the graph read lock, or document the
   graph lock as the serialization point.

### Track H — Hybrid substrate hardening

- S1 bound + spill the tail buffer (cap, or drain into base on re-finalize).
- H4 lazy snapshot refresh (`appends_since_snapshot` counter, re-freeze every N or on first hunt).
- S2/S3 keep tail sorted-on-insert; avoid redundant freeze allocations.
- Tail-merge property test; `Partial` flag plumbed; coverage tests.

### Track O — Azure E2E + ingest hardening

- H1 wire `SessionGraphAccess` + pipeline supervisor + `azure_streaming` commands; surface
  metrics/breaker/channel depths to the UI.
- H3 overflow shutdown-drain + idempotent-replay integration test + `fsync`.
- H5 Parquet decode + `parse_rows` fast path.
- Circuit-breaker recovery test.

### Track P — Performance

- H2 promote cost-aware planner to default with `GRAPHHUNTER_LFTJ_LEGACY=1` escape hatch
  (after C2/C4 so the index paths are correct first).
- T-S snapshot cache + cost-model skip for small graphs.
- T-M parallel finalize default-on by degree threshold.
- T-L rel-type-bucketed hub neighbor layout (bench-gated; do not reintroduce a global B-tree).

## Testing strategy

| Layer | Tests |
|-------|-------|
| Unit | k-hop tail-inclusive delta; NLF out-of-range rebuild; breaker recovery; phase transitions |
| Property | tail-merge vs full re-sort on random append streams |
| Integration | spill mid-batch non-loss; overflow shutdown→replay idempotency; mock `LogSource` pipeline E2E |
| Parity | populated `LiveTailCoverage` shape (Rust ↔ TS) |
| Bench/CI | hub rel-type layout vs baseline; parallel-finalize tier M; planner-default no >10% regression |

## Acceptance criteria

- No deadlock on any ingest path; sync ingest enters `Finalizing` and rejects hunts during it.
- LiveTail hunts return correct results with tail edges reflected in k-hop/NLF (or indexes
  invalidated, not silently stale).
- No data loss on spill failure (DLQ/overflow path exercised by an integration test).
- Tail buffer memory bounded; long LiveTail session stays within the spill budget.
- Cost-aware planner default with legacy escape hatch; no tier S/M/L regression > 10% vs baseline.

## Risks

| Risk | Mitigation |
|------|------------|
| Tail-aware index changes introduce new merge bugs | Property tests; conservative invalidate-over-delta for k-hop |
| Planner default flip regresses on dissimilar hardware | Flip only after C2/C4; multi-host calibration; env escape hatch |
| Spill-path refactor changes ingest throughput | Bench ingest before/after; keep infallible fast path for non-spill backends |

## Next step

Invoke the writing-plans skill to produce task-by-task implementation plans for Tracks C → H →
O → P (correctness first). Track C is the merge gate.
