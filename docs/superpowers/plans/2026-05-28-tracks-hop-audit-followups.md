# Tracks H / O / P — Audit Follow-ups Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Land the hardening and performance work the audit identified on top of Cursor's existing track plans — bounding the live-tail tail buffer, lazy snapshot refresh, spill-time overflow routing, wiring the Azure pipeline into Tauri, and flipping the cost-aware planner / parallel-finalize defaults.

**Architecture:** This plan does **not** duplicate Cursor's existing mechanics plans. For work already specced there, it references the task and records only the audit's correction or default-flip. New work (tail bounding, lazy snapshot, overflow routing, hub layout) is specced in full here.

**Tech Stack:** Rust, `graph_hunter_core` (`streaming.rs`, `graph.rs`, `planner.rs`, `ingest/{writer,overflow}.rs`), `graph_hunter_api`, Tauri.

**Depends on:** `docs/superpowers/plans/2026-05-28-track-c-correctness.md` — **Track C must be green first** (the index-invalidation and spill-reorder fixes are preconditions for the planner-default flip and overflow routing here).

**Spec:** `docs/superpowers/specs/2026-05-28-ingest-audit-remediation-design.md` (Tracks H / O / P + optimization tables).

**Reference plans (Cursor):** `2026-05-28-track-h-hybrid-substrate.md`, `2026-05-28-track-o-azure-hardening.md`, `2026-05-28-track-p-performance.md`.

---

## Ordering

```
H4 lazy snapshot ─┐
S1 tail bound     ├─► (Track H hardening; unblocks live-tail at scale)
S2/property test ─┘
C3b + H3 overflow ─► O (data-durability; pairs with Track C T2)
H1 pipeline wiring ─► O (feature; ref Cursor track-o Tasks 4-7)
H5 Parquet/parse_rows ─► O (ref Cursor track-o Tasks 8-9)
H2 planner default ─► P (AFTER Track C T1 — indexes must be correct first)
T-M parallel finalize default ─► P
T-S snapshot cache / T-L hub layout ─► P (bench-gated)
```

---

# Track H — Hybrid substrate hardening

## Task H-1: Lazy snapshot refresh (H4)

Today `on_streaming_edge_appended` (`graph.rs:424`) resets `self.streaming_snapshot = OnceLock::new()` on **every** append, so under live-tail each appended edge forces a full `freeze()` + tail re-sort on the next hunt. Replace eager invalidation with a counter + threshold.

**Files:**
- Modify: `core/graph-engine/src/graph.rs` (add `appends_since_snapshot: u64` field; gate the snapshot reset)
- Test: `core/graph-engine/src/graph.rs` tests

- [ ] **Step 1: Write the failing test**

```rust
#[test]
fn snapshot_not_dropped_until_threshold() {
    let mut g = small_finalized_graph(); // helper: A->B finalized, snapshot warmed
    g.streaming_snapshot(); // warm the OnceLock
    assert!(g.has_streaming_snapshot()); // test-only accessor
    // One post-finalize append must NOT drop the snapshot (below threshold).
    g.add_relation(Relation::new("B", "C", RelationType::Auth, 200)).unwrap();
    assert!(g.has_streaming_snapshot(), "single append should not invalidate snapshot");
}
```

- [ ] **Step 2: Run — expect FAIL** (`cargo test --manifest-path core/graph-engine/Cargo.toml snapshot_not_dropped_until_threshold`).

- [ ] **Step 3: Implement counter-gated invalidation**

Add `appends_since_snapshot: u64` to `GraphHunter` (init 0). In `on_streaming_edge_appended`, replace the unconditional `self.streaming_snapshot = OnceLock::new();` with:

```rust
const SNAPSHOT_REFRESH_APPENDS: u64 = 10_000;
self.appends_since_snapshot += 1;
if self.appends_since_snapshot >= SNAPSHOT_REFRESH_APPENDS {
    self.streaming_snapshot = std::sync::OnceLock::new();
    self.appends_since_snapshot = 0;
}
```

`mutation_version` still bumps every append (the API LFTJ/Yannakakis caches key on it), so stale-cache safety is preserved; only the expensive snapshot rebuild is deferred. The tail-aware `freeze()` already merges the tail, so a re-freeze every N appends bounds staleness without per-append cost.

> **Interaction with Track C T1:** the finalized-gate invalidates NLF/k-hop every post-finalize append. That is correct but also costly under heavy live-tail. After this task, consider applying the same counter to the index invalidation (rebuild every N) — but only once a tail-aware delta or a coverage test proves correctness. Leave index invalidation per-append for now (correctness over speed).

- [ ] **Step 4: Run — expect PASS.** Then `cargo test --manifest-path platform/api/Cargo.toml hunt::` to confirm LFTJ cache invalidation still works via `mutation_version`.

- [ ] **Step 5: Commit** `perf: lazy streaming snapshot refresh every N live-tail appends (H4)`.

---

## Task H-2: Bound + drain the tail buffer (S1)

`InMemoryStreamingBackend.tails` (`streaming.rs:440`) grows unbounded; `auto_spill` only rewrites `vertices`, never the tail. A long live-tail session grows RAM without limit, defeating the 28 GB spill design.

**Files:**
- Modify: `core/graph-engine/src/streaming.rs` (track total tail edges; expose a drain/compact)
- Modify: `core/graph-engine/src/graph.rs` (trigger re-finalize when tail exceeds a budget)
- Test: `core/graph-engine/src/streaming.rs` tests

- [ ] **Step 1: Write the failing test**

```rust
#[test]
fn tail_drains_into_base_when_over_budget() {
    let backend = InMemoryStreamingBackend::new();
    // append + finalize a base, then append > budget tail edges
    // ... (mirror existing finalize tests) ...
    backend.set_tail_budget(8);
    for i in 0..20 { backend.append_edge(StrId::from_raw(1), edge(2, 100 + i, 0)); }
    assert!(backend.tail_edge_count() <= 8, "tail must be compacted back into base when over budget");
}
```

- [ ] **Step 2: Run — expect FAIL.**

- [ ] **Step 3: Implement budget + drain**

Add a `tail_budget` (default e.g. 50_000 edges total) and a `drain_tails_into_base()` that, when the total tail size crosses the budget, merges each per-vertex tail into its sorted base list (reusing `merge_sorted_edge_slices`) and clears the tail. On a spill-enabled backend, route the merged base through the existing `auto_spill` path so tail memory is reclaimed. Call the drain from `append_edge`/`append_edge_checked` when over budget (or expose it for `graph.rs` to call from `on_streaming_edge_appended`).

> This re-establishes the spill invariant: post-finalize edges no longer accumulate solely in RAM. It pairs with H-1 (snapshot refresh) — a drain is a natural re-freeze point.

- [ ] **Step 4: Run — expect PASS.** Regression: `cargo test --manifest-path core/graph-engine/Cargo.toml streaming::`.

- [ ] **Step 5: Commit** `fix: bound the live-tail buffer and drain into base over budget (S1)`.

---

## Task H-3: Tail-merge property test + sorted-on-insert (S2)

The plan required a property test comparing tail-merge output to a full re-sort; it is missing. Also, the per-vertex tail is re-sorted on every `freeze`/`neighbors_in_window` (`streaming.rs:712-730,858`) — keep it sorted on insert.

**Files:**
- Modify: `core/graph-engine/src/streaming.rs` (insert into tail in sorted position)
- Test: `core/graph-engine/src/streaming.rs` tests (add `proptest` or a deterministic randomized test)

- [ ] **Step 1: Write the property/randomized merge-equivalence test**

```rust
#[test]
fn tail_merge_matches_full_resort_on_random_streams() {
    use rand::{Rng, SeedableRng};
    let mut rng = rand::rngs::StdRng::seed_from_u64(42);
    for _ in 0..200 {
        let backend = InMemoryStreamingBackend::new();
        let src = StrId::from_raw(1);
        let mut all = Vec::new();
        let split = rng.gen_range(0..30);
        for i in 0..30 {
            let ts = rng.gen_range(0i64..1000);
            let e = edge(rng.gen_range(2..10), ts, 0);
            all.push(e);
            backend.append_edge(src, e);
            if i == split { backend.finalize(); } // some land pre-, some post-finalize
        }
        let mut reference = all.clone();
        reference.sort_by_key(|e| e.timestamp);
        let got = backend.freeze().neighbors(src); // or neighbors_in_window full range
        assert_eq!(timestamps(&got), timestamps(&reference));
    }
}
```

> Use the crate's existing RNG dev-dependency; if none, use a deterministic LCG inline. The contract: merged output equals a full re-sort of all appended edges regardless of pre/post-finalize split.

- [ ] **Step 2: Run — expect PASS or reveal a merge bug.** If it fails, the merge has a real defect — fix before proceeding.

- [ ] **Step 3: Sorted-on-insert**

In `append_edge_inner`'s post-finalize branch, insert into the per-vertex tail `SmallVec` at its sorted position (`partition_point` by timestamp) instead of pushing unsorted. Then `freeze`/`neighbors_in_window` can drop the `sort_unstable` and do a straight two-way merge (O(n)).

- [ ] **Step 4: Run — expect PASS** (property test still holds; merge now assumes sorted tail).

- [ ] **Step 5: Commit** `perf: keep live-tail buffer sorted on insert; add merge-equivalence property test (S2)`.

---

## Task H-4: Plumb the `Partial` coverage flag

The spec wants a `Partial` flag when tail > 5% of edges; only the raw `index_coverage` float is plumbed today. Add the boolean so the UI doesn't re-derive it.

**Files:**
- Modify: `core/graph-engine/src/analytics.rs` (`LiveTailCoverage`: add `partial: bool`)
- Modify: `apps/tauri/src/types.ts` (mirror the field)
- Modify: `platform/api/tests/parity/dto_shapes.rs` (assert the populated shape)

- [ ] **Step 1: Write the parity + formula test** asserting `partial == (tail as f64 / total > 0.05)` and that the populated `LiveTailCoverage` serializes with the new key.
- [ ] **Step 2: Run — expect FAIL.**
- [ ] **Step 3: Add `partial` to the struct** (compute in `graph.rs:480-489` alongside `index_coverage`), the TS type, and a populated-shape assertion in the parity suite.
- [ ] **Step 4: Run — expect PASS.**
- [ ] **Step 5: Commit** `feat: expose Partial coverage flag on live-tail hunt responses`.

---

# Track O — Azure E2E + ingest hardening

## Task O-1: Route un-written batch remainder to overflow on spill (C3b + H3)

`GraphWriter::write_one_batch` (`writer.rs:195-198`) `return`s on a chunk error, dropping the failed chunk's remainder **and** the rest of the batch — no DLQ/overflow. `OverflowStore::write_batch` (`overflow.rs:142`) also lacks `fsync`.

**Files:**
- Modify: `core/graph-engine/src/ingest/writer.rs` (on `Err`, push remaining `pending` to `OverflowStore`)
- Modify: `core/graph-engine/src/ingest/overflow.rs` (`fsync` before rename)
- Test: `core/graph-engine/src/ingest/writer.rs` tests + an integration test

- [ ] **Step 1: Write the failing test** — a `GraphAccess` that fails the 2nd chunk; assert the un-written remainder lands in the `OverflowStore` (count preserved), not dropped.
- [ ] **Step 2: Run — expect FAIL.**
- [ ] **Step 3: Implement** — give `GraphWriter` an `Option<Arc<OverflowStore>>`; in the `Err` arm, instead of bare `return`, write the remaining `pending` (and the failed chunk's un-consumed tail, which the chunk method must leave in `pending` — verify `insert_*_chunk` only drains what it commits, or have it restore the un-committed remainder) to overflow, bump a metric, then stop the batch. Add `file.sync_all()` in `overflow.rs::write_batch` before the rename.
- [ ] **Step 4: Add the overflow shutdown→replay integration test** (Cursor track-o Task 3, still missing): fill channel, cancel writer with pending, assert overflow written, restart, drain, assert idempotent triple count.
- [ ] **Step 5: Run — expect PASS.**
- [ ] **Step 6: Commit** `fix: route spilled/cancelled batch remainder to overflow; fsync overflow writes (C3b, H3)`.

> **Coupling with Track C T2 (C3a):** the reorder there ensures the failing *triple* leaves no half-edge; this task ensures the failing *batch* is not silently lost. Both are needed for "no data loss under spill."

## Task O-2: Wire the Azure pipeline into Tauri (H1)

Implement Cursor's **track-o Tasks 4-7** as written (`SessionGraphAccess`, `pipeline.rs` supervisor, `azure_streaming` start/stop/status commands, mock-`LogSource` E2E test) — they are unstarted. Audit additions:

**Files:** see `2026-05-28-track-o-azure-hardening.md` Tasks 4-7 (exact file paths + code there).

- [ ] **Step 1–4:** Follow track-o Tasks 4-7 verbatim for `SessionGraphAccess`, `spawn_pipeline`, the three Tauri commands, and the mock E2E test.
- [ ] **Step 5 (audit add):** On `spawn_pipeline` success, set `SessionPhase::LiveTail` (Track H integration point) — and on the writer first edge, ensure `note_post_finalize_appends` is driven through the production `GraphAccess` path too (the deadlock-safe relocated call).
- [ ] **Step 6 (audit add):** `azure_streaming_status` must surface `WriterMetricsSnapshot` **and** the `PollerMetricsSnapshot { circuit_state, consecutive_failures }` + channel depths, so the breaker/spill counters added in Sprint 1 are finally observable (acceptance gap).
- [ ] **Step 7: Commit** per track-o (one commit per sub-task).

## Task O-3: Parquet + `parse_rows` fast path (H5)

Implement Cursor's **track-o Tasks 8-9** as written (`parser_task.rs:176` Parquet arm; `parse_rows` over pre-decoded rows). No audit corrections — just unstarted.

- [ ] Follow track-o Tasks 8-9; commit per task.

> Circuit-breaker recovery test (Cursor track-o gap) is already added in **Track C Task 5**.

---

# Track P — Performance

## Task P-1: Promote the cost-aware planner to default (H2)

`plan_with_hints_lazy` still short-circuits to legacy `plan()` unless `GRAPHHUNTER_LFTJ_AUTO=1` (`planner.rs:220-227`, `graph.rs:828`); the cost model is dead on the default path. **Do this only after Track C Task 1 is green** — the index paths the planner relies on must be correct first.

**Files:** see `2026-05-28-track-p-performance.md` Task 6 (the invert-the-gate steps). Audit additions below.

- [ ] **Step 1:** Run the full graph-engine suite with `GRAPHHUNTER_LFTJ_AUTO=1` forced on, on Windows and Linux, to confirm no plan-selection drift in snapshot tests (track-p Task 6 Step 2).
- [ ] **Step 2:** Invert the gate: cost-aware by default, `GRAPHHUNTER_LFTJ_LEGACY=1` restores `plan()`.
- [ ] **Step 3 (audit add):** Before flipping, replace the single-host calibration stub (`docs/superpowers/calibration/planner-cost-hints.json`, only `windows-dev`) with at least the Linux-CI host, and make `planner.rs` actually **load** the calibration (today nothing reads it — the test only asserts it parses). If loading is out of scope, delete the stub + cosmetic test rather than ship dead calibration.
- [ ] **Step 4:** Re-run `hunt_latency` tiers; assert no >10% regression vs the committed baseline.
- [ ] **Step 5: Commit** `perf: make cost-aware planner the default dispatch path (H2)`.

## Task P-2: Parallel finalize default-on by degree threshold (T-M)

`finalize_parallel` exists (`streaming.rs:817`) but is env-gated off (`GRAPHHUNTER_PARALLEL_FINALIZE`, `graph.rs:777`). Finalize is the tier-M bottleneck (O(Σ d log d)). Flip it on by a degree/size threshold.

**Files:**
- Modify: `core/graph-engine/src/graph.rs:777` (default selection) and `streaming.rs:817` (skip `len < 2` slots)
- Test: existing `finalize_parallel_matches_sequential` equivalence test guards correctness.

- [ ] **Step 1:** Add a threshold (e.g. parallel when `vertex_count > 50_000` or `edge_count > 1M`); default-select the parallel path above it, keep `GRAPHHUNTER_PARALLEL_FINALIZE=0` as an opt-out for one release.
- [ ] **Step 2:** In `finalize_parallel`, skip scheduling tasks for slots with `len < 2` (no-op sorts).
- [ ] **Step 3:** Run `cargo test --manifest-path core/graph-engine/Cargo.toml finalize_parallel_matches_sequential`; expected PASS (equivalence holds).
- [ ] **Step 4:** Bench tier M finalize wall time before/after; record in `docs/perf/`.
- [ ] **Step 5: Commit** `perf: enable parallel finalize by default above degree threshold (T-M)`.

## Task P-3: Tier-S snapshot cache + cost-model skip (T-S)

For small graphs the planner cost walk (O(V)+O(E)) and the first-hunt `freeze()` deep-copy rival the hunt itself.

**Files:**
- Modify: `core/graph-engine/src/planner.rs` (skip cost model below ~50K edges → legacy `plan()`)
- Modify: `core/graph-engine/src/graph.rs` (cache the frozen snapshot across hunts keyed on `mutation_version`)
- Test: graph-engine tests

- [ ] **Step 1:** In the planner default path, when `edge_count < 50_000`, use the cheaper legacy `plan()` directly (the cost model's win only materializes at scale).
- [ ] **Step 2:** Ensure `streaming_snapshot` (the `OnceLock`) is reused across hunts while `mutation_version` is unchanged — with H-1's counter-gated invalidation this is mostly done; add a test asserting two consecutive hunts with no mutation reuse the same snapshot (e.g. via a build-count test hook).
- [ ] **Step 3:** Bench tier S (1K/10K) p95 before/after; target < 2s for a 3-step hypothesis.
- [ ] **Step 4: Commit** `perf: skip cost model and reuse snapshot for small-tier hunts (T-S)`.

## Task P-4 (bench-gated): Hub rel-type neighbor layout (T-L)

The per-frame DFS scans the full in-window neighbor range and filters rel/dest type inline (`graph.rs:1899,2176,2361`); for hub vertices this dominates tier-L cost. Pilot a rel-type-bucketed layout for high-degree vertices.

**Files:**
- Modify: `core/graph-engine/src/streaming.rs` / `graph.rs` (secondary per-(src,rel_type) index for degree > threshold)
- Bench: `core/graph-engine/benches/hunt_latency.rs` hub group

- [ ] **Step 1:** Add a bench comparing hub-spray hunt latency with/without the bucketed layout (do **not** ship without a measured win; do **not** reintroduce a global B-tree — spec constraint).
- [ ] **Step 2:** If the bench shows a win, implement a per-(src, rel_type) min/max-timestamp side index (or a rel-type partition) consulted only for vertices above the degree threshold; fall back to the linear scan otherwise.
- [ ] **Step 3:** Run the equivalence/correctness hunt tests + the hub bench; require no correctness change and a measured tier-L improvement.
- [ ] **Step 4: Commit** `perf: rel-type-bucketed hub neighbor layout (T-L, bench-gated)`.

---

## Acceptance checklist (Tracks H / O / P)

- [ ] Single live-tail append no longer drops the snapshot; snapshot refreshes every N (H-1).
- [ ] Tail buffer bounded; long live-tail session stays within spill budget (H-2).
- [ ] Tail-merge property test passes; tail kept sorted on insert (H-3).
- [ ] `Partial` flag plumbed engine → dto → TS, asserted by parity test (H-4).
- [ ] Spilled/cancelled batch remainder routed to overflow + fsync; replay idempotent (O-1).
- [ ] Azure pipeline runs from Tauri against a mock source; breaker/spill/channel metrics visible (O-2).
- [ ] Parquet chunk parses; `parse_rows` fast path benched (O-3).
- [ ] Cost-aware planner default with legacy escape hatch; calibration loaded or removed (P-1).
- [ ] Parallel finalize default-on above threshold; equivalence test green (P-2).
- [ ] Tier S p95 < 2s; snapshot reused across no-mutation hunts (P-3).
- [ ] Hub layout shipped only with a measured tier-L bench win (P-4).
