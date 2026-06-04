# Track H — Hybrid Substrate Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Enable hybrid batch + live-tail sessions with graceful hunt degradation via `SessionPhase`, tail buffers, incremental indexes, and extended diagnostics.

**Architecture:** Session lifecycle lives in `platform/api`; streaming backend gains per-vertex tail buffers post-finalize; existing `mutation_version` invalidates API caches; `HuntDiagnostic` extended for live-tail metadata (distinct from zero-path diagnostics in `analytics.rs`).

**Tech Stack:** Rust, `platform/api`, Tauri commands, `graph_hunter_core` (`streaming.rs`, `graph.rs`, `nlf.rs`, `khop_reach.rs`).

**Spec:** `docs/superpowers/specs/2026-05-28-ingest-streaming-matcher-audit-design.md` (Track H section)

**Depends on:** Track O Sprint 1 spill-error propagation (optional but recommended before LiveTail hunts in production).

---

## File map

| File | Responsibility |
|------|----------------|
| `platform/api/src/state/session.rs` | `SessionPhase`, phase transitions, tail stats |
| `platform/api/src/state/session_types.rs` | Serializable phase + stats types |
| `platform/api/src/operations/hunt.rs` | Phase gating, attach live-tail metadata to responses |
| `platform/api/src/operations/ingestion.rs` | Transition Loading → Finalizing → Ready on batch complete |
| `core/graph-engine/src/streaming.rs` | `TailBuffer`, merge read path |
| `core/graph-engine/src/graph.rs` | Wire incremental NLF/k-hop on append; lazy snapshot refresh |
| `core/graph-engine/src/analytics.rs` | Extend or add `LiveTailDiagnostic` (avoid breaking existing `HuntDiagnostic`) |
| `apps/tauri/src-tauri/src/types.rs` | IPC types for phase + diagnostics |
| `apps/tauri/src-tauri/src/http/hunt.rs` | Pass through new fields |

---

## Sprint 2 — SessionPhase + hunt gating

### Task 1: Define `SessionPhase`

**Files:**
- Modify: `platform/api/src/state/session_types.rs`
- Modify: `platform/api/src/state/session.rs`

- [ ] **Step 1: Add enum**

In `session_types.rs`:

```rust
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SessionPhase {
    Loading,
    Finalizing,
    Ready,
    LiveTail,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct LiveTailStats {
    pub tail_edge_count: u64,
    pub last_append_at: Option<i64>,
}
```

- [ ] **Step 2: Add fields to `Session`**

In `session.rs` on `Session` struct:

```rust
pub phase: RwLock<SessionPhase>,
pub live_tail_stats: RwLock<LiveTailStats>,
```

Initialize new sessions to `SessionPhase::Loading` in `SessionStore::create`.

- [ ] **Step 3: Add accessors**

```rust
impl Session {
    pub fn phase(&self) -> SessionPhase {
        *self.phase.read().unwrap_or_else(|e| e.into_inner())
    }
    pub fn set_phase(&self, phase: SessionPhase) {
        *self.phase.write().unwrap_or_else(|e| e.into_inner()) = phase;
    }
}
```

- [ ] **Step 4: Run platform/api tests**

Run: `cargo test --manifest-path platform/api/Cargo.toml session::`

Expected: compile; fix any struct literal sites.

- [ ] **Step 5: Commit**

```bash
git add platform/api/src/state/session.rs platform/api/src/state/session_types.rs
git commit -m "feat: add SessionPhase and LiveTailStats to session state"
```

---

### Task 2: Hunt gating by phase

**Files:**
- Modify: `platform/api/src/operations/hunt.rs`
- Test: add test in `platform/api/src/operations/hunt.rs` or `platform/api/tests/`

- [ ] **Step 1: Write failing test**

```rust
#[test]
fn hunt_rejected_while_finalizing() {
    // build session in Finalizing phase
    // call hunt entrypoint
    // assert Err with message containing "finalizing"
}
```

- [ ] **Step 2: Run test — expect FAIL**

Run: `cargo test --manifest-path platform/api/Cargo.toml hunt_rejected_while_finalizing`

- [ ] **Step 3: Gate at hunt entry**

Before acquiring graph read lock for hunt, read `session.phase()`:

- `Loading` / `Finalizing` → return structured error (HTTP 409 / Tauri error code)
- `Ready` / `LiveTail` → proceed

- [ ] **Step 4: Transition on ingest complete**

In `operations/ingestion.rs` after `sort_edges_by_timestamp()` / snapshot build:

```rust
session.set_phase(SessionPhase::Ready);
```

- [ ] **Step 5: Run tests**

Run: `cargo test --manifest-path platform/api/Cargo.toml hunt_rejected_while_finalizing`

Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add platform/api/src/operations/hunt.rs platform/api/src/operations/ingestion.rs
git commit -m "feat: gate hunts during Loading/Finalizing session phases"
```

---

## Sprint 3 — Tail buffer + merge read path

### Task 3: Per-vertex tail buffer in streaming

**Files:**
- Modify: `core/graph-engine/src/streaming.rs`
- Test: `core/graph-engine/src/streaming.rs` tests module

- [ ] **Step 1: Write failing merge test**

```rust
#[test]
fn neighbors_merge_base_and_tail_by_timestamp() {
    let backend = InMemoryStreamingBackend::new();
    let src = StrId::from_raw(1);
    backend.append_edge(src, edge(2, 100, 0));
    backend.append_edge(src, edge(3, 300, 0));
    backend.finalize();
    backend.set_finalized(true); // new flag if needed
    backend.append_edge(src, edge(4, 200, 0)); // goes to tail
    let window = (150i64, 250i64);
    let n = backend.neighbors_in_window(src, window);
    assert_eq!(n.len(), 1);
    assert_eq!(n[0].dst, 4);
}
```

- [ ] **Step 2: Run test — expect FAIL**

Run: `cargo test --manifest-path core/graph-engine/Cargo.toml neighbors_merge_base_and_tail`

- [ ] **Step 3: Implement tail storage**

Add to `InMemoryStreamingBackend`:

```rust
finalized: AtomicBool,
tails: RwLock<HashMap<StrId, SmallVec<[StreamEdge; 4]>>>,
```

In `append_edge`: if `finalized`, push to `tails[src]` instead of mutating sorted inline/vec.

- [ ] **Step 4: Implement `neighbors_in_window` merge**

- Binary search on sorted base slice for window bounds
- Linear scan tail buffer, filter by timestamp, merge sorted

- [ ] **Step 5: Property test vs brute force**

Add test that randomizes append order, compares merge output to full re-sort reference.

- [ ] **Step 6: Commit**

```bash
git add core/graph-engine/src/streaming.rs
git commit -m "feat: per-vertex tail buffer with timestamp merge read path"
```

---

### Task 4: Wire graph append path to tail + stats

**Files:**
- Modify: `core/graph-engine/src/graph.rs` (`add_relation`, `insert_raw_events_chunk`)
- Modify: `platform/api/src/state/session.rs`

- [ ] **Step 1: On live append, bump `LiveTailStats`**

When ingest path detects `SessionPhase::LiveTail`, increment `tail_edge_count` and set `last_append_at`.

- [ ] **Step 2: Set phase on Azure writer start (Track O integration point)**

When pipeline spawns successfully: `session.set_phase(SessionPhase::LiveTail)`.

- [ ] **Step 3: Integration test**

Extend existing MVCC ingest test pattern: finalize graph, append batch, assert tail stats > 0.

- [ ] **Step 4: Commit**

```bash
git add core/graph-engine/src/graph.rs platform/api/src/state/session.rs
git commit -m "feat: track live tail stats on post-finalize appends"
```

---

## Sprint 3 — Incremental indexes + diagnostics

### Task 5: Incremental NLF/k-hop on append

**Files:**
- Modify: `core/graph-engine/src/graph.rs`
- Reference: `core/graph-engine/src/nlf.rs` (`try_record_edge`)
- Reference: `core/graph-engine/src/khop_reach.rs` (`try_record_edge_delta`)

- [ ] **Step 1: Write failing test**

Reuse pattern from `nlf.rs` test `add_relation_after_nlf_built_keeps_nlf_live_via_incremental_update` but through public `GraphHunter::add_relation` after hunt warmed indexes.

- [ ] **Step 2: In `add_relation`, after streaming append**

If NLF index built and not mmap-spilled:

```rust
if let Some(nlf) = self.nlf_index.get() {
    let _ = nlf.try_record_edge(src, dst, rel_type, timestamp);
}
```

Same for k-hop delta when `khop_reach` is materialized.

- [ ] **Step 3: On mmap spill failure path, invalidate lazy indexes**

Call existing reset hooks; do not full `sort_edges_by_timestamp()`.

- [ ] **Step 4: Run graph-engine tests**

Run: `cargo test --manifest-path core/graph-engine/Cargo.toml nlf:: khop_reach::`

- [ ] **Step 5: Commit**

```bash
git add core/graph-engine/src/graph.rs
git commit -m "feat: incremental NLF and k-hop updates on live append"
```

---

### Task 6: Live-tail hunt coverage metadata

**Files:**
- Create or extend: `core/graph-engine/src/analytics.rs` — add `LiveTailCoverage` struct (do not overload zero-path `HuntDiagnostic`)
- Modify: `platform/api/src/operations/hunt.rs`
- Modify: `apps/tauri/src-tauri/src/types.rs`

- [ ] **Step 1: Define response extension**

```rust
#[derive(Serialize, Clone, Debug, Default)]
pub struct LiveTailCoverage {
    pub phase: String,
    pub tail_edge_count: u64,
    pub index_coverage: f64, // 1.0 = full snapshot; lower when tail dominates
}
```

Attach as `Option<LiveTailCoverage>` on hunt batch response (alongside existing `diagnostic: Option<HuntDiagnostic>` for zero-path hints).

- [ ] **Step 2: Compute `index_coverage`**

Example: `1.0 - (tail_edges as f64 / total_edges.max(1) as f64).min(0.5)` when phase is LiveTail; flag `Partial` in UI when tail > 5% of edges (per spec acceptance).

- [ ] **Step 3: Expose via Tauri HTTP**

Update `apps/tauri/src-tauri/src/http/hunt.rs` JSON shape; update frontend banner (minimal string first).

- [ ] **Step 4: Commit**

```bash
git add core/graph-engine/src/analytics.rs platform/api/src/operations/hunt.rs apps/tauri/src-tauri/src/types.rs apps/tauri/src-tauri/src/http/hunt.rs
git commit -m "feat: live-tail coverage metadata on hunt responses"
```

---

### Task 7: Lazy snapshot refresh policy

**Files:**
- Modify: `core/graph-engine/src/graph.rs` (`streaming_snapshot`, `mutation_version`)

- [ ] **Step 1: Stop dropping snapshot on every append**

Replace eager invalidation with counter `appends_since_snapshot: AtomicU64`.

- [ ] **Step 2: Re-freeze on first hunt after N appends (N=10_000 default) or explicit API call**

- [ ] **Step 3: Test that `mutation_version` still bumps and LFTJ cache invalidates**

Run existing tests in `platform/api/src/operations/hunt.rs` around LFTJ cache version.

- [ ] **Step 4: Commit**

```bash
git add core/graph-engine/src/graph.rs
git commit -m "perf: lazy streaming snapshot refresh during LiveTail"
```

---

## Acceptance checklist (Track H)

- [ ] Hunts blocked with clear error during `Finalizing`
- [ ] Post-finalize appends do not resort full graph
- [ ] Tail merge property tests pass
- [ ] LiveTail hunt returns `LiveTailCoverage` when tail non-empty
- [ ] Incremental NLF/k-hop tests pass after live append
