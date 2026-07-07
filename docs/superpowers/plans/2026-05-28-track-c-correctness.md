# Track C — Correctness Remediation Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Fix the correctness bugs the audit found in Cursor's sprint work so the `feat/sprint1-ingest-audit` branch is mergeable: stale live-tail indexes, spill-time graph corruption, missing finalize gate on sync ingest, an ungated AI hunt path, and a wall-clock circuit breaker.

**Architecture:** All fixes are surgical and local. The unifying insight for the index bugs (C2/C4): incremental NLF/k-hop deltas are only sound *before* finalize (everything is in the base neighbor lists); once the streaming backend is finalized, appends land in the per-vertex tail buffer that the deltas can't see, so we must **invalidate-and-rebuild** instead of delta. The spill-corruption fix (C3a) makes the fallible streaming push happen *before* any irreversible mutation.

**Tech Stack:** Rust, `graph_hunter_core` (`graph.rs`, `nlf.rs`, `khop_reach.rs`, `ingest/source_poller.rs`), `graph_hunter_api` (`operations/{hunt,ingestion,ai}.rs`).

**Spec:** `docs/superpowers/specs/2026-05-28-ingest-audit-remediation-design.md` (Track C).

**Status note:** **C1 (the `note_post_finalize_appends` self-deadlock) is already fixed** on this branch — the helper was relocated past the `graph.write()` guard at `ingestion.rs:428/633/734/1430` and `platform/api` compiles clean. This plan covers C2–C9.

---

## File map

| File | Responsibility | Tasks |
|------|----------------|-------|
| `core/graph-engine/src/graph.rs` | `on_streaming_edge_appended` invalidation gate; `add_relation`/`insert_triples`/`insert_raw_events` push order | T1, T2 |
| `core/graph-engine/src/nlf.rs` | `try_record_edge` out-of-range returns `false` | T1 |
| `core/graph-engine/src/ingest/source_poller.rs` | monotonic `now_millis` | T5 |
| `platform/api/src/operations/ingestion.rs` | sync ingest `Finalizing` gate; stop clobbering `LiveTail` | T3 |
| `platform/api/src/operations/hunt.rs` | expose `ensure_huntable_phase` as `pub(crate)` | T4 |
| `platform/api/src/operations/ai.rs` | gate the AI `run_hunt` tool by phase | T4 |

---

## Task 1: C2 + C4 — invalidate live-tail indexes instead of stale deltas

The incremental NLF/k-hop deltas in `on_streaming_edge_appended` (`graph.rs:432-465`) read **base** neighbor lists only (`khop_reach.rs:367` `streaming.with_neighbors`), so a post-finalize append in the tail buffer is invisible to them → wrong hunts (C2). Independently, `nlf::try_record_edge` returns `true` (silent success, no rebuild) for an out-of-range vertex (`nlf.rs:130-133`) → a brand-new start vertex gets an all-zero NLF row and is wrongly pruned (C4).

**Files:**
- Modify: `core/graph-engine/src/graph.rs:419-467` (`on_streaming_edge_appended`)
- Modify: `core/graph-engine/src/nlf.rs:119-134` (`try_record_edge`)
- Test: `core/graph-engine/src/graph.rs` (`#[cfg(test)]` module) and `core/graph-engine/src/nlf.rs` tests

- [ ] **Step 1: Write the failing behavioral test (k-hop tail visibility)**

Add to the `#[cfg(test)] mod tests` in `core/graph-engine/src/graph.rs`. Mirror the hunt-construction helpers already used by existing graph tests (search the file for `search_temporal_pattern(` to copy a 2-step `Hypothesis` construction):

```rust
#[test]
fn post_finalize_tail_edge_is_visible_to_khop_after_index_built() {
    use crate::{Entity, EntityType, Relation, RelationType};
    let mut g = GraphHunter::new();
    // Base: A --Auth--> B at t=100
    g.add_entity(Entity::new("A", EntityType::User)).unwrap();
    g.add_entity(Entity::new("B", EntityType::Host)).unwrap();
    g.add_relation(Relation::new("A", "B", RelationType::Auth, 100)).unwrap();
    g.sort_edges_by_timestamp().unwrap();
    assert!(g.streaming_is_finalized());

    // Warm NLF + k-hop by running a 1-step hunt (builds the lazy indexes).
    let warm = crate::hypothesis::Hypothesis::single_step(
        EntityType::User, RelationType::Auth, EntityType::Host,
    );
    let _ = g.search_temporal_pattern(&warm, None, Some(10)).unwrap();
    assert!(g.nlf.get().is_some(), "warm-up should build NLF");

    // Post-finalize append: B --Auth--> C at t=200 (lands in the tail).
    g.add_entity(Entity::new("C", EntityType::Host)).unwrap();
    g.add_relation(Relation::new("B", "C", RelationType::Auth, 200)).unwrap();

    // The append must have invalidated the built indexes so the next hunt
    // rebuilds tail-inclusively (rather than running a stale base-only index).
    assert!(g.nlf.get().is_none(), "post-finalize append must invalidate NLF");
    assert!(g.khop_reach.get().is_none(), "post-finalize append must invalidate k-hop");
}
```

> If `Hypothesis::single_step` does not exist with that exact name, copy the hypothesis-construction snippet from the nearest existing test in `graph.rs` that calls `search_temporal_pattern`. The assertions on `g.nlf`/`g.khop_reach` are the real contract.

- [ ] **Step 2: Run the test — expect FAIL**

Run: `cargo test --manifest-path core/graph-engine/Cargo.toml post_finalize_tail_edge_is_visible_to_khop -- --nocapture`
Expected: FAIL — the indexes are NOT invalidated today (the delta path keeps them, stale).

- [ ] **Step 3: Add the finalized-gate to `on_streaming_edge_appended`**

In `core/graph-engine/src/graph.rs`, replace the body of `on_streaming_edge_appended` (lines 422-467) so the incremental delta is skipped once finalized:

```rust
fn on_streaming_edge_appended(&mut self, src_sid: StrId, dst_sid: StrId) {
    self.edges_sorted = false;
    self.streaming_snapshot = std::sync::OnceLock::new();

    // Post-finalize appends land in the per-vertex tail buffer. The
    // incremental NLF/k-hop deltas below read BASE neighbor lists only
    // (see khop_reach::try_record_edge_delta), so they cannot see the
    // tail. Attempting a delta would silently desync the index from the
    // tail and corrupt hunt results. Once the backend is finalized we
    // therefore drop any built index and let the next hunt rebuild it
    // tail-inclusively. (Track P/H optimizes this with a tail-aware
    // delta or batched re-freeze; correctness comes first.)
    if self.streaming.is_finalized() {
        if self.nlf.get().is_some() {
            self.nlf = std::sync::OnceLock::new();
        }
        if self.khop_reach.get().is_some() {
            self.khop_reach = std::sync::OnceLock::new();
        }
        self.bump_mutation_version();
        return;
    }

    let dst_tag = self
        .entity_type_tags
        .get(dst_sid.index())
        .copied()
        .unwrap_or(crate::nlf::NLF_TYPE_COUNT as u8);

    let mut nlf_invalidate = true;
    if let Some(nlf) = self.nlf.get_mut() {
        if nlf.try_record_edge(src_sid, dst_tag) {
            nlf_invalidate = false;
        }
    } else if self.nlf.get().is_none() {
        nlf_invalidate = false;
    }
    if nlf_invalidate {
        self.nlf = std::sync::OnceLock::new();
    }

    const KHOP_DELTA_BUDGET: usize = 100_000;
    let mut khop_invalidate = true;
    let streaming_handle = self.streaming.clone();
    let reverse_adj_view: &ahash::HashMap<StrId, Vec<StrId>> = &self.reverse_adj;
    let reverse_adj_ptr: *const ahash::HashMap<StrId, Vec<StrId>> = reverse_adj_view;
    if let Some(reach) = self.khop_reach.get_mut() {
        let reverse_adj_safe: &ahash::HashMap<StrId, Vec<StrId>> =
            unsafe { &*reverse_adj_ptr };
        if reach.try_record_edge_delta(
            src_sid,
            &streaming_handle,
            reverse_adj_safe,
            KHOP_DELTA_BUDGET,
        ) {
            khop_invalidate = false;
        }
    } else if self.khop_reach.get().is_none() {
        khop_invalidate = false;
    }
    if khop_invalidate {
        self.khop_reach = std::sync::OnceLock::new();
    }
    self.bump_mutation_version();
}
```

- [ ] **Step 4: Fix C4 — `try_record_edge` returns `false` on out-of-range vertex (defense in depth)**

In `core/graph-engine/src/nlf.rs`, change the tail of `try_record_edge` (lines 130-133):

```rust
        match counts.get_mut(src_sid.index()) {
            Some(row) => {
                row[tag] = row[tag].saturating_add(1);
                true
            }
            // New vertex beyond the table's sized rows: we cannot record
            // it, so signal the caller to rebuild rather than silently
            // keeping a table that is missing this vertex's row (which
            // would wrongly prune it as a hunt start).
            None => false,
        }
```

- [ ] **Step 5: Add the C4 unit test**

In `core/graph-engine/src/nlf.rs` tests module:

```rust
#[test]
fn try_record_edge_out_of_range_forces_rebuild() {
    // Build a tiny NLF sized for 1 vertex, then try to record an edge
    // whose src index is beyond the table — must return false (rebuild).
    let mut nlf = NlfTable::for_capacity(1); // use the real constructor; see existing tests
    let out_of_range = StrId::from_raw(999);
    assert_eq!(nlf.try_record_edge(out_of_range, 0), false);
}
```

> Use whatever constructor the existing `nlf.rs` tests use to build a small table (search the test module for `NlfTable::`). The contract under test is the `false` return for an out-of-range `src_sid`.

- [ ] **Step 6: Run the tests — expect PASS**

Run: `cargo test --manifest-path core/graph-engine/Cargo.toml post_finalize_tail_edge_is_visible_to_khop try_record_edge_out_of_range -- --nocapture`
Expected: PASS. Then run the existing index tests to confirm no regression: `cargo test --manifest-path core/graph-engine/Cargo.toml nlf:: khop_reach::`

- [ ] **Step 7: Commit**

```bash
git add core/graph-engine/src/graph.rs core/graph-engine/src/nlf.rs
git commit -m "fix: invalidate NLF/k-hop on post-finalize append; NLF rebuild on out-of-range start

Incremental deltas read base neighbors only and miss the tail buffer,
producing stale live-tail hunt results (C2). try_record_edge silently
succeeded for out-of-range vertices, wrongly pruning new starts (C4)."
```

---

## Task 2: C3a — fallible streaming push before irreversible mutation

`add_relation` (`graph.rs:413-415`), `insert_triples` (`graph.rs:2997-2999`), and `insert_raw_events` (the mirror block in `graph.rs:3012+`) push the reverse-adjacency edge **before** the fallible `push_to_streaming?`. On `GraphError::Spill` the reverse edge is committed but the forward edge is not → a dangling reverse edge corrupts the live graph (C3a). Reorder so the fallible push happens first.

**Files:**
- Modify: `core/graph-engine/src/graph.rs` (three call sites: `add_relation`, `insert_triples`, `insert_raw_events`)
- Test: `core/graph-engine/src/graph.rs` tests module (uses the existing `with_spill_fail` backend hook referenced in `streaming.rs` tests)

- [ ] **Step 1: Write the failing test**

```rust
#[test]
fn spill_failure_leaves_no_dangling_reverse_edge() {
    // A backend forced to fail its spill on append. add_relation must
    // return Err WITHOUT having pushed the reverse-adjacency edge.
    let mut g = GraphHunter::with_spill_failing_backend(); // see note
    g.add_entity(Entity::new("A", EntityType::User)).unwrap();
    g.add_entity(Entity::new("B", EntityType::Host)).unwrap();
    let res = g.add_relation(Relation::new("A", "B", RelationType::Auth, 100));
    assert!(matches!(res, Err(GraphError::Spill(_))));
    // reverse_adj for B must NOT contain A — the edge never landed.
    let b_sid = g.interner_lookup("B").expect("B interned");
    assert!(g.reverse_adj_for(b_sid).map_or(true, |v| v.is_empty()),
        "reverse edge must not be committed when the forward push failed");
}
```

> Two helpers may need thin test-only accessors if they don't exist: a constructor that installs a spill-failing `InMemoryStreamingBackend` (mirror `with_spill_fail(true)` from `streaming.rs` tests), and read accessors for the interner + `reverse_adj`. Add them as `#[cfg(test)]` if absent. If exposing `reverse_adj` is awkward, assert instead that `g.relation_count()` is unchanged and `streaming_edge_count()` did not grow.

- [ ] **Step 2: Run the test — expect FAIL**

Run: `cargo test --manifest-path core/graph-engine/Cargo.toml spill_failure_leaves_no_dangling_reverse_edge -- --nocapture`
Expected: FAIL — today the reverse edge is pushed before the failing forward push.

- [ ] **Step 3: Reorder in `add_relation` (graph.rs:413-415)**

```rust
        self.push_to_streaming(&compact)?;
        self.reverse_adj.entry(dst_sid).or_default().push(src_sid);
        self.on_streaming_edge_appended(src_sid, dst_sid);
        Ok(())
```

- [ ] **Step 4: Reorder in `insert_triples` (graph.rs:2997-2999)**

```rust
            self.push_to_streaming(&compact)?;
            self.reverse_adj.entry(dst_sid).or_default().push(src_sid);
            self.on_streaming_edge_appended(src_sid, dst_sid);
            new_relations += 1;
```

- [ ] **Step 5: Reorder in `insert_raw_events`**

Open `graph.rs` and find the matching block in `insert_raw_events` (search for the second occurrence of `self.reverse_adj.entry(dst_sid).or_default().push(src_sid);` followed by `self.push_to_streaming(&compact)?;`). Apply the identical swap: `push_to_streaming(&compact)?` first, then the `reverse_adj` push, then `on_streaming_edge_appended`, then the `new_relations += 1`.

> The orphan `meta_store.append` (run earlier to build `compact`) is harmless on failure — an append-only store leaves an unreferenced offset. Document this in a one-line comment above the reordered push.

- [ ] **Step 6: Run tests — expect PASS**

Run: `cargo test --manifest-path core/graph-engine/Cargo.toml spill_failure_leaves_no_dangling_reverse_edge -- --nocapture`
Then regression: `cargo test --manifest-path core/graph-engine/Cargo.toml insert_ add_relation`
Expected: PASS.

- [ ] **Step 7: Commit**

```bash
git add core/graph-engine/src/graph.rs
git commit -m "fix: push streaming edge before reverse_adj so spill failure leaves no dangling edge (C3a)"
```

> **C3b** (the async `GraphWriter` dropping the un-written batch remainder on spill error, `writer.rs:195-198`) requires `OverflowStore` routing and is tracked in the H/O/P follow-ups plan, not here.

---

## Task 3: C5 + C9 — sync ingest enters `Finalizing` and stops clobbering `LiveTail`

The synchronous ingest paths in `operations/ingestion.rs` jump `Loading → Ready` and never set `Finalizing`, so hunts are not rejected during the sync sort/score window (C5). The trailing unconditional `session.set_phase(Ready)` also clobbers a `Ready → LiveTail` transition on re-ingest (C9). Wrap the sort/score region in a `Finalizing` window and make the final transition conditional.

**Files:**
- Modify: `platform/api/src/operations/ingestion.rs` (the three sync `set_phase(Ready)` sites: ~`:473`, `:660`, `:775`, and the `run_full_scoring` blocks that precede them)
- Test: `platform/api/src/operations/ingestion.rs` tests or `platform/api/tests/`

- [ ] **Step 1: Write the failing test**

Mirror the existing `hunt_rejected_while_finalizing` test (in `operations/hunt.rs`) but drive it through a sync ingest: assert that a hunt issued while a sync ingest holds the session in `Finalizing` returns `ApiError::Conflict`. If a deterministic mid-ingest hook is impractical, instead unit-test a small extracted helper:

```rust
#[test]
fn finalize_transition_does_not_clobber_live_tail() {
    let session = /* build a Ready+finalized session, see session.rs tests */;
    session.set_phase(SessionPhase::LiveTail);
    // The post-ingest transition must NOT force Ready over an active LiveTail.
    finalize_phase_after_ingest(&session); // helper introduced in Step 3
    assert_eq!(session.phase(), SessionPhase::LiveTail);
}
```

- [ ] **Step 2: Run — expect FAIL**

Run: `cargo test --manifest-path platform/api/Cargo.toml finalize_transition_does_not_clobber_live_tail -- --nocapture`
Expected: FAIL — `finalize_phase_after_ingest` does not exist yet / current code force-sets `Ready`.

- [ ] **Step 3: Introduce a shared phase-finalize helper**

In `operations/ingestion.rs`, add near the existing `note_post_finalize_appends` free function:

```rust
/// Final phase transition after a synchronous ingest completes.
/// Sets `Ready` from a load/finalize state, but never downgrades an
/// active `LiveTail` (post-finalize re-ingest stays in LiveTail).
fn finalize_phase_after_ingest(session: &Session) {
    match session.phase() {
        crate::state::SessionPhase::LiveTail => {} // keep live tail
        _ => session.set_phase(crate::state::SessionPhase::Ready),
    }
}
```

- [ ] **Step 4: Wrap each sync ingest write/score region in a `Finalizing` window**

At each sync site, set `Finalizing` immediately before the `graph.write()` block that runs `insert_*` + `run_full_scoring`, and replace the trailing `session.set_phase(SessionPhase::Ready)` with `finalize_phase_after_ingest(&session)`. Pattern (apply at `:473`, `:660`, `:775` regions):

```rust
        session.set_phase(crate::state::SessionPhase::Finalizing);
        let (new_entities, new_relations, /* ... */) = {
            let mut graph = session.graph.write().map_err(/* ... */)?;
            // insert_* + run_full_scoring(&mut graph) as today
        };
        // ... datasets / totals as today ...
        note_post_finalize_appends(&session, new_relations); // already relocated (C1)
        finalize_phase_after_ingest(&session);
```

> Order matters: `note_post_finalize_appends` (which may set `LiveTail`) must run **before** `finalize_phase_after_ingest` (which preserves `LiveTail`). On a first load the graph is not yet finalized, so `note_post_finalize_appends` no-ops and `finalize_phase_after_ingest` sets `Ready`.

- [ ] **Step 5: Run tests — expect PASS**

Run: `cargo test --manifest-path platform/api/Cargo.toml finalize_transition_does_not_clobber_live_tail ingestion:: -- --nocapture`
Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add platform/api/src/operations/ingestion.rs
git commit -m "fix: sync ingest enters Finalizing and preserves LiveTail on completion (C5, C9)"
```

---

## Task 4: C6 — gate the AI `run_hunt` tool by session phase

The AI tool dispatcher (`operations/ai.rs:455`) calls `graph.search_temporal_pattern` directly, bypassing the `ensure_huntable_phase` gate every other hunt entrypoint uses.

**Files:**
- Modify: `platform/api/src/operations/hunt.rs:72` (make `ensure_huntable_phase` `pub(crate)`)
- Modify: `platform/api/src/operations/ai.rs` (check phase before the `run_hunt` arm)

- [ ] **Step 1: Write the failing test**

In `operations/ai.rs` tests (or `platform/api/tests/`):

```rust
#[test]
fn ai_run_hunt_rejected_while_finalizing() {
    // Build a session in Finalizing phase, invoke the AI tool dispatcher
    // with a run_hunt tool call, assert it returns the Conflict message.
    // (Mirror the harness of the existing ai.rs tool-call tests.)
    let session = /* Finalizing session */;
    let err = run_ai_tool_call_for_test(&session, "run_hunt", /* dsl */ "...");
    assert!(err.unwrap_err().contains("finaliz"));
}
```

- [ ] **Step 2: Run — expect FAIL**

Run: `cargo test --manifest-path platform/api/Cargo.toml ai_run_hunt_rejected_while_finalizing -- --nocapture`
Expected: FAIL — the AI path runs the hunt regardless of phase.

- [ ] **Step 3: Expose the gate**

In `operations/hunt.rs:72`, change `fn ensure_huntable_phase` to `pub(crate) fn ensure_huntable_phase`.

- [ ] **Step 4: Gate the AI dispatcher**

In `operations/ai.rs`, the tool-dispatch function has access to the resolved `Session` (it resolves the graph from it). Before executing the `"run_hunt"` arm (line 455), add:

```rust
        "run_hunt" => {
            crate::operations::hunt::ensure_huntable_phase(session.phase())
                .map_err(|e| e.to_string())?;
            // ... existing dsl parse + search ...
```

> If the dispatch function only holds a `&GraphHunter` and not the `Session`, thread the `SessionPhase` (a `Copy` enum) in from the caller that already owns the session, and check it here. Find the caller by searching `ai.rs` for where the graph lock is acquired for tool dispatch.

- [ ] **Step 5: Run tests — expect PASS**

Run: `cargo test --manifest-path platform/api/Cargo.toml ai_run_hunt_rejected_while_finalizing ai:: -- --nocapture`
Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add platform/api/src/operations/hunt.rs platform/api/src/operations/ai.rs
git commit -m "fix: gate AI run_hunt tool by session phase (C6)"
```

---

## Task 5: C7 — monotonic clock for the circuit breaker

`CircuitBreaker::now_millis` (`source_poller.rs:89-94`) reads `SystemTime` (wall clock); an NTP step skews the backoff window. Switch to a process-monotonic baseline. All stored `circuit_open_until` values become monotonic-millis consistently, so only `now_millis` changes.

**Files:**
- Modify: `core/graph-engine/src/ingest/source_poller.rs:89-94`
- Test: `core/graph-engine/src/ingest/source_poller.rs` tests

- [ ] **Step 1: Write the failing test (recovery + monotonic intent)**

The existing tests cover open-after-N and skip-while-open. Add a recovery test (also closes the C-track test gap):

```rust
#[tokio::test]
async fn circuit_recovers_after_success() {
    let metrics = PollerMetrics::default();
    let breaker = CircuitBreaker::new(3, Duration::from_millis(10));
    for _ in 0..3 { breaker.record_failure(&metrics); }
    assert!(CircuitBreaker::is_open(&metrics));
    // Wait out a short backoff using the monotonic clock, then succeed.
    tokio::time::sleep(Duration::from_millis(20)).await;
    breaker.record_success(&metrics);
    assert!(!CircuitBreaker::is_open(&metrics));
    assert_eq!(metrics.circuit_consecutive_failures.load(Ordering::Relaxed), 0);
}
```

- [ ] **Step 2: Run — expect PASS or FAIL**

Run: `cargo test --manifest-path core/graph-engine/Cargo.toml circuit_recovers_after_success -- --nocapture`
Expected: likely PASS on the logic, but it currently rides wall-clock time. Proceed to make the clock monotonic regardless (the bug is correctness-under-clock-step, not directly observable in a fast test).

- [ ] **Step 3: Make `now_millis` monotonic**

Replace `source_poller.rs:89-94`:

```rust
    fn now_millis() -> i64 {
        use std::sync::OnceLock;
        use std::time::Instant;
        // Monotonic process baseline: immune to wall-clock / NTP steps,
        // which previously let an SystemTime jump widen or collapse the
        // circuit-breaker backoff window.
        static START: OnceLock<Instant> = OnceLock::new();
        START.get_or_init(Instant::now).elapsed().as_millis() as i64
    }
```

Remove the now-unused `SystemTime`/`UNIX_EPOCH` import from this file if no other code uses it (search the file first).

- [ ] **Step 4: Run tests — expect PASS**

Run: `cargo test --manifest-path core/graph-engine/Cargo.toml source_poller:: circuit_ -- --nocapture`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add core/graph-engine/src/ingest/source_poller.rs
git commit -m "fix: monotonic clock for circuit breaker backoff (C7); add recovery test"
```

---

## Task 6 (optional): C8 — make the hunt phase gate non-advisory

The phase is read at hunt entry (`hunt.rs:104,318`) then released before the graph read lock is taken; a background `set_phase(Finalizing)` can land in the gap. Low likelihood (the finalize write lock blocks the hunt's read lock), so this is optional hardening.

**Files:**
- Modify: `platform/api/src/operations/hunt.rs` (re-check inside the read-lock scope) **or** add a doc comment declaring the graph lock the serialization point.

- [ ] **Step 1: Decision** — either re-check `session.phase()` immediately after acquiring `session.graph.read()` in `run_hunt`/`run_hunt_batch`, returning `Conflict` if no longer huntable; or add a comment at `hunt.rs:104` documenting that the graph read lock (held for the whole search) is the true serialization point and the phase check is an early-out only.
- [ ] **Step 2: If re-checking, add a test** that flips phase between the entry check and lock acquisition (use a barrier) and asserts the second check rejects.
- [ ] **Step 3: Commit** `fix: re-validate session phase under hunt read lock (C8)` (skip if documenting only).

---

## Acceptance checklist (Track C)

- [ ] Post-finalize append invalidates NLF + k-hop; a hunt afterward reflects tail edges (T1).
- [ ] `try_record_edge` returns `false` for out-of-range start vertices (T1).
- [ ] Spill failure on append leaves no dangling reverse edge / no relation-count drift (T2).
- [ ] Sync ingest enters `Finalizing`; hunts rejected during it; `LiveTail` not clobbered (T3).
- [ ] AI `run_hunt` rejected during `Loading`/`Finalizing` (T4).
- [ ] Circuit breaker uses a monotonic clock; recovery test passes (T5).
- [ ] `cargo test --manifest-path core/graph-engine/Cargo.toml` and `--manifest-path platform/api/Cargo.toml` both green.

## Final verification

```bash
cargo test --manifest-path core/graph-engine/Cargo.toml
cargo test --manifest-path platform/api/Cargo.toml
```
Expected: PASS. Track C is the merge gate — do not proceed to Tracks H/O/P until this is green.
