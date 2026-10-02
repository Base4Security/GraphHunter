# Close the SOT `ingestion_time` blind channel Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Close the audit's `ingestion_time` blind channel by stamping a real ingestion timestamp on graph edges (instead of the hardcoded `0`), making it readable, and re-freezing the audit to `fidelity: full` — flipping `ingestion_time` out of `loss_reconstruction`'s blind set (the witness shifts to `provenance_stability`; `loss_reconstruction` stays `InsufficientWithWitness`, NOT Sufficient).

**Architecture:** The graph edge carries `ingested_at_delta: u32` = seconds since `INGEST_EPOCH_BASE` (2024-01-01), encoded by `encode_ingested_at`. Five mass-ingest sites in `core/graph-engine/src/graph.rs` hardcode it to `0`; only the unused `add_relation` stamps `encode_ingested_at(now_seconds())`. The audit channel's witness `same_observed` is literally "identical edge (ingested_at_delta hardcoded 0)", so the channel cannot honestly close until those `0`s become a real receive-time AND the value is observable. Chosen approach (recon Option (i), uniform, earns an honest `full` for the `late_arrival` context — vs the envelope-threading Option (ii) which only earns `degraded` due to partial/flag-gated coverage): stamp `encode_ingested_at(now_seconds())` (GraphHunter's receive/insert clock) at every mass-ingest site, preserve it across `compact_before` (which today resets to 0), and expose it on the materialized `Relation` so it's reconstructable.

**Tech Stack:** Rust (`graph_hunter_core` — ort-free, tests RUN), Python audit runner (sot repo).

## Global Constraints

- **Honest fidelity, honest note.** The re-freeze grades `ingestion_time` `full` ONLY because all three conditions hold: (1) a real receive-time replaces the literal `0` at every mass-ingest site, (2) it survives `compact_before`, (3) it is readable on the materialized `Relation`. The `ingest_surface.json` note MUST disclose the boundaries: the stamp is **GraphHunter's receive/insert clock (wall-clock `now`)**, not the upstream source's own ingestion timestamp; and it is **not reproducible across a from-scratch rebuild** (a rebuild re-stamps `now` at rebuild time) — threading the journal envelope's frozen `ingestion_time` for full journal-reproducibility is named as future work. Do NOT claim more than "the edge now records a real receive-time distinct from event_time, readable, breaking the hardcoded-0 witness."
- **Do NOT overclaim `loss_reconstruction`.** After this flip, `loss_reconstruction` is STILL `InsufficientWithWitness` — `provenance_stability` (degraded) remains blind and becomes the new lead witness. Every doc/note/user-facing statement must say `ingestion_time` closed and the `loss_reconstruction` witness SHIFTED to provenance, not that `loss_reconstruction` is Sufficient.
- **The 30 catalog hypotheses are unaffected.** `ingestion_time` is not one of the 7 `HYPOTHESIS_REQUIRES` channels (it is transversal-only, required by `loss_reconstruction`). The frozen `audit_results.json` must still show 30/30 `Sufficient` and `exhaustiveness_marking` `Sufficient` after the re-freeze — verify this, do not let it regress.
- **`now_seconds()` once per call, not per edge.** Compute the ingestion timestamp once at the top of each insert function and reuse it for every edge in that call — avoids a per-edge syscall and gives a batch one consistent ingestion instant (matching the envelope model). Never call `now_seconds()` inside the per-edge loop.
- **Determinism / equivalence:** stamping `now` makes `ingested_at` non-deterministic across a rebuild — that is ACCEPTED. The incremental-vs-rebuild comparator already marks `mvcc_ingested_at` as `NotComparable` and MUST keep doing so (update its reason text; do NOT start comparing `ingested_at` in the edge multiset — the edge-equality key must NOT include it, or the equivalence certificate breaks).
- **MANIFEST via git-blob only** (sot repo): never `write_manifest.py` (corrupts entries under autocrlf). Compute sha256 of `git cat-file blob :<path>` after `git add`.
- **No unrelated WIP.** Both repos carry heavy WIP. Never `git add -A`; stage only each task's named files.

---

### Task 1: Stamp a real ingestion time at the mass-ingest sites + preserve across compaction

**Files:**
- Modify: `core/graph-engine/src/graph.rs` (the 5 `ingested_at_delta: 0` sites)
- Test: `core/graph-engine/tests/mvcc_ingested_at.rs` (update expectations) + any `--lib` test asserting `ingested_at_delta == 0` / `ingested_at() == INGEST_EPOCH_BASE`

**Interfaces:**
- Consumes: `encode_ingested_at(now_seconds()) -> u32` (`relation.rs:169`, `graph.rs:41`); `CompactRelation::ingested_at() -> i64` (`relation.rs:152`); `INGEST_EPOCH_BASE`.
- Produces: every mass-ingest-created edge carries `ingested_at_delta = encode_ingested_at(now_seconds())`; `compact_before` preserves the source edge's existing delta.

- [ ] **Step 1: Write/adjust the failing test — a freshly ingested edge has a real (non-zero-base) ingestion time**

In `mvcc_ingested_at.rs` (read it first — it currently likely asserts the base/0). Add/adjust:

```rust
#[test]
fn ingested_edges_carry_a_real_receive_time_not_the_epoch_base() {
    let mut g = GraphHunter::new();
    // ingest one event via insert_raw_events (or insert_triples) ...
    let before = now_seconds();
    // ... perform the insert ...
    let after = now_seconds();
    let rels = g.get_compact_relations(/* source sid */);
    let ts = rels[0].ingested_at();
    assert!(ts >= before && ts <= after, "ingested_at should be ~now, got {ts} (base={INGEST_EPOCH_BASE})");
    assert!(ts > INGEST_EPOCH_BASE, "must not be the hardcoded-0 epoch base");
}
```

Match the real accessor names (`get_compact_relations`/`get_relations_by_sid`) and construct the insert the way existing tests in this file do.

- [ ] **Step 2: Run — fail (currently stamps 0 → reads epoch base)**

Run: `cd core/graph-engine && cargo test --test mvcc_ingested_at ingested_edges_carry_a_real_receive_time`
Expected: FAIL — reads `INGEST_EPOCH_BASE`.

- [ ] **Step 3: Stamp real ingestion time at the 4 mass-ingest sites + preserve at compact_before**

At each of `graph.rs:2685` (`ingest_logs_with_policy`), `:3051` (`ingest_logs_chunked`), `:3180` (`insert_triples`), `:3270` (`insert_raw_events`): compute `let ingested_at_delta = encode_ingested_at(now_seconds());` ONCE at the top of the function (before the edge loop) and use it in the `CompactRelation { … ingested_at_delta, … }` literal instead of `0`.
At `graph.rs:3528` (`compact_before`, the rebuild/compaction path): this rebuilds edges from existing ones — PRESERVE the source edge's `ingested_at_delta` (carry the old value) instead of resetting to `0`. Read the surrounding code to get the source edge in scope; if the source is a `CompactRelation`/`StreamEdge`, copy its `ingested_at_delta` field directly (do NOT re-`encode` `now` — that would erase the original receive time on every compaction).

- [ ] **Step 4: Run — pass + full engine suite**

Run: `cd core/graph-engine && cargo test --test mvcc_ingested_at` then `cargo test --lib`
Expected: green. Fix any other test that asserted `ingested_at_delta == 0` / `ingested_at() == INGEST_EPOCH_BASE` to the new reality (a real receive time). List each such test you touched in the report.

- [ ] **Step 5: Commit**

```bash
git add core/graph-engine/src/graph.rs core/graph-engine/tests/mvcc_ingested_at.rs
git commit -m "feat(graph): stamp real ingestion time on edges (was hardcoded 0); preserve across compaction"
```

(Stage any other test file you had to update too.)

---

### Task 2: Expose `ingested_at` on the materialized `Relation` (read-back) + fix the stale comparator note

**Files:**
- Modify: `core/graph-engine/src/relation.rs` (`Relation` struct) + `core/graph-engine/src/graph.rs` (`materialize_relation`)
- Modify: `platform/api/src/journal.rs` (the `mvcc_ingested_at` NotComparable reason text)
- Test: engine `--lib` + `platform/api` parity

**Interfaces:**
- Consumes: `CompactRelation::ingested_at() -> i64`.
- Produces: `Relation` gains `ingested_at: i64` (epoch seconds), populated by `materialize_relation`; the value is now observable on the primary export/hunt path.

- [ ] **Step 1: Write the failing test — a materialized Relation exposes the ingestion time**

```rust
#[test]
fn materialized_relation_exposes_ingestion_time() {
    let mut g = GraphHunter::new();
    // ingest one event ...
    let rels = g.get_relations(/* source id */);   // returns Vec<Relation>
    assert!(rels[0].ingested_at > INGEST_EPOCH_BASE, "materialized Relation must carry a real ingested_at");
}
```

- [ ] **Step 2: Run — fail (Relation has no `ingested_at`)**

Run: `cd core/graph-engine && cargo test --lib materialized_relation_exposes_ingestion_time`
Expected: FAIL to compile — `Relation` has no such field.

- [ ] **Step 3: Add the field + populate in `materialize_relation`**

Add `pub ingested_at: i64` to `Relation` (`relation.rs:31-45`). In `materialize_relation` (`graph.rs:660-674`) set `ingested_at: compact.ingested_at()` from the source `CompactRelation`. For serialization: add the field additively; if `Relation` derives `Serialize`, guard with a sensible default so existing wire consumers don't break (or accept the additive field — verify against `platform/api` parity in Step 4). Update every OTHER constructor of `Relation` in the tree to set the new field (grep `Relation {` — the compiler will list them); for non-ingest constructors use `INGEST_EPOCH_BASE` (0-delta) or the real value if available.

- [ ] **Step 4: Fix the stale comparator note + run parity**

In `platform/api/src/journal.rs` the `mvcc_ingested_at` dimension is `NotComparable` with reason "ingested_at_delta is hardcoded 0 on both raw-event paths". That is now FALSE. Update the reason to the truth: e.g. "ingested_at is GraphHunter's receive clock (wall-clock at insert), so it genuinely differs between a live graph and a from-scratch rebuild; the comparator does not compare it — NotComparable, not a diff." Keep `mvcc_ingested_at` `NotComparable` (do NOT start comparing it). Ensure the edge-equality key in `compare_observable_equality` does NOT include `ingested_at` (confirm the certificate still passes).

Run: `cd core/graph-engine && cargo test --lib` then `cd ../../platform/api && cargo test --lib journal::` and `cargo test --test parity` and `cargo test --test incremental_rebuild_validation`.
Expected: all green (the equivalence certificate still holds — `ingested_at` is not compared; parity accommodates the additive field).

- [ ] **Step 5: Commit**

```bash
git add core/graph-engine/src/relation.rs core/graph-engine/src/graph.rs platform/api/src/journal.rs
git commit -m "feat(graph): expose ingested_at on materialized Relation (read-back); correct stale mvcc NotComparable note"
```

(Stage any other files whose `Relation {` literals you had to update.)

---

### Task 3: Re-freeze the audit — `ingestion_time` → full, verify the honest verdict shift

**Files:**
- Modify (sot repo): `C:\Users\lsotomayor\sot\validation\graphhunter\ingest_surface.json` (the `ingestion_time` channel)
- Regenerate (sot repo): `validation/graphhunter/audit_results.json` (via the runner) + `MANIFEST.sha256`

**Interfaces:**
- Consumes: Task 1+2's committed GraphHunter code (cite file:line as the evidence in the note).
- Produces: `ingestion_time` `fidelity: full`; `loss_reconstruction` blind set drops `ingestion_time`, witness shifts to `provenance_stability`, status stays `InsufficientWithWitness`; 30/30 catalog + `exhaustiveness_marking` unchanged.

- [ ] **Step 1: Flip the fidelity + write the honest note**

In `ingest_surface.json`, set the `ingestion_time` channel `"fidelity": "full"` and rewrite `note` to the evidence + boundaries (per Global Constraints): the 5 sites now stamp `encode_ingested_at(now_seconds())` (cite `graph.rs` sites), preserved across `compact_before`, readable via `Relation.ingested_at` / `CompactRelation::ingested_at()` (cite `relation.rs`, `materialize_relation`); boundaries: it is GraphHunter's receive clock (not the upstream source's ingestion timestamp) and is not journal-reproducible across a from-scratch rebuild (rebuild re-stamps `now`) — envelope-`ingestion_time` threading for full reproducibility is future work. Keep the `fix` field pointing at that future work. Do NOT touch `provenance_stability` (stays `degraded`).

- [ ] **Step 2: Re-run the runner + verify the honest flip**

```bash
cd /c/Users/lsotomayor/sot
python scripts/sot_sys/audit_graphhunter.py            # regenerate audit_results.json
python scripts/sot_sys/audit_graphhunter.py --check    # confirm up to date
```
Then INSPECT `audit_results.json`:
- `loss_reconstruction`: status STILL `InsufficientWithWitness`; `blind_channels` now = `provenance_stability` ONLY (ingestion_time removed); the `witness` is now the `provenance_stability` (mapping_edit) one.
- All 30 `cat-*`: STILL `Sufficient`, empty blind_channels. `exhaustiveness_marking`: STILL `Sufficient`.
If `loss_reconstruction` unexpectedly flips to `Sufficient`, STOP — that means `provenance_stability` was mis-declared; do not proceed.

- [ ] **Step 3: Regenerate MANIFEST (git-blob procedure) + commit**

Stage the two changed files, compute their sha256 via `git cat-file blob :<path>`, update `MANIFEST.sha256` for `validation/graphhunter/ingest_surface.json` and `validation/graphhunter/audit_results.json` (git-blob only, NOT write_manifest.py), then:

```bash
cd /c/Users/lsotomayor/sot
git add validation/graphhunter/ingest_surface.json validation/graphhunter/audit_results.json MANIFEST.sha256
git commit -m "GraphHunter audit: ingestion_time -> full (real receive-time stamp); loss_reconstruction witness shifts to provenance_stability"
```

---

### Task 4: Document the closure honestly

**Files:**
- Modify: `docs/architecture/incremental-correctness.md` (or the audit md) — a short "ingestion_time closed" section

- [ ] **Step 1: Write the section**

Document, honestly: the 5 sites now stamp a real receive-time (was 0); preserved across compaction; readable via `Relation.ingested_at`. The audit flip: `ingestion_time` → `full`, so it leaves `loss_reconstruction`'s blind set — but **`loss_reconstruction` stays `InsufficientWithWitness`**, the witness having shifted to `provenance_stability` (degraded), which is the remaining work to make that transversal Sufficient. Boundaries: receive-clock not source-ingestion-clock; not journal-reproducible across rebuild (mvcc_ingested_at stays NotComparable in the equivalence certificate); 30/30 catalog unaffected (ingestion_time is transversal-only).

- [ ] **Step 2: Commit**

```bash
git add docs/architecture/incremental-correctness.md
git commit -m "docs: ingestion_time channel closed (real receive-time); loss_reconstruction still Insufficient on provenance_stability"
```

---

## Self-Review notes

- **The one non-negotiable:** the audit `same_observed` is defined against `ingested_at_delta hardcoded 0`, so the code change (Task 1) is a HARD precondition for the flip (Task 3) — the flip is dishonest without it. The read-back (Task 2) is what earns "full" over "degraded" (observable/reconstructable).
- **No overclaim:** `loss_reconstruction` stays Insufficient (provenance_stability). 30/30 catalog unchanged. `ingested_at` is non-deterministic across rebuild (accepted; mvcc stays NotComparable; not in the edge-equality key).
- **Whole-phase review must scrutinize the `full` grade** the way it scrutinized `source_coverage`'s flip — is receive-clock-wall-now honestly `full` for the `late_arrival` witness, or should it be `degraded`? Route that question to the reviewer explicitly.
