# Enable SOT defaults + journal rotation Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Turn the 4 SOT feature flags ON by default in production — but responsibly: first bound the append-only journal with size-based rotation/retention (so `GRAPHHUNTER_JOURNAL` default-on cannot fill the disk), then invert all 4 flag defaults (off→on, keeping each flag as a falsy-to-disable escape hatch), fix the ~15 default-off test assertions, and update the audit channel-note disclosures that say "default off".

**Architecture:** The journal is a single unbounded append-only `journal.jsonl` (`JournalStore`, `platform/api/src/journal.rs`). Add size-based rotation: when the active file would exceed `GRAPHHUNTER_JOURNAL_MAX_BYTES` (default 256 MiB), rotate it to `journal.jsonl.1` (replacing any prior `.1`) and start fresh — bounding total journal disk to ~2× the cap. `read_all`/`count` span `.1` + the active file so the retained window (used by rebuild-from-journal + crash-reingest dedup) stays readable; records older than the retained window are pruned (the disclosed retention tradeoff). Then the 4 flag predicates (`journal_enabled`, `graphdelta_enabled`, `coverage_enabled`, `source_coverage_enabled`) flip to default-ON / falsy-to-disable — the exact inverse of today, matching the `kql_escape_hatch_enabled`/`hunting_templates_enabled` house pattern.

**Tech Stack:** Rust (`graph_hunter_api` — ort-free, tests RUN), Python audit runner (sot repo, for the note re-freeze).

## Global Constraints

- **Journal bound is a HARD precondition for the JOURNAL/GRAPHDELTA default flip.** Do not flip `journal_enabled`/`graphdelta_enabled` to default-on (Task 2) until rotation (Task 1) is in place and tested — an unbounded journal on the default path is a disk-fill hazard.
- **Rotation must not lose data within the retained window, and must never corrupt.** `read_all` must return the full retained window in chronological order (`.1` then active). A crash mid-rotation must leave a readable journal (rotate = rename active→.1 then create fresh; rename is atomic on the same filesystem; never delete the active file before the rename succeeds). Disclose the retention semantics: full from-scratch rebuild only covers the retained window (recent), not all-time history — which is fine for crash-reingest dedup and small-dataset equivalence, the journal's actual uses.
- **`GRAPHHUNTER_JOURNAL_MAX_BYTES` env-configurable, sane default (256 MiB).** Parse defensively (bad value → default). Document it.
- **Default flip is a clean predicate inversion.** After Task 2: unset env → enabled; explicit falsy (`0/false/no/off`) → disabled. Byte-identical semantics to the escape-hatch flags, just applied to these 4. Keep the flags (do not delete them) — they remain the disable escape hatch.
- **No-op-when-off tests become explicit-off tests.** The ~15 assertions that today rely on the DEFAULT being off must set the flag explicitly off (or assert the new default-on). Do NOT delete the coverage — invert it so the disable path stays tested. Add/keep a `defaults_on` assertion for each flag.
- **Audit note consistency:** channel notes in `sot/validation/graphhunter/ingest_surface.json` that disclose "Behind GRAPHHUNTER_X (default off)" become stale — update them to "default on (falsy-to-disable)". This does NOT change any verdict (the closures now hold on the DEFAULT path — a strengthening, not a regression); re-freeze `audit_results.json` + MANIFEST (git-blob). Verify 30/30 + both transversals still Sufficient.
- **No unrelated WIP; never `git add -A`.** MANIFEST via git-blob only.

---

### Task 1: Bound the journal with size-based rotation/retention

**Files:**
- Modify: `platform/api/src/journal.rs` (`JournalStore` + a `MAX_JOURNAL_BYTES` reader)
- Test: the journal.rs test module

**Interfaces:**
- Consumes: `JournalStore { path: PathBuf }` (`journal.rs:20`), `append` (`:34`), `read_all` (`:44`), `count` (`:62`), `JOURNAL_FILE = "journal.jsonl"` (`:18`).
- Produces: `journal_max_bytes() -> u64` (env `GRAPHHUNTER_JOURNAL_MAX_BYTES`, default `256 * 1024 * 1024`); rotation inside `append`; `read_all`/`count` span the rotated segment + the active file.

- [ ] **Step 1: Write failing tests**

```rust
#[test]
fn journal_rotates_at_cap_and_read_all_spans_segments() {
    let dir = tempfile::tempdir().unwrap();
    // Force a tiny cap for the test (env), so a few appends trigger rotation.
    let _g = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    unsafe { std::env::set_var("GRAPHHUNTER_JOURNAL_MAX_BYTES", "300"); }
    let j = JournalStore::open(dir.path()).unwrap();
    for i in 0..20 { j.append(&env(&format!("row-{i}"), i, i*10)).unwrap(); }
    unsafe { std::env::remove_var("GRAPHHUNTER_JOURNAL_MAX_BYTES"); }
    // A rotated segment exists AND read_all returns ALL 20 in order (spans .1 + active).
    assert!(dir.path().join("journal.jsonl.1").exists(), "expected a rotated segment");
    let all = j.read_all().unwrap();
    assert_eq!(all.len(), 20, "read_all must span the rotated segment + active file");
    assert_eq!(all[0].raw_payload, "row-0");
    assert_eq!(all[19].raw_payload, "row-19");
    assert_eq!(j.count().unwrap(), 20);
}

#[test]
fn journal_retention_bounds_disk_to_two_segments() {
    // With a tiny cap and many appends, only the active file + one .1 exist
    // (older data pruned) — total on-disk stays ~2x cap, not unbounded.
    let dir = tempfile::tempdir().unwrap();
    let _g = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    unsafe { std::env::set_var("GRAPHHUNTER_JOURNAL_MAX_BYTES", "300"); }
    let j = JournalStore::open(dir.path()).unwrap();
    for i in 0..200 { j.append(&env(&format!("r{i}"), i, i)).unwrap(); }
    unsafe { std::env::remove_var("GRAPHHUNTER_JOURNAL_MAX_BYTES"); }
    // No .2 / older segments — retention keeps only active + .1.
    assert!(!dir.path().join("journal.jsonl.2").exists());
    let bytes: u64 = std::fs::read_dir(dir.path()).unwrap()
        .filter_map(|e| e.ok()).map(|e| e.metadata().unwrap().len()).sum();
    assert!(bytes < 300 * 3, "journal disk must stay bounded (~2x cap), got {bytes}");
}
```

Reuse the existing `env(...)` test helper + `ENV_LOCK`.

- [ ] **Step 2: Run — fail (no rotation yet)**

Run: `cd platform/api && cargo test --lib journal::tests::journal_rotates journal_retention`
Expected: FAIL — no `.1` segment; unbounded growth.

- [ ] **Step 3: Implement rotation + segment-spanning reads**

- Add `fn journal_max_bytes() -> u64` (env `GRAPHHUNTER_JOURNAL_MAX_BYTES`, default `256*1024*1024`, bad/absent → default).
- In `append`: before/after writing, check the active file size; when it exceeds the cap, rotate — `rename(journal.jsonl, journal.jsonl.1)` (removing any existing `.1` first, or letting rename replace it), then the next `append` recreates `journal.jsonl`. Ensure the just-appended record isn't lost (rotate BEFORE writing when the current size already ≥ cap, so the new line starts the fresh file; the rename preserves the full prior file as `.1`). Never delete the active file except via the atomic rename.
- In `read_all` and `count`: if `journal.jsonl.1` exists, read it FIRST (older), then the active file (newer), concatenating in chronological order.
- Keep single-segment behavior (no `.1`) byte-identical to today when under the cap.

- [ ] **Step 4: Run — pass + full journal suite**

Run: `cd platform/api && cargo test --lib journal::`
Expected: all green — rotation + retention tests pass; the existing append/read/rebuild/idempotent/equivalence tests still pass (they operate under the cap, single-segment, unchanged).

- [ ] **Step 5: Commit**

```bash
git add platform/api/src/journal.rs
git commit -m "feat(journal): size-based rotation + retention (GRAPHHUNTER_JOURNAL_MAX_BYTES, default 256MiB) so default-on cannot fill disk"
```

---

### Task 2: Flip the 4 SOT flag defaults off→on

**Files:**
- Modify: `platform/api/src/journal.rs` (`journal_enabled` :77, `graphdelta_enabled` :256)
- Modify: `platform/api/src/coverage.rs` (`coverage_enabled` :18, `source_coverage_enabled` :101)
- Test: the flag-predicate tests in both files

**Interfaces:**
- Produces: all 4 predicates return `true` when the env var is unset; `false` only on an explicit falsy value (`0/false/no/off`, case-insensitive, trimmed) — the inverse of today, matching `kql_escape_hatch_enabled` (`http/escape_hatch.rs`).

- [ ] **Step 1: Invert the flag-default tests**

For each of the 4, update its `*_defaults_off` test to `*_defaults_on` (unset env → `true`), keep/adjust the truthy/falsy tests so an explicit falsy value → `false`. Mirror `flag_defaults_enabled_and_respects_explicit_falsy` exactly.

- [ ] **Step 2: Run — fail (still default-off)**

Run: `cd platform/api && cargo test --lib journal_enabled coverage_enabled source_coverage graphdelta`
Expected: FAIL — the new `defaults_on` assertions fail against the current default-off predicates.

- [ ] **Step 3: Invert the 4 predicates**

Change each predicate body to the default-on / falsy-to-disable form (copy the exact match from `escape_hatch.rs:15-23`): `match std::env::var("GRAPHHUNTER_X") { Ok(v) => !matches!(v.trim().to_ascii_lowercase().as_str(), "0"|"false"|"no"|"off"), Err(_) => true }`. Update each predicate's doc comment ("Default OFF" → "Default ON — falsy-to-disable"). Note `graphdelta_enabled` still additionally requires `journal_enabled()` at its call sites (unchanged — both now default-on, so the combined path is on by default).

- [ ] **Step 4: Run — flag tests pass**

Run: `cd platform/api && cargo test --lib journal_enabled coverage_enabled source_coverage graphdelta`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add platform/api/src/journal.rs platform/api/src/coverage.rs
git commit -m "feat(sot): flip GRAPHHUNTER_JOURNAL/GRAPHDELTA/COVERAGE/SOURCE_COVERAGE to default-on (falsy-to-disable)"
```

---

### Task 3: Fix the default-off ripple across the suite

**Files:**
- Modify: the ~10 files with default-off assertions (from `grep`): `platform/api/src/{coverage.rs, journal.rs, operations/hunt.rs, operations/ingestion.rs, sentinel_connector.rs, dto/v1/hunt.rs, ...}`, `platform/api/tests/real_hunt_demo.rs`, and any other test that assumed a flag was off by default.

**Interfaces:**
- Consumes: the now-default-on predicates.
- Produces: every test that relied on the default being off now sets the flag explicitly off (to keep testing the disable path) or is updated to the default-on expectation; the SOT-behavior tests that were "flag on" still pass (they set it on explicitly — now redundant but harmless).

- [ ] **Step 1: Find + triage every default-off assumption**

`grep -rn "assert!(!.*_enabled())\|defaults_off\|off_by_default\|no.op.*off"` across `platform/api` + `core/graph-engine`. For EACH: does it test the DISABLE path (then set the env var explicitly falsy so it still exercises disable) or assume the default (then flip the expectation to default-on)? A test named `..._off_omits/records_nothing/no_op...` should now explicitly `set_var(flag, "0")` around the body (serialized via the env lock) so the disable path stays covered.

- [ ] **Step 2: Apply the inversions + run the whole suite**

Update each site. Then run: `cd platform/api && cargo test` (lib + all integration tests) and `cd ../../core/graph-engine && cargo test --lib` (bounded — filter to affected tests if the full run is too slow). Fix every failure that is a default-assumption (NOT the 2 known pre-existing unrelated failures: `graph_meta_integration` deferred-panic + `agentic_ambiguous_fields` missing fixture — leave those). Report the full green counts.

- [ ] **Step 3: Commit**

```bash
git add <the files you changed>
git commit -m "test(sot): invert default-off assumptions to default-on; disable-path tests now set the flag explicitly off"
```

---

### Task 4: Update audit note disclosures ("default off" → "default on") + doc + re-freeze

**Files:**
- Modify (sot repo): `validation/graphhunter/ingest_surface.json` (channel notes mentioning "default off"); regenerate `audit_results.json` + `MANIFEST.sha256`
- Modify: `docs/architecture/incremental-correctness.md` (a short "SOT enabled by default" section)

- [ ] **Step 1: Update the stale "default off" disclosures**

In `ingest_surface.json`, the notes for channels closed behind these flags (`edge_multiplicity` "Behind GRAPHHUNTER_GRAPHDELTA (default off…)", `row_completeness`/`skip_diagnostics` "Behind GRAPHHUNTER_JOURNAL (default off)", `ingest_completeness`/`completeness_flag`/`source_coverage` "Behind GRAPHHUNTER_COVERAGE/SOURCE_COVERAGE (default off)") now over-disclose a default that changed. Update each to "default ON (falsy-to-disable) as of the enable-defaults fase; the journal is bounded by GRAPHHUNTER_JOURNAL_MAX_BYTES rotation" — a STRENGTHENING (the closure now holds on the default path). Do NOT change any `fidelity`. This is a disclosure-accuracy edit, not a verdict change.

- [ ] **Step 2: Re-freeze + verify no verdict change**

```bash
cd /c/Users/lsotomayor/sot
python scripts/sot_sys/audit_graphhunter.py
python scripts/sot_sys/audit_graphhunter.py --check
```
Verify `audit_results.json`: 30/30 catalog Sufficient, `loss_reconstruction` + `exhaustiveness_marking` Sufficient — UNCHANGED (flipping code defaults changes no fidelity; only the note prose changed, and note prose for full channels may not even appear in the frozen results — confirm the results file is byte-stable or changes only where expected). Update `MANIFEST.sha256` (git-blob) for whatever changed.

- [ ] **Step 3: Doc + commits**

Doc: a short section noting SOT is now enabled by default (journal+dedup+coverage+source-coverage), the journal is bounded by rotation (retained-window semantics disclosed), each flag remains a falsy-to-disable escape hatch. Then:
```bash
# GraphHunter
git add docs/architecture/incremental-correctness.md
git commit -m "docs: SOT enabled by default (bounded journal + dedup + coverage); flags are falsy-to-disable"
# sot
cd /c/Users/lsotomayor/sot
git add validation/graphhunter/ingest_surface.json validation/graphhunter/audit_results.json MANIFEST.sha256
git commit -m "GraphHunter audit: disclose SOT flags now default-on (bounded journal); no verdict change"
```

---

## Self-Review notes

- **Ordering is safety-critical:** Task 1 (journal bound) MUST precede Task 2's JOURNAL/GRAPHDELTA flip — never ship an unbounded default-on journal.
- **Rotation correctness:** atomic rename, read spans segments in order, crash-safe, retention disclosed (window not all-time). The equivalence certificate operates under the cap (single segment) so stays green.
- **Flip is a clean inversion** matching the escape-hatch pattern; flags remain as disable hatches (not deleted).
- **No verdict change** from the flip — the audit fidelities are unchanged; only the "default off" disclosures update (a strengthening). Verify 30/30 + both transversals Sufficient after re-freeze.
- **Ripple discipline:** disable-path coverage is preserved by making those tests set the flag explicitly off, not by deleting them.
