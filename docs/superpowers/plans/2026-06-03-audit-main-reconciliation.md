# Audit ↔ Main Reconciliation Plan

> **For agentic workers:** This is a git MERGE runbook — a single atomic, sequential operation, NOT parallelizable. Execute INLINE (superpowers:executing-plans). Do NOT dispatch parallel subagents (they would conflict in the same tree). Steps use `- [ ]` for tracking.

**Goal:** Merge `feat/sprint1-ingest-audit` (FortiGate parser, set_phase, ingest-audit) into a copy of `origin/main` (hydration/seed/pause), resolve the 4 code conflicts, verify both lineages' tests pass, then publish as the unified `main` and retire the audit branch.

**Architecture:** All work in a throwaway worktree branch `reconcile-audit-main` based on `origin/main`. `origin/main` and `feat/sprint1-ingest-audit` stay untouched until the final verified push. Conflict resolution is manual, file-by-file (no mass `theirs/ours`).

**Tech Stack:** git, Rust (cargo per-crate `--manifest-path`), TypeScript (tsc).

## Conflict surface (from spec §3)
4 code files + 6 trivial docs. 94 audit-only + 16 main-only files merge clean.
- `apps/tauri/src-tauri/src/commands/graph_ops.rs` — union (audit +1)
- `platform/mcp/src/tools/node/expand.ts` — union (audit +1/-1)
- `core/graph-engine/src/analytics.rs` — audit base + re-apply main's `HydrationOutcome`+`Neighborhood.hydration`
- `platform/api/src/operations/sentinel.rs` — main spine + restore `set_phase` (spec §4)

---

## Task 1: Create reconcile worktree and start the merge

- [ ] **Step 1: Worktree from origin/main**
```bash
cd <repo-root>
git worktree add .claude/worktrees/reconcile-audit-main -b reconcile-audit-main origin/main
cd .claude/worktrees/reconcile-audit-main
```
(If `EnterWorktree` native tool is available, prefer it with base = origin/main. Provenance: this is a superpowers/throwaway worktree.)

- [ ] **Step 2: Copy env artifacts (gitignored, needed for tauri check / api harness)**
```bash
cp -r <repo-root>/apps/tauri/dist apps/tauri/ 2>/dev/null
for f in ambiguous_fields_csv.csv ambiguous_fields_forti.log; do cp "<repo-root>/demo_data/$f" demo_data/ 2>/dev/null; done
```

- [ ] **Step 3: Baseline (main side green before merge)**
Run: `cargo test --manifest-path platform/api/Cargo.toml --lib`
Expected: PASS (this is main's state — hydration/seed/pause tests).

- [ ] **Step 4: Start the merge (expect conflicts)**
```bash
git merge --no-commit --no-ff feat/sprint1-ingest-audit
git status --short | grep '^UU\|^AA\|^U' 
```
Expected: conflicts in ~4 code files + up to 6 docs. The 94 audit-only files stage cleanly (shown as `A`). Do NOT commit yet.

---

## Task 2: Resolve the trivial conflicts

- [ ] **Step 1: Docs (6 spec/plan files)**
These are identical content (cherry-picked between branches). For each conflicted `docs/superpowers/**` file, take whichever side is non-empty/complete (they match):
```bash
git checkout --theirs docs/superpowers/ 2>/dev/null || true
git add docs/superpowers/
```
(If a doc genuinely differs, open it and keep the union; but they should be identical.)

- [ ] **Step 2: `commands/graph_ops.rs` (union)**
Open `apps/tauri/src-tauri/src/commands/graph_ops.rs`. Main's version has the live `cmd_expand_node` (async, `live`/`time_window` params). Audit added 1 line. Keep main's `cmd_expand_node` in full AND fold in audit's 1-line addition (inspect the conflict marker — it's a small additive change). Then:
```bash
git add apps/tauri/src-tauri/src/commands/graph_ops.rs
```

- [ ] **Step 3: `tools/node/expand.ts` (union)**
Open `platform/mcp/src/tools/node/expand.ts`. Keep main's `live`/`lookback` params + execute wiring; fold in audit's 1-line change. Then:
```bash
git add platform/mcp/src/tools/node/expand.ts
```

- [ ] **Step 4: Checkpoint — only analytics.rs + sentinel.rs remain conflicted**
Run: `git status --short | grep '^UU\|^AA'`
Expected: only `core/graph-engine/src/analytics.rs` and `platform/api/src/operations/sentinel.rs`.

---

## Task 3: Resolve `core/graph-engine/src/analytics.rs`

Audit rewrote parts (+95/-55: tail-aware `out_degree`, unique-by-type `neighbor_types`). Main added purely (`HydrationOutcome` struct + `hydration` field on `Neighborhood` + `hydration: None` in constructors).

- [ ] **Step 1: Take audit's version as the base, re-apply main's additions**
Open the file. Resolve so the result has BOTH:
- audit's `out_degree`/`neighbor_types` changes (the structural rewrite), AND
- main's additions: the `HydrationOutcome` struct (Serialize, fields `skipped`/`reason`/`new_entities`/`new_relations`/`tables_hit`/`tables_attempted`), the `pub hydration: Option<HydrationOutcome>` field on `Neighborhood` (with `#[serde(default, skip_serializing_if = "Option::is_none")]`), and `hydration: None` in EVERY `Neighborhood { ... }` constructor in this file.
- [ ] **Step 2: Stage**
```bash
git add core/graph-engine/src/analytics.rs
```
- [ ] **Step 3: Compile-check core**
Run: `cargo check --manifest-path core/graph-engine/Cargo.toml`
Expected: clean (if a `Neighborhood {...}` constructor elsewhere is missing `hydration`, the compiler lists it — fix and re-stage).

---

## Task 4: Resolve `platform/api/src/operations/sentinel.rs` (the hard one)

Per spec §4: main's version is the spine (all features), restore `set_phase` from audit wired to the pause model.

- [ ] **Step 1: Start from main's version, layer in set_phase**
Resolve the conflict so the file keeps ALL of main's functions verbatim:
`hydrate_node_with`, `seed_from_ioc`, `seed_from_ioc_with`, `build_seed_result`, `seeded_neighborhood`, `rank_top_anomalies`, `sentinel_resume`, `sentinel_pause`, `run_kql`, `run_hunting_template`, `preview_hunting_template`, `sentinel_status`, `sentinel_check_env`, `sentinel_disconnect`, and the paused-by-default `sentinel_connect`.

- [ ] **Step 2: Re-introduce `set_phase` calls (now that `SessionPhase` exists via the merged session.rs)**
Add these calls into main's functions:
```rust
// in sentinel_connect, after the connector handle is registered (paused):
session.set_phase(crate::state::SessionPhase::Ready);

// in sentinel_resume, after pause_tx.send(false):
if let Some(session) = self.sessions().current_session() {
    session.set_phase(crate::state::SessionPhase::LiveTail);
}

// in sentinel_pause, after pause_tx.send(true):
if let Some(session) = self.sessions().current_session() {
    session.set_phase(crate::state::SessionPhase::Ready);
}

// in sentinel_disconnect, where audit set it (after the final scoring pass):
session.set_phase(crate::state::SessionPhase::Ready);
```
(Confirm the exact `SessionPhase`/`set_phase` path from the merged `platform/api/src/state/session.rs` — audit's session.rs defines them; use the real path. If `sentinel_connect` holds `session` by a different binding, adapt.)

- [ ] **Step 3: Stage + compile-check api**
```bash
git add platform/api/src/operations/sentinel.rs
cargo check --manifest-path platform/api/Cargo.toml
```
Expected: clean. Fix any leftover conflict markers / missing symbols (e.g. `SessionPhase` import) until it compiles.

---

## Task 5: Complete the merge + full verification gate

- [ ] **Step 1: Confirm no unresolved conflicts**
Run: `git status --short | grep '^UU\|^AA\|^DD\|^U'`
Expected: empty. If anything remains, resolve + `git add` it.

- [ ] **Step 2: Commit the merge**
```bash
git commit --no-edit   # uses the default merge message; or -m "merge: reconcile feat/sprint1-ingest-audit into main"
```

- [ ] **Step 3: Verification gate (spec §6) — ALL must pass**
```bash
cargo test --manifest-path core/graph-engine/Cargo.toml --lib -- --skip benchmark_
cargo test --manifest-path platform/api/Cargo.toml --lib
cargo test --manifest-path platform/parsers/Cargo.toml --lib
cargo check --manifest-path apps/tauri/src-tauri/Cargo.toml
( cd platform/mcp && npx tsc --noEmit )
```
Expected: all green. The `platform/api` lib run must contain BOTH `hydrate_tests`/`seed_tests`/`pause_tests`/`expand_live_tests` (from main) AND the ingest-audit tests (from audit). `platform/parsers` must include `fortigate` tests.

- [ ] **Step 4: Targeted sanity checks**
```bash
ls platform/parsers/src/fortigate.rs                      # exists
grep -rn 'set_phase' platform/api/src/operations/sentinel.rs   # connect/resume/pause/disconnect
grep -rn 'sentinel_resume\|hydrate_node_with\|seed_from_ioc' platform/api/src/operations/sentinel.rs | head
```
Expected: fortigate.rs present; set_phase used in the 4 lifecycle fns; the 3 features' fns present.

- [ ] **Step 5: If anything failed**
Fix inside this worktree (the merge isn't published yet), re-run Step 3 until green. Do NOT proceed to Task 6 with any red.

---

## Task 6: Publish unified main + retire audit

**Only after Task 5 is fully green.**

- [ ] **Step 1: Fast-forward local main to the reconciled commit + push**
```bash
cd <repo-root>
RECON=$(git -C .claude/worktrees/reconcile-audit-main rev-parse HEAD)
git branch -f main "$RECON"          # main not checked out anywhere -> safe ref move
git push origin main                 # publishes unified main (NOTE: this is a real merge of histories, not a ff of origin/main->main; if push is rejected as non-ff, it is because origin/main is an ancestor of the merge -> it IS a ff; if not, STOP and reassess)
```
> NOTE: the reconciled commit has BOTH `origin/main` and `feat/sprint1-ingest-audit` as ancestors (it's a merge commit whose first parent is origin/main). So `origin/main -> reconciled` is a fast-forward. The push should be clean.

- [ ] **Step 2: Retire the audit branch (after confirming content is in main)**
```bash
git branch --merged main | grep feat/sprint1-ingest-audit   # confirm it's merged
git push origin --delete feat/sprint1-ingest-audit
git branch -D feat/sprint1-ingest-audit
```
> CAUTION: the working root is currently ON `feat/sprint1-ingest-audit` with uncommitted changes. Before deleting it: either commit/stash those changes, or `git checkout main` in the root first. Do NOT lose the operator's uncommitted work — inspect `git status` and confirm with the user what to do with any uncommitted files before deleting the branch.

- [ ] **Step 3: Clean up the reconcile worktree**
```bash
git worktree remove .claude/worktrees/reconcile-audit-main   # or ExitWorktree if created natively
git worktree prune
```

---

## Self-review notes
- **Spec coverage:** §2 unified main (Task 5/6); §3 conflict surface — graph_ops/expand.ts (T2), analytics.rs (T3), sentinel.rs (T4); §4 set_phase resolution (T4 Step 2, exact table); §5 mechanics (worktree T1, manual file-by-file T2-T4, publish T6); §6 verification gate (T5 Step 3-4); §8 rollback (everything in throwaway worktree until T6).
- **Risk flags:** (a) the working root is on the audit branch with uncommitted changes — T6 Step 2 explicitly guards against losing them (confirm with user). (b) `set_phase`/`SessionPhase` exact path must be read from the merged session.rs (T4 Step 2 note). (c) if the api lib tests reveal a semantic conflict the merge didn't surface (e.g. a test from one side asserting behavior the other side changed), fix in-worktree before publishing (T5 Step 5).
- **Not TDD-shaped:** a merge has no "write failing test first" — the tests already exist on both sides; the gate is "both sides' existing tests pass on the merged tree." That is the correct verification model here.
