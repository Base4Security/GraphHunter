# C — core Rust quality (static-only)

**Date:** 2026-05-27
**Method:** Static grep scans across 14 Cargo.toml manifests in `core/`, `platform/`, and `apps/`. Dynamic checks (`cargo test`, `cargo clippy`, `cargo fmt --check`, `cargo doc`) deferred to `rust-ci.yml` (Unit 10, PR #66) which runs on every PR going forward.
**Worker:** unit-14 (retry, static-only)
**Base commit:** 258d30d

## Summary

5 findings: **1 P0, 1 P1, 2 P2, 1 P3**

| # | Sev | Finding |
|---|-----|---------|
| 1 | P0 | `unimplemented!()` reachable in production path (`platform/api/src/operations/dlq.rs:498`) |
| 2 | P1 | 260 `unwrap()` calls in `core/graph-engine/src/` (excluding `tests.rs`) — risk of panics on edge inputs |
| 3 | P2 | 3 `unsafe` SIMD prefetch blocks without explicit `// SAFETY:` comment (`core/graph-engine/src/graph.rs:1711, 1931, 2193`) |
| 4 | P2 | Dynamic verification skipped this pass — `cargo test`, clippy, fmt-check, doc warnings not yet validated |
| 5 | P3 | 14 Cargo crates form a deep workspace tree — no central lint config detected |

## Findings

### F1 — P0: `unimplemented!()` in production path

- **File:** `platform/api/src/operations/dlq.rs:498`
- **Evidence:** `git grep 'unimplemented!'` returns exactly one match outside `tests/`:
  ```
  platform/api/src/operations/dlq.rs:498:        unimplemented!()
  ```
- **Impact:** A hit on this code path will panic the API process (no graceful error, no DLQ retry). Because DLQ is itself the recovery path for failed ingest, panics here are doubly bad — the recovery handler is itself unreachable.
- **Why P0:** Any `unimplemented!()`/`todo!()` reachable from a public API surface is a release blocker by policy. The companion `todo!()` scan returned zero matches anywhere in the tree, so this is the *only* such marker — and it must be either implemented or replaced with a typed `Err(NotImplemented)` before the next tag.
- **Fix sketch:**
  1. Read the surrounding function (likely a stub for a planned operation).
  2. Replace `unimplemented!()` with a typed error variant (e.g. `Err(DlqError::NotImplemented { op: "..." })`) so callers can degrade gracefully.
  3. Add a regression test that exercises the path and asserts the `Err(...)`.

### F2 — P1: 260 `unwrap()` calls in `core/graph-engine/src/` (production code)

- **Scope:** `git grep -nE '\.unwrap\(\)' -- 'core/graph-engine/src/**/*.rs' | grep -v 'src/tests.rs' | grep -v '#[cfg(test)]'` → 260 hits across ~35 files.
- **Heaviest concentrations** (by file, raw count incl. test cfg lines):
  - `ingest/overflow.rs`: 49
  - `khop_reach.rs`: 46
  - `ingest/source_poller.rs` / `lftj_query.rs` / `lftj.rs`: 36-41 each
  - `drift/store.rs`, `watermark_store.rs`: 31-33 each
- **Impact:** `graph-engine` is the hot path of the entire product (ingest, query, drift). A poison `.unwrap()` on user-supplied input or a moved file produces a thread panic that kills the worker. The 260 count is a fleet liability, not a single bug.
- **Why P1 (not P0):** No evidence any specific unwrap is on a tainted input path — but the aggregate risk is high enough to warrant a deliberate cleanup pass.
- **Recommendation:**
  - Add a workspace-level `clippy::unwrap_used` lint to `core/graph-engine` (soft, advisory) once Unit 10's CI lands.
  - Triage the top 3 files (`ingest/overflow.rs`, `khop_reach.rs`, `ingest/source_poller.rs`) and convert input-bound unwraps to typed errors.
  - Mutex/lock unwraps (panic on poison) are acceptable to leave; document the convention.

### F3 — P2: 3 unsafe SIMD prefetch blocks lack explicit `// SAFETY:` comment

- **Files / lines:** `core/graph-engine/src/graph.rs:1711, 1931, 2193`
- **Evidence:** Each unsafe block calls `_mm_prefetch::<_MM_HINT_T0>(self.entity_type_tags.as_ptr().add(probe_dst) as *const i8)`. The block is guarded by an `if probe_dst < self.entity_type_tags.len()` check immediately above — so soundness is in fact established, just not documented as a comment.
- **Other production unsafe** (graph.rs:566/622/669/2546/2646/3242, index_storage.rs:111/115/154, mmap_advise.rs:41, nauty_symmetry.rs:125, simd_rust.rs SIMD blocks, streaming.rs:83/249/391/869/885/1012/1025) **all carry SAFETY comments** — the bar is set well; the prefetch trio is the only gap.
- **Memory ref:** `project_simd_security_followups` queues SIMD hardening work after PR #21 merges; this finding adds the prefetch documentation to that backlog.
- **Fix:** Two-line `// SAFETY:` block above each of the three call sites stating the bounds check is the precondition.

### F4 — P2: Dynamic verification deferred to CI

- **Scope:** This audit pass is static-only. The following were not exercised:
  - `cargo test --workspace --no-run` (compile-only) → not run
  - `cargo test --workspace` → not run
  - `cargo clippy --workspace --all-targets -- -D warnings` → not run
  - `cargo fmt --all -- --check` → not run
  - `cargo doc --workspace --no-deps` → not run
- **Why P2:** Not having dynamic verification *now* is a known gap, but Unit 10's `rust-ci.yml` (PR #66 in this batch) makes every future PR validate compile + test + clippy + fmt automatically. The risk is bounded to the window between merge of this audit branch and merge of #66.
- **Fix:** No code change. Merge PR #66 (Unit 10) to close this gap. Optionally add `cargo doc -D warnings` to the same workflow on a follow-up.

### F5 — P3: 14-crate workspace lacks a central lint baseline

- **Manifests:**
  ```
  apps/cli/Cargo.toml
  apps/tauri/src-tauri/Cargo.toml
  core/gnn/Cargo.toml
  core/graph-engine/Cargo.toml
  core/matcher-ffi/Cargo.toml
  platform/api/Cargo.toml
  platform/canonical/Cargo.toml
  platform/constrained-decode/Cargo.toml
  platform/dsl/Cargo.toml
  platform/local-llm/Cargo.toml
  platform/parsers/Cargo.toml
  platform/siem/Cargo.toml
  platform/sources/Cargo.toml
  platform/vrl/Cargo.toml
  ```
- **Observation:** 14 crates is healthy for separation of concerns, but absent a workspace-level `[lints]` block in the root `Cargo.toml` each crate sets its own (or no) lint floor. This makes a finding like F2 (unwrap policy) hard to enforce uniformly.
- **Why P3:** Style / policy, not correctness. Defer until F2 is acted on — easier to land a `[lints.clippy]` block once the policy is clear.

## Method log

```bash
# 1. Crate inventory (14 manifests)
find . -name Cargo.toml -not -path '*/target/*' -not -path '*/_archive/*' -not -path '*/spikes/*'

# 2. unimplemented!/todo! sweep
git grep -nE '\b(unimplemented!|todo!)\b' -- '**/*.rs'
#   → 1 hit: platform/api/src/operations/dlq.rs:498   (P0, confirmed)
#   → 0 todo! anywhere

# 3. panic!() in production src/ (excluding tests)
git grep -nE '\bpanic!\(' -- 'core/*/src/**/*.rs' 'platform/*/src/**/*.rs' 'apps/*/src/**/*.rs'
#   → ~13 candidates, ALL in #[cfg(test)] modules (verified by locating
#     the `#[cfg(test)]` marker line, which precedes every hit)
#   → 0 production panic!() — no finding

# 4. unwrap() density in core/graph-engine
git grep -nE '\.unwrap\(\)' -- 'core/graph-engine/src/**/*.rs' | grep -v 'src/tests.rs' | wc -l
#   → 260 (excluding the 585 in tests.rs)   (F2 — P1)

# 5. unsafe blocks in core
git grep -nE '^\s*unsafe \{' -- 'core/**/*.rs' | wc -l
#   → 41 unsafe blocks total in core/
git grep -nB3 'unsafe {' -- 'core/**/*.rs'
#   → All carry preceding `// SAFETY:` comment EXCEPT 3 prefetch blocks
#     in graph.rs (lines 1711, 1931, 2193).   (F3 — P2)

# Skipped (deferred to PR #66 rust-ci.yml, Unit 10):
#   cargo test, cargo clippy, cargo fmt --check, cargo doc
```
