# D — Tauri+sidecar surface

**Date:** 2026-05-27
**Method:** tauri.conf.json scan + .env audit + silent failure grep + IPC command audit (sidecar source absence deferred to Unit 5 / PR #65)
**Worker:** unit-15 (retry)
**Base commit:** 258d30d

## Summary

6 findings: 0 P0, 3 P1, 3 P2, 0 P3. Sidecar source absence findings: see Unit 5 / PR #65 (this audit did not re-investigate the `apps/tauri/src-tauri/binaries/` and `sidecar/` untracked directories — that surface is covered by the dedicated unit).

## Findings

### D-1 — `tauri.conf.json` sets `app.security.csp: null`

- **Severity:** P1
- **Axis:** Security / Hardening
- **Front:** Tauri shell
- **Evidence:** `apps/tauri/src-tauri/tauri.conf.json:35` — `"csp": null`. Tauri docs explicitly warn that a null CSP disables one of the strongest defenses against XSS injection from any HTML content the frontend renders (search results, hunt output, ingested log snippets).
- **Risk:** A malicious log line or hunt payload rendered without escaping could execute JS inside the Tauri WebView, with full IPC access to the 100 backend commands. For an OSS v1.0 release that ingests untrusted log files, leaving CSP off is hard to justify.
- **Fix action:** Define a baseline CSP (`"default-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline'; script-src 'self'"`) and tighten from there. Validate against the existing UI to avoid breakage.
- **Cost:** S (1 dev-day to land + verify in UI)
- **Gate:** Should land before v1.0.0 GA.
- **Owner:** Frontend/Tauri shell maintainer.

### D-2 — `tauri.conf.json` missing `bundle.targets` and per-OS bundle config

- **Severity:** P1
- **Axis:** Distribution / Cross-platform
- **Front:** Tauri shell
- **Evidence:** `apps/tauri/src-tauri/tauri.conf.json:6-17` — `bundle` block only declares `icon` + `resources`. No `targets` (defaults to `all`, which builds every installer type), no `windows`/`macOS`/`linux` keys, no `category`, no `shortDescription`, no `longDescription`, no `publisher`, no signing config.
- **Risk:** For a v1.0 OSS release, distributing binaries without explicit bundle targets means CI builds whatever the host supports, which is brittle. Missing publisher/category metadata makes the installers look unsigned/unattributed on Windows SmartScreen and macOS Gatekeeper.
- **Fix action:** Explicitly list `bundle.targets` (at minimum `["msi", "nsis", "deb", "appimage", "dmg"]`), add `publisher`, `category` (`"DeveloperTool"` or `"Security"`), `shortDescription`, `longDescription`. Wire a code-signing CI step if signing keys are available.
- **Cost:** S (configuration only) — signing is M if certificates need procurement.
- **Gate:** Required for v1.0.0 GA distribution channel.
- **Owner:** Release engineer / OSS maintainer.

### D-3 — Empty `.catch(() => {})` handlers swallow IPC errors silently in frontend

- **Severity:** P1
- **Axis:** Reliability / Observability
- **Front:** Tauri frontend (React)
- **Evidence:** `git grep -nE '\.catch\(' apps/tauri/src` returned multiple empty handlers in `App.tsx:276,281,288,295,313`, `hooks/useSentinelEvents.ts:57`, `lib/webIngest.ts:81`. Pattern aggregated as one finding. This directly matches the user-reported issue in memory note `feedback_hunt_session_real`: "silent run_hunt failures" — the frontend cannot report the failure because the catch is empty.
- **Risk:** When a hunt, ingest, or Sentinel call fails, the user sees nothing. The hunt UI hangs in a stale state until manually refreshed. For an OSS release, this is the #1 footgun preventing users from diagnosing their own issues, and the most common reason a v1.0 product gets a bad first-impression review.
- **Fix action:** Replace empty `.catch(() => {})` with a single helper `reportIpcError(error, { command, context })` that (a) `console.error`s for dev, (b) emits to a centralized error toast/status bar, (c) optionally pipes to a telemetry-opt-in channel. Required at every `invoke()` boundary.
- **Cost:** M (1-2 dev-days to design + roll out).
- **Gate:** Should land before v1.0.0 GA — directly user-visible quality issue.
- **Owner:** Frontend lead.

### D-4 — Tauri commands return bare `T` instead of `Result<T, E>`

- **Severity:** P2
- **Axis:** API contract / Error propagation
- **Front:** Tauri backend (Rust)
- **Evidence:** Of ~100 `#[tauri::command]` definitions across `apps/tauri/src-tauri/src`, a non-trivial subset return bare types (sampled from a multiline grep): `cmd_get_simd_isa -> String` (`commands/graph_ops.rs:328`), `cmd_get_memory_status -> MemoryStatus` (`commands/memory.rs:54`), `cmd_get_perf_status -> PerfStatus` (`commands/perf.rs:54`), `cmd_get_ingest_engine_status -> IngestEngineStatus` (`commands/ingest_status.rs:60`), `cmd_sentinel_check_env -> SentinelEnvStatus` (`commands/sentinel.rs:67`), `cmd_preview_hunting_template -> String` (`commands/sentinel.rs:91`). Aggregated as one finding.
- **Risk:** Bare-return commands force fallible operations (env probes, MaxMind lookup, Sentinel API) to swallow errors internally and return defaults. The frontend cannot distinguish "everything OK" from "silent failure". Compounds D-3.
- **Fix action:** Audit all 100 commands. For any command that performs IO, network, parsing, or fallible computation, change the signature to `Result<T, IpcError>` with a stable `IpcError` enum the frontend can match on. Read-only getters over already-validated in-memory state may remain `T`.
- **Cost:** M (2-4 dev-days incl. frontend updates).
- **Gate:** Recommend before v1.0.0 GA; can ship in v1.0.x patch if scoped to the most user-facing commands first.
- **Owner:** Backend Rust lead.

### D-5 — Rust backend `let _ = handle.emit(...)` discards event emit errors

- **Severity:** P2
- **Axis:** Reliability / Observability
- **Front:** Tauri backend (Rust)
- **Evidence:** `git grep -nE '\.ok\(\)|let _ '` in `apps/tauri/src-tauri/src` surfaced `tauri_emitter.rs:40`, `http/helpers.rs:16,28`, `commands/ingest_status.rs:191,232` — all `let _ = handle.emit(EVENT, payload)`. Aggregated as one finding (recurring pattern). Other `.ok()` uses (e.g. `lib.rs:34,117,212`, `helpers.rs:32`) are legitimate fallbacks for env probes / parsing and are NOT flagged.
- **Risk:** If a Tauri event channel is dropped or fails to serialize, ingest-status/notes-changed/mcp-view-update updates are lost without trace. The frontend assumes its view is fresh when in fact it's stale.
- **Fix action:** Replace `let _ = handle.emit(...)` with a thin helper `emit_or_log!(handle, event, payload)` that does `if let Err(e) = handle.emit(...) { tracing::warn!(?e, event, "emit failed") }`. Cheap, no semantic change, full visibility in logs.
- **Cost:** S (couple of hours).
- **Gate:** Nice-to-have for v1.0.0; safe to defer to v1.0.1.
- **Owner:** Backend Rust lead.

### D-6 — No `.env.example` template in `apps/tauri`

- **Severity:** P2
- **Axis:** Onboarding / Developer experience
- **Front:** Tauri shell
- **Evidence:** `find apps/tauri -name '.env*' -not -path '*/node_modules/*'` returned zero results; `git ls-files apps/tauri | grep -i env` also empty. No `.env` is tracked (good — no leaked secrets to flag P0). But no `.env.example` either, meaning new contributors have no template for the env vars the app reads at startup (Sentinel creds, MaxMind path, ports, etc.).
- **Risk:** Low immediate risk, but for a v1.0 OSS release that wants community contributors, a missing env template is a documented friction point.
- **Fix action:** Add `apps/tauri/.env.example` listing all env vars the shell + frontend consume (sourced from `lib.rs` env reads and Vite `import.meta.env` references). Document each with a short comment.
- **Cost:** S (1 hour).
- **Gate:** Quality-of-life — defer to v1.0.x patch.
- **Owner:** OSS maintainer / docs.

## Method log

Commands run (in order):

1. `git rev-parse --short HEAD` → `258d30d`
2. `git checkout -b audit/unit-15-d-tauri-retry` → branch created.
3. `mkdir -p audit-findings/` → confirmed dir exists.
4. `Read apps/tauri/src-tauri/tauri.conf.json` → 38 lines. Findings: `csp: null` (D-1), no `bundle.targets` / metadata (D-2), no `externalBin` (deferred to Unit 5).
5. `find apps/tauri -name '.env*'` → zero matches (no leaked .env, but also no template → D-6).
6. `git ls-files apps/tauri | grep -i env` → no tracked env files (no P0).
7. `Grep "fn run_hunt|fn hunt"` in `apps/tauri/src-tauri/src` → no matches (commands live elsewhere); same grep in `core/graph-engine/src` → `hunt_diagnostic` + `hunt` (cancellation token).
8. `Grep "run_hunt|hunt_query"` in `apps/tauri/src-tauri/src` → `commands/graph_ops.rs:42 cmd_run_hunt`, `:83 cmd_run_hunt_batch` (verified the chain exists).
9. `Grep "\.ok\(\)|let _ ="` in `apps/tauri/src-tauri/src` (first 15) → 5 instances of `let _ = handle.emit(...)` flagged as D-5; other `.ok()` are legitimate fallbacks (not flagged).
10. `Grep "\.catch\("` in `apps/tauri/src` (first 10) → 10 matches including `App.tsx:276,281,288,295,313 .catch(() => {})` empty handlers → D-3 (cross-referenced to `feedback_hunt_session_real`).
11. `Grep "#\[tauri::command\]"` in `apps/tauri/src-tauri/src` → 100 total commands (`grep -rn ... | wc -l`).
12. Multiline grep for `#[tauri::command]` followed by `pub fn ... -> T {` (bare-return signatures) → at least 6 commands return bare `T` instead of `Result<T,E>` (`cmd_get_simd_isa`, `cmd_get_memory_status`, `cmd_get_perf_status`, `cmd_get_ingest_engine_status`, `cmd_sentinel_check_env`, `cmd_preview_hunting_template`) → D-4.
13. `Grep "externalBin|sidecar|targets"` in `tauri.conf.json` → no matches (confirms sidecar config missing — deferred to Unit 5).

**Scope deferred:** sidecar source absence (`apps/tauri/src-tauri/binaries/`, `sidecar/` untracked dirs) — covered by Unit 5 / PR #65, not re-investigated per Unit 15 brief.
