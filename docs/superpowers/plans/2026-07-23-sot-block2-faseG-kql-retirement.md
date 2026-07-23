# Fase G — Analytic-KQL Retirement (Opt-in Gating) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Complete Fase G — retire the "old analytic KQL path" — as an *opt-in* gating, without changing any production default. Scoping established that the analytic-hypothesis criterion is already satisfied by the architecture (`run_hunt`/`run_hunt_batch` are 100% local with no KQL fallback; the MCP hypothesis tools use no KQL; the escape hatch is already gated at HTTP). What remains is defense-in-depth: make the two residual KQL surfaces that embed hunt-flavored semantics **flag-gateable** (default ON = no behavior change), and close one real gap where the GUI bypasses the existing escape-hatch gate.

**Architecture:** All flag-reading logic and the API-layer gate live in `platform/api` (which runs ort-free — real green tests, unlike ONNX-blocked `apps/tauri`). The `apps/tauri` command layer + React frontend consume those flags. Two flags, both **default ON** (only an explicit falsy value disables), mirroring the existing `kql_escape_hatch_enabled()` contract:
- `GRAPHHUNTER_KQL_ESCAPE_HATCH` (existing) — raw free-text KQL read-out. Gap closed here: the GUI `cmd_run_kql` currently bypasses it.
- `GRAPHHUNTER_HUNTING_TEMPLATES` (new) — the 4 fixed hunting templates (`render/run_hunting_template`).

**Tech Stack:** Rust (`graph_hunter_api` — testable/ort-free; `graph-hunter-app` Tauri commands — compile+read-verify, ONNX blocks test *execution*), React/TypeScript frontend (vite/tsc build — not affected by the Rust ONNX issue).

## Global Constraints

- **NO production-default flip.** Both flags default ON; with neither set, behavior is byte-identical to today. Flipping a default to OFF (actually retiring a surface in production) is the user's separate, explicit decision — this plan only makes retirement *possible*, and must document the flip as NOT done and pending user OK.
- **Collection KQL is untouched.** `materialization_kql` (graph_build/propose), `usage_kql`/`sample_kql` (schema_discover), node hydration, `seed_from_ioc`, streaming poll KQL, and the internal `run_kql` ingest path are legitimate DATA COLLECTION per spec and MUST NOT be gated. Only free-text analyst KQL read-out and the hunting templates are in scope.
- **Testable logic in platform/api.** Every flag reader + the API-layer gate on `run_hunting_template` must have unit tests that RUN in `platform/api` (ort-free). `apps/tauri` command changes and the React change are compile/build-verified only (the `apps/tauri` test binary cannot launch here — pre-existing ONNX `onnxruntime.dll` blocker affecting the whole crate; state this honestly, do not claim a green run you couldn't produce).
- **Preserve the existing escape-hatch contract.** The current `GRAPHHUNTER_KQL_ESCAPE_HATCH` default-ON semantics + `disabled_response()` shape (`{error:"kql_escape_hatch_disabled", hint, source_tabular:true}`) and its tests (`http/escape_hatch.rs`, `http/siem.rs`) must keep passing (compile-verified). Do not weaken the internal-caller exemption (journal expand / collection KQL stay ungated).
- **No unrelated WIP.** Both repos carry uncommitted/untracked WIP (haproxy.rs, apps/tauri/*, core files, docs/libro, etc.). Never `git add -A`; stage only each task's named files.
- **Audit null-delta.** Fase G touches no telemetry channel — the frozen audit (30/30 Sufficient) must be unchanged. The re-run's honest report is a null delta.

---

### Task 1: Flag readers + `run_hunting_template` gate + env-status reporting (platform/api — testable)

**Files:**
- Create or modify: `platform/api/src/` — a small flags module (e.g. `platform/api/src/kql_flags.rs`) or add to an existing suitable module; wire into `platform/api/src/lib.rs` if new.
- Modify: `platform/api/src/operations/sentinel.rs` (gate `run_hunting_template`; extend `sentinel_check_env`/`SentinelEnvStatus`)
- Test: unit tests in the flags module + a gate test in sentinel.rs's test module.

**Interfaces:**
- Consumes: `run_hunting_template` (`sentinel.rs:884`, `ApiResult<KqlResult>`); `render_hunting_template` (`sentinel.rs:2043`); `ApiError` (pick a variant that maps to 403/forbidden — check the enum; if none fits, add `ApiError::FeatureDisabled { feature, hint }` and map it in the HTTP error translation like other variants); `sentinel_check_env() -> SentinelEnvStatus`.
- Produces: `pub fn hunting_templates_enabled() -> bool` and `pub fn kql_escape_hatch_enabled() -> bool` (both default ON, only explicit falsy `0/false/no/off` disables — copy the exact semantics from `apps/tauri/src-tauri/src/http/escape_hatch.rs:15-23`); extended `SentinelEnvStatus` with `hunting_templates_enabled: bool` + `kql_escape_hatch_enabled: bool`.

- [ ] **Step 1: Write failing tests for the flag readers (default-on + explicit-falsy)**

Mirror `flag_defaults_enabled_and_respects_explicit_falsy` from `http/escape_hatch.rs`. Use a process-global env lock (the crate's Rust edition marks `set_var`/`remove_var` unsafe — wrap in `unsafe {}`, and serialize env-mutating tests with a `Mutex` as escape_hatch.rs does).

```rust
#[test]
fn hunting_templates_flag_defaults_on_and_respects_falsy() {
    let _g = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    unsafe { std::env::remove_var("GRAPHHUNTER_HUNTING_TEMPLATES"); }
    assert!(hunting_templates_enabled());
    unsafe { std::env::set_var("GRAPHHUNTER_HUNTING_TEMPLATES", "0"); }
    assert!(!hunting_templates_enabled());
    unsafe { std::env::set_var("GRAPHHUNTER_HUNTING_TEMPLATES", "off"); }
    assert!(!hunting_templates_enabled());
    unsafe { std::env::remove_var("GRAPHHUNTER_HUNTING_TEMPLATES"); }
}
```

Add the analogous test for `kql_escape_hatch_enabled()`.

- [ ] **Step 2: Run — fails (symbols absent)**

Run: `cd platform/api && cargo test --lib hunting_templates_flag`
Expected: FAIL — `hunting_templates_enabled` not defined.

- [ ] **Step 3: Implement both flag readers**

Copy the exact default-ON / explicit-falsy semantics from `escape_hatch.rs:15-23` for both `hunting_templates_enabled()` (`GRAPHHUNTER_HUNTING_TEMPLATES`) and `kql_escape_hatch_enabled()` (`GRAPHHUNTER_KQL_ESCAPE_HATCH`). Doc-comment `kql_escape_hatch_enabled` noting it is the canonical reader that `apps/tauri` delegates to (Task 2). Export both `pub` from the crate.

- [ ] **Step 4: Run — flag tests pass**

Run: `cd platform/api && cargo test --lib hunting_templates_flag kql_escape_hatch`
Expected: PASS.

- [ ] **Step 5: Write the failing gate test for `run_hunting_template`**

```rust
#[tokio::test]
async fn run_hunting_template_disabled_returns_structured_steer() {
    let _g = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    unsafe { std::env::set_var("GRAPHHUNTER_HUNTING_TEMPLATES", "0"); }
    let api = GraphHunterApi::new_noop();
    let err = api.run_hunting_template(RunHuntingTemplateRequest {
        template: Some(HuntingTemplateId::FailedLogonBurst),
        /* fill required fields; workspace/azure creds can be dummy — the gate
           must fire BEFORE any network call */
        ..Default::default() // or construct explicitly if no Default
    }).await.unwrap_err();
    unsafe { std::env::remove_var("GRAPHHUNTER_HUNTING_TEMPLATES"); }
    // Assert it's the disabled error, not a network/credential error.
    let msg = format!("{err}");
    assert!(msg.to_lowercase().contains("disabled") || msg.contains("hunting_templates"),
        "expected feature-disabled steer, got: {msg}");
}
```

Confirm `HuntingTemplateId`, `RunHuntingTemplateRequest`'s fields, and `new_noop()` against source; the key property: the gate fires before any Azure call, so the test needs no network.

- [ ] **Step 6: Run — fails (gate not yet added)**

Run: `cd platform/api && cargo test --lib run_hunting_template_disabled`
Expected: FAIL — currently proceeds to `render_hunting_template`/`run_kql`.

- [ ] **Step 7: Add the gate at the top of `run_hunting_template`**

At the very top of `run_hunting_template` (before rendering), if `!hunting_templates_enabled()` return the structured disabled error (an `ApiError` variant that maps to 403 with a hint steering to the local graph tools — mirror `disabled_response()`'s wording: "Hunting templates are disabled (GRAPHHUNTER_HUNTING_TEMPLATES). Hunt in the local graph via hunt_run / the hypothesis catalog."). This gates ALL callers of the template path (currently the Tauri `cmd_run_hunting_template`) uniformly.

- [ ] **Step 8: Extend `sentinel_check_env` / `SentinelEnvStatus`**

Add `hunting_templates_enabled: bool` + `kql_escape_hatch_enabled: bool` to `SentinelEnvStatus`, populated from the two readers, so the frontend (Task 3) can decide what to render. Update any existing `sentinel_check_env` test to include the new fields (or add one asserting the defaults are `true`).

- [ ] **Step 9: Run the full sentinel + flag suite**

Run: `cd platform/api && cargo test --lib sentinel:: ` and `cargo test --lib kql_flags` (or wherever the flags live), plus `cargo test --test parity`
Expected: all green; the new gate + flag tests pass; parity 35/35 unaffected.

- [ ] **Step 10: Commit**

```bash
git add platform/api/src/operations/sentinel.rs platform/api/src/kql_flags.rs platform/api/src/lib.rs
git commit -m "feat(kql): flag readers + run_hunting_template gate + env-status reporting (Fase G, default on)"
```

(Adjust staged paths to the files you actually created/modified. Stage nothing else.)

---

### Task 2: Close the GUI `cmd_run_kql` escape-hatch bypass (apps/tauri — compile + read-verify)

**Files:**
- Modify: `apps/tauri/src-tauri/src/http/escape_hatch.rs` (delegate `kql_escape_hatch_enabled` to the platform/api canonical reader, OR keep local but reference the shared semantics — see step)
- Modify: `apps/tauri/src-tauri/src/commands/sentinel.rs` (gate `cmd_run_kql`; the template command is already gated API-side by Task 1)

**Interfaces:**
- Consumes: `graph_hunter_api::kql_escape_hatch_enabled()` (Task 1); `cmd_run_kql` (`commands/sentinel.rs:73`, calls `api.run_kql` directly); the existing `disabled_response()` shape.
- Produces: `cmd_run_kql` returns a structured "escape hatch disabled" `CommandError` when the flag is off, matching the HTTP `disabled_response()` semantics, closing the bypass so GUI free-text KQL honors the same gate as HTTP/MCP.

- [ ] **Step 1: Point `apps/tauri`'s escape-hatch check at the canonical reader**

To avoid two divergent readers of `GRAPHHUNTER_KQL_ESCAPE_HATCH`, make `apps/tauri`'s `kql_escape_hatch_enabled()` (`http/escape_hatch.rs:15`) delegate to `graph_hunter_api::kql_escape_hatch_enabled()` (Task 1), keeping the HTTP `disabled_response()` where it is. The existing HTTP tests (`http/escape_hatch.rs`, `http/siem.rs`) must still compile and their assertions still hold (they test the same env-var semantics — now sourced from one place).

- [ ] **Step 2: Gate `cmd_run_kql`**

In `cmd_run_kql` (`commands/sentinel.rs:73`), before calling `api.run_kql(...)`, check `kql_escape_hatch_enabled()`; if disabled, return a `CommandError` carrying the same steer as `disabled_response()` ("Raw KQL is disabled (GRAPHHUNTER_KQL_ESCAPE_HATCH). Use the graph tools…"). This is the free-text analyst-KQL entry point from the GUI; the internal/collection callers of `api.run_kql` remain ungated (do NOT gate `api.run_kql` itself — gate at the command boundary, exactly as the HTTP layer gates at its boundary).

- [ ] **Step 3: Compile + read-verify (ONNX blocks test execution)**

Run: `cd apps/tauri/src-tauri && cargo build --lib`
Expected: compiles. The `apps/tauri` test binary cannot launch (pre-existing ONNX `onnxruntime.dll` `STATUS_ENTRYPOINT_NOT_FOUND` blocker — affects the whole crate, unrelated to this change). State this honestly in the report; the flag semantics themselves are green-tested in `platform/api` (Task 1). Read-verify that `cmd_run_kql` now checks the flag and that the template command is covered by Task 1's API gate.

- [ ] **Step 4: Commit**

```bash
git add apps/tauri/src-tauri/src/http/escape_hatch.rs apps/tauri/src-tauri/src/commands/sentinel.rs
git commit -m "fix(kql): close GUI cmd_run_kql escape-hatch bypass; delegate flag reader to platform/api (Fase G)"
```

---

### Task 3: Frontend — hide gated surfaces when flags are off (React)

**Files:**
- Modify: `apps/tauri/src/components/ingest/SentinelConnectForm.tsx` (conditionally render `HuntingTemplatesSection` + the ad-hoc KQL textarea)
- Modify: `apps/tauri/src/components/DatasetsLeftPanel.tsx` (the `runHuntingTemplate`/`runAdhocKql` wiring, if it needs the flag)
- Possibly: the TS type for `SentinelEnvStatus` / wherever `cmd_sentinel_check_env`'s result is typed.

**Interfaces:**
- Consumes: `cmd_sentinel_check_env` → `SentinelEnvStatus` now carrying `hunting_templates_enabled` + `kql_escape_hatch_enabled` (Task 1). The component already calls `cmd_sentinel_check_env` (confirm; if not, add the invoke + state).
- Produces: `HuntingTemplatesSection` (the 4 cards + "ver KQL" preview) rendered only when `hunting_templates_enabled`; the ad-hoc raw-KQL textarea rendered only when `kql_escape_hatch_enabled`.

- [ ] **Step 1: Thread the two flags into the component**

Read `SentinelConnectForm.tsx` (the `HuntingTemplatesSection` at ~:415 and the ad-hoc KQL textarea rendered via ~:257) and `DatasetsLeftPanel.tsx`. Ensure the component has the `SentinelEnvStatus` (from an existing `cmd_sentinel_check_env` call, or add one with `useState`/`useEffect`). Add the two new booleans to the TS type of the env status.

- [ ] **Step 2: Conditionally render**

Wrap `HuntingTemplatesSection` so it renders only when `hunting_templates_enabled !== false` (default-visible: treat `undefined`/`true` as on, matching the backend default-ON — so a frontend built before the backend field exists still shows it). Wrap the ad-hoc KQL textarea similarly on `kql_escape_hatch_enabled !== false`. When hidden, do not leave a dangling label/handler.

- [ ] **Step 3: Build-verify the frontend**

Run the frontend build/typecheck (e.g. `cd apps/tauri && npm run build` or the repo's `tsc`/vite check — confirm the exact command from `package.json`). Expected: compiles/typechecks with no errors. (This is TS/vite, unaffected by the Rust ONNX blocker.) If a full build is heavy, at minimum run the typecheck script.

- [ ] **Step 4: Commit**

```bash
git add apps/tauri/src/components/ingest/SentinelConnectForm.tsx apps/tauri/src/components/DatasetsLeftPanel.tsx
git commit -m "feat(ui): hide hunting templates + ad-hoc KQL when their flags are off (Fase G, default visible)"
```

(Stage the TS types file too if you edited it. Nothing else.)

---

### Task 4: Migration doc Fase G section + null-delta audit + ledger

**Files:**
- Modify: `docs/migration/sentinel-mcp-decoupling.md` (Fase G section)
- Re-run (sot repo): `python scripts/sot_sys/audit_graphhunter.py --check` — expect null delta.

**Interfaces:**
- Consumes: Tasks 1-3 (cite the flag names, the gate, the closed bypass, the frontend hiding).
- Produces: the migration doc's Fase G certification; a ledger line.

- [ ] **Step 1: Write the Fase G section**

Append to `docs/migration/sentinel-mcp-decoupling.md`, honestly:
- **Criterion already satisfied by architecture:** the analytic-hypothesis KQL path does not exist — `run_hunt`/`run_hunt_batch` are 100% local with NO KQL fallback (cite `operations/hunt.rs`); the MCP hypothesis tools use no KQL (Fase D/E); the escape hatch was already gated at HTTP (Fase A). State this is the real content of Fase G's acceptance criterion "MCP sin KQL para hipótesis" — met by construction, not by this phase's code.
- **What this phase added (defense-in-depth, opt-in):** the new `GRAPHHUNTER_HUNTING_TEMPLATES` flag gating `run_hunting_template` (API-layer, so all callers); closing the GUI `cmd_run_kql` bypass so free-text KQL honors `GRAPHHUNTER_KQL_ESCAPE_HATCH` uniformly across HTTP/MCP/GUI; frontend hiding of both surfaces when off. Both flags **default ON** — zero production behavior change.
- **Honest limits + the pending decision:** the "collection" KQL (materialization, schema-discovery, hydration, seed, streaming) stays — it is data collection, not analysis, per spec. The `apps/tauri` command + frontend changes are compile/build-verified (flag semantics green-tested in platform/api; `apps/tauri` test execution blocked by the pre-existing ONNX DLL issue). **Flipping either default to OFF in production (actually retiring a surface) is the user's separate, explicit decision and is NOT done here** — this phase makes retirement possible and reversible, gated behind an opt-in flag.
- Use the doc's existing claim discipline (implemented/tested/descriptive).

- [ ] **Step 2: Null-delta audit**

Run: `cd /c/Users/lsotomayor/sot && python scripts/sot_sys/audit_graphhunter.py --check`
Expected: `audit_results.json up to date` (Fase G touches no telemetry channel). If it reports drift, STOP and investigate.

- [ ] **Step 3: Commit + ledger**

```bash
git add docs/migration/sentinel-mcp-decoupling.md
git commit -m "docs(migration): Fase G — analytic-KQL retirement is opt-in gating; criterion met by architecture; default unchanged"
```

Append to `.superpowers/sdd/progress.md`: Fase G complete as opt-in gating (2 flags default ON, GUI bypass closed, frontend hiding); analytic criterion met by architecture; audit null-delta; production-default flip remains user's explicit pending decision.

---

## Self-Review notes

- **Spec coverage:** §25.2 (MCP sin KQL para hipótesis) → documented as met-by-architecture (Task 4) with the residual surfaces now gateable (Tasks 1-3). §25.13 (camino viejo tras feature flag) → the two residual KQL surfaces are now behind flags. Fase G ("desactivar cuando tests y métricas demuestren equivalencia") → the equivalence evidence is the prior validation-mode phase; this phase makes the *disable* mechanism exist without exercising it in production.
- **No placeholders:** every step has concrete code/commands; the two "confirm against source" notes (ApiError variant, exact request fields, frontend command wiring) are verification instructions.
- **Type consistency:** `hunting_templates_enabled()`/`kql_escape_hatch_enabled()` defined in Task 1, consumed by Tasks 2-3; `SentinelEnvStatus`'s two new bools flow Task 1 → Task 3.
- **YAGNI / honesty:** no default flip, no gating of collection KQL, no new analytic path removed (there is none) — the phase is precisely the opt-in gating the honest scope calls for.
