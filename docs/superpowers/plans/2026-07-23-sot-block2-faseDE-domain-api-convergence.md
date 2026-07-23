# Fase D/E — Domain API Convergence + Cross-Transport Certificate Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Certify SOT acceptance criterion §25.11 ("misma hipótesis = mismo resultado desde core/REST/MCP") for the hypothesis path, and fix the transport field-drop that silently strips Fase F's `AnswerCoverage` from the MCP/HTTP response.

**Architecture:** Fases D ("MCP + frontend consume the local Domain API for hypotheses") and E ("`run_hypothesis` always runs on the local engine") are, per reconnaissance, already the runtime behavior: the MCP POSTs a DSL hypothesis to the local desktop HTTP server, which delegates to the single transport-agnostic `GraphHunterApi::run_hunt` — the exact function the Tauri GUI command `cmd_run_hunt` calls. No KQL is generated for hypotheses; no Sentinel round-trip happens. The genuine gap is a **certificate** and one **defect**: the HTTP handler (`apps/tauri/src-tauri/src/http/hunt.rs`) defines its own `RunHuntResponse` struct that re-emits only `path_count`/`truncated`/`diagnostic`/`live_tail_coverage` and **drops the `coverage: AnswerCoverage` field** the core response carries (with Fase F's `missing_sources`/`source_watermarks`). So Fase F's "a blind/failed window is distinguishable on the answer" guarantee holds in the core but is lost over the MCP transport — the primary SOT consumer. This phase surfaces `coverage` on the transport and adds a two-layer cross-transport certificate mirroring the repo's existing `tests/parity` philosophy.

**Tech Stack:** Rust (axum 0.7, serde, tokio), `tower` (util/`oneshot`) as a new dev-dependency for the end-to-end layer; Python audit runner (sot repo) for the null-delta re-freeze.

## Global Constraints

- **No-op when off:** with `GRAPHHUNTER_COVERAGE` off, `AnswerCoverage::default()` + `skip_serializing_if` must yield **byte-identical** wire JSON to the pre-coverage contract. The new `coverage` field on the HTTP response MUST carry the same `skip_serializing_if` guard so flag-off callers see no change.
- **Honesty of the audit flips:** Fase D/E changes **no telemetry channel** — the frozen audit verdict (30/30 Sufficient) MUST be unchanged after this phase. The re-run's honest report is a **null delta** (criterion §17: each phase re-runs the runner and shows the change; here the change is "none"). Do NOT claim D/E advanced any sufficiency channel.
- **Do not touch unrelated WIP:** both repos carry pre-existing uncommitted/untracked WIP (incl. `platform/parsers/src/haproxy.rs`). Never `git add -A`; stage only the files each task names.
- **The projection is intentional for `paths`:** the HTTP handler deliberately does not inline `paths` (MCP pages them via `hunt_results`/`get_hunt_page`). Only `coverage` is an unintended drop. Do not add `paths` to the HTTP response.
- **KQL stays out of the hypothesis path:** no task may introduce KQL rendering into `run_hunt`/the MCP hunt tools. The escape hatch (`sentinel_query`) and collection KQL (`graph_build`/`graph_propose`) are out of scope.

---

### Task 1: Surface `coverage` on the HTTP hunt response + cross-transport certificate

**Files:**
- Modify: `apps/tauri/src-tauri/src/http/hunt.rs` (add `coverage` field to the response struct; extract a pure projection fn; add tests)
- Modify: `apps/tauri/src-tauri/src/http/mod.rs` (make `build_app` `pub(crate)` so the end-to-end test can drive the real router)
- Modify: `apps/tauri/src-tauri/Cargo.toml` (add `tower` with `util` feature under `[dev-dependencies]`)
- Test: inline `#[cfg(test)] mod tests` in `apps/tauri/src-tauri/src/http/hunt.rs`

**Interfaces:**
- Consumes: `graph_hunter_api::dto::hunt::RunHuntResponse` (core; has `pub coverage: AnswerCoverage`, `pub paths`, `path_count`, `truncated`, `diagnostic`, `live_tail_coverage`); `graph_hunter_api::coverage::AnswerCoverage` (`pub`, derives `Default + Serialize + Deserialize + PartialEq`); `GraphHunterApi::run_hunt(RunHuntRequest) -> ApiResult<RunHuntResponse>`.
- Produces: `fn project_run_hunt_response(&graph_hunter_api::dto::hunt::RunHuntResponse) -> RunHuntResponse` (the pure core→http mapping, unit-tested); `pub(crate) fn build_app(...)` in `http/mod.rs`.

- [ ] **Step 1: Write the failing projection test**

Add to a `#[cfg(test)] mod tests` in `http/hunt.rs`. This pins the defect: a core response carrying a non-default `coverage` must serialize `coverage` on the HTTP response.

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use graph_hunter_api::coverage::AnswerCoverage;

    // A core response with a populated coverage (Fase F: a blind source)
    // must survive the core->http projection and appear on the wire.
    #[test]
    fn coverage_survives_core_to_http_projection() {
        let mut cov = AnswerCoverage::default();
        cov.possibly_incomplete = true;
        cov.missing_sources = vec!["sentinel".to_string()];
        cov.source_watermarks.insert("elastic".to_string(), 42);

        let core = graph_hunter_api::dto::hunt::RunHuntResponse {
            paths: vec![],
            path_count: 7,
            truncated: false,
            diagnostic: None,
            live_tail_coverage: None,
            coverage: cov,
        };

        let http = project_run_hunt_response(&core);
        let v = serde_json::to_value(&http).unwrap();
        assert_eq!(v["path_count"], 7);
        assert_eq!(v["coverage"]["missing_sources"][0], "sentinel");
        assert_eq!(v["coverage"]["source_watermarks"]["elastic"], 42);
        assert_eq!(v["coverage"]["possibly_incomplete"], true);
    }

    // No-op when off: a default coverage must be omitted entirely so
    // flag-off callers see byte-identical JSON to the pre-coverage wire.
    #[test]
    fn default_coverage_is_omitted_from_http_wire() {
        let core = graph_hunter_api::dto::hunt::RunHuntResponse {
            paths: vec![],
            path_count: 0,
            truncated: false,
            diagnostic: None,
            live_tail_coverage: None,
            coverage: AnswerCoverage::default(),
        };
        let http = project_run_hunt_response(&core);
        let v = serde_json::to_value(&http).unwrap();
        assert!(v.get("coverage").is_none(), "default coverage must be omitted from the wire");
    }
}
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `cd apps/tauri/src-tauri && cargo test --lib coverage_survives_core_to_http_projection`
Expected: FAIL to compile — `project_run_hunt_response` does not exist and `RunHuntResponse` has no `coverage` field.

- [ ] **Step 3: Add the `coverage` field + skip guard + pure projection fn**

In `http/hunt.rs`, extend the response struct and add a `skip_serializing_if` helper + the projection fn. `AnswerCoverage` derives `PartialEq + Default`, so default-detection is a plain equality check.

```rust
#[derive(serde::Serialize)]
pub(super) struct RunHuntResponse {
    path_count: usize,
    truncated: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    diagnostic: Option<graph_hunter_core::HuntDiagnostic>,
    #[serde(skip_serializing_if = "Option::is_none")]
    live_tail_coverage: Option<graph_hunter_core::LiveTailCoverage>,
    // Fase D/E: carry the core's answer-coverage across the transport so
    // the MCP consumer sees Fase F's missing_sources/source_watermarks.
    // Default coverage is omitted -> byte-identical wire when the flag is off.
    #[serde(skip_serializing_if = "is_default_coverage")]
    coverage: graph_hunter_api::coverage::AnswerCoverage,
}

fn is_default_coverage(c: &graph_hunter_api::coverage::AnswerCoverage) -> bool {
    *c == graph_hunter_api::coverage::AnswerCoverage::default()
}

/// Pure core->http projection. `paths` is intentionally not inlined
/// (the MCP pages results via /hunt_results); `coverage` MUST cross.
fn project_run_hunt_response(
    resp: &graph_hunter_api::dto::hunt::RunHuntResponse,
) -> RunHuntResponse {
    RunHuntResponse {
        path_count: resp.path_count,
        truncated: resp.truncated,
        diagnostic: resp.diagnostic.clone(),
        live_tail_coverage: resp.live_tail_coverage.clone(),
        coverage: resp.coverage.clone(),
    }
}
```

Then, in `handler_run_hunt`, replace the inline `ok_json(RunHuntResponse { path_count: resp.path_count, truncated: resp.truncated, diagnostic: resp.diagnostic, live_tail_coverage: resp.live_tail_coverage })` construction with `ok_json(project_run_hunt_response(&resp))`. Keep all the existing view-emission logic (node_ids/subgraph) unchanged — only the final `ok_json(...)` payload changes. Note `resp` is consumed after; if the borrow conflicts with the earlier `resp.paths`/`resp.path_count` reads, project after those reads (project takes `&resp`, so read order is fine).

- [ ] **Step 4: Run the projection tests to verify they pass**

Run: `cd apps/tauri/src-tauri && cargo test --lib project -- --nocapture` and `cargo test --lib coverage`
Expected: PASS — both `coverage_survives_core_to_http_projection` and `default_coverage_is_omitted_from_http_wire`.

- [ ] **Step 5: Add the end-to-end (oneshot) equivalence test**

Add `tower = { version = "0.5", features = ["util"] }` to `[dev-dependencies]` in `apps/tauri/src-tauri/Cargo.toml` (match the workspace's existing tower-http 0.5 line; if 0.5 fails to resolve against axum 0.7, use `tower = { version = "0.4", features = ["util"] }`). Make `build_app` `pub(crate)` in `http/mod.rs`.

Add the end-to-end test to the same `mod tests`. It drives the SAME DSL through the real router via `oneshot` and asserts the HTTP result equals a direct `api.run_hunt` call — the §25.11 certificate for the transport wiring. Use the crate's existing helpers for building an `AppState`/`GraphHunterApi` in tests; if none exists, seed a `GraphHunterApi::new_noop()` (as `tests/parity/fixture.rs` does) with a small graph and a session, and construct `AppState` the way `http::run` does. Match the actual constructor signatures in the crate — do not invent them.

```rust
#[tokio::test]
async fn same_hypothesis_same_result_core_vs_http() {
    use tower::ServiceExt; // oneshot
    use axum::body::Body;
    use axum::http::{Request, StatusCode};

    // Build an API + seeded session shared by both transports.
    let (app_state, api, session_id, dsl) = crate::http::hunt::tests_support::seeded_hunt_fixture();

    // (a) direct core call
    let core = api
        .run_hunt(graph_hunter_api::dto::hunt::RunHuntRequest {
            session: Some(session_id.clone().into()),
            hypothesis: graph_hunter_core::parse_dsl(dsl, Some("t")).unwrap().hypothesis,
            time_window: None,
            max_results: Some(10_000),
            scoring: None,
            dedup_mode: None,
        })
        .unwrap();

    // (b) through the real router
    let app = crate::http::build_app(app_state, api.clone());
    let req = Request::builder()
        .method("POST")
        .uri("/run_hunt")
        .header("content-type", "application/json")
        .body(Body::from(serde_json::json!({ "hypothesis_dsl": dsl }).to_string()))
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX).await.unwrap();
    let http: serde_json::Value = serde_json::from_slice(&bytes).unwrap();

    // Same hypothesis => same answer across transports.
    assert_eq!(http["path_count"].as_u64().unwrap() as usize, core.path_count);
    assert_eq!(http["truncated"].as_bool().unwrap(), core.truncated);
}
```

If wiring a full `AppState` proves impractical in a unit test (it needs the desktop event sink), keep the projection tests (Step 1) as the field-drop guard and downgrade this end-to-end test to assert only the `/run_hunt` route exists and returns 200 for a valid DSL against an empty session — documenting in a comment (like `siem.rs` does) exactly what harness limitation forced the reduced form. Do NOT fabricate a passing test by mocking away the handler. Report which form you landed.

- [ ] **Step 6: Run the full hunt + parity suite**

Run: `cd apps/tauri/src-tauri && cargo test --lib hunt` then `cd ../../../platform/api && cargo test --test parity`
Expected: all green; parity still 35/35 (this task doesn't touch the core DTO, only the transport re-emit).

- [ ] **Step 7: Commit**

```bash
git add apps/tauri/src-tauri/src/http/hunt.rs apps/tauri/src-tauri/src/http/mod.rs apps/tauri/src-tauri/Cargo.toml apps/tauri/src-tauri/Cargo.lock
git commit -m "fix(http): surface AnswerCoverage on /run_hunt response + cross-transport equivalence test (Fase D/E)"
```

(Include `Cargo.lock` only if adding `tower` changed it. Do not stage anything else.)

---

### Task 2: Certify D/E in the migration doc + null-delta audit re-run

**Files:**
- Modify: `C:\Users\lsotomayor\GraphHunter\docs\migration\sentinel-mcp-decoupling.md` (add a Fase D/E section)
- Re-run (sot repo): `python scripts/sot_sys/audit_graphhunter.py --check` — expect "up to date" (no channel changed)
- Modify (only if a tracked frozen file changes — expected NONE): `C:\Users\lsotomayor\sot\validation\graphhunter\*`

**Interfaces:**
- Consumes: Task 1's committed fix + tests (cite the file:line of `project_run_hunt_response` and the equivalence test as the §25.11 evidence).
- Produces: the migration doc's D/E certification section; a ledger line recording the null audit delta.

- [ ] **Step 1: Write the Fase D/E section in the migration doc**

Append a section to `docs/migration/sentinel-mcp-decoupling.md` covering, honestly:
- **Convergence (evidence):** MCP `hunt_run` → HTTP `/run_hunt` → `GraphHunterApi::run_hunt` ← Tauri `cmd_run_hunt`; one engine, always local, no hypothesis KQL. Cite `platform/mcp/src/tools/hunt/run.ts`, `apps/tauri/src-tauri/src/http/hunt.rs:handler_run_hunt`, `platform/api/src/operations/hunt.rs:run_hunt`, `apps/tauri/src-tauri/src/commands/graph_ops.rs:cmd_run_hunt`.
- **§25.11 certified:** name the new projection tests + the equivalence test as the certificate, and note they close the `tests/parity/scenarios.rs` "until a full HTTP/Tauri runtime harness lands" gap for the hunt path.
- **Defect found & fixed:** the HTTP `RunHuntResponse` previously dropped `coverage`, so Fase F's `missing_sources`/`source_watermarks` never reached the MCP; now surfaced. State plainly that **before this fix, Fase F's guarantee did not hold over the MCP transport** — this is the honest walk-back-style disclosure the program requires.
- **Honest residuals (unclaimed):** (a) GUI `cmd_run_hunt` hardcodes `scoring: None`/`dedup_mode: None` while the MCP exposes per-call overrides — an intentional default asymmetry, not an engine divergence; (b) `paths` are intentionally paged (not inlined) on the HTTP response; (c) the Domain API still carries ~231 `AZURE_*`/`TimeGenerated` hits in its **collection/export** layers (Fase A territory), orthogonal to hypothesis evaluation — D/E does not claim to have de-Azured the API.

Use the Tabla-1 claim discipline (proved/implemented/tested/proposed) already used across these docs: the convergence is **tested**; the coverage fix is **tested**; the residuals are **stated limits**.

- [ ] **Step 2: Re-run the audit runner (null-delta check)**

Run: `cd /c/Users/lsotomayor/sot && python scripts/sot_sys/audit_graphhunter.py --check`
Expected: `audit_results.json up to date` (D/E changed no telemetry channel; 30/30 Sufficient unchanged). If — unexpectedly — the runner reports drift, STOP and investigate before committing: a D/E-induced verdict change would mean an unintended channel edit.

- [ ] **Step 3: Commit the doc (GraphHunter repo)**

```bash
git add docs/migration/sentinel-mcp-decoupling.md
git commit -m "docs(migration): certify Fase D/E convergence + record the MCP coverage-drop fix"
```

- [ ] **Step 4: Record the null delta in the ledger**

Append to `.superpowers/sdd/progress.md`: `Fase D/E: convergence certified (§25.11 tested via projection + oneshot equivalence); MCP coverage-drop defect fixed; audit re-run = NULL DELTA (30/30 Sufficient unchanged, no channel touched).` No sot commit is expected (no frozen file changed); if `--check` was clean, do not fabricate a re-freeze commit.

---

## Self-Review notes

- **Spec coverage:** §25.11 (same hypothesis = same result core/REST/MCP) → Task 1 certificate. §25.2 (MCP without KQL for hypotheses) → already true, documented in Task 2. Criterion §17 (each phase re-runs the runner, shows delta) → Task 2 Step 2 (delta = null, honestly reported). Deliverable "Refactor MCP sobre Domain API | 2-D/E" → the convergence is pre-existing; the deliverable is the certificate + the coverage-drop fix + the migration doc.
- **No placeholders:** all test code is complete; the one conditional is Step 5's harness fallback, which is explicitly bounded (keep projection guard; document the limitation like `siem.rs`; never fake a pass).
- **Type consistency:** `project_run_hunt_response` returns the http `RunHuntResponse` (Task 1) and is referenced by name in Task 2's doc. `is_default_coverage` uses `AnswerCoverage: PartialEq + Default` (confirmed derived).
