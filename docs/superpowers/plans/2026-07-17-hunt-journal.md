# Hunt Journal + token-lean tool surface — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make GraphHunter mandatorily capture every hunting action + its graph topology into a per-hunt journal (Part A), and use that server-side retention to return terse summary-first tool responses with a measured token budget (Part B) — so a hunt via the tools costs the LLM fewer tokens than raw KQL, verifiably.

**Architecture:** Part A is an engine/HTTP change in `apps/tauri/src-tauri/src` — a capture middleware on the existing request chokepoint, a new pure-logic `journal/` module (event schema, secret redaction, append-only per-hunt store, path→semantics interpreter), `/journal/*` endpoints, and MCP wrapper tools. Part B adds a per-endpoint summarizer + token estimator (same module) and makes the MCP response renderer prefer an API-provided summary over blunt truncation. Staged: A first (journal), then B (token-lean) on top.

**Tech Stack:** Rust (`apps/tauri/src-tauri`, axum) + TypeScript (`platform/mcp`). Serde JSON. Tests: Rust `#[test]` (`cargo test` from the crate dir) + MCP `node:test` (`cd platform/mcp && npm run build && npm run test:contract`).

## Global Constraints

- **Mandatory capture is enforced at the transport layer** — the axum middleware, not per-handler and not the prompt. Every non-excluded request produces a `HuntEvent`.
- **Secrets are NEVER persisted** — `azure_client_secret`, `azure_client_id`, keys matching `*secret*`/`*token*`/`*password*`, and the `Authorization` header are redacted before any write. Hard requirement, no opt-out.
- **No bulky response bodies stored** — summaries + graph-fingerprint deltas only; `result.body_bytes` records size, not content.
- **Per-hunt journal keyed by a cycle id** — current-hunt model: events attach to the engine's current hunt id (lazily created), `/journal/start {label}` rotates.
- **Additive / backward-compatible** — new middleware behavior + new endpoints/module + a new optional summary field; existing endpoint contracts unchanged; the MCP summary-first render falls back to today's truncation when no summary is present.
- **`est_tokens` is a heuristic** (bytes/≈4) — for comparison + soft-cap only, not billing-exact.
- Commits: **no Claude / Co-Authored-By trailers.** Conventional-commit prefixes.
- Branch `spec/hunt-journal` (already checked out; spec committed there).
- The working tree has pre-existing untracked/modified files (`informes-a/`, `docs/libro/`, other crates) — every task stages ONLY the files it changes.

---

### Task A0: Baseline — crate/test commands, AppState, middleware wiring

**Files:** none (read-only discovery).

- [ ] **Step 1:** Confirm the Tauri crate name + how to run its tests: `grep -m1 '^name' apps/tauri/src-tauri/Cargo.toml`. Establish the lib test command (likely `cd apps/tauri/src-tauri && cargo test --lib`) and record baseline green: run it, note the count. If red at baseline, STOP.
- [ ] **Step 2:** Read the wiring the plan builds on and record exact shapes for later tasks:
  - `grep -n "struct AppState" apps/tauri/src-tauri/src/lib.rs` (or wherever) — its fields + how it's constructed (this is where the journal store gets threaded).
  - `apps/tauri/src-tauri/src/http/mod.rs` — `log_requests` (:58), `auth_middleware`, `build_app` router + `.layer(...)` order, `HttpState` (:41).
  - `grep -n "dirs::data_dir" apps/tauri/src-tauri/src/lib.rs` — the on-disk base dir pattern (journals live under `data_dir()/graphhunter/journals/` — match the existing subdir convention).
- [ ] **Step 3:** Confirm MCP test cmd: `cd platform/mcp && npm run build && npm run test:contract` green at baseline. Record.

Record findings inline in your task report; later tasks reference them.

---

### Task A1: `HuntEvent` schema + secret redaction (pure)

**Files:**
- Create: `apps/tauri/src-tauri/src/journal/mod.rs` (module root, `pub mod event; pub mod redact;`)
- Create: `apps/tauri/src-tauri/src/journal/event.rs`
- Create: `apps/tauri/src-tauri/src/journal/redact.rs`
- Modify: `apps/tauri/src-tauri/src/lib.rs` (add `mod journal;`)

**Interfaces:**
- Produces:
  - `event.rs`: `HuntEvent { seq: u64, ts: i64, kind: String, endpoint: String, params: serde_json::Value, result: EventResult, topology: Topology }`, `EventResult { status: u16, duration_ms: u64, row_count: Option<u64>, new_entities: Option<u64>, new_relations: Option<u64>, body_bytes: u64, est_tokens: u64 }`, `Topology { graph_before: GraphCounts, graph_after: GraphCounts, touched: Option<Touched> }`, `GraphCounts { entities: u64, relations: u64 }`, `Touched { nodes: Vec<serde_json::Value>, edges: Vec<String>, path: Option<Vec<serde_json::Value>> }` — all `#[derive(Debug, Clone, Serialize, Deserialize, Default)]` (Default where sensible).
  - `redact.rs`: `pub fn redact_secrets(v: &serde_json::Value) -> serde_json::Value` — deep-clones the JSON, replacing the value of any key matching (case-insensitive) `azure_client_secret` / containing `secret`/`token`/`password` with the string `"[REDACTED]"`, recursing into objects and arrays.

- [ ] **Step 1: Write the failing test** — add `#[cfg(test)] mod tests` in `redact.rs`:
```rust
#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    #[test]
    fn redacts_azure_secret_and_tokenish_keys() {
        let v = json!({
            "kql": "SigninLogs | take 1",
            "azure_client_secret": "supersecret",
            "azure_client_id": "id-123",
            "nested": { "api_token": "abc", "keep": "ok" },
            "list": [{ "password": "pw" }]
        });
        let r = redact_secrets(&v);
        assert_eq!(r["azure_client_secret"], "[REDACTED]");
        assert_eq!(r["nested"]["api_token"], "[REDACTED]");
        assert_eq!(r["list"][0]["password"], "[REDACTED]");
        assert_eq!(r["kql"], "SigninLogs | take 1"); // non-secret preserved
        assert_eq!(r["nested"]["keep"], "ok");
        // original untouched
        assert_eq!(v["azure_client_secret"], "supersecret");
    }
}
```

- [ ] **Step 2: Run it, verify RED** — `cd apps/tauri/src-tauri && cargo test --lib redacts_azure_secret`. Expected: FAIL (module missing).

- [ ] **Step 3: Implement** — create the module, `event.rs` (structs above), and `redact.rs`:
```rust
use serde_json::Value;

fn is_secret_key(k: &str) -> bool {
    let k = k.to_ascii_lowercase();
    k == "azure_client_secret" || k.contains("secret") || k.contains("token") || k.contains("password")
}

/// Deep-clone `v`, replacing any secret-bearing field's value with "[REDACTED]".
pub fn redact_secrets(v: &Value) -> Value {
    match v {
        Value::Object(map) => Value::Object(
            map.iter()
                .map(|(k, val)| {
                    if is_secret_key(k) {
                        (k.clone(), Value::String("[REDACTED]".into()))
                    } else {
                        (k.clone(), redact_secrets(val))
                    }
                })
                .collect(),
        ),
        Value::Array(a) => Value::Array(a.iter().map(redact_secrets).collect()),
        other => other.clone(),
    }
}
```
Add `mod journal;` to `lib.rs` and `pub mod event; pub mod redact;` to `journal/mod.rs`.

- [ ] **Step 4: GREEN** — `cd apps/tauri/src-tauri && cargo test --lib journal::`. Expected: pass (+ full `cargo test --lib` still green).

- [ ] **Step 5: Commit**
```bash
git add apps/tauri/src-tauri/src/journal/ apps/tauri/src-tauri/src/lib.rs
git commit -m "feat(journal): HuntEvent schema + secret redaction"
```

---

### Task A2: Append-only per-hunt store + current-hunt state

**Files:**
- Create: `apps/tauri/src-tauri/src/journal/store.rs`
- Modify: `apps/tauri/src-tauri/src/journal/mod.rs` (`pub mod store;`)

**Interfaces:**
- Consumes (A1): `HuntEvent`.
- Produces: `JournalStore` — thread-safe (`Arc<Mutex<…>>` inside), constructed with a base dir (`JournalStore::new(base: PathBuf)`), with:
  - `fn start_hunt(&self, label: Option<String>) -> String` — creates a new hunt dir + `meta.json`, sets it current, returns the hunt id.
  - `fn current_hunt_id(&self) -> String` — the current hunt id, lazily creating an anonymous timestamp-id hunt if none is open (timestamp passed in — see note).
  - `fn append(&self, ev: HuntEvent)` — appends one JSON line to `<base>/<hunt_id>/events.jsonl` and bumps `meta.json` counters (event_count, cumulative est_tokens, cumulative entities/relations added).
  - `fn list(&self) -> Vec<HuntMeta>`, `fn read(&self, id: &str) -> Option<(HuntMeta, Vec<HuntEvent>)>`.
  - `HuntMeta { id, label: Option<String>, started_at, closed_at: Option<i64>, event_count, cumulative_est_tokens, entities_added, relations_added }`.
- Note on time/ids: `Date::now`/`SystemTime::now` ARE available in Rust here (unlike the workflow sandbox). Use `chrono::Utc::now()` for ids/timestamps (id = e.g. `hunt-{unix_millis}`), consistent with the rest of the codebase (`grep -n "Utc::now\|SystemTime" apps/tauri/src-tauri/src` to match the existing style).

- [ ] **Step 1: Write the failing test** (`store.rs` test module) — round-trip + attribution:
```rust
#[cfg(test)]
mod tests {
    use super::*;
    use crate::journal::event::HuntEvent;
    fn tmp() -> std::path::PathBuf {
        let p = std::env::temp_dir().join(format!("ghj-{}", uuid_like()));
        std::fs::create_dir_all(&p).unwrap(); p
    }
    // small helper to avoid rand: use a nanosecond counter
    fn uuid_like() -> u128 { std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos() }

    #[test]
    fn append_and_read_round_trip_under_current_hunt() {
        let store = JournalStore::new(tmp());
        let id = store.start_hunt(Some("cycle-A".into()));
        let mut ev = HuntEvent::default();
        ev.seq = 0; ev.kind = "query".into(); ev.endpoint = "/kql".into();
        ev.result.est_tokens = 42;
        store.append(ev.clone());
        let (meta, events) = store.read(&id).expect("hunt exists");
        assert_eq!(meta.label.as_deref(), Some("cycle-A"));
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].endpoint, "/kql");
        assert_eq!(meta.event_count, 1);
        assert_eq!(meta.cumulative_est_tokens, 42);
    }

    #[test]
    fn append_without_start_lazily_creates_current_hunt() {
        let store = JournalStore::new(tmp());
        let mut ev = HuntEvent::default(); ev.endpoint = "/graph/neighbors".into();
        store.append(ev);
        assert_eq!(store.list().len(), 1); // one lazily-created hunt
    }
}
```

- [ ] **Step 2: RED** — `cd apps/tauri/src-tauri && cargo test --lib journal::store`. FAIL (store missing).

- [ ] **Step 3: Implement** `store.rs`: an `Arc<Mutex<Inner>>` holding `base: PathBuf` + `current: Option<String>`. `append` computes `seq` from the current hunt's existing event count, writes the line with `OpenOptions::new().create(true).append(true)`, and updates `meta.json` (read-modify-write under the lock). `start_hunt` mints `hunt-{millis}` (+ a short suffix from a counter to avoid collision), creates the dir + initial `meta.json`, sets `current`. `current_hunt_id` returns `current` or calls `start_hunt(None)`. Serialize meta/events with `serde_json`. Keep it simple and synchronous (file I/O under the mutex).

- [ ] **Step 4: GREEN** — `cd apps/tauri/src-tauri && cargo test --lib journal::`. Pass + full lib green.

- [ ] **Step 5: Commit**
```bash
git add apps/tauri/src-tauri/src/journal/store.rs apps/tauri/src-tauri/src/journal/mod.rs
git commit -m "feat(journal): append-only per-hunt store with current-hunt attribution"
```

---

### Task A3: Path→semantics interpreter

**Files:**
- Create: `apps/tauri/src-tauri/src/journal/interpret.rs`
- Modify: `apps/tauri/src-tauri/src/journal/mod.rs` (`pub mod interpret;`)

**Interfaces:**
- Produces: `pub fn classify_kind(path: &str) -> &'static str` mapping the endpoint path to a kind, and `pub fn extract_touched(path: &str, resp: &serde_json::Value) -> Option<Touched>` pulling the small subgraph from a graph-traversal response. `pub fn extract_result_meta(resp: &serde_json::Value) -> (Option<u64>, Option<u64>, Option<u64>)` returning `(row_count, new_entities, new_relations)` from known response fields.

- [ ] **Step 1: Write the failing test** (`interpret.rs`):
```rust
#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    #[test]
    fn classifies_known_endpoints() {
        assert_eq!(classify_kind("/sentinel/seed"), "seed");
        assert_eq!(classify_kind("/graph/build"), "build");
        assert_eq!(classify_kind("/graph/neighbors"), "traverse");
        assert_eq!(classify_kind("/graph/path"), "traverse");
        assert_eq!(classify_kind("/kql"), "query");
        assert_eq!(classify_kind("/notes"), "note");
        assert_eq!(classify_kind("/something_new"), "other");
    }
    #[test]
    fn extracts_query_row_count_and_build_counts() {
        let (rows, _, _) = extract_result_meta(&json!({"row_count": 54}));
        assert_eq!(rows, Some(54));
        let (_, ne, nr) = extract_result_meta(&json!({"new_entities": 8, "new_relations": 227}));
        assert_eq!((ne, nr), (Some(8), Some(227)));
    }
    #[test]
    fn extracts_touched_from_neighbors() {
        let resp = json!({"entity": {"class":"User","value":"a@b.com"},
                          "neighbors": [{"edge":"Connect","node":{"class":"IP","value":"1.1.1.1"}}]});
        let t = extract_touched("/graph/neighbors", &resp).expect("touched");
        assert_eq!(t.edges, vec!["Connect"]);
        assert_eq!(t.nodes.len(), 1);
    }
}
```

- [ ] **Step 2: RED** — `cd apps/tauri/src-tauri && cargo test --lib journal::interpret`. FAIL.

- [ ] **Step 3: Implement** — `classify_kind`: match on path prefix (`/sentinel/seed`→seed; `/graph/build`→build; `/graph/neighbors`|`/graph/path`|`/graph/anomaly`→traverse; `/kql`→query; `/notes`→note; `/tag`|`/untag`→tag; `/save_hypothesis_as_sigma`→finding; `/export_`|`/file_ticket`|`/publish_`→export; else `other`). `extract_result_meta`: read `resp["row_count"]/["new_entities"]/["new_relations"]` as u64 if present. `extract_touched`: for `/graph/neighbors`, map `resp["neighbors"]` → `Touched { nodes: [neighbor.node], edges: [neighbor.edge], path: None }`; for `/graph/path`, map the path array; else `None`. (Consult the real response shapes: `grep -n "struct.*Neighbor\|struct GraphPathResult\|neighbors" platform/api/src/dto/v1/graph_ops.rs` — mirror field names.)

- [ ] **Step 4: GREEN** — `cd apps/tauri/src-tauri && cargo test --lib journal::`. Pass.

- [ ] **Step 5: Commit**
```bash
git add apps/tauri/src-tauri/src/journal/interpret.rs apps/tauri/src-tauri/src/journal/mod.rs
git commit -m "feat(journal): path->kind interpreter + topology/meta extraction"
```

---

### Task A4: Capture middleware (mandatory) + wire the store into AppState

**Files:**
- Modify: `apps/tauri/src-tauri/src/http/mod.rs` (replace/extend `log_requests`; register store)
- Modify: `apps/tauri/src-tauri/src/lib.rs` (construct `JournalStore` with `data_dir()/graphhunter/journals`, put it in `AppState`)

**Interfaces:**
- Consumes: `JournalStore` (A2), `redact_secrets` (A1), `classify_kind`/`extract_result_meta`/`extract_touched` (A3).
- Produces: every non-excluded request appends a `HuntEvent` to the current hunt.

- [ ] **Step 1: Read** (from A0's notes) `AppState`'s fields + construction in `lib.rs`, and the middleware layer order + `build_app` in `http/mod.rs`. Add a `pub journal: Arc<JournalStore>` field to `AppState` (or `HttpState`), constructed in `lib.rs`.

- [ ] **Step 2: Write the failing test** — an integration test that drives `build_app`'s router in-process and asserts an event was journaled. If the router isn't easily unit-testable, instead unit-test a helper `fn build_event(path, method, status, dur_ms, req_body, resp_body, before, after) -> HuntEvent` that assembles a redacted `HuntEvent` from the captured parts, and assert it (secret redacted, kind classified, counts filled). Prefer the helper (deterministic, no live server):
```rust
#[test]
fn build_event_redacts_and_classifies() {
    let req = serde_json::json!({"kql":"X","azure_client_secret":"s"});
    let resp = serde_json::json!({"row_count": 3});
    let ev = build_event("/kql", "POST", 200, 12, &req, &resp,
                         GraphCounts{entities:0,relations:0}, GraphCounts{entities:0,relations:0});
    assert_eq!(ev.kind, "query");
    assert_eq!(ev.params["azure_client_secret"], "[REDACTED]");
    assert_eq!(ev.result.row_count, Some(3));
    assert!(ev.result.est_tokens > 0);
}
```

- [ ] **Step 3: RED** — `cd apps/tauri/src-tauri && cargo test --lib build_event_redacts`. FAIL.

- [ ] **Step 4: Implement**
  - `build_event(...)` in `journal/mod.rs` (or http): assemble `HuntEvent` using `classify_kind`, `redact_secrets(req_body)`, `extract_result_meta(resp)`, `extract_touched(path, resp)`, `est_tokens = (serialized summary len)/4`, `body_bytes = resp serialized len`, `topology.graph_before/after` from the passed counts.
  - The `capture` middleware in `http/mod.rs`: buffer the request body (axum: `let (parts, body) = req.into_parts(); let bytes = to_bytes(body).await; …` then rebuild `Request::from_parts(parts, Body::from(bytes.clone()))`), parse it as JSON (best-effort; non-JSON → `Value::Null`), read graph counts before (from `State(Arc<AppState>)` via a cheap count — reuse the graph summary totals; `grep -n "fn graph_summary\|entity_count\|total_entities" platform/api/src`), run `next.run`, read counts after, buffer the response similarly to extract the small JSON for the interpreter (cap parsing to a sane size; if the body is huge, skip `extract_touched`/`row_count` and still record the mandatory core), then `state.journal.append(build_event(...))`. Skip the allowlist paths (`/health`, `/metrics`, `/`, and any `/journal/…`). Register the middleware in `build_app` so it sees authenticated, path-resolved requests (inside auth). Keep `tracing::debug!` line too.

- [ ] **Step 5: GREEN** — `cd apps/tauri/src-tauri && cargo test --lib` (build_event test + full lib green). Note: the middleware body-buffering path is exercised by the A6 integration test, not this unit test.

- [ ] **Step 6: Commit**
```bash
git add apps/tauri/src-tauri/src/http/mod.rs apps/tauri/src-tauri/src/lib.rs apps/tauri/src-tauri/src/journal/
git commit -m "feat(journal): mandatory capture middleware + AppState wiring"
```

---

### Task A5: `/journal/*` endpoints + MCP wrapper tools

**Files:**
- Create: `apps/tauri/src-tauri/src/http/journal.rs` (handlers)
- Modify: `apps/tauri/src-tauri/src/http/mod.rs` (routes)
- Create: `platform/mcp/src/tools/journal/{index.ts,start.ts,list.ts,get.ts,export.ts}`
- Modify: `platform/mcp/src/registry.ts` + `platform/mcp/src/tools/…` registry aggregation

**Interfaces:**
- Endpoints: `POST /journal/start {label?}` → `{hunt_id}`; `POST /journal/close`; `GET /journal/list` → `[HuntMeta]`; `GET /journal/:id` → `{meta, events}`; `POST /journal/export {id}` → NDJSON text.
- MCP tools mirror them (`journal_start/list/get/export`), thin `ctx.api` calls, following the existing tool pattern (see `platform/mcp/src/tools/notes/index.ts`).

- [ ] **Step 1:** Handlers in `journal.rs` calling `state.journal.{start_hunt,list,read}`; register routes in `build_app` (all under `/journal`, which the middleware allowlist skips). MCP tools mirror `tools/notes` exactly (copy the shape, swap paths).
- [ ] **Step 2:** MCP contract test `platform/mcp/tests/contract/journal-registered.test.ts` — assert `journal_list` etc. appear in `registry`. Rust: a handler smoke test if the router harness allows, else covered by A6.
- [ ] **Step 3:** `cd apps/tauri/src-tauri && cargo test --lib` green; `cd platform/mcp && npm run build && npm run test:contract` green.
- [ ] **Step 4: Commit**
```bash
git add apps/tauri/src-tauri/src/http/journal.rs apps/tauri/src-tauri/src/http/mod.rs platform/mcp/src/tools/journal/ platform/mcp/src/registry.ts platform/mcp/tests/contract/journal-registered.test.ts
git commit -m "feat(journal): /journal endpoints + MCP journal tools"
```

---

### Task A6: Integration acceptance — capture is mandatory + secret-free

**Files:**
- Create: `scripts/e2e-journal.mjs` (mirror `scripts/e2e-graph-cycle.mjs` auth/helper)

Manual/integration gate (needs a REBUILT app — the running `:37891` is stale). Requires the app rebuilt+restarted with this branch.

- [ ] **Step 1:** Script: `POST /journal/start {label:"e2e"}` → id. `POST /kql {kql:"SigninLogs | take 1", azure_client_secret:"FAKE-SECRET-123", ingest:false, acknowledge_fallback:true}`. `POST /graph/neighbors {entity:{class:"User",value:"x"}}` (may 200-error; fine). `GET /journal/:id`.
- [ ] **Step 2:** Assert: the journal has ≥2 events in order; the `/kql` event `kind=="query"`; **`FAKE-SECRET-123` appears NOWHERE** in the journal JSON (redaction); events carry `est_tokens > 0`. Print `journal e2e: mandatory capture + redaction OK`.
- [ ] **Step 3:** `node scripts/e2e-journal.mjs` against the rebuilt app. If app unavailable/stale, report BLOCKED (don't fake).
- [ ] **Step 4: Commit** `test(e2e): hunt-journal mandatory capture + secret redaction`

---

### Task B1: Per-endpoint summarizer + token estimator

**Files:**
- Create: `apps/tauri/src-tauri/src/journal/summarize.rs`
- Modify: `apps/tauri/src-tauri/src/journal/mod.rs` (`pub mod summarize;`)

**Interfaces:**
- Produces: `pub fn summarize(path: &str, resp: &serde_json::Value, detail_ref: &str) -> Option<serde_json::Value>` — for a large/known response, returns a compact summary object `{ _summary: true, kind, counts, top: [...], detail_ref }`; `None` when the response is already small (below a token threshold) or unknown (caller keeps the original). `pub fn est_tokens(v: &serde_json::Value) -> u64` (serialized_len / 4).

- [ ] **Step 1: Test** (`summarize.rs`): a large `/kql` response (100 rows) → `summarize` returns a summary with `top` ≤ N, `counts.row_count == 100`, and `detail_ref` set, and `est_tokens(summary) < est_tokens(full)`. A small response (2 rows) → `None`.
- [ ] **Step 2: RED** — `cd apps/tauri/src-tauri && cargo test --lib journal::summarize`.
- [ ] **Step 3: Implement** — `est_tokens` = `serde_json::to_string(v).len() as u64 / 4`. `summarize`: if `est_tokens(resp) <= THRESHOLD` (const, e.g. 400) → `None`. Else, per kind (reuse `classify_kind`): for `query`, take `resp["rows"][..N]` as `top`, `counts = {row_count}`; for `traverse`, keep the (already small) neighborhood but attach `detail_ref`; else a generic `{ counts: {keys/len}, detail_ref }`. Always include `_summary: true` + `detail_ref`.
- [ ] **Step 4: GREEN** — `cd apps/tauri/src-tauri && cargo test --lib journal::`.
- [ ] **Step 5: Commit** `feat(journal): semantic response summarizer + token estimator`

---

### Task B2: Wire est_tokens into events + `journal_stats`; expose summary from the API

**Files:**
- Modify: `apps/tauri/src-tauri/src/http/mod.rs` (capture middleware: set `est_tokens`; optional soft-cap forcing summary), `apps/tauri/src-tauri/src/http/journal.rs` (+ `GET /journal/:id/stats` or fold into `/journal/:id`), `platform/mcp/src/tools/journal/` (`journal_stats`)

- [ ] **Step 1:** In `build_event`, set `result.est_tokens = summarize::est_tokens(resp_summary_or_body)`. Store cumulative in meta (A2 already sums it). Add a `stats` accessor returning `{cumulative_est_tokens, event_count, by_kind}` and a `journal_stats` MCP tool.
- [ ] **Step 2: Test:** unit — two appended events → `meta.cumulative_est_tokens` is their sum (extends A2's assertion). MCP contract — `journal_stats` registered.
- [ ] **Step 3:** Rust + MCP suites green.
- [ ] **Step 4: Commit** `feat(journal): est_tokens accounting + journal_stats`

---

### Task B3: MCP render prefers API summary over blunt truncation

**Files:**
- Modify: `platform/mcp/src/lib/content.ts` (the truncation path) — when a tool result carries `_summary: true`, render it as-is (it's already compact) and DO NOT apply the byte-truncation; otherwise fall back to today's truncation.
- Test: `platform/mcp/tests/contract/summary-passthrough.test.ts`

- [ ] **Step 1: Test:** a payload with `_summary: true` passes through unchanged (no `_truncated` marker); a large non-summary payload still gets truncated as before.
- [ ] **Step 2: RED** — `cd platform/mcp && npm run build && npm run test:contract`.
- [ ] **Step 3: Implement** — guard the truncation entry with `if (isSummary(value)) return renderAsIs(value);`.
- [ ] **Step 4: GREEN** — contract suite green.
- [ ] **Step 5: Commit** `feat(mcp): pass API summaries through untruncated`

---

### Task B4: Acceptance — tool path is measurably cheaper than raw

**Files:**
- Modify: `scripts/e2e-journal.mjs` (add the token-comparison block)

Manual/integration gate (rebuilt app).

- [ ] **Step 1:** Run the same lookup two ways against the live app: (a) a graph/summary path (seed + neighbors, or a summarized `/kql`), (b) raw `/kql` returning full rows. Read `journal_stats` (or the events' `est_tokens`) for each. Assert the tool/summary path's cumulative `est_tokens` < the raw path's. Also assert a large query's response carries `_summary`/`detail_ref`.
- [ ] **Step 2:** `node scripts/e2e-journal.mjs` → prints `journal e2e: token-lean (tool < raw) OK`. BLOCKED if app stale.
- [ ] **Step 3: Commit** `test(e2e): token-lean tool path cheaper than raw`

---

## Self-Review

**Spec coverage:** §3a capture middleware → A4. §3b interpreter → A3. §3c store+endpoints+MCP tools → A2/A5. §3d redaction → A1. §4 HuntEvent → A1. §5 acceptance → A6. §5b summarizer+budget → B1/B2, MCP render B3, acceptance B4. §6 files map to A1–B4. §7 non-goals honored (no bulky bodies stored; est heuristic; no blob cache; secrets never persisted).

**Placeholder scan:** A0/A4-Step1 are read-to-discover steps (AppState fields + middleware order + graph-count source can't be spec'd without the file open); every such step names the exact grep and the concrete follow-up carries real code. No TBD/vague-error steps.

**Type consistency:** `HuntEvent`/`EventResult`/`Topology`/`GraphCounts`/`Touched` (A1) are consumed unchanged by A2/A3/A4/B1/B2. `JournalStore` methods (A2) are used by A4/A5/B2. `redact_secrets`, `classify_kind`, `extract_result_meta`, `extract_touched`, `summarize`, `est_tokens` names match across tasks. Endpoint paths + MCP tool names consistent A5↔B2↔B3.
