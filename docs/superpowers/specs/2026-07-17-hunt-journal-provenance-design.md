# Design — Hunt Journal + token-lean tool surface

**Date:** 2026-07-17
**Status:** Approved design, pending implementation plan
**Related:** HTTP API + `log_requests` middleware (`apps/tauri/src-tauri/src/http/mod.rs`), MCP response rendering (`safeJsonContent`, the blunt `GRAPHHUNTER_MCP_NO_TRUNCATE` truncation), session model (`platform/api/src/state/`), the agent-driven `/notes` (manual memory). Complements the graph-native work (gh_hunt, SaaS-egress) — once cycles are graph-native, the captured "routes" become real graph traversals.

**Two coupled capabilities, one insight.** Capturing everything server-side (the **journal**, Part A) is exactly what lets the tool return **terse summaries + handles** to the LLM instead of huge payloads (Part B) — without losing information, because the detail is durably retained. The result: a hunt driven through the tools costs the LLM **fewer tokens** than doing it raw (KQL dumps of thousands of rows into context), and the engine **measures** that so the guarantee is a number, not a claim.

---

## 1. Problem

A hunting cycle today leaves no reconstructable footprint. The delivered reports narrate findings, but the *actual path* taken — which queries ran, which pivots, which graph traversals, in what order, against what graph state — is not persisted anywhere. Consequences:

- **No provenance / audit trail.** For a regulated client (Niubiz, PCI scope), "how did you reach this finding" cannot be answered from a durable record — only from the analyst's prose.
- **No recreation.** A hunt cannot be resumed, handed to another analyst, or re-traced.
- **It depends on the prompt.** The only current persistence (`/notes`) is agent-discretionary — the agent must choose to save. Nothing *forces* a record of what was done, so most of the hunt's topology is lost the moment the session moves on.
- **It is token-expensive.** Driven raw, a hunt dumps large results into the LLM's context — a single `/kql` over a busy table returns hundreds of rows of JSON, every one paid for in tokens. This session's cycles ran that way; the graph was empty and each pivot's full rows entered context. Using the tool must cost *fewer* tokens than doing the hunt directly, not more — otherwise the "assisted" value is undercut by its own overhead.

**Goal:** GraphHunter must (A) act as a **hunt journal** — **mandatorily** capturing every hunting action (queries, pivots, traversals, seeds, builds, findings) and the **topology** (routes through the graph) of each hunt, so a cycle can be reviewed, audited, and (later) reconstructed — **without the prompt asking for it; the tool enforces it** — and (B) be **token-lean by construction**: tool responses to the LLM are compact summaries backed by server-side detail, and the engine **measures** response-token cost per hunt so "cheaper than raw" is verifiable.

## 2. Chosen scope and shape (approved)

- **Layered, trail-first.** **L1 (this spec):** mandatory capture + a per-hunt journal + view/export (the audit trail; also the substrate for later layers). **L2 (future):** graph reconstruction (replay seed/build events + dataset snapshots to re-materialize the same graph without re-querying Sentinel). **L3 (future):** deterministic replay (re-execute the full event stream — hard due to Sentinel data drift; aspirational).
- **Per action: a structured event + graph topology** (not full HTTP bodies). Semantic kind, params, result summary, and the topology touched.
- **Per-hunt journal keyed by a cycle id** (not one continuous stream) — so each cycle's journal attaches to its report as a provenance appendix.
- **Automatic secret redaction** is a hard requirement.
- **Token-lean responses + measured budget (Part B, §5b).** Tool responses to the LLM are **summary-first** (compact summary + a handle; full detail retained server-side via the journal), replacing the blunt truncation. The engine **estimates and accumulates response tokens per hunt** and exposes the number, so "tool path < raw-KQL path" is an auditable metric, not a promise.

## 3. Architecture — capture at the transport layer

Everything an agent or analyst does in a hunt becomes an HTTP request to the local API (all ~55 MCP tools call `ctx.api.post(...)`). The `log_requests` axum middleware (`apps/tauri/src-tauri/src/http/mod.rs`) already sees **every** request. That is the mandatory chokepoint: an action cannot happen without passing through it, and no prompt is involved.

Three pieces:

### 3a. Mandatory capture middleware (the enforcement)
Replace/extend `log_requests` with a `capture` middleware that, for every non-excluded request, records a `HuntEvent`:
- reads method + path;
- buffers and reads the **request body** (small — a KQL string, an IoC, a `proposal_id`, an anchor entity), then re-injects it for the handler;
- reads a cheap **graph fingerprint** (entity/relation counts) *before* and *after* `next.run(request)` — the **delta is the topology delta for free**, without parsing the (potentially large) response body;
- records response status, byte size, and duration;
- redacts secrets (§3d) and appends the event to the current hunt's journal (§3c).

Excluded by a small allowlist: `/health`, `/metrics`, `/`, `/journal/*` (don't journal the journal). The mandatory core (path + fingerprint delta + status/timing) needs **no** response-body parsing, so it is cheap even for 32 GB/day-scale query responses.

### 3b. Interpreter (structure + route)
A pure `interpret(path, req_body, resp_body_opt) -> (kind, topology_detail)` keyed on the endpoint path adds meaning on top of the mandatory core:
- `/sentinel/seed` → `kind: "seed"`, topology from the seed's returned neighborhood;
- `/graph/build` → `kind: "build"`;
- `/graph/neighbors` | `/graph/path` | `/graph/anomaly` → `kind: "traverse"`, topology = the nodes/edges/path in the response (small subgraphs);
- `/kql` → `kind: "query"` (+ `row_count` from the response metadata);
- `/notes` → `kind: "note"`; `/tag` → `kind: "tag"`; `/file_ticket`|`/export_*` → `kind: "export"`; `/save_hypothesis_as_sigma` → `kind: "finding"`.
- Unknown paths → `kind: "other"`, no topology detail (still fully captured by 3a).

The middleware guarantees **completeness**; the interpreter adds **richness**, degrading gracefully. A new endpoint is captured raw from day one, richly interpreted once an `interpret` arm is added.

### 3c. Store — the hunt journal ("servidor de guardado")
A dedicated append-only store, separate from the working session:
- **Current-hunt model (mandatory attribution):** the engine keeps a *current hunt id*. Every captured event attaches to it. Lazily creates one (timestamp id) if none is open, so attribution is automatic — no client cooperation. `POST /journal/start {label}` opens/rotates to a new hunt with a meaningful cycle id (e.g. `Hunting-2026-07-14-S01`); `POST /journal/close` seals the current one.
- **On disk:** `<data-dir>/journals/<hunt-id>/events.jsonl` (one `HuntEvent` per line, append-only → crash-robust) + `<hunt-id>/meta.json` (label, cycle id, started/closed_at, event count, cumulative topology counts). An index file lists hunts.
- **Endpoints:** `POST /journal/start`, `POST /journal/close`, `GET /journal/list`, `GET /journal/:id` (ordered events + accumulated topology), `POST /journal/export` (NDJSON of events, plus an optional topology-graph JSON for viewing).
- **MCP tools (thin wrappers):** `journal_list`, `journal_get`, `journal_export`, `journal_start` — so the huella is reviewable from the agent/analyst side like any other tool.

### 3d. Automatic secret redaction (hard requirement)
Before any request body is persisted, a redactor strips known secret-bearing fields from the JSON: `azure_client_secret`, `azure_client_id`, any key matching `*secret*`/`*token*`/`*password*`, and the `Authorization` header value. Applied **unconditionally** on every write path; the raw secret is never written to disk. Unit-tested against the `/kql`, `/sentinel/seed`, and `/graph/build` bodies (which carry `azure_client_secret`).

## 4. The `HuntEvent` schema

```
HuntEvent {
  seq: u64,              // per-hunt monotonic sequence
  ts: i64,               // epoch millis
  kind: String,          // seed|build|query|traverse|pivot|tag|note|finding|export|other
  endpoint: String,      // request path
  params: Value,         // request body, SECRETS REDACTED
  result: {
    status: u16,
    duration_ms: u64,
    row_count?: u64,     // extracted known metadata fields where cheap
    new_entities?: u64,
    new_relations?: u64,
    body_bytes: u64,     // size, not the body
  },
  topology: {
    graph_before: { entities: u64, relations: u64 },
    graph_after:  { entities: u64, relations: u64 },
    touched?: { nodes: [EntityRef], edges: [String], path?: [EntityRef] }  // traverse endpoints only
  }
}
```

The **fingerprint delta** (`graph_before`/`graph_after`) is the always-present topology signal (came from graph state, not the body); `touched` is the best-effort route detail from the interpreter.

## 5. What this delivers (L1 acceptance)

- Run any sequence of hunting actions → `GET /journal/:id` returns the **ordered event stream** and the **accumulated topology** of that cycle; **no `azure_client_secret`** appears anywhere in it.
- `POST /journal/export` produces a portable record that attaches to the cycle's report as a **provenance appendix** (the audit trail the regulated client needs).
- Nothing was captured because a prompt asked — every event exists because it flowed through the middleware.
- Acceptance test: issue `/sentinel/seed` + `/graph/neighbors` + `/kql` (with a fake secret in the body), then assert the journal has 3 events in order with the right `kind`s, a non-zero topology delta on the seed, a `touched` subgraph on the neighbors call, and zero occurrences of the secret string.

## 5b. Part B — token-lean responses + measured budget

The journal (Part A) retains full detail server-side. That is precisely what lets tool responses to the LLM be terse without losing anything.

### Summary-first responses
Replace the blunt truncation (`safeJsonContent` cutting to a byte budget) with a **semantic summarizer**, keyed on the tool/endpoint (the same interpretation the journal already does), that renders a large result as:
- a **compact summary** — the shape and the answer: counts, top-N rows/nodes, distribution, and for graph traversals the small subgraph; and
- a **`detail_ref`** — the journal event id, so the full detail is *addressable* on demand rather than pushed into context.

Fetching detail: the default summary is designed to answer the likely question, so the LLM rarely needs the dump. When it does, it either narrows the query (natural pivot) or calls a `journal_get(detail_ref)` that returns the retained summary/params (and, for the query kind, the params to re-run). L1 does **not** cache full response bodies for replay — narrowing/re-running is the detail path; a content-addressed blob cache is a future refinement.

The summarizer degrades safely: an endpoint with no summarizer arm returns its existing payload (subject to the old truncation as a backstop), so nothing regresses; endpoints are made summary-first incrementally.

### Measured token budget (the verifiable "sí o sí")
- The engine **estimates the token size** of each response (cheap heuristic — bytes/≈4, or a small tokenizer) and records it on the `HuntEvent` as `result.est_tokens`.
- The journal's `meta` accumulates **cumulative response tokens per hunt**, exposed via `GET /journal/:id` and a `journal_stats` MCP tool.
- This makes the guarantee measurable: for a representative cycle, the summed response tokens through the graph/summary tools must be **lower than the raw-KQL equivalent**. The acceptance test (below) runs both and asserts the tool path is cheaper.
- Optional soft cap: when a single response's `est_tokens` exceeds a threshold, the summarizer is forced on (and the event notes it), so a stray verbose response can't silently blow the budget.

### Acceptance (Part B)
- Run a small hunt via the graph/summary tools and the same hunt via raw `/kql`; assert `journal_stats(tool_run).cumulative_est_tokens < raw_run` — the tool path is measurably cheaper.
- Assert a large query's tool response is a summary (bounded `est_tokens`) carrying a `detail_ref`, and that `journal_get(detail_ref)` resolves.

## 6. Files touched (anticipated)

- **New module** `apps/tauri/src-tauri/src/journal/` — `event.rs` (schema), `store.rs` (append-only per-hunt store + current-hunt state), `interpret.rs` (path→kind/topology), `redact.rs` (secret redaction). Pure/testable.
- **Modify** `apps/tauri/src-tauri/src/http/mod.rs` — replace `log_requests` with the `capture` middleware; register `/journal/*` routes; thread the journal store into `AppState`/`HttpState`.
- **New** `apps/tauri/src-tauri/src/http/journal.rs` — the `/journal/*` handlers.
- **New MCP tools** `platform/mcp/src/tools/journal/` (`journal_list/get/export/start`, `journal_stats`) + registry wiring.
- **Part B — summarizer + token accounting:**
  - `apps/tauri/src-tauri/src/journal/summarize.rs` — the per-endpoint semantic summarizer (compact summary + `detail_ref`), reusing the interpreter's endpoint knowledge; and a token estimator recorded as `result.est_tokens`.
  - **Modify** the MCP response rendering (`platform/mcp/src/**` where `safeJsonContent` lives) — prefer the API-provided summary when present, fall back to the old truncation only as a backstop.
- Tests: `redact` (secrets stripped), `interpret` (path→kind/topology), `store` (append/read round-trip, current-hunt attribution), `summarize` (large result → bounded summary + `detail_ref`), `est_tokens` accounting, and integration tests for §5 and §5b acceptance (incl. tool-path-cheaper-than-raw).

## 7. Non-goals

- **L1 does not replay or reconstruct** — capture + view/export only. Reconstruction (L2) and deterministic replay (L3) are future layers.
- **No bulky response bodies stored** — summaries + fingerprint deltas only; `body_bytes` records size, not content.
- **Not a general APM/tracing system** — scoped to hunting actions on this API.
- **Secrets are never persisted** — no debug flag turns this off.
- **Not changing the cycle prompts** — the journal is engine-enforced and prompt-independent (that is the point). (The separate graph-native methodology work may add `journal_start` at cycle boundaries, but capture does not depend on it.)
- **Part B does not cache full response bodies for replay** in L1 — summary + `detail_ref` + narrow/re-run is the detail path; a content-addressed blob cache is future.
- **`est_tokens` is an estimate, not a billing-exact count** — a cheap heuristic sufficient to compare tool-path vs raw-path and to gate the soft cap; not a substitute for provider token metering.

## 8. Backward compatibility & performance

- Purely additive: new middleware behavior + new endpoints/module; existing endpoints unchanged in contract.
- Mandatory core is cheap: no big-body parsing; two count-reads of graph state per request (skippable for read-only endpoints via the allowlist) + one small append. The interpreter parses only small graph-traversal responses.
- Append-only JSONL is crash-robust; a partial last line on crash is tolerated on read.

## 9. Open questions (resolve in the plan)

- Exact graph-fingerprint source (reuse `/graph/summary`'s totals vs a direct cheap count) and whether to skip fingerprinting on GET/read-only endpoints.
- Retention/rotation of old journals (size cap? age cap?) — pick a sane default in the plan.
- Whether `journal_start` should auto-fire on `/sentinel/seed` when no hunt is open (convenience) vs always lazy-anonymous until named.
- Middleware layer ordering: the `capture` layer must sit so it sees the *authenticated*, path-resolved request (i.e. inside auth, outside the handlers). Axum applies `.layer(...)` outermost-last — settle the exact order in the plan so unauthorized requests are not journaled as hunt events.
