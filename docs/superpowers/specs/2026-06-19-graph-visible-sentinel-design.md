# Graph-Visible Sentinel — Design Spec

**Date:** 2026-06-19
**Status:** Draft for review
**Scope:** MCP server enhancement + 2 new backend endpoints
**Estimated effort:** 5–7 days (single implementation plan)

---

## Problem

When Claude drives GraphHunter against Azure Sentinel, it frequently defaults to generating raw KQL via `sentinel_query` instead of exercising the graph-side tooling (`sentinel_seed`, `node_expand`, `hunt_run`, `heavy_edges`, `channel_behavior`). Two failure modes dominate:

1. **Session start** — given an IoC, Claude writes ad-hoc KQL instead of invoking `sentinel_seed` to begin populating the graph.
2. **Mid-investigation** — nodes already exist in the graph, but Claude generates a fresh KQL instead of `node_expand` over them.

The shared root cause: Claude does not *see* graph state at the moment of tool selection. With no visible graph context, the most familiar primitive (general-purpose KQL) outranks the codebase-specific graph primitives. The result is that GraphHunter acts as a thin, expensive proxy in front of the Sentinel KQL endpoint instead of as the correlated multi-source graph it is designed to be.

## Goals

- Make graph state continuously visible to Claude through MCP `resources`.
- Append a short, bounded `graph-context` footer to every tool response so graph awareness persists across turns.
- When `sentinel_query` is called with `ingest=false`, compute overlap between the result rows and the graph and surface a non-blocking nudge.
- Keep the existing tool surface, schemas, and the validated `ingest=false` default unchanged.
- Make the feature plug-and-play: default-on with a visible UI badge, no manual env configuration.

## Non-goals

- A macro `hunt()` tool that hides primitive selection from Claude (explicitly rejected; conflicts with the transparency stance in `sentinel_query`'s description).
- Persisting `recent_pivots` across backend restarts (in-memory ring buffer is acceptable for v1).
- Multi-session or multi-workspace isolation of resources (global v1).
- Replacing or rewriting Sentinel analytic rules.

## Architecture

```
Claude
  │ MCP protocol
  ├── list_resources / read_resource
  └── call_tool
        │
        ▼
platform/mcp (TypeScript, @modelcontextprotocol/sdk)
  ┌───────────────────────────────────────────────┐
  │ Existing tools (sentinel_query, sentinel_seed,│
  │ node_expand, hunt_run, …)                     │
  │                                               │
  │ NEW Resources                                 │
  │   graph://summary                             │
  │   graph://active-hunts                        │
  │   graph://recent-pivots                       │
  │                                               │
  │ NEW ContextEnricher (wraps registerTools)     │
  │   - footer on every tool response             │
  │   - overlap nudge on sentinel_query           │
  └────────────────────┬──────────────────────────┘
                       │ HTTP
                       ▼
platform/api (Rust)
  NEW endpoints in operations/graph_meta.rs:
    GET  /graph/summary
    POST /graph/overlap
```

## Component 1 — MCP Resources

Three read-only resources exposed via `server.resource(...)`. The MCP SDK already supports this; no new infrastructure required. Resources are lazy: computed on read with a 30s server-side cache on `summary` (the others are cheap enough to compute fresh).

### `graph://summary`

Always-read orientation resource. Resource description tells Claude: *"Read this at the start of any hunting conversation. If `graph_empty` is true, prefer `sentinel_seed` before `sentinel_query`."*

```json
{
  "schema_version": 1,
  "as_of": "2026-06-19T14:23:00Z",
  "totals": {
    "nodes": 2412588,
    "edges": 18402117,
    "by_type": {"IP": 412000, "User": 8200, "Domain": 38000, "Host": 6100}
  },
  "sources": [
    {"name": "Sentinel",  "last_ingest": "2026-06-19T14:00:00Z", "rows_lifetime": 18000000},
    {"name": "FortiGate", "last_ingest": "2026-06-19T11:00:00Z", "rows_lifetime": 220000000}
  ],
  "active_datasets": ["ator-evtx-snapshot"],
  "graph_empty": false
}
```

`graph_empty: true` is the explicit signal for the cold-start case.

### `graph://active-hunts`

Surfaces currently cached hunts from the backend `hunt_cache_handle`. A hunt in GraphHunter is execution-scoped (a parameterized DFS with a cached result), not a long-lived investigation entity, so this resource enumerates cached hunts only — no new persistence layer.

```json
{
  "schema_version": 1,
  "as_of": "...",
  "hunts": [
    {
      "cache_key": "hunt-7f2a…",
      "params_summary": "seed=lasoto@telecarga.cl depth=3 mode=ByPath",
      "result_size": 1840,
      "computed_at": "2026-06-19T13:50:00Z",
      "ttl_seconds_remaining": 2400
    }
  ]
}
```

### `graph://recent-pivots`

Top 20 most recent seed/expand events, oldest-first dropped. Surfaces the `expanded` flag directly: `expanded: false` means the pivot is unexplored, an open invitation for `node_expand`.

```json
{
  "schema_version": 1,
  "as_of": "...",
  "pivots": [
    {"entity": "203.0.113.42", "type": "IP", "added_at": "...", "expanded": false, "degree": 0},
    {"entity": "lasoto@telecarga.cl", "type": "User", "added_at": "...", "expanded": true, "degree": 47}
  ]
}
```

## Component 2 — ContextEnricher

Lives in `platform/mcp/src/lib/context-enricher.ts`. Wraps the existing tool handler in `registerTools` ([platform/mcp/src/server.ts:53](platform/mcp/src/server.ts#L53)). Every tool response receives an additional text content block separate from the tool's own output, so MCP clients that don't care about it can ignore it cleanly.

### Footer (always present, ~120 tokens)

```
---graph-context---
graph: 2.4M nodes / 18M edges  |  sources: Sentinel(30m), FortiGate(3h), Zoho(1d)
active hunt: cache-7f2a (seed=lasoto…) | recent pivot: 203.0.113.42 (unexpanded)
```

Two lines: totals + source freshness, then hunts/pivots. The second line collapses when neither is present.

### Nudge rules (conditional, ~50–200 tokens)

| Tool | Condition | Nudge |
|------|-----------|-------|
| `sentinel_query` ingest=false | overlap > 0 | "N entities of this result are already in the graph. Top: `<entity>` (degree D, connected to `<top_neighbor>`). Consider `node_expand` before another KQL." |
| `sentinel_query` ingest=false | overlap = 0 | "None of this KQL's entities are in the graph. To explore these rows, re-run with `ingest=true`." |
| `sentinel_seed` | always | "Node `X` added. Next: `node_expand` for neighbors, or `hunt_run` if the `<scenario>` playbook fits." |
| `node_expand` | neighbors > 0 | "Found N neighbors. Top by degree: […]. For channel anomalies: `channel_behavior` on this node." |
| all other tools | n/a | (base footer only) |

### Entity extraction (for `sentinel_query` overlap)

Over the first N rows (default 100, cap 500):

- **IP**: `\b\d{1,3}(\.\d{1,3}){3}\b`, optional filter of private/reserved ranges.
- **Email/User**: simplified RFC 5322 email regex.
- **Domain**: FQDN regex with TLD ≥ 2 characters.
- **Hostname**: only from columns named `Computer`, `Hostname`, `DeviceName` (field-name heuristic).

Deduplicated, capped at 500 entities, sent to `POST /graph/overlap`.

### Failure mode

Best-effort. Both `/graph/summary` (cached) and `/graph/overlap` requests are issued in parallel with the main tool call, each with an 800ms timeout. On timeout or 5xx, the footer becomes `---graph-context---\n(unavailable)` and the tool response goes out unchanged. The enricher never breaks a tool call.

### Kill switch

- `GH_MCP_ENRICH=off` → enricher becomes identity (returns original response unchanged).
- Optional per-request opt-out via `_meta.enrich: false` for benchmark cleanliness.

## Component 3 — Backend endpoints

New module: `platform/api/src/operations/graph_meta.rs`. Registered in the existing axum router.

### `GET /graph/summary`

Response schema as in the `graph://summary` resource above plus `schema_version: 1`. Computed lazily, 30s in-memory TTL cache. Numbers are eventually-consistent — a read during heavy ingest reflects a mid-state, which is acceptable since the footer is orientation, not authoritative.

### `POST /graph/overlap`

**Request:**
```json
{
  "schema_version": 1,
  "entities": [
    {"type": "IP",   "value": "203.0.113.42"},
    {"type": "User", "value": "lasoto@telecarga.cl"}
  ]
}
```
413 if `entities.len() > 500`.

**Response:**
```json
{
  "schema_version": 1,
  "found": [
    {"entity": "203.0.113.42", "type": "IP", "degree": 47,
     "top_neighbor": {"entity": "lasoto@telecarga.cl", "type": "User", "edge_count": 12}}
  ],
  "missing": ["8.8.8.8"]
}
```

Hash lookup typed by entity kind, microseconds per lookup. `top_neighbor` requires one adjacency-list pass per found entity; precomputed out-degree (already maintained for analytics) keeps this O(neighbors_of_top_one) per entity.

### Data sources

| Field | Source | Notes |
|-------|--------|-------|
| `totals.nodes`, `totals.edges` | Incremental counters in `core/graph-engine` ingest path | Hook to add if absent in v1 (~1 day) |
| `totals.by_type` | Per-type incremental counters | Same hook |
| `sources` + `last_ingest` | `operations/dataset.rs` + format registry | Existing |
| `active_datasets` | `operations/dataset.rs` | Existing |
| `active_hunts` | `hunt_cache_handle` | Existing |
| `recent_pivots` | New ring buffer (size 20) in `operations/graph_meta.rs`, pushed on successful `sentinel_seed` and `node_expand` | In-memory, dies on restart (acceptable v1) |

## Schema versioning

All four new payloads (`/graph/summary`, `/graph/overlap` request and response, each resource) carry `schema_version: 1` and follow the same discipline as `BODY_FORMAT_VERSION` / `check_body_compatible` introduced in the in-flight session body versioning work. Drift fails loudly on the MCP client side. Bumping `schema_version` is a coordinated change across the Rust DTO, the zod schema in TS, and a golden test on both sides.

## Data flow — `sentinel_query` with overlap

```
Claude → call_tool sentinel_query(kql, ingest=false)
   │
   ▼
MCP server (registerTools handler)
   ├── tool.execute(ctx, parsed)         → backend POST /kql           ┐
   ├── enricher: read graph://summary    → backend GET  /graph/summary │ in
   └── enricher: extract entities → ...  → backend POST /graph/overlap ┘ parallel
   ▼
ContextEnricher composes:
   content: [
     { type: "text", text: "<rows>" },
     { type: "text", text: "---graph-context---\n<footer>\n<nudge>" }
   ]
   ▼
Claude
```

The two enrichment calls overlap (literally and figuratively) with the main `/kql` call, so the user-visible latency overhead is bounded by `max(kql_latency, 800ms)` rather than additive.

## Testing strategy

**Unit (each side independently):**

- Backend: golden shape + `schema_version` tests for `/graph/summary` and `/graph/overlap`. Incremental counter test: ingest N rows of Sentinel, read summary, assert `totals.nodes` delta equals N (modulo node merging).
- MCP: extractor fixtures (private/public IPs, malformed emails, FQDN edge cases, field-name heuristic). ContextEnricher with mocked backend covering overlap = 0, overlap > 0, 503, timeout.

**Integration (cross-layer):**

- E2E: stand up backend + MCP server, exercise `sentinel_query` against a mock workspace, assert the footer appears and the nudge composes correctly when overlap is present, and that a downed backend yields `(unavailable)` without breaking the tool call.
- Resources: `list_resources` enumerates the three; `read_resource` validates against both the Rust DTO and the TS zod schema.

**Performance — strict bisection via env vars** ([feedback_bench_methodology](C:/Users/lsotomayor/.claude/projects/c--Users-lsotomayor-GraphHunter/memory/feedback_bench_methodology.md)):

- Baseline: a recorded hunting session replayed with `GH_MCP_ENRICH=off`.
- Treatment: same session with `GH_MCP_ENRICH=on`.
- Compare p50/p95 latency per tool call, total token usage, end-to-end wall clock.
- Merge gate: p95 overhead per tool call < 300 ms, total tokens delta < 15%.

## Rollout

1. **Dogfood (Lucas + Diego), 1 week.** Default-on in local builds. Telemetry captured (see Metrics).
2. **Beta opt-in, 2 weeks.** Tauri config flag. Analysts can enable.
3. **Default on with UI badge** per [feedback_perf_plug_and_play](C:/Users/lsotomayor/.claude/projects/c--Users-lsotomayor-GraphHunter/memory/feedback_perf_plug_and_play.md): on at startup, badge in app shows `graph-context: on`. No manual env configuration.

## Metrics of success

Instrumented in the MCP server, per session, exported as Prometheus counters/histograms.

| Metric | Measures | Target post-rollout |
|--------|----------|---------------------|
| `tool_call_ratio{tool}` | tool calls per session, normalized | `sentinel_query` < 30% of total |
| `pivot_followthrough_rate` | % of added pivots expanded within the same session | > 60% |
| `nudge_followed_total / nudge_displayed_total` | rate Claude acts on a nudge in the next call | > 40% |
| `cross_source_hits` | tool calls whose result touched ≥2 sources in the graph | > 25% of hunt calls |
| `graph_resource_reads` | reads of `graph://summary` per session | ≥ 1 (Claude is orienting itself) |

The defining metrics are `tool_call_ratio{sentinel_query}` (should drop) and `pivot_followthrough_rate` (should rise) versus the dogfood baseline. If neither moves, the A+C hypothesis is invalidated and brainstorming reopens.

## Risks and mitigations

| Risk | Severity | Mitigation |
|------|----------|------------|
| Token bloat in long sessions | Medium | Truncate footer when client context > 70% used (v1.1) |
| Entity extractor false positives (8.8.8.8, gmail.com) | Low | Nudge only sketches the top-degree entity; extras are counted, not enumerated. Denylist in v2 if it annoys users. |
| Counter drift during heavy ingest | Low | 30s TTL on summary; footer is orientation, not authoritative |
| `recent_pivots` lost on restart | Low | Accepted v1; persistence in v2 if long sessions demand it |
| Backend timeout in enricher path | Low | 800ms per-call cap, `(unavailable)` footer, tool call never blocked |
| Schema drift between Rust DTO and TS zod | Medium | `schema_version` + golden tests on both sides, mirroring `BODY_FORMAT_VERSION` discipline |

## Out of scope

- Persisting `recent_pivots` to disk.
- Per-session or per-workspace resource scoping.
- A `graph://playbook-status` resource.
- A `graph://schema` resource enumerating node/edge types.
- UI changes inside the Tauri app beyond the `graph-context: on` badge.
- Rewriting `sentinel_query`'s `ingest=false` default (validated invariant, [feedback_sentinel_ingest_idempotency](C:/Users/lsotomayor/.claude/projects/c--Users-lsotomayor-GraphHunter/memory/feedback_sentinel_ingest_idempotency.md)).

## File layout

**New files:**

- `platform/mcp/src/lib/context-enricher.ts` — middleware, footer composer, entity extractor.
- `platform/mcp/src/lib/graph-state-client.ts` — typed client for `/graph/summary` and `/graph/overlap`.
- `platform/mcp/src/resources/index.ts` — registry of the three resources.
- `platform/mcp/src/resources/graph-summary.ts`, `graph-active-hunts.ts`, `graph-recent-pivots.ts`.
- `platform/api/src/operations/graph_meta.rs` — endpoints, ring buffer, counters wiring.
- `platform/api/src/dto/v1/graph_meta.rs` — request/response DTOs with `schema_version`.

**Edited files:**

- `platform/mcp/src/server.ts` — wrap the handler in `registerTools` (single point at line 53).
- `platform/mcp/src/index.ts` — register resources alongside tools.
- `platform/api/src/operations/mod.rs` — declare `graph_meta`.
- `core/graph-engine/src/ingest/*.rs` (or equivalent) — add counter hooks on node/edge insertion if not present.
- `platform/api/src/operations/sentinel.rs` and `entity.rs` — push to `recent_pivots` on successful seed/expand.

## Open questions resolved during design

1. **Does Hunt persist?** No — hunt is execution-scoped with a result cache (`hunt_cache_handle`). `active-hunts` exposes the cache, no new persistence layer required.
2. **Are incremental counters in place?** Not certain across all paths; we add the hooks where needed during implementation (~1 day allowance built into the estimate).
3. **Resource scoping:** global v1. Multi-session isolation deferred.

## Remaining open questions

None blocking. To be confirmed at implementation start:

- Exact location of the counter hooks in `core/graph-engine/src/ingest/` (file path will be picked once the plan is being executed).
- Whether the existing axum router setup uses path prefixes (`/api/v1/graph/...`) — match what's already there.
