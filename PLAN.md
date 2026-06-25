# PLAN — GraphHunter graph-cycle capability half (Microsoft Sentinel focus)

## Current architecture
- **Centralized Log Analytics client**: `run_sentinel_query` (sync) + `HttpSentinelTransport` /
  `SentinelTransport` trait — `platform/siem/src/sentinel.rs`, `platform/siem/src/sentinel_streaming.rs`.
  `normalize_response` flattens the Log Analytics `tables/columns/rows` into a JSON array of row
  objects. **No query cost/statistics captured.** Auth + `AZURE_WORKSPACE_ID` resolved by `env_or`
  (`platform/api/src/operations/sentinel.rs`), which already returns a clear "Missing AZURE_WORKSPACE_ID"
  error rather than a stack trace.
- **Ingest** (`run_kql`, `platform/api/src/operations/sentinel.rs`): parse → `insert_triples` →
  dataset register → scoring; `dataset` snapshot-replace via
  `remove_entities_and_relations_by_dataset`. Helper `run_kql_rows` runs a KQL string → `Vec<Value>`.
- **Sentinel triple parser** (`core/graph-engine/src/sentinel.rs`) is **hardcoded per table**
  (SecurityEvent/SigninLogs/Device*/CommonSecurityLog). No AWSCloudTrail, no `parse_json` of
  `RequestParameters`/`AdditionalEventData`.
- **Traversal**: `get_neighborhood`/`expand_node` exist. **No path-between-two-nodes** primitive.
- **Centrality**: `degree_score`/`betweenness`/`pagerank_score`/`rarity_score` on `Entity`;
  `explain_score` gives percentiles. **No z-scores, no isolation metric.**
- **MCP**: namespaced tools under `platform/mcp/src/tools/<ns>/`, spread in `registry.ts`;
  HTTP handlers in `apps/tauri/src-tauri/src/http/`, routes in `mod.rs`.
- **Already shipped (commit 9eb540e)**: `graph_state`/`advisory` on `graph_summary`+`/health`,
  `graph_advisory` on `sentinel_query`, and a `sentinel_schema` discovery tool.

## The gap
Discovery/advisory nudges exist, but there is no way to **build** or **traverse** a graph from a
proposed schema, no query-cost visibility, no enforcement steering raw KQL into the graph path, and
the parser can't materialize arbitrary (cloud) schemas.

## Decisions
- Doc tool names. Rename `sentinel_schema` → `schema_discover` (deprecated alias kept).
- `class` = engine `EntityType` names (User/IP/Host/Process/File/Domain, `Other(_)`); no
  Identity/Role/Account translation layer.
- `threat_intel`: honest stub (geoip+asn real at build; capability false until a feed is configured).
- No new dependencies; no graph-store / SessionFile / binary-format schema change.

## Implementation order (one tool per commit, each with tests)
0. **Foundation** — query cost capture (`Prefer: include-statistics` → `QueryStats`); ephemeral
   `Session.proposals` + `Session.last_build`; route new-tool queries through `SentinelTransport`
   for mock-based unit tests.
1. **schema_discover** (§4.1) — rename+align to the doc output; surface cost.
2. **graph_propose** (§4.2) — candidate schemas + materialization KQL (`parse_json` +
   `columnifexists` guards); persist proposals.
3. **graph_build** (§4.3) — schema-driven row→triple mapper; enrich once (geoip/asn); merge_mode
   append|replace; record `last_build`; surface cost.
4. **graph_neighbors** (§4.5) — format `get_neighborhood` to the doc shape.
5. **graph_path** (§4.4) — new bounded BFS/DFS between entities.
6. **graph_anomaly** (§4.6) — z-scores over degree/betweenness + new isolation metric.
7. **sentinel_query** (§4.7) — `acknowledge_fallback` gate + ready `graph_propose` payload + logging.
8. **§5 status** — `last_build` on `graph_summary` + `/health`.
9. **e2e + docs** — env-gated scripted cycle; README/CHANGELOG.

## Testing
- Unit (mock SIEM via existing `MockTransport`) for query-executing ops; pure-logic unit tests for
  the schema mapper, KQL generation, BFS, z-score/isolation, fallback-gate decision.
- Integration gated behind `GRAPHHUNTER_LIVE_SENTINEL_TEST=1` + `AZURE_*`, hitting a test workspace.
- `cargo test -p graph-hunter-api -p graph-hunter-core -p graph-hunter-siem`; `npm run build` +
  `npm run test:contract` in `platform/mcp`.

## Definition of done
All six tools registered/enumerable (with `sentinel_schema` alias); e2e completes
schema_discover→propose→build→neighbors/path against a live/test workspace with cost +
`enrichment_applied` reported and `graph_state` flipping empty→populated; fallback gate blocks
un-acknowledged entity-class raw KQL and logs use; existing tools/schemas unchanged; tests pass.
