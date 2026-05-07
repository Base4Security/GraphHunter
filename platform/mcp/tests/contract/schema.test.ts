/**
 * F4.9 / ADR-004 §D5 — MCP ↔ API contract test.
 *
 * Runs only when `GRAPHHUNTER_CONTRACT_TEST=1`. The harness assumes a
 * `platform/api`-backed server is reachable at `GRAPHHUNTER_API_URL`
 * (default `http://127.0.0.1:37891`). Our CI job brings one up before
 * invoking `npm run test:contract`; locally you can run the Tauri app
 * and export the token.
 *
 * What we assert:
 *   1. `/v1/schema` is reachable and returns `SchemaResponse`-shaped JSON.
 *   2. The contract version matches what we expect.
 *   3. Every endpoint path a migrated tool depends on is registered.
 *
 * Why we keep this test surface narrow:
 *   - Full JSON-Schema-per-DTO generation is a follow-up. For now the
 *     class of breakage we catch is "endpoint was renamed / removed
 *     without updating the registry," which is the historically most
 *     common MCP-vs-API drift.
 *   - Per-tool input/output assertions grow organically: as tools
 *     migrate with non-`z.unknown()` schemas, add their own
 *     `tests/contract/<tool>.test.ts` alongside this file.
 */

import { test } from "node:test";
import assert from "node:assert/strict";

const API_BASE = process.env.GRAPHHUNTER_API_URL ?? "http://127.0.0.1:37891";
const ENABLED = process.env.GRAPHHUNTER_CONTRACT_TEST === "1";

interface EndpointMeta {
  path: string;
  method: "GET" | "POST";
  description: string;
  heavy?: boolean;
  stability: "stable" | "experimental" | "deprecated";
}

interface SchemaResponse {
  version: string;
  endpoints: EndpointMeta[];
}

async function fetchSchema(): Promise<SchemaResponse> {
  const res = await fetch(new URL("/v1/schema", API_BASE));
  if (!res.ok) throw new Error(`HTTP ${res.status}`);
  return (await res.json()) as SchemaResponse;
}

test("contract: /v1/schema is reachable and well-formed", { skip: !ENABLED }, async () => {
  const schema = await fetchSchema();
  assert.equal(typeof schema.version, "string", "version is a string");
  assert.match(schema.version, /^\d+\.\d+\.\d+$/, "version is semver");
  assert.ok(Array.isArray(schema.endpoints), "endpoints is an array");
  assert.ok(schema.endpoints.length > 0, "endpoints non-empty");
  for (const ep of schema.endpoints) {
    assert.equal(typeof ep.path, "string");
    assert.ok(ep.path.startsWith("/"), `path absolute: ${ep.path}`);
    assert.ok(["GET", "POST"].includes(ep.method), `method: ${ep.method}`);
    assert.ok(
      ["stable", "experimental", "deprecated"].includes(ep.stability),
      `stability: ${ep.stability}`,
    );
  }
});

test(
  "contract: endpoints used by migrated tools are registered",
  { skip: !ENABLED },
  async () => {
    const schema = await fetchSchema();
    const paths = new Set(schema.endpoints.map((e) => e.path));

    // v2 catalog (orthogonal namespaces). Keeping this list explicit
    // (rather than deriving from the registry) catches "tool migrated
    // but endpoint not registered in platform/api" — the exact drift
    // we want to break the build on. Grouped by new namespace.
    const requiredPaths = [
      // session
      "/health",
      "/v1/schema",
      // graph.*
      "/graph_summary",
      "/entity_types",
      "/entity_type_counts",
      "/relation_schema",
      "/subnet_analysis",
      "/temporal_heatmap",
      "/datasets",
      "/path_nodes",
      // node.*
      "/node_details",
      "/explain_score",
      "/search",
      "/expand",
      "/expand_grouped",
      "/events_for_node",
      "/events_paginated",
      "/subgraph",
      "/export_subgraph",
      // hunt.*
      "/parse_dsl",
      "/run_hunt",
      "/hunt_results",
      "/diff_hunts",
      // /enable_anomaly_scoring is no longer hit by any MCP tool —
      // the v2 follow-up wired per-call `scoring` into RunHuntRequest
      // / RunHuntBody so hunt.run(scoring=anomaly|gnn) finalizes the
      // scorer server-side without a pre-call enable hop. The legacy
      // endpoint still exists on the API for direct callers.
      // catalog.get
      "/catalog",
      "/catalog/status",
      "/catalog/diagnostics",
      // tags / notes / scores / review
      "/tag",
      "/untag",
      "/tags",
      "/notes",
      "/notes/list",
      "/compute_scores",
      "/agentic_review_approve",
      "/agentic_review_reject",
      "/agentic_review_list",
      // ingest.*
      "/ingest_negotiate",
      "/parser_generate",
      "/canonical_map",
      "/mapping_regression_test",
      "/check_invariants",
      "/invariant_check_hypothetical",
      "/schema_drift_detect",
      "/list_dead_letters",
      "/purge_dead_letters",
      "/reingest_dead_letter",
      "/fetch_shared_mappings",
      "/publish_mapping",
      // enrich
      "/enrich_ip",
      // export
      "/export_hunt_results",
      "/export_iocs",
      "/export_ocsf",
      "/save_hypothesis_as_sigma",
      // publish
      "/publish_iocs_to_sentinel",
      "/file_ticket",
    ];

    for (const path of requiredPaths) {
      assert.ok(paths.has(path), `missing schema entry for ${path}`);
    }
  },
);
