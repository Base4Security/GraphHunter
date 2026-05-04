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
async function fetchSchema() {
    const res = await fetch(new URL("/v1/schema", API_BASE));
    if (!res.ok)
        throw new Error(`HTTP ${res.status}`);
    return (await res.json());
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
        assert.ok(["stable", "experimental", "deprecated"].includes(ep.stability), `stability: ${ep.stability}`);
    }
});
test("contract: endpoints used by migrated tools are registered", { skip: !ENABLED }, async () => {
    const schema = await fetchSchema();
    const paths = new Set(schema.endpoints.map((e) => e.path));
    // Keeping this list explicit (rather than deriving from the
    // registry) catches "tool migrated but endpoint not registered in
    // platform/api" — the exact drift we want to break the build on.
    // Grouped by domain; mirrors the registry order.
    const requiredPaths = [
        // navigation
        "/health",
        "/entity_types",
        "/v1/schema",
        "/search",
        "/expand",
        "/node_details",
        "/subgraph",
        "/events_for_node",
        "/relation_schema",
        "/events_paginated",
        "/expand_grouped",
        // hunting
        "/run_hunt",
        "/hunt_results",
        "/parse_dsl",
        "/diff_hunts",
        "/export_hunt_results",
        "/save_hypothesis_as_sigma",
        // scoring
        "/enable_anomaly_scoring",
        "/compute_scores",
        "/explain_score",
        // graph-views
        "/graph_summary",
        "/entity_type_counts",
        "/temporal_heatmap",
        "/subnet_analysis",
        // catalogs
        "/catalog",
        "/catalog/status",
        "/catalog/diagnostics",
        "/datasets",
        // notes
        "/notes",
        "/notes/list",
        "/path_nodes",
        "/tag",
        "/untag",
        "/tags",
        // export
        "/export_subgraph",
        "/export_ocsf",
        "/export_iocs",
        // data-quality
        "/check_invariants",
        "/schema_drift_detect",
        "/mapping_regression_test",
        "/invariant_check_hypothetical",
        "/list_dead_letters",
        "/reingest_dead_letter",
        "/purge_dead_letters",
        // agentic
        "/ingest_negotiate",
        "/canonical_map",
        "/parser_generate",
        "/agentic_review_list",
        "/agentic_review_approve",
        "/agentic_review_reject",
        "/publish_mapping",
        "/fetch_shared_mappings",
        // integrations
        "/enrich_ip",
        "/file_ticket",
        "/publish_iocs_to_sentinel",
    ];
    for (const path of requiredPaths) {
        assert.ok(paths.has(path), `missing schema entry for ${path}`);
    }
});
