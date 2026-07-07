#!/usr/bin/env node
// End-to-end smoke test for the four-phase graph cycle (design doc §3):
//   schema_discover → graph_propose → graph_build → graph_neighbors / graph_path / graph_anomaly
//
// Drives the GraphHunter HTTP API directly (the same endpoints the MCP tools
// call). Env-gated so it never runs by accident:
//
//   GRAPHHUNTER_E2E=1                 required, opt-in
//   GRAPHHUNTER_API_URL=...           default http://127.0.0.1:37891
//   GRAPHHUNTER_API_TOKEN=...         bearer token printed by the app at startup
//   AZURE_WORKSPACE_ID / _TENANT_ID / _CLIENT_ID / _CLIENT_SECRET
//                                     a real (test) Sentinel workspace
//   GH_E2E_TABLE / GH_E2E_LOOKBACK    optional overrides for table + window
//
// The app must be running with a session (or graph_propose will auto-create
// one). Exits non-zero on the first failed phase.

const BASE = process.env.GRAPHHUNTER_API_URL ?? "http://127.0.0.1:37891";
const TOKEN = process.env.GRAPHHUNTER_API_TOKEN;
const LOOKBACK = process.env.GH_E2E_LOOKBACK ?? "24h";

if (process.env.GRAPHHUNTER_E2E !== "1") {
  console.log("skip: set GRAPHHUNTER_E2E=1 to run the graph-cycle e2e.");
  process.exit(0);
}

async function call(path, body) {
  const res = await fetch(new URL(path, BASE), {
    method: "POST",
    headers: {
      "content-type": "application/json",
      ...(TOKEN ? { authorization: `Bearer ${TOKEN}` } : {}),
    },
    body: JSON.stringify(body ?? {}),
  });
  const text = await res.text();
  let json;
  try {
    json = JSON.parse(text);
  } catch {
    json = text;
  }
  if (!res.ok) {
    throw new Error(`${path} → HTTP ${res.status}: ${text}`);
  }
  return json;
}

function step(n, label) {
  console.log(`\n=== Phase ${n}: ${label} ===`);
}

async function main() {
  // Phase 1 — discover.
  step(1, "schema_discover");
  const schema = await call("/sentinel/schema", { lookback: LOOKBACK, max_tables: 10 });
  const tables = schema.tables ?? [];
  console.log(`  discovered ${schema.total_tables ?? tables.length} table(s); cost`, schema.cost ?? "n/a");
  if (!tables.length) throw new Error("schema_discover returned no tables — check AZURE_* + workspace data");

  // Pick the table (env override, else first with ≥2 node fields).
  const wanted = process.env.GH_E2E_TABLE;
  const pickable = (t) => (t.fields ?? []).filter((f) => f.graph_affinity === "node").length >= 2;
  const table =
    (wanted && tables.find((t) => t.name === wanted)) ||
    tables.find(pickable) ||
    tables[0];
  const nodeFields = (table.fields ?? []).filter((f) => f.graph_affinity === "node");
  if (nodeFields.length < 2) {
    throw new Error(`table ${table.name} has <2 node fields; set GH_E2E_TABLE to a richer table`);
  }
  const selected_fields = nodeFields.slice(0, 3).map((f) => ({ table: table.name, field: f.name }));
  console.log(`  using ${table.name}:`, selected_fields.map((s) => s.field).join(", "));

  // Phase 2 — propose.
  step(2, "graph_propose");
  const proposed = await call("/graph/propose", { selected_fields, lookback: LOOKBACK });
  const proposal = (proposed.proposals ?? [])[0];
  if (!proposal) throw new Error("graph_propose returned no proposals");
  console.log(`  proposal_id=${proposal.proposal_id}; nodes=${proposal.nodes.length} edges=${proposal.edges.length}`);
  console.log(`  materialization_kql:\n    ${proposal.materialization_kql.replace(/\n/g, "\n    ")}`);

  // Phase 3 — build.
  step(3, "graph_build");
  const built = await call("/graph/build", { proposal_id: proposal.proposal_id, lookback: LOOKBACK, merge_mode: "replace" });
  console.log(`  build_id=${built.build_id} entities=${built.entities_created} relations=${built.relations_created}`);
  console.log(`  enrichment_applied`, built.enrichment_applied, `graph_state=${built.graph_state}`, `cost`, built.cost ?? "n/a");
  if (built.entities_created === 0) throw new Error("graph_build created 0 entities — nothing to analyze");

  // Find a built entity to anchor analysis on (first node-class field's value).
  step(4, "graph_neighbors / graph_path / graph_anomaly");
  const anomalies = await call("/graph/anomaly", { metric: "all", top_n: 5 });
  console.log(`  graph_anomaly → ${(anomalies.anomalies ?? []).length} hit(s)`);
  const anchor = (anomalies.anomalies ?? [])[0]?.entity;
  if (anchor) {
    const nbrs = await call("/graph/neighbors", { entity: anchor, degree: 1 });
    console.log(`  graph_neighbors(${anchor.class}:${anchor.value}) → ${(nbrs.neighbors ?? []).length} neighbor(s)`);
    const second = (nbrs.neighbors ?? [])[0]?.node;
    if (second) {
      const paths = await call("/graph/path", { from_entity: anchor, to_entity: second, max_depth: 4 });
      console.log(`  graph_path(${anchor.value} → ${second.value}) → ${(paths.paths ?? []).length} path(s)`);
    }
  } else {
    console.log("  (no anomalies to anchor neighbors/path on — graph may be tiny)");
  }

  console.log("\n✅ graph cycle e2e completed");
}

main().catch((e) => {
  console.error("\n❌ e2e failed:", e.message);
  process.exit(1);
});
