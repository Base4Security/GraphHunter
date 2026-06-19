import test from "node:test";
import assert from "node:assert/strict";
import { ContextEnricher } from "../../src/lib/context-enricher.js";
import { GraphStateClient } from "../../src/lib/graph-state-client.js";

// ── Bisection scenario ────────────────────────────────────────────────────
// Replays a short hunting trajectory through the ContextEnricher and
// measures the overhead added by the enrichment path.
//
// To keep this test fully hermetic we don't drive the actual MCP server;
// we exercise the enricher directly with a stub backend. That isolates
// the cost we care about (zod parse, regex extraction, JSON.stringify
// for the footer) from the cost of HTTP/IPC.
//
// Gate (enforced when PERF_BISECT=1 is set):
//   - p95 overhead per call < 300 ms
//   - total wall delta < 15 %
//
// Without PERF_BISECT=1 this test is skipped so the normal suite stays
// fast.

const SHOULD_RUN = process.env.PERF_BISECT === "1";

const SCENARIO_ROWS = Array.from({ length: 200 }, (_, i) => ({
  Computer: `host-${i % 10}`,
  src: `10.0.${Math.floor(i / 256)}.${i % 256}`,
  user: `u${i}@telecarga.cl`,
}));

const SCENARIO = [
  {
    tool: "sentinel_seed",
    args: { value: "10.0.0.1", entity_type: "IP" },
    rows: SCENARIO_ROWS.slice(0, 1),
  },
  {
    tool: "node_expand",
    args: { node_id: "10.0.0.1", neighbors_found: 47 },
    rows: SCENARIO_ROWS.slice(0, 47),
  },
  {
    tool: "sentinel_query",
    args: { query: "SecurityAlert | take 200", ingest: false },
    rows: SCENARIO_ROWS,
  },
  {
    tool: "hunt_run",
    args: { seed: "10.0.0.1", depth: 3 },
    rows: SCENARIO_ROWS.slice(0, 100),
  },
];

function makeFetch() {
  return async (url: string): Promise<Response> => {
    if (url.endsWith("/graph/summary")) {
      return new Response(
        JSON.stringify({
          schema_version: 1,
          as_of: new Date().toISOString(),
          totals: { nodes: 200, edges: 1000, by_type: {} },
          sources: [{ name: "Sentinel", last_ingest: new Date().toISOString(), rows_lifetime: 200 }],
          active_datasets: [],
          active_hunts: [],
          recent_pivots: [],
          graph_empty: false,
        }),
        { headers: { "content-type": "application/json" } },
      );
    }
    return new Response(
      JSON.stringify({ schema_version: 1, found: [], missing: [] }),
      { headers: { "content-type": "application/json" } },
    );
  };
}

async function runScenario(enrich: boolean) {
  const client = new GraphStateClient("http://x", {
    fetchImpl: makeFetch() as unknown as typeof fetch,
  });
  const enricher = new ContextEnricher(client);
  const durations: number[] = [];
  let totalTokens = 0;

  for (const step of SCENARIO) {
    const rawText = JSON.stringify(step.rows);
    const content = [{ type: "text" as const, text: rawText }];
    const t0 = performance.now();
    if (enrich) {
      const out = await enricher.enrich(step.tool, step.args, content);
      totalTokens += out.content.reduce((sum, c) => sum + c.text.length, 0);
    } else {
      totalTokens += rawText.length;
    }
    durations.push(performance.now() - t0);
  }

  durations.sort((a, b) => a - b);
  const p50 = durations[Math.floor(durations.length * 0.5)];
  const p95 = durations[Math.floor(durations.length * 0.95)];
  return { p50, p95, totalTokens };
}

test("bisection: enrich on vs off (gate 300ms p95 / 15% tokens)", { skip: !SHOULD_RUN }, async () => {
  const off = await runScenario(false);
  const on = await runScenario(true);
  const overhead = on.p95 - off.p95;
  const tokenDelta = (on.totalTokens - off.totalTokens) / Math.max(off.totalTokens, 1);

  console.log("bisect off:", off, "on:", on, "overhead_p95_ms:", overhead, "token_delta:", tokenDelta);
  assert.ok(
    overhead < 300,
    `enrich p95 overhead ${overhead.toFixed(1)}ms exceeds 300ms gate`,
  );
  assert.ok(
    tokenDelta < 0.15,
    `enrich token delta ${(tokenDelta * 100).toFixed(1)}% exceeds 15% gate`,
  );
});
