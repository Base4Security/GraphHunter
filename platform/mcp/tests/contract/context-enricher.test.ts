import test from "node:test";
import assert from "node:assert/strict";
import { ContextEnricher } from "../../src/lib/context-enricher.js";
import { GraphStateClient } from "../../src/lib/graph-state-client.js";

function makeFetch(mode: "ok" | "down") {
  return async (url: string): Promise<Response> => {
    if (mode === "down") throw new Error("backend down");
    if (url.endsWith("/graph/summary")) {
      return new Response(
        JSON.stringify({
          schema_version: 1,
          as_of: new Date().toISOString(),
          totals: { nodes: 100, edges: 200, by_type: {} },
          sources: [
            {
              name: "Sentinel",
              last_ingest: new Date().toISOString(),
              rows_lifetime: 1000,
            },
          ],
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

test("enrich appends a graph-context footer to a sentinel_query response", async () => {
  const client = new GraphStateClient("http://x", {
    fetchImpl: makeFetch("ok") as unknown as typeof fetch,
  });
  const enricher = new ContextEnricher(client);
  const out = await enricher.enrich(
    "sentinel_query",
    { ingest: false },
    [{ type: "text" as const, text: JSON.stringify([{ src: "203.0.113.42" }]) }],
  );
  assert.equal(out.content.length, 2);
  assert.match(out.content[1].text, /graph-context/);
});

test("GH_MCP_ENRICH=off returns original content untouched", async () => {
  process.env.GH_MCP_ENRICH = "off";
  try {
    const enricher = new ContextEnricher(new GraphStateClient("http://x"));
    const orig = [{ type: "text" as const, text: "x" }];
    const out = await enricher.enrich(
      "sentinel_query",
      { ingest: false },
      orig,
    );
    assert.deepEqual(out.content, orig);
    assert.equal(out.nudged, false);
  } finally {
    delete process.env.GH_MCP_ENRICH;
  }
});

test("backend down: footer says (unavailable), tool output preserved", async () => {
  const client = new GraphStateClient("http://x", {
    fetchImpl: makeFetch("down") as unknown as typeof fetch,
  });
  const enricher = new ContextEnricher(client);
  const orig = [{ type: "text" as const, text: "rows" }];
  const out = await enricher.enrich("sentinel_query", { ingest: false }, orig);
  assert.equal(out.content[0].text, "rows");
  assert.match(out.content[1].text, /\(unavailable\)/);
});

test("node_expand: enricher extracts neighbors count from Neighborhood result", async () => {
  const client = new GraphStateClient("http://x", {
    fetchImpl: makeFetch("ok") as unknown as typeof fetch,
  });
  const enricher = new ContextEnricher(client);
  const neighborhood = {
    center: { id: "x" },
    nodes: Array.from({ length: 47 }, (_, i) => ({ id: `n${i}` })),
    edges: [],
  };
  const out = await enricher.enrich(
    "node_expand",
    { node_id: "x" },
    [{ type: "text" as const, text: JSON.stringify(neighborhood) }],
  );
  // Footer present, AND nudge mentions channel_behavior because count > 0.
  assert.match(out.content[1].text, /Found 47 neighbors/);
  assert.match(out.content[1].text, /channel_behavior/);
  assert.equal(out.nudged, true);
});
