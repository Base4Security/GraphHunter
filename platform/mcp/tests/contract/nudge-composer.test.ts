import test from "node:test";
import assert from "node:assert/strict";
import { composeNudge } from "../../src/lib/nudge-composer.js";

test("sentinel_query with overlap > 0 suggests node_expand on top entity", () => {
  const n = composeNudge(
    "sentinel_query",
    { ingest: false },
    {
      schema_version: 1,
      found: [
        {
          entity: "203.0.113.42",
          type: "IP",
          degree: 47,
          top_neighbor: {
            entity: "lasoto@telecarga.cl",
            type: "User",
            edge_count: 12,
          },
        },
      ],
      missing: ["8.8.8.8"],
    },
  );
  assert.ok(n);
  assert.match(n, /1 entit/);
  assert.match(n, /203\.0\.113\.42/);
  assert.match(n, /node_expand/);
  assert.match(n, /lasoto@telecarga\.cl/);
});

test("sentinel_query with overlap=0 suggests ingest=true", () => {
  const n = composeNudge(
    "sentinel_query",
    { ingest: false },
    {
      schema_version: 1,
      found: [],
      missing: ["8.8.8.8"],
    },
  );
  assert.ok(n);
  assert.match(n, /ingest=true/);
});

test("sentinel_query with ingest=true emits no nudge", () => {
  assert.equal(
    composeNudge(
      "sentinel_query",
      { ingest: true },
      { schema_version: 1, found: [], missing: [] },
    ),
    null,
  );
});

test("sentinel_seed always suggests next step", () => {
  const n = composeNudge("sentinel_seed", { value: "X" }, null);
  assert.ok(n);
  assert.match(n, /node_expand/);
});

test("node_expand with neighbors > 0 suggests channel_behavior", () => {
  // neighbors_found is injected into args by ContextEnricher.countNeighbors,
  // which parses the result Neighborhood.nodes.length. The nudge sees an
  // augmented args object, not the raw tool input.
  const n = composeNudge("node_expand", { neighbors_found: 47 }, null);
  assert.ok(n);
  assert.match(n, /channel_behavior/);
});

test("node_expand with zero neighbors: no nudge", () => {
  assert.equal(composeNudge("node_expand", { neighbors_found: 0 }, null), null);
});

test("unknown tool: no nudge", () => {
  assert.equal(composeNudge("export", {}, null), null);
});

test("sentinel_query picks the highest-degree entity for the top suggestion", () => {
  const n = composeNudge(
    "sentinel_query",
    { ingest: false },
    {
      schema_version: 1,
      found: [
        { entity: "low", type: "IP", degree: 3, top_neighbor: null },
        { entity: "high", type: "IP", degree: 47, top_neighbor: null },
        { entity: "mid", type: "IP", degree: 12, top_neighbor: null },
      ],
      missing: [],
    },
  );
  assert.ok(n);
  assert.match(n, /Top: high/);
});
