import test from "node:test";
import assert from "node:assert/strict";
import { composeFooter } from "../../src/lib/footer-composer.js";
import type { Summary } from "../../src/lib/graph-state-client.js";

function minutesAgo(m: number): string {
  return new Date(Date.now() - m * 60_000).toISOString();
}

const baseSummary: Summary = {
  schema_version: 1,
  as_of: new Date().toISOString(),
  totals: { nodes: 2_412_588, edges: 18_402_117, by_type: {} },
  sources: [
    { name: "Sentinel", last_ingest: minutesAgo(30), rows_lifetime: 18_000_000 },
    { name: "FortiGate", last_ingest: minutesAgo(180), rows_lifetime: 220_000_000 },
  ],
  active_datasets: [],
  active_hunts: [],
  recent_pivots: [],
  graph_empty: false,
};

test("base footer has totals and source freshness", () => {
  const f = composeFooter(baseSummary);
  assert.match(f, /---graph-context---/);
  assert.match(f, /2\.4M nodes/);
  assert.match(f, /Sentinel\(30m\)/);
  assert.match(f, /FortiGate\(3h\)/);
});

test("collapses second line when no hunts and no pivots", () => {
  const f = composeFooter(baseSummary);
  // header + totals line only
  assert.equal(f.split("\n").length, 2);
});

test("includes active hunt when present", () => {
  const f = composeFooter({
    ...baseSummary,
    active_hunts: [
      {
        cache_key: "hunt-abc123def456",
        params_summary: "seed=X depth=3",
        result_size: 1840,
        computed_at: new Date().toISOString(),
        ttl_seconds_remaining: 2400,
      },
    ],
  });
  // cache_key sliced to 12 chars: "hunt-abc123d"
  assert.match(f, /active hunt: hunt-abc123d /);
  assert.match(f, /seed=X depth=3/);
});

test("includes recent pivot with expanded flag", () => {
  const f = composeFooter({
    ...baseSummary,
    recent_pivots: [
      {
        entity: "203.0.113.42",
        type: "IP",
        added_at: new Date().toISOString(),
        expanded: false,
        degree: 0,
      },
    ],
  });
  assert.match(f, /recent pivot: 203\.0\.113\.42/);
  assert.match(f, /unexpanded/);
});

test("unavailable when summary is null", () => {
  assert.match(composeFooter(null), /\(unavailable\)/);
});
