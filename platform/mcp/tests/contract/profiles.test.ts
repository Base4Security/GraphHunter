/**
 * Tool groups decide what every session pays for up front. These pin
 * that the grouping is total (no tool silently unreachable, none listed
 * twice) and that the default stays small.
 */

import test from "node:test";
import assert from "node:assert/strict";
import { z } from "zod";
import { GROUPS, instructionsFor, selectTools } from "../../src/profiles.js";
import { registry } from "../../src/registry.js";

const names = registry.map((t) => t.name);

test("contract: every tool is in exactly one group, and groups name only real tools", () => {
  const grouped = Object.values(GROUPS).flatMap((g) => g.tools);
  assert.deepEqual([...grouped].sort(), [...names].sort());
  assert.equal(new Set(grouped).size, grouped.length, "a tool is listed in two groups");
});

test("contract: the default is the core group and nothing else", () => {
  for (const spec of [undefined, "", "  "]) {
    const s = selectTools(registry, spec);
    assert.deepEqual(s.groups, ["core"]);
    assert.deepEqual(s.tools.map((t) => t.name).sort(), [...GROUPS.core.tools].sort());
  }
});

test("contract: core covers a hunt end to end", () => {
  for (const needed of [
    "session_create",
    "ingest_load",
    "graph_relation_schema",
    "node_search",
    "hunt_run",
    "hunt_results",
    "journal",
  ]) {
    assert.ok(GROUPS.core.tools.includes(needed), `${needed} must stay in core`);
  }
});

test("contract: the default costs well under half of the full catalog", () => {
  const size = (tools: typeof registry) =>
    tools.reduce(
      (n, t) =>
        n +
        JSON.stringify({
          name: t.name,
          description: t.description,
          inputSchema: z.toJSONSchema(t.inputSchema),
        }).length,
      0,
    );
  const core = size(selectTools(registry, undefined).tools);
  const full = size(registry);
  assert.ok(core < full * 0.4, `core ${core} chars vs full ${full}`);
});

test("contract: groups add to core; full and unknown names behave", () => {
  const some = selectTools(registry, "Sentinel, report");
  assert.deepEqual(some.groups, ["core", "sentinel", "report"]);
  assert.ok(some.tools.some((t) => t.name === "sentinel_query"));
  assert.ok(some.tools.some((t) => t.name === "hunt_run"));
  assert.ok(!some.tools.some((t) => t.name === "ingest_negotiate"));

  assert.equal(selectTools(registry, "full").tools.length, registry.length);

  const typo = selectTools(registry, "analisis");
  assert.deepEqual(typo.unknown, ["analisis"]);
  assert.deepEqual(typo.groups, ["core"]);
});

test("contract: instructions name the groups that are off, and vanish when all are on", () => {
  const text = instructionsFor(selectTools(registry, "analysis"));
  assert.match(text, /sentinel/);
  assert.match(text, /GRAPHHUNTER_MCP_TOOLS/);
  assert.doesNotMatch(text, /^- analysis:/m);
  assert.equal(instructionsFor(selectTools(registry, "full")), "");
});
