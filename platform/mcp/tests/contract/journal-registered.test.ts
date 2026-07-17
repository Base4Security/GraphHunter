/**
 * Task A5 — asserts the `journal` tool (list/get/export past hunts) is
 * wired into the registry. Mirrors the shape of the other contract
 * tests: a cheap, always-on structural check rather than a live-server
 * assertion (those are gated behind GRAPHHUNTER_CONTRACT_TEST, see
 * schema.test.ts).
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import { registry } from "../../src/registry.js";
import type { ApiClient, Logger, ToolContext } from "../../src/lib/types.js";

test("contract: journal tool is registered", () => {
  const journal = registry.find((t) => t.name === "journal");
  assert.ok(journal, "journal tool present in registry");
  assert.equal(journal?.category, "hunt");
  assert.equal(journal?.stability, "stable");

  const op = journal?.inputSchema.safeParse({ op: "list" });
  assert.ok(op?.success, "op=list is a valid input");
});

// Regression for the "op=export returns an escaped NDJSON string" finding:
// the MCP content layer JSON.stringifies whatever `execute` returns, so a
// joined-string return value would force the LLM to un-escape and re-split
// it. op=export must return the structured events array itself.
test("contract: journal op=export returns the events array, not a joined string", async () => {
  const journal = registry.find((t) => t.name === "journal");
  assert.ok(journal, "journal tool present in registry");

  const events = [
    { kind: "call", tool: "search", ts: "2026-07-01T00:00:00Z" },
    { kind: "call", tool: "expand", ts: "2026-07-01T00:00:01Z" },
  ];

  const noopLogger: Logger = {
    info() {},
    warn() {},
    error() {},
    tool() {},
    api() {},
  };
  const fakeApi: ApiClient = {
    async get(path: string) {
      assert.equal(path, "/journal/hunt-123");
      return { meta: { id: "hunt-123" }, events };
    },
    async post() {
      throw new Error("unexpected POST in op=export test");
    },
  };
  const ctx: ToolContext = { api: fakeApi, logger: noopLogger, requestId: "test" };

  const result = await journal!.execute(ctx, { op: "export", id: "hunt-123" });

  assert.ok(Array.isArray(result), "op=export result is an array, not a string");
  assert.deepEqual(result, events);
});
