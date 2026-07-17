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

test("contract: journal tool is registered", () => {
  const journal = registry.find((t) => t.name === "journal");
  assert.ok(journal, "journal tool present in registry");
  assert.equal(journal?.category, "hunt");
  assert.equal(journal?.stability, "stable");

  const op = journal?.inputSchema.safeParse({ op: "list" });
  assert.ok(op?.success, "op=list is a valid input");
});
