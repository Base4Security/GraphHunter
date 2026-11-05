/**
 * Task B3 — the MCP render layer must pass API-produced summaries
 * (`{ _summary: true, ... }`) through `sanitizeApiResponse` untouched
 * instead of running the usual array/string truncation over them.
 * Summaries are already compact by construction; blunt-truncating one
 * would corrupt the payload and strip the `_summary`/`detail_ref`
 * markers callers rely on. Non-summary payloads must still truncate
 * exactly as before — this proves the guard is narrowly scoped.
 */

import test from "node:test";
import assert from "node:assert/strict";
import { sanitizeApiResponse } from "../../src/lib/content.js";

test("contract: a _summary:true payload passes through sanitizeApiResponse untouched", () => {
  const summary = {
    _summary: true,
    kind: "query",
    counts: { row_count: 100 },
    top: [{ a: 1 }],
    detail_ref: "h#1",
  };

  const result = sanitizeApiResponse(summary);

  assert.deepEqual(result, summary);
  assert.equal((result as Record<string, unknown>)._summary, true);
  assert.equal((result as Record<string, unknown>).detail_ref, "h#1");
  assert.equal(
    Object.prototype.hasOwnProperty.call(result as object, "_truncated"),
    false,
    "no _truncated marker should be added to a summary payload",
  );
  assert.equal(
    Object.prototype.hasOwnProperty.call(result as object, "_showing"),
    false,
    "no _showing marker should be added to a summary payload",
  );
});

test("contract: a large non-summary payload with a COLLECTION_KEYS array still truncates", () => {
  // "nodes" is one of the COLLECTION_KEYS in src/lib/content.ts.
  const nodes = Array.from({ length: 150 }, (_, i) => ({ id: i }));
  const payload = { kind: "graph", nodes };

  const result = sanitizeApiResponse(payload) as Record<string, unknown>;

  assert.equal(result._nodes_truncated, true, "large COLLECTION_KEYS array still gets the truncation marker");
  assert.equal(result._nodes_total, 150);
  assert.ok(Array.isArray(result.nodes));
  assert.equal((result.nodes as unknown[]).length, 100, "array is capped at MAX_ARRAY_ITEMS");
});

test("contract: a bare large array with no _summary still returns the _truncated envelope", () => {
  const items = Array.from({ length: 150 }, (_, i) => ({ id: i }));

  const result = sanitizeApiResponse(items) as Record<string, unknown>;

  assert.equal(result._truncated, true);
  assert.equal(result._total, 150);
  assert.equal(result._showing, 100);
  assert.ok(Array.isArray(result.items));
  assert.equal((result.items as unknown[]).length, 100);
});
