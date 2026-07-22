import { test } from "node:test";
import assert from "node:assert/strict";
import { sentinelQuery } from "../../src/tools/sentinel/query.js";

test("sentinel_query is flagged as an escape hatch", () => {
  assert.equal(sentinelQuery.escapeHatch, true);
  assert.equal(sentinelQuery.name, "sentinel_query");
});

test("sentinel_query labels its result as source-tabular, not a graph answer", async () => {
  // Stub ctx.api.post to return raw rows; execute must label them so the
  // caller can never mistake source rows for a causal graph result. We use
  // the spread variant (source_tabular sibling + original top-level fields)
  // because ContextEnricher.parseRows (src/lib/context-enricher.ts) reads
  // `.rows` directly off the tool's raw execute() output in production —
  // wrapping in `{ result }` would silently break the overlap-nudge feature
  // for sentinel_query.
  const calls: Array<{ path: string; body: unknown }> = [];
  const ctx = {
    api: {
      post: async (path: string, body: unknown) => {
        calls.push({ path, body });
        return { rows: [{ a: 1 }], kql_executed: "SecurityEvent | take 1" };
      },
    },
  } as any;
  const out: any = await sentinelQuery.execute(ctx, { query: "SecurityEvent | take 1" });
  assert.equal(calls[0].path, "/kql");
  assert.equal(out.source_tabular, true);
  // The underlying rows survive at the top level (the spread variant, not a
  // `{ result }` wrap) — this is exactly what lets ContextEnricher.parseRows
  // read `.rows` directly off execute()'s output.
  assert.deepEqual(out.rows, [{ a: 1 }]);
});
