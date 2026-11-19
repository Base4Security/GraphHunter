/**
 * `/graph/summary` and `/graph/overlap` sit behind the API's bearer
 * auth. The enricher's client used to call them with no Authorization
 * header: every call was a 401, the client turned that into `null`, and
 * the graph-context footer read "(unavailable)" on every tool response.
 * These pin the header so that cannot regress silently again.
 */

import test from "node:test";
import assert from "node:assert/strict";
import { GraphStateClient } from "../../src/lib/graph-state-client.js";

function recordingFetch(seen: Array<Record<string, string>>): typeof fetch {
  return (async (_url: unknown, init?: RequestInit) => {
    seen.push({ ...((init?.headers ?? {}) as Record<string, string>) });
    return new Response("{}", { status: 401 });
  }) as typeof fetch;
}

test("contract: getSummary sends the bearer token", async () => {
  const seen: Array<Record<string, string>> = [];
  const client = new GraphStateClient("http://127.0.0.1:1", {
    token: "t0ken",
    fetchImpl: recordingFetch(seen),
  });
  await client.getSummary({ timeoutMs: 500 });
  assert.equal(seen.length, 1);
  assert.equal(seen[0].authorization, "Bearer t0ken");
});

test("contract: postOverlap sends the bearer token and a JSON content type", async () => {
  const seen: Array<Record<string, string>> = [];
  const client = new GraphStateClient("http://127.0.0.1:1", {
    token: "t0ken",
    fetchImpl: recordingFetch(seen),
  });
  await client.postOverlap([{ type: "IP", value: "198.51.100.7" }]);
  assert.equal(seen[0].authorization, "Bearer t0ken");
  assert.equal(seen[0]["content-type"], "application/json");
});

test("contract: no token configured means no Authorization header", async () => {
  const seen: Array<Record<string, string>> = [];
  const client = new GraphStateClient("http://127.0.0.1:1", { fetchImpl: recordingFetch(seen) });
  await client.getSummary({ timeoutMs: 500 });
  assert.equal(seen[0].authorization, undefined);
});
