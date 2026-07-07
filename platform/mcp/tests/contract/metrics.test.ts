import test from "node:test";
import assert from "node:assert/strict";
import { Metrics, FollowthroughTracker } from "../../src/lib/metrics.js";

test("counters increment and snapshot reports them", () => {
  const m = new Metrics();
  m.incToolCall("sentinel_query");
  m.incToolCall("sentinel_query");
  m.incToolCall("node_expand");
  m.incNudgeDisplayed("sentinel_query");
  m.incNudgeFollowed("sentinel_query");
  m.incResourceRead("graph://summary");

  const snap = m.snapshot();
  assert.equal(snap.tool_calls.sentinel_query, 2);
  assert.equal(snap.tool_calls.node_expand, 1);
  assert.equal(snap.nudges_displayed.sentinel_query, 1);
  assert.equal(snap.nudges_followed.sentinel_query, 1);
  assert.equal(snap.resource_reads["graph://summary"], 1);
});

test("FollowthroughTracker credits a graph-side call after a nudge", () => {
  const t = new FollowthroughTracker();
  t.recordNudge("sentinel_query");
  const r = t.recordCall("node_expand");
  assert.equal(r.followedNudgeFor, "sentinel_query");
});

test("FollowthroughTracker does NOT credit a subsequent sentinel_query", () => {
  const t = new FollowthroughTracker();
  t.recordNudge("sentinel_query");
  const r = t.recordCall("sentinel_query");
  assert.equal(r.followedNudgeFor, null);
});

test("FollowthroughTracker resets after a non-followthrough call", () => {
  const t = new FollowthroughTracker();
  t.recordNudge("sentinel_query");
  t.recordCall("sentinel_query"); // resets
  const r = t.recordCall("node_expand");
  // The stale nudge was already cleared, so this is no longer a credit.
  assert.equal(r.followedNudgeFor, null);
});
