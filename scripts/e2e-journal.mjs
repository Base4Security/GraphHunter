#!/usr/bin/env node
// End-to-end acceptance test for the Hunt Journal (design doc
// docs/superpowers/plans/2026-07-17-hunt-journal.md, Task A6):
//   journal_start → /kql (carrying a fake secret) → /graph/neighbors → journal_get
//
// Proves two things about the mandatory capture middleware:
//   1. Capture is mandatory: every non-excluded request produces an
//      in-order HuntEvent in the current hunt's journal.
//   2. Capture is secret-free: request bodies are redacted before
//      persistence, so a secret sent on the wire never appears in the
//      journal's JSON.
//
// Drives the GraphHunter HTTP API directly (same endpoints the MCP tools
// call). Env-gated so it never runs by accident:
//
//   GRAPHHUNTER_E2E=1                 required, opt-in
//   GRAPHHUNTER_API_URL=...           default http://127.0.0.1:37891
//   GRAPHHUNTER_API_TOKEN=...         bearer token printed by the app at startup
//
// Exits non-zero on the first failed assertion.

const BASE = process.env.GRAPHHUNTER_API_URL ?? "http://127.0.0.1:37891";
const TOKEN = process.env.GRAPHHUNTER_API_TOKEN;
const FAKE_SECRET = "FAKE-SECRET-123";

if (process.env.GRAPHHUNTER_E2E !== "1") {
  console.log("skip: set GRAPHHUNTER_E2E=1 to run the journal e2e.");
  process.exit(0);
}

function headers() {
  return {
    "content-type": "application/json",
    ...(TOKEN ? { authorization: `Bearer ${TOKEN}` } : {}),
  };
}

// POST helper mirroring e2e-graph-cycle.mjs's `call()`: throws on non-2xx.
async function post(path, body) {
  const res = await fetch(new URL(path, BASE), {
    method: "POST",
    headers: headers(),
    body: JSON.stringify(body ?? {}),
  });
  const text = await res.text();
  let json;
  try {
    json = JSON.parse(text);
  } catch {
    json = text;
  }
  if (!res.ok) {
    throw new Error(`${path} → HTTP ${res.status}: ${text}`);
  }
  return json;
}

// POST helper that tolerates non-2xx (some endpoints legitimately 200-with-
// error-body or error out on live-credential calls; the point of this e2e
// is that the request got CAPTURED, not that it succeeded).
async function postTolerant(path, body) {
  const res = await fetch(new URL(path, BASE), {
    method: "POST",
    headers: headers(),
    body: JSON.stringify(body ?? {}),
  });
  const text = await res.text();
  let json;
  try {
    json = JSON.parse(text);
  } catch {
    json = text;
  }
  return { status: res.status, ok: res.ok, body: json };
}

async function get(path) {
  const res = await fetch(new URL(path, BASE), {
    method: "GET",
    headers: headers(),
  });
  const text = await res.text();
  let json;
  try {
    json = JSON.parse(text);
  } catch {
    json = text;
  }
  if (!res.ok) {
    throw new Error(`${path} → HTTP ${res.status}: ${text}`);
  }
  return json;
}

function step(n, label) {
  console.log(`\n=== Step ${n}: ${label} ===`);
}

function fail(message, offending) {
  console.error(`\n❌ assertion failed: ${message}`);
  if (offending !== undefined) {
    console.error("offending value:", JSON.stringify(offending, null, 2));
  }
  process.exit(1);
}

async function main() {
  // Step 1 — start a hunt.
  step(1, "POST /journal/start");
  const started = await post("/journal/start", { label: "e2e" });
  const huntId = started.hunt_id;
  if (!huntId) fail("/journal/start did not return hunt_id", started);
  console.log(`  hunt_id=${huntId}`);

  // Step 2 — a captured endpoint carrying a secret. Non-2xx is fine (live
  // Sentinel creds may not be configured); what matters is the request is
  // captured and the secret redacted before persistence.
  step(2, "POST /kql (carries a fake secret)");
  const kql = await postTolerant("/kql", {
    kql: "SigninLogs | take 1",
    azure_client_secret: FAKE_SECRET,
    ingest: false,
    acknowledge_fallback: true,
  });
  console.log(`  /kql → HTTP ${kql.status}`);

  // Step 3 — a graph traversal call. May 200-with-error-body; fine.
  step(3, "POST /graph/neighbors");
  const neighbors = await postTolerant("/graph/neighbors", {
    entity: { class: "User", value: "x" },
  });
  console.log(`  /graph/neighbors → HTTP ${neighbors.status}`);

  // Step 4 — read the journal back.
  step(4, "GET /journal/:hunt_id");
  const record = await get(`/journal/${huntId}`);
  const events = record.events ?? [];
  console.log(`  ${events.length} event(s) recorded`);

  // --- Assertions ---

  // At least 2 events, seq strictly increasing (in order).
  if (events.length < 2) {
    fail(`journal record has ${events.length} event(s), expected >= 2`, record);
  }
  for (let i = 1; i < events.length; i++) {
    const prev = events[i - 1].seq;
    const cur = events[i].seq;
    if (!(cur > prev)) {
      fail(
        `event seq not strictly increasing at index ${i} (prev=${prev}, cur=${cur})`,
        events.map((e) => e.seq),
      );
    }
  }
  console.log(`  ✓ ${events.length} events, seq strictly increasing: [${events.map((e) => e.seq).join(", ")}]`);

  // At least one event classified as kind "query" (the /kql call).
  const queryEvents = events.filter((e) => e.kind === "query");
  if (queryEvents.length === 0) {
    fail(
      'no event with kind === "query" found (expected the /kql call to classify as "query")',
      events.map((e) => ({ endpoint: e.endpoint, kind: e.kind })),
    );
  }
  console.log(`  ✓ ${queryEvents.length} event(s) with kind "query"`);

  // The fake secret must appear NOWHERE in the journal JSON — redaction proof.
  const recordJson = JSON.stringify(record);
  if (recordJson.includes(FAKE_SECRET)) {
    fail(
      `literal secret "${FAKE_SECRET}" found in journal record — redaction FAILED`,
      recordJson,
    );
  }
  console.log(`  ✓ "${FAKE_SECRET}" does not appear anywhere in the journal record`);

  // Every event's result.est_tokens > 0.
  const zeroTokenEvents = events.filter((e) => !(e.result?.est_tokens > 0));
  if (zeroTokenEvents.length > 0) {
    fail(
      "found event(s) with result.est_tokens not > 0",
      zeroTokenEvents.map((e) => ({ endpoint: e.endpoint, est_tokens: e.result?.est_tokens })),
    );
  }
  console.log(`  ✓ all ${events.length} events have result.est_tokens > 0`);

  console.log("\njournal e2e: mandatory capture + redaction OK");
}

main().catch((e) => {
  console.error("\n❌ e2e failed:", e.message);
  process.exit(1);
});
