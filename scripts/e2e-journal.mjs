#!/usr/bin/env node
// End-to-end acceptance test for the Hunt Journal (design doc
// docs/superpowers/plans/2026-07-17-hunt-journal.md, Tasks A6 + B4):
//
// SECTION 1 (A6): journal_start → /kql (carrying a fake secret) →
//   /graph/neighbors → journal_get. Proves two things about the
//   mandatory capture middleware:
//   1. Capture is mandatory: every non-excluded request produces an
//      in-order HuntEvent in the current hunt's journal.
//   2. Capture is secret-free: request bodies are redacted before
//      persistence, so a secret sent on the wire never appears in the
//      journal's JSON.
//
// SECTION 2 (B4): runs the same lookup two ways, each in its own hunt —
//   a summarized tool-path /kql query vs. a raw-dump /kql query — and
//   proves the tool path's cumulative_est_tokens (from journal_stats)
//   is measurably lower, plus that the tool path's summary carries a
//   real detail_ref pointer back to the full data.
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

async function runCaptureAndRedactionSection() {
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

// ============================================================
// SECTION 2 (Task B4): token-lean acceptance — the tool/summary path is
// measurably cheaper (fewer recorded est_tokens) than a raw KQL dump for
// the same logical lookup.
//
// Runs the same lookup ("recent Sentinel sign-in activity") two ways,
// each isolated in its own hunt so journal_stats for one is unaffected
// by the other:
//
//   tool/summary hunt (T): a wide-row-count, narrow-column /kql query.
//     Enough rows to blow well past the summarizer's 400-est-token
//     threshold (see journal/summarize.rs), so the persisted event
//     carries a compact {_summary:true, counts, top<=5, detail_ref}
//     instead of the full result set.
//
//   raw hunt (R): a small-row-count, full-column /kql query — the
//     "analyst just dumped the raw rows" baseline. Real Sentinel rows
//     are wide (AuthenticationDetails, AuthenticationProcessingDetails,
//     ...), so even a handful of un-projected rows outweighs the tool
//     path's 5-row narrow summary by an order of magnitude. In practice
//     this baseline also ends up past the summarizer threshold — that's
//     fine per the task brief's fallback: what matters is the RECORDED
//     cost is clearly bigger than the tool path's, not that this path
//     dodges summarization altogether.
async function runTokenLeanSection() {
  console.log("\n\n=== SECTION 2: token-lean acceptance (tool < raw) ===");

  // Step 5 — start the tool/summary hunt.
  step(5, "POST /journal/start {label: tool}");
  const startedT = await post("/journal/start", { label: "tool" });
  const huntT = startedT.hunt_id;
  if (!huntT) fail("/journal/start (tool) did not return hunt_id", startedT);
  console.log(`  hunt_id=${huntT}`);

  // Step 6 — many rows, narrow projection: the summarizer should compress this.
  step(6, "POST /kql — many rows, narrow projection (tool/summary path)");
  const toolKql = await post("/kql", {
    kql: "SigninLogs | take 30 | project TimeGenerated, UserPrincipalName, IPAddress, ResultType, AppDisplayName",
    ingest: false,
    acknowledge_fallback: true,
  });
  console.log(`  /kql (tool) → row_count=${toolKql.row_count ?? "?"}`);

  // Step 7 — start the raw hunt.
  step(7, "POST /journal/start {label: raw}");
  const startedR = await post("/journal/start", { label: "raw" });
  const huntR = startedR.hunt_id;
  if (!huntR) fail("/journal/start (raw) did not return hunt_id", startedR);
  console.log(`  hunt_id=${huntR}`);

  // Step 8 — few rows, full columns: the raw-dump baseline.
  step(8, "POST /kql — few rows, full columns (raw path)");
  const rawKql = await post("/kql", {
    kql: "SigninLogs | take 5",
    ingest: false,
    acknowledge_fallback: true,
  });
  console.log(`  /kql (raw) → row_count=${rawKql.row_count ?? "?"}`);

  // Step 9 — compare cumulative_est_tokens between the two isolated hunts.
  step(9, "GET /journal/:id/stats for both hunts");
  const statsT = await get(`/journal/${huntT}/stats`);
  const statsR = await get(`/journal/${huntR}/stats`);
  console.log(`  tool: cumulative_est_tokens=${statsT.cumulative_est_tokens}`);
  console.log(`  raw:  cumulative_est_tokens=${statsR.cumulative_est_tokens}`);

  if (!(statsT.cumulative_est_tokens < statsR.cumulative_est_tokens)) {
    fail(
      `tool/summary hunt's cumulative_est_tokens (${statsT.cumulative_est_tokens}) is not < raw hunt's (${statsR.cumulative_est_tokens})`,
      { tool: statsT, raw: statsR },
    );
  }
  console.log(`  ✓ tool (${statsT.cumulative_est_tokens}) < raw (${statsR.cumulative_est_tokens})`);

  // Step 10 — prove the summary/reconstruction pointer exists: at least
  // one event in the tool hunt must carry a real summary + detail_ref.
  step(10, "GET /journal/:id_T — confirm a real summary + detail_ref exists");
  const recordT = await get(`/journal/${huntT}`);
  const events = recordT.events ?? [];
  const summarized = events.filter(
    (e) =>
      e.result?.summary?._summary === true &&
      typeof e.result.summary.detail_ref === "string" &&
      e.result.summary.detail_ref.length > 0,
  );
  if (summarized.length === 0) {
    fail(
      "no event in the tool hunt carries result.summary with _summary===true and a non-empty detail_ref",
      events.map((e) => ({ endpoint: e.endpoint, summary: e.result?.summary })),
    );
  }
  console.log(
    `  ✓ ${summarized.length} event(s) with a real summary + detail_ref (e.g. detail_ref="${summarized[0].result.summary.detail_ref}")`,
  );

  console.log("\njournal e2e: token-lean (tool < raw) OK");
}

async function main() {
  try {
    await runCaptureAndRedactionSection();
  } catch (e) {
    console.error(`\n❌ SECTION 1 (capture + redaction) failed: ${e.message}`);
    process.exit(1);
  }

  try {
    await runTokenLeanSection();
  } catch (e) {
    console.error(`\n❌ SECTION 2 (token-lean tool < raw) failed: ${e.message}`);
    process.exit(1);
  }
}

main().catch((e) => {
  console.error("\n❌ e2e failed:", e.message);
  process.exit(1);
});
