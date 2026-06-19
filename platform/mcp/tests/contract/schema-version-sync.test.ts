import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { SummarySchema } from "../../src/lib/graph-state-client.js";

const __dirname = path.dirname(fileURLToPath(import.meta.url));

// Loaded from compiled dist/tests/contract/, relative to the source tree.
// The golden lives in src tree at platform/mcp/tests/fixtures.
const GOLDEN_PATH = path.resolve(
  __dirname,
  "..",
  "..",
  "..",
  "tests",
  "fixtures",
  "summary.v1.golden.json",
);

test("zod schema accepts the shared v1 golden fixture", () => {
  const raw = fs.readFileSync(GOLDEN_PATH, "utf-8");
  const parsed = SummarySchema.parse(JSON.parse(raw));
  assert.equal(parsed.schema_version, 1);
  assert.equal(parsed.graph_empty, true);
  assert.equal(parsed.totals.nodes, 0);
});

test("bumping schema_version in the golden breaks the zod check (drift guard)", () => {
  const raw = fs.readFileSync(GOLDEN_PATH, "utf-8");
  const bumped = { ...JSON.parse(raw), schema_version: 2 };
  assert.throws(
    () => SummarySchema.parse(bumped),
    /Invalid literal|expected.*1/i,
    "schema_version is z.literal(1) — bumping must fail",
  );
});
