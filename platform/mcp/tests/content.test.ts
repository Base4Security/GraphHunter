/**
 * Regression test for the v2 long-text truncation bug (#2 from the
 * 2026-05-06 QA pass): `safeJsonContent` was cutting every string
 * > 200 chars with " ... " regardless of key, destroying
 * payload-bearing fields like `narrative`, `yaml`, `content`,
 * `vrl_source`, etc. Fix: key-aware whitelist (`LONG_TEXT_KEYS`).
 *
 * These tests pin the contract: long-text keys round-trip unchanged,
 * unknown long strings still get truncated.
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import { sanitizeApiResponse } from "../src/lib/content.js";

const longString = "A".repeat(800) + "Z";

test("sanitize: whitelisted long-text keys pass through verbatim", () => {
  const out = sanitizeApiResponse({
    narrative: longString,
    yaml: longString,
    content: longString,
    vrl_source: longString,
    rationale: longString,
    kql_executed: longString,
  }) as Record<string, string>;
  for (const key of [
    "narrative",
    "yaml",
    "content",
    "vrl_source",
    "rationale",
    "kql_executed",
  ]) {
    assert.equal(
      out[key],
      longString,
      `${key} must round-trip without truncation`,
    );
    assert.equal(out[key].length, 801, `${key} length preserved`);
  }
});

test("sanitize: unknown long strings still get truncated", () => {
  const out = sanitizeApiResponse({ random_metadata: longString }) as Record<
    string,
    string
  >;
  assert.notEqual(
    out.random_metadata,
    longString,
    "unknown keys must still be capped",
  );
  assert.ok(
    out.random_metadata.includes(" ... "),
    "truncation marker preserved for unknown keys",
  );
  assert.ok(
    out.random_metadata.length < 250,
    "truncated value stays around the 200-char cap",
  );
});

test("sanitize: nested objects also respect the whitelist", () => {
  const out = sanitizeApiResponse({
    drafts: [
      { id: "abc", vrl_source: longString, rationale: longString },
    ],
  }) as { drafts: Array<{ vrl_source: string; rationale: string }> };
  assert.equal(out.drafts[0].vrl_source, longString);
  assert.equal(out.drafts[0].rationale, longString);
});

test("sanitize: short strings unchanged regardless of key", () => {
  const out = sanitizeApiResponse({
    narrative: "short",
    random: "also short",
  }) as Record<string, string>;
  assert.equal(out.narrative, "short");
  assert.equal(out.random, "also short");
});
