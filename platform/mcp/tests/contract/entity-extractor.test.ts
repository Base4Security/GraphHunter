import test from "node:test";
import assert from "node:assert/strict";
import { extractEntities } from "../../src/lib/entity-extractor.js";

test("extracts IPs from arbitrary string columns", () => {
  const rows = [{ Message: "src=203.0.113.42 dst=8.8.8.8" }];
  const out = extractEntities(rows);
  const ips = out
    .filter((e) => e.type === "IP")
    .map((e) => e.value)
    .sort();
  assert.deepEqual(ips, ["203.0.113.42", "8.8.8.8"]);
});

test("extracts emails as User", () => {
  const rows = [{ Account: "lasoto@telecarga.cl" }, { who: "x@y.zw" }];
  const out = extractEntities(rows);
  const users = out
    .filter((e) => e.type === "User")
    .map((e) => e.value)
    .sort();
  assert.deepEqual(users, ["lasoto@telecarga.cl", "x@y.zw"]);
});

test("Hostname classification gated on field name", () => {
  const rows = [{ Computer: "fw01.telecarga.cl", Note: "fw02.telecarga.cl" }];
  const out = extractEntities(rows);
  const hosts = out
    .filter((e) => e.type === "Hostname")
    .map((e) => e.value);
  assert.deepEqual(hosts, ["fw01.telecarga.cl"]);
  // The Note field's FQDN is classified as Domain, not Hostname.
  const domains = out
    .filter((e) => e.type === "Domain")
    .map((e) => e.value);
  assert.ok(domains.includes("fw02.telecarga.cl"));
});

test("dedupes across rows and caps at 500", () => {
  const rows = Array.from({ length: 1200 }, (_, i) => ({
    Message: `src=10.0.${Math.floor(i / 256)}.${i % 256}`,
  }));
  const out = extractEntities(rows);
  assert.ok(out.length <= 500, `cap respected: ${out.length} <= 500`);
});

test("maxRows cap is respected (does not scan past N rows)", () => {
  const rows = Array.from({ length: 1000 }, (_, i) => ({
    Message: `203.0.113.${i % 256}`,
  }));
  const out = extractEntities(rows, { maxRows: 50 });
  // 50 rows of values from 0..255 → at most 50 unique IPs
  assert.ok(out.length <= 50);
});

test("handles null and undefined values gracefully", () => {
  const rows = [
    { a: null, b: undefined, Message: "1.2.3.4" } as unknown as Record<string, unknown>,
  ];
  const out = extractEntities(rows);
  const ips = out.filter((e) => e.type === "IP").map((e) => e.value);
  assert.deepEqual(ips, ["1.2.3.4"]);
});
