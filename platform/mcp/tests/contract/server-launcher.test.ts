/**
 * The packaged bundle works with no configuration because the MCP server
 * finds `graph-hunter-server` beside itself and runs it on a port of its
 * own. These pin the two pieces that make that true.
 */

import test from "node:test";
import assert from "node:assert/strict";
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { createServer } from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { pathToFileURL } from "node:url";
import { findBundledServer, freePort } from "../../src/lib/server-launcher.js";

const exe = process.platform === "win32" ? "graph-hunter-server.exe" : "graph-hunter-server";

test("contract: finds the server in bin/ beside the entry file's directory", () => {
  const root = mkdtempSync(join(tmpdir(), "gh-bundle-"));
  try {
    mkdirSync(join(root, "server"));
    mkdirSync(join(root, "bin"));
    writeFileSync(join(root, "bin", exe), "");
    const entry = pathToFileURL(join(root, "server", "index.mjs")).href;
    assert.equal(findBundledServer(entry), join(root, "bin", exe));
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test("contract: no bundled server means none is reported", () => {
  const root = mkdtempSync(join(tmpdir(), "gh-bundle-"));
  try {
    mkdirSync(join(root, "server"));
    const entry = pathToFileURL(join(root, "server", "index.mjs")).href;
    assert.equal(findBundledServer(entry), "");
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test("contract: freePort returns a loopback port that can be bound", async () => {
  const port = await freePort();
  assert.ok(port > 0 && port < 65536);
  await new Promise<void>((resolve, reject) => {
    const s = createServer();
    s.once("error", reject);
    s.listen(port, "127.0.0.1", () => s.close(() => resolve()));
  });
});
