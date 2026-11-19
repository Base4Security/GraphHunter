#!/usr/bin/env node
/**
 * Builds the self-contained Graph Hunter MCP bundle for this platform:
 *
 *   graph-hunter-mcp-<version>-<platform>-<arch>/
 *   ├── manifest.json          MCPB manifest (Claude Desktop reads this)
 *   ├── server/index.mjs       the MCP server, bundled into one file
 *   ├── bin/graph-hunter-server[.exe]
 *   ├── README.md
 *   └── LICENSE
 *
 * and the same tree zipped as `<name>.mcpb`. The MCP server finds the
 * binary beside itself and runs it on a private port, so the bundle
 * needs nothing but Node: no desktop app, no environment variables.
 *
 * One bundle per platform — the server binary is native. Run this on
 * each OS you ship for.
 *
 *   node scripts/pack.mjs [--server-bin PATH] [--out DIR] [--no-smoke]
 *
 * --server-bin  use an already-built graph-hunter-server instead of
 *               running `cargo build --locked --release`.
 */

import { spawn, spawnSync } from "node:child_process";
import { chmodSync, copyFileSync, existsSync, mkdirSync, readFileSync, readdirSync, rmSync, statSync, writeFileSync } from "node:fs";
import { dirname, join, relative, resolve, sep } from "node:path";
import { fileURLToPath } from "node:url";
import { deflateRawSync } from "node:zlib";
import { build } from "esbuild";

const mcpDir = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const repo = resolve(mcpDir, "..", "..");
const args = process.argv.slice(2);
const flag = (name) => args.includes(name);
const value = (name) => {
  const i = args.indexOf(name);
  return i >= 0 ? args[i + 1] : undefined;
};

const pkg = JSON.parse(readFileSync(join(mcpDir, "package.json"), "utf8"));
const exe = process.platform === "win32" ? "graph-hunter-server.exe" : "graph-hunter-server";
const bundleName = `graph-hunter-mcp-${pkg.version}-${process.platform}-${process.arch}`;
const outDir = resolve(value("--out") ?? join(mcpDir, "bundle"));
const stage = join(outDir, bundleName);

// No shell: arguments go to the program as an array, never through a
// command line that would need escaping.
function run(cmd, cmdArgs, cwd) {
  const r = spawnSync(cmd, cmdArgs, { cwd, stdio: "inherit" });
  if (r.error) throw r.error;
  if (r.status !== 0) throw new Error(`${cmd} ${cmdArgs.join(" ")} failed`);
}

// ── 1. server binary ───────────────────────────────────────────────────
let serverBin = value("--server-bin");
if (!serverBin) {
  const manifest = join(repo, "platform", "server", "Cargo.toml");
  run("cargo", ["build", "--locked", "--release", "--manifest-path", manifest], repo);
  const targetDir = process.env.CARGO_TARGET_DIR
    ? resolve(process.env.CARGO_TARGET_DIR)
    : join(repo, "platform", "server", "target");
  serverBin = join(targetDir, "release", exe);
}
serverBin = resolve(serverBin);
if (!existsSync(serverBin)) throw new Error(`server binary not found: ${serverBin}`);

// ── 2. stage ───────────────────────────────────────────────────────────
rmSync(stage, { recursive: true, force: true });
mkdirSync(join(stage, "server"), { recursive: true });
mkdirSync(join(stage, "bin"), { recursive: true });

run(process.execPath, [join(mcpDir, "node_modules", "typescript", "bin", "tsc"), "--noEmit"], mcpDir);
await build({
  entryPoints: [join(mcpDir, "src", "index.ts")],
  outfile: join(stage, "server", "index.mjs"),
  bundle: true,
  platform: "node",
  format: "esm",
  target: "node18",
  // Some dependencies are CommonJS and call require() for Node built-ins;
  // an ESM bundle has no `require` unless we give it one.
  banner: {
    js: "import { createRequire as __createRequire } from 'node:module';\nconst require = __createRequire(import.meta.url);",
  },
  legalComments: "eof",
  logLevel: "warning",
});

copyFileSync(serverBin, join(stage, "bin", exe));
chmodSync(join(stage, "bin", exe), 0o755);
copyFileSync(join(repo, "LICENSE"), join(stage, "LICENSE"));
copyFileSync(join(mcpDir, "scripts", "bundle-README.md"), join(stage, "README.md"));

const manifest = {
  $schema: "https://raw.githubusercontent.com/anthropics/mcpb/main/schemas/mcpb-manifest-v0.4.schema.json",
  manifest_version: "0.4",
  name: "graph-hunter",
  display_name: "Graph Hunter",
  version: pkg.version,
  description:
    "Threat hunting on a temporal graph: ingest logs from several sources, correlate them with one-line patterns, rank rare entities.",
  author: { name: "GraphHunter Contributors" },
  license: "GPL-3.0-only",
  server: {
    type: "node",
    entry_point: "server/index.mjs",
    mcp_config: {
      command: "node",
      args: ["${__dirname}/server/index.mjs"],
      env: {
        GRAPHHUNTER_INGEST_ROOT: "${user_config.ingest_root}",
        GRAPHHUNTER_DOMAIN_ALIASES: "${user_config.domain_aliases}",
        GRAPHHUNTER_MCP_TOOLS: "${user_config.tool_groups}",
      },
    },
  },
  user_config: {
    ingest_root: {
      type: "directory",
      title: "Log directory",
      description:
        "Directory holding the log files to investigate. Graph Hunter only reads files under it; without it, file ingest is refused.",
      required: true,
    },
    domain_aliases: {
      type: "string",
      title: "Domain aliases (optional)",
      description:
        "NETBIOS=dns.domain pairs, comma-separated (e.g. CORP=corp.example), so CORP\\user and user@corp.example are one account. Leave empty if unsure.",
      required: false,
      default: "",
    },
    tool_groups: {
      type: "string",
      title: "Extra tool groups (optional)",
      description:
        "Empty loads the core tools only, which keeps every session cheap. Add groups separated by commas: analysis, report, sentinel, ingest-advanced. Or `full` for everything.",
      required: false,
      default: "",
    },
  },
  compatibility: {
    platforms: [process.platform],
    runtimes: { node: ">=18" },
  },
};
writeFileSync(join(stage, "manifest.json"), JSON.stringify(manifest, null, 2) + "\n");

// ── 3. smoke test: the staged bundle, with nothing in the environment ──
if (!flag("--no-smoke")) await smoke();

// ── 4. zip as .mcpb ────────────────────────────────────────────────────
const archive = join(outDir, `${bundleName}.mcpb`);
writeFileSync(archive, zip(stage));
const mb = (p) => (statSync(p).size / 1e6).toFixed(1) + " MB";
console.log(`\nbundle:  ${stage}`);
console.log(`archive: ${archive} (${mb(archive)}; server binary ${mb(join(stage, "bin", exe))})`);

// ───────────────────────────────────────────────────────────────────────

/** Speak MCP over stdio to the staged server: it must start its own
 *  graph-hunter-server, list its tools and reach the API. */
async function smoke() {
  const env = { ...process.env };
  for (const k of Object.keys(env)) if (k.startsWith("GRAPHHUNTER_") || k === "GH_MCP_ENRICH") delete env[k];
  env.GRAPHHUNTER_INGEST_ROOT = stage;
  const child = spawn(process.execPath, [join(stage, "server", "index.mjs")], { env, stdio: ["pipe", "pipe", "pipe"] });
  let stderr = "";
  child.stderr.on("data", (d) => (stderr += d));
  let buf = "";
  const waiting = new Map();
  child.stdout.on("data", (d) => {
    buf += d;
    for (let i; (i = buf.indexOf("\n")) >= 0; ) {
      const line = buf.slice(0, i).trim();
      buf = buf.slice(i + 1);
      if (!line) continue;
      const msg = JSON.parse(line);
      waiting.get(msg.id)?.(msg);
      waiting.delete(msg.id);
    }
  });
  let id = 0;
  const rpc = (method, params) =>
    new Promise((res, rej) => {
      const mine = ++id;
      const timer = setTimeout(() => rej(new Error(`smoke: no answer to ${method}\n${stderr}`)), 40_000);
      waiting.set(mine, (m) => (clearTimeout(timer), res(m)));
      child.stdin.write(JSON.stringify({ jsonrpc: "2.0", id: mine, method, params }) + "\n");
    });
  try {
    await rpc("initialize", { protocolVersion: "2024-11-05", capabilities: {}, clientInfo: { name: "pack-smoke", version: "0" } });
    child.stdin.write(JSON.stringify({ jsonrpc: "2.0", method: "notifications/initialized" }) + "\n");
    const tools = (await rpc("tools/list", {})).result.tools;
    const check = await rpc("tools/call", { name: "session_check", arguments: {} });
    const text = check.result.content.map((c) => c.text).join("");
    if (!text.includes('"ok": true')) throw new Error(`smoke: API not reachable through the bundle:\n${text}\n${stderr}`);
    if (!/"server":"launched"/.test(stderr)) throw new Error(`smoke: the bundled server was not launched\n${stderr}`);
    const size = JSON.stringify(tools).length;
    console.log(
      `smoke: ok — ${tools.length} tools (~${Math.round(size / 4)} tokens of definitions), bundled server launched and answering`,
    );
  } finally {
    child.stdin.end();
    await new Promise((r) => child.once("exit", r));
  }
}

/** Minimal zip writer (deflate, no zip64): enough for a .mcpb, and it
 *  records Unix modes so the server binary stays executable. */
function zip(root) {
  const files = [];
  (function walk(dir) {
    for (const name of readdirSync(dir).sort()) {
      const full = join(dir, name);
      if (statSync(full).isDirectory()) walk(full);
      else files.push(full);
    }
  })(root);

  const table = new Uint32Array(256).map((_, n) => {
    let c = n;
    for (let k = 0; k < 8; k++) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1;
    return c >>> 0;
  });
  const crc32 = (data) => {
    let c = 0xffffffff;
    for (const byte of data) c = table[(c ^ byte) & 0xff] ^ (c >>> 8);
    return (c ^ 0xffffffff) >>> 0;
  };

  const local = [];
  const central = [];
  let offset = 0;
  for (const full of files) {
    const name = Buffer.from(relative(root, full).split(sep).join("/"));
    const data = readFileSync(full);
    const packed = deflateRawSync(data, { level: 9 });
    const mode = full.includes(`${sep}bin${sep}`) ? 0o100755 : 0o100644;
    const head = Buffer.alloc(30);
    head.writeUInt32LE(0x04034b50, 0);
    head.writeUInt16LE(20, 4); // version needed
    head.writeUInt16LE(0x0800, 6); // UTF-8 names
    head.writeUInt16LE(8, 8); // deflate
    head.writeUInt32LE(0x00210000, 10); // fixed DOS time/date: reproducible archives
    head.writeUInt32LE(crc32(data), 14);
    head.writeUInt32LE(packed.length, 18);
    head.writeUInt32LE(data.length, 22);
    head.writeUInt16LE(name.length, 26);
    const entry = Buffer.alloc(46);
    entry.writeUInt32LE(0x02014b50, 0);
    entry.writeUInt16LE((3 << 8) | 20, 4); // made by: Unix
    head.copy(entry, 6, 4, 30); // version needed .. extra length
    entry.writeUInt32LE((mode << 16) >>> 0, 38); // external attrs: Unix mode
    entry.writeUInt32LE(offset, 42);
    local.push(head, name, packed);
    central.push(entry, name);
    offset += head.length + name.length + packed.length;
  }
  const centralSize = central.reduce((n, b) => n + b.length, 0);
  const end = Buffer.alloc(22);
  end.writeUInt32LE(0x06054b50, 0);
  end.writeUInt16LE(files.length, 8);
  end.writeUInt16LE(files.length, 10);
  end.writeUInt32LE(centralSize, 12);
  end.writeUInt32LE(offset, 16);
  return Buffer.concat([...local, ...central, end]);
}
