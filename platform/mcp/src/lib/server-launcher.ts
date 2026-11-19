/**
 * Starts `graph-hunter-server` (the headless API) when nothing is
 * listening yet, so an MCP client can run a whole hunt without the
 * desktop app open.
 *
 * Opt-in: only when `GRAPHHUNTER_SERVER_BIN` points at the binary. An
 * API that already answers at `baseUrl` (the desktop app, or a server
 * someone else started) is always used as is — two processes would
 * otherwise hold two different in-memory graphs.
 *
 * The child's stdout/stderr go to our logger (stderr). They must never
 * reach our stdout, which carries the MCP stdio protocol.
 */

import { spawn, type ChildProcess } from "node:child_process";
import { randomUUID } from "node:crypto";
import { existsSync } from "node:fs";
import { createServer } from "node:net";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import type { Logger } from "./types.js";

export interface LaunchConfig {
  baseUrl: string;
  /** Token from the environment; empty when the operator set none. */
  token: string;
  /** Path to `graph-hunter-server`; empty disables launching. */
  serverBin: string;
  logger: Logger;
  /** How long to wait for the server to answer `/health`. */
  startupTimeoutMs?: number;
}

export interface LaunchResult {
  /** Token every API call must send. */
  token: string;
  /** True when this process started (and owns) the server. */
  launched: boolean;
}

const PROBE_TIMEOUT_MS = 1_500;
const DEFAULT_STARTUP_TIMEOUT_MS = 20_000;

async function isHealthy(baseUrl: string): Promise<boolean> {
  const ctl = new AbortController();
  const timer = setTimeout(() => ctl.abort(), PROBE_TIMEOUT_MS);
  try {
    const res = await fetch(new URL("/health", baseUrl), { signal: ctl.signal });
    return res.ok;
  } catch {
    return false;
  } finally {
    clearTimeout(timer);
  }
}

function forwardLines(stream: NodeJS.ReadableStream | null, logger: Logger): void {
  if (!stream) return;
  let pending = "";
  stream.setEncoding("utf8");
  stream.on("data", (chunk: string) => {
    pending += chunk;
    const lines = pending.split(/\r?\n/);
    pending = lines.pop() ?? "";
    for (const line of lines) {
      // The server echoes a token it generated itself. It never does
      // when we pass one, but a token must not reach a log either way.
      if (line && !line.startsWith("GRAPHHUNTER_API_TOKEN=")) logger.info("[server] " + line);
    }
  });
}

/**
 * `graph-hunter-server` shipped next to this MCP server, if any. The
 * packaged bundle puts it in `bin/` beside the entry file's directory
 * (`server/index.mjs` -> `bin/`); a repo build has none and returns "".
 */
export function findBundledServer(entryUrl: string): string {
  const exe = process.platform === "win32" ? "graph-hunter-server.exe" : "graph-hunter-server";
  const here = dirname(fileURLToPath(entryUrl));
  for (const dir of [join(here, "..", "bin"), join(here, "bin")]) {
    const candidate = join(dir, exe);
    if (existsSync(candidate)) return candidate;
  }
  return "";
}

/** A TCP port nobody is listening on right now, on loopback. */
export function freePort(): Promise<number> {
  return new Promise((resolve, reject) => {
    const probe = createServer();
    probe.once("error", reject);
    probe.listen(0, "127.0.0.1", () => {
      const address = probe.address();
      const port = typeof address === "object" && address ? address.port : 0;
      probe.close(() => (port ? resolve(port) : reject(new Error("no free port"))));
    });
  });
}

export async function ensureServer(cfg: LaunchConfig): Promise<LaunchResult> {
  if (await isHealthy(cfg.baseUrl)) {
    return { token: cfg.token, launched: false };
  }
  if (!cfg.serverBin) {
    // Nothing to start. Tools will report the API as unreachable.
    return { token: cfg.token, launched: false };
  }

  const url = new URL(cfg.baseUrl);
  const token = cfg.token || randomUUID();
  const env: NodeJS.ProcessEnv = { ...process.env, GRAPHHUNTER_API_TOKEN: token };
  if (url.port) env.GRAPHHUNTER_API_PORT = url.port;

  cfg.logger.info("starting graph-hunter-server", { bin: cfg.serverBin, port: url.port || "default" });
  // stdin is a pipe we never write to: the server exits when it closes,
  // which the OS does for us if this process is killed outright. The
  // handlers below cover the orderly exits; this covers the rest.
  const child: ChildProcess = spawn(cfg.serverBin, ["--exit-with-stdin"], {
    env,
    stdio: ["pipe", "pipe", "pipe"],
    windowsHide: true,
  });
  forwardLines(child.stdout, cfg.logger);
  forwardLines(child.stderr, cfg.logger);

  let exited: string | null = null;
  child.once("error", (e) => {
    exited = `could not start: ${e.message}`;
  });
  child.once("exit", (code, signal) => {
    exited = `exited (${signal ?? code})`;
  });

  // The server lives exactly as long as this MCP process.
  const stop = (): void => {
    if (child.exitCode === null && !child.killed) child.kill();
  };
  process.once("exit", stop);
  for (const sig of ["SIGINT", "SIGTERM"] as const) {
    process.once(sig, () => {
      stop();
      process.exit(0);
    });
  }
  // The client closing our stdin is how a stdio MCP server is told to go.
  process.stdin.once("end", () => {
    stop();
    process.exit(0);
  });

  const deadline = Date.now() + (cfg.startupTimeoutMs ?? DEFAULT_STARTUP_TIMEOUT_MS);
  while (Date.now() < deadline) {
    if (exited) throw new Error(`graph-hunter-server ${exited}`);
    if (await isHealthy(cfg.baseUrl)) {
      cfg.logger.info("graph-hunter-server is up");
      return { token, launched: true };
    }
    await new Promise((r) => setTimeout(r, 250));
  }
  stop();
  throw new Error(`graph-hunter-server did not answer ${cfg.baseUrl}/health in time`);
}
