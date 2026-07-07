/**
 * Structured stderr logger. Stdout is reserved for the MCP protocol.
 * Ported from `graph-hunter-mcp/src/index.ts` log() without behavioral
 * changes — same prefix, same JSON tail, same levels.
 */

import type { Logger } from "./types.js";

const LOG_PREFIX = "[graph-hunter-mcp]";

export function createLogger(): Logger {
  const write = (level: string, message: string, detail?: Record<string, unknown>): void => {
    const ts = new Date().toISOString();
    const detailStr =
      detail && Object.keys(detail).length > 0 ? ` ${JSON.stringify(detail)}` : "";
    process.stderr.write(`${LOG_PREFIX} [${ts}] [${level}] ${message}${detailStr}\n`);
  };
  return {
    info: (m, d) => write("info", m, d),
    warn: (m, d) => write("warn", m, d),
    error: (m, d) => write("error", m, d),
    tool: (m, d) => write("tool", m, d),
    api: (m, d) => write("api", m, d),
  };
}

export function truncate(s: string, maxLen = 80): string {
  if (s.length <= maxLen) return s;
  return s.slice(0, maxLen - 3) + "...";
}
