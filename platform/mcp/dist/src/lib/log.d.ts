/**
 * Structured stderr logger. Stdout is reserved for the MCP protocol.
 * Ported from `graph-hunter-mcp/src/index.ts` log() without behavioral
 * changes — same prefix, same JSON tail, same levels.
 */
import type { Logger } from "./types.js";
export declare function createLogger(): Logger;
export declare function truncate(s: string, maxLen?: number): string;
//# sourceMappingURL=log.d.ts.map