/**
 * ADR-004 §D1 — Tool interface.
 *
 * Every MCP tool is a `Tool<I, O>` value produced by `defineTool`. The
 * registry (`src/registry.ts`) collects them and a single place in
 * `src/server.ts` forwards each one to the MCP SDK. Adding a tool =
 * creating one file under `src/tools/<category>/` and exporting it.
 */

import type { ZodSchema } from "zod";

export type ToolStability = "stable" | "experimental" | "deprecated";

/**
 * v2 catalog (orthogonal namespaces). Each tool's `name` is also
 * dot-prefixed with the same value (e.g. `tags` lives under category
 * "tags", `node.expand` under "node"). The MCP SDK accepts dotted
 * tool names; this enum is the bookkeeping fence so a stray tool
 * doesn't end up with the wrong family in `tools/list`.
 */
export type ToolCategory =
  | "session"
  | "graph"
  | "node"
  | "hunt"
  | "catalog"
  | "tags"
  | "notes"
  | "scores"
  | "review"
  | "ingest"
  | "sentinel"
  | "enrich"
  | "export"
  | "publish";

export interface DeprecationNotice {
  readonly since: string;
  readonly replacement?: string;
}

export interface Logger {
  info(message: string, detail?: Record<string, unknown>): void;
  warn(message: string, detail?: Record<string, unknown>): void;
  error(message: string, detail?: Record<string, unknown>): void;
  tool(message: string, detail?: Record<string, unknown>): void;
  api(message: string, detail?: Record<string, unknown>): void;
}

export interface ApiClient {
  get(path: string, params?: Record<string, string>, timeoutMs?: number): Promise<unknown>;
  post(path: string, body: unknown, timeoutMs?: number): Promise<unknown>;
}

export interface ToolContext {
  readonly api: ApiClient;
  readonly logger: Logger;
  readonly requestId: string;
}

/**
 * How the tool's return value is rendered back to the MCP client.
 *
 * - `"json"` (default): run through `safeJsonContent` (sanitize + pretty-
 *   print + truncate to the LLM budget).
 * - `"text"`: the tool's `execute` returns a string; the server wraps
 *   it in `textContent` verbatim. Use for export tools that already
 *   render CSV/JSON/NDJSON/YAML themselves.
 */
export type ResultFormat = "json" | "text";

export interface Tool<I = unknown, O = unknown> {
  readonly name: string;
  readonly description: string;
  readonly category: ToolCategory;
  readonly version: number;
  readonly stability: ToolStability;
  readonly inputSchema: ZodSchema<I>;
  readonly outputSchema: ZodSchema<O>;
  readonly deprecated?: DeprecationNotice;
  readonly resultFormat?: ResultFormat;

  execute(ctx: ToolContext, input: I): Promise<O>;
}

export function defineTool<I, O>(def: Tool<I, O>): Tool<I, O> {
  return def;
}
