#!/usr/bin/env node
/**
 * GraphHunter MCP Server
 *
 * Exposes graph operations as MCP tools so AI assistants (e.g. Cursor, OpenAI)
 * can explore the graph to find malicious or suspicious paths.
 *
 * Requires GraphHunter desktop app to be running with a session loaded.
 * The app exposes an HTTP API on port 37891 (or GRAPHHUNTER_API_PORT).
 */

import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { z } from "zod";

const API_BASE =
  process.env.GRAPHHUNTER_API_URL || "http://127.0.0.1:37891";

/** Bearer token for API auth. GraphHunter app prints GRAPHHUNTER_API_TOKEN=... at startup. */
const API_TOKEN = process.env.GRAPHHUNTER_API_TOKEN || "";

const API_TIMEOUT_MS = 8000;

const LOG_PREFIX = "[graph-hunter-mcp]";
const DEBUG = process.env.GRAPHHUNTER_MCP_DEBUG === "1" || process.env.GRAPHHUNTER_MCP_DEBUG === "true";

/** Log to stderr so it appears in MCP/activity logs; stdout is used for the protocol. */
function log(level: "info" | "tool" | "api" | "error", message: string, detail?: Record<string, unknown>): void {
  const ts = new Date().toISOString();
  const detailStr = detail && Object.keys(detail).length > 0 ? ` ${JSON.stringify(detail)}` : "";
  const line = `${LOG_PREFIX} [${ts}] [${level}] ${message}${detailStr}\n`;
  process.stderr.write(line);
}

/** Summarize result for activity log (entity count, path count, etc.). */
function summarizeResult(tool: string, result: unknown): string {
  if (result == null) return "ok";
  const o = result as Record<string, unknown>;
  if (Array.isArray(o)) return `count=${o.length}`;
  if (typeof o === "object") {
    if (typeof o.entity_types === "object" && Array.isArray(o.entity_types)) return `types=${(o.entity_types as unknown[]).length}`;
    if (typeof o.entities === "object" && Array.isArray(o.entities)) return `entities=${(o.entities as unknown[]).length}`;
    if (typeof o.edges === "object" && Array.isArray(o.edges)) return `edges=${(o.edges as unknown[]).length}`;
    if (typeof o.path_count === "number") return `path_count=${o.path_count}`;
    if (typeof o.paths === "object" && Array.isArray(o.paths)) {
      const total = typeof o.total_paths === "number" ? o.total_paths : (o.paths as unknown[]).length;
      return `paths=${(o.paths as unknown[]).length} total_paths=${total}`;
    }
    if (typeof o.nodes === "object" && Array.isArray(o.nodes)) return `nodes=${(o.nodes as unknown[]).length}`;
    if (typeof o.events === "object" && Array.isArray(o.events)) return `events=${(o.events as unknown[]).length}`;
    if (typeof o.id === "string" || typeof o.content === "string") return "created";
  }
  return "ok";
}

/** Truncate long strings for safe logging. */
function truncate(s: string, maxLen = 80): string {
  if (s.length <= maxLen) return s;
  return s.slice(0, maxLen - 3) + "...";
}

const CONNECTION_ERROR_MSG =
  `GraphHunter app unreachable at ${API_BASE}. Ensure: (1) GraphHunter desktop app is running, (2) a session is loaded, (3) data has been ingested so the graph is non-empty.`;

const NOT_GRAPHHUNTER_MSG =
  `The server at ${API_BASE} responded but did not return JSON (e.g. it returned HTML). Another app may be using this port. Use only the GraphHunter desktop app on this port, or set GRAPHHUNTER_API_URL to the correct URL.`;

function fetchWithTimeout(
  url: string,
  options: RequestInit & { timeoutMs?: number } = {}
): Promise<Response> {
  const { timeoutMs = API_TIMEOUT_MS, ...fetchOptions } = options;
  const controller = new AbortController();
  const timeoutId = setTimeout(() => controller.abort(), timeoutMs);
  return fetch(url, { ...fetchOptions, signal: controller.signal }).finally(
    () => clearTimeout(timeoutId)
  );
}

/** Parse response body as JSON; if server returns HTML, throw a clear error. */
async function parseJsonResponse(res: Response): Promise<unknown> {
  const contentType = res.headers.get("content-type") ?? "";
  const text = await res.text();
  const looksLikeHtml =
    contentType.toLowerCase().includes("text/html") ||
    text.trim().toLowerCase().startsWith("<!");
  if (looksLikeHtml) {
    throw new Error(NOT_GRAPHHUNTER_MSG);
  }
  try {
    return text ? JSON.parse(text) : {};
  } catch {
    throw new Error(NOT_GRAPHHUNTER_MSG);
  }
}

function authHeaders(): Record<string, string> {
  const h: Record<string, string> = {};
  if (API_TOKEN) h["Authorization"] = `Bearer ${API_TOKEN}`;
  return h;
}

async function apiGet(path: string, params?: Record<string, string>): Promise<unknown> {
  const url = new URL(path, API_BASE);
  if (params) {
    for (const [k, v] of Object.entries(params)) {
      if (v !== undefined && v !== "") url.searchParams.set(k, v);
    }
  }
  const start = Date.now();
  log("api", "GET " + path, params ? { params: Object.keys(params).join(",") } : undefined);
  let res: Response;
  try {
    res = await fetchWithTimeout(url.toString(), { headers: authHeaders() });
  } catch (e) {
    const msg = e instanceof Error ? e.message : String(e);
    const isAbort = msg.includes("abort") || (e instanceof Error && e.name === "AbortError");
    log("api", "GET " + path + " failed", { error: truncate(msg, 120), duration_ms: Date.now() - start });
    throw new Error(
      isAbort
        ? `${CONNECTION_ERROR_MSG} Request timed out after ${API_TIMEOUT_MS}ms.`
        : `${CONNECTION_ERROR_MSG} Network error: ${msg}`
    );
  }
  const data = await parseJsonResponse(res);
  const durationMs = Date.now() - start;
  const responseSize = DEBUG && typeof data === "object" ? JSON.stringify(data).length : undefined;
  if (!res.ok) {
    const err = data as { error?: string };
    const msg = err?.error ?? res.statusText;
    log("api", "GET " + path + " error", { status: res.status, message: truncate(String(msg), 100), duration_ms: durationMs });
    throw new Error(`${res.status} ${res.statusText}: ${msg}`);
  }
  log("api", "GET " + path + " ok", { status: res.status, duration_ms: durationMs, ...(responseSize != null ? { response_bytes: responseSize } : {}) });
  return data;
}

async function apiPost(path: string, body: unknown): Promise<unknown> {
  const url = new URL(path, API_BASE);
  const start = Date.now();
  const bodySummary =
    body && typeof body === "object" && !Array.isArray(body)
      ? Object.fromEntries(
          Object.entries(body).map(([k, v]) => [k, Array.isArray(v) ? `[${v.length}]` : truncate(String(v), 40)])
        )
      : {};
  log("api", "POST " + path, bodySummary);
  let res: Response;
  const headers: Record<string, string> = { "Content-Type": "application/json", ...authHeaders() };
  try {
    res = await fetchWithTimeout(url.toString(), {
      method: "POST",
      headers,
      body: JSON.stringify(body),
      timeoutMs: API_TIMEOUT_MS,
    });
  } catch (e) {
    const msg = e instanceof Error ? e.message : String(e);
    const isAbort = msg.includes("abort") || (e instanceof Error && e.name === "AbortError");
    log("api", "POST " + path + " failed", { error: truncate(msg, 120), duration_ms: Date.now() - start });
    throw new Error(
      isAbort
        ? `${CONNECTION_ERROR_MSG} Request timed out after ${API_TIMEOUT_MS}ms.`
        : `${CONNECTION_ERROR_MSG} Network error: ${msg}`
    );
  }
  const data = await parseJsonResponse(res);
  const durationMs = Date.now() - start;
  const responseSize = DEBUG && typeof data === "object" ? JSON.stringify(data).length : undefined;
  if (!res.ok) {
    const err = data as { error?: string };
    const msg = err?.error ?? res.statusText;
    log("api", "POST " + path + " error", { status: res.status, message: truncate(String(msg), 100), duration_ms: durationMs });
    throw new Error(`${res.status} ${res.statusText}: ${msg}`);
  }
  log("api", "POST " + path + " ok", { status: res.status, duration_ms: durationMs, ...(responseSize != null ? { response_bytes: responseSize } : {}) });
  return data;
}

function textContent(text: string) {
  return { content: [{ type: "text" as const, text }] };
}

const server = new McpServer({
  name: "graph-hunter-mcp",
  version: "1.0.0",
});

// check_connection – verify app is running and optionally if a session is loaded (no session required)
server.tool(
  "check_connection",
  "Check if the GraphHunter desktop app is reachable and whether a session is loaded. Call this first before other tools to avoid timeouts or unclear errors.",
  async () => {
    const start = Date.now();
    log("tool", "check_connection", {});
    try {
      const v = await apiGet("/health");
      const summary = typeof v === "object" && v !== null && "session_loaded" in v ? { session_loaded: (v as { session_loaded?: boolean }).session_loaded } : {};
      log("tool", "check_connection done", { duration_ms: Date.now() - start, ...summary });
      return textContent(JSON.stringify(v, null, 2));
    } catch (e) {
      const msg = e instanceof Error ? e.message : String(e);
      log("tool", "check_connection error", { duration_ms: Date.now() - start, error: truncate(msg, 200) });
      return textContent(msg);
    }
  }
);

// get_entity_types – entity types present in the graph
server.tool(
  "get_entity_types",
  "List entity types present in the current graph (e.g. IP, Host, User, Process).",
  async () => {
    const start = Date.now();
    log("tool", "get_entity_types", {});
    try {
      const v = await apiGet("/entity_types");
      const summaryStr = summarizeResult("get_entity_types", v);
      log("tool", "get_entity_types done", { duration_ms: Date.now() - start, result: summaryStr });
      return textContent(JSON.stringify(v, null, 2));
    } catch (e) {
      const msg = e instanceof Error ? e.message : String(e);
      log("tool", "get_entity_types error", { duration_ms: Date.now() - start, error: truncate(msg, 200) });
      return textContent(msg);
    }
  }
);

// search_entities – search by query and optional type filter
server.tool(
  "search_entities",
  "Search entities by substring. Use to find nodes by ID, name, or metadata. Optional type filter (e.g. IP, Host).",
  {
    q: z.string().describe("Search query (substring match)"),
    type: z.string().optional().describe("Optional entity type filter"),
    limit: z.number().optional().describe("Max results (default 50)"),
  },
  async ({ q, type, limit }) => {
    const start = Date.now();
    log("tool", "search_entities", { q: truncate(q, 60), type: type ?? "-", limit: limit ?? "-" });
    try {
      const params: Record<string, string> = { q };
      if (type) params.type = type;
      if (limit != null) params.limit = String(limit);
      const v = await apiGet("/search", params);
      const summaryStr = summarizeResult("search_entities", v);
      log("tool", "search_entities done", { duration_ms: Date.now() - start, result: summaryStr });
      return textContent(JSON.stringify(v, null, 2));
    } catch (e) {
      const msg = e instanceof Error ? e.message : String(e);
      log("tool", "search_entities error", { duration_ms: Date.now() - start, error: truncate(msg, 200) });
      return textContent(msg);
    }
  }
);

// expand_node – get neighborhood (nodes and edges) from a starting node
server.tool(
  "expand_node",
  "Expand from a node to get its neighbors (nodes and edges). Use to explore the graph from a starting node and find suspicious paths.",
  {
    node_id: z.string().describe("Entity ID to expand from"),
    max_hops: z.number().optional().describe("Max hops (default 1)"),
    max_nodes: z.number().optional().describe("Max nodes in result (default 50)"),
  },
  async ({ node_id, max_hops, max_nodes }) => {
    const start = Date.now();
    log("tool", "expand_node", { node_id: truncate(node_id, 50), max_hops: max_hops ?? 1, max_nodes: max_nodes ?? "-" });
    try {
      const params: Record<string, string> = { node_id };
      if (max_hops != null) params.max_hops = String(max_hops);
      if (max_nodes != null) params.max_nodes = String(max_nodes);
      const v = await apiGet("/expand", params);
      const summaryStr = summarizeResult("expand_node", v);
      log("tool", "expand_node done", { duration_ms: Date.now() - start, result: summaryStr });
      return textContent(JSON.stringify(v, null, 2));
    } catch (e) {
      const msg = e instanceof Error ? e.message : String(e);
      log("tool", "expand_node error", { duration_ms: Date.now() - start, error: truncate(msg, 200) });
      return textContent(msg);
    }
  }
);

// get_node_details – full details for one node (scores, degrees, neighbors)
server.tool(
  "get_node_details",
  "Get detailed information about a node: scores, degrees, neighbor counts, time range.",
  {
    node_id: z.string().describe("Entity ID"),
  },
  async ({ node_id }) => {
    const start = Date.now();
    log("tool", "get_node_details", { node_id: truncate(node_id, 50) });
    try {
      const v = await apiGet("/node_details", { node_id });
      log("tool", "get_node_details done", { duration_ms: Date.now() - start, result: "ok" });
      return textContent(JSON.stringify(v, null, 2));
    } catch (e) {
      const msg = e instanceof Error ? e.message : String(e);
      log("tool", "get_node_details error", { duration_ms: Date.now() - start, error: truncate(msg, 200) });
      return textContent(msg);
    }
  }
);

// get_subgraph – nodes and edges for a set of node IDs
server.tool(
  "get_subgraph",
  "Get the subgraph (nodes and edges) for a list of node IDs.",
  {
    node_ids: z.array(z.string()).describe("List of entity IDs"),
  },
  async ({ node_ids }) => {
    const start = Date.now();
    log("tool", "get_subgraph", { node_count: node_ids.length });
    try {
      const v = await apiPost("/subgraph", { node_ids });
      const summaryStr = summarizeResult("get_subgraph", v);
      log("tool", "get_subgraph done", { duration_ms: Date.now() - start, result: summaryStr });
      return textContent(JSON.stringify(v, null, 2));
    } catch (e) {
      const msg = e instanceof Error ? e.message : String(e);
      log("tool", "get_subgraph error", { duration_ms: Date.now() - start, error: truncate(msg, 200) });
      return textContent(msg);
    }
  }
);

// get_events_for_node – all edges (events) where the node is source or target
server.tool(
  "get_events_for_node",
  "Get all relations/events for a node (incoming and outgoing edges).",
  {
    node_id: z.string().describe("Entity ID"),
  },
  async ({ node_id }) => {
    const start = Date.now();
    log("tool", "get_events_for_node", { node_id: truncate(node_id, 50) });
    try {
      const v = await apiGet("/events_for_node", { node_id });
      const summaryStr = summarizeResult("get_events_for_node", v);
      log("tool", "get_events_for_node done", { duration_ms: Date.now() - start, result: summaryStr });
      return textContent(JSON.stringify(v, null, 2));
    } catch (e) {
      const msg = e instanceof Error ? e.message : String(e);
      log("tool", "get_events_for_node error", { duration_ms: Date.now() - start, error: truncate(msg, 200) });
      return textContent(msg);
    }
  }
);

// run_hunt – run a hypothesis (DSL) and return path count
server.tool(
  "run_hunt",
  "Run a threat-hunting hypothesis. Pass a DSL chain like 'IP -[Connect]-> Host -[Execute]-> Process'. Returns path count and whether results were truncated. After running, use get_hunt_results to retrieve paths with scores (structural scores always; anomaly and GNN threat when scoring is enabled).",
  {
    hypothesis_dsl: z
      .string()
      .describe(
        "Hypothesis in DSL form, e.g. 'IP -[Connect]-> Host -[Auth]-> User -[Execute]-> Process'"
      ),
  },
  async ({ hypothesis_dsl }) => {
    const start = Date.now();
    log("tool", "run_hunt", { hypothesis_dsl: truncate(hypothesis_dsl, 80) });
    try {
      const v = await apiPost("/run_hunt", { hypothesis_dsl });
      const summaryStr = summarizeResult("run_hunt", v);
      log("tool", "run_hunt done", { duration_ms: Date.now() - start, result: summaryStr });
      return textContent(JSON.stringify(v, null, 2));
    } catch (e) {
      const msg = e instanceof Error ? e.message : String(e);
      log("tool", "run_hunt error", { duration_ms: Date.now() - start, error: truncate(msg, 200) });
      return textContent(msg);
    }
  }
);

// get_hunt_results – one page of last run_hunt results with scores
server.tool(
  "get_hunt_results",
  "Get one page of the last run_hunt results. When anomaly scoring is enabled, paths include anomaly_score and anomaly_breakdown (including gnn_threat) and are sorted by anomaly (highest first). When scoring is not enabled, paths still include max_score and total_score (structural scores) and are sorted by those; anomaly_score and anomaly_breakdown will be null/absent. Use total_paths and filtered_paths in the response to decide whether to fetch more pages (higher page or larger page_size). Call run_hunt first.",
  {
    page: z.number().optional().default(0).describe("Page index (0-based)."),
    page_size: z.number().optional().default(20).describe("Number of paths per page."),
    min_score: z.number().optional().describe("Filter paths by max node score (0–100)."),
  },
  async ({ page, page_size, min_score }) => {
    const start = Date.now();
    log("tool", "get_hunt_results", { page, page_size, min_score: min_score ?? "-" });
    try {
      const params: Record<string, string> = {
        page: String(page),
        page_size: String(page_size),
      };
      if (min_score != null && !Number.isNaN(min_score)) params.min_score = String(min_score);
      const v = await apiGet("/hunt_results", params);
      const summaryStr = summarizeResult("get_hunt_results", v);
      log("tool", "get_hunt_results done", { duration_ms: Date.now() - start, result: summaryStr });
      return textContent(JSON.stringify(v, null, 2));
    } catch (e) {
      const msg = e instanceof Error ? e.message : String(e);
      log("tool", "get_hunt_results error", { duration_ms: Date.now() - start, error: truncate(msg, 200) });
      return textContent(msg);
    }
  }
);

// create_note – add a note to the current session (e.g. hunt report)
server.tool(
  "create_note",
  "Add a note to the current GraphHunter session. Use for saving hunt reports or findings. Optional node_id links the note to a graph node.",
  {
    content: z.string().describe("Note content (e.g. markdown or plain text report)."),
    node_id: z
      .string()
      .optional()
      .describe("Optional entity/node ID to link this note to."),
  },
  async ({ content, node_id }) => {
    const start = Date.now();
    log("tool", "create_note", { content_len: content.length, node_id: node_id ?? "-" });
    try {
      const v = await apiPost("/notes", { content, node_id: node_id ?? undefined });
      log("tool", "create_note done", { duration_ms: Date.now() - start, result: "created" });
      return textContent(JSON.stringify(v, null, 2));
    } catch (e) {
      const msg = e instanceof Error ? e.message : String(e);
      log("tool", "create_note error", { duration_ms: Date.now() - start, error: truncate(msg, 200) });
      return textContent(msg);
    }
  }
);

async function main() {
  log("info", "GraphHunter MCP server starting", {
    name: "graph-hunter-mcp",
    version: "1.0.0",
    api_base: API_BASE,
    debug: DEBUG,
  });
  const transport = new StdioServerTransport();
  await server.connect(transport);
  log("info", "GraphHunter MCP server connected (stdio transport ready)");
}

main().catch((err) => {
  log("error", "Fatal server error", { error: err instanceof Error ? err.message : String(err) });
  process.stderr.write((err instanceof Error ? err.stack : String(err)) + "\n");
  process.exit(1);
});
