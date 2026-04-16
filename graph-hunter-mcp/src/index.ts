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

const API_TIMEOUT_MS = 30_000;

/** Extended timeout for graph operations that may touch high-degree nodes (1M+ edges). */
const HEAVY_TIMEOUT_MS = 120_000;

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

async function apiGet(path: string, params?: Record<string, string>, timeoutMs?: number): Promise<unknown> {
  const effectiveTimeout = timeoutMs ?? API_TIMEOUT_MS;
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
    res = await fetchWithTimeout(url.toString(), { headers: authHeaders(), timeoutMs: effectiveTimeout });
  } catch (e) {
    const msg = e instanceof Error ? e.message : String(e);
    const isAbort = msg.includes("abort") || (e instanceof Error && e.name === "AbortError");
    log("api", "GET " + path + " failed", { error: truncate(msg, 120), duration_ms: Date.now() - start });
    throw new Error(
      isAbort
        ? `${CONNECTION_ERROR_MSG} Request timed out after ${effectiveTimeout}ms.`
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

async function apiPost(path: string, body: unknown, timeoutMs?: number): Promise<unknown> {
  const effectiveTimeout = timeoutMs ?? API_TIMEOUT_MS;
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
      timeoutMs: effectiveTimeout,
    });
  } catch (e) {
    const msg = e instanceof Error ? e.message : String(e);
    const isAbort = msg.includes("abort") || (e instanceof Error && e.name === "AbortError");
    log("api", "POST " + path + " failed", { error: truncate(msg, 120), duration_ms: Date.now() - start });
    throw new Error(
      isAbort
        ? `${CONNECTION_ERROR_MSG} Request timed out after ${effectiveTimeout}ms.`
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

// ── Response sanitization for large datasets ──────────────────────────
// LLM context windows are finite (~128K tokens). Raw API responses with
// 10K+ nodes or events can easily produce 50MB of JSON. These helpers
// ensure every tool response stays within a budget that fits comfortably
// in context while still giving the LLM useful, actionable data.

/** Hard cap on text returned to the LLM (characters). ~25K tokens. */
const MAX_RESPONSE_CHARS = 100_000;

/** Max items in any array before we truncate and summarize. */
const MAX_ARRAY_ITEMS = 100;

/** Max length for individual metadata string values. */
const MAX_METADATA_VALUE_LEN = 200;

/** Truncate a metadata value, preserving start + end for readability. */
function truncateValue(v: unknown): unknown {
  if (typeof v === "string" && v.length > MAX_METADATA_VALUE_LEN) {
    return v.slice(0, MAX_METADATA_VALUE_LEN - 20) + " ... " + v.slice(-15);
  }
  if (Array.isArray(v)) return v.slice(0, 20).map(truncateValue);
  if (v && typeof v === "object") return sanitizeObject(v as Record<string, unknown>);
  return v;
}

/** Recursively sanitize an object: truncate long strings, cap arrays. */
function sanitizeObject(obj: Record<string, unknown>): Record<string, unknown> {
  const result: Record<string, unknown> = {};
  for (const [key, val] of Object.entries(obj)) {
    if (val && typeof val === "object" && !Array.isArray(val)) {
      result[key] = sanitizeObject(val as Record<string, unknown>);
    } else {
      result[key] = truncateValue(val);
    }
  }
  return result;
}

/**
 * Sanitize an API response for LLM consumption:
 * - Cap known collection fields (nodes, edges, events, paths, entities) to MAX_ARRAY_ITEMS
 * - Truncate metadata string values
 * - Add _truncated summary when data was clipped
 */
function sanitizeApiResponse(data: unknown): unknown {
  if (data == null || typeof data !== "object") return data;
  if (Array.isArray(data)) {
    if (data.length <= MAX_ARRAY_ITEMS) return data.map((item) => typeof item === "object" && item ? sanitizeObject(item as Record<string, unknown>) : item);
    const truncated = data.slice(0, MAX_ARRAY_ITEMS).map((item) =>
      typeof item === "object" && item ? sanitizeObject(item as Record<string, unknown>) : item
    );
    return { _truncated: true, _total: data.length, _showing: MAX_ARRAY_ITEMS, _hint: `Showing first ${MAX_ARRAY_ITEMS} of ${data.length} items. Use pagination or filters to access the rest.`, items: truncated };
  }
  const obj = data as Record<string, unknown>;
  const result: Record<string, unknown> = {};
  const COLLECTION_KEYS = ["nodes", "edges", "events", "paths", "entities", "items", "subnets", "datasets", "notes"];
  for (const [key, val] of Object.entries(obj)) {
    if (Array.isArray(val) && COLLECTION_KEYS.includes(key)) {
      if (val.length > MAX_ARRAY_ITEMS) {
        result[`_${key}_total`] = val.length;
        result[`_${key}_truncated`] = true;
        result[key] = val.slice(0, MAX_ARRAY_ITEMS).map((item: unknown) =>
          typeof item === "object" && item ? sanitizeObject(item as Record<string, unknown>) : item
        );
      } else {
        result[key] = val.map((item: unknown) =>
          typeof item === "object" && item ? sanitizeObject(item as Record<string, unknown>) : item
        );
      }
    } else if (val && typeof val === "object" && !Array.isArray(val)) {
      result[key] = sanitizeObject(val as Record<string, unknown>);
    } else {
      result[key] = truncateValue(val);
    }
  }
  return result;
}

function textContent(text: string) {
  if (text.length <= MAX_RESPONSE_CHARS) {
    return { content: [{ type: "text" as const, text }] };
  }
  // Hard truncation with clear signal to the LLM
  const trimmed = text.slice(0, MAX_RESPONSE_CHARS - 200);
  const notice = `\n\n--- RESPONSE TRUNCATED (${text.length} chars total, showing first ${MAX_RESPONSE_CHARS - 200}). Use pagination parameters or narrower filters to get manageable results. ---`;
  return { content: [{ type: "text" as const, text: trimmed + notice }] };
}

/** Format API data as sanitized JSON text for the LLM. */
function safeJsonContent(data: unknown) {
  const sanitized = sanitizeApiResponse(data);
  return textContent(JSON.stringify(sanitized, null, 2));
}

const server = new McpServer({
  name: "graph-hunter-mcp",
  version: "1.2.0",
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
      return safeJsonContent(v);
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
      return safeJsonContent(v);
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
    q: z.string().max(1000).describe("Search query (substring match)"),
    type: z.string().max(100).optional().describe("Optional entity type filter"),
    limit: z.number().int().min(1).max(500).optional().describe("Max results (default 50)"),
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
      return safeJsonContent(v);
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
    node_id: z.string().max(500).describe("Entity ID to expand from"),
    max_hops: z.number().int().min(1).max(5).optional().describe("Max hops (default 1)"),
    max_nodes: z.number().int().min(1).max(500).optional().describe("Max nodes in result (default 50)"),
  },
  async ({ node_id, max_hops, max_nodes }) => {
    const start = Date.now();
    log("tool", "expand_node", { node_id: truncate(node_id, 50), max_hops: max_hops ?? 1, max_nodes: max_nodes ?? "-" });
    try {
      const params: Record<string, string> = { node_id };
      if (max_hops != null) params.max_hops = String(max_hops);
      if (max_nodes != null) params.max_nodes = String(max_nodes);
      const v = await apiGet("/expand", params, HEAVY_TIMEOUT_MS);
      const summaryStr = summarizeResult("expand_node", v);
      log("tool", "expand_node done", { duration_ms: Date.now() - start, result: summaryStr });
      return safeJsonContent(v);
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
    node_id: z.string().max(500).describe("Entity ID"),
  },
  async ({ node_id }) => {
    const start = Date.now();
    log("tool", "get_node_details", { node_id: truncate(node_id, 50) });
    try {
      const v = await apiGet("/node_details", { node_id }, HEAVY_TIMEOUT_MS);
      log("tool", "get_node_details done", { duration_ms: Date.now() - start, result: "ok" });
      return safeJsonContent(v);
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
    node_ids: z.array(z.string().max(500)).max(1000).describe("List of entity IDs (max 1000)"),
  },
  async ({ node_ids }) => {
    const start = Date.now();
    log("tool", "get_subgraph", { node_count: node_ids.length });
    try {
      const v = await apiPost("/subgraph", { node_ids }, HEAVY_TIMEOUT_MS);
      const summaryStr = summarizeResult("get_subgraph", v);
      log("tool", "get_subgraph done", { duration_ms: Date.now() - start, result: summaryStr });
      return safeJsonContent(v);
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
    node_id: z.string().max(500).describe("Entity ID"),
  },
  async ({ node_id }) => {
    const start = Date.now();
    log("tool", "get_events_for_node", { node_id: truncate(node_id, 50) });
    try {
      const v = await apiGet("/events_for_node", { node_id }, HEAVY_TIMEOUT_MS);
      const summaryStr = summarizeResult("get_events_for_node", v);
      log("tool", "get_events_for_node done", { duration_ms: Date.now() - start, result: summaryStr });
      return safeJsonContent(v);
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
      .max(2000)
      .describe(
        "Hypothesis in DSL form, e.g. 'IP -[Connect]-> Host -[Auth]-> User -[Execute]-> Process'"
      ),
  },
  async ({ hypothesis_dsl }) => {
    const start = Date.now();
    log("tool", "run_hunt", { hypothesis_dsl: truncate(hypothesis_dsl, 80) });
    try {
      const v = await apiPost("/run_hunt", { hypothesis_dsl }, HEAVY_TIMEOUT_MS);
      const summaryStr = summarizeResult("run_hunt", v);
      log("tool", "run_hunt done", { duration_ms: Date.now() - start, result: summaryStr });
      return safeJsonContent(v);
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
    page: z.number().int().min(0).max(10000).optional().default(0).describe("Page index (0-based)."),
    page_size: z.number().int().min(1).max(200).optional().default(20).describe("Number of paths per page."),
    min_score: z.number().min(0).max(100).optional().describe("Filter paths by max node score (0–100)."),
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
      return safeJsonContent(v);
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
    content: z.string().max(50000).describe("Note content (e.g. markdown or plain text report)."),
    node_id: z
      .string()
      .max(500)
      .optional()
      .describe("Optional entity/node ID to link this note to."),
  },
  async ({ content, node_id }) => {
    const start = Date.now();
    log("tool", "create_note", { content_len: content.length, node_id: node_id ?? "-" });
    try {
      const v = await apiPost("/notes", { content, node_id: node_id ?? undefined });
      log("tool", "create_note done", { duration_ms: Date.now() - start, result: "created" });
      return safeJsonContent(v);
    } catch (e) {
      const msg = e instanceof Error ? e.message : String(e);
      log("tool", "create_note error", { duration_ms: Date.now() - start, error: truncate(msg, 200) });
      return textContent(msg);
    }
  }
);

// ── New tools: maximize info extraction for LLMs ──

// get_graph_summary – comprehensive overview of the entire graph
server.tool(
  "get_graph_summary",
  "Get a comprehensive summary of the entire graph: entity counts, relation counts, type distribution, time range, and top anomalies. This is the best starting point for understanding what data is in the graph. Call this first to orient yourself before diving into specific entities or hunts.",
  async () => {
    const start = Date.now();
    log("tool", "get_graph_summary", {});
    try {
      const v = await apiGet("/graph_summary");
      log("tool", "get_graph_summary done", { duration_ms: Date.now() - start, result: "ok" });
      return safeJsonContent(v);
    } catch (e) {
      const msg = e instanceof Error ? e.message : String(e);
      log("tool", "get_graph_summary error", { duration_ms: Date.now() - start, error: truncate(msg, 200) });
      return textContent(msg);
    }
  }
);

// get_entity_type_counts – how many entities of each type exist
server.tool(
  "get_entity_type_counts",
  "Get the count of entities for each type (e.g. 150 IPs, 42 Hosts, 30 Users). Use to understand the composition of the graph and identify which entity types are most prevalent.",
  async () => {
    const start = Date.now();
    log("tool", "get_entity_type_counts", {});
    try {
      const v = await apiGet("/entity_type_counts");
      const summaryStr = summarizeResult("get_entity_type_counts", v);
      log("tool", "get_entity_type_counts done", { duration_ms: Date.now() - start, result: summaryStr });
      return safeJsonContent(v);
    } catch (e) {
      const msg = e instanceof Error ? e.message : String(e);
      log("tool", "get_entity_type_counts error", { duration_ms: Date.now() - start, error: truncate(msg, 200) });
      return textContent(msg);
    }
  }
);

// get_temporal_heatmap – hourly activity patterns by relation type
server.tool(
  "get_temporal_heatmap",
  "Get hourly activity patterns showing when events occur by relation type (Auth, Connect, Execute, etc.). Returns bucketed counts. Use to identify spikes, off-hours activity, or unusual temporal patterns that may indicate compromise.",
  async () => {
    const start = Date.now();
    log("tool", "get_temporal_heatmap", {});
    try {
      const v = await apiGet("/temporal_heatmap", undefined, HEAVY_TIMEOUT_MS);
      const summaryStr = summarizeResult("get_temporal_heatmap", v);
      log("tool", "get_temporal_heatmap done", { duration_ms: Date.now() - start, result: summaryStr });
      return safeJsonContent(v);
    } catch (e) {
      const msg = e instanceof Error ? e.message : String(e);
      log("tool", "get_temporal_heatmap error", { duration_ms: Date.now() - start, error: truncate(msg, 200) });
      return textContent(msg);
    }
  }
);

// get_subnet_analysis – group IPs by /24 subnet
server.tool(
  "get_subnet_analysis",
  "Analyze IP entities by /24 subnet: groups all IPs in the graph by their network segment, shows whether each subnet is internal or external, aggregates byte counts, and lists connected services. Use to identify which network segments are most active, detect lateral movement within subnets, or find unusual external destinations.",
  async () => {
    const start = Date.now();
    log("tool", "get_subnet_analysis", {});
    try {
      const v = await apiGet("/subnet_analysis", undefined, HEAVY_TIMEOUT_MS);
      const summaryStr = summarizeResult("get_subnet_analysis", v);
      log("tool", "get_subnet_analysis done", { duration_ms: Date.now() - start, result: summaryStr });
      return safeJsonContent(v);
    } catch (e) {
      const msg = e instanceof Error ? e.message : String(e);
      log("tool", "get_subnet_analysis error", { duration_ms: Date.now() - start, error: truncate(msg, 200) });
      return textContent(msg);
    }
  }
);

// enrich_ip – GeoIP enrichment for external IPs
server.tool(
  "enrich_ip",
  "Enrich a public/external IP address with GeoIP data: country, city, ASN, ISP/organization. Only works for public IPs (returns error for private/internal IPs). The enrichment data is persisted on the entity's metadata, so subsequent get_node_details calls will include it. Use to identify where external connections go (country, ISP) for threat analysis.",
  {
    ip: z.string().max(45).describe("Public IP address to enrich (e.g. '8.8.8.8')"),
  },
  async ({ ip }) => {
    const start = Date.now();
    log("tool", "enrich_ip", { ip });
    try {
      const v = await apiPost("/enrich_ip", { ip });
      log("tool", "enrich_ip done", { duration_ms: Date.now() - start, result: "ok" });
      return safeJsonContent(v);
    } catch (e) {
      const msg = e instanceof Error ? e.message : String(e);
      log("tool", "enrich_ip error", { duration_ms: Date.now() - start, error: truncate(msg, 200) });
      return textContent(msg);
    }
  }
);

// get_catalog – available ATT&CK hypothesis patterns
server.tool(
  "get_catalog",
  "Get the catalog of pre-built threat-hunting hypotheses based on MITRE ATT&CK techniques. Each entry has an id, name, description, and DSL pattern that can be passed to run_hunt. Use this to discover what hunt patterns are available and find the right hypothesis for a given threat scenario.",
  async () => {
    const start = Date.now();
    log("tool", "get_catalog", {});
    try {
      const v = await apiGet("/catalog");
      const summaryStr = summarizeResult("get_catalog", v);
      log("tool", "get_catalog done", { duration_ms: Date.now() - start, result: summaryStr });
      return safeJsonContent(v);
    } catch (e) {
      const msg = e instanceof Error ? e.message : String(e);
      log("tool", "get_catalog error", { duration_ms: Date.now() - start, error: truncate(msg, 200) });
      return textContent(msg);
    }
  }
);

// list_datasets – loaded data sources
server.tool(
  "list_datasets",
  "List all ingested datasets in the current session. Each dataset represents a data source (e.g. a log file or SIEM query) with its name, file path, entity/relation counts, and timestamp. Use to understand what data is available for analysis and where it came from.",
  async () => {
    const start = Date.now();
    log("tool", "list_datasets", {});
    try {
      const v = await apiGet("/datasets");
      const summaryStr = summarizeResult("list_datasets", v);
      log("tool", "list_datasets done", { duration_ms: Date.now() - start, result: summaryStr });
      return safeJsonContent(v);
    } catch (e) {
      const msg = e instanceof Error ? e.message : String(e);
      log("tool", "list_datasets error", { duration_ms: Date.now() - start, error: truncate(msg, 200) });
      return textContent(msg);
    }
  }
);

// get_path_nodes – pinned investigation nodes
server.tool(
  "get_path_nodes",
  "Get the list of pinned 'path nodes' in the current session. Path nodes are entities marked by the analyst as important to the investigation — they serve as waypoints in the threat hunting workflow. Use to understand the current investigation focus.",
  async () => {
    const start = Date.now();
    log("tool", "get_path_nodes", {});
    try {
      const v = await apiGet("/path_nodes");
      const summaryStr = summarizeResult("get_path_nodes", v);
      log("tool", "get_path_nodes done", { duration_ms: Date.now() - start, result: summaryStr });
      return safeJsonContent(v);
    } catch (e) {
      const msg = e instanceof Error ? e.message : String(e);
      log("tool", "get_path_nodes error", { duration_ms: Date.now() - start, error: truncate(msg, 200) });
      return textContent(msg);
    }
  }
);

// get_notes – all session notes
server.tool(
  "get_notes",
  "Get all notes in the current session. Notes are analyst observations, findings, or reports — optionally linked to specific graph nodes. Use to read the analyst's existing findings and build on their investigation.",
  async () => {
    const start = Date.now();
    log("tool", "get_notes", {});
    try {
      const v = await apiGet("/notes/list");
      const summaryStr = summarizeResult("get_notes", v);
      log("tool", "get_notes done", { duration_ms: Date.now() - start, result: summaryStr });
      return safeJsonContent(v);
    } catch (e) {
      const msg = e instanceof Error ? e.message : String(e);
      log("tool", "get_notes error", { duration_ms: Date.now() - start, error: truncate(msg, 200) });
      return textContent(msg);
    }
  }
);

// export_subgraph – export subgraph as JSON or CSV text
server.tool(
  "export_subgraph",
  "Export the subgraph (nodes + edges) for given node IDs as JSON or CSV text. Use when you need the raw data for a set of entities — for example, to produce a detailed report of a suspicious path, or to analyze entity metadata in bulk.",
  {
    node_ids: z.array(z.string().max(500)).max(1000).describe("List of entity IDs to include in the export (max 1000)"),
    format: z.enum(["json", "csv"]).optional().default("json").describe("Export format: 'json' or 'csv'"),
  },
  async ({ node_ids, format }) => {
    const start = Date.now();
    log("tool", "export_subgraph", { node_count: node_ids.length, format });
    try {
      const v = await apiPost("/export_subgraph", { node_ids, format }, HEAVY_TIMEOUT_MS) as { data: string; format: string };
      log("tool", "export_subgraph done", { duration_ms: Date.now() - start, result: `format=${v.format} len=${v.data.length}` });
      return textContent(v.data);
    } catch (e) {
      const msg = e instanceof Error ? e.message : String(e);
      log("tool", "export_subgraph error", { duration_ms: Date.now() - start, error: truncate(msg, 200) });
      return textContent(msg);
    }
  }
);

// ── Phase 2: Complete MCP coverage (6 new tools) ──

// parse_dsl – validate DSL before executing hunt
server.tool(
  "parse_dsl",
  "Validate a hunt hypothesis DSL pattern WITHOUT executing it. Returns whether the DSL is valid, the formatted version, and step count. Use BEFORE run_hunt to catch syntax errors cheaply. DSL syntax: 'EntityType -[RelationType]-> EntityType -[RelationType]-> EntityType'. Example: 'IP -[Connect]-> Host -[Auth]-> User -[Execute]-> Process'.",
  {
    dsl: z.string().max(2000).describe("DSL pattern to validate, e.g. 'IP -[Connect]-> Host -[Execute]-> Process'"),
    name: z.string().max(200).optional().describe("Optional name for the hypothesis"),
  },
  async ({ dsl, name }) => {
    const start = Date.now();
    log("tool", "parse_dsl", { dsl: truncate(dsl, 80), name: name ?? "-" });
    try {
      const v = await apiPost("/parse_dsl", { dsl, name });
      const result = v as { valid: boolean; formatted?: string; error?: string };
      log("tool", "parse_dsl done", { duration_ms: Date.now() - start, valid: result.valid });
      return safeJsonContent(v);
    } catch (e) {
      const msg = e instanceof Error ? e.message : String(e);
      log("tool", "parse_dsl error", { duration_ms: Date.now() - start, error: truncate(msg, 200) });
      return textContent(msg);
    }
  }
);

// get_events_paginated – paginated, sortable events for a node
server.tool(
  "get_events_paginated",
  "Get paginated and sortable events (relations/edges) for a node. Returns events where the node is source or target. Supports sort_by: 'timestamp' (chronological order), 'rel_type', 'source', 'target'. Returns total_count for pagination. Better than get_events_for_node when the node has many connections.",
  {
    node_id: z.string().max(500).describe("Entity ID to get events for"),
    page: z.number().int().min(0).max(10000).optional().default(0).describe("Page index (0-based)"),
    page_size: z.number().int().min(1).max(200).optional().default(50).describe("Events per page (default 50)"),
    sort_by: z.enum(["timestamp", "rel_type", "source", "target"]).optional().describe("Sort field"),
  },
  async ({ node_id, page, page_size, sort_by }) => {
    const start = Date.now();
    log("tool", "get_events_paginated", { node_id: truncate(node_id, 50), page, page_size, sort_by: sort_by ?? "-" });
    try {
      const params: Record<string, string> = { node_id, page: String(page), page_size: String(page_size) };
      if (sort_by) params.sort_by = sort_by;
      const v = await apiGet("/events_paginated", params, HEAVY_TIMEOUT_MS);
      const summaryStr = summarizeResult("get_events_paginated", v);
      log("tool", "get_events_paginated done", { duration_ms: Date.now() - start, result: summaryStr });
      return safeJsonContent(v);
    } catch (e) {
      const msg = e instanceof Error ? e.message : String(e);
      log("tool", "get_events_paginated error", { duration_ms: Date.now() - start, error: truncate(msg, 200) });
      return textContent(msg);
    }
  }
);

// expand_node_grouped – neighborhood with grouped edges for high-degree nodes
server.tool(
  "expand_node_grouped",
  "Expand a node's neighborhood with edge GROUPING — collapses repeated edge types into summaries (e.g. '42 Connect edges to IPs' instead of 42 individual edges). Use for HIGH-DEGREE nodes where expand_node would return too much data or timeout. Returns grouped neighbor edges with counts, first/last timestamps per group.",
  {
    node_id: z.string().max(500).describe("Entity ID to expand from"),
    max_hops: z.number().int().min(1).max(5).optional().describe("Max hops (default 1)"),
    max_nodes: z.number().int().min(1).max(500).optional().describe("Max nodes in result (default 50)"),
  },
  async ({ node_id, max_hops, max_nodes }) => {
    const start = Date.now();
    log("tool", "expand_node_grouped", { node_id: truncate(node_id, 50), max_hops: max_hops ?? 1, max_nodes: max_nodes ?? "-" });
    try {
      const params: Record<string, string> = { node_id };
      if (max_hops != null) params.max_hops = String(max_hops);
      if (max_nodes != null) params.max_nodes = String(max_nodes);
      const v = await apiGet("/expand_grouped", params, HEAVY_TIMEOUT_MS);
      const summaryStr = summarizeResult("expand_node_grouped", v);
      log("tool", "expand_node_grouped done", { duration_ms: Date.now() - start, result: summaryStr });
      return safeJsonContent(v);
    } catch (e) {
      const msg = e instanceof Error ? e.message : String(e);
      log("tool", "expand_node_grouped error", { duration_ms: Date.now() - start, error: truncate(msg, 200) });
      return textContent(msg);
    }
  }
);

// export_hunt_results – export last hunt results as text
server.tool(
  "export_hunt_results",
  "Export the results of the last run_hunt as JSON or CSV text. Includes full scoring for all paths (max_score, total_score, anomaly_score, chain_summary, time range). Use to produce a detailed threat report after hunting. Call run_hunt first.",
  {
    format: z.enum(["json", "csv"]).optional().default("json").describe("Export format"),
  },
  async ({ format }) => {
    const start = Date.now();
    log("tool", "export_hunt_results", { format });
    try {
      const v = await apiPost("/export_hunt_results", { format }, HEAVY_TIMEOUT_MS) as { data: string; format: string };
      log("tool", "export_hunt_results done", { duration_ms: Date.now() - start, result: `format=${v.format} len=${v.data.length}` });
      return textContent(v.data);
    } catch (e) {
      const msg = e instanceof Error ? e.message : String(e);
      log("tool", "export_hunt_results error", { duration_ms: Date.now() - start, error: truncate(msg, 200) });
      return textContent(msg);
    }
  }
);

// enable_anomaly_scoring – activate anomaly-based hunt ranking
server.tool(
  "enable_anomaly_scoring",
  "Enable anomaly-based scoring for hunt results. Once enabled, run_hunt uses score-guided DFS and get_hunt_results includes anomaly_score and anomaly_breakdown (entity rarity, edge rarity, temporal novelty, neighborhood concentration). Call this BEFORE running hunts to get anomaly-ranked results instead of just structural scores.",
  async () => {
    const start = Date.now();
    log("tool", "enable_anomaly_scoring", {});
    try {
      const v = await apiPost("/enable_anomaly_scoring", {});
      log("tool", "enable_anomaly_scoring done", { duration_ms: Date.now() - start, result: "ok" });
      return safeJsonContent(v);
    } catch (e) {
      const msg = e instanceof Error ? e.message : String(e);
      log("tool", "enable_anomaly_scoring error", { duration_ms: Date.now() - start, error: truncate(msg, 200) });
      return textContent(msg);
    }
  }
);

// compute_scores – recalculate all entity scores
server.tool(
  "compute_scores",
  "Recalculate all entity scores: degree centrality, PageRank, and betweenness. Use after enabling anomaly scoring or when you suspect scores are stale. Scores affect hunt result ranking and node_details output.",
  async () => {
    const start = Date.now();
    log("tool", "compute_scores", {});
    try {
      const v = await apiPost("/compute_scores", {}, HEAVY_TIMEOUT_MS);
      log("tool", "compute_scores done", { duration_ms: Date.now() - start, result: "ok" });
      return safeJsonContent(v);
    } catch (e) {
      const msg = e instanceof Error ? e.message : String(e);
      log("tool", "compute_scores error", { duration_ms: Date.now() - start, error: truncate(msg, 200) });
      return textContent(msg);
    }
  }
);

async function main() {
  log("info", "GraphHunter MCP server starting", {
    name: "graph-hunter-mcp",
    version: "1.2.0",
    api_base: API_BASE,
    debug: DEBUG,
    auth: API_TOKEN ? "bearer" : "none",
  });
  if (!API_TOKEN) {
    const allow = process.env.GRAPHHUNTER_MCP_ALLOW_NO_TOKEN === "1"
      || process.env.GRAPHHUNTER_MCP_ALLOW_NO_TOKEN === "true";
    if (!allow) {
      log("error", "GRAPHHUNTER_API_TOKEN is not set — refusing to start unauthenticated. Set GRAPHHUNTER_MCP_ALLOW_NO_TOKEN=1 for local dev.");
      process.exit(2);
    }
    log("info", "Running without API token (GRAPHHUNTER_MCP_ALLOW_NO_TOKEN=1)");
  }
  const transport = new StdioServerTransport();
  await server.connect(transport);
  log("info", "GraphHunter MCP server connected (stdio transport ready)");
}

main().catch((err) => {
  log("error", "Fatal server error", { error: err instanceof Error ? err.message : String(err) });
  process.stderr.write((err instanceof Error ? err.stack : String(err)) + "\n");
  process.exit(1);
});
