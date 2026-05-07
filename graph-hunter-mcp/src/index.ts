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

/**
 * Max length for individual metadata string values. Bumped from 200 →
 * 50_000 on 2026-05-07 — the original 200-char cap was a relic of the
 * old metadata-bag protection (raw event JSON dumps that could be
 * hundreds of KB). With `MAX_RESPONSE_CHARS` capping the whole payload
 * at 100 KB and `MAX_ARRAY_ITEMS` capping arrays at 100, the per-string
 * cap was redundant *and* mauling load-bearing fields (analyst notes,
 * narrative paragraphs, sigma yaml, vrl source). 50_000 means a single
 * truly runaway value still gets cut, but reasonable analyst content
 * always round-trips. Set `GRAPHHUNTER_MCP_NO_TRUNCATE=1` to disable
 * per-key truncation entirely (only `MAX_RESPONSE_CHARS` then applies).
 */
const MAX_METADATA_VALUE_LEN = 50_000;
const PER_KEY_TRUNCATION_DISABLED =
  process.env.GRAPHHUNTER_MCP_NO_TRUNCATE === "1" ||
  process.env.GRAPHHUNTER_MCP_NO_TRUNCATE === "true";

/**
 * Keys whose string values are passed through verbatim regardless of
 * length. They carry analyst-meaningful payload (LLM narratives,
 * generated rule YAML, user-authored notes, compiled VRL, KQL audit
 * echoes, ingestion rationale, raw command lines that constitute
 * hunt signal). Mirrors `platform/mcp/src/lib/content.ts`.
 */
const LONG_TEXT_KEYS = new Set([
  "narrative",
  "yaml",
  "content",
  "vrl_source",
  "rationale",
  "kql",
  "kql_executed",
  "dsl",
  "hypothesis_dsl",
  "formatted",
  "description",
  "summary",
  "explanation",
  "message",
  "reason",
  "skipped_reason",
  "raw_sample",
  "candidate_vrl",
  "hypothetical_vrl",
  "command_line",
  "process_command_line",
  "cmdline",
  "ProcessCommandLine",
]);

/** Truncate a metadata value, preserving start + end for readability. */
function truncateValue(v: unknown, key?: string): unknown {
  if (typeof v === "string" && v.length > MAX_METADATA_VALUE_LEN) {
    if (key && LONG_TEXT_KEYS.has(key)) return v;
    if (PER_KEY_TRUNCATION_DISABLED) return v;
    return v.slice(0, MAX_METADATA_VALUE_LEN - 20) + " ... " + v.slice(-15);
  }
  if (Array.isArray(v)) return v.slice(0, 20).map((item) => truncateValue(item, key));
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
      result[key] = truncateValue(val, key);
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
      result[key] = truncateValue(val, key);
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
  version: "1.3.0",
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

// get_temporal_heatmap – bucketed activity patterns by relation type
server.tool(
  "get_temporal_heatmap",
  "Get bucketed activity patterns per relation type. Default bucket is 1h; pass `bucket_size_seconds` (60..86400) to rebucket. Output now densifies zero-count buckets between first and last event so gaps are explicit rather than silently skipped.",
  {
    bucket_size_seconds: z
      .number()
      .int()
      .min(60)
      .max(86_400)
      .optional()
      .describe("Bucket width in seconds, default 3600"),
  },
  async ({ bucket_size_seconds }) => {
    const start = Date.now();
    log("tool", "get_temporal_heatmap", { bucket_size_seconds });
    try {
      const params: Record<string, string> = {};
      if (bucket_size_seconds != null) params.bucket_size_seconds = String(bucket_size_seconds);
      const v = await apiGet("/temporal_heatmap", params, HEAVY_TIMEOUT_MS);
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

// export_ocsf – project every triple to OCSF v1.4 + Provenance Extension
server.tool(
  "export_ocsf",
  "Export every triple in the session — or a single dataset — as OCSF v1.4 events carrying Graph Hunter's Provenance Extension (schema_version, parser_name, mapping_id, mapping_hash, source_dataset_id, raw_event_sha256). Use when you need an auditable canonical view of the graph for cold storage, downstream SIEM ingest, or mapping audits. Shapes outside the shipping subset (Authentication, Process/Network/DNS/File/Registry activity) fall into the `Other` variant with a diagnostic reason instead of being silently dropped. `format='ndjson'` streams one event per line; `format='json'` returns a single JSON array.",
  {
    dataset_id: z.string().max(500).optional().describe("Restrict the export to triples from this dataset. Omit to export every dataset."),
    format: z.enum(["json", "ndjson"]).optional().default("ndjson").describe("Output format: 'ndjson' (one event per line, streaming-friendly) or 'json' (single array)"),
  },
  async ({ dataset_id, format }) => {
    const start = Date.now();
    log("tool", "export_ocsf", { dataset_id: dataset_id ?? "-", format });
    try {
      const body: Record<string, unknown> = { format };
      if (dataset_id != null) body.dataset_id = dataset_id;
      const v = await apiPost("/export_ocsf", body, HEAVY_TIMEOUT_MS) as { data: string; format: string };
      log("tool", "export_ocsf done", { duration_ms: Date.now() - start, result: `format=${v.format} len=${v.data.length}` });
      return textContent(v.data);
    } catch (e) {
      const msg = e instanceof Error ? e.message : String(e);
      log("tool", "export_ocsf error", { duration_ms: Date.now() - start, error: truncate(msg, 200) });
      return textContent(msg);
    }
  }
);

// invariant_checker – run P1/P2/P3/P4 + treewidth heuristic over session/dataset
server.tool(
  "invariant_checker",
  "Run the shipped first-order invariants over the current session's graph (or a single dataset) and return a per-predicate report. Predicates: P1 causal monotonicity (timestamps along source→dest chains are non-decreasing), P2 type-shape plausibility (each (src_type, rel_type, dst_type) triple is in the catalog), P3 identity coherence (no illegal same-timestamp self-loops), P4 referential closure (every endpoint resolves to an entity in scope). Also returns a treewidth upper bound on the type-quotient graph with an explicit method tag. Use this after ingest to audit a mapping, or before trusting a detection query that assumes causal order. P5 (rarity sanity) is reserved and currently reports 'skipped'.",
  {
    dataset_id: z.string().max(500).optional().describe("Restrict the check to this dataset. Omit to run against every dataset in the session."),
  },
  async ({ dataset_id }) => {
    const start = Date.now();
    log("tool", "invariant_checker", { dataset_id: dataset_id ?? "-" });
    try {
      const body: Record<string, unknown> = {};
      if (dataset_id != null) body.dataset_id = dataset_id;
      const report = await apiPost("/check_invariants", body, HEAVY_TIMEOUT_MS) as {
        entity_count: number;
        relation_count: number;
        results: Array<{ predicate: string; passed: boolean; violated: number }>;
        treewidth_estimate?: { value: number; method: string };
      };
      const totalViolations = (report.results ?? [])
        .reduce((acc, r) => acc + (r.violated ?? 0), 0);
      log("tool", "invariant_checker done", {
        duration_ms: Date.now() - start,
        result: `entities=${report.entity_count} relations=${report.relation_count} violations=${totalViolations} tw=${report.treewidth_estimate?.value ?? "n/a"}`,
      });
      return safeJsonContent(report);
    } catch (e) {
      const msg = e instanceof Error ? e.message : String(e);
      log("tool", "invariant_checker error", { duration_ms: Date.now() - start, error: truncate(msg, 200) });
      return textContent(msg);
    }
  }
);

// ── M4 agentic slow-lane tools (6 ops + 3 review-queue ops) ──────────
//
// All nine tools share the same LLM-as-compiler guardrail: deterministic
// heuristics own the primary path, LLM refinement only kicks in when the
// heuristic is visibly insufficient. Every artefact lands in the per-
// session review queue as a `MappingDraft` with a stable `draft_id`,
// and no draft is ever auto-promoted — approval always requires a
// separate `agentic_review_approve` call.

const fieldConfigSchema = z
  .object({ mappings: z.array(z.record(z.any())) })
  .passthrough()
  .describe("FieldConfig produced by preview_fields / ingest_negotiate.");

server.tool(
  "ingest_negotiate",
  "Propose a FieldConfig for a raw-log sample by running the deterministic preview heuristic first and only falling back to the local LLM when the heuristic yields nothing useful. Returns a draft_id referring to a pending MappingDraft in the session's review queue — approve it via agentic_review_approve to stamp the FieldConfig onto the target dataset. The LLM NEVER sees production events; only the `raw_sample` block passed here.",
  {
    raw_sample: z.string().max(100_000).describe("Small slice of raw events (typically 50–200 rows). Bounded by the caller."),
    dataset_id: z.string().max(500).optional().describe("Optional dataset to scope the proposal to."),
    hint_format: z.string().max(100).optional().describe("Format hint ('csv', 'sysmon', 'generic', ...). Omit for auto-detect."),
    max_rounds: z.number().int().min(1).max(10).optional().describe("Soft cap on negotiation rounds. Advisory in M4 (single pass)."),
  },
  async ({ raw_sample, dataset_id, hint_format, max_rounds }) => {
    const start = Date.now();
    log("tool", "ingest_negotiate", { sample_len: raw_sample.length, dataset_id: dataset_id ?? "-", hint_format: hint_format ?? "-" });
    try {
      const body: Record<string, unknown> = { raw_sample };
      if (dataset_id != null) body.dataset_id = dataset_id;
      if (hint_format != null) body.hint_format = hint_format;
      if (max_rounds != null) body.max_rounds = max_rounds;
      const resp = await apiPost("/ingest_negotiate", body, HEAVY_TIMEOUT_MS);
      log("tool", "ingest_negotiate done", { duration_ms: Date.now() - start });
      return safeJsonContent(resp);
    } catch (e) {
      const msg = e instanceof Error ? e.message : String(e);
      log("tool", "ingest_negotiate error", { duration_ms: Date.now() - start, error: truncate(msg, 200) });
      return textContent(msg);
    }
  }
);

server.tool(
  "canonical_map",
  "Given a FieldConfig, decide which OCSF v1.4 category it projects to (process_activity, network_activity, authentication, dns_activity, file_activity, or 'other') and return a ProvenanceTemplate stamp. The common cases are pinned deterministically by entity-type signature; the LLM is only consulted when a target_ocsf_category is supplied that contradicts the deterministic pick.",
  {
    field_config: fieldConfigSchema,
    target_ocsf_category: z.string().max(120).optional().describe("Pin a specific OCSF category; mapper warns if deterministic choice disagrees."),
  },
  async ({ field_config, target_ocsf_category }) => {
    const start = Date.now();
    log("tool", "canonical_map", { target: target_ocsf_category ?? "-" });
    try {
      const body: Record<string, unknown> = { field_config };
      if (target_ocsf_category != null) body.target_ocsf_category = target_ocsf_category;
      const resp = await apiPost("/canonical_map", body);
      log("tool", "canonical_map done", { duration_ms: Date.now() - start });
      return safeJsonContent(resp);
    } catch (e) {
      const msg = e instanceof Error ? e.message : String(e);
      log("tool", "canonical_map error", { duration_ms: Date.now() - start, error: truncate(msg, 200) });
      return textContent(msg);
    }
  }
);

server.tool(
  "parser_generate",
  "Compile a FieldConfig to a deterministic VRL program (via field_config_to_vrl) and register the result as a pending MappingDraft in the review queue. Returns the VRL source and its mapping_hash (sha256 of the source). With optimization_hint='fidelity', the LLM is allowed to propose refinements — still gated by the review queue and (in M6) by constrained decoding, so malformed VRL can never be emitted.",
  {
    field_config: fieldConfigSchema,
    ocsf_category: z.string().max(120).optional().describe("Carried verbatim into the program's provenance template."),
    optimization_hint: z.enum(["speed", "fidelity"]).optional().describe("'speed' keeps deterministic output as-is; 'fidelity' allows LLM refinement."),
  },
  async ({ field_config, ocsf_category, optimization_hint }) => {
    const start = Date.now();
    log("tool", "parser_generate", { hint: optimization_hint ?? "speed" });
    try {
      const body: Record<string, unknown> = { field_config };
      if (ocsf_category != null) body.ocsf_category = ocsf_category;
      if (optimization_hint != null) body.optimization_hint = optimization_hint;
      const resp = await apiPost("/parser_generate", body, HEAVY_TIMEOUT_MS);
      log("tool", "parser_generate done", { duration_ms: Date.now() - start });
      return safeJsonContent(resp);
    } catch (e) {
      const msg = e instanceof Error ? e.message : String(e);
      log("tool", "parser_generate error", { duration_ms: Date.now() - start, error: truncate(msg, 200) });
      return textContent(msg);
    }
  }
);

server.tool(
  "schema_drift_detect",
  "Report per-field drift signals for a dataset — type-tag histogram mix, null-rate EWMA, and a recommended action ('none' | 'review' | 'renegotiate'). Backed by the drift store written by the ingest path; no LLM is consulted. Use this as a scheduled trigger for re-running ingest_negotiate when a source starts producing novel field shapes.",
  {
    dataset_id: z.string().max(500).describe("Dataset to inspect."),
    window_secs: z.number().int().min(60).optional().describe("Aggregation window in seconds. Defaults to 3600."),
  },
  async ({ dataset_id, window_secs }) => {
    const start = Date.now();
    log("tool", "schema_drift_detect", { dataset_id });
    try {
      const body: Record<string, unknown> = { dataset_id };
      if (window_secs != null) body.window_secs = window_secs;
      const resp = await apiPost("/schema_drift_detect", body);
      log("tool", "schema_drift_detect done", { duration_ms: Date.now() - start });
      return safeJsonContent(resp);
    } catch (e) {
      const msg = e instanceof Error ? e.message : String(e);
      log("tool", "schema_drift_detect error", { duration_ms: Date.now() - start, error: truncate(msg, 200) });
      return textContent(msg);
    }
  }
);

server.tool(
  "mapping_regression_test",
  "Replay a baseline dataset's events through a candidate VRL program and diff the resulting triples (Jaccard), OCSF field coverage, and invariant-violation counts against the live mapping. Returns verdict 'pass' | 'warn' | 'fail'. Zero production-graph writes — the candidate never touches the live state. Pair this with parser_generate before promoting a new mapping via agentic_review_approve.",
  {
    candidate_vrl: z.string().max(200_000).describe("VRL source to evaluate. Typically sourced from a parser_generate draft."),
    baseline_dataset_id: z.string().max(500).describe("Dataset whose events are replayed through both baseline and candidate."),
    sample_size: z.number().int().min(1).optional().describe("Cap on rows to replay. Defaults to 1000."),
  },
  async ({ candidate_vrl, baseline_dataset_id, sample_size }) => {
    const start = Date.now();
    log("tool", "mapping_regression_test", { baseline_dataset_id, sample_size: sample_size ?? 1000 });
    try {
      const body: Record<string, unknown> = { candidate_vrl, baseline_dataset_id };
      if (sample_size != null) body.sample_size = sample_size;
      const resp = await apiPost("/mapping_regression_test", body, HEAVY_TIMEOUT_MS);
      log("tool", "mapping_regression_test done", { duration_ms: Date.now() - start });
      return safeJsonContent(resp);
    } catch (e) {
      const msg = e instanceof Error ? e.message : String(e);
      log("tool", "mapping_regression_test error", { duration_ms: Date.now() - start, error: truncate(msg, 200) });
      return textContent(msg);
    }
  }
);

server.tool(
  "invariant_check_hypothetical",
  "Run the P1–P5 invariant suite against a *hypothetical* graph: replay a dataset's events through a candidate VRL program, project the resulting triples, and evaluate invariants over that synthetic graph. Lets you sanity-check a candidate mapping before approval without paying any ingest cost.",
  {
    hypothetical_vrl: z.string().max(200_000).describe("VRL source to evaluate. Usually the `vrl_source` from a parser_generate draft."),
    dataset_id: z.string().max(500).describe("Dataset whose events provide the synthetic graph's inputs."),
    sample_size: z.number().int().min(1).optional().describe("Cap on rows to replay. Defaults to 1000."),
  },
  async ({ hypothetical_vrl, dataset_id, sample_size }) => {
    const start = Date.now();
    log("tool", "invariant_check_hypothetical", { dataset_id, sample_size: sample_size ?? 1000 });
    try {
      const body: Record<string, unknown> = { hypothetical_vrl, dataset_id };
      if (sample_size != null) body.sample_size = sample_size;
      const resp = await apiPost("/invariant_check_hypothetical", body, HEAVY_TIMEOUT_MS);
      log("tool", "invariant_check_hypothetical done", { duration_ms: Date.now() - start });
      return safeJsonContent(resp);
    } catch (e) {
      const msg = e instanceof Error ? e.message : String(e);
      log("tool", "invariant_check_hypothetical error", { duration_ms: Date.now() - start, error: truncate(msg, 200) });
      return textContent(msg);
    }
  }
);

server.tool(
  "agentic_review_list",
  "List MappingDrafts in the current session's review queue. Defaults to pending only; pass include_resolved=true to see the audit trail of prior Approved/Rejected drafts (with their reasons and timestamps).",
  {
    include_resolved: z.boolean().optional().describe("When true, include Approved and Rejected drafts. Defaults to false."),
  },
  async ({ include_resolved }) => {
    const start = Date.now();
    log("tool", "agentic_review_list", { include_resolved: include_resolved ?? false });
    try {
      const body: Record<string, unknown> = {};
      if (include_resolved != null) body.include_resolved = include_resolved;
      const resp = await apiPost("/agentic_review_list", body);
      log("tool", "agentic_review_list done", { duration_ms: Date.now() - start });
      return safeJsonContent(resp);
    } catch (e) {
      const msg = e instanceof Error ? e.message : String(e);
      log("tool", "agentic_review_list error", { duration_ms: Date.now() - start, error: truncate(msg, 200) });
      return textContent(msg);
    }
  }
);

server.tool(
  "agentic_review_approve",
  "Approve a pending MappingDraft. For IngestNegotiator drafts, this stamps the proposed FieldConfig onto the most recent dataset in the session (returned as promoted_dataset_id). For ParserGenerator / CanonicalMapper drafts, approval only flips status — the VRL flows into provenance the next time export_ocsf runs on a dataset whose FieldConfig hashes to the same mapping_hash. Idempotent: approving an already-resolved draft returns InvalidState.",
  {
    draft_id: z.string().max(200).describe("The draft_id returned by a previous agentic tool call."),
  },
  async ({ draft_id }) => {
    const start = Date.now();
    log("tool", "agentic_review_approve", { draft_id });
    try {
      const resp = await apiPost("/agentic_review_approve", { draft_id });
      log("tool", "agentic_review_approve done", { duration_ms: Date.now() - start });
      return safeJsonContent(resp);
    } catch (e) {
      const msg = e instanceof Error ? e.message : String(e);
      log("tool", "agentic_review_approve error", { duration_ms: Date.now() - start, error: truncate(msg, 200) });
      return textContent(msg);
    }
  }
);

server.tool(
  "agentic_review_reject",
  "Reject a pending MappingDraft and persist the reason on the draft for audit. Reason is required — an empty or whitespace-only string is rejected with InvalidInput.",
  {
    draft_id: z.string().max(200).describe("The draft_id returned by a previous agentic tool call."),
    reason: z.string().min(1).max(2000).describe("Required human-readable reason. Stored verbatim on the draft."),
  },
  async ({ draft_id, reason }) => {
    const start = Date.now();
    log("tool", "agentic_review_reject", { draft_id });
    try {
      const resp = await apiPost("/agentic_review_reject", { draft_id, reason });
      log("tool", "agentic_review_reject done", { duration_ms: Date.now() - start });
      return safeJsonContent(resp);
    } catch (e) {
      const msg = e instanceof Error ? e.message : String(e);
      log("tool", "agentic_review_reject error", { duration_ms: Date.now() - start, error: truncate(msg, 200) });
      return textContent(msg);
    }
  }
);

// ── M5 dead-letter queue tools ────────────────────────────────────────

server.tool(
  "list_dead_letters",
  "List rows the ingest pipeline rejected (parse failure, invariant violation, empty yield). Supports filtering by dataset_id and failure_kind plus paging. The DLQ lives on disk as JSONL shards and survives restarts — when unconfigured (tests / headless), returns an empty page.",
  {
    dataset_id: z.string().max(500).optional().describe("Restrict to rows rejected for this dataset."),
    failure_kind: z.enum([
      "parse_failure",
      "invariant_causality",
      "invariant_referential",
      "invariant_type_shape",
      "empty_yield",
      "other",
    ]).optional().describe("Restrict to a single failure category."),
    offset: z.number().int().min(0).optional(),
    limit: z.number().int().min(1).max(1000).optional().describe("Page size. Defaults to 100."),
  },
  async ({ dataset_id, failure_kind, offset, limit }) => {
    const start = Date.now();
    log("tool", "list_dead_letters", { dataset_id: dataset_id ?? "-", failure_kind: failure_kind ?? "-" });
    try {
      const body: Record<string, unknown> = {};
      if (dataset_id != null) body.dataset_id = dataset_id;
      if (failure_kind != null) body.failure_kind = failure_kind;
      if (offset != null) body.offset = offset;
      if (limit != null) body.limit = limit;
      const resp = await apiPost("/list_dead_letters", body);
      log("tool", "list_dead_letters done", { duration_ms: Date.now() - start });
      return safeJsonContent(resp);
    } catch (e) {
      const msg = e instanceof Error ? e.message : String(e);
      log("tool", "list_dead_letters error", { duration_ms: Date.now() - start, error: truncate(msg, 200) });
      return textContent(msg);
    }
  }
);

server.tool(
  "reingest_dead_letter",
  "Retry a set of DLQ entries against their datasets' *current* FieldConfigs. The expected workflow: a row failed with the previous mapping → user fixes the mapping (agentic_review_approve) → reingest. Entries whose dataset is gone or unmapped come back in `failed`; successful ones are removed from the DLQ.",
  {
    dlq_ids: z.array(z.string().max(200)).min(1).max(1000).describe("IDs returned by list_dead_letters."),
  },
  async ({ dlq_ids }) => {
    const start = Date.now();
    log("tool", "reingest_dead_letter", { count: dlq_ids.length });
    try {
      const resp = await apiPost("/reingest_dead_letter", { dlq_ids }, HEAVY_TIMEOUT_MS);
      log("tool", "reingest_dead_letter done", { duration_ms: Date.now() - start });
      return safeJsonContent(resp);
    } catch (e) {
      const msg = e instanceof Error ? e.message : String(e);
      log("tool", "reingest_dead_letter error", { duration_ms: Date.now() - start, error: truncate(msg, 200) });
      return textContent(msg);
    }
  }
);

server.tool(
  "purge_dead_letters",
  "Bulk-remove DLQ entries. Without `all=true`, at least one of `dataset_id` / `failure_kind` is required — the empty-filter case is rejected to prevent accidental wipes.",
  {
    all: z.boolean().optional().describe("When true, remove every DLQ entry regardless of filter."),
    dataset_id: z.string().max(500).optional(),
    failure_kind: z.enum([
      "parse_failure",
      "invariant_causality",
      "invariant_referential",
      "invariant_type_shape",
      "empty_yield",
      "other",
    ]).optional(),
  },
  async ({ all, dataset_id, failure_kind }) => {
    const start = Date.now();
    log("tool", "purge_dead_letters", { all: all ?? false });
    try {
      const body: Record<string, unknown> = {};
      if (all != null) body.all = all;
      if (dataset_id != null) body.dataset_id = dataset_id;
      if (failure_kind != null) body.failure_kind = failure_kind;
      const resp = await apiPost("/purge_dead_letters", body);
      log("tool", "purge_dead_letters done", { duration_ms: Date.now() - start });
      return safeJsonContent(resp);
    } catch (e) {
      const msg = e instanceof Error ? e.message : String(e);
      log("tool", "purge_dead_letters error", { duration_ms: Date.now() - start, error: truncate(msg, 200) });
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
  "Export the results of the last run_hunt as JSON or CSV text. When `aggregate=true` (recommended for large result sets) identical paths collapse into one row with an edge_count column — drops the response size ~10x for spray-style hunts. `page`/`page_size` stream the deduped export.",
  {
    format: z.enum(["json", "csv"]).optional().default("json").describe("Export format"),
    page: z.number().int().min(0).max(10000).optional().describe("Page index (0-based, default 0)."),
    page_size: z.number().int().min(1).max(10000).optional().describe("Page size (default = whole result set)."),
    aggregate: z.boolean().optional().describe("When true, collapse identical paths with an edge_count aggregate."),
  },
  async ({ format, page, page_size, aggregate }) => {
    const start = Date.now();
    log("tool", "export_hunt_results", { format, page, page_size, aggregate });
    try {
      const body: Record<string, unknown> = { format };
      if (page != null) body.page = page;
      if (page_size != null) body.page_size = page_size;
      if (aggregate != null) body.aggregate = aggregate;
      const v = await apiPost("/export_hunt_results", body, HEAVY_TIMEOUT_MS) as { data: string; format: string };
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

// save_hypothesis_as_sigma (C.3) – convert a DSL hypothesis to a Sigma rule
server.tool(
  "save_hypothesis_as_sigma",
  "Convert a DSL hypothesis (with optional IoC set) to a Sigma rule YAML ready for `sigmac` compilation. Maps (rel_type, dest_type) pairs to canonical Sigma logsources (User -[Auth]-> IP → azure signinlogs; Process -[Spawn]-> Process → process_creation; etc.). Metadata predicates become selection fields; HAVING count aggregations become Sigma count() conditions with timeframe. Response: {yaml, title, fully_mapped}. When fully_mapped=false the rule contains a comment block marking the gap the analyst needs to fill.",
  {
    hypothesis_dsl: z.string().min(1).max(10_000),
    title: z.string().min(1).max(200),
    tag_prefix: z.string().max(100).optional().describe("Filter IoC seed by tag prefix (default `ioc:`)"),
    level: z.enum(["low", "medium", "high", "critical"]).optional().describe("Sigma severity level (default medium)"),
  },
  async ({ hypothesis_dsl, title, tag_prefix, level }) => {
    const start = Date.now();
    log("tool", "save_hypothesis_as_sigma", { title, tag_prefix: tag_prefix ?? "ioc:" });
    try {
      const body: Record<string, unknown> = { hypothesis_dsl, title };
      if (tag_prefix != null) body.tag_prefix = tag_prefix;
      if (level != null) body.level = level;
      const v = await apiPost("/save_hypothesis_as_sigma", body, HEAVY_TIMEOUT_MS);
      log("tool", "save_hypothesis_as_sigma done", { duration_ms: Date.now() - start, result: "ok" });
      return safeJsonContent(v);
    } catch (e) {
      const msg = e instanceof Error ? e.message : String(e);
      log("tool", "save_hypothesis_as_sigma error", { duration_ms: Date.now() - start, error: truncate(msg, 200) });
      return textContent(msg);
    }
  }
);

// file_ticket (C.4) – push an incident to Jira Cloud or ServiceNow
server.tool(
  "file_ticket",
  "Create a ticket in Jira Cloud or ServiceNow with the hunt context. Gated by env GRAPHHUNTER_TICKET_PUBLISH_ENABLED=1, `confirm:true` per call, or `dry_run:true` to preview. Jira requires env JIRA_BASE_URL, JIRA_EMAIL, JIRA_API_TOKEN, JIRA_PROJECT_KEY (optional JIRA_ISSUE_TYPE, default `Task`). ServiceNow requires SERVICENOW_INSTANCE, SERVICENOW_USERNAME, SERVICENOW_PASSWORD (optional SERVICENOW_TABLE, default `incident`). Response includes extracted `ticket_id` (Jira key or SN number).",
  {
    system: z.enum(["jira", "servicenow"]),
    title: z.string().min(1).max(500),
    body: z.string().min(1).max(50_000),
    priority: z.string().max(50).optional(),
    assignee: z.string().max(200).optional().describe("Jira: accountId. ServiceNow: username."),
    dry_run: z.boolean().optional(),
    confirm: z.boolean().optional(),
  },
  async ({ system, title, body, priority, assignee, dry_run, confirm }) => {
    const start = Date.now();
    log("tool", "file_ticket", { system, dry_run: !!dry_run, confirm: !!confirm });
    try {
      const requestBody: Record<string, unknown> = { system, title, body };
      if (priority != null) requestBody.priority = priority;
      if (assignee != null) requestBody.assignee = assignee;
      if (dry_run != null) requestBody.dry_run = dry_run;
      if (confirm != null) requestBody.confirm = confirm;
      const v = await apiPost("/file_ticket", requestBody, HEAVY_TIMEOUT_MS);
      log("tool", "file_ticket done", { duration_ms: Date.now() - start, result: "ok" });
      return safeJsonContent(v);
    } catch (e) {
      const msg = e instanceof Error ? e.message : String(e);
      log("tool", "file_ticket error", { duration_ms: Date.now() - start, error: truncate(msg, 200) });
      return textContent(msg);
    }
  }
);

// publish_iocs_to_sentinel (C.2) – push tagged IoCs to an Azure Sentinel Watchlist
server.tool(
  "publish_iocs_to_sentinel",
  "Publish the session's tagged IoCs as an Azure Sentinel Watchlist. Mutates the Sentinel tenant — requires three gates: (1) env GRAPHHUNTER_IOC_PUBLISH_ENABLED=1 on the GraphHunter process, (2) `confirm: true` in this call, (3) at least one entity tagged with the `tag_prefix` (default `ioc:`). Use `dry_run: true` first to preview the payload + target URL without posting. Required env vars: AZURE_TENANT_ID, AZURE_CLIENT_ID, AZURE_CLIENT_SECRET, AZURE_SUBSCRIPTION_ID, AZURE_RESOURCE_GROUP, AZURE_WORKSPACE_NAME. The service principal needs `Microsoft Sentinel Contributor` role on the workspace. Response includes `http_status`, `payload` (always), and `azure_response_body` when posted.",
  {
    watchlist_name: z.string().min(1).max(200).describe("Human-readable watchlist name; will be normalized to an ARM alias (lowercased, spaces → _)"),
    display_name: z.string().max(200).optional().describe("Optional Sentinel displayName (defaults to watchlist_name)"),
    description: z.string().max(2000).optional().describe("Optional Sentinel description"),
    tag_prefix: z.string().max(100).optional().describe("Tag prefix filter (default `ioc:`)"),
    dry_run: z.boolean().optional().describe("When true, return payload + target URL without posting"),
    confirm: z.boolean().optional().describe("Must be true to actually POST (safety gate)"),
  },
  async ({ watchlist_name, display_name, description, tag_prefix, dry_run, confirm }) => {
    const start = Date.now();
    log("tool", "publish_iocs_to_sentinel", { watchlist_name, dry_run: !!dry_run, confirm: !!confirm });
    try {
      const body: Record<string, unknown> = { watchlist_name };
      if (display_name != null) body.display_name = display_name;
      if (description != null) body.description = description;
      if (tag_prefix != null) body.tag_prefix = tag_prefix;
      if (dry_run != null) body.dry_run = dry_run;
      if (confirm != null) body.confirm = confirm;
      const v = await apiPost("/publish_iocs_to_sentinel", body, HEAVY_TIMEOUT_MS);
      log("tool", "publish_iocs_to_sentinel done", { duration_ms: Date.now() - start, result: "ok" });
      return safeJsonContent(v);
    } catch (e) {
      const msg = e instanceof Error ? e.message : String(e);
      log("tool", "publish_iocs_to_sentinel error", { duration_ms: Date.now() - start, error: truncate(msg, 200) });
      return textContent(msg);
    }
  }
);

// diff_hunts (C.1) – compare hunt results at two points in time
server.tool(
  "diff_hunts",
  "Run the same DSL hypothesis at two upper time bounds (baseline_ts, current_ts) and return what was added/removed between them. Killer tool for tracking attack progression: pass a cat-017 pattern with `baseline_ts=<T-6h>` and `current_ts=<now>` — the response tells you exactly which IPs/users were added to the spray in the last 6 hours. Paths compared by node-sequence equality after DedupMode::ByPath. Response shape: {baseline_count, current_count, added: ScoredPath[], removed: ScoredPath[]}.",
  {
    hypothesis_dsl: z.string().min(1).max(10_000).describe("Hunt pattern in DSL form"),
    baseline_ts: z.number().int().describe("Upper bound of the baseline snapshot (Unix seconds)"),
    current_ts: z.number().int().describe("Upper bound of the current snapshot (Unix seconds); must be >= baseline_ts"),
  },
  async ({ hypothesis_dsl, baseline_ts, current_ts }) => {
    const start = Date.now();
    log("tool", "diff_hunts", { baseline_ts, current_ts });
    try {
      const v = await apiPost(
        "/diff_hunts",
        { hypothesis_dsl, baseline_ts, current_ts },
        HEAVY_TIMEOUT_MS,
      );
      log("tool", "diff_hunts done", { duration_ms: Date.now() - start, result: "ok" });
      return safeJsonContent(v);
    } catch (e) {
      const msg = e instanceof Error ? e.message : String(e);
      log("tool", "diff_hunts error", { duration_ms: Date.now() - start, error: truncate(msg, 200) });
      return textContent(msg);
    }
  }
);

// ─── v1.3 MCP tools (post-hunt feedback) ──────────────────────────

// get_relation_schema – enumerate (rel_type, source_type, target_type) triples
server.tool(
  "get_relation_schema",
  "List every (rel_type, source_type, target_type) triple actually present in the loaded graph, with edge counts and observed metadata keys. Call this BEFORE writing a run_hunt DSL — it's the cheapest way to confirm edge direction and discover which metadata keys can be used in filter predicates. Replaces trial-and-error hunt authoring with zero-result feedback. Response shape: `{ entries, _meta: { compute_ms, cache_hit } }` — `cache_hit=true` means the result came from the memoized schema cache, so an analyst can tell at a glance whether the warm path is working.",
  async () => {
    const start = Date.now();
    log("tool", "get_relation_schema", {});
    try {
      const v = await apiGet("/relation_schema");
      const summaryStr = summarizeResult("get_relation_schema", v);
      const meta = (v as { _meta?: { compute_ms?: number; cache_hit?: boolean } })?._meta;
      log("tool", "get_relation_schema done", {
        duration_ms: Date.now() - start,
        result: summaryStr,
        ...(meta ? { server_compute_ms: meta.compute_ms, cache_hit: meta.cache_hit } : {}),
      });
      return safeJsonContent(v);
    } catch (e) {
      const msg = e instanceof Error ? e.message : String(e);
      log("tool", "get_relation_schema error", { duration_ms: Date.now() - start, error: truncate(msg, 200) });
      return textContent(msg);
    }
  }
);

// get_catalog_with_status – catalog + per-entry compatibility
server.tool(
  "get_catalog_with_status",
  "Return the ATT&CK hypothesis catalog with per-entry compatibility checked against the current graph. Each entry has `compatible:bool` plus `missing_entity_types`/`missing_rel_types` when the dataset can't support the pattern. Use this instead of `get_catalog` to avoid running patterns that were never going to match (e.g. DARPA-style Process patterns against a cloud-identity dataset).",
  async () => {
    const start = Date.now();
    log("tool", "get_catalog_with_status", {});
    try {
      const v = await apiGet("/catalog/status");
      const summaryStr = summarizeResult("get_catalog_with_status", v);
      log("tool", "get_catalog_with_status done", { duration_ms: Date.now() - start, result: summaryStr });
      return safeJsonContent(v);
    } catch (e) {
      const msg = e instanceof Error ? e.message : String(e);
      log("tool", "get_catalog_with_status error", { duration_ms: Date.now() - start, error: truncate(msg, 200) });
      return textContent(msg);
    }
  }
);

// get_catalog_diagnostics – YAML load errors collected at startup
server.tool(
  "get_catalog_diagnostics",
  "Return any diagnostics the catalog loader collected at startup. Empty array means every built-in YAML and every user-supplied YAML under $GRAPHHUNTER_CATALOG_DIR parsed + validated cleanly. Non-empty entries carry `source_path`, `entry_id`, and `message` — use to surface to the analyst that their custom catalog YAMLs were silently skipped.",
  async () => {
    const start = Date.now();
    log("tool", "get_catalog_diagnostics", {});
    try {
      const v = await apiGet("/catalog/diagnostics");
      const summaryStr = summarizeResult("get_catalog_diagnostics", v);
      log("tool", "get_catalog_diagnostics done", { duration_ms: Date.now() - start, result: summaryStr });
      return safeJsonContent(v);
    } catch (e) {
      const msg = e instanceof Error ? e.message : String(e);
      log("tool", "get_catalog_diagnostics error", { duration_ms: Date.now() - start, error: truncate(msg, 200) });
      return textContent(msg);
    }
  }
);

// explain_score – 4-dim breakdown + percentiles + peers for a node
server.tool(
  "explain_score",
  "Explain why a node has the score it has: the four-dimension anomaly breakdown (entity rarity, edge rarity, neighborhood concentration, temporal novelty), composite and degree percentiles against the whole graph, top-5 same-type peers, and a plain-English narrative. Use to distinguish structural centrality (e.g. /usr/bin/grep under MDE) from genuine anomalies before triaging a top_anomalies hit.",
  {
    node_id: z.string().max(500).describe("Entity ID to explain"),
  },
  async ({ node_id }) => {
    const start = Date.now();
    log("tool", "explain_score", { node_id: truncate(node_id, 50) });
    try {
      const v = await apiGet("/explain_score", { node_id });
      log("tool", "explain_score done", { duration_ms: Date.now() - start, result: "ok" });
      return safeJsonContent(v);
    } catch (e) {
      const msg = e instanceof Error ? e.message : String(e);
      log("tool", "explain_score error", { duration_ms: Date.now() - start, error: truncate(msg, 200) });
      return textContent(msg);
    }
  }
);

// tag_entity – mark a node as IoC / benign / investigated
server.tool(
  "tag_entity",
  "Apply a tag to an entity (e.g. `ioc:malicious`, `benign:confirmed`, `investigated:fp`). Tags persist with the session and are queryable via list_tagged / exportable via export_iocs. Use to build an IoC list during a hunt instead of copy-pasting node IDs into external notes.",
  {
    node_id: z.string().max(500).describe("Entity ID to tag"),
    tag: z.string().min(1).max(100).describe("Tag label (convention: `ioc:malicious`, `benign:confirmed`, `investigated:fp`)"),
    reason: z.string().max(2000).optional().describe("Optional human-readable rationale"),
  },
  async ({ node_id, tag, reason }) => {
    const start = Date.now();
    log("tool", "tag_entity", { node_id: truncate(node_id, 50), tag });
    try {
      const v = await apiPost("/tag", { node_id, tag, reason: reason ?? undefined });
      log("tool", "tag_entity done", { duration_ms: Date.now() - start, result: "ok" });
      return safeJsonContent(v);
    } catch (e) {
      const msg = e instanceof Error ? e.message : String(e);
      log("tool", "tag_entity error", { duration_ms: Date.now() - start, error: truncate(msg, 200) });
      return textContent(msg);
    }
  }
);

// untag_entity – remove a previously-applied tag
server.tool(
  "untag_entity",
  "Remove a tag previously applied with tag_entity. No-op if the (node_id, tag) pair was not tagged.",
  {
    node_id: z.string().max(500),
    tag: z.string().min(1).max(100),
  },
  async ({ node_id, tag }) => {
    const start = Date.now();
    log("tool", "untag_entity", { node_id: truncate(node_id, 50), tag });
    try {
      const v = await apiPost("/untag", { node_id, tag });
      log("tool", "untag_entity done", { duration_ms: Date.now() - start, result: "ok" });
      return safeJsonContent(v);
    } catch (e) {
      const msg = e instanceof Error ? e.message : String(e);
      log("tool", "untag_entity error", { duration_ms: Date.now() - start, error: truncate(msg, 200) });
      return textContent(msg);
    }
  }
);

// list_tagged – filter session tags by prefix
server.tool(
  "list_tagged",
  "List all entity tags in the current session, optionally filtered by prefix (e.g. `ioc:` to list IoCs only). Returns `{node_id, tag, reason?, created_at}` entries.",
  {
    tag_prefix: z.string().max(100).optional().describe("Optional prefix filter (e.g. `ioc:`)"),
  },
  async ({ tag_prefix }) => {
    const start = Date.now();
    log("tool", "list_tagged", { tag_prefix: tag_prefix ?? "-" });
    try {
      const params: Record<string, string> = {};
      if (tag_prefix) params.tag_prefix = tag_prefix;
      const v = await apiGet("/tags", params);
      const summaryStr = summarizeResult("list_tagged", v);
      log("tool", "list_tagged done", { duration_ms: Date.now() - start, result: summaryStr });
      return safeJsonContent(v);
    } catch (e) {
      const msg = e instanceof Error ? e.message : String(e);
      log("tool", "list_tagged error", { duration_ms: Date.now() - start, error: truncate(msg, 200) });
      return textContent(msg);
    }
  }
);

// export_iocs – emit a consumable IoC feed in one of four formats
server.tool(
  "export_iocs",
  "Export the session's tagged entities as a consumable IoC feed. Formats: `stix21` (STIX 2.1 bundle for MISP/ThreatStream), `misp_csv` (MISP import), `kql_ioc_set` (a `let IoC_IPs = datatable(...)` block ready to paste into Azure Sentinel hunting), `sigma_stub` (a Sigma rule seeded with the IoC set). `tag_prefix` defaults to `ioc:` so the common CSIRT workflow needs no args.",
  {
    format: z.enum(["stix21", "misp_csv", "kql_ioc_set", "sigma_stub"]).describe("Output format"),
    tag_prefix: z.string().max(100).optional().describe("Tag prefix filter (default `ioc:`)"),
  },
  async ({ format, tag_prefix }) => {
    const start = Date.now();
    log("tool", "export_iocs", { format, tag_prefix: tag_prefix ?? "ioc:" });
    try {
      const body: Record<string, unknown> = { format };
      if (tag_prefix != null) body.tag_prefix = tag_prefix;
      const v = await apiPost("/export_iocs", body, HEAVY_TIMEOUT_MS) as string;
      log("tool", "export_iocs done", { duration_ms: Date.now() - start, result: `format=${format} len=${typeof v === "string" ? v.length : "?"}` });
      return textContent(typeof v === "string" ? v : JSON.stringify(v));
    } catch (e) {
      const msg = e instanceof Error ? e.message : String(e);
      log("tool", "export_iocs error", { duration_ms: Date.now() - start, error: truncate(msg, 200) });
      return textContent(msg);
    }
  }
);

// ── M7 mapping library publish/consume ──────────────────────────────

server.tool(
  "publish_mapping",
  "Force-publish any review-queue draft (Pending / Approved / Rejected) to the shared mapping library. Mirrors what agentic_review_approve does as a side effect, but is the analyst path: stamps PublishSource::Manual so audit can distinguish auto-publication from explicit override. Errors with InvalidState when the mapping library is not configured (headless / tests) or when the draft has no field_config to fingerprint.",
  {
    draft_id: z.string().max(200).describe("draft_id from any prior agentic_* tool call."),
    ocsf_category: z.string().max(120).optional().describe("Optional OCSF class to stamp on the entry (e.g. 'authentication', 'process_activity')."),
  },
  async ({ draft_id, ocsf_category }) => {
    const start = Date.now();
    log("tool", "publish_mapping", { draft_id, ocsf_category: ocsf_category ?? "-" });
    try {
      const body: Record<string, unknown> = { draft_id };
      if (ocsf_category != null) body.ocsf_category = ocsf_category;
      const resp = await apiPost("/publish_mapping", body);
      log("tool", "publish_mapping done", { duration_ms: Date.now() - start });
      return safeJsonContent(resp);
    } catch (e) {
      const msg = e instanceof Error ? e.message : String(e);
      log("tool", "publish_mapping error", { duration_ms: Date.now() - start, error: truncate(msg, 200) });
      return textContent(msg);
    }
  }
);

server.tool(
  "fetch_shared_mappings",
  "List published mappings from the shared library as compact summaries. Optionally filter by exact fingerprint or ocsf_category; pass `limit` to cap the page (newest first). Returns `total` pre-limit so the caller can paginate. The library lives on disk and is shared across sessions — drafts auto-publish on agentic_review_approve, and analysts can force-publish via publish_mapping.",
  {
    fingerprint: z.string().max(64).optional().describe("Exact-match fingerprint filter (e.g. 'fp-abc123…')."),
    ocsf_category: z.string().max(120).optional().describe("Exact-match category filter."),
    limit: z.number().int().min(1).max(1000).optional().describe("Cap on returned summaries; sorts newest-first when set."),
  },
  async ({ fingerprint, ocsf_category, limit }) => {
    const start = Date.now();
    log("tool", "fetch_shared_mappings", { fingerprint: fingerprint ?? "-", ocsf_category: ocsf_category ?? "-", limit: limit ?? "-" });
    try {
      const body: Record<string, unknown> = {};
      if (fingerprint != null) body.fingerprint = fingerprint;
      if (ocsf_category != null) body.ocsf_category = ocsf_category;
      if (limit != null) body.limit = limit;
      const resp = await apiPost("/fetch_shared_mappings", body);
      log("tool", "fetch_shared_mappings done", { duration_ms: Date.now() - start });
      return safeJsonContent(resp);
    } catch (e) {
      const msg = e instanceof Error ? e.message : String(e);
      log("tool", "fetch_shared_mappings error", { duration_ms: Date.now() - start, error: truncate(msg, 200) });
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
