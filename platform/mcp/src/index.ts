#!/usr/bin/env node
/**
 * platform/mcp entrypoint — successor to `graph-hunter-mcp/src/index.ts`.
 *
 * Boots the MCP stdio server, threads a single `ToolContext` through
 * every tool in `registry`, and lets `server.ts` handle the
 * SDK-facing glue. See ADR-004 for the architecture.
 */

import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { createApiClient } from "./lib/api-client.js";
import { ContextEnricher } from "./lib/context-enricher.js";
import { GraphStateClient } from "./lib/graph-state-client.js";
import { createLogger } from "./lib/log.js";
import type { ToolContext } from "./lib/types.js";
import { instructionsFor, selectTools } from "./profiles.js";
import { registry } from "./registry.js";
import { registerResources } from "./resources/index.js";
import { ensureServer, findBundledServer, freePort } from "./lib/server-launcher.js";
import { registerTools } from "./server.js";

const EXPLICIT_API_URL = process.env.GRAPHHUNTER_API_URL || "";
let API_BASE = EXPLICIT_API_URL || "http://127.0.0.1:37891";
const ENV_TOKEN = process.env.GRAPHHUNTER_API_TOKEN || "";
// Path to `graph-hunter-server`. When set and nothing answers at
// API_BASE, the server is started here and stopped with this process.
// The packaged bundle ships the binary beside this file; the variable is
// for a repo build, or to point at a different one.
const SERVER_BIN = process.env.GRAPHHUNTER_SERVER_BIN || findBundledServer(import.meta.url);
const DEBUG =
  process.env.GRAPHHUNTER_MCP_DEBUG === "1" || process.env.GRAPHHUNTER_MCP_DEBUG === "true";

const logger = createLogger();

// Two modes. Attach: the operator named an API (URL or token), so use it and
// only start a server if nothing answers there. Private: we have a server
// binary and nothing was named, so run our own on a free port with a token
// of our own — it cannot collide with the desktop app or with another
// client's server, and never talks to an API it has no token for.
const privateServer = Boolean(SERVER_BIN) && !EXPLICIT_API_URL && !ENV_TOKEN;
if (privateServer) {
  try {
    API_BASE = `http://127.0.0.1:${await freePort()}`;
  } catch (e) {
    logger.warn("could not pick a free port, using the default", {
      error: e instanceof Error ? e.message : String(e),
    });
  }
}

let API_TOKEN = ENV_TOKEN;
let launched = false;
try {
  ({ token: API_TOKEN, launched } = await ensureServer({
    baseUrl: API_BASE,
    token: ENV_TOKEN,
    serverBin: SERVER_BIN,
    logger,
  }));
} catch (e) {
  // Keep serving: every tool then reports the API as unreachable, which
  // tells the client more than an MCP server that failed to start.
  logger.warn("could not start graph-hunter-server", {
    error: e instanceof Error ? e.message : String(e),
  });
}

const api = createApiClient({ baseUrl: API_BASE, token: API_TOKEN, logger, debug: DEBUG });

// Tool groups: `core` unless the operator asks for more. See profiles.ts.
const selection = selectTools(registry, process.env.GRAPHHUNTER_MCP_TOOLS);
if (selection.unknown.length > 0) {
  logger.warn("unknown tool groups in GRAPHHUNTER_MCP_TOOLS, ignored", {
    unknown: selection.unknown.join(","),
  });
}
const instructions = instructionsFor(selection);

const server = new McpServer(
  { name: "graph-hunter-mcp", version: "1.0.0" },
  instructions ? { instructions } : undefined,
);

const makeContext = (requestId: string): ToolContext => ({ api, logger, requestId });

// graph-context enricher: wraps every tool response with a graph state
// footer + (for sentinel_query) an overlap nudge. Default-on; kill switch
// is GH_MCP_ENRICH=off. See ContextEnricher for the failure-mode contract
// (timeouts produce "(unavailable)" footer, tool output never broken).
const graphClient = new GraphStateClient(API_BASE, { token: API_TOKEN });
const enricher = new ContextEnricher(graphClient);

registerTools(server, selection.tools, makeContext, enricher);
const registeredResources = registerResources(server, graphClient);

logger.info("starting graph-hunter-mcp", {
  api_base: API_BASE,
  tools: selection.tools.length,
  tool_groups: selection.groups.join(","),
  resources: registeredResources.length,
  enrich: process.env.GH_MCP_ENRICH === "off" ? "off" : "on",
  auth: API_TOKEN ? "bearer" : "none",
  server: launched ? "launched" : "external",
});

const transport = new StdioServerTransport();
await server.connect(transport);
