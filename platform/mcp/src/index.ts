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
import { createLogger } from "./lib/log.js";
import type { ToolContext } from "./lib/types.js";
import { registry } from "./registry.js";
import { registerTools } from "./server.js";

const API_BASE = process.env.GRAPHHUNTER_API_URL || "http://127.0.0.1:37891";
const API_TOKEN = process.env.GRAPHHUNTER_API_TOKEN || "";
const DEBUG =
  process.env.GRAPHHUNTER_MCP_DEBUG === "1" || process.env.GRAPHHUNTER_MCP_DEBUG === "true";

const logger = createLogger();
const api = createApiClient({ baseUrl: API_BASE, token: API_TOKEN, logger, debug: DEBUG });

const server = new McpServer({ name: "graph-hunter-mcp", version: "1.0.0" });

const makeContext = (requestId: string): ToolContext => ({ api, logger, requestId });

registerTools(server, registry, makeContext);

logger.info("starting graph-hunter-mcp", {
  api_base: API_BASE,
  tools: registry.length,
  auth: API_TOKEN ? "bearer" : "none",
});

const transport = new StdioServerTransport();
await server.connect(transport);
