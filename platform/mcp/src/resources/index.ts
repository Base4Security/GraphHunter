import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import type { GraphStateClient } from "../lib/graph-state-client.js";

import * as summary from "./graph-summary.js";
import * as hunts from "./graph-active-hunts.js";
import * as pivots from "./graph-recent-pivots.js";

/**
 * Register the three `graph://` resources with the MCP server. Returns
 * the URIs that were registered for visibility / testing.
 */
export function registerResources(
  server: McpServer,
  client: GraphStateClient,
): string[] {
  summary.register(server, client);
  hunts.register(server, client);
  pivots.register(server, client);
  return [summary.URI, hunts.URI, pivots.URI];
}
