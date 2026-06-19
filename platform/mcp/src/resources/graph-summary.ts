import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import type { GraphStateClient } from "../lib/graph-state-client.js";

export const URI = "graph://summary";
export const DESC =
  "Current graph state: totals by type, sources ingested with freshness, " +
  "active datasets, active hunts, and recent pivots. " +
  "Read this at the start of any hunting conversation. " +
  "If graph_empty is true, prefer sentinel_seed before sentinel_query.";

export function register(server: McpServer, client: GraphStateClient): void {
  server.resource(URI, DESC, async () => {
    const s = await client.getSummary({ timeoutMs: 800 });
    const text = s
      ? JSON.stringify(s, null, 2)
      : JSON.stringify({ error: "graph_summary unavailable" });
    return {
      contents: [{ uri: URI, mimeType: "application/json", text }],
    };
  });
}
