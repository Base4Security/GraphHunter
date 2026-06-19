import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import type { GraphStateClient } from "../lib/graph-state-client.js";

export const URI = "graph://recent-pivots";
export const DESC =
  "Last 20 entities added via sentinel_seed or expanded via node_expand. " +
  "Entries with expanded=false are open invitations for node_expand — " +
  "prefer expanding them over generating a fresh KQL.";

export function register(server: McpServer, client: GraphStateClient): void {
  server.resource(URI, DESC, async () => {
    const s = await client.getSummary({ timeoutMs: 800 });
    const pivots = s ? s.recent_pivots : [];
    return {
      contents: [
        {
          uri: URI,
          mimeType: "application/json",
          text: JSON.stringify({ schema_version: 1, pivots }, null, 2),
        },
      ],
    };
  });
}
