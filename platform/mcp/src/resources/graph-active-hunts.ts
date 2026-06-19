import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import type { GraphStateClient } from "../lib/graph-state-client.js";

export const URI = "graph://active-hunts";
export const DESC =
  "Currently cached hunts (execution-scoped DFS results). " +
  "When the user mentions an ongoing investigation, check here " +
  "before launching a new hunt — the prior result may still be in cache.";

export function register(server: McpServer, client: GraphStateClient): void {
  server.resource(URI, DESC, async () => {
    const s = await client.getSummary({ timeoutMs: 800 });
    const hunts = s ? s.active_hunts : [];
    return {
      contents: [
        {
          uri: URI,
          mimeType: "application/json",
          text: JSON.stringify({ schema_version: 1, hunts }, null, 2),
        },
      ],
    };
  });
}
