import { z } from "zod";
import { defineTool } from "../../lib/types.js";

export const graphPathNodes = defineTool({
  name: "graph_path_nodes",
  description:
    "Get the list of pinned 'path nodes' in the current session. Path nodes are entities marked by the analyst as important to the investigation — they serve as waypoints in the threat hunting workflow. Use to understand the current investigation focus.",
  category: "graph",
  version: 1,
  stability: "stable",
  inputSchema: z.object({}),
  outputSchema: z.unknown(),
  async execute(ctx) {
    return ctx.api.get("/path_nodes");
  },
});
