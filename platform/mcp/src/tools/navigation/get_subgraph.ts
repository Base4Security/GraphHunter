import { z } from "zod";
import { defineTool } from "../../lib/types.js";
import { HEAVY } from "../../lib/api-client.js";

const input = z.object({
  node_ids: z
    .array(z.string().max(500))
    .max(1000)
    .describe("List of entity IDs (max 1000)"),
});

export const getSubgraph = defineTool({
  name: "get_subgraph",
  description: "Get the subgraph (nodes and edges) for a list of node IDs.",
  category: "navigation",
  version: 1,
  stability: "stable",
  inputSchema: input,
  outputSchema: z.unknown(),
  async execute(ctx, { node_ids }) {
    return ctx.api.post("/subgraph", { node_ids }, HEAVY);
  },
});
