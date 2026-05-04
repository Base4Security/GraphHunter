import { z } from "zod";
import { defineTool } from "../../lib/types.js";
import { HEAVY } from "../../lib/api-client.js";

const input = z.object({
  node_id: z.string().max(500).describe("Entity ID"),
});

export const getNodeDetails = defineTool({
  name: "get_node_details",
  description:
    "Get detailed information about a node: scores, degrees, neighbor counts, time range.",
  category: "navigation",
  version: 1,
  stability: "stable",
  inputSchema: input,
  outputSchema: z.unknown(),
  async execute(ctx, { node_id }) {
    return ctx.api.get("/node_details", { node_id }, HEAVY);
  },
});
