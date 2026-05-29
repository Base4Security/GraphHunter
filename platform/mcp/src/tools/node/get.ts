import { z } from "zod";
import { defineTool } from "../../lib/types.js";
import { HEAVY } from "../../lib/api-client.js";

const input = z.object({
  node_id: z.string().max(500).describe("Entity ID"),
});

export const nodeGet = defineTool({
  name: "node_get",
  description:
    "Get detailed information about a node: scores, degrees, neighbor counts, time range. For the long-form anomaly narrative + score breakdown, use `node.score_explanation` instead.",
  category: "node",
  version: 1,
  stability: "stable",
  inputSchema: input,
  outputSchema: z.unknown(),
  async execute(ctx, { node_id }) {
    return ctx.api.get("/node_details", { node_id }, HEAVY);
  },
});
