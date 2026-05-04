import { z } from "zod";
import { defineTool } from "../../lib/types.js";
import { HEAVY } from "../../lib/api-client.js";

export const getSubnetAnalysis = defineTool({
  name: "get_subnet_analysis",
  description:
    "Analyze IP entities by /24 subnet: groups all IPs in the graph by their network segment, shows whether each subnet is internal or external, aggregates byte counts, and lists connected services. Use to identify which network segments are most active, detect lateral movement within subnets, or find unusual external destinations.",
  category: "graph-views",
  version: 1,
  stability: "stable",
  inputSchema: z.object({}),
  outputSchema: z.unknown(),
  async execute(ctx) {
    return ctx.api.get("/subnet_analysis", undefined, HEAVY);
  },
});
