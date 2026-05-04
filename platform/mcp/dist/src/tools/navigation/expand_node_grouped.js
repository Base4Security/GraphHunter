import { z } from "zod";
import { defineTool } from "../../lib/types.js";
import { HEAVY } from "../../lib/api-client.js";
const input = z.object({
    node_id: z.string().max(500).describe("Entity ID to expand from"),
    max_hops: z.number().int().min(1).max(5).optional().describe("Max hops (default 1)"),
    max_nodes: z.number().int().min(1).max(500).optional().describe("Max nodes in result (default 50)"),
});
export const expandNodeGrouped = defineTool({
    name: "expand_node_grouped",
    description: "Expand a node's neighborhood with edge GROUPING — collapses repeated edge types into summaries (e.g. '42 Connect edges to IPs' instead of 42 individual edges). Use for HIGH-DEGREE nodes where expand_node would return too much data or timeout. Returns grouped neighbor edges with counts, first/last timestamps per group.",
    category: "navigation",
    version: 1,
    stability: "stable",
    inputSchema: input,
    outputSchema: z.unknown(),
    async execute(ctx, { node_id, max_hops, max_nodes }) {
        const params = { node_id };
        if (max_hops != null)
            params.max_hops = String(max_hops);
        if (max_nodes != null)
            params.max_nodes = String(max_nodes);
        return ctx.api.get("/expand_grouped", params, HEAVY);
    },
});
