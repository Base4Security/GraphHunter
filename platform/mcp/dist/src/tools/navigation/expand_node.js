import { z } from "zod";
import { defineTool } from "../../lib/types.js";
import { HEAVY } from "../../lib/api-client.js";
const input = z.object({
    node_id: z.string().max(500).describe("Entity ID to expand from"),
    max_hops: z.number().int().min(1).max(5).optional().describe("Max hops (default 1)"),
    max_nodes: z.number().int().min(1).max(500).optional().describe("Max nodes in result (default 50)"),
});
export const expandNode = defineTool({
    name: "expand_node",
    description: "Expand from a node to get its neighbors (nodes and edges). Use to explore the graph from a starting node and find suspicious paths.",
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
        return ctx.api.get("/expand", params, HEAVY);
    },
});
