import { z } from "zod";
import { defineTool } from "../../lib/types.js";
import { HEAVY } from "../../lib/api-client.js";
const input = z.object({
    node_id: z.string().max(500).describe("Entity ID to get events for"),
    page: z.number().int().min(0).max(10000).optional().default(0).describe("Page index (0-based)"),
    page_size: z.number().int().min(1).max(200).optional().default(50).describe("Events per page (default 50)"),
    sort_by: z.enum(["timestamp", "rel_type", "source", "target"]).optional().describe("Sort field"),
});
export const getEventsPaginated = defineTool({
    name: "get_events_paginated",
    description: "Get paginated and sortable events (relations/edges) for a node. Returns events where the node is source or target. Supports sort_by: 'timestamp' (chronological order), 'rel_type', 'source', 'target'. Returns total_count for pagination. Better than get_events_for_node when the node has many connections.",
    category: "navigation",
    version: 1,
    stability: "stable",
    inputSchema: input,
    outputSchema: z.unknown(),
    async execute(ctx, { node_id, page, page_size, sort_by }) {
        const params = {
            node_id,
            page: String(page),
            page_size: String(page_size),
        };
        if (sort_by)
            params.sort_by = sort_by;
        return ctx.api.get("/events_paginated", params, HEAVY);
    },
});
