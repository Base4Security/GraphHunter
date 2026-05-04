import { z } from "zod";
import { defineTool } from "../../lib/types.js";
import { HEAVY } from "../../lib/api-client.js";
const input = z.object({
    node_id: z.string().max(500).describe("Entity ID"),
});
export const getEventsForNode = defineTool({
    name: "get_events_for_node",
    description: "Get all relations/events for a node (incoming and outgoing edges).",
    category: "navigation",
    version: 1,
    stability: "stable",
    inputSchema: input,
    outputSchema: z.unknown(),
    async execute(ctx, { node_id }) {
        return ctx.api.get("/events_for_node", { node_id }, HEAVY);
    },
});
