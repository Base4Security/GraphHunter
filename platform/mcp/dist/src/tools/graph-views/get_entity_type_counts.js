import { z } from "zod";
import { defineTool } from "../../lib/types.js";
export const getEntityTypeCounts = defineTool({
    name: "get_entity_type_counts",
    description: "Get the count of entities for each type (e.g. 150 IPs, 42 Hosts, 30 Users). Use to understand the composition of the graph and identify which entity types are most prevalent.",
    category: "graph-views",
    version: 1,
    stability: "stable",
    inputSchema: z.object({}),
    outputSchema: z.unknown(),
    async execute(ctx) {
        return ctx.api.get("/entity_type_counts");
    },
});
