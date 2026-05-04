import { z } from "zod";
import { defineTool } from "../../lib/types.js";
import { HEAVY } from "../../lib/api-client.js";
const input = z.object({
    node_ids: z
        .array(z.string().max(500))
        .max(1000)
        .describe("List of entity IDs to include in the export (max 1000)"),
    format: z.enum(["json", "csv"]).optional().default("json").describe("Export format: 'json' or 'csv'"),
});
export const exportSubgraph = defineTool({
    name: "export_subgraph",
    description: "Export the subgraph (nodes + edges) for given node IDs as JSON or CSV text. Use when you need the raw data for a set of entities — for example, to produce a detailed report of a suspicious path, or to analyze entity metadata in bulk.",
    category: "export",
    version: 1,
    stability: "stable",
    resultFormat: "text",
    inputSchema: input,
    outputSchema: z.string(),
    async execute(ctx, { node_ids, format }) {
        const v = (await ctx.api.post("/export_subgraph", { node_ids, format }, HEAVY));
        return v.data;
    },
});
