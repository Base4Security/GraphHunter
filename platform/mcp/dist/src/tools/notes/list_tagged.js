import { z } from "zod";
import { defineTool } from "../../lib/types.js";
const input = z.object({
    tag_prefix: z.string().max(100).optional().describe("Optional prefix filter (e.g. `ioc:`)"),
});
export const listTagged = defineTool({
    name: "list_tagged",
    description: "List all entity tags in the current session, optionally filtered by prefix (e.g. `ioc:` to list IoCs only). Returns `{node_id, tag, reason?, created_at}` entries.",
    category: "notes",
    version: 1,
    stability: "stable",
    inputSchema: input,
    outputSchema: z.unknown(),
    async execute(ctx, { tag_prefix }) {
        const params = {};
        if (tag_prefix)
            params.tag_prefix = tag_prefix;
        return ctx.api.get("/tags", params);
    },
});
