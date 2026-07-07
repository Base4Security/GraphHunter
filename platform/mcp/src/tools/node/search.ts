import { z } from "zod";
import { defineTool } from "../../lib/types.js";

const input = z.object({
  q: z.string().max(1000).describe("Search query (substring match)"),
  type: z.string().max(100).optional().describe("Optional entity type filter"),
  limit: z.number().int().min(1).max(500).optional().describe("Max results (default 50)"),
});

export const nodeSearch = defineTool({
  name: "node_search",
  description:
    "Search entities by substring. Use to find nodes by ID, name, or metadata. Optional type filter (e.g. IP, Host).",
  category: "node",
  version: 1,
  stability: "stable",
  inputSchema: input,
  outputSchema: z.unknown(),
  async execute(ctx, { q, type, limit }) {
    const params: Record<string, string> = { q };
    if (type) params.type = type;
    if (limit != null) params.limit = String(limit);
    return ctx.api.get("/search", params);
  },
});
