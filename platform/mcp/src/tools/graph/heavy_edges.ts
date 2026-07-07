import { z } from "zod";
import { defineTool } from "../../lib/types.js";
import { HEAVY } from "../../lib/api-client.js";

const input = z.object({
  top_n: z.number().int().min(1).max(500).optional().describe("Max edge groups (default 50)."),
  min_count: z.number().int().min(1).optional().describe("Only groups with at least this many edges."),
  rel_type: z.string().optional().describe("Filter to one relation type (e.g. Connect, SNAT, Exposes)."),
});

export const graphHeavyEdges = defineTool({
  name: "graph_heavy_edges",
  description:
    "List the heaviest edges: repeated (source -> target : rel_type) groups ranked by connection count, with total bytes, total duration, %resets, and time span. Use to find high-volume channels / top talkers / noisy (reset-heavy) connections.",
  category: "graph",
  version: 1,
  stability: "stable",
  inputSchema: input,
  outputSchema: z.unknown(),
  async execute(ctx, { top_n, min_count, rel_type }) {
    const params: Record<string, string> = {};
    if (top_n != null) params.top_n = String(top_n);
    if (min_count != null) params.min_count = String(min_count);
    if (rel_type) params.rel_type = rel_type;
    return ctx.api.get("/heavy_edges", params, HEAVY);
  },
});
