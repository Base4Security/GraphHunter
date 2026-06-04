import { z } from "zod";
import { defineTool } from "../../lib/types.js";
import { HEAVY } from "../../lib/api-client.js";

const input = z.object({
  node_id: z.string().max(500).describe("Entity ID to expand from"),
  mode: z
    .enum(["raw", "grouped"])
    .optional()
    .default("raw")
    .describe(
      "raw: return individual edges (replaces the old `expand_node`). grouped: collapse repeated edge types into per-type summaries with counts + first/last timestamps (replaces `expand_node_grouped`). Use grouped for high-degree nodes that would overflow the prompt as raw.",
    ),
  max_hops: z.number().int().min(1).max(5).optional().describe("Max hops (default 1)"),
  max_nodes: z
    .number()
    .int()
    .min(1)
    .max(500)
    .optional()
    .describe("Max nodes in result (default 50)"),
  live: z
    .boolean()
    .optional()
    .describe(
      "When true, hydrate this node from Sentinel (pull all of its events in the lookback window) before expanding, so the neighborhood is complete w.r.t. the SIEM. No-op on non-Sentinel sessions. Only applies to mode=raw.",
    ),
  lookback: z
    .enum(["1h", "6h", "24h", "7d", "30d"])
    .optional()
    .describe("Hydration window when live=true (default 24h)."),
});

export const nodeExpand = defineTool({
  name: "node_expand",
  description:
    "Expand from a node to get its neighbors (nodes and edges). Default mode=raw returns individual edges; mode=grouped returns per-edge-type summaries (better for hubs). Use to explore the graph from a starting node and find suspicious paths.",
  category: "node",
  version: 1,
  stability: "stable",
  inputSchema: input,
  outputSchema: z.unknown(),
  async execute(ctx, { node_id, mode, max_hops, max_nodes, live, lookback }) {
    const params: Record<string, string> = { node_id };
    if (max_hops != null) params.max_hops = String(max_hops);
    if (max_nodes != null) params.max_nodes = String(max_nodes);
    if (mode !== "grouped" && live) {
      params.live = "true";
      if (lookback) params.lookback = lookback;
    }
    const path = mode === "grouped" ? "/expand_grouped" : "/expand";
    return ctx.api.get(path, params, HEAVY);
  },
});
