import { z } from "zod";
import { defineTool } from "../../lib/types.js";
import { HEAVY } from "../../lib/api-client.js";

const input = z.object({
  top_n: z.number().int().min(1).max(500).optional().describe("Max channels (default 50)."),
  min_count: z.number().int().min(1).optional().describe("Only channels with at least this many edges (default 4)."),
  window_secs: z.number().int().min(1).optional().describe("Bucket size for reset/volume windows (default 60)."),
  rel_type: z.string().optional().describe("Filter to one relation type (e.g. Connect, SNAT)."),
  sort_by: z.enum(["beacon", "resets", "volume"]).optional().describe("Ranking signal (default beacon)."),
});

export const graphChannelBehavior = defineTool({
  name: "graph_channel_behavior",
  description:
    "Per-channel temporal behavior: detect beaconing (regular inter-arrival intervals -> beacon_score), reset bursts, and volume spikes for each (source -> target : rel_type). Use to find C2-like periodic channels, error storms, or exfil bursts that pure volume (graph_heavy_edges) misses.",
  category: "graph",
  version: 1,
  stability: "stable",
  inputSchema: input,
  outputSchema: z.unknown(),
  async execute(ctx, { top_n, min_count, window_secs, rel_type, sort_by }) {
    const params: Record<string, string> = {};
    if (top_n != null) params.top_n = String(top_n);
    if (min_count != null) params.min_count = String(min_count);
    if (window_secs != null) params.window_secs = String(window_secs);
    if (rel_type) params.rel_type = rel_type;
    if (sort_by) params.sort_by = sort_by;
    return ctx.api.get("/channel_behavior", params, HEAVY);
  },
});
