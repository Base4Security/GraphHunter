import { z } from "zod";
import { defineTool } from "../../lib/types.js";
import { HEAVY } from "../../lib/api-client.js";

const input = z.object({
  bucket_size_seconds: z
    .number()
    .int()
    .min(60)
    .max(86_400)
    .optional()
    .describe("Bucket width in seconds, default 3600"),
});

export const graphTemporalHeatmap = defineTool({
  name: "graph_temporal_heatmap",
  description:
    "Get bucketed activity patterns per relation type. Default bucket is 1h; pass `bucket_size_seconds` (60..86400) to rebucket. Output densifies zero-count buckets between first and last event so gaps are explicit rather than silently skipped.",
  category: "graph",
  version: 1,
  stability: "stable",
  inputSchema: input,
  outputSchema: z.unknown(),
  async execute(ctx, { bucket_size_seconds }) {
    const params: Record<string, string> = {};
    if (bucket_size_seconds != null) params.bucket_size_seconds = String(bucket_size_seconds);
    return ctx.api.get("/temporal_heatmap", params, HEAVY);
  },
});
