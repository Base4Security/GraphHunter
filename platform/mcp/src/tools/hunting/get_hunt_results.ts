import { z } from "zod";
import { defineTool } from "../../lib/types.js";

const input = z.object({
  page: z.number().int().min(0).max(10000).optional().default(0).describe("Page index (0-based)."),
  page_size: z.number().int().min(1).max(200).optional().default(20).describe("Number of paths per page."),
  min_score: z.number().min(0).max(100).optional().describe("Filter paths by max node score (0–100)."),
});

export const getHuntResults = defineTool({
  name: "get_hunt_results",
  description:
    "Get one page of the last run_hunt results. When anomaly scoring is enabled, paths include anomaly_score and anomaly_breakdown (including gnn_threat) and are sorted by anomaly (highest first). When scoring is not enabled, paths still include max_score and total_score (structural scores) and are sorted by those; anomaly_score and anomaly_breakdown will be null/absent. Use total_paths and filtered_paths in the response to decide whether to fetch more pages (higher page or larger page_size). Call run_hunt first.",
  category: "hunting",
  version: 1,
  stability: "stable",
  inputSchema: input,
  outputSchema: z.unknown(),
  async execute(ctx, { page, page_size, min_score }) {
    const params: Record<string, string> = {
      page: String(page),
      page_size: String(page_size),
    };
    if (min_score != null && !Number.isNaN(min_score)) params.min_score = String(min_score);
    return ctx.api.get("/hunt_results", params);
  },
});
