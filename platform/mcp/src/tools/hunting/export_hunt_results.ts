import { z } from "zod";
import { defineTool } from "../../lib/types.js";
import { HEAVY } from "../../lib/api-client.js";

const input = z.object({
  format: z.enum(["json", "csv"]).optional().default("json").describe("Export format"),
  page: z.number().int().min(0).max(10000).optional().describe("Page index (0-based, default 0)."),
  page_size: z.number().int().min(1).max(10000).optional().describe("Page size (default = whole result set)."),
  aggregate: z.boolean().optional().describe("When true, collapse identical paths with an edge_count aggregate."),
});

export const exportHuntResults = defineTool({
  name: "export_hunt_results",
  description:
    "Export the results of the last run_hunt as JSON or CSV text. When `aggregate=true` (recommended for large result sets) identical paths collapse into one row with an edge_count column — drops the response size ~10x for spray-style hunts. `page`/`page_size` stream the deduped export.",
  category: "hunting",
  version: 1,
  stability: "stable",
  resultFormat: "text",
  inputSchema: input,
  outputSchema: z.string(),
  async execute(ctx, { format, page, page_size, aggregate }) {
    const body: Record<string, unknown> = { format };
    if (page != null) body.page = page;
    if (page_size != null) body.page_size = page_size;
    if (aggregate != null) body.aggregate = aggregate;
    const v = (await ctx.api.post("/export_hunt_results", body, HEAVY)) as {
      data: string;
      format: string;
    };
    return v.data;
  },
});
