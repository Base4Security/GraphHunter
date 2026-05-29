import { z } from "zod";
import { defineTool } from "../../lib/types.js";

export const graphSummary = defineTool({
  name: "graph_summary",
  description:
    "Get a comprehensive summary of the entire graph: entity counts, relation counts, type distribution, time range, and top anomalies. This is the best starting point for understanding what data is in the graph. Call this first to orient yourself before diving into specific entities or hunts.",
  category: "graph",
  version: 1,
  stability: "stable",
  inputSchema: z.object({}),
  outputSchema: z.unknown(),
  async execute(ctx) {
    return ctx.api.get("/graph_summary");
  },
});
