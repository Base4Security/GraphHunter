import { z } from "zod";
import { defineTool } from "../../lib/types.js";
import { HEAVY } from "../../lib/api-client.js";

export const computeScores = defineTool({
  name: "compute_scores",
  description:
    "Recalculate all entity scores: degree centrality, PageRank, and betweenness. Use after enabling anomaly scoring or when you suspect scores are stale. Scores affect hunt result ranking and node_details output.",
  category: "scoring",
  version: 1,
  stability: "stable",
  inputSchema: z.object({}),
  outputSchema: z.unknown(),
  async execute(ctx) {
    return ctx.api.post("/compute_scores", {}, HEAVY);
  },
});
