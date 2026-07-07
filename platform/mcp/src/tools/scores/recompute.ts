import { z } from "zod";
import { defineTool } from "../../lib/types.js";
import { HEAVY } from "../../lib/api-client.js";

export const scoresRecompute = defineTool({
  name: "scores_recompute",
  description:
    "Recalculate all entity scores: degree centrality, PageRank, and betweenness. Use after a substantial ingest or when you suspect scores are stale. Scores affect hunt result ranking and node.get output. Note: anomaly scoring is now per-call via `hunt.run(scoring=anomaly)` and doesn't require a separate enable step.",
  category: "scores",
  version: 1,
  stability: "stable",
  inputSchema: z.object({}),
  outputSchema: z.unknown(),
  async execute(ctx) {
    return ctx.api.post("/compute_scores", {}, HEAVY);
  },
});
