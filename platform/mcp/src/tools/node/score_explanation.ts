import { z } from "zod";
import { defineTool } from "../../lib/types.js";

const input = z.object({
  node_id: z.string().max(500).describe("Entity ID to explain"),
});

export const nodeScoreExplanation = defineTool({
  name: "node_score_explanation",
  description:
    "Explain why a node has the score it has: the four-dimension anomaly breakdown (entity rarity, edge rarity, neighborhood concentration, temporal novelty), composite and degree percentiles against the whole graph, top-5 same-type peers, and a plain-English narrative. Use to distinguish structural centrality (e.g. /usr/bin/grep under MDE) from genuine anomalies before triaging a top_anomalies hit.",
  category: "node",
  version: 1,
  stability: "stable",
  inputSchema: input,
  outputSchema: z.unknown(),
  async execute(ctx, { node_id }) {
    return ctx.api.get("/explain_score", { node_id });
  },
});
