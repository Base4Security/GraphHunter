import { z } from "zod";
import { defineTool } from "../../lib/types.js";

const input = z.object({
  metric: z
    .enum(["degree", "betweenness", "isolation", "all"])
    .optional()
    .describe("Which structural metric to score (default all)."),
  node_class: z
    .string()
    .optional()
    .describe("Restrict to one node class; also scopes the z-score baseline."),
  top_n: z
    .number()
    .int()
    .min(1)
    .max(500)
    .optional()
    .describe("Number of anomalies to return (default 20)."),
});

export const graphAnomaly = defineTool({
  name: "graph_anomaly",
  description:
    "PHASE 4 / ANALYSIS (design doc §4.6): surface entities with atypical graph structure — unusually high degree (hub), high betweenness (bridges otherwise-separate clusters), or high isolation (weakly connected / rare for its class). Reports a z-score against the population (optionally scoped to a node_class) plus a human-readable observation. Pure graph read over the built graph — no Sentinel round-trip. Run graph_build / scoring first so centrality is populated.",
  category: "graph",
  version: 1,
  stability: "experimental",
  inputSchema: input,
  outputSchema: z.unknown(),
  async execute(ctx, { metric, node_class, top_n }) {
    const body: Record<string, unknown> = {};
    if (metric) body.metric = metric;
    if (node_class) body.node_class = node_class;
    if (top_n != null) body.top_n = top_n;
    return ctx.api.post("/graph/anomaly", body);
  },
});
