import { z } from "zod";
import { defineTool } from "../../lib/types.js";
import { HEAVY } from "../../lib/api-client.js";

const input = z.object({
  query: z.string().max(10000).describe("The KQL query to run against the connected Sentinel workspace."),
  lookback: z
    .enum(["1h", "6h", "24h", "7d", "30d"])
    .optional()
    .describe("Soft-sugar time window; ignored if your query already filters TimeGenerated."),
  ingest: z
    .boolean()
    .optional()
    .describe("false (default): return rows for inspection without touching the graph. true: parse + ingest into the graph."),
  max_rows: z
    .number()
    .int()
    .min(1)
    .max(1000)
    .optional()
    .describe("Cap rows returned in inspect mode (default 200)."),
});

export const sentinelQuery = defineTool({
  name: "sentinel_query",
  description:
    "Run a free-form KQL query against the connected Sentinel workspace. Dual mode: ingest=false (default) returns rows so you can inspect/verify a hypothesis without polluting the graph; ingest=true parses and ingests the results. Use node_enrich for targeted per-node pulls; use this for arbitrary KQL.",
  category: "sentinel",
  version: 1,
  stability: "stable",
  inputSchema: input,
  outputSchema: z.unknown(),
  async execute(ctx, { query, lookback, ingest, max_rows }) {
    const body: Record<string, unknown> = { kql: query, ingest: ingest ?? false };
    if (lookback) body.lookback = lookback;
    if (max_rows != null) body.max_rows = max_rows;
    return ctx.api.post("/kql", body, HEAVY);
  },
});
