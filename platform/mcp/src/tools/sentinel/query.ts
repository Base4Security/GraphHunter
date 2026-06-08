import { z } from "zod";
import { defineTool } from "../../lib/types.js";
import { HEAVY } from "../../lib/api-client.js";

const input = z.object({
  query: z.string().max(10000).describe("The KQL query to run against the connected Sentinel workspace."),
  lookback: z
    .enum(["1h", "6h", "24h", "7d", "30d"])
    .optional()
    .describe("Optional time window shorthand; ignored if your KQL already filters TimeGenerated."),
  ingest: z
    .boolean()
    .optional()
    .describe("false (default): inspect rows only — does NOT add anything to the graph. true: parse the results and ADD them to the graph. Set true whenever the user wants the data IN the graph (to hunt/expand on it), not just to read it."),
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
    "Run a free-form KQL query against the connected Sentinel workspace. Dual mode: ingest=false (default) returns rows to inspect/verify a hypothesis WITHOUT changing the graph; ingest=true parses the results and adds them to the graph. IMPORTANT: inspect mode does NOT populate the graph — if the user wants the data in the graph (to hunt or expand on it), you MUST re-run with ingest=true. Typical flow: inspect once to confirm the query is right, then run again with ingest=true to load it. Use node_enrich for targeted per-node pulls; use this for arbitrary KQL.",
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
