import { z } from "zod";
import { defineTool } from "../../lib/types.js";
import { HEAVY } from "../../lib/api-client.js";

const input = z.object({
  node_id: z.string().max(500).describe("Existing graph node to enrich (also the value searched in Sentinel)."),
  tables: z
    .array(z.string().max(120))
    .max(20)
    .optional()
    .describe("Restrict to these Sentinel tables (default: all tables mapped for the node's type)."),
  lookback: z
    .enum(["1h", "6h", "24h", "7d", "30d"])
    .optional()
    .describe("Time window to pull from Sentinel (default 24h)."),
  max_rows: z
    .number()
    .int()
    .min(1)
    .max(5000)
    .optional()
    .describe("Cap rows pulled per table (default 1000)."),
  dataset: z
    .string()
    .min(1)
    .max(200)
    .optional()
    .describe("Name this enrichment as a refreshable layer — re-enriching with the same dataset name REPLACES it instead of duplicating (snapshot). Omit for a one-off append. Use a stable per-scenario/hypothesis name."),
});

export const nodeEnrich = defineTool({
  name: "node_enrich",
  description:
    "Pull a specific slice of an existing node's Sentinel events into the graph on demand. Use when you need a particular data point to enrich the graph — e.g. just this user's SigninLogs for the last 7d. Narrower than node_expand(live), which hydrates everything. Returns what was added (new entities/relations, tables hit).",
  category: "node",
  version: 1,
  stability: "stable",
  inputSchema: input,
  outputSchema: z.unknown(),
  async execute(ctx, { node_id, tables, lookback, max_rows, dataset }) {
    const body: Record<string, unknown> = { node_id };
    if (tables) body.tables = tables;
    if (lookback) body.lookback = lookback;
    if (max_rows != null) body.max_rows = max_rows;
    if (dataset) body.dataset = dataset;
    return ctx.api.post("/node/enrich", body, HEAVY);
  },
});
