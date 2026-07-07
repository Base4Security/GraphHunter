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
  dataset: z
    .string()
    .min(1)
    .max(200)
    .optional()
    .describe("Only with ingest=true: name this ingest as a refreshable layer — re-running with the same dataset name REPLACES it instead of duplicating (snapshot). Omit for a one-off append."),
  acknowledge_fallback: z
    .boolean()
    .optional()
    .describe("§4.7 fallback gate. An inspect query (ingest not true) that projects entity-class columns (IPs/identities) is NOT executed unless this is true — instead a ready-to-run graph_propose payload is returned. Prefer following that payload (graph_propose → graph_build); set true only to read rows out as a deliberate one-off raw-KQL fallback (logged)."),
});

export const sentinelQuery = defineTool({
  name: "sentinel_query",
  description:
    "ADVANCED escape hatch for raw KQL. For normal hunting prefer the graph-building flow — sentinel_seed (cold-start from an IoC), then node_enrich (pull a node's events) and node_expand / hunt_run plus graph analytics (heavy_edges, channel_behavior). GraphHunter's value is the correlated, persistent graph (cross-source entity unification, multi-hop paths, anomaly scoring), NOT the raw query — so reach for the graph tools first. Use sentinel_query only for arbitrary KQL those tools can't express, or to verify a hypothesis before committing data. Dual mode: ingest=false (default) returns rows to inspect WITHOUT changing the graph; ingest=true parses the results and ADDS them to the graph. Inspect mode does NOT populate the graph — to put data in the graph you MUST run with ingest=true (typical flow: inspect once to confirm the query, then re-run with ingest=true).",
  category: "sentinel",
  version: 1,
  stability: "stable",
  inputSchema: input,
  outputSchema: z.unknown(),
  async execute(ctx, { query, lookback, ingest, max_rows, dataset, acknowledge_fallback }) {
    const body: Record<string, unknown> = { kql: query, ingest: ingest ?? false };
    if (lookback) body.lookback = lookback;
    if (max_rows != null) body.max_rows = max_rows;
    if (dataset) body.dataset = dataset;
    if (acknowledge_fallback != null) body.acknowledge_fallback = acknowledge_fallback;
    return ctx.api.post("/kql", body, HEAVY);
  },
});
