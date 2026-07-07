import { z } from "zod";
import { defineTool } from "../../lib/types.js";
import { HEAVY } from "../../lib/api-client.js";

const input = z.object({
  proposal_id: z
    .string()
    .min(1)
    .describe("Id of a proposal returned by graph_propose (session-scoped)."),
  lookback: z
    .enum(["1h", "6h", "24h", "7d", "30d"])
    .optional()
    .describe("Materialization window; the proposal's own TimeGenerated filter wins if present."),
  enrich: z
    .array(z.enum(["geoip", "asn", "threat_intel"]))
    .optional()
    .describe("Enrichments to apply at build (default: all declared on the schema). threat_intel is a no-op stub."),
  merge_mode: z
    .enum(["append", "replace"])
    .optional()
    .describe("append (default): add to the graph. replace: refresh this proposal's prior build (snapshot)."),
});

export const graphBuild = defineTool({
  name: "graph_build",
  description:
    "PHASE 3 / MATERIALIZATION (design doc §4.3): execute an approved proposal's materialization KQL against Sentinel, map rows to entities/relations per the schema, load them into the persistent graph, and apply enrichment ONCE at build time (geoip+asn on IP nodes; threat_intel is a stub). Returns entities/relations created, enrichment_applied, query cost, duration, and the new graph_state. Use merge_mode=replace to refresh a proposal's prior build. Run graph_propose first to get a proposal_id; after building, analyze with graph_neighbors / graph_path / graph_anomaly instead of re-querying Sentinel.",
  category: "graph",
  version: 1,
  stability: "experimental",
  inputSchema: input,
  outputSchema: z.unknown(),
  async execute(ctx, { proposal_id, lookback, enrich, merge_mode }) {
    const body: Record<string, unknown> = { proposal_id };
    if (lookback) body.lookback = lookback;
    if (enrich) body.enrich = enrich;
    if (merge_mode) body.merge_mode = merge_mode;
    return ctx.api.post("/graph/build", body, HEAVY);
  },
});
