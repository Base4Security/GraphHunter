import { z } from "zod";
import { defineTool } from "../../lib/types.js";
import { HEAVY } from "../../lib/api-client.js";

const input = z.object({
  selected_fields: z
    .array(z.object({ table: z.string().min(1), field: z.string().min(1) }))
    .min(1)
    .describe("Fields chosen from schema_discover, as {table, field} pairs."),
  hypothesis_context: z
    .string()
    .max(2000)
    .optional()
    .describe("Free-text hunt description to orient the proposal's wording."),
  max_proposals: z
    .number()
    .int()
    .min(1)
    .max(10)
    .optional()
    .describe("Max candidate schemas to return (default 3)."),
  lookback: z
    .enum(["1h", "6h", "24h", "7d", "30d"])
    .optional()
    .describe("Window spliced into the materialization KQL + estimate probe (default 24h)."),
});

export const graphPropose = defineTool({
  name: "graph_propose",
  description:
    "PHASE 2 / MAPPING (design doc §4.2): from fields picked in schema_discover, propose candidate graph schemas — each with its nodes, edges, and the exact materialization_kql graph_build will run. Proposals are persisted in the session; pass a proposal_id to graph_build to materialize it. estimated_entities/relations are a best-effort probe when Azure creds are set. This is where the graph schema is decided explicitly instead of improvised — call it after schema_discover and before graph_build.",
  category: "graph",
  version: 1,
  stability: "experimental",
  inputSchema: input,
  outputSchema: z.unknown(),
  async execute(ctx, { selected_fields, hypothesis_context, max_proposals, lookback }) {
    const body: Record<string, unknown> = { selected_fields };
    if (hypothesis_context != null) body.hypothesis_context = hypothesis_context;
    if (max_proposals != null) body.max_proposals = max_proposals;
    if (lookback) body.lookback = lookback;
    return ctx.api.post("/graph/propose", body, HEAVY);
  },
});
