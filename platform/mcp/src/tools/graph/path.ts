import { z } from "zod";
import { defineTool } from "../../lib/types.js";

const entity = z.object({ class: z.string().optional(), value: z.string().min(1) });

const input = z.object({
  from_entity: entity.describe("Origin entity. `value` is the graph id."),
  to_entity: entity
    .optional()
    .describe("Destination entity. Omit to return all outbound paths up to max_depth."),
  max_depth: z
    .number()
    .int()
    .min(1)
    .max(8)
    .optional()
    .describe("Maximum hop depth (default 4)."),
  edge_filter: z
    .array(z.string().min(1))
    .optional()
    .describe("Restrict traversal to these edge (relation) types."),
  max_paths: z
    .number()
    .int()
    .min(1)
    .max(500)
    .optional()
    .describe("Cap on paths returned (default 50)."),
});

export const graphPath = defineTool({
  name: "graph_path",
  description:
    "PHASE 4 / ANALYSIS (design doc §4.4): find paths between two entities in the built graph — or all outbound paths up to max_depth when to_entity is omitted. Reveals relation chains (e.g. Identity → IP → Role → Account) that in KQL would need several chained joins; here it's one traversal over precomputed structure. Each hop reports the edge taken and the node's class/value (IP nodes include geoip when enriched). Pure graph read — no Sentinel round-trip. Build the graph first with graph_build.",
  category: "graph",
  version: 1,
  stability: "experimental",
  inputSchema: input,
  outputSchema: z.unknown(),
  async execute(ctx, { from_entity, to_entity, max_depth, edge_filter, max_paths }) {
    const body: Record<string, unknown> = { from_entity };
    if (to_entity) body.to_entity = to_entity;
    if (max_depth != null) body.max_depth = max_depth;
    if (edge_filter) body.edge_filter = edge_filter;
    if (max_paths != null) body.max_paths = max_paths;
    return ctx.api.post("/graph/path", body);
  },
});
