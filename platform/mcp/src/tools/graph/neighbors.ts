import { z } from "zod";
import { defineTool } from "../../lib/types.js";

const input = z.object({
  entity: z
    .object({ class: z.string().optional(), value: z.string().min(1) })
    .describe("The central entity. `value` is the graph id; `class` is advisory."),
  degree: z
    .number()
    .int()
    .min(1)
    .max(4)
    .optional()
    .describe("Neighborhood expansion degree in hops (default 1)."),
  edge_filter: z
    .array(z.string().min(1))
    .optional()
    .describe("Restrict to these edge (relation) types."),
  max_nodes: z
    .number()
    .int()
    .min(1)
    .max(1000)
    .optional()
    .describe("Cap neighbors returned (default 100)."),
});

export const graphNeighbors = defineTool({
  name: "graph_neighbors",
  description:
    "PHASE 4 / ANALYSIS (design doc §4.5): return the immediate neighborhood of an entity in the built graph — the center's attributes plus every directly-connected entity and the edge metadata to each. This is the 'what else touched this entity?' tool; it answers in one call over the precomputed graph instead of new KQL. Pure graph read — no Sentinel round-trip. Build the graph first with graph_build (or sentinel_seed).",
  category: "graph",
  version: 1,
  stability: "experimental",
  inputSchema: input,
  outputSchema: z.unknown(),
  async execute(ctx, { entity, degree, edge_filter, max_nodes }) {
    const body: Record<string, unknown> = { entity };
    if (degree != null) body.degree = degree;
    if (edge_filter) body.edge_filter = edge_filter;
    if (max_nodes != null) body.max_nodes = max_nodes;
    return ctx.api.post("/graph/neighbors", body);
  },
});
