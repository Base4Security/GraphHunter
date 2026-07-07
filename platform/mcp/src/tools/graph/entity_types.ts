import { z } from "zod";
import { defineTool } from "../../lib/types.js";

const input = z.object({
  with_counts: z
    .boolean()
    .optional()
    .default(false)
    .describe(
      "When false (default), return just the list of entity types. When true, also include per-type entity counts (replaces the old `get_entity_type_counts` tool).",
    ),
});

export const graphEntityTypes = defineTool({
  name: "graph_entity_types",
  description:
    "List entity types present in the current graph (e.g. IP, Host, User, Process). Pass `with_counts=true` to also get per-type cardinality (e.g. 150 IPs, 42 Hosts, 30 Users) — useful for understanding graph composition.",
  category: "graph",
  version: 1,
  stability: "stable",
  inputSchema: input,
  outputSchema: z.unknown(),
  async execute(ctx, { with_counts }) {
    if (with_counts) return ctx.api.get("/entity_type_counts");
    return ctx.api.get("/entity_types");
  },
});
