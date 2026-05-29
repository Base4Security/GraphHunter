import { z } from "zod";
import { defineTool } from "../../lib/types.js";

export const graphRelationSchema = defineTool({
  name: "graph_relation_schema",
  description:
    "List every (rel_type, source_type, target_type) triple actually present in the loaded graph, with edge counts and observed metadata keys. Call this BEFORE writing a hunt.run DSL — it's the cheapest way to confirm edge direction and discover which metadata keys can be used in filter predicates. Replaces trial-and-error hunt authoring with zero-result feedback. Response shape: `{ entries, _meta: { compute_ms, cache_hit } }` — `cache_hit=true` means the result came from the memoized schema cache, so an analyst can tell at a glance whether the warm path is working.",
  category: "graph",
  version: 1,
  stability: "stable",
  inputSchema: z.object({}),
  outputSchema: z.unknown(),
  async execute(ctx) {
    return ctx.api.get("/relation_schema");
  },
});
