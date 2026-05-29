import { z } from "zod";
import { defineTool } from "../../lib/types.js";
import { HEAVY } from "../../lib/api-client.js";

const input = z.object({
  dataset_id: z
    .string()
    .max(500)
    .optional()
    .describe(
      "Restrict the check to this dataset. Omit to run against every dataset in the session.",
    ),
});

export const ingestInvariantsLive = defineTool({
  name: "ingest_invariants_live",
  description:
    "Run the shipped first-order invariants over the current session's graph (or a single dataset) and return a per-predicate report. Predicates: P1 causal monotonicity (timestamps along source→dest chains are non-decreasing), P2 type-shape plausibility (each (src_type, rel_type, dst_type) triple is in the catalog), P3 identity coherence (no illegal same-timestamp self-loops), P4 referential closure (every endpoint resolves to an entity in scope). Also returns a treewidth upper bound on the type-quotient graph with an explicit method tag. Use after ingest to audit a mapping, or before trusting a detection query that assumes causal order. P5 (rarity sanity) is reserved and currently reports 'skipped'. For evaluating a *candidate* VRL before approval, use ingest.invariants_hypothetical instead — its inputs are disjoint, so the two stay separate tools.",
  category: "ingest",
  version: 1,
  stability: "stable",
  inputSchema: input,
  outputSchema: z.unknown(),
  async execute(ctx, { dataset_id }) {
    const body: Record<string, unknown> = {};
    if (dataset_id != null) body.dataset_id = dataset_id;
    return ctx.api.post("/check_invariants", body, HEAVY);
  },
});
