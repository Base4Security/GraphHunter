import { z } from "zod";
import { defineTool } from "../../lib/types.js";
import { HEAVY } from "../../lib/api-client.js";

const input = z.object({
  hypothetical_vrl: z
    .string()
    .max(200_000)
    .describe(
      "VRL source to evaluate. Usually the `vrl_source` from an ingest.parser_generate draft.",
    ),
  dataset_id: z
    .string()
    .max(500)
    .describe("Dataset whose events provide the synthetic graph's inputs."),
  sample_size: z
    .number()
    .int()
    .min(1)
    .optional()
    .describe("Cap on rows to replay. Defaults to 1000."),
});

export const ingestInvariantsHypothetical = defineTool({
  name: "ingest_invariants_hypothetical",
  description:
    "Run the P1–P5 invariant suite against a *hypothetical* graph: replay a dataset's events through a candidate VRL program, project the resulting triples, and evaluate invariants over that synthetic graph. Lets you sanity-check a candidate mapping before approval without paying any ingest cost. Kept separate from ingest.invariants_live because the inputs are disjoint (live takes only an optional dataset_id; this requires both VRL + dataset_id).",
  category: "ingest",
  version: 1,
  stability: "stable",
  inputSchema: input,
  outputSchema: z.unknown(),
  async execute(ctx, { hypothetical_vrl, dataset_id, sample_size }) {
    const body: Record<string, unknown> = { hypothetical_vrl, dataset_id };
    if (sample_size != null) body.sample_size = sample_size;
    return ctx.api.post("/invariant_check_hypothetical", body, HEAVY);
  },
});
