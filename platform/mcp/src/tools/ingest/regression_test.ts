import { z } from "zod";
import { defineTool } from "../../lib/types.js";
import { HEAVY } from "../../lib/api-client.js";

const input = z.object({
  candidate_vrl: z
    .string()
    .max(200_000)
    .describe("VRL source to evaluate. Typically sourced from an ingest.parser_generate draft."),
  baseline_dataset_id: z
    .string()
    .max(500)
    .describe("Dataset whose events are replayed through both baseline and candidate."),
  sample_size: z
    .number()
    .int()
    .min(1)
    .optional()
    .describe("Cap on rows to replay. Defaults to 1000."),
});

export const ingestRegressionTest = defineTool({
  name: "ingest_regression_test",
  description:
    "Replay a baseline dataset's events through a candidate VRL program and diff the resulting triples (Jaccard), OCSF field coverage, and invariant-violation counts against the live mapping. Returns verdict 'pass' | 'warn' | 'fail'. Zero production-graph writes — the candidate never touches the live state. Pair with ingest.parser_generate before promoting a new mapping via review(op=approve).",
  category: "ingest",
  version: 1,
  stability: "stable",
  inputSchema: input,
  outputSchema: z.unknown(),
  async execute(ctx, { candidate_vrl, baseline_dataset_id, sample_size }) {
    const body: Record<string, unknown> = { candidate_vrl, baseline_dataset_id };
    if (sample_size != null) body.sample_size = sample_size;
    return ctx.api.post("/mapping_regression_test", body, HEAVY);
  },
});
