import { z } from "zod";
import { defineTool } from "../../lib/types.js";
import { HEAVY } from "../../lib/api-client.js";

const input = z.object({
  raw_sample: z
    .string()
    .max(100_000)
    .describe("Small slice of raw events (typically 50–200 rows). Bounded by the caller."),
  dataset_id: z.string().max(500).optional().describe("Optional dataset to scope the proposal to."),
  hint_format: z
    .string()
    .max(100)
    .optional()
    .describe("Format hint ('csv', 'sysmon', 'generic', ...). Omit for auto-detect."),
  max_rounds: z
    .number()
    .int()
    .min(1)
    .max(10)
    .optional()
    .describe("Soft cap on negotiation rounds. Advisory in M4 (single pass)."),
});

export const ingestNegotiate = defineTool({
  name: "ingest_negotiate",
  description:
    "Propose a FieldConfig for a raw-log sample by running the deterministic preview heuristic first and only falling back to the local LLM when the heuristic yields nothing useful. Returns a draft_id referring to a pending MappingDraft in the session's review queue — approve via review(op=approve) to stamp the FieldConfig onto the target dataset. The LLM NEVER sees production events; only the `raw_sample` block passed here.",
  category: "ingest",
  version: 1,
  stability: "stable",
  inputSchema: input,
  outputSchema: z.unknown(),
  async execute(ctx, { raw_sample, dataset_id, hint_format, max_rounds }) {
    const body: Record<string, unknown> = { raw_sample };
    if (dataset_id != null) body.dataset_id = dataset_id;
    if (hint_format != null) body.hint_format = hint_format;
    if (max_rounds != null) body.max_rounds = max_rounds;
    return ctx.api.post("/ingest_negotiate", body, HEAVY);
  },
});
