import { z } from "zod";
import { defineTool } from "../../lib/types.js";

const input = z.object({
  dataset_id: z.string().max(500).describe("Dataset to inspect."),
  window_secs: z
    .number()
    .int()
    .min(60)
    .optional()
    .describe("Aggregation window in seconds. Defaults to 3600."),
});

export const ingestSchemaDrift = defineTool({
  name: "ingest_schema_drift",
  description:
    "Report per-field drift signals for a dataset — type-tag histogram mix, null-rate EWMA, and a recommended action ('none' | 'review' | 'renegotiate'). Backed by the drift store written by the ingest path; no LLM is consulted. Use as a scheduled trigger for re-running ingest.negotiate when a source starts producing novel field shapes.",
  category: "ingest",
  version: 1,
  stability: "stable",
  inputSchema: input,
  outputSchema: z.unknown(),
  async execute(ctx, { dataset_id, window_secs }) {
    const body: Record<string, unknown> = { dataset_id };
    if (window_secs != null) body.window_secs = window_secs;
    return ctx.api.post("/schema_drift_detect", body);
  },
});
