import { z } from "zod";
import { defineTool } from "../../lib/types.js";

const input = z.object({
  draft_id: z.string().max(200).describe("draft_id from any prior ingest.* / review tool call."),
  ocsf_category: z
    .string()
    .max(120)
    .optional()
    .describe("Optional OCSF class to stamp on the entry (e.g. 'authentication', 'process_activity')."),
});

export const ingestPublishMapping = defineTool({
  name: "ingest_publish_mapping",
  description:
    "Force-publish any review-queue draft (Pending / Approved / Rejected) to the shared mapping library. Mirrors what review(op=approve) does as a side effect, but is the analyst path: stamps PublishSource::Manual so audit can distinguish auto-publication from explicit override. Errors with InvalidState when the mapping library is not configured (headless / tests) or when the draft has no field_config to fingerprint.",
  category: "ingest",
  version: 1,
  stability: "stable",
  inputSchema: input,
  outputSchema: z.unknown(),
  async execute(ctx, { draft_id, ocsf_category }) {
    const body: Record<string, unknown> = { draft_id };
    if (ocsf_category != null) body.ocsf_category = ocsf_category;
    return ctx.api.post("/publish_mapping", body);
  },
});
