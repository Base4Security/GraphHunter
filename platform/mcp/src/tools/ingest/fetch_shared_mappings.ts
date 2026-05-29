import { z } from "zod";
import { defineTool } from "../../lib/types.js";

const input = z.object({
  fingerprint: z
    .string()
    .max(64)
    .optional()
    .describe("Exact-match fingerprint filter (e.g. 'fp-abc123…')."),
  ocsf_category: z.string().max(120).optional().describe("Exact-match category filter."),
  limit: z
    .number()
    .int()
    .min(1)
    .max(1000)
    .optional()
    .describe("Cap on returned summaries; sorts newest-first when set."),
});

export const ingestFetchSharedMappings = defineTool({
  name: "ingest_fetch_shared_mappings",
  description:
    "List published mappings from the shared library as compact summaries. Optionally filter by exact fingerprint or ocsf_category; pass `limit` to cap the page (newest first). Returns `total` pre-limit so the caller can paginate. The library lives on disk and is shared across sessions — drafts auto-publish on review(op=approve), and analysts can force-publish via ingest.publish_mapping.",
  category: "ingest",
  version: 1,
  stability: "stable",
  inputSchema: input,
  outputSchema: z.unknown(),
  async execute(ctx, { fingerprint, ocsf_category, limit }) {
    const body: Record<string, unknown> = {};
    if (fingerprint != null) body.fingerprint = fingerprint;
    if (ocsf_category != null) body.ocsf_category = ocsf_category;
    if (limit != null) body.limit = limit;
    return ctx.api.post("/fetch_shared_mappings", body);
  },
});
