import { z } from "zod";
import { defineTool } from "../../lib/types.js";
import { fieldConfigSchema } from "./field_config_schema.js";

const input = z.object({
  field_config: fieldConfigSchema,
  target_ocsf_category: z
    .string()
    .max(120)
    .optional()
    .describe("Pin a specific OCSF category; mapper warns if deterministic choice disagrees."),
});

export const ingestCanonicalMap = defineTool({
  name: "ingest_canonical_map",
  description:
    "Given a FieldConfig, decide which OCSF v1.4 category it projects to (process_activity, network_activity, authentication, dns_activity, file_activity, or 'other') and return a ProvenanceTemplate stamp. The common cases are pinned deterministically by entity-type signature; the LLM is only consulted when a target_ocsf_category is supplied that contradicts the deterministic pick.",
  category: "ingest",
  version: 1,
  stability: "stable",
  inputSchema: input,
  outputSchema: z.unknown(),
  async execute(ctx, { field_config, target_ocsf_category }) {
    const body: Record<string, unknown> = { field_config };
    if (target_ocsf_category != null) body.target_ocsf_category = target_ocsf_category;
    return ctx.api.post("/canonical_map", body);
  },
});
