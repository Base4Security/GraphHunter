import { z } from "zod";
import { defineTool } from "../../lib/types.js";
import { HEAVY } from "../../lib/api-client.js";
import { fieldConfigSchema } from "./field_config_schema.js";

const input = z.object({
  field_config: fieldConfigSchema,
  ocsf_category: z
    .string()
    .max(120)
    .optional()
    .describe("Carried verbatim into the program's provenance template."),
  optimization_hint: z
    .enum(["speed", "fidelity"])
    .optional()
    .describe("'speed' keeps deterministic output as-is; 'fidelity' allows LLM refinement."),
});

export const ingestParserGenerate = defineTool({
  name: "ingest_parser_generate",
  description:
    "Compile a FieldConfig to a deterministic VRL program (via field_config_to_vrl) and register the result as a pending MappingDraft in the review queue. Returns the VRL source and its mapping_hash (sha256 of the source). With optimization_hint='fidelity', the LLM is allowed to propose refinements — still gated by the review queue and (in M6) by constrained decoding, so malformed VRL can never be emitted.",
  category: "ingest",
  version: 1,
  stability: "stable",
  inputSchema: input,
  outputSchema: z.unknown(),
  async execute(ctx, { field_config, ocsf_category, optimization_hint }) {
    const body: Record<string, unknown> = { field_config };
    if (ocsf_category != null) body.ocsf_category = ocsf_category;
    if (optimization_hint != null) body.optimization_hint = optimization_hint;
    return ctx.api.post("/parser_generate", body, HEAVY);
  },
});
