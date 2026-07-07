import { z } from "zod";

export const fieldConfigSchema = z
  .object({ mappings: z.array(z.record(z.any())) })
  .passthrough()
  .describe("FieldConfig produced by preview_fields / ingest.negotiate.");
