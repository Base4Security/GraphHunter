import { z } from "zod";

export const fieldConfigSchema = z
  .object({ mappings: z.array(z.record(z.string(), z.any())) })
  .loose()
  .describe("FieldConfig produced by preview_fields / ingest.negotiate.");
