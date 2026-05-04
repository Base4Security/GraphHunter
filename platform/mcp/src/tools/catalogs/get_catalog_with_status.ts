import { z } from "zod";
import { defineTool } from "../../lib/types.js";

export const getCatalogWithStatus = defineTool({
  name: "get_catalog_with_status",
  description:
    "Return the ATT&CK hypothesis catalog with per-entry compatibility checked against the current graph. Each entry has `compatible:bool` plus `missing_entity_types`/`missing_rel_types` when the dataset can't support the pattern. Use this instead of `get_catalog` to avoid running patterns that were never going to match (e.g. DARPA-style Process patterns against a cloud-identity dataset).",
  category: "catalogs",
  version: 1,
  stability: "stable",
  inputSchema: z.object({}),
  outputSchema: z.unknown(),
  async execute(ctx) {
    return ctx.api.get("/catalog/status");
  },
});
