import { z } from "zod";
import { defineTool } from "../../lib/types.js";

const input = z.object({
  include: z
    .array(z.enum(["diagnostics", "status"]))
    .optional()
    .default([])
    .describe(
      "Optional add-ons. 'diagnostics' merges in catalog-loader diagnostics (replaces old `get_catalog_diagnostics`). 'status' merges per-entry compatibility against the current graph (replaces old `get_catalog_with_status`). When empty (default), returns the bare catalog (replaces old `get_catalog`).",
    ),
});

export const catalogGet = defineTool({
  name: "catalog_get",
  description:
    "Get the catalog of pre-built threat-hunting hypotheses based on MITRE ATT&CK techniques. Each entry has an id, name, description, and DSL pattern that can be passed to hunt.run. Optional `include` parameter merges diagnostics from the catalog loader and/or per-entry compatibility against the current graph.",
  category: "catalog",
  version: 1,
  stability: "stable",
  inputSchema: input,
  outputSchema: z.unknown(),
  async execute(ctx, { include }) {
    const inc = include ?? [];
    const wantDiag = inc.includes("diagnostics");
    const wantStatus = inc.includes("status");
    const base = (await ctx.api.get(wantStatus ? "/catalog/status" : "/catalog")) as Record<
      string,
      unknown
    >;
    if (wantDiag) {
      const diag = await ctx.api.get("/catalog/diagnostics");
      return { ...base, diagnostics: diag };
    }
    return base;
  },
});
