import { z } from "zod";
import { defineTool } from "../../lib/types.js";
export const getCatalogDiagnostics = defineTool({
    name: "get_catalog_diagnostics",
    description: "Return any diagnostics the catalog loader collected at startup. Empty array means every built-in YAML and every user-supplied YAML under $GRAPHHUNTER_CATALOG_DIR parsed + validated cleanly. Non-empty entries carry `source_path`, `entry_id`, and `message` — use to surface to the analyst that their custom catalog YAMLs were silently skipped.",
    category: "catalogs",
    version: 1,
    stability: "stable",
    inputSchema: z.object({}),
    outputSchema: z.unknown(),
    async execute(ctx) {
        return ctx.api.get("/catalog/diagnostics");
    },
});
