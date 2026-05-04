import { z } from "zod";
import { defineTool } from "../../lib/types.js";
import { HEAVY } from "../../lib/api-client.js";
const input = z.object({
    format: z.enum(["stix21", "misp_csv", "kql_ioc_set", "sigma_stub"]).describe("Output format"),
    tag_prefix: z.string().max(100).optional().describe("Tag prefix filter (default `ioc:`)"),
});
export const exportIocs = defineTool({
    name: "export_iocs",
    description: "Export the session's tagged entities as a consumable IoC feed. Formats: `stix21` (STIX 2.1 bundle for MISP/ThreatStream), `misp_csv` (MISP import), `kql_ioc_set` (a `let IoC_IPs = datatable(...)` block ready to paste into Azure Sentinel hunting), `sigma_stub` (a Sigma rule seeded with the IoC set). `tag_prefix` defaults to `ioc:` so the common CSIRT workflow needs no args.",
    category: "export",
    version: 1,
    stability: "stable",
    resultFormat: "text",
    inputSchema: input,
    outputSchema: z.string(),
    async execute(ctx, { format, tag_prefix }) {
        const body = { format };
        if (tag_prefix != null)
            body.tag_prefix = tag_prefix;
        const v = await ctx.api.post("/export_iocs", body, HEAVY);
        return typeof v === "string" ? v : JSON.stringify(v);
    },
});
