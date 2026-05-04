import { z } from "zod";
import { defineTool } from "../../lib/types.js";
import { HEAVY } from "../../lib/api-client.js";
const input = z.object({
    watchlist_name: z
        .string()
        .min(1)
        .max(200)
        .describe("Human-readable watchlist name; will be normalized to an ARM alias (lowercased, spaces → _)"),
    display_name: z.string().max(200).optional().describe("Optional Sentinel displayName (defaults to watchlist_name)"),
    description: z.string().max(2000).optional().describe("Optional Sentinel description"),
    tag_prefix: z.string().max(100).optional().describe("Tag prefix filter (default `ioc:`)"),
    dry_run: z.boolean().optional().describe("When true, return payload + target URL without posting"),
    confirm: z.boolean().optional().describe("Must be true to actually POST (safety gate)"),
});
export const publishIocsToSentinel = defineTool({
    name: "publish_iocs_to_sentinel",
    description: "Publish the session's tagged IoCs as an Azure Sentinel Watchlist. Mutates the Sentinel tenant — requires three gates: (1) env GRAPHHUNTER_IOC_PUBLISH_ENABLED=1 on the GraphHunter process, (2) `confirm: true` in this call, (3) at least one entity tagged with the `tag_prefix` (default `ioc:`). Use `dry_run: true` first to preview the payload + target URL without posting. Required env vars: AZURE_TENANT_ID, AZURE_CLIENT_ID, AZURE_CLIENT_SECRET, AZURE_SUBSCRIPTION_ID, AZURE_RESOURCE_GROUP, AZURE_WORKSPACE_NAME. The service principal needs `Microsoft Sentinel Contributor` role on the workspace. Response includes `http_status`, `payload` (always), and `azure_response_body` when posted.",
    category: "integrations",
    version: 1,
    stability: "stable",
    inputSchema: input,
    outputSchema: z.unknown(),
    async execute(ctx, { watchlist_name, display_name, description, tag_prefix, dry_run, confirm }) {
        const body = { watchlist_name };
        if (display_name != null)
            body.display_name = display_name;
        if (description != null)
            body.description = description;
        if (tag_prefix != null)
            body.tag_prefix = tag_prefix;
        if (dry_run != null)
            body.dry_run = dry_run;
        if (confirm != null)
            body.confirm = confirm;
        return ctx.api.post("/publish_iocs_to_sentinel", body, HEAVY);
    },
});
