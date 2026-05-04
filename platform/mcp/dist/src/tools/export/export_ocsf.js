import { z } from "zod";
import { defineTool } from "../../lib/types.js";
import { HEAVY } from "../../lib/api-client.js";
const input = z.object({
    dataset_id: z
        .string()
        .max(500)
        .optional()
        .describe("Restrict the export to triples from this dataset. Omit to export every dataset."),
    format: z
        .enum(["json", "ndjson"])
        .optional()
        .default("ndjson")
        .describe("Output format: 'ndjson' (one event per line, streaming-friendly) or 'json' (single array)"),
});
export const exportOcsf = defineTool({
    name: "export_ocsf",
    description: "Export every triple in the session — or a single dataset — as OCSF v1.4 events carrying Graph Hunter's Provenance Extension (schema_version, parser_name, mapping_id, mapping_hash, source_dataset_id, raw_event_sha256). Use when you need an auditable canonical view of the graph for cold storage, downstream SIEM ingest, or mapping audits. Shapes outside the shipping subset (Authentication, Process/Network/DNS/File/Registry activity) fall into the `Other` variant with a diagnostic reason instead of being silently dropped. `format='ndjson'` streams one event per line; `format='json'` returns a single JSON array.",
    category: "export",
    version: 1,
    stability: "stable",
    resultFormat: "text",
    inputSchema: input,
    outputSchema: z.string(),
    async execute(ctx, { dataset_id, format }) {
        const body = { format };
        if (dataset_id != null)
            body.dataset_id = dataset_id;
        const v = (await ctx.api.post("/export_ocsf", body, HEAVY));
        return v.data;
    },
});
