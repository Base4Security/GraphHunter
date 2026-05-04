import { z } from "zod";
import { defineTool } from "../../lib/types.js";
const input = z.object({
    node_id: z.string().max(500).describe("Entity ID to tag"),
    tag: z
        .string()
        .min(1)
        .max(100)
        .describe("Tag label (convention: `ioc:malicious`, `benign:confirmed`, `investigated:fp`)"),
    reason: z.string().max(2000).optional().describe("Optional human-readable rationale"),
});
export const tagEntity = defineTool({
    name: "tag_entity",
    description: "Apply a tag to an entity (e.g. `ioc:malicious`, `benign:confirmed`, `investigated:fp`). Tags persist with the session and are queryable via list_tagged / exportable via export_iocs. Use to build an IoC list during a hunt instead of copy-pasting node IDs into external notes.",
    category: "notes",
    version: 1,
    stability: "stable",
    inputSchema: input,
    outputSchema: z.unknown(),
    async execute(ctx, { node_id, tag, reason }) {
        return ctx.api.post("/tag", { node_id, tag, reason: reason ?? undefined });
    },
});
