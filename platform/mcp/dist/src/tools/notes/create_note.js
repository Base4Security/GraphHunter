import { z } from "zod";
import { defineTool } from "../../lib/types.js";
const input = z.object({
    content: z.string().max(50000).describe("Note content (e.g. markdown or plain text report)."),
    node_id: z
        .string()
        .max(500)
        .optional()
        .describe("Optional entity/node ID to link this note to."),
});
export const createNote = defineTool({
    name: "create_note",
    description: "Add a note to the current GraphHunter session. Use for saving hunt reports or findings. Optional node_id links the note to a graph node.",
    category: "notes",
    version: 1,
    stability: "stable",
    inputSchema: input,
    outputSchema: z.unknown(),
    async execute(ctx, { content, node_id }) {
        return ctx.api.post("/notes", { content, node_id: node_id ?? undefined });
    },
});
