import { z } from "zod";
import { defineTool } from "../../lib/types.js";

export const getNotes = defineTool({
  name: "get_notes",
  description:
    "Get all notes in the current session. Notes are analyst observations, findings, or reports — optionally linked to specific graph nodes. Use to read the analyst's existing findings and build on their investigation.",
  category: "notes",
  version: 1,
  stability: "stable",
  inputSchema: z.object({}),
  outputSchema: z.unknown(),
  async execute(ctx) {
    return ctx.api.get("/notes/list");
  },
});
