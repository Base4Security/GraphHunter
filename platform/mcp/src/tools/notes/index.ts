import { z } from "zod";
import { defineTool, type Tool } from "../../lib/types.js";

const input = z.object({
  op: z
    .enum(["add", "list"])
    .describe("Discriminator. add: create a new note. list: read all session notes."),
  content: z
    .string()
    .max(50_000)
    .optional()
    .describe("Note content (markdown or plain text). Required for op=add."),
  node_id: z
    .string()
    .max(500)
    .optional()
    .describe("Optional entity ID to link the note to (op=add only)."),
});

export const notes = defineTool({
  name: "notes",
  description:
    "Manage session notes. op=add saves an analyst observation/finding/report (optionally linked to a node); op=list returns every note in the current session. Use to read the analyst's prior work and append to it.",
  category: "notes",
  version: 1,
  stability: "stable",
  inputSchema: input,
  outputSchema: z.unknown(),
  async execute(ctx, { op, content, node_id }) {
    if (op === "add") {
      if (!content) throw new Error("op=add requires content");
      return ctx.api.post("/notes", { content, node_id: node_id ?? undefined });
    }
    return ctx.api.get("/notes/list");
  },
});

export const notesTools: Tool[] = [notes];
