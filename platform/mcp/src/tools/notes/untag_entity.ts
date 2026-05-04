import { z } from "zod";
import { defineTool } from "../../lib/types.js";

const input = z.object({
  node_id: z.string().max(500),
  tag: z.string().min(1).max(100),
});

export const untagEntity = defineTool({
  name: "untag_entity",
  description:
    "Remove a tag previously applied with tag_entity. No-op if the (node_id, tag) pair was not tagged.",
  category: "notes",
  version: 1,
  stability: "stable",
  inputSchema: input,
  outputSchema: z.unknown(),
  async execute(ctx, { node_id, tag }) {
    return ctx.api.post("/untag", { node_id, tag });
  },
});
