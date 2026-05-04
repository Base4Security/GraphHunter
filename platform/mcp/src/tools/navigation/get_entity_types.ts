import { z } from "zod";
import { defineTool } from "../../lib/types.js";

export const getEntityTypes = defineTool({
  name: "get_entity_types",
  description:
    "List entity types present in the current graph (e.g. IP, Host, User, Process).",
  category: "navigation",
  version: 1,
  stability: "stable",
  inputSchema: z.object({}),
  outputSchema: z.unknown(),
  async execute(ctx) {
    return ctx.api.get("/entity_types");
  },
});
