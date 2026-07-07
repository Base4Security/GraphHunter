import { z } from "zod";
import { defineTool } from "../../lib/types.js";

export const sessionCheck = defineTool({
  name: "session_check",
  description:
    "Check if the GraphHunter desktop app is reachable and whether a session is loaded. Also reports graph_state (empty | partial | populated) and, when empty/partial, an advisory on how to populate the graph (sentinel_seed / sentinel_schema). Call this first before other tools to avoid timeouts or unclear errors.",
  category: "session",
  version: 1,
  stability: "stable",
  inputSchema: z.object({}),
  outputSchema: z.unknown(),
  async execute(ctx) {
    return ctx.api.get("/health");
  },
});
