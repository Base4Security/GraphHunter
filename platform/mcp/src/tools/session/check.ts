import { z } from "zod";
import { defineTool } from "../../lib/types.js";

export const sessionCheck = defineTool({
  name: "session_check",
  description:
    "Check if the GraphHunter API (desktop app or headless graph-hunter-server) is reachable and whether a session is loaded. Also reports graph_state (empty | partial | populated) and, when it is not populated, how to populate it (ingest_load for files; the sentinel group for a SIEM). Call it first.",
  category: "session",
  version: 1,
  stability: "stable",
  inputSchema: z.object({}),
  outputSchema: z.unknown(),
  async execute(ctx) {
    return ctx.api.get("/health");
  },
});
