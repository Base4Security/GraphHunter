import { z } from "zod";
import { defineTool } from "../../lib/types.js";

const input = z.object({});

export const sentinelStatus = defineTool({
  name: "sentinel_status",
  description:
    "Read-only Sentinel connection state: whether a connector is registered, its status (Paused/Polling/...), and connector id. Check this before running sentinel_query / node_enrich so you know a workspace is reachable.",
  category: "sentinel",
  version: 1,
  stability: "stable",
  inputSchema: input,
  outputSchema: z.unknown(),
  async execute(ctx) {
    return ctx.api.get("/sentinel_status");
  },
});
