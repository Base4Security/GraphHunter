import { z } from "zod";
import { defineTool } from "../../lib/types.js";
import { HEAVY } from "../../lib/api-client.js";

const input = z.object({
  entity_type: z
    .enum(["IP", "User", "Host", "Process", "File"])
    .describe("Type of the IoC you are seeding from."),
  value: z.string().max(1000).describe("The IoC value, e.g. an IP, UPN, hostname, or path."),
  lookback: z
    .enum(["1h", "6h", "24h", "7d", "30d"])
    .optional()
    .describe("Time window to pull from Sentinel (default 24h)."),
});

export const sentinelSeed = defineTool({
  name: "sentinel_seed",
  description:
    "Cold-start a hunt from a known Sentinel IoC. Pulls every event touching the IoC (IP/User/Host/Process/File) in the lookback window, ingests it into the graph (auto-creating a session if needed), and returns the seeded neighborhood + top anomalies. Use this FIRST when the graph is empty, then hunt_run / node_expand from the seeded nodes.",
  category: "sentinel",
  version: 1,
  stability: "stable",
  inputSchema: input,
  outputSchema: z.unknown(),
  async execute(ctx, { entity_type, value, lookback }) {
    const body: Record<string, unknown> = { entity_type, value };
    if (lookback) body.lookback = lookback;
    return ctx.api.post("/sentinel/seed", body, HEAVY);
  },
});
