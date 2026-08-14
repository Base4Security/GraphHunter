import { z } from "zod";
import { defineTool } from "../../lib/types.js";

export const sentinelControl = defineTool({
  name: "sentinel_control",
  description:
    "Start or stop live ingest on the Sentinel connector. IMPORTANT: the connector registers in a PAUSED state, so op='resume' is required before any rows are ingested -- until you call it, sentinel_status reports a healthy connector and the graph stays empty, with no error anywhere to tell you why. op='pause' stops ingest without disconnecting; resuming picks up from the stored watermark rather than re-reading. Check sentinel_status after either call to confirm the transition.",
  category: "sentinel",
  version: 1,
  stability: "stable",
  inputSchema: z.object({
    op: z.enum(["resume", "pause"]).describe("resume = start live ingest; pause = stop it."),
  }),
  outputSchema: z.unknown(),
  async execute(ctx, { op }) {
    return ctx.api.post(`/sentinel/${op}`, {});
  },
});
