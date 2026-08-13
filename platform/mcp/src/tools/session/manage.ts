import { z } from "zod";
import { defineTool } from "../../lib/types.js";

const createInput = z.object({
  name: z
    .string()
    .max(200)
    .optional()
    .describe("Human-readable session name. Defaults to 'Untitled'."),
});

export const sessionCreate = defineTool({
  name: "session_create",
  description:
    "Create an empty session and make it the current one. Ingest and hunt operations need a session; on a fresh GraphHunter process there is none, so this is the first call in any remote workflow. IMPORTANT: 'current' is process-global, not per-client -- if anything else is using the same GraphHunter, pass the returned session id explicitly to later calls instead of relying on the current-session fallback, or your data will interleave with theirs.",
  category: "session",
  version: 1,
  stability: "stable",
  inputSchema: createInput,
  outputSchema: z.unknown(),
  async execute(ctx, { name }) {
    const body: Record<string, unknown> = {};
    if (name != null) body.name = name;
    return ctx.api.post("/session/create", body);
  },
});

export const sessionList = defineTool({
  name: "session_list",
  description:
    "List available sessions -- those held in memory plus a scan of the session directory on disk. Use it to find an existing session id to pass to ingest or hunt calls rather than creating a new one.",
  category: "session",
  version: 1,
  stability: "stable",
  inputSchema: z.object({}),
  outputSchema: z.unknown(),
  async execute(ctx) {
    return ctx.api.get("/session/list");
  },
});
