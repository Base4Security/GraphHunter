import { z } from "zod";
import { defineTool } from "../../lib/types.js";
import { HEAVY } from "../../lib/api-client.js";

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

export const sessionCurrent = defineTool({
  name: "session_current",
  description:
    "The session that ingest and hunt calls fall back to when they omit an explicit handle. Returns null when none is selected -- in which case those calls fail, and session_create or session_load is the fix. Worth checking first in any workflow that does not pass session ids explicitly, since 'current' is shared across every client of this GraphHunter process.",
  category: "session",
  version: 1,
  stability: "stable",
  inputSchema: z.object({}),
  outputSchema: z.unknown(),
  async execute(ctx) {
    return ctx.api.get("/session/current");
  },
});

export const sessionLoad = defineTool({
  name: "session_load",
  description:
    "Load a previously saved session from disk and make it current, restoring its graph, datasets and tags. Use session_list to find the id. Deserializing a large graph takes a while, so this is a heavy call.",
  category: "session",
  version: 1,
  stability: "stable",
  inputSchema: z.object({
    session_id: z.string().min(1).max(200).describe("Session id, from session_list."),
  }),
  outputSchema: z.unknown(),
  async execute(ctx, { session_id }) {
    return ctx.api.post("/session/load", { session_id }, HEAVY);
  },
});

export const sessionSave = defineTool({
  name: "session_save",
  description:
    "Persist a session's graph and datasets to disk so it survives a restart and can be reopened with session_load. Ingested data is otherwise in-memory only and lost when the process exits.",
  category: "session",
  version: 1,
  stability: "stable",
  inputSchema: z.object({
    session_id: z.string().min(1).max(200).describe("Session to persist."),
  }),
  outputSchema: z.unknown(),
  async execute(ctx, { session_id }) {
    return ctx.api.post("/session/save", { session_id }, HEAVY);
  },
});
