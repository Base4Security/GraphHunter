import { z } from "zod";
import { defineTool, type Tool } from "../../lib/types.js";

const input = z.object({
  op: z
    .enum(["start", "list", "get", "export", "stats", "expand"])
    .describe(
      "start: open a new hunt (rarely needed: the first API call opens one). list: summaries of past hunts. get: one hunt as {meta, events}. export: only its ordered event array. stats: token accounting for one hunt. expand: the FULL rows of that hunt's query that match `value`, to correlate columns within a row that the stored summary cannot show.",
    ),
  label: z
    .string()
    .max(200)
    .optional()
    .describe("op=start only. Human-readable label for the new hunt."),
  id: z
    .string()
    .max(200)
    .optional()
    .describe(
      "op=get / op=export / op=stats / op=expand only. The hunt id, as returned by op=list or op=start.",
    ),
  value: z
    .string()
    .max(500)
    .optional()
    .describe(
      "op=expand only, required. The value seen in the hunt's summary (e.g. a rare/singleton value or an aggregate top value) to expand into full matching rows.",
    ),
  column: z
    .string()
    .max(200)
    .optional()
    .describe(
      "op=expand only. Restrict the match to this column (exact, case-insensitive). Omit to match ANY field containing the value (case-insensitive substring).",
    ),
  limit: z
    .number()
    .int()
    .positive()
    .optional()
    .describe("op=expand only. Cap on the number of matched rows returned. Defaults server-side."),
});

interface JournalHuntRecord {
  events: unknown[];
  [key: string]: unknown;
}

export const journal = defineTool({
  name: "journal",
  description:
    "Audit trail of past hunts: every API call made, grouped by hunt, with redacted params, status, graph deltas and token accounting. Use it to reconstruct the route a hunt took (op=list, then op=get or op=export) or to check its cost (op=stats). It is not a data replay: responses are stored as compact summaries, so past findings cannot be re-materialized from it — except through op=expand, which re-runs the hunt's query for the rows matching one value.",
  category: "hunt",
  version: 1,
  stability: "stable",
  inputSchema: input,
  outputSchema: z.unknown(),
  async execute(ctx, { op, label, id, value, column, limit }) {
    if (op === "start") {
      return ctx.api.post("/journal/start", { label: label ?? undefined });
    }
    if (op === "list") {
      return ctx.api.get("/journal/list");
    }
    if (op === "get") {
      if (!id) throw new Error("op=get requires id");
      return ctx.api.get(`/journal/${id}`);
    }
    if (op === "stats") {
      if (!id) throw new Error("op=stats requires id");
      return ctx.api.get(`/journal/${id}/stats`);
    }
    if (op === "expand") {
      if (!id) throw new Error("op=expand requires id");
      if (!value) throw new Error("op=expand requires value");
      return ctx.api.post(`/journal/${id}/expand`, { value, column, limit });
    }
    // op === "export"
    if (!id) throw new Error("op=export requires id");
    // The backend also exposes POST /journal/export, which streams raw
    // NDJSON bytes (one JSON object per line, matching events.jsonl on
    // disk) for non-MCP callers (curl, file consumers) that want a
    // genuinely line-delimited wire format. That endpoint is unsuitable
    // for MCP tool results: the shared ApiClient (lib/api-client.ts)
    // always JSON.parses the entire response body (breaking on
    // multi-line NDJSON), and even if it didn't, returning a joined
    // NDJSON *string* would get re-escaped by the MCP content layer's
    // JSON.stringify, forcing the LLM to un-escape and re-split it
    // before use. Instead, reuse the already-JSON `GET /journal/:id`
    // route and return the events array itself as structured JSON —
    // the tool's `json` result format renders it cleanly with no
    // escaping round-trip.
    const record = (await ctx.api.get(`/journal/${id}`)) as JournalHuntRecord;
    return record.events;
  },
});

export const journalTools: Tool[] = [journal];
