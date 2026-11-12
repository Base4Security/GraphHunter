import { z } from "zod";
import { defineTool, type Tool } from "../../lib/types.js";

const input = z.object({
  op: z
    .enum(["start", "list", "get", "export", "stats", "expand"])
    .describe(
      "Discriminator. start: open a new hunt (rarely needed — the first captured API call already lazily opens one). list: summaries of every past hunt (id, label, timestamps, event/entity/relation counts). get: hunt metadata plus its events, as {meta, events} — use this for hunt context (label, timestamps, counts) alongside the event log. export: just that hunt's full ordered event array as structured JSON — an audit trail of the route taken (redacted params, status, topology deltas, token accounting per step), not the underlying data; use this to reconstruct what a prior hunt did, not to replay or re-materialize its results. stats: per-hunt token accounting — {hunt_id, cumulative_est_tokens, event_count, by_kind} — the measured proof that journaling summaries instead of full response bodies is cheaper. expand: re-runs the hunt's query filtered to rows matching a value from the summary (e.g. a `rare` value or an aggregate top value), returning those FULL rows so the agent can correlate columns within a row cheaply — instead of re-dumping the whole result. This is how to resolve a row-level correlation the compact summary/aggregates can't convey.",
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
    "Read the append-only audit trail of past hunts — every API call made (redacted params, status, topology deltas), grouped by hunt. op=list to see past hunts cheaply, op=get to pull one hunt's metadata plus its full event log as {meta, events}, op=export to pull just the ordered event array as structured JSON, op=stats to pull per-hunt token accounting (cumulative_est_tokens, event_count, by_kind) — the measured proof the journal path is cheaper than re-fetching full responses. op=expand re-runs the hunt's query filtered to rows matching a value from the summary (e.g. a `rare` value or an aggregate top value), returning those FULL rows so the agent can correlate columns within a row cheaply — instead of re-dumping the whole result; this is how to resolve a row-level correlation the compact summary/aggregates can't convey. Aside from op=expand, this is an audit trail for RECONSTRUCTING what path a prior hunt took (which endpoints were called, in what order, with what topology deltas) — not a data replay: params are redacted and response bodies are stored as compact summaries (top rows / counts), not full results, so it cannot re-materialize a prior hunt's actual findings.",
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
