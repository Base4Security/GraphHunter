import { z } from "zod";
import { defineTool, type Tool } from "../../lib/types.js";

const input = z.object({
  op: z
    .enum(["start", "list", "get", "export"])
    .describe(
      "Discriminator. start: open a new hunt (rarely needed — the first captured API call already lazily opens one). list: summaries of every past hunt (id, label, timestamps, event/entity/relation counts). get: one hunt's full route/topology — meta plus every captured event. export: that hunt's events as NDJSON text (mirrors on-disk events.jsonl).",
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
    .describe("op=get / op=export only. The hunt id, as returned by op=list or op=start."),
});

interface JournalHuntRecord {
  events: unknown[];
  [key: string]: unknown;
}

export const journal = defineTool({
  name: "journal",
  description:
    "Read the append-only audit trail of past hunts — every API call made (redacted params, status, topology deltas), grouped by hunt. op=list to see past hunts cheaply, op=get to pull one hunt's full route, op=export for its raw event log as NDJSON. Use this to RECONSTRUCT a prior hunt's findings instead of re-running the same queries.",
  category: "hunt",
  version: 1,
  stability: "stable",
  inputSchema: input,
  outputSchema: z.unknown(),
  async execute(ctx, { op, label, id }) {
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
    // op === "export"
    if (!id) throw new Error("op=export requires id");
    // The backend's POST /journal/export streams raw NDJSON bytes (one
    // JSON object per line, matching events.jsonl on disk) so non-MCP
    // callers get a wire format that is genuinely line-delimited JSON.
    // The shared ApiClient (lib/api-client.ts) always JSON.parses the
    // *entire* response body, which breaks on any multi-line NDJSON
    // payload (i.e. any real hunt with more than one captured event)
    // even though each individual line is valid JSON. Rather than
    // special-case NDJSON parsing in the shared client for this one
    // endpoint, reuse the already-JSON `GET /journal/:id` route and
    // rebuild byte-identical NDJSON text here.
    const record = (await ctx.api.get(`/journal/${id}`)) as JournalHuntRecord;
    return record.events.map((ev) => JSON.stringify(ev)).join("\n");
  },
});

export const journalTools: Tool[] = [journal];
