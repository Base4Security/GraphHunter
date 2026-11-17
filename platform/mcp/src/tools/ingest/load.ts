import { z } from "zod";
import { defineTool } from "../../lib/types.js";
import { HEAVY } from "../../lib/api-client.js";

const CONTAINMENT_NOTE =
  "The path is resolved on the GraphHunter host and must be inside GRAPHHUNTER_INGEST_ROOT (403 if that is not configured, 404 otherwise).";

const RESULT_NOTE =
  "A 200 is not a useful ingest: check `zero_triples` (rows parsed, nothing produced: wrong field mapping) and `stopped_early` (truncated by the memory guard).";

const previewInput = z.object({
  path: z.string().min(1).max(4096).describe("Path to the log file on the GraphHunter host."),
  format: z
    .string()
    .max(64)
    .default("auto")
    .describe("Format name, or 'auto' to detect (csv, sysmon, sentinel, evtx, haproxy, ...)."),
});

export const ingestPreview = defineTool({
  name: "ingest_preview",
  description:
    "Detect a log file's format and show the field -> entity-type mapping ingest_load would apply, without ingesting. Run it first on unfamiliar data. " +
    CONTAINMENT_NOTE,
  category: "ingest",
  version: 1,
  stability: "stable",
  inputSchema: previewInput,
  outputSchema: z.unknown(),
  async execute(ctx, { path, format }) {
    return ctx.api.post("/ingest/preview", { path, format }, HEAVY);
  },
});

const loadInput = z.object({
  path: z.string().min(1).max(4096).describe("Path to the log file on the GraphHunter host."),
  format: z.string().max(64).default("auto").describe("Format name, or 'auto' to detect."),
  session: z
    .string()
    .max(200)
    .optional()
    .describe(
      "Session to ingest into. Defaults to the current session.",
    ),
});

export const ingestLoad = defineTool({
  name: "ingest_load",
  description:
    "Ingest a log file into the session graph with the automatic field mapping. Needs a session (session_create). " +
    RESULT_NOTE +
    " If a very large file outlives the client timeout, the ingest keeps running: check graph_datasets before retrying, or it is ingested twice. " +
    CONTAINMENT_NOTE,
  category: "ingest",
  version: 1,
  stability: "stable",
  inputSchema: loadInput,
  outputSchema: z.unknown(),
  async execute(ctx, { path, format, session }) {
    const body: Record<string, unknown> = { path, format };
    if (session != null) body.session = session;
    return ctx.api.post("/ingest/load", body, HEAVY);
  },
});

const loadWithConfigInput = z.object({
  path: z.string().min(1).max(4096).describe("Path to the log file on the GraphHunter host."),
  // zod 3 left a z.unknown() key implicitly optional; zod 4 does not.
  // Spelled out so the published tool contract survives the migration.
  config: z
    .unknown()
    .optional()
    .describe(
      "A FieldConfig object: { mappings: [{ raw_name, role: 'Node'|'Metadata'|'Ignore', entity_type?, timestamp_format?, locale? }] }. Get a starting point from ingest_preview or ingest_negotiate.",
    ),
  session: z.string().max(200).optional().describe("Session to ingest into."),
});

export const ingestLoadWithConfig = defineTool({
  name: "ingest_load_with_config",
  description:
    "ingest_load with an explicit FieldConfig instead of the automatic mapping: use it to fix a zero-triple ingest or to force a column's entity type. The format is still inferred. Same result checks and path rules as ingest_load.",
  category: "ingest",
  version: 1,
  stability: "stable",
  inputSchema: loadWithConfigInput,
  outputSchema: z.unknown(),
  async execute(ctx, { path, config, session }) {
    const body: Record<string, unknown> = { path, config };
    if (session != null) body.session = session;
    return ctx.api.post("/ingest/load_with_config", body, HEAVY);
  },
});
