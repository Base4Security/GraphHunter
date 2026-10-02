import { z } from "zod";
import { defineTool } from "../../lib/types.js";
import { HEAVY } from "../../lib/api-client.js";

const CONTAINMENT_NOTE =
  "The path must resolve inside a directory the operator listed in GRAPHHUNTER_INGEST_ROOT; anything else returns 403 (root not configured) or 404. Paths are resolved on the GraphHunter host, not the caller's machine.";

const RESULT_NOTE =
  "HTTP 200 does not mean the ingest was useful: check `zero_triples` (rows parsed but no triples produced -- almost always a wrong field mapping, fix it with ingest_preview then ingest_load_with_config) and `stopped_early` (input truncated by the memory guard, so the graph is incomplete).";

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
    "Detect a log file's format and propose a field -> entity-type mapping WITHOUT ingesting anything. Run this before ingest_load on unfamiliar data: the proposed mapping is what ingest_load would apply, so reviewing it here is how you avoid a zero-triple ingest. " +
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
      "Session to ingest into. Omit to use the process-global current session -- but that is shared across clients, so pass it explicitly whenever you hold one.",
    ),
});

export const ingestLoad = defineTool({
  name: "ingest_load",
  description:
    "Parse a log file on the GraphHunter host and insert it into the session graph, using an auto-built field mapping. Create a session first (session_create) if you do not have one. " +
    RESULT_NOTE +
    " Very large files can outrun the client timeout while the ingest keeps running server-side; check graph_datasets before retrying, or a retry will double-ingest. " +
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
  config: z
    .unknown()
    .describe(
      "A FieldConfig object: { mappings: [{ raw_name, role: 'Node'|'Metadata'|'Ignore', entity_type?, timestamp_format?, locale? }] }. Get a starting point from ingest_preview or ingest_negotiate.",
    ),
  session: z.string().max(200).optional().describe("Session to ingest into."),
});

export const ingestLoadWithConfig = defineTool({
  name: "ingest_load_with_config",
  description:
    "Like ingest_load, but applies an explicit FieldConfig instead of the auto-built mapping. Use this to fix a zero-triple ingest, or when you need a column mapped to a specific entity type. Note there is no `format` argument -- the format is inferred, the config governs the fields. " +
    RESULT_NOTE +
    " " +
    CONTAINMENT_NOTE,
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
