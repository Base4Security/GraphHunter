import { z } from "zod";
import { defineTool } from "../../lib/types.js";

const streamInput = z.object({
  path: z.string().min(1).max(4096).describe("Path to the log file on the GraphHunter host."),
  format: z.string().max(64).default("auto").describe("Format name, or 'auto' to detect."),
  config: z
    .unknown()
    .optional()
    .describe("Optional FieldConfig. Omit to use the auto-built mapping."),
  session: z.string().max(200).optional().describe("Session to ingest into."),
  date_from: z
    .string()
    .max(64)
    .optional()
    .describe("Optional lower bound (ISO date) for line-delimited formats."),
  date_to: z.string().max(64).optional().describe("Optional upper bound (ISO date)."),
});

export const ingestStream = defineTool({
  name: "ingest_stream",
  description:
    "Start a BACKGROUND ingest of a large log file and return {job_id, dataset_id} immediately -- the data is NOT loaded when this returns. Poll ingest_status with the job_id until state is 'complete' or 'error'. Use this instead of ingest_load when the file is big enough that a synchronous load would time out or exceed the host's size cap (ingest_load returns 413 in that case). Returns 409 if too many ingests are already running; there is no way to cancel one, so check ingest_jobs before starting another.",
  category: "ingest",
  version: 1,
  stability: "stable",
  inputSchema: streamInput,
  outputSchema: z.unknown(),
  async execute(ctx, { path, format, config, session, date_from, date_to }) {
    const body: Record<string, unknown> = { path, format };
    if (config != null) body.config = config;
    if (session != null) body.session = session;
    if (date_from != null) body.date_from = date_from;
    if (date_to != null) body.date_to = date_to;
    return ctx.api.post("/ingest/stream", body);
  },
});

export const ingestStatus = defineTool({
  name: "ingest_status",
  description:
    "Poll one background ingest by job_id. Returns state ('running' | 'complete' | 'error'), the current phase, byte counts, and -- once complete -- the LoadResult. Note: bytes_read/bytes_total are 0 for EVTX, PCAP and Zeek, where `phase` is the only progress signal, so do not treat 0/0 as no progress. On 'complete' you MUST still check result.zero_triples (parsed rows but produced nothing, i.e. a wrong mapping) and result.stopped_early (truncated by the memory guard). A 404 means the job is unknown, was evicted, or the GraphHunter process restarted and took the ingest with it. If state stays 'running' with an updated_at that stops advancing for several minutes, assume the same.",
  category: "ingest",
  version: 1,
  stability: "stable",
  inputSchema: z.object({
    job_id: z.string().min(1).max(200).describe("job_id returned by ingest_stream."),
  }),
  outputSchema: z.unknown(),
  async execute(ctx, { job_id }) {
    return ctx.api.get("/ingest/status", { job_id });
  },
});

export const ingestJobs = defineTool({
  name: "ingest_jobs",
  description:
    "List recent background ingest jobs, most recently updated first. Use it to recover a job_id you lost, to see whether an ingest is already running before starting another, or to spot a job left stranded by a process restart.",
  category: "ingest",
  version: 1,
  stability: "stable",
  inputSchema: z.object({
    limit: z.number().int().min(1).max(64).optional().describe("Max jobs to return (default 32)."),
  }),
  outputSchema: z.unknown(),
  async execute(ctx, { limit }) {
    const params: Record<string, string> = {};
    if (limit != null) params.limit = String(limit);
    return ctx.api.get("/ingest/jobs", params);
  },
});
