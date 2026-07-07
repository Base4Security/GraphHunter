import { z } from "zod";
import { defineTool, type ToolContext } from "../../lib/types.js";
import { HEAVY } from "../../lib/api-client.js";

const input = z.object({
  lookback: z
    .enum(["1h", "6h", "24h", "7d", "30d"])
    .optional()
    .describe("Window used to detect active tables and sample fields (default 24h)."),
  table_filter: z
    .array(z.string().min(1))
    .optional()
    .describe("Restrict discovery to these tables (case-insensitive). Omit to inspect all active tables."),
  min_ingestion_mb: z
    .number()
    .min(0)
    .optional()
    .describe("Exclude tables whose billable ingestion in the window is below this many MB."),
  max_tables: z
    .number()
    .int()
    .min(1)
    .max(200)
    .optional()
    .describe("Cap on tables sampled + classified, most-ingested first (default 25). A `note` is returned when the cap drops tables."),
  sample_rows: z
    .number()
    .int()
    .min(1)
    .max(1000)
    .optional()
    .describe("Rows sampled per table for field classification (default 200)."),
});

const DESCRIPTION =
  "PHASE 1 / DISCOVERY (design doc §4.1): list the active Sentinel tables (by ingestion volume) and classify each field for graph construction. Per field it reports graph_affinity (node | edge | attribute), node_class for identifiers (IP, User, Host, …), enrichable tags (geoip/asn/threat_intel for IPs), cardinality, and sample_values; per table ingestion_24h_mb + last_ingested; plus query cost. Call this FIRST when the graph is empty to decide which tables/fields are worth materializing, then graph_propose → graph_build. Read-only: samples Sentinel, never modifies the graph. Degrades cleanly when AZURE_WORKSPACE_ID is unset (clear error).";

async function execute(
  ctx: ToolContext,
  { lookback, table_filter, min_ingestion_mb, max_tables, sample_rows }: z.infer<typeof input>,
) {
  const body: Record<string, unknown> = {};
  if (lookback) body.lookback = lookback;
  if (table_filter) body.table_filter = table_filter;
  if (min_ingestion_mb != null) body.min_ingestion_mb = min_ingestion_mb;
  if (max_tables != null) body.max_tables = max_tables;
  if (sample_rows != null) body.sample_rows = sample_rows;
  return ctx.api.post("/sentinel/schema", body, HEAVY);
}

export const schemaDiscover = defineTool({
  name: "schema_discover",
  description: DESCRIPTION,
  category: "sentinel",
  version: 1,
  stability: "experimental",
  inputSchema: input,
  outputSchema: z.unknown(),
  execute,
});

/** Deprecated alias for the pre-rename name. Forwards to the same endpoint so
 * existing callers keep working; prefer `schema_discover`. */
export const sentinelSchema = defineTool({
  name: "sentinel_schema",
  description: `DEPRECATED alias for schema_discover. ${DESCRIPTION}`,
  category: "sentinel",
  version: 1,
  stability: "deprecated",
  inputSchema: input,
  outputSchema: z.unknown(),
  execute,
});
