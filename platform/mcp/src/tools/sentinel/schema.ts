import { z } from "zod";
import { defineTool } from "../../lib/types.js";
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

export const sentinelSchema = defineTool({
  name: "sentinel_schema",
  description:
    "DISCOVERY / cold-start orientation: list the active Sentinel tables (by ingestion volume) and classify each field for graph construction. For every field it reports graph_affinity (node | edge | attribute), the node_class for identifiers (IP, User, Host, …), which enrichments apply (geoip/asn for IPs), cardinality, and sample values. Call this FIRST when the graph is empty to decide which tables/fields are worth materializing — then sentinel_seed / node_enrich to build, not raw KQL. Read-only: it samples Sentinel and never modifies the graph.",
  category: "sentinel",
  version: 1,
  stability: "experimental",
  inputSchema: input,
  outputSchema: z.unknown(),
  async execute(ctx, { lookback, table_filter, min_ingestion_mb, max_tables, sample_rows }) {
    const body: Record<string, unknown> = {};
    if (lookback) body.lookback = lookback;
    if (table_filter) body.table_filter = table_filter;
    if (min_ingestion_mb != null) body.min_ingestion_mb = min_ingestion_mb;
    if (max_tables != null) body.max_tables = max_tables;
    if (sample_rows != null) body.sample_rows = sample_rows;
    return ctx.api.post("/sentinel/schema", body, HEAVY);
  },
});
