import { z } from "zod";
import { defineTool } from "../../lib/types.js";
import { HEAVY } from "../../lib/api-client.js";

const input = z.object({
  path: z
    .string()
    .min(1)
    .max(4096)
    .describe(
      "Absolute path to a .pcap / .pcapng / .cap file on the host's local filesystem. " +
        "PCAP is binary — passing the file content directly is not supported; pass the path."
    ),
});

/**
 * MCP wrapper around the canonical PCAP / PCAPNG offline preview. The
 * heavy lifting (reader init, L2-L4 decode, top-N aggregation) lives
 * in the API; this tool is a thin POST to `/pcap_preview`.
 *
 * Returned shape mirrors `graph_hunter_api::dto::ingestion::PcapPreviewResult`:
 *   - format: "pcap" | "pcapng" | "unknown"
 *   - file_size, packets_sampled, packet_count_estimate
 *   - time_span: { first_unix_secs, last_unix_secs, duration_secs } | null
 *   - protocol_mix: [{ protocol, packets, bytes }, ...]
 *   - top_src_ips / top_dst_ips: [{ ip, packets, bytes }, ...]
 *   - top_dst_ports: [{ port, protocol, service?, packets }, ...]
 *   - warnings: string[]
 *
 * Sampling is bounded (≤ 10K packets) so even a multi-GB capture
 * previews in well under a second. The flow-aggregating full-ingest
 * path lives in a separate tool — this one is observability-only.
 */
export const ingestPcapPreview = defineTool({
  name: "ingest_pcap_preview",
  description:
    "Summarize an offline PCAP / PCAPNG capture: top source / destination IPs, top destination ports (with well-known service tags), protocol mix (TCP / UDP / ICMP / Other), and time span. Reads at most 10K packets so multi-GB captures still return in well under a second. Use to scope a capture before committing it to the graph via the (forthcoming) flow ingest path. The file MUST live on the host's local filesystem — PCAP is binary, so passing content inline is not supported.",
  category: "ingest",
  version: 1,
  stability: "experimental",
  inputSchema: input,
  outputSchema: z.unknown(),
  async execute(ctx, { path }) {
    return ctx.api.post("/pcap_preview", { path }, HEAVY);
  },
});
