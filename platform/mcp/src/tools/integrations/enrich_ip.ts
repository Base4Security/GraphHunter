import { z } from "zod";
import { defineTool } from "../../lib/types.js";

const input = z.object({
  ip: z.string().max(45).describe("Public IP address to enrich (e.g. '8.8.8.8')"),
});

export const enrichIp = defineTool({
  name: "enrich_ip",
  description:
    "Enrich a public/external IP address with GeoIP data: country, city, ASN, ISP/organization. Only works for public IPs (returns error for private/internal IPs). The enrichment data is persisted on the entity's metadata, so subsequent get_node_details calls will include it. Use to identify where external connections go (country, ISP) for threat analysis.",
  category: "integrations",
  version: 1,
  stability: "stable",
  inputSchema: input,
  outputSchema: z.unknown(),
  async execute(ctx, { ip }) {
    return ctx.api.post("/enrich_ip", { ip });
  },
});
