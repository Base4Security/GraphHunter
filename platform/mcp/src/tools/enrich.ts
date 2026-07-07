import { z } from "zod";
import { defineTool, type Tool } from "../lib/types.js";

const input = z.object({
  target_type: z
    .enum(["ip", "domain", "hash", "url"])
    .describe(
      "Entity kind to enrich. Today only `ip` has a real backend (GeoIP via MaxMind). The other variants are reserved for future enrichment providers and currently throw NotImplemented.",
    ),
  value: z
    .string()
    .max(2048)
    .describe(
      "The value to enrich. For target_type=ip, an IPv4/IPv6 address (e.g. '8.8.8.8'). For domain, a hostname. For hash, hex digest. For url, the full URL.",
    ),
});

export const enrich = defineTool({
  name: "enrich",
  description:
    "Enrich an entity with external context. Supported today: target_type=ip → GeoIP (country, city, ASN, ISP). The enrichment is persisted on the entity's metadata, so subsequent node.get calls include it. Future variants (domain, hash, url) will dispatch to whichever providers are configured; today they error with NotImplemented to keep the surface honest.",
  category: "enrich",
  version: 1,
  stability: "stable",
  inputSchema: input,
  outputSchema: z.unknown(),
  async execute(ctx, { target_type, value }) {
    if (target_type === "ip") {
      return ctx.api.post("/enrich_ip", { ip: value });
    }
    throw new Error(
      `enrich(target_type=${target_type}) is not implemented yet — only "ip" has a wired backend.`,
    );
  },
});

export const enrichTools: Tool[] = [enrich];
