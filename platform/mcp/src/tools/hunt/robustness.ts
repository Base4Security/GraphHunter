import { z } from "zod";
import { defineTool } from "../../lib/types.js";
import { HEAVY } from "../../lib/api-client.js";

const recordKey = z
  .union([
    z.object({ kind: z.literal("edge") }),
    z.object({ kind: z.literal("identical") }),
    z.object({ kind: z.literal("metadata"), keys: z.array(z.string().max(200)).min(1).max(10) }),
  ])
  .describe(
    "What counts as one record for λ. `identical` (default): edges equal in endpoints, type, timestamp and dataset are one record — a duplicated ingest is not redundancy. `edge`: every edge counts. `metadata`: edges sharing these metadata values are one record, e.g. [\"Computer\", \"EventRecordID\"].",
  );

const domainBase = z
  .union([
    z.object({ kind: z.literal("dataset") }),
    z.object({ kind: z.literal("metadata"), key: z.string().max(200) }),
  ])
  .describe(
    "Where an edge's failure domain comes from: the dataset it was loaded from (default), or one metadata field such as the Sentinel table (`Type`) or the forwarding device.",
  );

const input = z.object({
  hypothesis_dsl: z
    .string()
    .max(4000)
    .describe("A chain hypothesis in the hunt DSL (joins with `;` are not supported here)."),
  source: z.string().max(500).optional().describe("First entity of one attribution. Give target too."),
  target: z.string().max(500).optional().describe("Last entity of one attribution. Give source too."),
  options: z
    .object({
      record_key: recordKey.optional(),
      domains: z
        .object({
          base: domainBase.optional(),
          groups: z
            .record(z.string().max(500), z.array(z.string().max(500)).max(50))
            .optional()
            .describe(
              "Shared risk groups: a base value → the components it depends on (connector, agent, forwarder). The edge is lost when any of them fails.",
            ),
        })
        .optional(),
      time_window: z
        .tuple([z.number().int(), z.number().int()])
        .optional()
        .describe("Inclusive [from, to] in engine seconds."),
      max_exact_domains: z
        .number()
        .int()
        .min(1)
        .max(20)
        .optional()
        .describe("Enumerate ρ exactly only up to this many domains in the support (default 16, at most 20)."),
    })
    .optional(),
  max_pairs: z
    .number()
    .int()
    .min(1)
    .max(5000)
    .optional()
    .describe("When no source/target is given, evaluate at most this many endpoint pairs (default 200)."),
});

export const huntRobustness = defineTool({
  name: "hunt_robustness",
  description:
    "How much lost evidence an attribution survives. For a chain hypothesis between two entities: λ = least records whose loss leaves no match, ρ = least failure domains (datasets, tables, collectors) whose loss does, the cuts that witness both, and which single domains break it. Without source/target it hunts the hypothesis and evaluates every endpoint pair; `summary` gives counts with their denominator, including `gap` (λ ≥ 2 and ρ = 1: evidence that looks redundant but falls with one domain). ρ is exact when `rho_lower == rho_upper`; whether ρ = 1 is always exact.",
  category: "hunt",
  version: 1,
  stability: "experimental",
  inputSchema: input,
  outputSchema: z.unknown(),
  async execute(ctx, args) {
    return ctx.api.post("/attribution_robustness", args, HEAVY);
  },
});
