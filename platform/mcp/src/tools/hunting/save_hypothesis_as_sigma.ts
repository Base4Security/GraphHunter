import { z } from "zod";
import { defineTool } from "../../lib/types.js";
import { HEAVY } from "../../lib/api-client.js";

const input = z.object({
  hypothesis_dsl: z.string().min(1).max(10_000),
  title: z.string().min(1).max(200),
  tag_prefix: z.string().max(100).optional().describe("Filter IoC seed by tag prefix (default `ioc:`)"),
  level: z.enum(["low", "medium", "high", "critical"]).optional().describe("Sigma severity level (default medium)"),
});

export const saveHypothesisAsSigma = defineTool({
  name: "save_hypothesis_as_sigma",
  description:
    "Convert a DSL hypothesis (with optional IoC set) to a Sigma rule YAML ready for `sigmac` compilation. Maps (rel_type, dest_type) pairs to canonical Sigma logsources (User -[Auth]-> IP → azure signinlogs; Process -[Spawn]-> Process → process_creation; etc.). Metadata predicates become selection fields; HAVING count aggregations become Sigma count() conditions with timeframe. Response: {yaml, title, fully_mapped}. When fully_mapped=false the rule contains a comment block marking the gap the analyst needs to fill.",
  category: "hunting",
  version: 1,
  stability: "stable",
  inputSchema: input,
  outputSchema: z.unknown(),
  async execute(ctx, { hypothesis_dsl, title, tag_prefix, level }) {
    const body: Record<string, unknown> = { hypothesis_dsl, title };
    if (tag_prefix != null) body.tag_prefix = tag_prefix;
    if (level != null) body.level = level;
    return ctx.api.post("/save_hypothesis_as_sigma", body, HEAVY);
  },
});
