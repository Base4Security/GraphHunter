import { z } from "zod";
import { defineTool } from "../../lib/types.js";
import { HEAVY } from "../../lib/api-client.js";

const input = z.object({
  hypothesis_dsl: z
    .string()
    .max(2000)
    .describe(
      "Hypothesis in DSL form, e.g. 'IP -[Connect]-> Host -[Auth]-> User -[Execute]-> Process'",
    ),
});

export const runHunt = defineTool({
  name: "run_hunt",
  description:
    "Run a threat-hunting hypothesis. Pass a DSL chain like 'IP -[Connect]-> Host -[Execute]-> Process'. Returns path count and whether results were truncated. After running, use get_hunt_results to retrieve paths with scores (structural scores always; anomaly and GNN threat when scoring is enabled).",
  category: "hunting",
  version: 1,
  stability: "stable",
  inputSchema: input,
  outputSchema: z.unknown(),
  async execute(ctx, { hypothesis_dsl }) {
    return ctx.api.post("/run_hunt", { hypothesis_dsl }, HEAVY);
  },
});
