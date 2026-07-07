import { z } from "zod";
import { defineTool } from "../../lib/types.js";
import { HEAVY } from "../../lib/api-client.js";

const input = z.object({
  hypothesis_dsl: z.string().min(1).max(10_000).describe("Hunt pattern in DSL form"),
  baseline_ts: z.number().int().describe("Upper bound of the baseline snapshot (Unix seconds)"),
  current_ts: z
    .number()
    .int()
    .describe("Upper bound of the current snapshot (Unix seconds); must be >= baseline_ts"),
});

export const huntDiff = defineTool({
  name: "hunt_diff",
  description:
    "Run the same DSL hypothesis at two upper time bounds (baseline_ts, current_ts) and return what was added/removed between them. Killer tool for tracking attack progression: pass a cat-017 pattern with `baseline_ts=<T-6h>` and `current_ts=<now>` — the response tells you exactly which IPs/users were added to the spray in the last 6 hours. Paths compared by node-sequence equality after DedupMode::ByPath. Response shape: {baseline_count, current_count, added: ScoredPath[], removed: ScoredPath[]}.",
  category: "hunt",
  version: 1,
  stability: "stable",
  inputSchema: input,
  outputSchema: z.unknown(),
  async execute(ctx, { hypothesis_dsl, baseline_ts, current_ts }) {
    return ctx.api.post("/diff_hunts", { hypothesis_dsl, baseline_ts, current_ts }, HEAVY);
  },
});
