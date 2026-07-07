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
  scoring: z
    .enum(["structural", "anomaly", "gnn"])
    .optional()
    .default("structural")
    .describe(
      "Per-call scoring mode. 'structural' (default): degree/PageRank/betweenness only. 'anomaly': enables score-guided DFS + four-dimension anomaly breakdown (entity rarity, edge rarity, neighborhood concentration, temporal novelty) on every result path. 'gnn': adds GNN-derived threat scores. Replaces the stateful enable_anomaly_scoring latch — every hunt.run is now self-contained and replayable from a transcript.",
    ),
});

export const huntRun = defineTool({
  name: "hunt_run",
  description:
    "Run a threat-hunting hypothesis. Pass a DSL chain like 'IP -[Connect]-> Host -[Execute]-> Process' and (optionally) a scoring mode. Returns path count and whether results were truncated. After running, use hunt.results to retrieve paths with the per-mode scores. The transcript is **fully self-contained**: each call carries its own scoring mode, the backend honors the per-call override (Structural always uses plain DFS, Anomaly/Gnn always finalizes the scorer first), so replay produces identical paths regardless of prior session state. The legacy `enable_anomaly_scoring` latch is no longer load-bearing.",
  category: "hunt",
  version: 1,
  stability: "stable",
  inputSchema: input,
  outputSchema: z.unknown(),
  async execute(ctx, { hypothesis_dsl, scoring }) {
    // v2 follow-up landed: `RunHuntBody` (apps/tauri/src-tauri/src/http/hunt.rs)
    // and `RunHuntRequest` (platform/api/src/dto/v1/hunt.rs) accept a
    // `scoring` enum that drives the search-path choice per call.
    // Structural forces the plain DFS even when the session has a
    // sticky scorer; Anomaly/Gnn finalize the scorer before the run.
    // No more pre-call `/enable_anomaly_scoring` hop.
    return ctx.api.post(
      "/run_hunt",
      { hypothesis_dsl, scoring },
      HEAVY,
    );
  },
});
