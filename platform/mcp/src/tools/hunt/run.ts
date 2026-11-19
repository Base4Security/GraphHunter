import { z } from "zod";
import { defineTool } from "../../lib/types.js";
import { HEAVY } from "../../lib/api-client.js";

const input = z.object({
  hypothesis_dsl: z
    .string()
    .max(2000)
    .describe(
      "Chain: 'User -[Execute]-> Process -[DNS]-> Domain'. Join on a shared node: 'User u -[Auth]-> IP i; Host h -[Connect]-> IP i'.",
    ),
  scoring: z
    .enum(["structural", "anomaly", "gnn"])
    .optional()
    .default("structural")
    .describe(
      "structural (default): plain search. anomaly: rarity-guided search, with a per-path anomaly breakdown. gnn: adds GNN threat scores when the build has them.",
    ),
});

export const huntRun = defineTool({
  name: "hunt_run",
  description:
    "Run a hunting pattern over the graph. A chain follows edges forward in time ('IP -[Connect]-> Host -[Execute]-> Process'). To correlate sources, join clauses on a shared node: name the nodes and separate clauses with ';' ('User u -[Auth]-> IP i; Domain d -[Resolve]-> IP i'); clauses must form a tree. A joined pattern ignores time unless you end it with 'WITHIN 1h': then every edge it matches falls in one window, which is what ties an address to the host holding it at the time. Take entity and relation names from graph_relation_schema first: a pair that does not exist returns 0 paths and a diagnostic. Returns the path count and whether it was truncated; read the paths with hunt_results. A truncated joined pattern names `truncated_in_group`: matches come grouped on the most shared node, smallest group first, so every group but that one is complete. `non_discriminating` in the result means the pattern matches most of the population, so its paths are not findings. A 504 means the hunt was cancelled for running too long: narrow it.",
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
