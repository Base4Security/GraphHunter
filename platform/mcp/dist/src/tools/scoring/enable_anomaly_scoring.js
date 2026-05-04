import { z } from "zod";
import { defineTool } from "../../lib/types.js";
export const enableAnomalyScoring = defineTool({
    name: "enable_anomaly_scoring",
    description: "Enable anomaly-based scoring for hunt results. Once enabled, run_hunt uses score-guided DFS and get_hunt_results includes anomaly_score and anomaly_breakdown (entity rarity, edge rarity, temporal novelty, neighborhood concentration). Call this BEFORE running hunts to get anomaly-ranked results instead of just structural scores.",
    category: "scoring",
    version: 1,
    stability: "stable",
    inputSchema: z.object({}),
    outputSchema: z.unknown(),
    async execute(ctx) {
        return ctx.api.post("/enable_anomaly_scoring", {});
    },
});
