import type { Tool } from "../../lib/types.js";
import { enableAnomalyScoring } from "./enable_anomaly_scoring.js";
import { computeScores } from "./compute_scores.js";
import { explainScore } from "./explain_score.js";

export const scoringTools: Tool[] = [enableAnomalyScoring, computeScores, explainScore];
