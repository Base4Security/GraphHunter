import type { Tool } from "../../lib/types.js";
import { getGraphSummary } from "./get_graph_summary.js";
import { getEntityTypeCounts } from "./get_entity_type_counts.js";
import { getTemporalHeatmap } from "./get_temporal_heatmap.js";
import { getSubnetAnalysis } from "./get_subnet_analysis.js";

export const graphViewTools: Tool[] = [
  getGraphSummary,
  getEntityTypeCounts,
  getTemporalHeatmap,
  getSubnetAnalysis,
];
