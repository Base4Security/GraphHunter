import type { Tool } from "../../lib/types.js";
import { graphSummary } from "./summary.js";
import { graphEntityTypes } from "./entity_types.js";
import { graphRelationSchema } from "./relation_schema.js";
import { graphSubnetAnalysis } from "./subnet_analysis.js";
import { graphTemporalHeatmap } from "./temporal_heatmap.js";
import { graphDatasets } from "./datasets.js";
import { graphPathNodes } from "./path_nodes.js";

export const graphTools: Tool[] = [
  graphSummary,
  graphEntityTypes,
  graphRelationSchema,
  graphSubnetAnalysis,
  graphTemporalHeatmap,
  graphDatasets,
  graphPathNodes,
];
