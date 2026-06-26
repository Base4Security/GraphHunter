import type { Tool } from "../../lib/types.js";
import { graphSummary } from "./summary.js";
import { graphEntityTypes } from "./entity_types.js";
import { graphRelationSchema } from "./relation_schema.js";
import { graphSubnetAnalysis } from "./subnet_analysis.js";
import { graphTemporalHeatmap } from "./temporal_heatmap.js";
import { graphDatasets } from "./datasets.js";
import { graphPathNodes } from "./path_nodes.js";
import { graphHeavyEdges } from "./heavy_edges.js";
import { graphChannelBehavior } from "./channel_behavior.js";
import { graphPropose } from "./propose.js";
import { graphBuild } from "./build.js";
import { graphNeighbors } from "./neighbors.js";
import { graphPath } from "./path.js";
import { graphAnomaly } from "./anomaly.js";

export const graphTools: Tool[] = [
  graphSummary,
  graphEntityTypes,
  graphRelationSchema,
  graphSubnetAnalysis,
  graphTemporalHeatmap,
  graphDatasets,
  graphPathNodes,
  graphHeavyEdges,
  graphChannelBehavior,
  graphPropose,
  graphBuild,
  graphNeighbors,
  graphPath,
  graphAnomaly,
];
