import type { Tool } from "../../lib/types.js";
import { nodeGet } from "./get.js";
import { nodeScoreExplanation } from "./score_explanation.js";
import { nodeSearch } from "./search.js";
import { nodeExpand } from "./expand.js";
import { nodeEvents } from "./events.js";
import { nodeSubgraph } from "./subgraph.js";
import { nodeEnrich } from "./enrich.js";

export const nodeTools: Tool[] = [
  nodeGet,
  nodeScoreExplanation,
  nodeSearch,
  nodeExpand,
  nodeEvents,
  nodeSubgraph,
  nodeEnrich,
];
