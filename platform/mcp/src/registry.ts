/**
 * ADR-004 §D3 — central registry.
 *
 * Each domain directory under `src/tools/` exports a `<domain>Tools:
 * Tool[]`. The registry spreads them in a stable order so clients see
 * the same tool list every boot.
 */

import type { Tool } from "./lib/types.js";
import { navigationTools } from "./tools/navigation/index.js";
import { huntingTools } from "./tools/hunting/index.js";
import { scoringTools } from "./tools/scoring/index.js";
import { graphViewTools } from "./tools/graph-views/index.js";
import { catalogTools } from "./tools/catalogs/index.js";
import { notesTools } from "./tools/notes/index.js";
import { exportTools } from "./tools/export/index.js";
import { dataQualityTools } from "./tools/data-quality/index.js";
import { agenticTools } from "./tools/agentic/index.js";
import { integrationsTools } from "./tools/integrations/index.js";

export const registry: Tool[] = [
  ...navigationTools,
  ...huntingTools,
  ...scoringTools,
  ...graphViewTools,
  ...catalogTools,
  ...notesTools,
  ...exportTools,
  ...dataQualityTools,
  ...agenticTools,
  ...integrationsTools,
];
