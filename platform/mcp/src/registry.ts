/**
 * v2 catalog (orthogonal namespaces). Each domain directory under
 * `src/tools/<namespace>/` exports a `<namespace>Tools: Tool[]`. The
 * registry spreads them in a stable order so clients see the same
 * tool list every boot.
 *
 * v1 → v2 hard cut shipped on 2026-05-06: the old flat names
 * (`get_graph_summary`, `tag_entity`, `enable_anomaly_scoring`, etc.)
 * are gone. See `docs/architecture/phase1/ADR/004-mcp-tools-architecture.md`
 * for the migration log.
 */

import type { Tool } from "./lib/types.js";
import { sessionTools } from "./tools/session/index.js";
import { graphTools } from "./tools/graph/index.js";
import { nodeTools } from "./tools/node/index.js";
import { huntTools } from "./tools/hunt/index.js";
import { catalogTools } from "./tools/catalog/index.js";
import { tagsTools } from "./tools/tags/index.js";
import { notesTools } from "./tools/notes/index.js";
import { scoresTools } from "./tools/scores/index.js";
import { reviewTools } from "./tools/review/index.js";
import { ingestTools } from "./tools/ingest/index.js";
import { sentinelTools } from "./tools/sentinel/index.js";
import { enrichTools } from "./tools/enrich.js";
import { exportTools } from "./tools/export.js";
import { publishTools } from "./tools/publish.js";

export const registry: Tool[] = [
  ...sessionTools,
  ...graphTools,
  ...nodeTools,
  ...huntTools,
  ...catalogTools,
  ...tagsTools,
  ...notesTools,
  ...scoresTools,
  ...reviewTools,
  ...ingestTools,
  ...sentinelTools,
  ...enrichTools,
  ...exportTools,
  ...publishTools,
];
