import { z } from "zod";
import { defineTool } from "../../lib/types.js";

export const graphDatasets = defineTool({
  name: "graph_datasets",
  description:
    "List all ingested datasets in the current session. Each dataset represents a data source (e.g. a log file or SIEM query) with its name, file path, entity/relation counts, and timestamp. Use to understand what data is available for analysis and where it came from.",
  category: "graph",
  version: 1,
  stability: "stable",
  inputSchema: z.object({}),
  outputSchema: z.unknown(),
  async execute(ctx) {
    return ctx.api.get("/datasets");
  },
});
