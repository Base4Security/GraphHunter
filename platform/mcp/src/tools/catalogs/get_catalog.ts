import { z } from "zod";
import { defineTool } from "../../lib/types.js";

export const getCatalog = defineTool({
  name: "get_catalog",
  description:
    "Get the catalog of pre-built threat-hunting hypotheses based on MITRE ATT&CK techniques. Each entry has an id, name, description, and DSL pattern that can be passed to run_hunt. Use this to discover what hunt patterns are available and find the right hypothesis for a given threat scenario.",
  category: "catalogs",
  version: 1,
  stability: "stable",
  inputSchema: z.object({}),
  outputSchema: z.unknown(),
  async execute(ctx) {
    return ctx.api.get("/catalog");
  },
});
