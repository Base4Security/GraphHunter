import { z } from "zod";
import { defineTool } from "../../lib/types.js";
import { HEAVY } from "../../lib/api-client.js";

const input = z.object({
  node_ids: z
    .array(z.string().max(500))
    .max(1000)
    .describe("List of entity IDs (max 1000)"),
  output: z
    .enum(["inline", "file"])
    .optional()
    .default("inline")
    .describe(
      "inline: return parsed nodes+edges JSON (replaces old `get_subgraph`). file: return rendered text (JSON or CSV) for download/save (replaces old `export_subgraph`).",
    ),
  format: z
    .enum(["json", "csv"])
    .optional()
    .default("json")
    .describe("Render format when output=file. Ignored when output=inline."),
  page_size: z
    .number()
    .int()
    .positive()
    .max(50000)
    .optional()
    .describe(
      "Cap on returned edges. Default 5000, ceiling 50000. The response carries `total_edges` + `has_more` so you know whether to walk further with `offset`.",
    ),
  offset: z
    .number()
    .int()
    .nonnegative()
    .optional()
    .describe(
      "Number of edges to skip before starting the page. Use with page_size to walk a large subgraph in chunks.",
    ),
});

export const nodeSubgraph = defineTool({
  name: "node_subgraph",
  description:
    "Get the subgraph (nodes and edges) for a list of node IDs. Default output=inline returns the parsed JSON for in-flight analysis; output=file returns rendered text (JSON or CSV) suitable for saving — use the latter to produce a detailed report of a suspicious path or bulk-export entity metadata.",
  category: "node",
  version: 1,
  stability: "stable",
  inputSchema: input,
  outputSchema: z.unknown(),
  async execute(ctx, { node_ids, output, format, page_size, offset }) {
    if (output === "file") {
      const v = (await ctx.api.post(
        "/export_subgraph",
        { node_ids, format },
        HEAVY,
      )) as { data: string; format: string };
      return { rendered: v.data, format: v.format };
    }
    return ctx.api.post(
      "/subgraph",
      { node_ids, page_size, offset },
      HEAVY,
    );
  },
});
