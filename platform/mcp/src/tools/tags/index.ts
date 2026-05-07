import { z } from "zod";
import { defineTool, type Tool } from "../../lib/types.js";

const input = z.object({
  op: z
    .enum(["add", "remove", "list"])
    .describe(
      "Discriminator. add: tag a node. remove: untag. list: list all tags (optionally filtered by prefix).",
    ),
  node_id: z
    .string()
    .max(500)
    .optional()
    .describe("Required for op=add and op=remove. Ignored for op=list."),
  tag: z
    .string()
    .min(1)
    .max(100)
    .optional()
    .describe(
      "Tag label. Required for op=add and op=remove. Convention: `ioc:malicious`, `benign:confirmed`, `investigated:fp`.",
    ),
  reason: z
    .string()
    .max(2000)
    .optional()
    .describe("Optional human-readable rationale (op=add only)."),
  prefix: z
    .string()
    .max(100)
    .optional()
    .describe("Optional prefix filter for op=list (e.g. `ioc:` to list IoCs only)."),
});

export const tags = defineTool({
  name: "tags",
  description:
    "Manage entity tags. op=add applies a tag (convention: `ioc:malicious`, `benign:confirmed`, `investigated:fp`); op=remove deletes a (node_id, tag) pair; op=list returns all tags with optional prefix filter. Tags persist with the session and feed export(kind=iocs) / publish(target=sentinel_watchlist).",
  category: "tags",
  version: 1,
  stability: "stable",
  inputSchema: input,
  outputSchema: z.unknown(),
  async execute(ctx, { op, node_id, tag, reason, prefix }) {
    if (op === "add") {
      if (!node_id || !tag)
        throw new Error("op=add requires both node_id and tag");
      return ctx.api.post("/tag", { node_id, tag, reason: reason ?? undefined });
    }
    if (op === "remove") {
      if (!node_id || !tag)
        throw new Error("op=remove requires both node_id and tag");
      return ctx.api.post("/untag", { node_id, tag });
    }
    // op === "list"
    const params: Record<string, string> = {};
    if (prefix) params.tag_prefix = prefix;
    return ctx.api.get("/tags", params);
  },
});

export const tagsTools: Tool[] = [tags];
