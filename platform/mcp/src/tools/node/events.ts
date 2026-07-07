import { z } from "zod";
import { defineTool } from "../../lib/types.js";
import { HEAVY } from "../../lib/api-client.js";

const input = z.object({
  node_id: z.string().max(500).describe("Entity ID"),
  page: z
    .number()
    .int()
    .min(0)
    .max(10000)
    .optional()
    .describe(
      "Optional page index (0-based). Omit page + page_size to get ALL events at once (replaces the old `get_events_for_node`).",
    ),
  page_size: z
    .number()
    .int()
    .min(1)
    .max(200)
    .optional()
    .describe(
      "Optional events per page (default 50 when paginating). When both page and page_size are omitted, returns all events.",
    ),
  sort_by: z
    .enum(["timestamp", "rel_type", "source", "target"])
    .optional()
    .describe("Sort field. Only meaningful when paginating."),
});

export const nodeEvents = defineTool({
  name: "node_events",
  description:
    "Get relations/events for a node (incoming and outgoing edges). Pass `page` + `page_size` for paginated, sortable output (better for high-degree nodes); omit both to get the full event list at once. Returns total_count when paginating.",
  category: "node",
  version: 1,
  stability: "stable",
  inputSchema: input,
  outputSchema: z.unknown(),
  async execute(ctx, { node_id, page, page_size, sort_by }) {
    if (page == null && page_size == null) {
      return ctx.api.get("/events_for_node", { node_id }, HEAVY);
    }
    const params: Record<string, string> = {
      node_id,
      page: String(page ?? 0),
      page_size: String(page_size ?? 50),
    };
    if (sort_by) params.sort_by = sort_by;
    return ctx.api.get("/events_paginated", params, HEAVY);
  },
});
