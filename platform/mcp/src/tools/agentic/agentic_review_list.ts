import { z } from "zod";
import { defineTool } from "../../lib/types.js";

const input = z.object({
  include_resolved: z
    .boolean()
    .optional()
    .describe("When true, include Approved and Rejected drafts. Defaults to false."),
});

export const agenticReviewList = defineTool({
  name: "agentic_review_list",
  description:
    "List MappingDrafts in the current session's review queue. Defaults to pending only; pass include_resolved=true to see the audit trail of prior Approved/Rejected drafts (with their reasons and timestamps).",
  category: "agentic",
  version: 1,
  stability: "stable",
  inputSchema: input,
  outputSchema: z.unknown(),
  async execute(ctx, { include_resolved }) {
    const body: Record<string, unknown> = {};
    if (include_resolved != null) body.include_resolved = include_resolved;
    return ctx.api.post("/agentic_review_list", body);
  },
});
