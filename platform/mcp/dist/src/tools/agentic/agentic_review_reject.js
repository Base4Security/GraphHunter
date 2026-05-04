import { z } from "zod";
import { defineTool } from "../../lib/types.js";
const input = z.object({
    draft_id: z.string().max(200).describe("The draft_id returned by a previous agentic tool call."),
    reason: z.string().min(1).max(2000).describe("Required human-readable reason. Stored verbatim on the draft."),
});
export const agenticReviewReject = defineTool({
    name: "agentic_review_reject",
    description: "Reject a pending MappingDraft and persist the reason on the draft for audit. Reason is required — an empty or whitespace-only string is rejected with InvalidInput.",
    category: "agentic",
    version: 1,
    stability: "stable",
    inputSchema: input,
    outputSchema: z.unknown(),
    async execute(ctx, { draft_id, reason }) {
        return ctx.api.post("/agentic_review_reject", { draft_id, reason });
    },
});
