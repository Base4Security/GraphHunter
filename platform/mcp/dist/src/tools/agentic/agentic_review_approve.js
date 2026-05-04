import { z } from "zod";
import { defineTool } from "../../lib/types.js";
const input = z.object({
    draft_id: z.string().max(200).describe("The draft_id returned by a previous agentic tool call."),
});
export const agenticReviewApprove = defineTool({
    name: "agentic_review_approve",
    description: "Approve a pending MappingDraft. For IngestNegotiator drafts, this stamps the proposed FieldConfig onto the most recent dataset in the session (returned as promoted_dataset_id). For ParserGenerator / CanonicalMapper drafts, approval only flips status — the VRL flows into provenance the next time export_ocsf runs on a dataset whose FieldConfig hashes to the same mapping_hash. Idempotent: approving an already-resolved draft returns InvalidState.",
    category: "agentic",
    version: 1,
    stability: "stable",
    inputSchema: input,
    outputSchema: z.unknown(),
    async execute(ctx, { draft_id }) {
        return ctx.api.post("/agentic_review_approve", { draft_id });
    },
});
