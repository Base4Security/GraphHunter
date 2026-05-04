import { z } from "zod";
import { defineTool } from "../../lib/types.js";
import { HEAVY } from "../../lib/api-client.js";
const input = z.object({
    dlq_ids: z.array(z.string().max(200)).min(1).max(1000).describe("IDs returned by list_dead_letters."),
});
export const reingestDeadLetter = defineTool({
    name: "reingest_dead_letter",
    description: "Retry a set of DLQ entries against their datasets' *current* FieldConfigs. The expected workflow: a row failed with the previous mapping → user fixes the mapping (agentic_review_approve) → reingest. Entries whose dataset is gone or unmapped come back in `failed`; successful ones are removed from the DLQ.",
    category: "data-quality",
    version: 1,
    stability: "stable",
    inputSchema: input,
    outputSchema: z.unknown(),
    async execute(ctx, { dlq_ids }) {
        return ctx.api.post("/reingest_dead_letter", { dlq_ids }, HEAVY);
    },
});
