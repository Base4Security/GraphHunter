import { z } from "zod";
import { defineTool } from "../../lib/types.js";
const input = z.object({
    all: z.boolean().optional().describe("When true, remove every DLQ entry regardless of filter."),
    dataset_id: z.string().max(500).optional(),
    failure_kind: z
        .enum([
        "parse_failure",
        "invariant_causality",
        "invariant_referential",
        "invariant_type_shape",
        "empty_yield",
        "other",
    ])
        .optional(),
});
export const purgeDeadLetters = defineTool({
    name: "purge_dead_letters",
    description: "Bulk-remove DLQ entries. Without `all=true`, at least one of `dataset_id` / `failure_kind` is required — the empty-filter case is rejected to prevent accidental wipes.",
    category: "data-quality",
    version: 1,
    stability: "stable",
    inputSchema: input,
    outputSchema: z.unknown(),
    async execute(ctx, { all, dataset_id, failure_kind }) {
        const body = {};
        if (all != null)
            body.all = all;
        if (dataset_id != null)
            body.dataset_id = dataset_id;
        if (failure_kind != null)
            body.failure_kind = failure_kind;
        return ctx.api.post("/purge_dead_letters", body);
    },
});
