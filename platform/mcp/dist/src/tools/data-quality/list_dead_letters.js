import { z } from "zod";
import { defineTool } from "../../lib/types.js";
const input = z.object({
    dataset_id: z.string().max(500).optional().describe("Restrict to rows rejected for this dataset."),
    failure_kind: z
        .enum([
        "parse_failure",
        "invariant_causality",
        "invariant_referential",
        "invariant_type_shape",
        "empty_yield",
        "other",
    ])
        .optional()
        .describe("Restrict to a single failure category."),
    offset: z.number().int().min(0).optional(),
    limit: z.number().int().min(1).max(1000).optional().describe("Page size. Defaults to 100."),
});
export const listDeadLetters = defineTool({
    name: "list_dead_letters",
    description: "List rows the ingest pipeline rejected (parse failure, invariant violation, empty yield). Supports filtering by dataset_id and failure_kind plus paging. The DLQ lives on disk as JSONL shards and survives restarts — when unconfigured (tests / headless), returns an empty page.",
    category: "data-quality",
    version: 1,
    stability: "stable",
    inputSchema: input,
    outputSchema: z.unknown(),
    async execute(ctx, { dataset_id, failure_kind, offset, limit }) {
        const body = {};
        if (dataset_id != null)
            body.dataset_id = dataset_id;
        if (failure_kind != null)
            body.failure_kind = failure_kind;
        if (offset != null)
            body.offset = offset;
        if (limit != null)
            body.limit = limit;
        return ctx.api.post("/list_dead_letters", body);
    },
});
