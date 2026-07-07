import { z } from "zod";
import { defineTool } from "../../lib/types.js";
import { HEAVY } from "../../lib/api-client.js";

const FAILURE_KINDS = z.enum([
  "parse_failure",
  "invariant_causality",
  "invariant_referential",
  "invariant_type_shape",
  "empty_yield",
  "other",
]);

const input = z.object({
  op: z
    .enum(["list", "purge", "retry"])
    .describe(
      "Discriminator. list: paged read of rejected rows. purge: bulk-delete by filter. retry: re-attempt ingest with the dataset's current FieldConfig.",
    ),
  dataset_id: z
    .string()
    .max(500)
    .optional()
    .describe("Filter by dataset (op=list, op=purge). Ignored for op=retry."),
  failure_kind: FAILURE_KINDS.optional().describe(
    "Filter by failure category (op=list, op=purge). Ignored for op=retry.",
  ),
  offset: z
    .number()
    .int()
    .min(0)
    .optional()
    .describe("op=list paging offset."),
  limit: z
    .number()
    .int()
    .min(1)
    .max(1000)
    .optional()
    .describe("op=list page size (default 100)."),
  all: z
    .boolean()
    .optional()
    .describe("op=purge only. When true, bypasses the require-a-filter guard."),
  ids: z
    .array(z.string().max(200))
    .min(1)
    .max(1000)
    .optional()
    .describe(
      "op=retry only. DLQ entry IDs returned by op=list. Required for retry; ignored otherwise.",
    ),
});

export const ingestDeadLetters = defineTool({
  name: "ingest_dead_letters",
  description:
    "Manage the ingest dead-letter queue (parse failure, invariant violation, empty yield). op=list reads with pagination + filters. op=purge bulk-deletes by filter (or all=true). op=retry re-attempts a set of entries against their datasets' *current* FieldConfigs — the canonical recovery flow after fixing a mapping via review(op=approve). The schema carries op-specific optional fields; the runtime rejects mismatched combinations (e.g. op=retry without ids).",
  category: "ingest",
  version: 1,
  stability: "stable",
  inputSchema: input,
  outputSchema: z.unknown(),
  async execute(ctx, { op, dataset_id, failure_kind, offset, limit, all, ids }) {
    if (op === "list") {
      const body: Record<string, unknown> = {};
      if (dataset_id != null) body.dataset_id = dataset_id;
      if (failure_kind != null) body.failure_kind = failure_kind;
      if (offset != null) body.offset = offset;
      if (limit != null) body.limit = limit;
      return ctx.api.post("/list_dead_letters", body);
    }
    if (op === "purge") {
      // Mirrors the runtime guard the old purge_dead_letters tool had:
      // either `all=true` or at least one filter must be set.
      if (!all && dataset_id == null && failure_kind == null) {
        throw new Error(
          "op=purge requires either all=true or at least one of dataset_id / failure_kind",
        );
      }
      const body: Record<string, unknown> = {};
      if (all != null) body.all = all;
      if (dataset_id != null) body.dataset_id = dataset_id;
      if (failure_kind != null) body.failure_kind = failure_kind;
      return ctx.api.post("/purge_dead_letters", body);
    }
    // op === "retry"
    if (!ids || ids.length === 0) {
      throw new Error("op=retry requires ids (DLQ entry IDs from op=list)");
    }
    return ctx.api.post("/reingest_dead_letter", { dlq_ids: ids }, HEAVY);
  },
});
