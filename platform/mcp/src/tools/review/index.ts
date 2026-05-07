import { z } from "zod";
import { defineTool, type Tool } from "../../lib/types.js";

const input = z.object({
  op: z
    .enum(["approve", "reject", "list"])
    .describe(
      "Discriminator. approve: stamp a draft. reject: persist a reason. list: read the queue.",
    ),
  draft_id: z
    .string()
    .max(200)
    .optional()
    .describe("Required for op=approve and op=reject. Ignored for op=list."),
  reason: z
    .string()
    .min(1)
    .max(2000)
    .optional()
    .describe("Required for op=reject (cannot be empty/whitespace). Stored verbatim on the draft."),
  include_resolved: z
    .boolean()
    .optional()
    .describe("op=list only. When true, also return Approved/Rejected drafts for audit."),
});

export const review = defineTool({
  name: "review",
  description:
    "Manage MappingDrafts in the review queue. op=approve stamps a draft (for IngestNegotiator drafts, also promotes the FieldConfig onto the dataset). op=reject persists a required reason. op=list returns pending drafts (or all when include_resolved=true). Idempotent on already-resolved drafts.",
  category: "review",
  version: 1,
  stability: "stable",
  inputSchema: input,
  outputSchema: z.unknown(),
  async execute(ctx, { op, draft_id, reason, include_resolved }) {
    if (op === "approve") {
      if (!draft_id) throw new Error("op=approve requires draft_id");
      return ctx.api.post("/agentic_review_approve", { draft_id });
    }
    if (op === "reject") {
      if (!draft_id) throw new Error("op=reject requires draft_id");
      if (!reason || !reason.trim())
        throw new Error("op=reject requires a non-empty reason");
      return ctx.api.post("/agentic_review_reject", { draft_id, reason });
    }
    // op === "list"
    const body: Record<string, unknown> = {};
    if (include_resolved != null) body.include_resolved = include_resolved;
    return ctx.api.post("/agentic_review_list", body);
  },
});

export const reviewTools: Tool[] = [review];
