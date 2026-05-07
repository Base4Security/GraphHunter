import { z } from "zod";
import { defineTool, type Tool } from "../lib/types.js";
import { HEAVY } from "../lib/api-client.js";

const input = z.object({
  target: z
    .enum(["sentinel_watchlist", "jira", "servicenow"])
    .describe(
      "External system to push to. sentinel_watchlist accepts kind=iocs only; jira/servicenow accept kind=hunt_context only.",
    ),
  kind: z
    .enum(["iocs", "hunt_context"])
    .describe("What payload to push. Validated against `target` at runtime."),
  // sentinel_watchlist
  watchlist_name: z
    .string()
    .min(1)
    .max(200)
    .optional()
    .describe(
      "target=sentinel_watchlist. Human-readable watchlist name (normalized to ARM alias on the server side).",
    ),
  display_name: z.string().max(200).optional().describe("Optional Sentinel displayName."),
  description: z.string().max(2_000).optional().describe("Optional Sentinel description."),
  tag_prefix: z
    .string()
    .max(100)
    .optional()
    .describe("kind=iocs. Tag prefix filter (default `ioc:`)."),
  // jira / servicenow
  title: z
    .string()
    .max(500)
    .optional()
    .describe("target=jira|servicenow. Ticket title."),
  body: z
    .string()
    .max(50_000)
    .optional()
    .describe("target=jira|servicenow. Ticket body / description."),
  priority: z
    .string()
    .max(50)
    .optional()
    .describe("target=jira|servicenow. Optional priority (system-specific)."),
  assignee: z
    .string()
    .max(200)
    .optional()
    .describe("target=jira: accountId. target=servicenow: username."),
  // safety gates (apply to all targets)
  dry_run: z
    .boolean()
    .optional()
    .describe("Preview the payload without making an external call."),
  confirm: z
    .boolean()
    .optional()
    .describe("Required to actually push; without it the call is rejected by the gate."),
});

export const publish = defineTool({
  name: "publish",
  description:
    "Push session artifacts to external systems. target=sentinel_watchlist + kind=iocs publishes the tagged IoCs as an Azure Sentinel Watchlist (replaces publish_iocs_to_sentinel). target=jira|servicenow + kind=hunt_context files a ticket with the hunt context (replaces file_ticket). Always honors `dry_run` / `confirm` gates plus the per-target env-var enable flags. The combo (target, kind) is validated at runtime so invalid pairs (e.g. target=jira + kind=iocs) reject cleanly.",
  category: "publish",
  version: 1,
  stability: "stable",
  inputSchema: input,
  outputSchema: z.unknown(),
  async execute(ctx, params) {
    const { target, kind } = params;
    if (target === "sentinel_watchlist") {
      if (kind !== "iocs")
        throw new Error("publish(target=sentinel_watchlist) only supports kind=iocs");
      if (!params.watchlist_name)
        throw new Error("publish(target=sentinel_watchlist) requires watchlist_name");
      const body: Record<string, unknown> = { watchlist_name: params.watchlist_name };
      if (params.display_name != null) body.display_name = params.display_name;
      if (params.description != null) body.description = params.description;
      if (params.tag_prefix != null) body.tag_prefix = params.tag_prefix;
      if (params.dry_run != null) body.dry_run = params.dry_run;
      if (params.confirm != null) body.confirm = params.confirm;
      return ctx.api.post("/publish_iocs_to_sentinel", body, HEAVY);
    }
    // ticketing
    if (kind !== "hunt_context")
      throw new Error(`publish(target=${target}) only supports kind=hunt_context`);
    if (!params.title || !params.body)
      throw new Error(`publish(target=${target}) requires title + body`);
    const body: Record<string, unknown> = {
      system: target,
      title: params.title,
      body: params.body,
    };
    if (params.priority != null) body.priority = params.priority;
    if (params.assignee != null) body.assignee = params.assignee;
    if (params.dry_run != null) body.dry_run = params.dry_run;
    if (params.confirm != null) body.confirm = params.confirm;
    return ctx.api.post("/file_ticket", body, HEAVY);
  },
});

export const publishTools: Tool[] = [publish];
