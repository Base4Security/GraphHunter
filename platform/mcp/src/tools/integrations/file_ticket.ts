import { z } from "zod";
import { defineTool } from "../../lib/types.js";
import { HEAVY } from "../../lib/api-client.js";

const input = z.object({
  system: z.enum(["jira", "servicenow"]),
  title: z.string().min(1).max(500),
  body: z.string().min(1).max(50_000),
  priority: z.string().max(50).optional(),
  assignee: z.string().max(200).optional().describe("Jira: accountId. ServiceNow: username."),
  dry_run: z.boolean().optional(),
  confirm: z.boolean().optional(),
});

export const fileTicket = defineTool({
  name: "file_ticket",
  description:
    "Create a ticket in Jira Cloud or ServiceNow with the hunt context. Gated by env GRAPHHUNTER_TICKET_PUBLISH_ENABLED=1, `confirm:true` per call, or `dry_run:true` to preview. Jira requires env JIRA_BASE_URL, JIRA_EMAIL, JIRA_API_TOKEN, JIRA_PROJECT_KEY (optional JIRA_ISSUE_TYPE, default `Task`). ServiceNow requires SERVICENOW_INSTANCE, SERVICENOW_USERNAME, SERVICENOW_PASSWORD (optional SERVICENOW_TABLE, default `incident`). Response includes extracted `ticket_id` (Jira key or SN number).",
  category: "integrations",
  version: 1,
  stability: "stable",
  inputSchema: input,
  outputSchema: z.unknown(),
  async execute(ctx, { system, title, body, priority, assignee, dry_run, confirm }) {
    const requestBody: Record<string, unknown> = { system, title, body };
    if (priority != null) requestBody.priority = priority;
    if (assignee != null) requestBody.assignee = assignee;
    if (dry_run != null) requestBody.dry_run = dry_run;
    if (confirm != null) requestBody.confirm = confirm;
    return ctx.api.post("/file_ticket", requestBody, HEAVY);
  },
});
