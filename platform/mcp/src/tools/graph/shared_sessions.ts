import { z } from "zod";
import { defineTool } from "../../lib/types.js";
import { HEAVY } from "../../lib/api-client.js";

export const graphSharedSessions = defineTool({
  name: "graph_shared_sessions",
  description:
    "Find sessions that more than one account was seen on -- the signature of a stolen token or a shared cookie, since a session id normally belongs to exactly one identity. Rare and high-value: on a 60,000-session corpus exactly one row came back, and it joined two accounts already confirmed as compromised, which no timing argument had connected. Ask this when triaging suspected account takeover, or when you have one confirmed victim and want to know which other accounts the same operator touched. Each row carries the accounts, the addresses the session was opened from, and its span. IMPORTANT: read `sessions_examined` before concluding anything from an empty list -- zero means the graph holds no session entities at all (the source carried no correlation id, or the ingest ceiling refused them), which is a different answer from 'checked and found none'; the `note` field says which.",
  category: "graph",
  version: 1,
  stability: "stable",
  inputSchema: z.object({
    limit: z
      .number()
      .int()
      .min(1)
      .max(5000)
      .optional()
      .describe("Maximum rows to return. Defaults to 500. Check `truncated` in the response."),
  }),
  outputSchema: z.unknown(),
  async execute(ctx, { limit }) {
    // Query params go on the wire as strings.
    return ctx.api.get(
      "/sessions/shared",
      limit == null ? undefined : { limit: String(limit) },
      HEAVY,
    );
  },
});
