import { z } from "zod";
import { defineTool } from "../../lib/types.js";
export const checkConnection = defineTool({
    name: "check_connection",
    description: "Check if the GraphHunter desktop app is reachable and whether a session is loaded. Call this first before other tools to avoid timeouts or unclear errors.",
    category: "navigation",
    version: 1,
    stability: "stable",
    inputSchema: z.object({}),
    outputSchema: z.unknown(),
    async execute(ctx) {
        return ctx.api.get("/health");
    },
});
