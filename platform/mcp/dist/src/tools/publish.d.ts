import { type Tool } from "../lib/types.js";
export declare const publish: Tool<{
    target: "sentinel_watchlist" | "jira" | "servicenow";
    kind: "iocs" | "hunt_context";
    body?: string | undefined;
    priority?: string | undefined;
    tag_prefix?: string | undefined;
    title?: string | undefined;
    watchlist_name?: string | undefined;
    display_name?: string | undefined;
    description?: string | undefined;
    assignee?: string | undefined;
    dry_run?: boolean | undefined;
    confirm?: boolean | undefined;
}, unknown>;
export declare const publishTools: Tool[];
//# sourceMappingURL=publish.d.ts.map