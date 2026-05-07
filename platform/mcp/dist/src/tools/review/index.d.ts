import { type Tool } from "../../lib/types.js";
export declare const review: Tool<{
    op: "list" | "approve" | "reject";
    reason?: string | undefined;
    draft_id?: string | undefined;
    include_resolved?: boolean | undefined;
}, unknown>;
export declare const reviewTools: Tool[];
//# sourceMappingURL=index.d.ts.map