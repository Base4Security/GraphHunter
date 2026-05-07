import { type Tool } from "../lib/types.js";
export declare const exportTool: Tool<{
    format: string;
    kind: "hunt" | "iocs" | "ocsf";
    page?: number | undefined;
    page_size?: number | undefined;
    hypothesis_dsl?: string | undefined;
    tag_prefix?: string | undefined;
    dataset_id?: string | undefined;
    aggregate?: boolean | undefined;
    title?: string | undefined;
    level?: "low" | "medium" | "high" | "critical" | undefined;
}, string>;
export declare const exportTools: Tool[];
//# sourceMappingURL=export.d.ts.map