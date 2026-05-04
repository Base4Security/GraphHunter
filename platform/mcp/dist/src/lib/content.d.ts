/**
 * Response sanitization for LLM consumption. Ported from
 * `graph-hunter-mcp/src/index.ts` without behavioral changes: same
 * caps, same collection keys, same truncation signals.
 *
 * LLM context is finite — raw API responses with 10K+ nodes can be
 * 50MB of JSON. These helpers cap arrays, truncate long strings, and
 * leave clear `_truncated` markers so the model knows it was clipped.
 */
export declare function sanitizeApiResponse(data: unknown): unknown;
export type McpTextContent = {
    content: Array<{
        type: "text";
        text: string;
    }>;
};
export declare function textContent(text: string): McpTextContent;
export declare function safeJsonContent(data: unknown): McpTextContent;
//# sourceMappingURL=content.d.ts.map