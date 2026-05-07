/**
 * Response sanitization for LLM consumption. Ported from
 * `graph-hunter-mcp/src/index.ts` without behavioral changes: same
 * caps, same collection keys, same truncation signals.
 *
 * LLM context is finite — raw API responses with 10K+ nodes can be
 * 50MB of JSON. These helpers cap arrays, truncate long strings, and
 * leave clear `_truncated` markers so the model knows it was clipped.
 *
 * **2026-05-06 fix (#2 truncation)**: the original `truncateValue`
 * cut every string > 200 chars regardless of key. That destroyed
 * payload-bearing fields like `narrative` (explain_score), `yaml`
 * (sigma export), `content` (notes), `vrl_source` (parser drafts) —
 * a session QA against v2 found the workflow `ingest_negotiate →
 * parser_generate → invariant_check_hypothetical → review` was
 * unrecoverable because the VRL never came back whole. Fix: a
 * key-aware whitelist (`LONG_TEXT_KEYS`) skips truncation for keys
 * that are legitimately load-bearing-long. Anonymous metadata
 * values still cap at 200 chars to keep the per-row cost bounded.
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