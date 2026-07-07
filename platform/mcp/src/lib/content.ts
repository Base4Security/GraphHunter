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

const MAX_RESPONSE_CHARS = 100_000;
const MAX_ARRAY_ITEMS = 100;
// 2026-05-06: bumped from 200 → 50 000. The 200-char cap was a relic
// of the original metadata-bag protection (raw event JSON dumps that
// could be hundreds of KB). With `MAX_RESPONSE_CHARS` capping the
// whole payload at 100 KB and `MAX_ARRAY_ITEMS` capping arrays at 100,
// the per-string-value cap was redundant *and* mauling load-bearing
// fields (analyst notes, narrative paragraphs, sigma yaml, vrl
// source). 50 000 means a single truly runaway value still gets cut,
// but reasonable analyst content always round-trips. Set
// `GRAPHHUNTER_MCP_NO_TRUNCATE=1` to disable per-key truncation
// entirely (only `MAX_RESPONSE_CHARS` then applies).
const MAX_METADATA_VALUE_LEN = 50_000;
const PER_KEY_TRUNCATION_DISABLED =
  process.env.GRAPHHUNTER_MCP_NO_TRUNCATE === "1" ||
  process.env.GRAPHHUNTER_MCP_NO_TRUNCATE === "true";

const COLLECTION_KEYS = [
  "nodes",
  "edges",
  "events",
  "paths",
  "entities",
  "items",
  "subnets",
  "datasets",
  "notes",
];

/**
 * String values living under any of these keys are passed through
 * verbatim. They are the contracts callers depend on for downstream
 * use (LLM narratives, generated rule YAML, user-authored notes,
 * compiled VRL, KQL audit echoes, ingestion rationale, raw command
 * lines that constitute hunt signal). When the response itself is a
 * single such field, it usually flows through `resultFormat: "text"`
 * which already bypasses sanitization — but for tools that return
 * JSON with these keys embedded, this whitelist is what keeps them
 * intact.
 *
 * Add to this set when a new tool exposes a payload field that
 * should round-trip without truncation. The catch-all
 * `MAX_METADATA_VALUE_LEN` still protects unknown long strings.
 */
const LONG_TEXT_KEYS = new Set([
  "narrative",
  "yaml",
  "content",
  "vrl_source",
  "rationale",
  "kql",
  "kql_executed",
  "dsl",
  "hypothesis_dsl",
  "formatted",
  "description",
  "summary",
  "explanation",
  "message",
  "reason",
  "skipped_reason",
  "raw_sample",
  "candidate_vrl",
  "hypothetical_vrl",
  "command_line",
  "process_command_line",
  "cmdline",
  "ProcessCommandLine",
]);

function truncateValue(v: unknown, key?: string): unknown {
  if (typeof v === "string" && v.length > MAX_METADATA_VALUE_LEN) {
    // Whitelisted keys carry meaningful payload — pass through.
    if (key && LONG_TEXT_KEYS.has(key)) return v;
    // Operator escape hatch: skip per-key truncation entirely and
    // rely only on the whole-response cap (`MAX_RESPONSE_CHARS`).
    if (PER_KEY_TRUNCATION_DISABLED) return v;
    return v.slice(0, MAX_METADATA_VALUE_LEN - 20) + " ... " + v.slice(-15);
  }
  if (Array.isArray(v)) return v.slice(0, 20).map((item) => truncateValue(item, key));
  if (v && typeof v === "object") return sanitizeObject(v as Record<string, unknown>);
  return v;
}

function sanitizeObject(obj: Record<string, unknown>): Record<string, unknown> {
  const result: Record<string, unknown> = {};
  for (const [key, val] of Object.entries(obj)) {
    if (val && typeof val === "object" && !Array.isArray(val)) {
      result[key] = sanitizeObject(val as Record<string, unknown>);
    } else {
      result[key] = truncateValue(val, key);
    }
  }
  return result;
}

export function sanitizeApiResponse(data: unknown): unknown {
  if (data == null || typeof data !== "object") return data;
  if (Array.isArray(data)) {
    if (data.length <= MAX_ARRAY_ITEMS) {
      return data.map((item) =>
        typeof item === "object" && item ? sanitizeObject(item as Record<string, unknown>) : item,
      );
    }
    const truncated = data
      .slice(0, MAX_ARRAY_ITEMS)
      .map((item) =>
        typeof item === "object" && item ? sanitizeObject(item as Record<string, unknown>) : item,
      );
    return {
      _truncated: true,
      _total: data.length,
      _showing: MAX_ARRAY_ITEMS,
      _hint: `Showing first ${MAX_ARRAY_ITEMS} of ${data.length} items. Use pagination or filters to access the rest.`,
      items: truncated,
    };
  }
  const obj = data as Record<string, unknown>;
  const result: Record<string, unknown> = {};
  for (const [key, val] of Object.entries(obj)) {
    if (Array.isArray(val) && COLLECTION_KEYS.includes(key)) {
      if (val.length > MAX_ARRAY_ITEMS) {
        result[`_${key}_total`] = val.length;
        result[`_${key}_truncated`] = true;
        result[key] = val.slice(0, MAX_ARRAY_ITEMS).map((item) =>
          typeof item === "object" && item
            ? sanitizeObject(item as Record<string, unknown>)
            : item,
        );
      } else {
        result[key] = val.map((item) =>
          typeof item === "object" && item
            ? sanitizeObject(item as Record<string, unknown>)
            : item,
        );
      }
    } else if (val && typeof val === "object" && !Array.isArray(val)) {
      result[key] = sanitizeObject(val as Record<string, unknown>);
    } else {
      // Pass `key` so the long-text whitelist (LONG_TEXT_KEYS) can
      // skip truncation for payload-bearing fields at the top level.
      result[key] = truncateValue(val, key);
    }
  }
  return result;
}

export type McpTextContent = { content: Array<{ type: "text"; text: string }> };

export function textContent(text: string): McpTextContent {
  if (text.length <= MAX_RESPONSE_CHARS) {
    return { content: [{ type: "text", text }] };
  }
  const trimmed = text.slice(0, MAX_RESPONSE_CHARS - 200);
  const notice = `\n\n--- RESPONSE TRUNCATED (${text.length} chars total, showing first ${MAX_RESPONSE_CHARS - 200}). Use pagination parameters or narrower filters to get manageable results. ---`;
  return { content: [{ type: "text", text: trimmed + notice }] };
}

export function safeJsonContent(data: unknown): McpTextContent {
  const sanitized = sanitizeApiResponse(data);
  return textContent(JSON.stringify(sanitized, null, 2));
}
