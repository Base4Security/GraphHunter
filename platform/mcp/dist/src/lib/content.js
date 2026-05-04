/**
 * Response sanitization for LLM consumption. Ported from
 * `graph-hunter-mcp/src/index.ts` without behavioral changes: same
 * caps, same collection keys, same truncation signals.
 *
 * LLM context is finite — raw API responses with 10K+ nodes can be
 * 50MB of JSON. These helpers cap arrays, truncate long strings, and
 * leave clear `_truncated` markers so the model knows it was clipped.
 */
const MAX_RESPONSE_CHARS = 100_000;
const MAX_ARRAY_ITEMS = 100;
const MAX_METADATA_VALUE_LEN = 200;
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
function truncateValue(v) {
    if (typeof v === "string" && v.length > MAX_METADATA_VALUE_LEN) {
        return v.slice(0, MAX_METADATA_VALUE_LEN - 20) + " ... " + v.slice(-15);
    }
    if (Array.isArray(v))
        return v.slice(0, 20).map(truncateValue);
    if (v && typeof v === "object")
        return sanitizeObject(v);
    return v;
}
function sanitizeObject(obj) {
    const result = {};
    for (const [key, val] of Object.entries(obj)) {
        if (val && typeof val === "object" && !Array.isArray(val)) {
            result[key] = sanitizeObject(val);
        }
        else {
            result[key] = truncateValue(val);
        }
    }
    return result;
}
export function sanitizeApiResponse(data) {
    if (data == null || typeof data !== "object")
        return data;
    if (Array.isArray(data)) {
        if (data.length <= MAX_ARRAY_ITEMS) {
            return data.map((item) => typeof item === "object" && item ? sanitizeObject(item) : item);
        }
        const truncated = data
            .slice(0, MAX_ARRAY_ITEMS)
            .map((item) => typeof item === "object" && item ? sanitizeObject(item) : item);
        return {
            _truncated: true,
            _total: data.length,
            _showing: MAX_ARRAY_ITEMS,
            _hint: `Showing first ${MAX_ARRAY_ITEMS} of ${data.length} items. Use pagination or filters to access the rest.`,
            items: truncated,
        };
    }
    const obj = data;
    const result = {};
    for (const [key, val] of Object.entries(obj)) {
        if (Array.isArray(val) && COLLECTION_KEYS.includes(key)) {
            if (val.length > MAX_ARRAY_ITEMS) {
                result[`_${key}_total`] = val.length;
                result[`_${key}_truncated`] = true;
                result[key] = val.slice(0, MAX_ARRAY_ITEMS).map((item) => typeof item === "object" && item
                    ? sanitizeObject(item)
                    : item);
            }
            else {
                result[key] = val.map((item) => typeof item === "object" && item
                    ? sanitizeObject(item)
                    : item);
            }
        }
        else if (val && typeof val === "object" && !Array.isArray(val)) {
            result[key] = sanitizeObject(val);
        }
        else {
            result[key] = truncateValue(val);
        }
    }
    return result;
}
export function textContent(text) {
    if (text.length <= MAX_RESPONSE_CHARS) {
        return { content: [{ type: "text", text }] };
    }
    const trimmed = text.slice(0, MAX_RESPONSE_CHARS - 200);
    const notice = `\n\n--- RESPONSE TRUNCATED (${text.length} chars total, showing first ${MAX_RESPONSE_CHARS - 200}). Use pagination parameters or narrower filters to get manageable results. ---`;
    return { content: [{ type: "text", text: trimmed + notice }] };
}
export function safeJsonContent(data) {
    const sanitized = sanitizeApiResponse(data);
    return textContent(JSON.stringify(sanitized, null, 2));
}
