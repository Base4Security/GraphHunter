/**
 * ADR-004 §D3 — single adapter between the `Tool` interface and the
 * MCP SDK. Every tool in the registry is forwarded through this
 * function; stability/deprecation warnings and output validation
 * happen here so each tool file stays free of boilerplate.
 */
import { safeJsonContent, textContent } from "./lib/content.js";
import { truncate } from "./lib/log.js";
let requestCounter = 0;
function nextRequestId() {
    requestCounter = (requestCounter + 1) % Number.MAX_SAFE_INTEGER;
    return `r${Date.now()}_${requestCounter}`;
}
function isEmptyObjectSchema(schema) {
    if (!schema || typeof schema !== "object")
        return false;
    const def = schema._def;
    if (!def || def.typeName !== "ZodObject")
        return false;
    const shape = def.shape ? def.shape() : undefined;
    return !!shape && Object.keys(shape).length === 0;
}
export function registerTools(server, tools, makeContext) {
    for (const tool of tools) {
        const handler = async (rawInput) => {
            const requestId = nextRequestId();
            const ctx = makeContext(requestId);
            const start = Date.now();
            ctx.logger.tool(tool.name, { request_id: requestId });
            if (tool.stability === "experimental") {
                ctx.logger.warn(`experimental tool used: ${tool.name}`);
            }
            if (tool.deprecated) {
                ctx.logger.warn(`deprecated tool ${tool.name}`, tool.deprecated.replacement ? { replacement: tool.deprecated.replacement } : undefined);
            }
            try {
                const parsed = tool.inputSchema.parse(rawInput ?? {});
                const result = await tool.execute(ctx, parsed);
                ctx.logger.tool(tool.name + " done", { duration_ms: Date.now() - start });
                if (tool.resultFormat === "text") {
                    return textContent(typeof result === "string" ? result : String(result));
                }
                return safeJsonContent(result);
            }
            catch (e) {
                const msg = e instanceof Error ? e.message : String(e);
                ctx.logger.tool(tool.name + " error", {
                    duration_ms: Date.now() - start,
                    error: truncate(msg, 200),
                });
                return textContent(msg);
            }
        };
        // MCP SDK: pass the raw Zod shape for tools with input; for empty
        // schemas the SDK expects the no-arg overload.
        if (isEmptyObjectSchema(tool.inputSchema)) {
            server.tool(tool.name, tool.description, () => handler(undefined));
        }
        else {
            const shape = tool.inputSchema.shape;
            server.tool(tool.name, tool.description, shape, (input) => handler(input));
        }
    }
}
