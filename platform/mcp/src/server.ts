/**
 * ADR-004 §D3 — single adapter between the `Tool` interface and the
 * MCP SDK. Every tool in the registry is forwarded through this
 * function; stability/deprecation warnings and output validation
 * happen here so each tool file stays free of boilerplate.
 */

import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import type { ContextEnricher } from "./lib/context-enricher.js";
import type { Tool, ToolContext } from "./lib/types.js";
import { safeJsonContent, textContent } from "./lib/content.js";
import { truncate } from "./lib/log.js";

let requestCounter = 0;

function nextRequestId(): string {
  requestCounter = (requestCounter + 1) % Number.MAX_SAFE_INTEGER;
  return `r${Date.now()}_${requestCounter}`;
}

function isEmptyObjectSchema(schema: unknown): boolean {
  if (!schema || typeof schema !== "object") return false;
  const def = (schema as { _def?: { typeName?: string; shape?: () => Record<string, unknown> } })._def;
  if (!def || def.typeName !== "ZodObject") return false;
  const shape = def.shape ? def.shape() : undefined;
  return !!shape && Object.keys(shape).length === 0;
}

export function registerTools(
  server: McpServer,
  tools: Tool[],
  makeContext: (requestId: string) => ToolContext,
  enricher?: ContextEnricher,
): void {
  for (const tool of tools) {
    const handler = async (rawInput: unknown) => {
      const requestId = nextRequestId();
      const ctx = makeContext(requestId);
      const start = Date.now();
      ctx.logger.tool(tool.name, { request_id: requestId });

      if (tool.stability === "experimental") {
        ctx.logger.warn(`experimental tool used: ${tool.name}`);
      }
      if (tool.deprecated) {
        ctx.logger.warn(
          `deprecated tool ${tool.name}`,
          tool.deprecated.replacement ? { replacement: tool.deprecated.replacement } : undefined,
        );
      }

      let parsedInput: Record<string, unknown> = {};
      try {
        const parsed = tool.inputSchema.parse(rawInput ?? {});
        parsedInput = (parsed ?? {}) as Record<string, unknown>;
        const result = await tool.execute(ctx, parsed);
        ctx.logger.tool(tool.name + " done", { duration_ms: Date.now() - start });
        const raw =
          tool.resultFormat === "text"
            ? textContent(typeof result === "string" ? result : String(result))
            : safeJsonContent(result);

        if (!enricher) return raw;
        const outcome = await enricher.enrich(
          tool.name,
          parsedInput,
          raw.content as Array<{ type: "text"; text: string }>,
        );
        return { ...raw, content: outcome.content };
      } catch (e) {
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
    } else {
      const shape = (tool.inputSchema as unknown as z.ZodObject<z.ZodRawShape>).shape;
      server.tool(tool.name, tool.description, shape, (input: unknown) => handler(input));
    }
  }
}
