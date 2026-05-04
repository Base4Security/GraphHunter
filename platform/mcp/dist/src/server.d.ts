/**
 * ADR-004 §D3 — single adapter between the `Tool` interface and the
 * MCP SDK. Every tool in the registry is forwarded through this
 * function; stability/deprecation warnings and output validation
 * happen here so each tool file stays free of boilerplate.
 */
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import type { Tool, ToolContext } from "./lib/types.js";
export declare function registerTools(server: McpServer, tools: Tool[], makeContext: (requestId: string) => ToolContext): void;
//# sourceMappingURL=server.d.ts.map