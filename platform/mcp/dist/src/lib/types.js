/**
 * ADR-004 §D1 — Tool interface.
 *
 * Every MCP tool is a `Tool<I, O>` value produced by `defineTool`. The
 * registry (`src/registry.ts`) collects them and a single place in
 * `src/server.ts` forwards each one to the MCP SDK. Adding a tool =
 * creating one file under `src/tools/<category>/` and exporting it.
 */
export function defineTool(def) {
    return def;
}
