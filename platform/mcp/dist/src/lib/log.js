/**
 * Structured stderr logger. Stdout is reserved for the MCP protocol.
 * Ported from `graph-hunter-mcp/src/index.ts` log() without behavioral
 * changes — same prefix, same JSON tail, same levels.
 */
const LOG_PREFIX = "[graph-hunter-mcp]";
export function createLogger() {
    const write = (level, message, detail) => {
        const ts = new Date().toISOString();
        const detailStr = detail && Object.keys(detail).length > 0 ? ` ${JSON.stringify(detail)}` : "";
        process.stderr.write(`${LOG_PREFIX} [${ts}] [${level}] ${message}${detailStr}\n`);
    };
    return {
        info: (m, d) => write("info", m, d),
        warn: (m, d) => write("warn", m, d),
        error: (m, d) => write("error", m, d),
        tool: (m, d) => write("tool", m, d),
        api: (m, d) => write("api", m, d),
    };
}
export function truncate(s, maxLen = 80) {
    if (s.length <= maxLen)
        return s;
    return s.slice(0, maxLen - 3) + "...";
}
