/**
 * HTTP client for the GraphHunter desktop app's local API. One instance
 * is threaded through `ToolContext.api`. Ports `apiGet`/`apiPost` from
 * `graph-hunter-mcp/src/index.ts` — same error shape, same timeouts,
 * same JSON-vs-HTML detection.
 */
import type { ApiClient, Logger } from "./types.js";
export declare const DEFAULT_API_TIMEOUT_MS = 30000;
/** Extended timeout for graph operations that may touch high-degree nodes. */
export declare const HEAVY_TIMEOUT_MS = 120000;
export { HEAVY_TIMEOUT_MS as HEAVY };
export interface ApiClientConfig {
    baseUrl: string;
    token: string;
    logger: Logger;
    debug: boolean;
}
export declare function createApiClient(cfg: ApiClientConfig): ApiClient;
//# sourceMappingURL=api-client.d.ts.map