/**
 * HTTP client for the GraphHunter desktop app's local API. One instance
 * is threaded through `ToolContext.api`. Ports `apiGet`/`apiPost` from
 * `graph-hunter-mcp/src/index.ts` — same error shape, same timeouts,
 * same JSON-vs-HTML detection.
 */

import type { ApiClient, Logger } from "./types.js";
import { truncate } from "./log.js";

export const DEFAULT_API_TIMEOUT_MS = 30_000;
/** Extended timeout for graph operations that may touch high-degree nodes. */
export const HEAVY_TIMEOUT_MS = 120_000;

export { HEAVY_TIMEOUT_MS as HEAVY };

export interface ApiClientConfig {
  baseUrl: string;
  token: string;
  logger: Logger;
  debug: boolean;
}

export function createApiClient(cfg: ApiClientConfig): ApiClient {
  const connErr = `GraphHunter app unreachable at ${cfg.baseUrl}. Ensure: (1) GraphHunter desktop app is running, (2) a session is loaded, (3) data has been ingested so the graph is non-empty.`;
  const notGhErr = `The server at ${cfg.baseUrl} responded but did not return JSON (e.g. it returned HTML). Another app may be using this port. Use only the GraphHunter desktop app on this port, or set GRAPHHUNTER_API_URL to the correct URL.`;

  const authHeaders = (): Record<string, string> =>
    cfg.token ? { Authorization: `Bearer ${cfg.token}` } : {};

  const fetchWithTimeout = (
    url: string,
    options: RequestInit & { timeoutMs: number },
  ): Promise<Response> => {
    const { timeoutMs, ...fetchOptions } = options;
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), timeoutMs);
    return fetch(url, { ...fetchOptions, signal: controller.signal }).finally(() =>
      clearTimeout(timeoutId),
    );
  };

  const parseJsonResponse = async (res: Response): Promise<unknown> => {
    const contentType = res.headers.get("content-type") ?? "";
    const text = await res.text();
    const looksLikeHtml =
      contentType.toLowerCase().includes("text/html") ||
      text.trim().toLowerCase().startsWith("<!");
    if (looksLikeHtml) throw new Error(notGhErr);
    try {
      return text ? JSON.parse(text) : {};
    } catch {
      throw new Error(notGhErr);
    }
  };

  const get = async (
    path: string,
    params?: Record<string, string>,
    timeoutMs?: number,
  ): Promise<unknown> => {
    const effectiveTimeout = timeoutMs ?? DEFAULT_API_TIMEOUT_MS;
    const url = new URL(path, cfg.baseUrl);
    if (params) {
      for (const [k, v] of Object.entries(params)) {
        if (v !== undefined && v !== "") url.searchParams.set(k, v);
      }
    }
    const start = Date.now();
    cfg.logger.api(
      "GET " + path,
      params ? { params: Object.keys(params).join(",") } : undefined,
    );
    let res: Response;
    try {
      res = await fetchWithTimeout(url.toString(), {
        headers: authHeaders(),
        timeoutMs: effectiveTimeout,
      });
    } catch (e) {
      const msg = e instanceof Error ? e.message : String(e);
      const isAbort = msg.includes("abort") || (e instanceof Error && e.name === "AbortError");
      cfg.logger.api("GET " + path + " failed", {
        error: truncate(msg, 120),
        duration_ms: Date.now() - start,
      });
      throw new Error(
        isAbort
          ? `${connErr} Request timed out after ${effectiveTimeout}ms.`
          : `${connErr} Network error: ${msg}`,
      );
    }
    const data = await parseJsonResponse(res);
    const durationMs = Date.now() - start;
    const responseSize =
      cfg.debug && typeof data === "object" ? JSON.stringify(data).length : undefined;
    if (!res.ok) {
      const err = data as { error?: string };
      const msg = err?.error ?? res.statusText;
      cfg.logger.api("GET " + path + " error", {
        status: res.status,
        message: truncate(String(msg), 100),
        duration_ms: durationMs,
      });
      throw new Error(`${res.status} ${res.statusText}: ${msg}`);
    }
    cfg.logger.api("GET " + path + " ok", {
      status: res.status,
      duration_ms: durationMs,
      ...(responseSize != null ? { response_bytes: responseSize } : {}),
    });
    return data;
  };

  const post = async (path: string, body: unknown, timeoutMs?: number): Promise<unknown> => {
    const effectiveTimeout = timeoutMs ?? DEFAULT_API_TIMEOUT_MS;
    const url = new URL(path, cfg.baseUrl);
    const start = Date.now();
    const bodySummary =
      body && typeof body === "object" && !Array.isArray(body)
        ? Object.fromEntries(
            Object.entries(body).map(([k, v]) => [
              k,
              Array.isArray(v) ? `[${v.length}]` : truncate(String(v), 40),
            ]),
          )
        : {};
    cfg.logger.api("POST " + path, bodySummary);
    let res: Response;
    const headers: Record<string, string> = {
      "Content-Type": "application/json",
      ...authHeaders(),
    };
    try {
      res = await fetchWithTimeout(url.toString(), {
        method: "POST",
        headers,
        body: JSON.stringify(body),
        timeoutMs: effectiveTimeout,
      });
    } catch (e) {
      const msg = e instanceof Error ? e.message : String(e);
      const isAbort = msg.includes("abort") || (e instanceof Error && e.name === "AbortError");
      cfg.logger.api("POST " + path + " failed", {
        error: truncate(msg, 120),
        duration_ms: Date.now() - start,
      });
      throw new Error(
        isAbort
          ? `${connErr} Request timed out after ${effectiveTimeout}ms.`
          : `${connErr} Network error: ${msg}`,
      );
    }
    const data = await parseJsonResponse(res);
    const durationMs = Date.now() - start;
    const responseSize =
      cfg.debug && typeof data === "object" ? JSON.stringify(data).length : undefined;
    if (!res.ok) {
      const err = data as { error?: string };
      const msg = err?.error ?? res.statusText;
      cfg.logger.api("POST " + path + " error", {
        status: res.status,
        message: truncate(String(msg), 100),
        duration_ms: durationMs,
      });
      throw new Error(`${res.status} ${res.statusText}: ${msg}`);
    }
    cfg.logger.api("POST " + path + " ok", {
      status: res.status,
      duration_ms: durationMs,
      ...(responseSize != null ? { response_bytes: responseSize } : {}),
    });
    return data;
  };

  return { get, post };
}
