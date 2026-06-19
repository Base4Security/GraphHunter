import { z } from "zod";

// ── Shared zod schemas for /graph/summary and /graph/overlap ───────────────
//
// All four payloads carry `schema_version: literal(1)`. Bumping the version
// is a coordinated change across the Rust DTO (platform/api/src/dto/v1/
// graph_meta.rs), this file, and the shared golden fixture (Task 16). A
// mismatch fails loudly here at parse time.

const TopNeighborSchema = z.object({
  entity: z.string(),
  type: z.string(),
  edge_count: z.number(),
});

const FoundEntitySchema = z.object({
  entity: z.string(),
  type: z.string(),
  degree: z.number(),
  top_neighbor: TopNeighborSchema.optional().nullable(),
});

export const SummarySchema = z.object({
  schema_version: z.literal(1),
  as_of: z.string(),
  totals: z.object({
    nodes: z.number(),
    edges: z.number(),
    by_type: z.record(z.string(), z.number()),
  }),
  sources: z.array(
    z.object({
      name: z.string(),
      last_ingest: z.string().nullable(),
      rows_lifetime: z.number(),
    }),
  ),
  active_datasets: z.array(z.string()),
  active_hunts: z.array(
    z.object({
      cache_key: z.string(),
      params_summary: z.string(),
      result_size: z.number(),
      computed_at: z.string(),
      ttl_seconds_remaining: z.number(),
    }),
  ),
  recent_pivots: z.array(
    z.object({
      entity: z.string(),
      type: z.string(),
      added_at: z.string(),
      expanded: z.boolean(),
      degree: z.number(),
    }),
  ),
  graph_empty: z.boolean(),
});
export type Summary = z.infer<typeof SummarySchema>;

export const OverlapResponseSchema = z.object({
  schema_version: z.literal(1),
  found: z.array(FoundEntitySchema),
  missing: z.array(z.string()),
});
export type OverlapResponse = z.infer<typeof OverlapResponseSchema>;

export interface EntityRef {
  type: string;
  value: string;
}

export interface ClientOpts {
  fetchImpl?: typeof fetch;
}

/**
 * Typed client for the backend's `/graph/summary` and `/graph/overlap`
 * endpoints. Every call is timeboxed; on timeout or 5xx the methods
 * return `null` rather than throwing — the ContextEnricher treats `null`
 * as "(unavailable)" and the surrounding tool call is never broken by
 * an enrichment failure.
 */
export class GraphStateClient {
  constructor(
    private baseUrl: string,
    private opts: ClientOpts = {},
  ) {}

  /** Fetch the cached /graph/summary payload. Returns null on timeout/5xx. */
  async getSummary(o: { timeoutMs: number }): Promise<Summary | null> {
    return this.callJson(
      `${this.baseUrl}/graph/summary`,
      "GET",
      undefined,
      o.timeoutMs,
      SummarySchema,
    );
  }

  /**
   * POST /graph/overlap with up to 500 entities. Above the cap throws
   * synchronously (the backend would 413 — this surfaces faster).
   */
  async postOverlap(
    entities: EntityRef[],
    o: { timeoutMs?: number } = {},
  ): Promise<OverlapResponse | null> {
    if (entities.length > 500) {
      throw new Error(`overlap: max 500 entities per request (got ${entities.length})`);
    }
    return this.callJson(
      `${this.baseUrl}/graph/overlap`,
      "POST",
      { schema_version: 1, entities },
      o.timeoutMs ?? 800,
      OverlapResponseSchema,
    );
  }

  private async callJson<T>(
    url: string,
    method: "GET" | "POST",
    body: unknown,
    timeoutMs: number,
    schema: z.ZodType<T>,
  ): Promise<T | null> {
    const ctl = new AbortController();
    const timer = setTimeout(() => ctl.abort(), timeoutMs);
    const f = this.opts.fetchImpl ?? fetch;
    try {
      const resp = await f(url, {
        method,
        signal: ctl.signal,
        headers: body ? { "content-type": "application/json" } : undefined,
        body: body ? JSON.stringify(body) : undefined,
      } as RequestInit);
      if (!resp.ok) return null;
      return schema.parse(await resp.json());
    } catch {
      return null;
    } finally {
      clearTimeout(timer);
    }
  }
}
