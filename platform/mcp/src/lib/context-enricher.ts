import type { GraphStateClient, EntityRef } from "./graph-state-client.js";
import { extractEntities } from "./entity-extractor.js";
import { composeFooter } from "./footer-composer.js";
import { composeNudge } from "./nudge-composer.js";

// ── Wraps every tool response with a graph-context footer + nudge ─────────
//
// Best-effort by design: any failure in the enrichment path leaves the
// original tool output intact and appends "(unavailable)" footer. We never
// break a tool call to add context.
//
// Kill switch: `GH_MCP_ENRICH=off` env var, plus per-request opt-out via
// `args._meta.enrich === false` (useful for benchmark cleanliness).

export interface TextContent {
  type: "text";
  text: string;
}

export interface EnrichOutcome {
  content: TextContent[];
  /** True iff a non-empty nudge was appended. Used by Task 17 metrics. */
  nudged: boolean;
}

export class ContextEnricher {
  constructor(private client: GraphStateClient) {}

  async enrich(
    tool: string,
    args: Record<string, unknown>,
    original: TextContent[],
  ): Promise<EnrichOutcome> {
    if (process.env.GH_MCP_ENRICH === "off") {
      return { content: original, nudged: false };
    }
    const meta = (args as { _meta?: { enrich?: boolean } } | null)?._meta;
    if (meta?.enrich === false) {
      return { content: original, nudged: false };
    }

    const wantsOverlap = tool === "sentinel_query" && args.ingest !== true;

    const [summary, overlap] = await Promise.all([
      this.client.getSummary({ timeoutMs: 800 }),
      wantsOverlap ? this.runOverlap(original) : Promise.resolve(null),
    ]);

    // For node_expand the nudge wants the neighbor count, but that lives
    // in the *result* (Neighborhood.nodes.length) not the *input args*.
    // Inject it into the args view the nudge composer sees so the rule
    // table stays a pure function.
    const augmented =
      tool === "node_expand"
        ? { ...args, neighbors_found: this.countNeighbors(original) }
        : args;

    const footer = composeFooter(summary);
    const nudge = composeNudge(tool, augmented, overlap);
    const text = nudge ? `${footer}\n${nudge}` : footer;
    const appended: TextContent = { type: "text", text };
    return {
      content: [...original, appended],
      nudged: nudge !== null,
    };
  }

  private async runOverlap(content: TextContent[]) {
    try {
      const rows = this.parseRows(content);
      const entities = extractEntities(rows);
      const cast: EntityRef[] = entities.map((e) => ({
        type: e.type,
        value: e.value,
      }));
      if (cast.length === 0) return null;
      return await this.client.postOverlap(cast, { timeoutMs: 800 });
    } catch {
      return null;
    }
  }

  /**
   * Extracts the neighborhood node count from a node_expand result.
   * Looks for `nodes.length` first (Neighborhood shape) and falls back
   * to top-level array length. Returns 0 on any parse failure so the
   * nudge composer treats it as "no neighbors, no nudge".
   */
  private countNeighbors(content: TextContent[]): number {
    const first = content[0]?.text;
    if (!first) return 0;
    try {
      const parsed: unknown = JSON.parse(first);
      if (parsed && typeof parsed === "object") {
        const nodes = (parsed as { nodes?: unknown }).nodes;
        if (Array.isArray(nodes)) return nodes.length;
      }
      if (Array.isArray(parsed)) return parsed.length;
    } catch {
      /* fall through to 0 */
    }
    return 0;
  }

  /** Best-effort JSON parse of the first text block. */
  private parseRows(content: TextContent[]): Array<Record<string, unknown>> {
    const first = content[0]?.text;
    if (!first) return [];
    try {
      const parsed = JSON.parse(first);
      if (Array.isArray(parsed)) {
        return parsed as Array<Record<string, unknown>>;
      }
      if (parsed && typeof parsed === "object" && Array.isArray((parsed as { rows?: unknown }).rows)) {
        return (parsed as { rows: Array<Record<string, unknown>> }).rows;
      }
    } catch {
      /* fall through to empty */
    }
    return [];
  }
}
