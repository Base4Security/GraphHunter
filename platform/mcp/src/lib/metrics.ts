// ── Lightweight in-process counters for the graph-context feature ─────────
//
// Tracks the metrics that distinguish "GraphHunter is being used as a graph"
// from "GraphHunter is being used as a thin proxy in front of Sentinel KQL"
// (the very thing this whole feature is designed to fix). Counts only —
// no histograms, no labels beyond tool/uri keys, no remote sink. snapshot()
// returns a serialisable object that a later task can wire to a /metrics
// endpoint or a Prometheus exporter.
//
// The defining ratios for the rollout success criteria:
//   - tool_calls[sentinel_query] / total tool_calls  → should drop
//   - nudges_followed / nudges_displayed              → follow-through
//   - resource_reads[graph://summary]                 → orientation count

export interface MetricsSnapshot {
  tool_calls: Record<string, number>;
  nudges_displayed: Record<string, number>;
  nudges_followed: Record<string, number>;
  resource_reads: Record<string, number>;
}

export class Metrics {
  private toolCalls = new Map<string, number>();
  private nudgesDisplayed = new Map<string, number>();
  private nudgesFollowed = new Map<string, number>();
  private resourceReads = new Map<string, number>();

  incToolCall(tool: string): void {
    this.bump(this.toolCalls, tool);
  }

  incNudgeDisplayed(tool: string): void {
    this.bump(this.nudgesDisplayed, tool);
  }

  incNudgeFollowed(tool: string): void {
    this.bump(this.nudgesFollowed, tool);
  }

  incResourceRead(uri: string): void {
    this.bump(this.resourceReads, uri);
  }

  snapshot(): MetricsSnapshot {
    return {
      tool_calls: Object.fromEntries(this.toolCalls),
      nudges_displayed: Object.fromEntries(this.nudgesDisplayed),
      nudges_followed: Object.fromEntries(this.nudgesFollowed),
      resource_reads: Object.fromEntries(this.resourceReads),
    };
  }

  private bump(m: Map<string, number>, k: string): void {
    m.set(k, (m.get(k) ?? 0) + 1);
  }
}

/**
 * Tracks per-session follow-through: when a sentinel_query nudge was
 * displayed and the *next* tool call was a graph-side tool, that counts
 * as "followed".
 *
 * Graph-side tools are the ones whose name does NOT start with
 * "sentinel_" — that captures node_expand, hunt_run, heavy_edges,
 * channel_behavior, etc., without enumerating every one.
 */
export class FollowthroughTracker {
  private lastNudgedTool: string | null = null;

  recordNudge(tool: string): void {
    this.lastNudgedTool = tool;
  }

  /** Returns true if the call should be counted as a nudge follow-through. */
  recordCall(tool: string): { followedNudgeFor: string | null } {
    const previous = this.lastNudgedTool;
    if (previous && !tool.startsWith("sentinel_")) {
      this.lastNudgedTool = null;
      return { followedNudgeFor: previous };
    }
    if (!previous) return { followedNudgeFor: null };
    // Another sentinel_query call — not a follow-through, but reset
    // so a stale nudge from N calls ago does not over-credit.
    this.lastNudgedTool = null;
    return { followedNudgeFor: null };
  }
}
