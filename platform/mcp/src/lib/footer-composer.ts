import type { Summary } from "./graph-state-client.js";

// ── Composes the always-present graph-context footer ──────────────────────
//
// The footer is the per-tool-response "what's in the graph?" digest that
// makes graph state continuously visible to Claude across every tool call.
// Two short lines max (~120 tokens):
//   line 1: totals + source freshness
//   line 2: active hunt + recent pivot — collapses when neither exists
//
// When summary is null (backend down / timed out), we still emit the
// header so clients can detect the footer's intent even in failure mode.

const HEADER = "---graph-context---";

export function composeFooter(summary: Summary | null): string {
  if (!summary) return `${HEADER}\n(unavailable)`;
  const lines: string[] = [HEADER];

  const nodes = compact(summary.totals.nodes);
  const edges = compact(summary.totals.edges);
  const sources = summary.sources
    .map((s) => `${s.name}(${freshness(s.last_ingest)})`)
    .join(", ");
  lines.push(
    `graph: ${nodes} nodes / ${edges} edges${sources ? `  |  sources: ${sources}` : ""}`,
  );

  const secondParts: string[] = [];
  if (summary.active_hunts.length > 0) {
    const h = summary.active_hunts[0];
    secondParts.push(
      `active hunt: ${h.cache_key.slice(0, 12)} (${h.params_summary})`,
    );
  }
  if (summary.recent_pivots.length > 0) {
    const p = summary.recent_pivots[0];
    secondParts.push(
      `recent pivot: ${p.entity} (${p.expanded ? "expanded" : "unexpanded"})`,
    );
  }
  if (secondParts.length > 0) lines.push(secondParts.join(" | "));

  return lines.join("\n");
}

function compact(n: number): string {
  if (n >= 1_000_000) return `${(n / 1_000_000).toFixed(1)}M`;
  if (n >= 1_000) return `${(n / 1_000).toFixed(1)}K`;
  return String(n);
}

function freshness(iso: string | null): string {
  if (!iso) return "unknown";
  const ms = Date.now() - new Date(iso).getTime();
  if (ms < 0) return "future";
  if (ms < 60_000) return `${Math.floor(ms / 1000)}s`;
  if (ms < 3_600_000) return `${Math.floor(ms / 60_000)}m`;
  if (ms < 86_400_000) return `${Math.floor(ms / 3_600_000)}h`;
  return `${Math.floor(ms / 86_400_000)}d`;
}
