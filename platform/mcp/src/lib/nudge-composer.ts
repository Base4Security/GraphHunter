import type { OverlapResponse } from "./graph-state-client.js";

// ── Per-tool nudge rules ──────────────────────────────────────────────────
//
// Nudges are short, non-prescriptive suggestions appended after the footer.
// They steer Claude toward the graph-native tool that would answer the
// question better than another raw KQL. Rules table:
//
//   sentinel_query(ingest=false), overlap>0 → suggest node_expand on top
//   sentinel_query(ingest=false), overlap=0 → suggest ingest=true
//   sentinel_query(ingest=true)             → no nudge (already ingesting)
//   sentinel_seed                           → suggest node_expand or hunt_run
//   node_expand with neighbors > 0          → suggest channel_behavior
//   anything else                           → no nudge
//
// A returned `null` means "no nudge to add"; the footer stands alone.

export function composeNudge(
  tool: string,
  args: Record<string, unknown>,
  overlap: OverlapResponse | null,
): string | null {
  switch (tool) {
    case "sentinel_query": {
      if (args.ingest === true) return null;
      if (!overlap) return null;
      if (overlap.found.length > 0) {
        const top = [...overlap.found].sort((a, b) => b.degree - a.degree)[0];
        const tail = top.top_neighbor
          ? `, connected to ${top.top_neighbor.entity}`
          : "";
        const pluralOrSingle = overlap.found.length === 1 ? "y" : "ies";
        return (
          `${overlap.found.length} entit${pluralOrSingle} of this result already in the graph. ` +
          `Top: ${top.entity} (degree ${top.degree}${tail}). ` +
          `Consider node_expand before another KQL.`
        );
      }
      return (
        `None of this KQL's entities are in the graph. ` +
        `To explore these rows, re-run with ingest=true.`
      );
    }
    case "sentinel_seed":
      return (
        `Node added. Next: node_expand for neighbors, ` +
        `or hunt_run if a playbook scenario fits.`
      );
    case "node_expand": {
      const n = Number(args.neighbors_found ?? 0);
      if (n <= 0) return null;
      return `Found ${n} neighbors. For channel anomalies: channel_behavior on this node.`;
    }
    default:
      return null;
  }
}
