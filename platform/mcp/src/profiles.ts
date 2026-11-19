/**
 * Which tools a session gets.
 *
 * Every tool definition is sent to the client at the start of every
 * session. All 66 cost ~18k tokens before the first question is asked,
 * and most sessions use a dozen. So tools belong to groups, `core` is
 * what a hunt needs end to end (load data, look around, run patterns,
 * keep notes), and the rest is opt-in:
 *
 *   GRAPHHUNTER_MCP_TOOLS=analysis,report     core + those groups
 *   GRAPHHUNTER_MCP_TOOLS=full                everything
 *
 * A tool must be in exactly one group — `tests/contract/profiles.test.ts`
 * fails otherwise, so a new tool cannot be added without deciding whether
 * every session should pay for it.
 */

import type { Tool } from "./lib/types.js";

export const DEFAULT_GROUP = "core";

export const GROUPS: Record<string, { summary: string; tools: string[] }> = {
  core: {
    summary: "sessions, file ingest, graph overview, node lookup, hunts, journal, notes",
    tools: [
      "session_check",
      "session_create",
      "session_list",
      "session_current",
      "session_load",
      "session_save",
      "ingest_preview",
      "ingest_load",
      "ingest_load_with_config",
      "graph_summary",
      "graph_relation_schema",
      "graph_entity_types",
      "graph_datasets",
      "node_search",
      "node_get",
      "node_expand",
      "node_events",
      "hunt_run",
      "hunt_results",
      "journal",
      "notes",
    ],
  },
  analysis: {
    summary: "paths, neighbourhoods, heatmaps, subnet and channel analytics, score explanations, hunt diff",
    tools: [
      "graph_neighbors",
      "graph_path",
      "graph_path_nodes",
      "graph_anomaly",
      "graph_heavy_edges",
      "graph_channel_behavior",
      "graph_shared_sessions",
      "graph_subnet_analysis",
      "graph_temporal_heatmap",
      "node_subgraph",
      "node_score_explanation",
      "scores_recompute",
      "hunt_diff",
      "hunt_parse",
      "catalog_get",
      "enrich",
    ],
  },
  report: {
    summary: "tags, IOC/subgraph export, publishing, chain reconstruction",
    tools: ["tags", "export", "publish", "hunt_reconstruct_chain", "hunt_export_tpcsa_instance"],
  },
  sentinel: {
    summary: "Microsoft Sentinel: query, schema discovery, graph proposal and build, enrichment",
    tools: [
      "sentinel_query",
      "sentinel_schema",
      "sentinel_seed",
      "sentinel_control",
      "sentinel_status",
      "schema_discover",
      "graph_propose",
      "graph_build",
      "node_enrich",
    ],
  },
  "ingest-advanced": {
    summary: "mapping negotiation and generation, drift, regression, dead letters, invariants, PCAP, streaming",
    tools: [
      "ingest_negotiate",
      "ingest_parser_generate",
      "ingest_canonical_map",
      "ingest_schema_drift",
      "ingest_regression_test",
      "ingest_publish_mapping",
      "ingest_fetch_shared_mappings",
      "ingest_dead_letters",
      "ingest_invariants_live",
      "ingest_invariants_hypothetical",
      "ingest_pcap_preview",
      "ingest_stream",
      "ingest_status",
      "ingest_jobs",
      "review",
    ],
  },
};

export interface Selection {
  tools: Tool[];
  /** Groups in effect, `core` first. */
  groups: string[];
  /** Names asked for that are not groups. */
  unknown: string[];
}

/** Resolve `GRAPHHUNTER_MCP_TOOLS` against the full registry. */
export function selectTools(all: Tool[], spec: string | undefined): Selection {
  const asked = (spec ?? "")
    .split(",")
    .map((s) => s.trim().toLowerCase())
    .filter(Boolean);
  if (asked.includes("full") || asked.includes("all")) {
    return { tools: all, groups: Object.keys(GROUPS), unknown: [] };
  }
  const groups = [DEFAULT_GROUP, ...asked.filter((g) => g !== DEFAULT_GROUP && g in GROUPS)];
  const unknown = asked.filter((g) => !(g in GROUPS));
  const wanted = new Set(groups.flatMap((g) => GROUPS[g].tools));
  // Registry order is kept so the list is stable across boots.
  return { tools: all.filter((t) => wanted.has(t.name)), groups: [...new Set(groups)], unknown };
}

/**
 * Server-level instructions: tells the client which groups are off, so
 * it can say "that needs the `sentinel` tools" instead of concluding the
 * capability does not exist.
 */
export function instructionsFor(selection: Selection): string {
  const off = Object.keys(GROUPS).filter((g) => !selection.groups.includes(g));
  if (off.length === 0) return "";
  const lines = off.map((g) => `- ${g}: ${GROUPS[g].summary}`);
  return [
    "Only part of Graph Hunter's tools are loaded in this session. Not loaded:",
    ...lines,
    "They are enabled by the operator with GRAPHHUNTER_MCP_TOOLS=<group>[,<group>] (or `full`) and a restart. If a task needs one, say which group.",
  ].join("\n");
}
