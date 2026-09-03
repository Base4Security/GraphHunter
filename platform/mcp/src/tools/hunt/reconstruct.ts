import { z } from "zod";
import { defineTool } from "../../lib/types.js";
import { HEAVY } from "../../lib/api-client.js";

const seed = z.object({
  node: z.string().max(500).describe("Entity id of a detection to explain"),
  prize: z
    .number()
    .min(0)
    .max(10)
    .optional()
    .default(10)
    .describe(
      "10 · P(attack) from a calibrated scorer, or a flat value when only a template match is known. 0 means 'not a terminal'.",
    ),
  tactic: z
    .string()
    .max(64)
    .optional()
    .describe(
      "ATT&CK tactic of the template that matched (e.g. credential-access). Drives the ranking: trees are ordered by how many distinct tactics they cover, never by prize alone.",
    ),
});

const window = z
  .object({
    from: z.number().int().describe("Inclusive lower edge timestamp (engine seconds)"),
    to: z.number().int().describe("Inclusive upper edge timestamp (engine seconds)"),
  })
  .describe("Optional time window; without it the whole loaded trace is used.");

const common = {
  seeds: z.array(seed).max(5000).describe("Detections (terminals) to explain"),
  window: window.optional(),
  epsilon_ms: z
    .number()
    .min(0)
    .optional()
    .describe("Resolution that separates cause from effect: 1 ms for EDR (default), 1000 for SIEM stamped to the second."),
  score_threshold: z
    .number()
    .optional()
    .describe("Also treat every entity whose score is at least this value as a terminal (prize 10·score/max_score)."),
  max_arcs: z
    .number()
    .int()
    .min(1)
    .optional()
    .describe("Refuse to export more arcs than this (protects the interactive path on huge sessions)."),
};

const exportInput = z.object(common);

export const huntExportTpcsaInstance = defineTool({
  name: "hunt_export_tpcsa_instance",
  description:
    "Export the loaded graph (or a window of it) as a TPCSA instance: nodes with kind/prize/tactic/root_cost and causal-flow arcs with microsecond timestamps and rarity costs. Use to hand the instance to an external solver or to inspect the mapping; for the actual reconstruction call hunt_reconstruct_chain.",
  category: "hunt",
  version: 1,
  stability: "experimental",
  inputSchema: exportInput,
  outputSchema: z.unknown(),
  async execute(ctx, args) {
    return ctx.api.post("/tpcsa/export", args, HEAVY);
  },
});

const reconstructInput = z.object({
  ...common,
  k: z
    .number()
    .int()
    .min(1)
    .max(10)
    .optional()
    .describe("Maximum entry points (trees). Default 2: with 1 a second implant disappears."),
  budget: z.number().int().min(1).optional().describe("Optional cap on arcs per tree."),
  certify: z
    .boolean()
    .optional()
    .describe(
      "Ask the HiGHS certification sidecar for an optimality certificate (status Optimal / TimeLimit with gap / TooLarge / Unavailable). Off by default: the greedy is the product, the certificate is the audit.",
    ),
  certify_time_limit_s: z.number().min(1).optional().describe("Sidecar time limit (default 120 s)."),
  certify_gap: z.number().min(0).optional().describe("Sidecar relative MIP gap (default 0.005)."),
});

export const huntReconstructChain = defineTool({
  name: "hunt_reconstruct_chain",
  description:
    "Reconstruct attack chains from detections: turn fragments (template matches, scored nodes) into time-respecting trees with an entry point, causal order, unlabelled connectors (processes no template flagged but on which N detections depend — candidate implants / C2), a ranking by ATT&CK tactic coverage, declared ties (two hypotheses within 1 %) and an optional optimality certificate. Every tree is independently verified before it is shown. Read `ties` before tree 1: a non-empty list means the evidence does not decide.",
  category: "hunt",
  version: 1,
  stability: "experimental",
  inputSchema: reconstructInput,
  outputSchema: z.unknown(),
  async execute(ctx, args) {
    return ctx.api.post("/reconstruct_chain", args, HEAVY);
  },
});
