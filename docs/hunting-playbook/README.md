# GraphHunter Hunting Playbook

## Purpose

This is the graph-native weekly hunting playbook for GraphHunter. Each Phase prompt is
designed to be pasted directly into Claude Desktop with the GraphHunter MCP server
connected. The playbook drives a full hunt cycle from raw telemetry assessment through
final synthesis — using the graph as the persistent, correlated artifact at every step,
not as a pass-through to a SIEM query console.

## Phase Map

- **Phase 1** (`01-phase1-telemetry-audit.md`) — Telemetry audit and seeding strategy:
  assess what data sources are connected, identify gaps, and choose seed IoCs for the hunt.
- **Phase 2** (`02-phase2-hypothesis-execution.md`) — Hypothesis execution, graph-first:
  seed the graph, enrich and expand nodes, run graph analytics, and develop findings.
- **Phase 3** (`03-phase3-validation-blast-radius.md`) — Validation and blast radius:
  confirm findings, compute k-hop attack paths, and assess lateral exposure.
- **Phase 4** (`04-phase4-synthesis-reporting.md`) — Synthesis and reporting: distill
  findings into a structured threat narrative with confidence levels and remediation
  recommendations.

## How to Use

Each `0N-*.md` file is a self-contained prompt for its matching phase of the hunt. Copy
the full contents and paste it as your opening message in Claude Desktop at the start of
that phase. The MCP server must be active so the tool calls execute against a live
GraphHunter session.

The Tooling Doctrine (`00-tooling-doctrine.md`) is the behavioral contract that governs
which tools to reach for and in what order. It is inlined verbatim into the Phase 2, 3,
and 4 prompts so the LLM carries the constraint forward through the entire hunt — and it
is kept standalone in `00-tooling-doctrine.md` so it can be referenced, updated, or
included independently.

## Why Graph-Native

The design rationale is documented in
[`docs/superpowers/specs/2026-06-08-graph-native-hunting-playbook-design.md`](../superpowers/specs/2026-06-08-graph-native-hunting-playbook-design.md).
The short version: the graph — with its cross-source entity unification, multi-hop
traversal, and anomaly scoring — is the product that GraphHunter delivers; KQL is an
escape hatch for the rare case the graph cannot express the test, not the default
execution path.
