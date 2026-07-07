************************
Architecture
************************

.. contents:: Table of Contents

Graph Hunter is split into a **Rust core** (domain logic, parsing, graph, search) and a **Tauri + React** desktop app (UI and persistence).

High-level layout
==================

::

   GraphHunter/
   ├── graph_hunter_core/     # Rust library — all domain logic, no UI
   ├── app/
   │   ├── src/               # React + TypeScript frontend
   │   └── src-tauri/         # Tauri backend (commands, session, HTTP API)
   ├── graph-hunter-mcp/      # MCP server for AI assistants (uses app HTTP API)
   ├── demo_data/             # Demo and real-data instructions
   └── docs/                  # This documentation

Core (graph_hunter_core)
========================

* **graph.rs** — GraphHunter engine: add entities/relations, ingest logs, run hypothesis search (temporal DFS).
* **Parsers** — ``sysmon.rs``, ``sentinel.rs``, ``generic.rs``, ``csv_parser.rs``; each implements the ``LogParser`` trait.
* **analytics.rs** — Neighborhood expansion, search results, summaries.
* **anomaly.rs** — Endogenous anomaly scorer: five components (Entity Rarity, Edge Rarity, Neighborhood Concentration, Temporal Novelty, GNN Threat); path and node-level scores; configurable weights (W1–W5).
* **gnn_bridge.rs** — Extracts k-hop subgraph features from the graph into the fixed-size tensor format expected by GNN/ONNX models.
* **npu_scorer.rs** — ONNX inference for GNN threat classification (5 classes: Benign, Exfiltration, C2 Beacon, Lateral Movement, Privilege Escalation); DirectML/CPU; scores feed into anomaly scorer as W5.
* **hypothesis.rs** — Hypothesis and steps; k-simplicity.
* **dsl.rs** — Hypothesis DSL parse/format.
* **catalog.rs** — ATT&CK hypothesis catalog.
* **entity.rs**, **relation.rs**, **types.rs** — Entity/relation types and enums.
* **field_preview.rs**, **preview.rs** — Field detection and preview for ingest.
* **benchmark.rs** — Synthetic graphs and instrumented search (for development/evaluation).

All business logic lives in the core; the Tauri layer only exposes commands and session state.

App (app/)
===========

* **src-tauri** — Tauri backend: ``cmd_*`` commands (e.g. ``cmd_load_data``, ``cmd_get_subgraph``, ``cmd_expand_node``), session persistence (create/switch/save/load), path nodes and notes. When the app runs, it also starts an **HTTP API** (default port 37891, configurable via ``GRAPHHUNTER_API_PORT``) so external tools (e.g. the graph-hunter-mcp MCP server) can query the current session’s graph.
* **src/** — React frontend: IngestPanel, HypothesisBuilder, GraphCanvas, ExplorerPanel, NodeDetailPanel, HuntResultsTable, EventsViewPanel, HeatmapView, TimelineView, PathNodesPanel, NotesPanel, SessionSelector, etc. Types in ``types.ts`` mirror Tauri response structs; backend calls via ``invoke<>``.

For using the HTTP API with AI assistants (MCP), see :doc:`mcp`.

Data flow
=========

1. User selects a file and format → frontend calls ``cmd_load_data`` with contents and format string.
2. Backend picks the parser (e.g. Sysmon, Sentinel, Generic), runs ``graph.ingest_logs()``, recomputes scores, returns stats.
3. For a hunt, frontend calls ``cmd_search`` (or equivalent) with hypothesis and optional time window; backend runs temporal DFS and returns path count and/or paginated paths.
4. For visualization, frontend requests subgraphs or neighborhoods via ``cmd_get_subgraph``, ``cmd_expand_node``, etc., and renders with Cytoscape.

More detail
===========

For the full file tree and conventions (parsers, tests, adding a new format), see the main README and ``.claude/CLAUDE.md`` in the repository root.
