**********************************************************
Graph Hunter
**********************************************************

.. contents:: Table of Contents

**Graph-based & Hypothesis-driven threat hunting**

Graph Hunter is a graph-based threat hunting engine that turns heterogeneous security telemetry (Sysmon, Microsoft Sentinel, generic JSON, CSV) into a single temporal knowledge graph. Analysts define **hypotheses** as chains of entity and relation types. The engine finds all paths matching the pattern while enforcing **causal monotonicity** (each step at or after the previous one in time). Results are explored via an interactive graph canvas, IOC search, timeline and heatmap views, and optional MITRE ATT&CK–aligned detection templates.

How it works
============

::

   Security Logs ──► Auto-Detect ──► Parser ──► Knowledge Graph ──► Hypothesis Search ──► Attack Paths
    (JSON/CSV/NDJSON)                              (Entities + Relations)    (Temporal DFS)

1. **Ingest** — Load logs; the engine auto-detects format or you specify it. Parsers extract entities and relations with timestamps.
2. **Build graph** — Entities become nodes, relations become directed edges; deduplication and metadata merge.
3. **Hunt** — Define a hypothesis (e.g. ``User →[Auth]→ Host →[Execute]→ Process``); the engine returns all temporally ordered paths.
4. **Explore** — Search IOCs, expand neighborhoods, use Events / Heatmap / Timeline views.

Features
========

* **Engine:** Temporal pattern matching (DFS + causal monotonicity), time-window filtering, 5-component endogenous anomaly scoring (Entity Rarity, Edge Rarity, Neighborhood Concentration, Temporal Novelty, GNN Threat), parallel parsing (Rayon), k-simplicity for path constraints.
* **Formats:** Sysmon, Microsoft Sentinel, generic JSON (80+ field variants), CSV; auto-detect or manual.
* **Hypotheses:** Visual step builder or DSL (e.g. ``User -[Auth]-> Host -[Execute]-> Process``); wildcards; ATT&CK hypothesis catalog.
* **UI:** Sessions (multiple graphs, persisted), Hunt vs Explorer modes, Events / Heatmap / Timeline views, Path Nodes, Notes, paginated hunt results.
* **Data:** Configurable generic parser, preview before ingest, dataset list per session.
* **SIEM integrations:** Query-based ingest from **Azure Sentinel** (Log Analytics) and **Elasticsearch**; see :doc:`user-guide/siem-ingest`.

Quick start
===========

.. code-block:: bash

   cd app
   npm install
   npm run tauri dev

Create a session → load a file from ``demo_data/`` with **Auto-detect** → open **Hunt Mode** → build or pick a hypothesis → **Run**.

Documentation
=============

.. toctree::
   :caption: Getting started
   :maxdepth: 2
   :hidden:

   getting-started/index

.. toctree::
   :caption: User guide
   :maxdepth: 2
   :hidden:

   user-guide/index

.. toctree::
   :caption: Reference
   :maxdepth: 2
   :hidden:

   reference/index
