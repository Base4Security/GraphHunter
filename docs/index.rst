**********************************************************
Graph Hunter
**********************************************************

.. contents:: Table of Contents

**Graph-based & Hypothesis-driven threat hunting**

Ingest security logs, build an entity-relationship graph with causal ordering, and hunt for attack paths using pattern matching with optional MITRE ATT&CK–aligned detection templates. Integrates GNN-based threat classification via ONNX models with optional NPU/GPU acceleration.

About
=====

Graph Hunter is a **graph-based threat hunting engine** that turns heterogeneous security telemetry (Sysmon, Microsoft Sentinel, generic JSON, CSV) into a single **knowledge graph**. Analysts define **hypotheses** as chains of entity types and relation types (e.g. *User →[Auth]→ Host →[Execute]→ Process*). The engine finds all paths that match the pattern while enforcing **causal monotonicity**: each step occurs at or after the previous one in time. Results are explored via an interactive graph canvas, IOC search, timeline and heatmap views, and optional ATT&CK-mapped hypothesis templates.

The engine includes an **endogenous anomaly scoring system** with five components — Entity Rarity, Edge Rarity, Neighborhood Concentration, Temporal Novelty, and **GNN Threat** — that automatically prioritizes the most suspicious paths. The GNN component integrates ONNX models (e.g. exported from GraphOS-APT) that classify k-hop subgraphs into threat categories (Benign, Exfiltration, C2 Beacon, Lateral Movement, Privilege Escalation), with optional **NPU/GPU acceleration** via DirectML.

Why graph-based hunting?
========================

Traditional SIEM-style queries are rigid and schema-bound. Attack chains span multiple data sources and event types; correlating them often requires custom rules and manual pivoting. Graph Hunter instead:

* **Normalizes** diverse log formats into a unified model (entities + typed relations + timestamps).
* **Searches** by *pattern* (who executed what, who connected where, what wrote which file) instead of by field names.
* **Surfaces** multi-hop attack paths that satisfy temporal order, so you see full chains, not isolated events.

How it works
============

::

   Security Logs ──► Parser ──► Knowledge Graph ──► Hypothesis Search ──► Hunt Attack Paths

1. **Ingest** — Load logs in any supported format. The engine auto-detects the format or you can specify it. Parsers extract entities (IP, Host, User, Process, File, Domain, Registry, URL, Service) and relations (Auth, Connect, Execute, Read, Write, DNS, Modify, Spawn, Delete) with timestamps.
2. **Build Graph** — Entities become nodes, relations become directed edges. Duplicate entities are deduplicated; metadata is merged.
3. **Hunt** — Define a hypothesis as a chain of typed steps (e.g. ``User →[Auth]→ Host →[Execute]→ Process``). The engine finds all paths matching the pattern with **causal monotonicity** (each step at or after the previous one). Optional **k-simplicity** allows a vertex to repeat up to *k* times per path.
4. **Explore** — Search for IOCs, expand node neighborhoods, inspect metadata and anomaly scores, pivot via Events view, Heatmap, and Timeline.

Key features
============

* **Engine:** Temporal pattern matching (DFS + causal monotonicity), 5-component endogenous anomaly scoring (ER, EdgeR, NC, TN, GNN Threat), parallel parsing (Rayon), entity/relation deduplication.
* **GNN Scoring:** ONNX model inference for k-hop subgraph classification (5 threat classes), DirectML NPU/GPU acceleration, batch scoring, configurable k-hop depth, feature-gated (``ml-scoring``).
* **Formats:** Sysmon, EVTX, Microsoft Sentinel, generic JSON (80+ field variants), CSV; auto-detect or manual.
* **Hypotheses:** Visual step builder or **DSL** (``User -[Auth]-> Host -[Execute]-> Process``); wildcards (``*``) for any type; **ATT&CK hypothesis catalog** with one-click load.
* **UI:** **Sessions** (multiple graphs, persisted); **Hunt** vs **Explorer** modes; **Events**, **Heatmap**, **Timeline** views; **Path Nodes** (pinned nodes); **Notes** (standalone or node-linked); **GNN Threat Model** panel; paginated hunt results for large path sets.
* **Data:** Configurable generic parser (field → entity type mapping); preview before ingest; dataset list per session (remove/rename).
* **SIEM integrations:** **Azure Sentinel** (Log Analytics): KQL queries, workspace + tenant/client/secret (env or UI). **Elasticsearch**: index + query JSON, API key or user/password (env or UI). See :doc:`user-guide/siem-ingest`.

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
