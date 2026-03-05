************************
First hunt (5 minutes)
************************

.. contents:: Table of Contents

This tutorial gets you from a fresh start to your first hunt result in a few minutes. You will load demo data, run a hypothesis, and see attack paths on the graph.

Prerequisites
=============

* Graph Hunter is installed. If not, see :doc:`installation`.
* From the repo root, you can reach the ``app/`` and ``demo_data/`` directories.

Step 1 — Start the app and create a session
===========================================

1. Start the app:

   .. code-block:: bash

      cd app
      npm run tauri dev

2. When the window opens, create or select a **session** from the session selector in the top bar. Each session is a separate workspace (graph, path nodes, notes). Use the default or create a new one (e.g. "First hunt").

Step 2 — Load demo data
=======================

1. Open the **Data** (ingestion) panel on the left.
2. Set **Log format** to **Auto-detect (Recommended)**.
3. Click **Select Log File** and choose:

   ``demo_data/apt_attack_simulation.json``

   This is a Sysmon-style dataset that simulates an APT kill chain (spearphishing, discovery, Mimikatz, PsExec, C2, exfiltration). See :doc:`demo-data` for other demo files.
4. After loading, the panel shows entity and relation counts; the graph may still be empty until you run a hunt or expand nodes.

Step 3 — Run a hunt
===================

1. Switch to the **Hunt** tab in the bottom panel.
2. In the hypothesis area, either:

   * **Type a DSL chain** in the input, e.g.:

     .. code-block:: text

        User -[Auth]-> Host -[Execute]-> Process

     then use **Parse** (or the equivalent control) to load it as the current hypothesis, or

   * **Load from the ATT&CK catalog**: open the catalog and pick a pre-built hypothesis such as "Valid Accounts — Lateral Auth" (same pattern).

3. Click **Run**.
4. The engine finds all paths that match the pattern with **causal monotonicity** (each step at or after the previous one in time). You will see:

   * **Path count** (and whether results were truncated).
   * If the number of paths is small enough (e.g. ≤ 100), the **graph** updates to show the subgraph and highlighted paths; otherwise use the **Hunt results table** to paginate and **View path** to show a single path on the graph.

Step 4 — Interpret the result
=============================

.. image:: ../images/screenshot-hunt.png
   :alt: Hunt results with graph and path table
   :width: 95%

* **Graph view**: Nodes are entities (User, Host, Process, etc.); edges are relations (Auth, Execute). Paths matching your hypothesis are highlighted. Click a node to see its details in the right panel (scores, degrees, neighbors).
* **Hunt results table** (if shown): Each row is one path. You can sort by score (when anomaly scoring is enabled) and click **View path** to focus that path on the graph.
* **Scores**: When scoring is enabled, paths include anomaly and optionally GNN threat scores to help prioritize the most suspicious chains.

Step 5 — Explore further (optional)
====================================

* **Explorer**: Switch to the **Explorer** tab. Search for an IOC (e.g. a hostname or process name from a path), then use **Show neighbours** or double-click a node on the graph to expand its neighborhood.
* **Notes**: Add a note (toolbar or panel) to record findings; you can link it to a node for context.
* **Other views**: Use **Events**, **Heatmap**, and **Timeline** for additional context on the same graph.

Next steps
==========

* **Full UI workflows** — :doc:`usage`
* **Hypothesis DSL and ATT&CK catalog** — :doc:`../user-guide/hypothesis-and-catalog`
* **More demo data and real datasets** — :doc:`demo-data`
* **GNN threat scoring** — :doc:`../user-guide/gnn-threat-scoring`
* **MCP (AI assistant integration)** — :doc:`../reference/mcp`
