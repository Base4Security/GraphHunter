************************
Usage
************************

.. contents:: Table of Contents

This page describes how to run Graph Hunter and use the main UI workflows.

Quick run
=========

.. code-block:: bash

   cd app
   npm run tauri dev

Then in the app: create or select a **session** → **Select Log File** → choose a file (e.g. from ``demo_data/``) → **Auto-detect** → load. Switch to **Hunt Mode**, build or select a hypothesis, and click **Run**.

.. image:: ../images/screenshot-hunt.png
   :alt: Main window after loading demo data and running a hunt
   :width: 95%

Sessions
========

* **Sessions** are separate workspaces; each has its own graph, path nodes, and notes.
* Create a new session from the session selector (top bar); switch between sessions from the same dropdown.
* Sessions are stored locally in your OS application data directory and persist between runs.
* Use different sessions for different investigations or datasets.

Loading data
============

1. Open the left panel (Data / ingestion).
2. Create or select a session.
3. Choose **Log format**: **Auto-detect (Recommended)** or a specific format (Sysmon, Sentinel, Generic JSON, CSV).
4. Click **Select Log File** and pick a JSON, NDJSON, or CSV file.
5. After load, entity and relation counts update; you can load more files into the same session (data is merged).

For **generic JSON** or custom schemas, you can use **Preview** and configure field → entity type mapping before ingest.

Hunt mode
=========

1. Switch to the **Hunt** tab (bottom panel).
2. **Build a hypothesis** either:

   * **Visually:** Add steps with the step builder (origin type → relation type → destination type), or
   * **DSL:** Type a chain, e.g. ``User -[Auth]-> Host -[Execute]-> Process``, and parse.
3. Optionally set a **time window** to restrict the hunt to a time range.
4. Click **Run**.
5. Results:

   * If paths ≤ 100: the graph shows the subgraph and highlighted paths.
   * If paths > 100: a **Hunt results table** appears; use it to paginate and **View path** to show a single path on the graph.
6. You can load a hypothesis from the **ATT&CK catalog** and then run or modify it.

Explorer mode
=============

1. Switch to the **Explorer** tab (bottom panel).
2. **Search** by IOC (e.g. IP, hostname, process name); matching nodes are listed.
3. **Show neighbours:** Pick a node and expand by **All** or **By type** to load its neighborhood onto the graph.
4. **Double-click** a node on the graph to expand it (Explorer mode).
5. **Right-click** a node for: Expand, Center, Copy ID, Add/Remove from Path Nodes, Show neighbours.

.. image:: ../images/screenshot-explorer.png
   :alt: Explorer and graph — IOC search, neighborhood expansion
   :width: 95%

Other views
===========

* **Events:** Event list for the current graph or selection.
* **Heatmap:** Entity/relation heatmap view.
* **Timeline:** Temporal view of activity.

.. image:: ../images/screenshot-views.png
   :alt: Events, Heatmap, Timeline views
   :width: 95%

Path nodes and notes
====================

* **Path nodes:** Pin important nodes (e.g. from a hunt path) so they stay easy to find; list and focus from the **Path Nodes** sidebar.
* **Notes:** Add free-form notes; they can be standalone or linked to a node. Open from the **Notes** toolbar button.

Map navigation
==============

* Use **Back** / **Forward** in the top bar to move through previous map states (e.g. after expanding a node or running a hunt).
* **Node detail panel:** Click a node to see its details in the right sidebar; from there you can expand or set center.
