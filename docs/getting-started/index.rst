Getting started
===============

Graph Hunter is a **graph-based threat hunting engine** that turns heterogeneous security telemetry (Sysmon, Microsoft Sentinel, generic JSON, CSV) into a single **knowledge graph**. Analysts define **hypotheses** as chains of entity and relation types; the engine finds all paths matching the pattern while enforcing **causal monotonicity** (each step at or after the previous one in time). Results are explored via an interactive graph canvas, IOC search, timeline and heatmap views, and optional MITRE ATT&CK–aligned detection templates. The engine includes **endogenous anomaly scoring** (Entity Rarity, Edge Rarity, Neighborhood Concentration, Temporal Novelty, and optional **GNN Threat**) and supports ONNX-based threat classification with optional NPU/GPU acceleration.

This section gets you from zero to running your first hunt:

.. toctree::
   :maxdepth: 1

   installation
   first-hunt
   usage
   demo-data
