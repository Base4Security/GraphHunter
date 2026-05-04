************************
GNN Threat Scoring
************************

.. contents:: Table of Contents

Graph Hunter integrates **GNN-based threat classification** through ONNX models (e.g. exported from GraphOS-APT), bridging hypothesis-driven investigation with ML-based detection on the same graph.

How it works
============

1. During **ingestion**, the anomaly observer records entity/edge frequency and timestamps.
2. After **finalize**, rarity, neighborhood concentration, and temporal novelty are computed.
3. The **GNN Bridge** extracts a k-hop subgraph around each entity and encodes it into a fixed-size tensor (1536-dim) compatible with the ONNX model.
4. The **NPU Scorer** runs ONNX inference (DirectML/GPU or CPU); output is 5-class threat logits.
5. Threat score = ``1 - P(Benign)`` after softmax; scores are injected into the anomaly scorer as weight **W5**.
6. **Hunt results** are ranked by the composite score (W1–W5), so high-threat paths appear first.

Threat classes (ATT&CK-aligned)
===============================

| Logit | Threat class         | ATT&CK |
|-------|----------------------|--------|
| 0     | Benign               | Normal |
| 1     | Exfiltration         | TA0010 |
| 2     | C2 Beacon            | TA0011 |
| 3     | Lateral Movement     | TA0008 |
| 4     | Privilege Escalation | TA0004 |

How it is used in the hunt
==========================

* **Path ranking** — Results are ordered by composite anomaly score. Paths with higher GNN threat (and other components) appear first for triage.
* **Where you see it** — The hunt results table and node tooltips show the **GNN Threat** component in the score breakdown when a model is loaded and scores have been computed. The **W5** slider in the left panel (GNN Threat Model) controls how much ML contributes vs the other four heuristics.
* **Optional** — GNN scoring is off by default (W5 = 0). Enable it by loading an ONNX model and clicking **Compute Scores**.

Value to threat hunting
=======================

* **Prioritization** — High-threat paths (C2, lateral movement, privilege escalation, exfiltration) rise to the top, reducing manual sifting.
* **ATT&CK-aligned context** — The 5-class output helps categorize and report findings by tactic.
* **Hybrid workflow** — Combines your hypothesis-driven pattern matching with ML-based subgraph classification on the same graph.

UI workflow
===========

1. Open the **GNN Threat Model** section in the left panel.
2. Load an ONNX model (file dialog).
3. Enable **Anomaly Scoring** and set weights (W1–W5) as desired.
4. Set **k-hop depth** (1–5, default 2).
5. Click **Compute Scores** — batch inference runs on all entities.
6. Run a hunt; results are ranked with GNN-enhanced scores.

For training and exporting models, see the **training/** README and **docs/GNN_STRATEGY.md** in the repository.
