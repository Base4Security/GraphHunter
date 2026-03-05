<p align="center">
	<a href="https://graphhunter.readthedocs.io/en/latest/" rel="noopener">
	 	<img src="https://github.com/Base4Security/GraphHunter/blob/master/docs/images/GraphHunterLogoBlack.png?raw=true" alt="Graph Hunter" width="200">
	</a>
</p>

<p align="center">
  <i>Graph-based & Hypothesis-driven threat hunting</i>
</p>

<p align="center">
  Ingest security logs, build an entity-relationship graph with causal ordering, and hunt for attack paths using pattern matching with optional MITRE ATT&CK–aligned detection templates. Integrates GNN-based threat classification via ONNX models with optional NPU/GPU acceleration.
</p>

<div align="center">

[![Rust](https://img.shields.io/badge/Rust-2024_Edition-orange)](https://www.rust-lang.org/)
[![Tauri](https://img.shields.io/badge/Tauri-v2-blue)](https://v2.tauri.app/)
[![React](https://img.shields.io/badge/React-19-61dafb)](https://react.dev/)
[![License](https://img.shields.io/badge/License-GPLv3-green)](LICENSE)

</div>

---

## Table of Contents

- [About](#about)
- [Why Graph-Based Hunting?](#why-graph-based-hunting)
- [How It Works](#how-it-works)
- [Key Features](#key-features)
- [Supported Log Formats](#supported-log-formats)
- [SIEM Integrations](#siem-integrations)
- [Hypothesis DSL & ATT&CK Catalog](#hypothesis-dsl--attack-catalog)
- [GNN Threat Scoring](#gnn-threat-scoring)
- [Architecture](#architecture)
- [HTTP API & MCP (AI integration)](#http-api--mcp-ai-integration)
- [Installation](#installation)
- [Usage](#usage)
- [Demo Data & Try It](#demo-data--try-it)
- [Privacy & Data](#privacy--data)
- [Screenshots](#screenshots)
- [Core Engine Details](#core-engine-details)
- [Documentation](docs/index.rst)
- [Changelog](CHANGELOG.md)
- [Contributing](CONTRIBUTING.md)
- [License](#license)

---

## About

Graph Hunter is a **graph-based threat hunting engine** that turns heterogeneous security telemetry (Sysmon, Microsoft Sentinel, generic JSON, CSV) into a single **knowledge graph**. Analysts define **hypotheses** as chains of entity types and relation types (e.g., *User →[Auth]→ Host →[Execute]→ Process*). The engine finds all paths that match the pattern while enforcing **causal monotonicity**: each step occurs at or after the previous one in time. Results are explored via an interactive graph canvas, IOC search, timeline and heatmap views, and optional ATT&CK-mapped hypothesis templates.

The engine includes an **endogenous anomaly scoring system** with five components — Entity Rarity, Edge Rarity, Neighborhood Concentration, Temporal Novelty, and **GNN Threat** — that automatically prioritizes the most suspicious paths. The GNN component integrates ONNX models (e.g., exported from GraphOS-APT) that classify k-hop subgraphs into threat categories (Benign, Exfiltration, C2 Beacon, Lateral Movement, Privilege Escalation), with optional **NPU/GPU acceleration** via DirectML.

**Authors:** From BASE4 Security, Lucas Sotomayor & Diego Staino.

---

## Why Graph-Based Hunting?

Traditional SIEM-style queries are rigid and schema-bound. Attack chains span multiple data sources and event types; correlating them often requires custom rules and manual pivoting. Graph Hunter instead:

- **Normalizes** diverse log formats into a unified model (entities + typed relations + timestamps).
- **Searches** by *pattern* (who executed what, who connected where, what wrote which file) instead of by field names.
- **Surfaces** multi-hop attack paths that satisfy temporal order, so you see full chains, not isolated events.

---

## How It Works

```
Security Logs ──► Auto-Detect ──► Parser ──► Knowledge Graph ──► Hypothesis Search ──► Attack Paths
 (JSON/CSV/NDJSON)                              (Entities + Relations)    (Temporal DFS)
```

1. **Ingest** — Load logs in any supported format. The engine auto-detects the format or you can specify it. Parsers extract entities (IP, Host, User, Process, File, Domain, Registry, URL, Service) and relations (Auth, Connect, Execute, Read, Write, DNS, Modify, Spawn, Delete) with timestamps.
2. **Build Graph** — Entities become nodes, relations become directed edges. Duplicate entities are deduplicated; metadata is merged.
3. **Hunt** — Define a hypothesis as a chain of typed steps (e.g., `User →[Auth]→ Host →[Execute]→ Process`). The engine finds all paths matching the pattern with **causal monotonicity** (each step at or after the previous one). Optional **k-simplicity** allows a vertex to repeat up to *k* times per path.
4. **Explore** — Search for IOCs, expand node neighborhoods, inspect metadata and anomaly scores, pivot via Events view, Heatmap, and Timeline.

![High-level workflow: ingest → graph → hunt → explore](docs/images/screenshot-workflow.png)

*Screenshot: end-to-end workflow (add `docs/images/screenshot-workflow.png`).*

---

## Key Features

| Area | Features |
|------|----------|
| **Engine** | Temporal pattern matching (DFS + causal monotonicity), time-window filtering, 5-component endogenous anomaly scoring (ER, EdgeR, NC, TN, GNN Threat), parallel parsing (Rayon), entity/relation deduplication |
| **GNN Scoring** | ONNX model inference for k-hop subgraph classification (5 threat classes), DirectML NPU/GPU acceleration, batch scoring, configurable k-hop depth, feature-gated (`ml-scoring`) |
| **Formats** | Sysmon, Microsoft Sentinel, generic JSON (80+ field variants), CSV; auto-detect or manual selection |
| **Hypotheses** | Visual step builder or **DSL** (`User -[Auth]-> Host -[Execute]-> Process`); wildcards (`*`) for any type; **ATT&CK hypothesis catalog** with one-click load |
| **UI** | **Sessions** (multiple graphs, persisted); **Hunt** vs **Explorer** modes; **Events**, **Heatmap**, **Timeline** views; **Path Nodes** (pinned nodes); **Notes** (standalone or node-linked); **GNN Threat Model** panel; paginated hunt results for large path sets |
| **Data** | Configurable generic parser (field → entity type mapping); preview before ingest; dataset list per session (remove/rename) |

---

## Supported Log Formats

### Auto-Detect (Recommended)

The engine identifies the log format from content heuristics:

- JSON with `EventID` + `UtcTime` → Sysmon parser  
- JSON with Sentinel `Type` field → Sentinel parser  
- Other JSON → Generic parser (field normalization)  
- Non-JSON content → CSV parser  

### Sysmon (Windows Event Log)

| Event ID | Description | Triples |
|----------|-------------|---------|
| 1 | Process Create | `User →[Execute]→ Process`, `Parent →[Spawn]→ Child` |
| 3 | Network Connection | `Host →[Connect]→ IP` |
| 11 | File Create | `Process →[Write]→ File` |
| 22 | DNS Query | `Process →[DNS]→ Domain` |

### Microsoft Sentinel (Azure)

| Table / Source | Triples |
|----------------|---------|
| SecurityEvent (4624/4625) | `User →[Auth]→ Host` |
| SecurityEvent (4688) | `User →[Execute]→ Process`, `Parent →[Spawn]→ Child` |
| SecurityEvent (4663) | `Process →[Read]→ File` |
| SigninLogs | `User →[Auth]→ IP` |
| DeviceProcessEvents | `User →[Execute]→ Process`, `Parent →[Spawn]→ Child` |
| DeviceNetworkEvents | `Host →[Connect]→ IP` |
| DeviceFileEvents | `Process →[Write/Read]→ File` |
| CommonSecurityLog | `IP →[Connect]→ IP` |

### Generic JSON

Format-agnostic parser: normalizes 80+ field name variants to canonical names (case-insensitive), then infers relations from normalized fields (e.g., `source_user` + `source_process` → `User →[Execute]→ Process`). Supports **configurable field mapping** and preview before ingest.

### CSV

Parses CSV with headers; each row is converted to a JSON object and processed by the Generic parser. Handles quoted fields and embedded commas.

---

## SIEM Integrations

Graph Hunter can pull data directly from **Azure Sentinel** (Log Analytics) and **Elasticsearch** via their APIs—run a query, then ingest the results into your session.

| SIEM | Auth | Usage |
|------|------|--------|
| **Azure Sentinel** | Tenant ID, Client ID, Client Secret (env or UI) | Workspace ID + KQL query; default: SecurityEvent, last 24h |
| **Elasticsearch** | API key or User/Password (env or UI) | Cluster URL, index, query JSON, size |

Available in the **web app with gateway** (Datasets → Data Ingestion) or via the gateway API (`POST /api/ingest/query`). Desktop app without gateway: use **From file** and export from your SIEM first. See **[SIEM query-based ingest](https://graphhunter.readthedocs.io/en/latest/user-guide/siem-ingest.html)** in the docs for env vars and pagination.

---

## Hypothesis DSL & ATT&CK Catalog

**DSL** — Build hypotheses as arrow chains with optional wildcards:

```text
User -[Auth]-> Host -[Execute]-> Process
Process -[DNS]-> Domain -[Connect]-> IP
* -[Execute]-> Process -[Spawn]-> Process
```

**Catalog** — Pre-built hypotheses mapped to MITRE ATT&CK (e.g., Valid Accounts T1078, Credential Dumping T1003, RDP Lateral Movement T1021.001, C2 T1071). Load from the catalog or use them as templates for custom chains.

---

## GNN Threat Scoring

Graph Hunter integrates GNN-based threat classification through ONNX models, bridging hypothesis-driven investigation with ML-based detection in a closed loop on the same graph.

### How it works

```
Ingestion → Anomaly Observer (entity/edge frequency, timestamps)
                → Finalize (compute rarity, concentration, novelty)
                    → GNN Bridge extracts k-hop subgraph features per entity
                        → NPU Scorer runs ONNX inference → 5-class threat logits
                            → Scores injected into anomaly scorer as W5
                                → Hunt results ranked by composite score (W1–W5)
```

The **GNN Bridge** (`gnn_bridge.rs`) translates Graph Hunter's temporal graph into fixed-size tensors compatible with trained GNN models. Each entity's k-hop neighborhood (capped at 32 nodes) is encoded as a 16-dimensional feature vector per node (one-hot entity type + degree + anomaly features) plus an adjacency matrix, flattened into a 1536-dim input tensor.

The **NPU Scorer** (`npu_scorer.rs`) loads ONNX models and runs inference with DirectML (NPU/GPU) or CPU fallback. Output is 5 logits mapped to threat classes:

| Logit | Threat Class | ATT&CK Alignment |
|-------|-------------|-------------------|
| 0 | Benign | Normal activity |
| 1 | Exfiltration | TA0010 — Data exfiltration |
| 2 | C2 Beacon | TA0011 — Command & Control |
| 3 | Lateral Movement | TA0008 — Lateral Movement |
| 4 | Privilege Escalation | TA0004 — Privilege Escalation |

The threat score is `1 - P(Benign)` after softmax. Scores feed into the anomaly scorer's W5 weight, creating a **bidirectional feedback loop**: anomaly features (rarity, novelty, concentration) are inputs to the GNN, and GNN outputs feed back into the composite anomaly score used for path ranking and DFS pruning.

### How GNN scoring is used in the hunt

- **Path ranking** — Node and links are ordered by the composite anomaly score (W1–W5). Paths with higher GNN threat (and other anomaly signals) appear first, so analysts triage the most suspicious chains before digging into noise.
- **Where you see it** — The path-level score breakdown (e.g. in the hunt results table and node tooltips) includes a **GNN Threat** component when a model is loaded and scores have been computed. You can tune the **W5** weight in the left panel to emphasize or downweight ML vs the other four heuristics (entity/edge rarity, neighborhood concentration, temporal novelty).
- **Optional** — GNN scoring is off by default (W5 = 0). You enable it by loading an ONNX model and running **Compute Scores**; until then, the engine behaves as before with the other four components only.

### Value to threat hunting

- **Prioritization** — Reduces manual sifting: high-threat paths (e.g. C2, lateral movement, privilege escalation) rise to the top instead of being buried in long result lists.
- **ATT&CK-aligned context** — The 5-class output (Benign, Exfiltration, C2 Beacon, Lateral Movement, Privilege Escalation) maps to MITRE ATT&CK tactics, helping categorize and report findings.
- **Hybrid approach** — Combines hypothesis-driven pattern matching (your chains) with ML-based subgraph classification on the same graph, so you get both rule coverage and learned threat signals in one workflow.

### UI workflow

1. Load an ONNX model (file dialog in the GNN Threat Model panel)
2. Enable anomaly scoring with desired weights (W1–W5)
3. Set k-hop depth (1–5, default 2)
4. Click "Compute Scores" — batch inference runs on all entities
5. Hunt results are now ranked with GNN-enhanced scores

---

## Architecture

```
GraphHunter/
├── graph_hunter_core/           # Rust core library
│   └── src/
│       ├── graph.rs             # GraphHunter engine (add, search, ingest)
│       ├── sysmon.rs            # Sysmon log parser
│       ├── sentinel.rs          # Microsoft Sentinel parser
│       ├── generic.rs           # Generic field-normalizing JSON parser
│       ├── csv_parser.rs        # CSV → generic pipeline
│       ├── parser.rs            # LogParser trait
│       ├── analytics.rs         # Neighborhood, search, scoring, summaries
│       ├── anomaly.rs           # Endogenous anomaly scorer (5 components incl. GNN)
│       ├── gnn_bridge.rs        # Subgraph feature extraction for GNN models
│       ├── npu_scorer.rs        # ONNX inference (DirectML/CPU), threat classification
│       ├── hypothesis.rs       # Hypothesis + steps, k-simplicity
│       ├── dsl.rs               # Hypothesis DSL parse/format
│       ├── catalog.rs           # ATT&CK hypothesis catalog
│       ├── field_preview.rs     # Configurable parser, field mapping
│       ├── preview.rs           # Format-specific preview (Sysmon/Sentinel/Generic)
│       ├── benchmark.rs         # Synthetic graphs, instrumented DFS
│       ├── entity.rs            # Entity struct
│       ├── relation.rs          # Relation struct
│       ├── types.rs             # EntityType, RelationType enums
│       └── errors.rs            # Error types
├── app/
│   ├── src/                     # React + TypeScript frontend
│   │   ├── components/
│   │   │   ├── IngestPanel.tsx       # Data load, format selector, sessions
│   │   │   ├── HypothesisBuilder.tsx # Hunt mode, DSL + catalog
│   │   │   ├── GraphCanvas.tsx       # Cytoscape graph visualization
│   │   │   ├── ExplorerPanel.tsx     # IOC search, neighborhood expansion
│   │   │   ├── NodeDetailPanel.tsx   # Node detail sidebar
│   │   │   ├── HuntResultsTable.tsx  # Paginated hunt paths
│   │   │   ├── EventsViewPanel.tsx   # Event list view
│   │   │   ├── HeatmapView.tsx      # Entity/relation heatmap
│   │   │   ├── TimelineView.tsx      # Temporal view
│   │   │   ├── PathNodesPanel.tsx   # Pinned path nodes
│   │   │   ├── NotesPanel.tsx       # Notes (standalone/node-linked)
│   │   │   ├── SessionSelector.tsx  # Session switch/create
│   │   │   ├── GraphMetricsLeftPanel.tsx # Anomaly scoring & GNN controls
│   │   │   ├── FieldSelector.tsx    # Generic parser field config
│   │   │   └── NodeContextMenu.tsx  # Expand, center, copy, path nodes
│   │   └── App.tsx
│   └── src-tauri/               # Tauri backend (commands, session persistence)
│       ├── src/lib.rs
│       └── src/http_api.rs      # HTTP REST API for external tools
├── graph-hunter-mcp/            # MCP server for AI assistants
│   └── (see graph-hunter-mcp/README.md)
├── demo_data/
│   ├── apt_attack_simulation.json       # Sysmon APT kill chain
│   ├── sentinel_attack_simulation.json  # Sentinel cloud-to-on-prem
│   ├── generic_csv_logs.csv             # CSV firewall/proxy logs
│   └── DOWNLOAD_REAL_DATA.md            # OTRF/Mordor, Splunk attack_data
└── README.md
```

---

## Installation

You need Rust, Node.js, and the [Tauri v2 prerequisites](https://v2.tauri.app/start/prerequisites/)—no extra services or accounts. Follow the steps below; the first run may take a few minutes while dependencies build.

1. **Install prerequisites (if not already installed):**

   - [Rust](https://rustup.rs/) (2024 edition)
   - [Node.js](https://nodejs.org/) (v18+)
   - Platform-specific build tools: see [Tauri prerequisites](https://v2.tauri.app/start/prerequisites/)

2. **Clone and run in development:**

   ```bash
   cd app
   npm install
   npm run tauri dev
   ```

3. **Verify:** The app window opens. Create a session, load `demo_data/apt_attack_simulation.json` with **Auto-detect**, then run a hunt (e.g. **Hunt Mode** → add step `User -[Auth]-> Host` → Run). If you see paths and the graph, you’re ready to go.

**Run tests:**

```bash
cd graph_hunter_core
cargo test
```

**Build for production:**

```bash
cd app
npm run tauri build
```

---

## Usage

Minimal run: start the app, load a log file, and hunt.

```bash
cd app && npm run tauri dev
```

Then in the UI: create or select a session → **Select Log File** → choose a file from `demo_data/` (or your own) → **Auto-detect** → load. Switch to **Hunt Mode**, build a hypothesis (or pick one from the ATT&CK catalog), and click **Run**. Results appear in the graph and in the hunt table when there are many paths.

![Main window after loading demo data and running a hunt](docs/images/screenshot-main.png)

*Screenshot: main window with session loaded and hunt results (add `docs/images/screenshot-main.png`).*

---

## Demo Data & Try It

Three attack simulation datasets are included in `demo_data/`:

| File | Format | Scenario |
|------|--------|----------|
| `apt_attack_simulation.json` | Sysmon | APT kill chain: spearphishing, discovery, Mimikatz, PsExec, C2, exfiltration |
| `sentinel_attack_simulation.json` | Sentinel | Cloud-to-on-prem: brute-force DC, Azure AD abuse, lateral movement, beacon, exfiltration |
| `generic_csv_logs.csv` | CSV | Firewall/proxy logs: normal + C2, SMB lateral, exfiltration attempts |

**Quick run:**

1. Start the app: `npm run tauri dev` (from `app/`).
2. Create or select a session; choose **Auto-detect** (or a specific format), then load a demo file.
3. Open **Hunt Mode** and build a hypothesis, e.g.:
   - `User →[Execute]→ Process →[Write]→ File` (malware drop)
   - `User →[Auth]→ Host` (lateral auth)
   - `Host →[Connect]→ IP` (C2)
   - `Process →[Spawn]→ Process` (parent-child chains)
   - Or pick a pattern from the **ATT&CK catalog**.
4. Switch to **Explorer Mode** to search IOCs and expand neighborhoods; use **Events**, **Heatmap**, and **Timeline** for context.

<details>
<summary>Real-world datasets (OTRF/Mordor, Splunk attack_data)</summary>

For large-scale testing with real attack telemetry, see [demo_data/DOWNLOAD_REAL_DATA.md](demo_data/DOWNLOAD_REAL_DATA.md) for download and conversion instructions (OTRF Security-Datasets, Mordor, Splunk attack_data).

</details>

---

## Privacy & data

All processing is **local**. Logs are read from files you select; no data is sent to external services. Sessions and notes are stored in your OS application data directory. No telemetry or analytics are included.

---

## Screenshots

| Description | Placeholder |
|-------------|-------------|
| **Hunt mode** — Hypothesis builder, DSL, and hunt results with graph and path table | ![Hunt mode](docs/images/screenshot-hunt.png) |
| **Explorer + graph** — IOC search, neighborhood expansion, and graph canvas | ![Explorer and graph](docs/images/screenshot-explorer.png) |
| **Hypothesis & ATT&CK catalog** — Step builder and one-click catalog templates | ![Hypothesis and catalog](docs/images/screenshot-catalog.png) |
| **Events, Heatmap, Timeline** — Event list, entity/relation heatmap, temporal view | ![Events, Heatmap, Timeline](docs/images/screenshot-views.png) |
| **GNN Threat Model** — ONNX model load, k-hop config, Compute Scores (optional) | ![GNN Threat Model](docs/images/screenshot-gnn.png) |

*Add the actual image files under `docs/images/` (e.g. `screenshot-hunt.png`, `screenshot-explorer.png`, etc.) or replace with a short [demo video](docs/images/) link.*

---

## Core Engine Details

- **Temporal pattern matching** — DFS with causal monotonicity (events in chronological order along the path).
- **Time window filtering** — Restrict hunts to a configurable time range.
- **Endogenous anomaly scoring** — 5-component path scoring: Entity Rarity, Edge Rarity, Neighborhood Concentration, Temporal Novelty, and GNN Threat. Each component in [0,1], combined with configurable weights.
- **GNN threat classification** — ONNX model inference on k-hop subgraphs. 5 threat classes (Benign, Exfiltration, C2 Beacon, Lateral Movement, Privilege Escalation). DirectML NPU/GPU acceleration with CPU fallback. Feature-gated (`ml-scoring`).
- **k-simplicity** — Limit how many times a vertex can appear in a path (default 1 = simple path).
- **Parallel parsing** — Rayon-based ingestion for large log files.
- **Deduplication** — Entities by ID; metadata from first occurrence preserved.
- **Multi-format** — JSON arrays, NDJSON, CSV; auto-detection.
- **Entity types** — IP, Host, User, Process, File, Domain, Registry, URL, Service (+ wildcard).
- **Relation types** — Auth, Connect, Execute, Read, Write, DNS, Modify, Spawn, Delete (+ wildcard).

---

## HTTP API & MCP (AI integration)

When the desktop app is running with a session loaded, it exposes an **HTTP API** on **127.0.0.1:37891** (configurable via `GRAPHHUNTER_API_PORT`). This allows external tools to query the graph (entity types, search, expand nodes, run hunts, create notes) without using the UI. The API is protected by **token authentication**: at startup the app prints `GRAPHHUNTER_API_TOKEN=<uuid>` to the console; clients (e.g. the MCP server) must send this token (e.g. via `Authorization: Bearer <token>` or the `GRAPHHUNTER_API_TOKEN` env var) or requests return **401 Unauthorized**.

The **graph-hunter-mcp** package is an **MCP (Model Context Protocol) server** that turns these operations into tools for AI assistants (e.g. Claude Code). You can ask the AI to hunt for malicious paths, expand nodes, or summarize findings while the app holds the session and graph.

| Prerequisite | Description |
|--------------|-------------|
| App running | Start the Tauri app and load or create a session with data. |
| API token | Copy `GRAPHHUNTER_API_TOKEN` from the app startup log into your MCP config `env` so the MCP can authenticate. |
| MCP config | Add the `graph-hunter-mcp` server to your MCP client pointing at the app’s API URL. |

**Quick setup:** See **[graph-hunter-mcp/README.md](graph-hunter-mcp/README.md)** for install, `mcp.json` example, tool list, and troubleshooting (firewall, port, 401, session required).

---

## Documentation

Full documentation is built with **Sphinx** (RST) and hosted on **Read the Docs**. It lives in the **[docs/](docs/)** folder with this structure:

```
docs/
├── conf.py              # Sphinx config
├── index.rst            # Home
├── .readthedocs.yaml    # Read the Docs build config
├── requirements.txt     # Sphinx + sphinx-rtd-theme
├── getting-started/     # Installation, Usage, Demo data
├── user-guide/          # Log formats, Hypothesis DSL & catalog
├── reference/           # Architecture, Privacy
├── _static/
└── images/
```

**Build locally:**

```bash
pip install -r docs/requirements.txt
cd docs && make html
```

Then open `docs/_build/html/index.html`. Or from the repo root: `sphinx-build -b html docs docs/_build/html`.

**Read the Docs:** Connect the repository to readthedocs.org; it will use `docs/conf.py` and `docs/.readthedocs.yaml` to build automatically.

---

## License

This project is licensed under the GNU General Public License v3.0 — see the [LICENSE](LICENSE) file for details.
