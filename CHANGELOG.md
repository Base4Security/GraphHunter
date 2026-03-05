# Changelog

All notable changes to Graph Hunter are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [1.0.0] – Initial release

### Added

- Graph-based threat hunting engine (Rust core).
- Temporal pattern matching with causal monotonicity and hypothesis DSL.
- Parsers: Sysmon, Microsoft Sentinel, generic JSON, CSV; auto-detect.
- Endogenous anomaly scoring (Entity Rarity, Edge Rarity, Neighborhood Concentration, Temporal Novelty, GNN Threat).
- GNN threat classification via ONNX (DirectML NPU/GPU, feature-gated).
- Tauri desktop app with React UI: sessions, Hunt/Explorer modes, graph canvas, Events/Heatmap/Timeline, Path Nodes, Notes.
- Hypothesis builder with ATT&CK hypothesis catalog.
- HTTP API (127.0.0.1, token auth) for external tools.
- Gateway (Go) for web-based upload and SIEM query ingest (Sentinel, Elasticsearch).
- MCP server for AI assistant integration.
- Sphinx documentation (Read the Docs).

[1.0.0]: https://github.com/Base4Security/GraphHunter/releases/tag/v1.0.0
