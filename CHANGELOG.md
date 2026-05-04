# Changelog

All notable changes to Graph Hunter are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [platform/mcp 1.0.0] – 2026-04-24

Full migration of the MCP tool registry from the legacy `graph-hunter-mcp/` monolith (1 670 LOC, 54 tools in one file) to the modular `platform/mcp/` layout introduced in 1.0.0. All 54 tools now live under `src/tools/<category>/` with one file per tool, a per-category barrel, and a single `registry.ts` importing each category in stable order. `server.ts` adapts every tool onto the MCP SDK in one place; no per-tool boilerplate.

### Added

- `platform/mcp/src/tools/{navigation,hunting,scoring,graph-views,catalogs,notes,export,data-quality,agentic,integrations}/` — 54 tool files (10 navigation, 6 hunting, 3 scoring, 4 graph-views, 4 catalogs, 6 notes, 3 export, 7 data-quality, 8 agentic, 3 integrations).
- `Tool.resultFormat?: "json" | "text"` (`src/lib/types.ts`) — export tools return raw CSV/JSON/NDJSON/YAML/STIX text and opt into `"text"` so the server adapter wraps them in `textContent` verbatim instead of running the string through `safeJsonContent`.
- `/v1/schema` now lists all **55** endpoints the migrated tools depend on (plus `/v1/schema` itself). 3 new tests cover the heavy flag, duplicate-path detection, and cross-category coverage; full `platform/api` suite: **157 passed / 0 failed**.
- Contract test (`platform/mcp/tests/contract/schema.test.ts`) asserts every migrated endpoint is registered in the schema response — breaks CI on MCP↔API drift.

### Changed

- CI (`.github/workflows/ci.yml`) builds `platform/mcp/` instead of the legacy package. `graph-hunter-mcp/` stays on disk for one release cycle so operators with the 1.3.0 binary pinned can still rebuild locally; it is no longer exercised by CI.
- `@graphhunter/mcp` bumped from `0.1.0-wip` to `1.0.0` — the package now owns the `graph-hunter-mcp` bin name going forward.

### Stability tier

`platform/mcp` is now **stable** alongside `platform/api`. Adding a tool = one file under `src/tools/<category>/` + one line in the category barrel; removing or renaming a tool is a 2.0.0 change.

## [platform/api 1.0.0] – 2026-04-23

First stable cut of the canonical API layer (`graph_hunter_api` crate). From this tag onward, DTOs under `platform/api/src/dto/v1/` are covered by semver — additive changes only within the major. Breaking changes land in a parallel `v2` namespace; callers opt in per endpoint.

### Added

- `dto::v1::schema` + `GraphHunterApi::get_schema()` — authoritative list of stable endpoints consumed by the MCP contract tests (ADR-004 §D5).
- `dto::v1::health` + `GraphHunterApi::get_health()` — process + GNN v1/v2 model status probe (ADR-003 §D5).
- `platform/mcp/` — successor to `graph-hunter-mcp/`, modular per-domain tool registry per ADR-004. Initial migration covers `navigation/check_connection` + `navigation/get_entity_types`; remaining tools tracked as F4.8 follow-up (closed in `platform/mcp 1.0.0`).
- `platform/api` `gnn-v2-experimental` feature flag forwarding to `graph_hunter_gnn` — compile-time opt-in for the unreleased v2 GNN path (ADR-003).
- DSL extension surface: `DslParser::v1().with_extension(...)`, `EntityTypeRegistry`, `RelationTypeRegistry`, `PredicateRegistry` (ADR-005). Cookbook recipe under `docs/extending/dsl-extension.md`.
- Cookbook for extension points under `docs/extending/` (MCP tool, log parser, transport).

### Changed

- DTOs migrated to `dto::v1::*` namespace; legacy import paths preserved via `pub use v1::*;` — no caller changes required. `dto::v2` reserved for the next breaking cycle.
- GNN model loading gated by `core/gnn::common::model_gate` — v2 models require `gnn-v2-experimental` + `trained_on ∈ {production, mixed}` + validation accuracy ≥ 0.80. Synthetic-only corpora are rejected unless the experimental feature is on.
- `scripts/train_gnn_v2.py` now writes an ADR-003 sidecar `metadata.json` (sha256, `trained_on`, validation accuracy, class labels, tensor shape) next to the exported ONNX.

### Stability tier

`platform/api` and `platform/dsl` are now **stable**. Breaking a public symbol requires a v2 module or a 2.0.0 release.

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
