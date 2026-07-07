# Changelog

All notable changes to Graph Hunter are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

### Graph-cycle intermediation (design doc §3–§5)

Turns the four-phase graph cycle from a design proposal into working tools, so
the graph — not raw KQL — is the default hunting path against Microsoft Sentinel.

#### Added — the six cycle tools (MCP + HTTP)

- **`schema_discover`** (§4.1) — live Log Analytics table/field discovery via the
  `Usage` table + per-table sampling; classifies each field's `graph_affinity`
  (node/edge/attribute), `node_class`, `cardinality`, and `enrichable` tags, and
  reports query cost. (Renamed from the interim `sentinel_schema`, which remains
  a deprecated alias.)
- **`graph_propose`** (§4.2) — from selected `{table, field}` pairs, emits candidate
  graph schemas with the exact `materialization_kql` (guards columns with
  `columnifexists`, extracts nested AWSCloudTrail fields via `parse_json`);
  proposals persist in the session by `proposal_id`.
- **`graph_build`** (§4.3) — runs an approved proposal's KQL, maps rows to
  entities/relations with a schema-driven mapper, loads them into the graph, and
  applies enrichment **once** (GeoIP+ASN on IP nodes; `threat_intel` is an honest
  stub). Supports `merge_mode` append/replace; records `last_build`.
- **`graph_neighbors`** (§4.5) — immediate neighborhood of an entity over the
  built graph (no SIEM round-trip).
- **`graph_path`** (§4.4) — paths between two entities (or all outbound paths up
  to `max_depth`), backed by a new bounded simple-path traversal in the engine.
- **`graph_anomaly`** (§4.6) — structural anomalies by degree / betweenness /
  isolation with z-scores, optionally scoped to a node class.

#### Changed — enforcement & active state

- **`sentinel_query` fallback gate** (§4.7) — inspect queries projecting
  entity-class columns are no longer executed by default; they return a
  ready-to-run `graph_propose` payload and `fallback_gated=true`. Pass
  `acknowledge_fallback=true` to run raw KQL as a logged one-off. Ingest/
  materialize paths are never gated.
- **`graph_summary` / `session_check`** now report the §5 active-state shape:
  `graph_state` (empty/partial/populated), `advisory`, `capabilities`, and
  `last_build`.
- **Sentinel client** captures query cost (`Prefer: include-statistics`):
  bytes scanned + server duration, surfaced by the cycle tools.

#### Added — verification

- `scripts/e2e-graph-cycle.mjs` — env-gated (`GRAPHHUNTER_E2E=1`) end-to-end run
  of the full cycle against a live/test workspace.

## [code-v1.0.0] – 2026-05-28

**First stable OSS public release** of the GraphHunter engine + app. Release-gated by a security & handoff audit; the user-facing book is maintained separately (internal).

### Performance

- **Semijoin start pruning** and **AMAC interleaved DFS** are now enabled by default on multi-step hunts. Opt out for one release with `GRAPHHUNTER_SEMIJOIN=0` or `GRAPHHUNTER_AMAC=0`.
- **Parallel streaming finalize** is now on by default for large graphs (>50 000 vertices or >1 000 000 edges). The rayon sort pass replaces the sequential O(Σ d log d) finalize without extra configuration. Opt out for one release with `GRAPHHUNTER_PARALLEL_FINALIZE=0`; force on for smaller graphs with `=1`.

### Hybrid sessions (Track H)

- **`SessionPhase`** lifecycle (`loading` → `finalizing` → `ready` / `live_tail`) gates hunts during ingest finalize; HTTP/Tauri callers receive **409 Conflict** while loading or finalizing.

### Added

- `CODE_OF_CONDUCT.md` (Contributor Covenant 2.1) + `.github/ISSUE_TEMPLATE/` (bug/feature/security) + `pull_request_template.md`.
- `.github/workflows/rust-ci.yml` — matrix `os: [ubuntu-latest, windows-latest] × 14 manifests`. Hard gates: `cargo build --release` + `cargo test`. Soft: clippy, fmt, deny, audit.
- `.github/dependabot.yml` — 14 cargo manifests (lockfile-only) + npm (apps/tauri) + github-actions, weekly schedule.
- `docs/decisions/2026-05-26-sidecar-integration.md` — ADR-lite for the Sentinel sidecar landing strategy + GPL-3.0↔MS License Terms analysis (IPC mere aggregation).

### Security

- **PII purge** (3 issues): 2 real `@base4sec.com` employee emails anonymized in test fixtures. 14 public IPs in attacker-spray fixtures + 1 LATAM ISP IP in an IIS fixture replaced with RFC5737 documentation ranges.
- **CVE fixes**: maxminddb 0.24→0.28.1 (RUSTSEC-2025-0132) across `platform/api` + `core/graph-engine` + `apps/tauri/src-tauri`. rustls-webpki 0.103.12→0.103.13 (RUSTSEC-2026-0104). rkyv 0.8.15→0.8.16 (RUSTSEC-2026-0122).
- **Tauri webview**: strict CSP (`default-src 'self' tauri:`) replaces `csp: null`. Bundle.targets + publisher metadata + cross-OS config. Empty `.catch(() => {})` handlers replaced with `console.error` logging (11 sites, 7 files).
- `deny.toml` license allow-list (MIT, Apache-2.0, BSD-2/3, ISC, MPL-2.0, CC0-1.0, Zlib, Unlicense, 0BSD, Unicode-DFS-2016, Unicode-3.0, GPL-3.0).
- `apps/tauri/src-tauri/binaries/` gitignored (355 .NET runtime DLLs are release artifacts, not source; `tools/fetch-sidecar-binaries.sh` documents the fetch convention).

### Ingest

- `LogParser::try_parse` trait method (additive, non-breaking) — emits `Result<Vec<ParsedTriple>, ParseError>` per row. `ParseError` enum (MalformedRow/FieldType/MissingField/Encoding/SourceSpecific). 3/13 source impls migrated (IIS, Generic, Sentinel JSON); `record_parse_errors` routes to the DLQ. Remaining 10 impls compile via the default impl (silent-drop preserved) — follow-up.
- `Subgraph` DTO: `impl Default` + 5 pagination fields (`total_edges`, `returned_edges`, `offset`, `page_size`, `has_more`). `tests/parity` now compiles.

### Removed

- `graph-hunter-mcp/` legacy MCP monolith (1 670 LOC). Superseded by `platform/mcp/` since `platform/mcp 1.0.0` (2026-04-24). Operators previously pinning the 1.3.0 binary should migrate to `@graphhunter/mcp 1.0.0+`.

### Pending / out-of-scope for v1.0.0

- **Sentinel sidecar landing**: feature branches `feat/sp1-4` to be rebased onto this release. Strategy in `docs/decisions/2026-05-26-sidecar-integration.md`.
- **LogParser migration**: 10/13 source impls still emit silent drops via the default `try_parse`. Follow-up PR for EVTX, PCAP, Fortianalyzer, Cognito, etc.
- **Quality backlog**: SAFETY comments on 3 SIMD prefetch blocks, Tauri bare-return commands → `Result`, `let _ = handle.emit()` logging, `.env.example` template, PerfBadge UI surface, agentic ingestor adoption of constrained-decode.

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
