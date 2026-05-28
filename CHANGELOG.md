# Changelog

All notable changes to Graph Hunter are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [book-v1.0.0] – 2026-05-27 (release date pending merge to main)

**First stable OSS public release.** Marks the cut from `docs/libro-m9-pulido` into `main` + tag `book-v1.0.0` with `libro.pdf` attached as GitHub Release artifact. Release-gated by the Release & Handoff Audit (18 discovery units + 13 fix tasks + 1 deferred follow-up unit; 27 PRs landed). See `docs/superpowers/specs/2026-05-26-release-handoff-audit-design.md` for the full audit spec.

### Documentation

- Libro unificado (~844pp): M0..M9 mergeados, 53 capítulos + 9 apéndices, ~440 ejercicios, ~150 problemas, 59 refs.bib entries, ~38 `@book-snippet` markers conectando libro↔código.
- README + CONTRIBUTING swept for 5 stale paths (`cd app`→`apps/tauri`, `graph_hunter_core/`→`core/graph-engine/`, `cd docs && make all`→`make libro`, `docs/{manual,especificacion,paper}/`→`docs/libro/`, `master`→`main`). Closes RH-P1-004.
- `CODE_OF_CONDUCT.md` (Contributor Covenant 2.1 español) added.
- `.github/ISSUE_TEMPLATE/` (bug/feature/security + config) + `pull_request_template.md` added.
- `docs/decisions/2026-05-26-sidecar-integration.md` — ADR-lite documenting sidecar landing strategy + GPL-3.0↔MS License Terms analysis (IPC mere aggregation).
- `audit-findings/{A4-pii,A5-attribution,B-libro,C-core,D-tauri,E-ubuntu,F-ingest}.md` — 7 discovery audit reports persisted as repo artifacts.

### CI / Build

- `.github/workflows/rust-ci.yml` — matrix `os: [ubuntu-latest, windows-latest] × 14 manifests`. Hard gates: `cargo build --release` + `cargo test`. Soft: clippy, fmt, deny, audit.
- `.github/workflows/libro-cross-os.yml` — Linux + Windows libro builds with sha256 reproducibility check (`SOURCE_DATE_EPOCH` + `\hypersetup` PDF metadata pinning).
- `.github/dependabot.yml` — 14 cargo manifests (lockfile-only) + npm (apps/tauri) + github-actions, weekly schedule.
- Root `build-libro.sh` — Bash wrapper invoking `make -C docs/libro all` with `SOURCE_DATE_EPOCH` + reproducibility checks.
- Top-level `Makefile` expose `libro` + `libro-clean` delegate targets. Closes RH-P1-007.

### Removed

- `graph-hunter-mcp/` legacy MCP monolith (1 670 LOC). Superseded by `platform/mcp/` since `platform/mcp 1.0.0` (2026-04-24). Kept on disk for one release cycle per stability policy; that cycle is now complete. Operators previously pinning the 1.3.0 binary should migrate to `@graphhunter/mcp 1.0.0+` from `platform/mcp/`.

### Security

- **PII purge** (3 P0 closed): 2 real `@base4sec.com` employee emails anonymized in test fixtures + archived LaTeX (RH-P0-002). 14 public IPs in attacker-spray fixtures + 1 LATAM ISP IP in IIS fixture replaced with RFC5737 doc ranges (RH-P0-003, RH-P0-004).
- **CVE fixes**: maxminddb 0.24→0.28.1 (RUSTSEC-2025-0132) in `platform/api`+`core/graph-engine`+`apps/tauri/src-tauri`. rustls-webpki 0.103.12→0.103.13 (RUSTSEC-2026-0104). rkyv 0.8.15→0.8.16 (RUSTSEC-2026-0122). Closes RH-P1-001/002/003/005.
- **Tauri webview**: strict CSP (`default-src 'self' tauri:`) replaces `csp: null`. Closes RH-P1-009. Bundle.targets + publisher metadata + cross-OS config (RH-P1-011 closed). Empty `.catch(() => {})` handlers replaced with `console.error` logging in 11 sites across 7 files (RH-P1-010).
- `deny.toml` allow-list explícito (MIT, Apache-2.0, BSD-2/3, ISC, MPL-2.0, CC0-1.0, Zlib, Unlicense, 0BSD, Unicode-DFS-2016, Unicode-3.0, GPL-3.0). Closes RH-P2-001.
- `apps/tauri/src-tauri/binaries/` agregado a `.gitignore` (355 DLLs runtime .NET no se commitean; fetch script stub `tools/fetch-sidecar-binaries.sh` documenta convención de release artifact).

### Ingest

- `LogParser::try_parse` trait method (aditivo, non-breaking) — emite `Result<Vec<ParsedTriple>, ParseError>` por row. ParseError enum (MalformedRow/FieldType/MissingField/Encoding/SourceSpecific). 3/13 source impls migrated (IIS, Generic, Sentinel JSON); helper `record_parse_errors` enruta a DLQ. 10 source impls restantes compilan via default impl (drop silencioso preservado) — follow-up. Closes RH-P1-012 (partial).
- `Subgraph` DTO: `impl Default` + 5 pagination fields (`total_edges`, `returned_edges`, `offset`, `page_size`, `has_more`). `tests/parity` ahora compila. Closes RH-P1-013.

### Process

- 18 discovery audit units + 13 fix execution tasks + 1 deferred (dependabot) = 27 PRs landed.
- Audit findings tracking: `audit-findings/TEMPLATE.md` define schema con 9 campos por finding; los 7 reports siguen la convención y son consolidados en spec Sec 5.
- Cumple gates duros del spec Sec 7: gitleaks clean (1 placeholder wontfix), CVE clean post-bumps, licencias GPL-3-compatibles, cross-OS builds verdes, PDF reproducible, 0 P0 open, 1 P1 open (RH-P1-014 Ubuntu apt → post-release issue).

### Notable corrections during audit (Unit 18 over Unit 14)

- `unimplemented!()` en `platform/api/src/operations/dlq.rs:498` reportado como P0 por Unit 14: **RETRACTED**. Verificado dentro de `#[cfg(test)] mod tests` con `#[allow(dead_code)]` — warning-silencer helper, nunca invocado. DLQ surface (record/list/reingest/purge) está fully implemented.
- "260 unwraps en hot paths" reportado como P1 fleet liability por Unit 14: **DOWNGRADED P1→P3**. Verificación archivo-por-archivo en 4 archivos más gordos (overflow.rs, source_poller.rs, khop_reach.rs, lftj.rs): **0 de 150 unwraps están en código producción** — todos pasada la barrera `#[cfg(test)]`. Memoria stale por aggressive grep sin filtrar test modules.

### Pending / out-of-scope for v1.0.0

- **Sidecar source landing**: 4+ feature branches sin mergear (`feat/sp2-alt-polling-differential`, `feat/sp3-kql-parser-offline`, `feat/sp4-sentinel-management`). Decision doc + checklist en `docs/decisions/2026-05-26-sidecar-integration.md`. Multi-PR follow-up post-release.
- **LogParser migration**: 10/13 source impls aún emit silent drops via default `try_parse`. Follow-up PR para EVTX, PCAP, Fortianalyzer, Cognito, etc.
- **README Ubuntu apt packages** (RH-P1-014): documentar dependencies inline (libwebkit2gtk-4.1-dev etc) — post-release issue.
- **P2 backlog** (~10 issues): GCP IP en libro narrative, lsotomayor Windows path en debug stub, listings drift TS, SAFETY comments en SIMD prefetch, Tauri bare-return commands, `let _ = handle.emit()` silencing, `.env.example` template, PerfBadge UI surface, agentic ingestor adoption de constrained-decode.
- **Internationalization libro → inglés**: decision separada.
- **Pen-test**: post v1.0.0 if scope+budget align.

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
