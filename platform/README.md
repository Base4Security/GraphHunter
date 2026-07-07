# platform/ — reusable capabilities

Feature seams that clients, MCP, CLI, or Tauri consume: HTTP/IPC API,
parsers, log sources, DSL, canonical OCSF projection, local LLM seam,
VRL fast lane, constrained-decode grammar validator, SIEM connectors.

**Invariants**: depends on `core/` only (never the other way around).
Public API is versioned; breaking changes require an ADR and a semver
bump. Extension points (traits, registries) are the layer's raison
d'être — clients add behaviour without forking.

Crates that land here during Fase 2: `canonical`, `vrl`,
`constrained-decode`, `api`, `siem`, `local-llm`, `parsers`, `sources`,
`dsl`, `mcp`. See `docs/architecture/phase1/MIGRATION_PLAN.md`.
