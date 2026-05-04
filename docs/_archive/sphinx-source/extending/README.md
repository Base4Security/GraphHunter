# Extending GraphHunter

GraphHunter is split into four shearing layers (see
[`docs/architecture/phase1/TARGET_ARCHITECTURE.md`](../architecture/phase1/TARGET_ARCHITECTURE.md)):
**core** (algorithmic, slow to change), **platform** (stable API for
integrators), **apps** (presentation, mutable), **legacy** (deprecated).

Extension points let you change behaviour **without forking the core**.
Every recipe here describes a surface that has explicit ADR-backed
stability guarantees and a migration path when things do break.

## Cookbook

| Recipe | When to use |
|---|---|
| [DSL extension](./dsl-extension.md) | Add entity types, relation types, or predicates the stock hypothesis grammar doesn't ship. Worked example: a Kubernetes-flavoured extension. |
| [MCP tool](./mcp-tool.md) | Expose a new operation to AI clients (Claude, Cursor, custom agents) through the MCP protocol. |
| [Log parser](./log-parser.md) | Ingest a log format GraphHunter doesn't already understand (cloud SaaS, appliance CSV, proprietary binary). |
| [Transport](./transport.md) | Speak the canonical API over a new wire protocol (gRPC, WebSocket, message queue) without reimplementing business logic. |

## Deciding which surface to extend

Before reaching for a plugin, ask: *is this a grammar change, a data
change, or a presentation change?*

- **Data change** (new log source, new entity kind, new tool surface) →
  the matching cookbook recipe. These are the stable extension points
  and they cover the majority of requests.
- **Grammar / protocol change** (new DSL syntax, new MCP request
  shape, new HTTP contract) → a versioning PR against `v1` DTOs with a
  parallel `v2` module. See the v1/v2 split in
  [`platform/api/src/dto/`](../../platform/api/src/dto/).
- **Presentation change** (new UI view, new dashboard widget) → fork
  or patch `apps/tauri/` directly. Apps are the mutable layer by
  design.

## Stability promises

- Recipes under this directory track **platform** stability — minor
  version bumps won't break them.
- Extension traits themselves live in `platform/*` crates. Their
  public APIs carry semver guarantees once `platform/api` reaches
  1.0.0 (F4.11 / `api-v1.0.0` tag).
- Core internals (`core/graph-engine`, `core/matcher-ffi`,
  `core/gnn`) are intentionally **not** listed here — we don't
  promise a stable extension surface across the algorithmic layer.

## When the cookbook can't answer your question

- Architecture: [`docs/architecture/phase1/`](../architecture/phase1/)
  (ADRs, TARGET_ARCHITECTURE, shearing maps).
- Contracts: each extension points to the ADR that defines it.
- Examples in-tree: look for `*-extension.md` companion tests under
  the relevant crate's `tests/` directory.
