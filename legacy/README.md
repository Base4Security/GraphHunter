# legacy/ — quarantined / archived code

Code that is no longer on the active layer map but is preserved for
reference, audit, or future evaluation. Not wired into workspace
builds; tests (if any) are not part of CI.

**Invariants**: read-only. No new commits here except deletions
(Fase 5 decision). Importing from `legacy/` into `core/`, `platform/`,
or `apps/` is a lint-level error.

Current inhabitants (landing during Fase 2.19): `gateway/` (Go job
manager superseded by direct Tauri ↔ platform/api IPC). See
`docs/architecture/phase1/MIGRATION_PLAN.md`.
