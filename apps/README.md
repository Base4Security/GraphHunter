# apps/ — end-user surfaces (glue)

Tauri desktop app, CLI, and any future frontend. Thin wrappers that
compose `platform/` capabilities for a specific delivery form.

**Invariants**: no business logic, no algorithms. Wiring, config
loading, user-facing error rendering. Changes here never touch `core/`
or `platform/` as a side effect — if an app needs a new capability,
the capability lands in `platform/` first.

Crates/dirs that land here during Fase 2: `tauri/`, `cli/`. See
`docs/architecture/phase1/MIGRATION_PLAN.md`.
