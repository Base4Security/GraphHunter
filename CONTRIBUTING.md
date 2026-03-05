# Contributing to Graph Hunter

Thank you for your interest in contributing. This document explains how to get set up, follow project conventions, and submit changes.

## Getting started

1. **Clone the repository** and ensure you have the [prerequisites](README.md#installation) (Rust, Node.js, Tauri v2 build tools).

2. **Run the app in development:**
   ```bash
   cd app
   npm install
   npm run tauri dev
   ```

3. **Run tests and checks before submitting:**
   ```bash
   cd graph_hunter_core && cargo test
   cd ../app && npx tsc --noEmit
   cd src-tauri && cargo check
   ```

## Development workflow

- **Branch:** Use a feature branch (e.g. `feature/new-parser`, `fix/hunt-pagination`). The default branch is `master`.
- **Commits:** Use imperative, concise summary lines (e.g. `Add CSV parser`, `Fix timeline sort`). Add a body for details when helpful.
- **Scope:** Keep changes focused. For larger work, open an issue first to discuss.

## Code conventions

- **Rust (graph_hunter_core):** Domain logic lives in the core library. Parsers implement the `LogParser` trait; tests live in the `mod tests` block in `lib.rs`. See [.claude/CLAUDE.md](.claude/CLAUDE.md) for parser pattern, test naming, and error handling.
- **Tauri (app/src-tauri):** Thin command layer over the core. Commands are prefixed with `cmd_`; add new formats via a match arm in `cmd_load_data` and a corresponding parser import.
- **Frontend (app/src):** Functional React components, TypeScript types in `types.ts`, Tauri `invoke<>` for backend calls. Icons from `lucide-react` with `size={14}` for consistency.

Full conventions (parser checklist, frontend patterns, Git) are documented in [.claude/CLAUDE.md](.claude/CLAUDE.md).

## Adding a new log format

1. Implement `LogParser` in `graph_hunter_core/src/<format>.rs`.
2. Register the module and parser in `graph_hunter_core/src/lib.rs`.
3. Add a format branch in `app/src-tauri/src/lib.rs` in `cmd_load_data`.
4. Add the format option in `app/src/components/IngestPanel.tsx`.
5. Add demo data under `demo_data/` and tests in `graph_hunter_core/src/lib.rs`.
6. Run `cargo test`, `npx tsc --noEmit`, and `cargo check` in `app/src-tauri`.

## Submitting changes

1. Ensure all tests pass and the app runs (`npm run tauri dev`).
2. Open a pull request with a clear title and description of the change.
3. Reference any related issue if applicable.

## Questions and issues

- **Bugs or feature ideas:** Open a GitHub issue.
- **Security concerns:** Please report privately (e.g. via maintainer contact) rather than in a public issue. See [SECURITY.md](SECURITY.md) for how to report vulnerabilities.

Thanks for contributing.
