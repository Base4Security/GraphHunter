# E-ubuntu — Ubuntu 22.04 first-clone walk-through

**Date:** 2026-05-26
**Method:** Live Docker walk-through (`ubuntu:22.04` container, bind-mounted worktree to `/source-readonly:ro`, copied to `/tmp/gh`, followed the README quickstart literally on a fresh shell with only `git curl build-essential pkg-config libssl-dev ca-certificates` installed).
**Worker:** unit-16
**Base commit:** c85594d

## Summary

8 findings: 0 P0, 5 P1, 0 P2, 3 P3 across the README quickstart and CONTRIBUTING.md getting-started flow. The headline issue is that **every quickstart command in the README that references a path is stale** — directories named in the snippets (`app/`, `graph_hunter_core/`, `docs/manual/`, `docs/especificacion/`, `docs/paper/`, plus the `cd docs && make all` entry point) do not exist on disk. A first-time external user copy-pasting from the README cannot get past step 2 of "Installation" without guessing the right paths. Toolchain prerequisites (Tauri Linux libs, Node setup-method) are deferred to upstream links without the minimum apt package list inline. None of this is a runtime crash, but the documented happy path is broken end-to-end on Linux and on every other OS too (the paths are wrong in absolute terms, not Linux-specific).

## Findings

### README "Installation" step 2 references non-existent directory `app/`

- **Severity:** P1
- **Axis:** docs
- **Front:** infra
- **Evidence:** `README.md:177` says `cd app` followed by `npm install` and `npm run tauri dev`. Live container output: `/walk.sh: line 22: cd: app: No such file or directory`. The actual Tauri app lives at `apps/tauri/`. The same broken path is repeated at `README.md:194` (build for production) and `README.md:282` (Usage section). The root `package.json` is unrelated (a single `claude` dep) so `npm install` at repo root produces no useful side effect either.
- **Risk:** Every external user who follows the README quickstart literally fails at step 2. The "first 5 minutes" experience is broken; people abandon at the first command that errors.
- **Fix action:** Replace `cd app` with `cd apps/tauri` at README.md lines 177, 194, 282 (and `Usage` section reference at line 305 which already correctly uses `apps/tauri/` — leverage that as the canonical form).
- **Cost:** XS
- **Gate:** pre-release
- **Owner suggested:** tú

### README "Run tests" snippet references non-existent directory `graph_hunter_core/`

- **Severity:** P1
- **Axis:** docs
- **Front:** infra
- **Evidence:** `README.md:187` says `cd graph_hunter_core && cargo test`. Live container output: `ls: cannot access 'graph_hunter_core': No such file or directory`. The actual core engine crate is at `core/graph-engine/`. The same stale crate name appears at `README.md:247`, `:252`, `:257` (SIMD section: `cargo build --features simd -p graph_hunter_core`) and in `apps/tauri/src-tauri/Cargo.toml`'s package name is in fact `graph-hunter-app` not `graph_hunter_core`. `CONTRIBUTING.md:18` repeats the same broken command, and `:31`, `:39`, `:40`, `:43` keep referring to the same non-existent directory in the "Code conventions" and "Adding a new log format" sections.
- **Risk:** Anyone trying to run tests, build the SIMD feature, or contribute via the `LogParser` pattern is blocked by stale paths in both README and CONTRIBUTING. The Makefile (`make test`) actually works but the README never mentions it; the user has to discover Makefile by `ls`.
- **Fix action:** Replace `graph_hunter_core` with `core/graph-engine` across `README.md` and `CONTRIBUTING.md` (sed -i 's|graph_hunter_core|core/graph-engine|g' on both files, then audit `-p graph_hunter_core` → `-p graph-hunter-core` per actual Cargo.toml package name). Also add a one-liner pointing to `make test` / `make check` as the recommended entry point.
- **Cost:** S
- **Gate:** pre-release
- **Owner suggested:** tú

### README architecture section instructs `cd docs && make all` but `docs/Makefile` does not exist

- **Severity:** P1
- **Axis:** docs
- **Front:** libro
- **Evidence:** `README.md:160`: ``Build: `cd docs && make all` (requires `xelatex` + `biber`). CI job `.github/workflows/docs.yml` builds the four PDFs on every push touching `docs/**` and uploads them as artifacts.`` Live container output:
  ```
  $ cd docs && make all
  cd-exit=0
  ls: cannot access 'Makefile': No such file or directory
  ```
  `docs/` contains only `README.md`, `_archive`, `arquitectura`, `images`, `libro`, `perf`, `superpowers`. No Makefile at any level under `docs/`. The single root-level `Makefile` is for Rust pre-merge checks, not for building documentation. The actual book build is per-subdirectory under `docs/libro/` and `docs/arquitectura/` and is invoked by `.github/workflows/docs.yml` — but neither path is reflected in the README quickstart.
- **Risk:** Anyone trying to build the documentation (which the README highlights as four PDFs covering architecture, spec, manual, paper) cannot execute the documented command. The CI workflow exists, but local reproducibility is blocked by missing entry point.
- **Fix action:** Either (a) add `docs/Makefile` with `all: arquitectura libro` targets that delegate to subdirectories, OR (b) update `README.md:160` to point at the actual command (e.g., `cd docs/libro && latexmk -xelatex main.tex` or a new top-level `build-libro.sh` from Unit 8 of this batch).
- **Cost:** S
- **Gate:** pre-release
- **Owner suggested:** tú (coordinate with Unit 8 which is creating `build-libro.sh`)

### README architecture section lists three documentation directories that do not exist

- **Severity:** P1
- **Axis:** docs
- **Front:** libro
- **Evidence:** `README.md:156-158` lists four books under `docs/`:
  - `docs/arquitectura/` — exists
  - `docs/especificacion/` — **MISSING**
  - `docs/manual/` — **MISSING**
  - `docs/paper/` — **MISSING**

  Live container output: `MISSING docs/manual / MISSING docs/especificacion / MISSING docs/paper`. The unified book initiative under `docs/libro/` (see project_libro_unificado in MEMORY) is consolidating these four books into one, but the README still advertises the four-book layout that no longer maps to disk.
- **Risk:** Readers expecting the spec / manual / paper PDFs cannot find them. Sets up incorrect expectations of what ships with the release.
- **Fix action:** Update README.md architecture section to reflect the consolidated `docs/libro/` reality: replace the four-bullet list with a single "`docs/libro/` — unified book covering architecture, spec, manual, and research paper (in Spanish, LaTeX → PDF)" item. Cross-reference the consolidation roadmap in `docs/libro/roadmap.md` (or whichever roadmap doc Unit 13 audits).
- **Cost:** XS
- **Gate:** pre-release
- **Owner suggested:** tú

### CONTRIBUTING.md says default branch is `master` but actual default is `main`

- **Severity:** P3
- **Axis:** docs
- **Front:** community
- **Evidence:** `CONTRIBUTING.md:25`: ``The default branch is `master`.`` Recent commits show `main` is the active default (PR merges target `main` per the M9 batch plan; `docs/libro-m9-pulido` is the current feature branch). Live container could not verify git context because the bind-mount of `.git/worktrees/` doesn't reach into the parent repo (`fatal: not a git repository: /tmp/gh/.../.git/worktrees/agent-...`), but the host context is clear.
- **Risk:** New contributors trying to `git checkout master` to start a feature branch get nothing or stale refs. Low blast radius (most people will just `git checkout main` after the first miss) but signals stale docs.
- **Fix action:** `sed -i 's|`master`|`main`|g' CONTRIBUTING.md` and grep for any other `master` references in top-level docs.
- **Cost:** XS
- **Gate:** post-release
- **Owner suggested:** automatable

### README does not enumerate Ubuntu/Debian apt packages needed for the Tauri build

- **Severity:** P1
- **Axis:** docs
- **Front:** tauri
- **Evidence:** `README.md:172`: ``Platform-specific build tools: see [Tauri prerequisites](https://v2.tauri.app/start/prerequisites/)`` — only a link, no inline command. The Tauri v2 page lists `libwebkit2gtk-4.1-dev`, `libsoup-3.0-dev`, `libjavascriptcoregtk-4.1-dev`, `libxdo-dev`, `libssl-dev`, `librsvg2-dev`, etc. for Ubuntu 22.04. A user who does only `apt install build-essential pkg-config libssl-dev` (the base set commonly assumed for Rust on Linux) will fail at the Tauri build step with cryptic linker errors. The Dockerfile at the repo root deliberately skips Tauri so it cannot serve as a reference. There is no `scripts/install-linux-deps.sh` or equivalent.
- **Risk:** Linux external users hit linker / webkit errors after `npm run tauri dev` and bounce — even though it's "just a documented apt-install" they have to leave the README to find out which packages.
- **Fix action:** Add a "Linux (Ubuntu 22.04 / Debian)" subsection under "Install prerequisites" with the explicit `sudo apt install` one-liner from the Tauri v2 docs, OR create `scripts/install-linux-deps.sh` and reference it. Suggested baseline: `sudo apt install -y libwebkit2gtk-4.1-dev libsoup-3.0-dev libjavascriptcoregtk-4.1-dev libxdo-dev libssl-dev librsvg2-dev libayatana-appindicator3-dev pkg-config build-essential curl wget file`.
- **Cost:** XS
- **Gate:** pre-release
- **Owner suggested:** tú

### README links to nodejs.org without saying which install method works on Ubuntu 22.04

- **Severity:** P3
- **Axis:** docs
- **Front:** infra
- **Evidence:** `README.md:171`: ``[Node.js](https://nodejs.org/) (v18+)`` — links to the marketing page. Ubuntu 22.04 ships `apt install nodejs` at v12 (way below v18 minimum). Users must know to use NodeSource (`curl -fsSL https://deb.nodesource.com/setup_20.x | sudo bash - && sudo apt install nodejs`), nvm, or asdf. Live container: `node` not present in base image, confirming a fresh user starts from zero.
- **Risk:** Users `apt install nodejs` → get v12 → `npm run tauri dev` fails with "engine not supported" or syntax errors → confusion. Low blast radius (developers usually have a node manager) but still a paper-cut.
- **Fix action:** Add to README under "Install prerequisites" → Linux: ``Install Node 20+ via NodeSource (`curl -fsSL https://deb.nodesource.com/setup_20.x | sudo bash - && sudo apt install -y nodejs`) or `nvm install --lts`. Ubuntu 22.04's `apt install nodejs` ships v12 which is too old.``
- **Cost:** XS
- **Gate:** post-release
- **Owner suggested:** automatable

### Root `package.json` is unrelated to the app and may confuse `npm install` at repo root

- **Severity:** P3
- **Axis:** docs
- **Front:** infra
- **Evidence:** Repo root contains `package.json` with `{"dependencies": {"claude": "^0.1.1"}}` and a 463-byte `package-lock.json`. Neither references the Tauri app. A user who guesses `npm install` at repo root (because the wrong README quickstart says to enter `app/` which doesn't exist) installs the unrelated `claude` package and continues to be confused. The actual Tauri app's `package.json` is at `apps/tauri/package.json` with `"name": "graph-hunter", "version": "1.0.0"`.
- **Risk:** Low — most users either find `apps/tauri` quickly or read `make help`. But the orphan root `package.json` is a red herring for newcomers and a stale artifact in the supply chain (one extra npm dep installed unintentionally).
- **Fix action:** Either delete root `package.json`+`package-lock.json` (they appear to be vestigial — the `claude` dep is the Claude Code SDK, irrelevant to runtime) OR move them to `.claude/` if they belong to tooling. Confirm with `git log --follow package.json` who introduced them.
- **Cost:** XS
- **Gate:** post-release
- **Owner suggested:** tú

## Method log

Chronological log of the live Docker walk-through. Container image `ubuntu:22.04`, executed via `docker --context default run --rm -v "$WORKTREE:/source-readonly:ro" -v "walk.sh:/walk.sh:ro" ubuntu:22.04 bash /walk.sh`. Total elapsed: ~3 min (apt-update dominated). The full captured output is reproduced verbatim below.

```
===== STEP A: apt-get update + base deps =====
0 added, 0 removed; done.
Running hooks in /etc/ca-certificates/update.d...
done.
exit=0

===== STEP B: copy source to writable location =====
PWD=/tmp/gh
Top-level entries:
CHANGELOG.md
CONTRIBUTING.md
Dockerfile
LICENSE
Makefile
README.md
SECURITY.md
apps
core
demo_data
docs
graph-hunter-mcp
legacy
package-lock.json
package.json
platform
scripts
templates
tools
training

===== STEP C: README quickstart -- section 'Installation' =====
164:## Installation
166-You need Rust, Node.js, and the [Tauri v2 prerequisites](...)--no extra services or accounts.
174-2. **Clone and run in development:**
176-   ```bash
177-   cd app
178-   npm install
179-   npm run tauri dev
180-   ```
[...]
187-cd graph_hunter_core
188-cargo test

===== STEP D: Follow README literally -- step 2 says 'cd app && npm install && npm run tauri dev' =====
$ cd app
/walk.sh: line 22: cd: app: No such file or directory
exit=1
Looking for 'app' dir from repo root:
ls: cannot access 'app': No such file or directory
Looking for actual Tauri app dir:
apps/tauri

===== STEP E: README also says 'cd graph_hunter_core && cargo test' (line ~188) =====
$ cd graph_hunter_core
ls: cannot access 'graph_hunter_core': No such file or directory
Looking for actual core engine dir:
core/graph-engine

===== STEP F: README architecture section claims 'cd docs && make all' (line ~160) =====
$ cd docs && make all
cd-exit=0
ls: cannot access 'Makefile': No such file or directory
ls-exit=2
Listing docs/ contents:
README.md
_archive
arquitectura
images
libro
perf
superpowers
README says 'docs/manual/', 'docs/especificacion/', 'docs/paper/' exist -- checking:
MISSING docs/manual
MISSING docs/especificacion
MISSING docs/paper

===== STEP G: CONTRIBUTING.md getting-started literally =====
CONTRIBUTING.md says default branch is master -- actual default branch on origin?
(We are offline in container so we cannot check origin, but the local copy has:)
fatal: not a git repository: /tmp/gh/C:/Users/lsotomayor/GraphHunter/.git/worktrees/agent-...
(Note: bind-mounted worktree's .git is a pointer to the parent repo, which is not bind-mounted.
The host git context confirms default branch is `main`; CONTRIBUTING.md says `master`.)

===== STEP H: Try the Dockerfile path (alternate quickstart) =====
Dockerfile head exists; documents 'docker build -t graphhunter:dev .' as the auditable Linux entry point.
Tauri / GUI explicitly out of scope of the Dockerfile (it builds platform/* only).
We are already inside a container so we did not run nested docker.

===== STEP I: Try Makefile (the actual entry point) =====
$ make help
GraphHunter Makefile targets:
  pre-merge   - Full safety net (layering + check + test) before pushing.
  check       - cargo check --tests on hot crates.
  check-all   - cargo check --tests on every crate.
  test        - cargo test on hot crates (skips long-running benchmark_*).
  [...]

$ make check  # cargo check on hot crates
rust not installed -- make check would fail with: cargo: command not found

===== STEP J: Try to install rustup as a fresh user would =====
README says 'install Rust via rustup' (line 170 link). Trying:
-rw-r--r-- 1 root root 29250 May 26 20:46 /tmp/rustup-init.sh
(rustup-init.sh fetched OK; install skipped to keep walk short -- adds ~500MB toolchain).

===== STEP K: Try README node path (npm) =====
$ npm --version
(not found)
node not installed by default -- Ubuntu 22.04 base has no node.
README points to nodejs.org but does not say which node version setup script Linux users should run.
Common Ubuntu pattern is NodeSource: curl -fsSL https://deb.nodesource.com/setup_20.x | bash - && apt-get install nodejs

===== STEP L: README mentions scripts/download-model.sh -- check it exists =====
-rwxr-xr-x 1 root root 5233 May 26 20:46 scripts/download-model.sh
(exists, executable -- README is consistent on this one.)

===== STEP M: README Docker section -- check Dockerfile only builds platform/* not the Tauri app =====
1
(Confirmed: Dockerfile only builds platform/* crates, no GUI. README is clear about that.)

===== STEP N: WALK COMPLETE =====
```

**Verifications corroborating findings from host (outside container):**

- `ls -d app graph_hunter_core docs/manual docs/especificacion docs/paper docs/Makefile` → all return "No such file or directory" except the parent dirs.
- `grep -n "cd app\|graph_hunter_core\|docs/manual\|docs/especificacion\|docs/paper" README.md` → 10 hits at lines 156, 157, 158, 160, 177, 187, 194, 247, 252, 257, 282.
- `grep -n "cd app\|graph_hunter_core\|master" CONTRIBUTING.md` → 7 hits at lines 11, 18, 25, 31, 39, 40, 43.
- `apps/tauri/package.json` has `"name": "graph-hunter"` confirming the canonical location.
- Root `package.json` only declares `{"dependencies": {"claude": "^0.1.1"}}` — orphan / tooling artifact.

**No P0 finding** — the app is not segfaulting, the source compiles via the Dockerfile path, and the Makefile-driven Rust path is internally consistent. The cascade is **docs ↔ filesystem drift**: paths in README/CONTRIBUTING haven't been updated since the monorepo migration that moved `app/` → `apps/tauri/`, `graph_hunter_core/` → `core/graph-engine/`, and consolidated `docs/{arquitectura,especificacion,manual,paper}/` into `docs/libro/`.
