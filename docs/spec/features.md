# Cargo feature flags

- **Status**: stable (contract frozen; new flags require an ADR entry)
- **Version**: v1.0
- **Date**: 2026-04-27
- **Source of truth**: the `[features]` block of each crate's `Cargo.toml`.
- **Citation target**: paper §limits / arquitectura §11-estado.

GraphHunter ships with the **minimum possible surface area enabled by
default**: no ML, no SIMD, no cold-store, no interactive LLM. Every
non-trivial capability is gated behind a named feature so reviewers
and packagers can know exactly what is compiled in — and regulators
can verify that the default binary has no ML surface at all.

Running `cargo test --workspace` with *no* features MUST pass. This
is verified on every PR.

---

## 1. The table

| Feature | Crate | Status | Default? | What it enables | Why it's gated |
|---------|-------|--------|---------:|-----------------|----------------|
| `simd` | `graph_hunter_matcher_ffi` | **stable** | off | Links libgraphmatch, activates the AVX2 C++ matcher via `run_simd_search`. | Optional C++ toolchain dep; pure-Rust DFS is the correct fallback on non-AVX2 hosts. |
| `simd` | `graph_hunter_api` | **stable** | off | Forwards to `graph_hunter_matcher_ffi/simd`; `run_hunt` routes to `search_temporal_pattern_simd`. | Mirrors the FFI gate one layer up so the API and the matcher stay in lockstep. |
| `simd` | `graph_hunter_app` (Tauri) | **stable** | off | Forwards into `graph_hunter_api/simd` for the desktop build. | Without this forward the `#[cfg(feature = "simd")]` switch inside `run_hunt` would silently stay off even when Tauri was built with `--features simd`. |
| `custom-protocol` | `graph_hunter_app` (Tauri) | **stable** | **on** | Standard Tauri asset protocol; required for release builds. | Controlled by Tauri, not by us. |
| `geoip` | `graph_hunter_core` | **stable** | off | Pulls MaxMindDB for offline IP → country/ASN enrichment. | MaxMind distributes the dataset separately; builders who don't have a `.mmdb` on disk shouldn't need to install the crate. |
| `ml-scoring` | `graph_hunter_gnn` | **experimental** | off | Compiles ONNX Runtime + ndarray backends for GNN inference. | Adds ~30 MB of binary weight via ORT; most deployments never load a model (see `w₅ = 0` default in `docs/spec/scoring-v1.md`). |
| `ml-scoring` | `graph_hunter_api` | **experimental** | off | Forwards to `graph_hunter_gnn/ml-scoring`; enables GNN score injection paths on the API. | Same dep-weight story as above. |
| `directml` | `graph_hunter_gnn` | **experimental** | off | DirectML backend for Windows GPU inference. | Currently Windows-only and untested on CI. |
| `gnn-v2-experimental` | `graph_hunter_gnn` | **experimental** | off | Enables the v2 GNN module gated by `common::model_gate` (ADR-003). **NEVER enable in production.** | Rejects synthetic-only models at runtime; compile-time gate is the first line of defence. |
| `gnn-v2-experimental` | `graph_hunter_api` | **experimental** | off | Transitively enables `ml-scoring` + GNN v2. | Same as above. |
| `xgrammar` | `graph_hunter_constrained_decode` | **experimental** | off | xgrammar-backed prefix-constrained sampler that masks decoder logits against the VRL subset CFG so the LLM emits VRL that parses by construction. Pairs with the `candle` backend below. | The post-hoc validator path is always available; the constrained sampler adds a runtime dep (llguidance) that's only needed for the agentic refinement loop. |
| `candle` | `graph_hunter_local_llm` | **experimental** | off | Compiles the candle-backed Phi-3-mini Q4 inference path (CPU-only, ~2.2 GB GGUF + tokenizer, lazy-loaded). Picked by `default_backend()` when `GRAPHHUNTER_LOCAL_MODEL_PATH` is set; falls back to the mock otherwise. | The mock backend covers CI; enabling candle pulls candle-core/candle-transformers/tokenizers and requires the model on disk (`scripts/download-model.sh`). |
| `local-llm-candle` | `graph_hunter_api` | **experimental** | off | Forwards to `graph_hunter_local_llm/candle`. | Same as above. |

---

## 2. Compatibility matrix

- **Default build (`cargo build --workspace`)**: no features. All ML,
  SIMD, cold-store, and LLM surfaces are compiled out. This is the
  shape the paper's security argument relies on.
- **`--features simd`** (activated at the app level): adds the C++
  matcher. Tests under `core/matcher-ffi/tests/` gate on
  `#[cfg(feature = "simd")]` and are vacuous without it.
- **`--features ml-scoring`**: adds ORT; still composites to the same
  `ScoringWeights::default()` which has `w₅ = 0`, so the scorer's
  output is unchanged unless a caller *explicitly* sets weights AND
  loads a model.
- **`--features gnn-v2-experimental`**: transitively activates
  `ml-scoring`. Gated at runtime by `common::model_gate` (ADR-003).
  Never enable on a build destined for end users.
- **`--all-features`**: pulls every feature above. MAY fail on hosts
  without: (a) a C++ toolchain compatible with libgraphmatch,
  (b) the MaxMindDB redistributable dataset, (c) a local LLM
  checkpoint matching `GRAPHHUNTER_LOCAL_MODEL_PATH`. These are
  expected external preconditions, not GraphHunter bugs.

---

## 3. Invariants the default profile enforces

1. **No ML symbols linked.** Removing all `ml-scoring` /
   `gnn-v2-experimental` / `directml` flags means `ort` is not a
   transitive dependency. This is verifiable via `cargo tree -p
   graph_hunter_gnn --no-default-features`.
2. **No C++ toolchain required.** With `simd` off, libgraphmatch is
   not built; a Rust-only CI host can produce a complete GraphHunter
   binary.
3. **No network calls at load time.** Nothing in the default feature
   set performs an outbound HTTP or DNS request at startup.
4. **Deterministic scoring.** The default profile's `w₅ = 0` is
   pinned by `tests::scoring_v1_default_profile_has_zero_gnn_weight`
   and documented in `docs/spec/scoring-v1.md`.

---

## 4. When to open an ADR for a new feature

A new Cargo feature needs an ADR entry when:

- Its default-off state is load-bearing for a public claim
  (e.g. `gnn-v2-experimental` for ADR-003's model gate).
- Enabling it materially widens the supply chain (a new transitive
  crate with native code, a model checkpoint, a C library).
- Turning it on changes observable semantics (`simd` qualifies
  because the matcher implementation changes, even though the result
  set is equivalence-checked by `core/matcher-ffi/tests/
  equivalence_proptest.rs`).

Refactor-only features (test gates, doc gates) do not need an ADR —
just a comment in the feature block explaining why it exists.
