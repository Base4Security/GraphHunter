# Anomaly scoring v1 — formal specification

- **Status**: stable (default profile frozen; GNN dimension experimental)
- **Version**: v1.0
- **Date**: 2026-04-24
- **Authoritative implementation**: `core/graph-engine/src/anomaly.rs` (`AnomalyScorer`, `ScoringWeights`, `ScoreBreakdown`), `core/graph-engine/src/scoring/composite.rs` (trait-based v2 orchestration).
- **Citation target**: paper §scoring, architecture §scoring-design.

This document specifies the composite anomaly score `S(p) ∈ [0, 1]`
GraphHunter assigns to a path `p = (v₁, …, vₙ)` produced by the matcher.
When code and this document disagree, code wins — open a PR against
both.

The headline claim this doc backs: **GraphHunter produces an explainable
score with no ML dependency by default**. The GNN threat component
(`w₅`) exists in the formula for forward compatibility with GraphOS-APT,
but its default weight is zero, so the shipping behaviour is 100 %
traditional, deterministic, auditable statistics over the ingested
graph.

---

## 1. Inputs

A finalized `AnomalyScorer` exposes the following caches (populated by
`observe_entity` / `observe_edge` during ingestion and closed by
`finalize(graph)`):

| Symbol | Source | Type | Meaning |
|--------|--------|------|---------|
| `freq(v)` | `entity_freq` | `u64` | Number of times entity `v` appeared as src or dst of an observed relation. |
| `maxFreq` | `log_max_freq` | `f64` | `ln(max freq)` across all entities, cached. |
| `freq(s, d)` | `pair_freq` | `u64` | Number of times the ordered pair `(s, d)` co-occurred on any edge. |
| `maxPairFreq` | `log_max_pair_freq` | `f64` | `ln(max pair freq)`, cached. |
| `τ_first(v)` | `first_seen` | `i64` | Earliest timestamp `v` was observed. |
| `τ_min`, `τ_max` | scalars | `i64` | Min / max of `τ_first` across all entities. |
| `NC(v)` | `nc_cache` | `f64 ∈ [0, 1]` | Pre-computed neighborhood concentration (see §2.3). |
| `GNN(v)` | `gnn_cache` | `f64 ∈ [0, 1]` | Externally injected threat score (optional). |

All caches are read-only after `finalize`. The scorer is immutable per
hunt; re-finalizing is a conscious operation the UI gates behind an
"advanced" dialog.

---

## 2. The five components

Each component is a function `cᵢ(p) ∈ [0, 1]` reported verbatim in
`ScoreBreakdown` (see `anomaly.rs:34`). Paths are sequences of entity
ids; edges are adjacent pairs.

### 2.1 Entity Rarity (`entity_rarity`)

```
ER(v) = 1 − ln(freq(v)) / ln(maxFreq)
ER(p) = mean(ER(v)) over v ∈ p
```

- **Range**: `[0, 1]`. `ER = 1` when `freq(v) = 1`; `ER = 0` when
  `freq(v) = maxFreq`.
- **Edge case**: if `maxFreq = 1` (ln = 0), the whole graph has no
  rare entities, so `ER(p) = 0`.
- **Intuition**: rare entities push the score up; "background" hosts
  push it down.

### 2.2 Edge Rarity (`edge_rarity`)

```
EdgeR(s, d) = 1 − ln(freq(s, d)) / ln(maxPairFreq)
EdgeR(p) = mean(EdgeR(vᵢ, vᵢ₊₁)) over consecutive pairs in p
```

- **Range**: `[0, 1]`.
- **Edge case**: a single-node path has no edges → `EdgeR(p) = 0`.
- **Intuition**: an unusual edge between two otherwise ordinary
  entities is a strong signal (e.g. `User → Domain` for an unrelated
  user-domain pair).

### 2.3 Neighborhood Concentration (`neighborhood_concentration`)

For a vertex `v`, let `T(v)` be the multiset of entity types of v's
neighbors. Let `H(v)` be Shannon entropy of `T(v)` and `Hₘₐₓ = log₂|T|`
where `T` is the number of distinct types seen across `v`'s neighbors.

```
NC(v) = 1 − H(v) / Hₘₐₓ        (clamped to [0, 1])
NC(p) = mean(NC(v)) over v ∈ p
```

- **Range**: `[0, 1]`. `NC = 1` when `v`'s neighbors are all one type
  (fully concentrated); `NC = 0` when neighbors are perfectly uniform
  across types (maximum entropy).
- **Edge case**: `Hₘₐₓ = 0` (only one neighbor type possible) → `NC =
  1.0` by convention.
- **Intuition**: an entity connected to a single homogeneous
  population is "cleaner" evidence than one spread over every
  conceivable type.

### 2.4 Temporal Novelty (`temporal_novelty`)

```
TN(v) = (τ_first(v) − τ_min) / (τ_max − τ_min)
TN(p) = mean(TN(v)) over v ∈ p
```

- **Range**: `[0, 1]`. Entities first seen at `τ_min` get 0; entities
  at `τ_max` get 1.
- **Edge case**: `τ_max = τ_min` (all entities observed at the same
  instant) → `TN(p) = 0`.
- **Intuition**: newly observed entities inside the hunt window are
  more suspicious than long-lived ones.

### 2.5 GNN Threat (`gnn_threat`)

```
GNN(v) = gnn_cache.get(v).unwrap_or(0.0)
GNN(p) = mean(GNN(v)) over v ∈ p    (0.0 if gnn_cache is empty)
```

- **Range**: `[0, 1]`, assumed pre-clamped by the GraphOS-APT model
  (see `ThreatClass::threat_score_from_logits`).
- **Default behaviour**: `gnn_cache` is empty unless a caller
  explicitly injects scores via `AnomalyScorer::set_gnn_scores`.
- **Status**: **experimental**. Gated behind `w₅ > 0`, which is NOT
  the default. Paper claims do not rely on this component.

---

## 3. Composite formula

```
S(p) = Σᵢ (wᵢ · cᵢ(p)) / Σᵢ wᵢ
```

where the sum runs over the five components. This is the crucial
property:

> **Renormalization by active weights.** If any `wᵢ = 0`, its
> component is dropped from *both* numerator and denominator. A user
> running with `w₅ = 0` gets a composite that is mathematically
> independent of `GNN(p)` — injecting, patching, or corrupting the
> GNN cache cannot shift the score.

This is pinned by
`tests.rs::scoring_v1_default_profile_ignores_injected_gnn_scores`.

The final composite is `.clamp(0, 1)` as defence-in-depth, though each
component is already individually clamped.

---

## 4. Default profile

`ScoringWeights::default()` returns:

| Weight | Component | Value |
|--------|-----------|-------|
| `w₁` | `entity_rarity` | `0.25` |
| `w₂` | `edge_rarity` | `0.30` |
| `w₃` | `neighborhood_concentration` | `0.25` |
| `w₄` | `temporal_novelty` | `0.20` |
| `w₅` | `gnn_threat` | **`0.00`** |

Sum of the first four = `1.00`, so under the default profile the
renormalized composite is exactly the weighted mean of the four
traditional dimensions. The active weights are sanity-checked by
`tests.rs::scoring_v1_default_profile_has_zero_gnn_weight`.

---

## 5. Guaranteed properties

The following are pinned by unit tests and must continue to hold under
any future refactor:

1. **Range.** `S(p), cᵢ(p) ∈ [0, 1]` for every non-empty path on a
   finalized scorer (`anomaly_score_range_0_to_1`).
2. **Empty input.** Empty path or non-finalized scorer → `S(p) = 0`,
   all components zero (`anomaly_empty_graph_no_panic`).
3. **Determinism / bit reproducibility.** Two independent builds of
   the same fixture score the same path to byte-identical `f64` —
   enforced via `f64::to_bits` equality
   (`scoring_v1_is_bit_for_bit_reproducible`).
4. **Directional sensitivity.** A controlled change that makes entity
   `v` objectively rarer strictly increases `ER(v)` — no sign flip or
   floor clamp obscures the signal
   (`scoring_v1_rarer_entity_raises_entity_rarity`).
5. **GNN-independence under default profile.** With `w₅ = 0`,
   injecting arbitrary `gnn_cache` values cannot change the composite
   (`scoring_v1_default_profile_ignores_injected_gnn_scores`). The
   breakdown, however, still surfaces the raw component for
   explainability — the renormalization is a *weighting* choice, not
   a visibility choice.
6. **Weighted-sum algebra.** `S(p) = Σ wᵢ · cᵢ / Σ wᵢ` to within
   `1e-10` (`anomaly_weights_sum_correctly`).

---

## 6. Explainability contract

Every scored path carries its `ScoreBreakdown` alongside the composite.
The struct is public (`pub use anomaly::{…, ScoreBreakdown, …}` in
`lib.rs`) and surfaces as an optional field on hunt results
(`analytics.rs::anomaly_breakdown: Option<ScoreBreakdown>`, exposed
through the platform API and the Tauri UI's `HuntResultsTable`).

A caller that receives a path can always answer:

- **"Why does this path score what it does?"** — inspect `breakdown`.
- **"Would the score change under a different weighting?"** — apply
  §3 formula over the same breakdown without re-running the matcher.

This is what distinguishes GraphHunter v1 scoring from a black-box
ML classifier: the score is a transparent weighted mean of four
first-order graph statistics, with the full decomposition exposed.

---

## 7. Non-goals for v1

- Learned weights (`w₁…w₄` remain operator-tunable constants).
- Cross-path context (the scorer is pure per-path).
- Time-decay of `freq` or `pair_freq` (all observations weigh equally
  once inside the ingest window).
- GNN training, inference orchestration, or drift detection. Those
  live behind the `gnn-v2-experimental` feature flag and ADR-003's
  empty-model-cache gate.

These are candidates for a future `scoring-v2.md` once the evidence
base supports them.
