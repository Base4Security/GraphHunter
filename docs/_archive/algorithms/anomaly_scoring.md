# Path anomaly scoring

**Implemented in:** `core/graph-engine/src/anomaly.rs` — `AnomalyScorer::score_path`, `finalize`.

## Problem statement

Given:
- A finalized graph `G` (nodes carry first-seen timestamps and
  observation counts; edges carry source/destination pair counts).
- A path `π = v₀ → v₁ → … → vₖ` produced by the DFS matcher
  (see [`dfs_temporal.md`](dfs_temporal.md)).
- A weight vector `w = (w₁, w₂, w₃, w₄, w₅)` with `wᵢ ≥ 0`.

Produce a **composite anomaly score** `S(π) ∈ [0, 1]` plus a component
breakdown. Higher score = more anomalous. The composite must be
monotone-friendly for downstream sorting and pagination.

## Components

All five components are normalized to `[0, 1]` before compositing.

### 1. Entity rarity (ER)

For a node `v` with observation count `freq(v)`:

    ER(v) = 1 − ln(freq(v)) / ln(max_freq)

Clamped to `[0, 1]`. The `ln` flattens heavy-tailed observation
distributions so a single very-popular node doesn't crush the rest.
When `max_freq = 1` (i.e., every node appears once), the formula
degenerates to 0/0; the implementation returns `0` in that case.

Per path: averaged over nodes.

    ER(π) = (1/|π|) · Σᵢ ER(vᵢ)

### 2. Edge rarity (EdgeR)

For a directed pair `(s, d)` with co-occurrence count `freq(s, d)`:

    EdgeR(s, d) = 1 − ln(freq(s, d)) / ln(max_pair_freq)

Per path: averaged over the `|π| − 1` edges.

### 3. Neighborhood concentration (NC)

Precomputed per-node during `finalize(&graph)` and cached. Intuitively:
nodes with few neighbors of a single dominant type score high; nodes
with diverse, populous neighborhoods score low. Encodes the classical
"dense anomalous subgraph" heuristic (Akoglu et al., ODDBall).

Per path: averaged over nodes.

### 4. Temporal novelty (TN)

Given the first-seen timestamp `τ_first(v)` and the graph-wide
`[τ_min, τ_max]` range:

    TN(v) = (τ_first(v) − τ_min) / (τ_max − τ_min)

More recently-first-seen entities score higher. When `τ_max = τ_min`
(degenerate single-timestamp graph), returns `0`.

Per path: averaged over nodes.

### 5. GNN threat (GNN)

If a GraphOS-APT GNN has scored nodes, `gnn_cache[v] ∈ [0, 1]` carries
the threat probability (pre-clamped to unit interval upstream). When
the cache is empty, this component is `0` — which combined with the
composite's weight renormalization means disabling ML scoring simply
redistributes weight across the other four components.

Per path: averaged over nodes.

## Composite

    S(π) = Σᵢ wᵢ · Cᵢ(π)  /  Σᵢ wᵢ

where `C = (ER, EdgeR, NC, TN, GNN)`. Clamped to `[0, 1]`.

The divisor renormalizes against the **active** weights. A caller that
sets `w₅ = 0` to disable the GNN component doesn't under-count: the
remaining four components just sum to a different constant in the
denominator. Equivalent to weighted arithmetic mean.

**Zero-weights guard.** When `Σwᵢ = 0`, the formula would be `0/0`.
The implementation returns `0.0` explicitly in that branch. This is
the invariant the `zero_weights_yield_zero_composite` property test
pins: a NaN here would propagate into heap/sort comparators downstream
and break strict-weak-ordering.

## Invariants (pinned by `anomaly_proptest.rs`)

1. **Bounded.** Every component `Cᵢ` ∈ `[0, 1]`; the composite `S` ∈ `[0, 1]`.
2. **No NaN / no Inf.** Even under adversarial inputs (tiny
   `log_max_freq`, identical timestamps, zero weights).
3. **Un-finalized ⇒ zeros.** If `finalize()` has not been called, the
   scorer returns `(0.0, ScoreBreakdown::default())` regardless of
   path. Callers can use `is_finalized()` as a gate.
4. **ER monotonicity.** For two nodes `a`, `b` with `freq(a) < freq(b)`
   and equal first-seen timestamps, `ER(a) ≥ ER(b)`. More observations
   ⇒ less rare ⇒ lower rarity.
5. **Composite stability.** Scaling all weights by the same positive
   constant leaves `S(π)` unchanged (the divisor cancels). The
   implementation does not rely on weight normalization at input —
   callers can pass any non-negative weights.

## Complexity

Let `k = |π|` (path length) and treat all cache lookups as `O(1)`
(`HashMap` / `ahash`).

- `score_path`: `O(k)` time, `O(1)` additional memory.
- `finalize`: `O(n + m)` to build the `log_max_freq`, `log_max_pair_freq`,
  `nc_cache`, and first-seen tables. Called once; result reused across
  all `score_path` calls for the same graph version.

## Known trade-offs

- **Averaging masks outliers.** A single extremely-rare node on a long
  path gets averaged down by common neighbors. Current design choice;
  alternatives (max-over-path, quantile) were considered but not
  adopted because they break the monotonicity property above in ways
  that complicate downstream pagination.
- **Log-normalization assumes Zipfian distributions.** For graphs where
  observation counts are roughly uniform, ER/EdgeR collapse to
  near-zero. The test fixtures in `sample_data/` are synthetic and do
  not exercise this regime; real production data consistently shows
  heavy-tailed distributions in both entity and edge frequencies.
- **First-seen timestamp can be manipulated.** An attacker who knows
  the scoring formula can backdate `τ_first(v)` on a new node to
  suppress TN. Mitigation lives outside this algorithm (ingestion
  should cross-check first-seen against an append-only audit log).

## References

- Akoglu, Tong, Koutra. "Graph-based anomaly detection and description:
  a survey." *Data Mining and Knowledge Discovery* 29(3), 2015 — for
  the rarity + neighborhood concentration framing.
- Chandola, Banerjee, Kumar. "Anomaly detection: a survey."
  *ACM Computing Surveys* 41(3), 2009 — for the normalization
  argument and bounded-score requirements.
- Akoglu, McGlohon, Faloutsos. "OddBall: Spotting Anomalies in Weighted
  Graphs." *PAKDD* 2010 — origin of the neighborhood-concentration
  heuristic.
