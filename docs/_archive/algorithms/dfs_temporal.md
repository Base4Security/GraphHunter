# DFS with temporal causality

**Implemented in:** `core/graph-engine/src/graph.rs` — `search_temporal_pattern`, `naive_dfs_recurse`, `verify_path_matches`.

## Problem statement

Given:
- A directed, labeled, time-stamped graph `G = (V, E)` where every edge
  carries an entity-type label on each endpoint, a relation-type label,
  and a timestamp `t ∈ ℤ`.
- A hypothesis `H = (s₁, s₂, …, sₖ)` — an ordered sequence of steps,
  each step `sᵢ = (origin_type, relation_type, dest_type, predicates)`.
- An optional time window `[t_start, t_end]`.
- A maximum result count `cap`.

Find: the set of node paths `π = v₀ → v₁ → … → vₖ` such that

1. **Type chain.** `type(vᵢ₋₁) = sᵢ.origin_type` and `type(vᵢ) = sᵢ.dest_type`
   for every `i ∈ [1..k]`. A wildcard type `Any` matches everything.
2. **Relation-type match.** There exists an edge `(vᵢ₋₁, vᵢ, rel, tᵢ) ∈ E`
   with `rel = sᵢ.relation_type` (or `sᵢ.relation_type = Any`).
3. **Temporal causality.** `t₁ ≤ t₂ ≤ … ≤ tₖ`. Edges are traversed in
   non-decreasing timestamp order.
4. **Time-window bound.** If `[t_start, t_end]` is set, every `tᵢ`
   lies in that interval.
5. **k-simplicity.** `v₀, v₁, …, vₖ` are all distinct (no node repeats
   within one path). This is the default; higher `k_simplicity` values
   relax the constraint (out of scope for this doc).
6. **Predicate match.** Edge and destination metadata must satisfy
   `sᵢ.edge_predicates` and `sᵢ.dest_predicates`. Evaluated lazily
   per-edge during traversal.

Return at most `cap` such paths (implementation-defined which subset
when more exist; a truncation flag signals the overflow).

## Algorithm

Depth-first search with backtracking, parameterized by the current
hypothesis step index. Equivalent to Cormen, Leiserson, Rivest, Stein
*Introduction to Algorithms* §22.3 (DFS) extended with:

- a **pattern pointer** that advances by one step per edge taken;
- a **time-guard** that refuses an edge whose timestamp violates
  causality or the window bound;
- **predicate evaluation** at the edge and destination before recursion.

Pseudocode:

```
dfs(v, i, path, visited):
    if i == k:           # matched every step → emit
        emit(path)
        return
    step = H[i]
    for edge (v, u, rel, t) in edges_from(v):
        if not compatible(edge, step): continue
        if u in visited and k_simplicity == 1: continue
        if path non-empty and t < last_edge_time: continue   # causality
        if window set and t ∉ [t_start, t_end]: continue
        push u onto path, mark visited[u]
        dfs(u, i+1, path, visited)
        pop, unmark
```

`start_sids` is the set of nodes whose type matches `H[0].origin_type`
(or all nodes if `Any`). The driver calls `dfs` on each start node with
`path = [v]`, `i = 0`.

## Complexity

Let `n = |V|`, `m = |E|`, `k = |H|`, `b = maxᵥ deg_out(v)`.

- **Worst case:** `O(n · b^k)` time, `O(k)` stack depth, `O(n)` visited-set memory.
  Reached when every edge matches every step type and causality never
  prunes (e.g. a star graph with monotone timestamps from the center).
- **Typical case:** The type filter and causality cut the effective
  branching factor to `b' ≪ b`. On the `User-Auth-IP` benchmark at
  `n = 10_000` the observed cost is ~15 ms — consistent with
  `b' · k ≈ 30` edge visits per start node.
- **Early termination:** `search_temporal_pattern` stops enumerating
  once `results.len() >= cap`, capping wall-time at the cost of
  result completeness. Callers receive a `truncated: bool` flag.

## Invariants (must hold for every call)

1. `hypothesis.validate()` runs before traversal — guarantees `k ≥ 1`
   and chain continuity (`sᵢ.dest_type = sᵢ₊₁.origin_type`).
2. The `visited` set is populated and popped in LIFO order; every
   `insert` is matched by a `remove` along the backtrack path.
3. No path in the result set contains a cycle (k-simplicity = 1).
4. Every emitted path has length exactly `k + 1`.
5. `nodes_visited` counter is monotone — never decremented — so the
   caller can use it as a cost proxy without worrying about reuse.

## Pruning optimizations (in effect today)

- **Edge-list pre-sort** by timestamp (`sort_edges_by_timestamp`) lets
  `get_relations_by_sid` return edges in temporal order, so the first
  edge that violates causality terminates the per-node inner loop
  early (`break` instead of `continue`). Not currently implemented as
  an early-break — see `TODO`s in `search_temporal_pattern`.
- **Type-filtered start set.** The `start_sids` computation avoids
  invoking DFS from nodes whose type can't match step 0.
- **Aggregation / deduplication.** Post-processed in
  `apply_aggregation`; not part of the traversal invariants.

## SIMD fallback contract

`core/matcher-ffi::search_temporal_pattern_simd` is intended to return
the same result set as `search_temporal_pattern` under the constraints
it supports (no predicates, built-in entity/relation types only). The
equivalence is pinned by the property test
`core/matcher-ffi/tests/equivalence_proptest.rs` (F3.6). Any divergence
is a bug in one of the two implementations, not a feature.

## References

- Cormen, Leiserson, Rivest, Stein. *Introduction to Algorithms*,
  3rd ed. §22.3 "Depth-first search." MIT Press, 2009.
- Tarjan. "Depth-first search and linear graph algorithms." *SIAM J.
  Comput.* 1(2), 1972 — for the backtracking complexity analysis.
- Fan, Li, Ma, Wang, Wu. "Graph Pattern Matching: From Intractable to
  Polynomial Time." *VLDB* 2010 — for the type-labeled pattern
  extension.
