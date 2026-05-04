# DSL v1 — Formal semantics

- **Status**: stable (frozen grammar; v2 features behind feature flags)
- **Version**: v1.0
- **Date**: 2026-04-24
- **Authoritative implementation**: `platform/dsl/src/lib.rs` (parser), `platform/dsl/src/hypothesis.rs` (AST + predicate evaluator), `core/graph-engine/src/graph.rs::apply_aggregation` (HAVING/WITHIN runtime).
- **Citation target**: paper §3 (hypothesis language), architecture §08-hypothesis.

This document is the reference for what the DSL v1 grammar *means*. When
code and this document disagree, code wins — open a PR against both. v2
features (extension registries with strict-unknown mode, CEL-like
predicates, richer HAVING aggregations) remain experimental and are
explicitly out of scope here.

---

## 1. Grammar (BNF, informal)

```
hypothesis  := chain trailing? k_suffix?
chain       := entity (arrow entity)+
arrow       := '-[' rel_type predicates? ']->'
entity      := type binding? predicates?
type        := 'IP' | 'Host' | 'User' | 'Process' | 'File' | 'Domain'
             | 'Registry' | 'URL' | 'Service' | '*' | IDENT
rel_type    := 'Auth' | 'Connect' | 'Execute' | 'Read' | 'Write'
             | 'DNS' | 'Modify' | 'Spawn' | 'Delete' | '*' | IDENT
binding     := IDENT_LOWERCASE                    (* see §4 *)
predicates  := '{' pred (',' pred)* '}'
pred        := IDENT op value
op          := '=' | '!=' | '~' | 'in' | 'not' 'in'
value       := STRING | IDENT | '[' STRING (',' STRING)* ']'

trailing    := (having | within)+               (* order-free *)
having      := 'HAVING' 'count' '(' 'distinct' IDENT ')' cmp NUMBER
cmp         := '>=' | '>'
within      := 'WITHIN' NUMBER unit?
unit        := 's'|'sec'|'m'|'min'|'h'|'hr'|'d'|'day'|'w'|'week' ...

k_suffix    := '{' 'k' '=' NUMBER '}'            (* NUMBER >= 1 *)
```

**Lexical rules**
- `IDENT`: `[A-Za-z_][A-Za-z0-9_]*`.
- `STRING`: `"` *any byte except `"`* `"`. No escape sequences in v1.
- Whitespace is insignificant between tokens.
- `IDENT` unrecognized as a built-in type is accepted as `Other(name)`
  — the parser does not reject unknown type names (see §4 and §10).

---

## 2. Semantics of *match* — paths, not walks

A match against a hypothesis with `n` steps is an ordered sequence of
`n + 1` entities `v_0, v_1, ..., v_n` connected by `n` edges
`e_1, ..., e_n` such that:

1. **Type match** — `type(v_i)` matches the type declared for position
   `i` in the hypothesis (`*` / `Any` matches any type; `Other(x)`
   matches entities whose registered type name equals `x` or whose
   FFI tag is the wildcard sentinel — see §10).
2. **Relation match** — `relation_type(e_i)` matches the type declared
   on arrow `i` (`*` matches any).
3. **Predicate match** — every predicate attached to arrow `i` holds on
   the metadata map of `e_i`; every predicate attached to entity-slot
   `i` holds on the metadata map of `v_i`. Missing key semantics:
   positive ops (`=`, `~`, `in`) fail when the key is absent; negative
   ops (`!=`, `not in`) succeed when the key is absent. This mirrors
   SIEM expectations — "absence means not the value we're filtering
   against". See `Predicate::eval` in `hypothesis.rs`.
4. **Temporal monotonicity** — `timestamp(e_i) <= timestamp(e_{i+1})`
   for all `i < n`. Equal timestamps are allowed; they model the
   common case where correlated events share a second-resolution tick
   or arrive from the same log record.
5. **k-simplicity** — no entity `v` appears more than `k` times in the
   sequence, where `k = k_simplicity` (default `1`, i.e. simple paths
   in the graph-theoretic sense: no vertex repeats).

**Terminology.** v1 returns *paths under k-simplicity*:
- `k = 1` — simple paths. No repeated vertex.
- `k > 1` — trails / walks with bounded repetition. Still finite
  because the edge count is bounded by the hypothesis length.

The matcher never returns *walks* in the unbounded graph-theoretic
sense — a vertex can repeat at most `k` times by construction.

---

## 3. `WITHIN <duration>` — inclusive temporal window

`WITHIN N<unit>` is applied as a **post-match filter** on the set of
paths returned by the DFS/SIMD search. For each path, compute the
*edge-timestamp span*:

```
span(path) = max_ts(path) - min_ts(path)
```

where `min_ts`/`max_ts` iterate the path's edges. Paths with
`span > N_seconds` are dropped. Paths with `span == N_seconds` are
**kept** — the window is inclusive on both endpoints.

- `N_seconds` is computed from the unit suffix: `s`=1, `m`=60, `h`=3600,
  `d`=86400, `w`=604800. No unit defaults to seconds.
- `WITHIN 0s` is legal and keeps only paths whose edges share a single
  timestamp (span == 0).
- Paths with no edge timestamps (all zero) are treated as span = 0 and
  therefore **kept** regardless of the window. This preserves old
  fixtures that don't set per-edge timestamps.
- Only one `WITHIN` clause per hypothesis — a second occurrence is a
  parse error.

---

## 4. Bindings and `HAVING count(distinct X) >= N`

**Bindings** — an entity slot may declare an identifier that other
clauses can reference: `User u -[Auth]-> IP i`. Bindings are
lower-case-starting identifiers that:
- are **not** the name of a built-in entity type;
- are **not** a reserved keyword (`HAVING`, `WITHIN`);
- do not conflict with a subsequent arrow's relation token (the parser
  lexes by looking ahead for `-[`).

An extension-registered type with a lower-case name (e.g. `pod`) would
shadow a binding of the same name; the parser warns on this collision
via extension registry (F4.3, read-only in v1).

**HAVING** groups paths by their **first node** (the match anchor) and
retains a group only if *every* `HAVING` clause holds on that group:

```
keep(group) := forall agg in aggregations:
                   |{ col(path) : path ∈ group }| >= agg.min_distinct
```

where `col(path)` picks one entry from the path:
- `col = First`  → `path[0]` (same as group key — trivial but legal).
- `col = Last`   → `path[n]`.
- `col = Named(b)` → `path[idx]` where `idx` is the step index at
  which binding `b` was declared (`origin_binding` at step `k` → `k`;
  `dest_binding` at step `k` → `k+1`). An undeclared binding makes the
  clause always-fail (conservative — never a silent match).

**Operator normalisation.** `count(distinct col) > N` is rewritten to
`>= (N + 1)` at parse time. All subsequent logic treats HAVING
clauses as `>= min_distinct`.

**Identifier resolution priority.** When HAVING references `col_name`:
1. If any step declares a binding with that name → `Named(col_name)`.
2. Else if `col_name` is `FIRST` / `LAST` (case-insensitive) → that
   endpoint.
3. Else if it matches the first step's origin type → `First`.
4. Else if it matches the last step's dest type → `Last`.
5. Else — parse error.

---

## 5. Wildcards

- `*` as an entity type → `EntityType::Any` → matches any entity type
  at that position.
- `*` as a relation type → `RelationType::Any` → matches any relation
  type.
- Wildcards participate in k-simplicity normally (a wildcard slot can
  still "use up" a vertex visit).
- Unknown identifiers parse as `Other(name)`. For entity types, the
  FFI layer treats unregistered `Other` as the GM_ENTITY_ANY tag 254,
  i.e. a *de-facto* wildcard at runtime. This is a documented v1
  limitation (see `core/matcher-ffi/tests/safety_invariants.rs` —
  `unknown_other_entity_type_becomes_wildcard`). v2 will add a strict
  mode that rejects unknown names at parse.

---

## 6. Predicate evaluation

All predicates are evaluated against a `HashMap<String, String>`
(metadata). Rules:

| Op      | Present → result                              | Absent → result |
|---------|-----------------------------------------------|-----------------|
| `=`     | `metadata[key] == value`                      | `false`         |
| `!=`    | `metadata[key] != value`                      | `true`          |
| `~`     | `to_lower(metadata[key]).contains(to_lower(value))` | `false`   |
| `in`    | `metadata[key] ∈ values`                      | `false`         |
| `not in`| `metadata[key] ∉ values`                      | `true`          |

- `~` is **case-insensitive** substring (ASCII lowercase). This is a
  deliberate v1 choice — analysts typing `name ~ "certutil"` expect
  `CertUtil.exe` to match. Regex-style match is a v2 feature.
- Whitespace inside a value string is preserved literally; no
  collapsing.
- Predicate lists combine with logical AND — every predicate must hold.

---

## 7. `{k=N}` k-simplicity suffix

- Appears at the very end of the hypothesis, after any trailing
  clauses.
- `N >= 1`. `{k=0}` is a parse error.
- `N = 1` is the default (omitted suffix is equivalent to `{k=1}`).
- Affects DFS/SIMD search; not evaluated post-hoc.

---

## 8. Edge cases (pinned behavior)

- **Empty input** — parse error.
- **Single entity, no arrow** — parse error ("chain must have at least
  one step").
- **Unterminated string literal** — parse error at the opening quote
  position.
- **Empty `in []` list** — parse error.
- **Equal timestamps on consecutive edges** — match is allowed (§2,
  rule 4).
- **`WITHIN` with no unit** — interpreted as seconds.
- **Extension-registered type collides with a binding name** —
  type wins (no binding is produced). Document via parser warning
  (F4.3+).

---

## 9. What the format→parse→format idempotence property covers

`platform/dsl/tests/roundtrip.rs` asserts that
`format_hypothesis ∘ parse_dsl ∘ format_hypothesis` is idempotent over
the generated `Hypothesis` surface. A passing property is strong
evidence that:

- the grammar is **unambiguous**: every AST has one canonical rendering,
  and every rendering has one AST;
- the parser and formatter agree on whitespace, ordering, and predicate
  escape conventions;
- extending either side without extending the other is caught
  immediately (a new AST shape unsupported by the formatter becomes a
  generator-rejection; a formatter that emits un-reparseable output is
  a proptest failure).

---

## 10. Out of scope for v1

The following are explicitly *not* part of v1 semantics:

- Strict unknown-type rejection (v2 via extension registry strict mode).
- Regex-style predicate match (v2).
- Nested / Boolean predicate combinators (AND beyond comma, OR, NOT as
  prefix).
- HAVING aggregations other than `count(distinct ...)` (sum, avg,
  min/max, etc.).
- SIMD-carried metadata — hypotheses with any predicate transparently
  fall back to the DFS engine. This is an operational contract, not a
  grammar feature.

---

## 11. Test coverage map

| Claim                                | Test(s)                                                         |
|--------------------------------------|-----------------------------------------------------------------|
| format↔parse idempotence             | `platform/dsl/tests/roundtrip.rs`                               |
| Predicate eval (all 5 ops)           | `platform/dsl/tests/semantics_v1.rs`                            |
| Wildcard behavior                    | `platform/dsl/tests/semantics_v1.rs`                            |
| HAVING / WITHIN AST-level            | `platform/dsl/tests/semantics_v1.rs`                            |
| WITHIN runtime filtering             | `core/graph-engine/tests/aggregation.rs`                        |
| HAVING runtime grouping              | `core/graph-engine/tests/aggregation.rs`                        |
| Unknown Other → wildcard (FFI)       | `core/matcher-ffi/tests/safety_invariants.rs`                   |
| DSL↔catalog compatibility            | `core/graph-engine/tests/catalog_compatibility.rs`              |
