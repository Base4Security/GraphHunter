//! F3.2 — `format ∘ parse ∘ format` idempotence property.
//!
//! Over the subset of `Hypothesis` that the DSL text surface preserves
//! (types, relations, predicates, bindings, HAVING, WITHIN, k-simplicity),
//! formatting then re-parsing must yield a hypothesis whose re-formatted
//! DSL is byte-identical to the first rendering. This is the strongest
//! roundtrip claim without requiring structural `PartialEq` on
//! `Hypothesis`, and it catches parser/formatter drift (e.g. escaping
//! rules, predicate ordering) that unit tests rarely enumerate.
//!
//! F3 update (2026-04-24): bindings, `HAVING`, and `WITHIN` are now part
//! of the rendered surface and the generator space. See
//! `docs/spec/dsl-v1-semantics.md` for the grammar.
//!
//! Generator constraints that remain:
//! - `Other(_)` entity/relation names are excluded — they collide with
//!   binding lexing and with user-defined type resolution.
//! - Predicate keys are `[a-z][a-z0-9_]{0,7}` identifiers; values are
//!   ASCII letters/digits/spaces (no quotes, brackets, or operator bytes
//!   that would need escaping — the current formatter doesn't escape).
//! - Bindings are lowercase identifiers that cannot collide with
//!   built-in type names or reserved keywords.
//! - HAVING columns reference either an endpoint type or a binding
//!   we actually declared on a step (undeclared bindings would parse-
//!   error per §4 priority rule 5).

use graph_hunter_dsl::hypothesis::{AggClause, AggColumn, Hypothesis, HypothesisStep, Predicate};
use graph_hunter_dsl::types::{EntityType, RelationType};
use graph_hunter_dsl::{format_hypothesis, parse_dsl};
use proptest::prelude::*;

fn arb_entity_type() -> impl Strategy<Value = EntityType> {
    prop_oneof![
        Just(EntityType::IP),
        Just(EntityType::Host),
        Just(EntityType::User),
        Just(EntityType::Process),
        Just(EntityType::File),
        Just(EntityType::Domain),
        Just(EntityType::Registry),
        Just(EntityType::URL),
        Just(EntityType::Service),
        Just(EntityType::Any),
    ]
}

fn arb_relation_type() -> impl Strategy<Value = RelationType> {
    prop_oneof![
        Just(RelationType::Auth),
        Just(RelationType::Connect),
        Just(RelationType::Execute),
        Just(RelationType::Read),
        Just(RelationType::Write),
        Just(RelationType::DNS),
        Just(RelationType::Modify),
        Just(RelationType::Spawn),
        Just(RelationType::Delete),
        Just(RelationType::Any),
    ]
}

fn arb_pred_key() -> impl Strategy<Value = String> {
    "[a-z][a-z0-9_]{0,7}".prop_map(|s| s.to_string())
}

fn arb_pred_value() -> impl Strategy<Value = String> {
    "[a-zA-Z0-9 ]{1,12}".prop_map(|s| s.to_string())
}

fn arb_predicate() -> impl Strategy<Value = Predicate> {
    prop_oneof![
        (arb_pred_key(), arb_pred_value()).prop_map(|(key, value)| Predicate::Eq { key, value }),
        (arb_pred_key(), arb_pred_value()).prop_map(|(key, value)| Predicate::Neq { key, value }),
        (arb_pred_key(), arb_pred_value()).prop_map(|(key, value)| Predicate::Match { key, value }),
        (
            arb_pred_key(),
            prop::collection::vec(arb_pred_value(), 1..=3)
        )
            .prop_map(|(key, values)| Predicate::In { key, values }),
        (
            arb_pred_key(),
            prop::collection::vec(arb_pred_value(), 1..=3)
        )
            .prop_map(|(key, values)| Predicate::NotIn { key, values }),
    ]
}

/// Bindings are short lowercase identifiers drawn from a fixed pool
/// chosen to avoid: (a) keyword collisions (`in`, `not`), (b) any
/// built-in type name (all are CamelCase), (c) word-matches for
/// `HAVING` / `WITHIN` (uppercase keywords in the parser). The binding
/// slot is still optional — `None` exercises the no-binding lex path.
fn arb_binding() -> impl Strategy<Value = Option<String>> {
    prop_oneof![
        Just(None),
        Just(Some("u".to_string())),
        Just(Some("h".to_string())),
        Just(Some("p".to_string())),
        Just(Some("x".to_string())),
        Just(Some("y".to_string())),
        Just(Some("dst".to_string())),
    ]
}

fn arb_step() -> impl Strategy<Value = HypothesisStep> {
    (
        arb_entity_type(),
        arb_relation_type(),
        arb_entity_type(),
        prop::collection::vec(arb_predicate(), 0..=2),
        prop::collection::vec(arb_predicate(), 0..=2),
        arb_binding(),
        arb_binding(),
    )
        .prop_map(|(o, r, d, ep, dp, ob, db)| HypothesisStep {
            origin_type: o,
            relation_type: r,
            dest_type: d,
            edge_predicates: ep,
            dest_predicates: dp,
            origin_binding: ob,
            dest_binding: db,
        })
}

/// HAVING clauses only target endpoint positions (First / Last). The
/// formatter renders these as the `FIRST` / `LAST` literal keywords, so
/// they roundtrip unambiguously even when the chain's first and last
/// entity types coincide. `Named(b)` is NOT generated here because the
/// post-extraction `enforce_binding_consistency` step cannot guarantee
/// that a randomly named binding exists; the `semantics_v1` suite
/// exercises `Named` separately.
fn arb_agg() -> impl Strategy<Value = AggClause> {
    (
        prop_oneof![Just(AggColumn::First), Just(AggColumn::Last)],
        1usize..=8,
    )
        .prop_map(|(column, min_distinct)| AggClause {
            column,
            min_distinct,
        })
}

fn arb_window_seconds() -> impl Strategy<Value = Option<i64>> {
    prop_oneof![Just(None), (0i64..=86_400).prop_map(Some),]
}

fn arb_hypothesis() -> impl Strategy<Value = Hypothesis> {
    (
        prop::collection::vec(arb_step(), 1..=4),
        1usize..=5,
        prop::collection::vec(arb_agg(), 0..=2),
        arb_window_seconds(),
    )
        .prop_map(|(steps, k, aggregations, window_seconds)| {
            // Consecutive-step binding consistency: if step[i].dest has a
            // binding, step[i+1].origin either matches or is None. The
            // parser only ever records *one* binding per node slot
            // (origin_binding of step k+1 == dest_binding of step k when
            // both are written), so rendering divergent bindings on the
            // same physical node would be lossy. Normalise by copying
            // the dest_binding forward so the formatter's single output
            // round-trips cleanly.
            let mut steps = steps;
            for i in 0..steps.len().saturating_sub(1) {
                let prev_dest = steps[i].dest_binding.clone();
                steps[i + 1].origin_binding = prev_dest;
            }
            Hypothesis {
                name: "prop".to_string(),
                steps,
                k_simplicity: k,
                aggregations,
                window_seconds,
                shape: graph_hunter_dsl::hypothesis::HypothesisShape::default(),
            }
        })
}

proptest! {
    #![proptest_config(ProptestConfig {
        cases: 256,
        ..ProptestConfig::default()
    })]

    /// Core roundtrip: formatting, re-parsing, and re-formatting must
    /// produce the exact same DSL string. Any drift between format and
    /// parse (escape bugs, ordering changes, whitespace, missing predicate
    /// support) trips this property.
    #[test]
    fn format_parse_format_is_idempotent(h in arb_hypothesis()) {
        let s1 = format_hypothesis(&h);
        let parsed = parse_dsl(&s1, Some("prop"))
            .unwrap_or_else(|e| panic!("parse failed for {s1:?}: {e}"));
        let s2 = format_hypothesis(&parsed.hypothesis);
        prop_assert_eq!(s1, s2);
    }

    /// Semantic structural check: parsed hypothesis must have the same
    /// step count and k-simplicity as the input. Type-level equality is
    /// implied by the idempotence property above, but counting steps
    /// catches parser off-by-one bugs that could re-format identically.
    #[test]
    fn parsed_structure_matches_input(h in arb_hypothesis()) {
        let s = format_hypothesis(&h);
        let parsed = parse_dsl(&s, Some("prop"))
            .unwrap_or_else(|e| panic!("parse failed for {s:?}: {e}"));
        prop_assert_eq!(parsed.hypothesis.steps.len(), h.steps.len());
        prop_assert_eq!(parsed.hypothesis.k_simplicity, h.k_simplicity);
    }
}
