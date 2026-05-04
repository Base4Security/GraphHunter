//! DSL v1 — semantics tests (parser + AST level).
//!
//! Runtime tests for `WITHIN` / `HAVING` (where a graph is actually
//! walked) live in `core/graph-engine/tests/aggregation.rs` — they need
//! `GraphHunter` which this crate deliberately does not depend on.
//!
//! This file pins the parser-visible behavior documented in
//! `docs/spec/dsl-v1-semantics.md`. Each test names the §section of
//! that document it exercises so a spec change must land a matching
//! test change.
//!
//! The tests favor "pin the observable behavior of v1" over "exhaust
//! the parser". They are enumerated, named after the claim being
//! pinned, and split into positive / negative pairs where that makes
//! the intent clearer. Error-position assertions are intentionally
//! omitted — byte-offset stability of error messages is not a v1
//! guarantee and would invert the cost/benefit of this suite.

use std::collections::HashMap;

use graph_hunter_dsl::hypothesis::{AggColumn, Predicate};
use graph_hunter_dsl::parse_dsl;
use graph_hunter_dsl::types::{EntityType, RelationType};

// ---------------------------------------------------------------------
// §2 rule 3 — predicate evaluation: positive and negative op semantics,
// including the "absent key" asymmetry (positive fails, negative
// succeeds). Pins the SIEM-friendly default.
// ---------------------------------------------------------------------
#[test]
fn predicate_eval_positive_and_negative_ops() {
    let mut md = HashMap::new();
    md.insert("name".to_string(), "certutil.exe".to_string());
    md.insert("pid".to_string(), "42".to_string());

    // Eq: present+equal → true; present+unequal → false; absent → false.
    assert!(
        Predicate::Eq {
            key: "pid".into(),
            value: "42".into()
        }
        .eval(&md)
    );
    assert!(
        !Predicate::Eq {
            key: "pid".into(),
            value: "99".into()
        }
        .eval(&md)
    );
    assert!(
        !Predicate::Eq {
            key: "missing".into(),
            value: "x".into()
        }
        .eval(&md)
    );

    // Neq: absent → true (documented asymmetry).
    assert!(
        Predicate::Neq {
            key: "missing".into(),
            value: "x".into()
        }
        .eval(&md)
    );
    assert!(
        !Predicate::Neq {
            key: "pid".into(),
            value: "42".into()
        }
        .eval(&md)
    );

    // In / NotIn: same asymmetry.
    assert!(
        Predicate::In {
            key: "pid".into(),
            values: vec!["1".into(), "42".into()]
        }
        .eval(&md)
    );
    assert!(
        !Predicate::In {
            key: "missing".into(),
            values: vec!["x".into()]
        }
        .eval(&md)
    );
    assert!(
        Predicate::NotIn {
            key: "missing".into(),
            values: vec!["x".into()]
        }
        .eval(&md)
    );
}

// ---------------------------------------------------------------------
// §6 — the `~` (Match) operator is case-insensitive substring. Pinning
// this prevents a future "be strict" refactor from silently breaking
// every LOLBAS-style hypothesis in the catalog.
// ---------------------------------------------------------------------
#[test]
fn match_operator_is_case_insensitive_substring() {
    let mut md = HashMap::new();
    md.insert(
        "name".to_string(),
        "C:\\Windows\\System32\\CertUtil.exe".to_string(),
    );

    // Lowercased needle matches mixed-case haystack.
    assert!(
        Predicate::Match {
            key: "name".into(),
            value: "certutil".into()
        }
        .eval(&md)
    );
    // Uppercased needle also matches.
    assert!(
        Predicate::Match {
            key: "name".into(),
            value: "CERTUTIL".into()
        }
        .eval(&md)
    );
    // Non-substring fails.
    assert!(
        !Predicate::Match {
            key: "name".into(),
            value: "powershell".into()
        }
        .eval(&md)
    );
    // Absent key — positive op → false.
    assert!(
        !Predicate::Match {
            key: "name_missing".into(),
            value: "certutil".into()
        }
        .eval(&md)
    );
}

// ---------------------------------------------------------------------
// §5 — wildcards parse to Any on both entity and relation sides.
// Regression gate: a future "strict mode" should be gated by a feature
// flag, not silently change the default.
// ---------------------------------------------------------------------
#[test]
fn wildcards_parse_to_any() {
    let r = parse_dsl("* -[*]-> Process", None).unwrap();
    assert_eq!(r.hypothesis.steps.len(), 1);
    let s = &r.hypothesis.steps[0];
    assert_eq!(s.origin_type, EntityType::Any);
    assert_eq!(s.relation_type, RelationType::Any);
    assert_eq!(s.dest_type, EntityType::Process);
}

// ---------------------------------------------------------------------
// §3 — `WITHIN` parses to window_seconds with unit multiplication.
// `WITHIN 0s` is legal (§3 — pins paths with single-timestamp edges).
// `WITHIN` with no unit defaults to seconds.
// ---------------------------------------------------------------------
#[test]
fn within_clause_parses_and_multiplies_units() {
    // Hours.
    let h = parse_dsl("User -[Auth]-> Host WITHIN 2h", None).unwrap();
    assert_eq!(h.hypothesis.window_seconds, Some(7200));

    // Minutes.
    let m = parse_dsl("User -[Auth]-> Host WITHIN 30m", None).unwrap();
    assert_eq!(m.hypothesis.window_seconds, Some(1800));

    // Default unit = seconds.
    let s = parse_dsl("User -[Auth]-> Host WITHIN 45", None).unwrap();
    assert_eq!(s.hypothesis.window_seconds, Some(45));

    // Zero seconds is legal — pins the "same-tick paths only" use case.
    let z = parse_dsl("User -[Auth]-> Host WITHIN 0s", None).unwrap();
    assert_eq!(z.hypothesis.window_seconds, Some(0));
}

// ---------------------------------------------------------------------
// §3 — duplicate WITHIN is a parse error (at most one window per
// hypothesis). Negative test complementing the positive above.
// ---------------------------------------------------------------------
#[test]
fn duplicate_within_is_rejected() {
    let err = parse_dsl("User -[Auth]-> Host WITHIN 1h WITHIN 2h", None)
        .expect_err("two WITHIN clauses must not parse");
    assert!(
        err.message.to_ascii_lowercase().contains("within"),
        "error should mention WITHIN, got: {}",
        err.message
    );
}

// ---------------------------------------------------------------------
// §4 — HAVING operator normalisation: `count(distinct X) > N` is stored
// as `min_distinct = N + 1`. Pins the rewrite so the runtime always
// sees `>=`. Also pins that an undeclared column resolves to FIRST/LAST
// when it matches an endpoint type name (priority rule 3/4).
// ---------------------------------------------------------------------
#[test]
fn having_gt_rewrites_to_ge_plus_one() {
    let gt = parse_dsl("User -[Auth]-> Host HAVING count(distinct Host) > 3", None).unwrap();
    assert_eq!(gt.hypothesis.aggregations.len(), 1);
    let clause = &gt.hypothesis.aggregations[0];
    assert_eq!(clause.column, AggColumn::Last);
    assert_eq!(clause.min_distinct, 4, "> 3 should rewrite to >= 4");

    let ge = parse_dsl("User -[Auth]-> Host HAVING count(distinct Host) >= 3", None).unwrap();
    let clause = &ge.hypothesis.aggregations[0];
    assert_eq!(clause.min_distinct, 3);
}

// ---------------------------------------------------------------------
// §4 priority rule 1 — a declared binding wins over endpoint-type
// resolution. `User u` + `count(distinct u)` must produce Named("u"),
// NOT First, even though `u` looks like nothing in particular.
// ---------------------------------------------------------------------
#[test]
fn having_named_binding_resolves_to_step_position() {
    let h = parse_dsl(
        "User u -[Auth]-> Host h HAVING count(distinct h) >= 2",
        None,
    )
    .unwrap();
    let step = &h.hypothesis.steps[0];
    assert_eq!(step.origin_binding.as_deref(), Some("u"));
    assert_eq!(step.dest_binding.as_deref(), Some("h"));
    let clause = &h.hypothesis.aggregations[0];
    assert_eq!(clause.column, AggColumn::Named("h".into()));
}

// ---------------------------------------------------------------------
// §4 — HAVING referencing an undeclared column that is neither a
// binding nor an endpoint-type must parse-error. This is the
// "conservative fail" rule (never silently match).
// ---------------------------------------------------------------------
#[test]
fn having_unknown_column_is_rejected() {
    let err = parse_dsl(
        "User -[Auth]-> Host HAVING count(distinct Nothing) >= 2",
        None,
    )
    .expect_err("unknown HAVING column must be rejected");
    assert!(
        err.message.contains("Nothing"),
        "error should mention the bad column, got: {}",
        err.message
    );
}

// ---------------------------------------------------------------------
// §8 — empty input and single-entity (no arrow) are parse errors.
// Guards against accidentally accepting "User" as a hypothesis.
// ---------------------------------------------------------------------
#[test]
fn empty_and_single_entity_rejected() {
    assert!(parse_dsl("", None).is_err(), "empty string must not parse");
    assert!(
        parse_dsl("   ", None).is_err(),
        "whitespace-only must not parse"
    );
    assert!(
        parse_dsl("User", None).is_err(),
        "entity without arrow must not parse"
    );
}

// ---------------------------------------------------------------------
// §7 — k-simplicity default and explicit values. {k=0} is rejected.
// ---------------------------------------------------------------------
#[test]
fn k_simplicity_default_and_bounds() {
    let default = parse_dsl("User -[Auth]-> Host", None).unwrap();
    assert_eq!(default.hypothesis.k_simplicity, 1);

    let explicit = parse_dsl("User -[Auth]-> Host {k=3}", None).unwrap();
    assert_eq!(explicit.hypothesis.k_simplicity, 3);

    assert!(
        parse_dsl("User -[Auth]-> Host {k=0}", None).is_err(),
        "k=0 must be rejected"
    );
}

// ---------------------------------------------------------------------
// §3 + §4 — HAVING and WITHIN are order-free trailing clauses. Both
// orderings must parse to the same AST fields being populated.
// ---------------------------------------------------------------------
#[test]
fn having_and_within_are_order_free() {
    let a = parse_dsl(
        "User -[Auth]-> Host HAVING count(distinct Host) >= 2 WITHIN 1h",
        None,
    )
    .unwrap();
    let b = parse_dsl(
        "User -[Auth]-> Host WITHIN 1h HAVING count(distinct Host) >= 2",
        None,
    )
    .unwrap();

    assert_eq!(a.hypothesis.window_seconds, Some(3600));
    assert_eq!(b.hypothesis.window_seconds, Some(3600));
    assert_eq!(a.hypothesis.aggregations, b.hypothesis.aggregations);
}
