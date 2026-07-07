//! Invariant checker (M2 — Win 2).
//!
//! A set of first-order predicates over the in-memory graph that every
//! canonical mapping is expected to preserve. This crate ships the
//! runner and the predicate definitions; per-predicate logic lives in
//! [`predicates`]. The MCP/HTTP surface in `graph_hunter_api` wraps
//! [`check_invariants`] with dataset filtering.
//!
//! The predicates shipped in M2 D1:
//!
//! * **P1 Causal monotonicity** — if `B.source == A.dest`, then
//!   `B.timestamp >= A.timestamp`. Catches mapping bugs that invert
//!   parent/child order.
//! * **P3 Identity coherence** — no relation may have `source == dest`
//!   at the exact same timestamp, unless the rel_type is [`RelationType::Any`]
//!   (the wildcard used by hypothesis DSL, not a real emitted edge).
//! * **P4 Referential closure** — every relation's `source_id` and
//!   `dest_id` must resolve to an existing entity in the same dataset
//!   (or in any dataset, for global checks).
//!
//! **Not yet shipped in this D1 slice:**
//!
//! * P2 type-shape plausibility (D2 — `shape_rules.yaml`)
//! * P5 rarity-vs-degree sanity (stretch, gated on edge count)
//! * Treewidth estimate (D3 — `invariants::treewidth`)

use serde::{Deserialize, Serialize};

use crate::entity::Entity;
use crate::relation::Relation;

pub mod predicates;
pub mod shape_catalog;
pub mod treewidth;

pub use shape_catalog::{ShapeCatalog, default_shape_catalog};
pub use treewidth::estimate_treewidth;

/// The id of a predicate. Kept as a strongly typed enum rather than a
/// free-form string so downstream surfaces (MCP schema, Prometheus
/// labels) can enumerate them.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum PredicateId {
    /// Causal monotonicity — timestamps along any source→dest chain are
    /// non-decreasing.
    P1CausalMonotonicity,
    /// Type-shape plausibility — `(src_type, rel_type, dst_type)` must
    /// appear in the shape catalog.
    P2TypeShapePlausibility,
    /// Identity coherence — no self-loop at the same timestamp for a
    /// concrete rel_type.
    P3IdentityCoherence,
    /// Referential closure — every relation endpoint resolves to an
    /// entity in the checked scope.
    P4ReferentialClosure,
    /// Rarity-vs-degree sanity — rarity_score ~ inverse of degree_score
    /// within a 5% margin on graphs with >= 1000 edges.
    P5RaritySanity,
}

impl PredicateId {
    pub fn as_str(&self) -> &'static str {
        match self {
            PredicateId::P1CausalMonotonicity => "P1_causal_monotonicity",
            PredicateId::P2TypeShapePlausibility => "P2_type_shape_plausibility",
            PredicateId::P3IdentityCoherence => "P3_identity_coherence",
            PredicateId::P4ReferentialClosure => "P4_referential_closure",
            PredicateId::P5RaritySanity => "P5_rarity_sanity",
        }
    }
}

/// An observed violation — kept as structured data (not strings) so the
/// UI badge and the MCP tool can format consistently.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct Violation {
    pub predicate: PredicateId,
    /// Human-readable explanation of what was violated.
    pub reason: String,
    /// Source relation id-pair (if applicable). Format: "{src} -rel-> {dst}".
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub relation_label: Option<String>,
    /// Timestamp of the violating relation, when there is one canonical
    /// timestamp to report.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub timestamp: Option<i64>,
    /// The dataset the violating triple came from (for scoping badges).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dataset_id: Option<String>,
}

/// Per-predicate pass/fail summary, with a capped sample of violations.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct PredicateResult {
    pub predicate: PredicateId,
    pub passed: bool,
    pub checked: usize,
    pub violated: usize,
    /// Bounded sample of violations; default cap is 16 per predicate.
    pub samples: Vec<Violation>,
    /// `None` when the predicate was skipped (e.g. P5 with < 1000 edges).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub skipped_reason: Option<String>,
}

impl PredicateResult {
    pub fn skipped(predicate: PredicateId, reason: impl Into<String>) -> Self {
        Self {
            predicate,
            passed: true,
            checked: 0,
            violated: 0,
            samples: Vec::new(),
            skipped_reason: Some(reason.into()),
        }
    }
}

/// Aggregate report — the type returned by `check_invariants`.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct InvariantReport {
    /// Scope this run was evaluated against.
    pub scope: Scope,
    /// Entity count in scope.
    pub entity_count: usize,
    /// Relation count in scope.
    pub relation_count: usize,
    /// Per-predicate results in the order they were evaluated.
    pub results: Vec<PredicateResult>,
    /// Treewidth estimate for the quotient graph (populated in D3).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub treewidth_estimate: Option<TreewidthEstimate>,
}

impl InvariantReport {
    pub fn all_passed(&self) -> bool {
        self.results.iter().all(|r| r.passed)
    }

    pub fn total_violations(&self) -> usize {
        self.results.iter().map(|r| r.violated).sum()
    }
}

/// Scope of an invariant run — either a single dataset or everything in
/// the session.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case", tag = "kind", content = "dataset_id")]
pub enum Scope {
    Session,
    Dataset(String),
}

/// Treewidth estimate — populated by [`treewidth::estimate_treewidth`]
/// in D3. Kept here as a stub now so the report shape is stable across
/// the three D1/D2/D3 drops.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct TreewidthEstimate {
    pub value: usize,
    /// Method tag — non-negotiable per the plan. Always documents whether
    /// the number is exact or approximate.
    pub method: String,
    pub quotient_node_count: usize,
    pub quotient_edge_count: usize,
}

/// Max violations kept per predicate in the report. Keeps the MCP
/// payload bounded.
pub const DEFAULT_SAMPLE_CAP: usize = 16;

/// Run every shipped predicate against `(entities, relations)` filtered
/// to `scope`. Returns a structured report; never errors.
pub fn check_invariants(
    entities: &[Entity],
    relations: &[Relation],
    scope: Scope,
) -> InvariantReport {
    // Filter to scope once so each predicate sees the same view.
    let (scoped_entities, scoped_relations) = match &scope {
        Scope::Session => (entities.to_vec(), relations.to_vec()),
        Scope::Dataset(target) => {
            let e = entities
                .iter()
                .filter(|e| e.dataset_id.as_deref() == Some(target.as_str()))
                .cloned()
                .collect::<Vec<_>>();
            let r = relations
                .iter()
                .filter(|r| r.dataset_id.as_deref() == Some(target.as_str()))
                .cloned()
                .collect::<Vec<_>>();
            (e, r)
        }
    };

    let catalog = default_shape_catalog();

    let mut results = Vec::new();
    results.push(predicates::check_p1_causal_monotonicity(
        &scoped_relations,
        &scope,
        DEFAULT_SAMPLE_CAP,
    ));
    results.push(predicates::check_p2_type_shape_plausibility(
        &scoped_entities,
        &scoped_relations,
        &scope,
        catalog,
        DEFAULT_SAMPLE_CAP,
    ));
    results.push(predicates::check_p3_identity_coherence(
        &scoped_relations,
        &scope,
        Some(catalog),
        DEFAULT_SAMPLE_CAP,
    ));
    results.push(predicates::check_p4_referential_closure(
        &scoped_entities,
        &scoped_relations,
        &scope,
        DEFAULT_SAMPLE_CAP,
    ));
    // P5 comes later; skipped with reason.
    results.push(PredicateResult::skipped(
        PredicateId::P5RaritySanity,
        "pending: rarity vs degree regression (deferred)",
    ));

    let tw = estimate_treewidth(&scoped_entities, &scoped_relations);

    InvariantReport {
        scope,
        entity_count: scoped_entities.len(),
        relation_count: scoped_relations.len(),
        results,
        treewidth_estimate: Some(tw),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{EntityType, RelationType};

    fn ent(id: &str, t: EntityType, dataset: Option<&str>) -> Entity {
        let mut e = Entity::new(id, t);
        if let Some(d) = dataset {
            e.dataset_id = Some(std::sync::Arc::from(d));
        }
        e
    }

    fn rel(src: &str, dst: &str, rt: RelationType, ts: i64, dataset: Option<&str>) -> Relation {
        let mut r = Relation::new(src, dst, rt, ts);
        if let Some(d) = dataset {
            r.dataset_id = Some(std::sync::Arc::from(d));
        }
        r
    }

    #[test]
    fn clean_graph_passes_every_shipped_predicate() {
        let entities = vec![
            ent("alice", EntityType::User, Some("dsA")),
            ent("dc-01", EntityType::Host, Some("dsA")),
            ent("cmd.exe", EntityType::Process, Some("dsA")),
            ent("whoami.exe", EntityType::Process, Some("dsA")),
        ];
        let relations = vec![
            rel(
                "alice",
                "dc-01",
                RelationType::Auth,
                1_700_000_000,
                Some("dsA"),
            ),
            rel(
                "alice",
                "cmd.exe",
                RelationType::Execute,
                1_700_000_001,
                Some("dsA"),
            ),
            rel(
                "cmd.exe",
                "whoami.exe",
                RelationType::Spawn,
                1_700_000_100,
                Some("dsA"),
            ),
        ];

        let report = check_invariants(&entities, &relations, Scope::Session);
        assert!(
            report.all_passed(),
            "clean graph should pass all predicates, got: {:?}",
            report.results
        );
        assert_eq!(report.entity_count, 4);
        assert_eq!(report.relation_count, 3);
    }

    #[test]
    fn scope_filter_restricts_to_named_dataset() {
        let entities = vec![
            ent("a", EntityType::User, Some("dsA")),
            ent("b", EntityType::Host, Some("dsA")),
            ent("c", EntityType::User, Some("dsB")),
        ];
        let relations = vec![
            rel("a", "b", RelationType::Auth, 1, Some("dsA")),
            rel("c", "missing", RelationType::Auth, 2, Some("dsB")), // P4 break in dsB only
        ];

        let report_a = check_invariants(&entities, &relations, Scope::Dataset("dsA".into()));
        assert!(report_a.all_passed(), "dsA is clean");
        assert_eq!(report_a.relation_count, 1);

        let report_b = check_invariants(&entities, &relations, Scope::Dataset("dsB".into()));
        assert!(!report_b.all_passed(), "dsB has a P4 violation");
        let p4 = report_b
            .results
            .iter()
            .find(|r| r.predicate == PredicateId::P4ReferentialClosure)
            .unwrap();
        assert_eq!(p4.violated, 1);
    }

    #[test]
    fn report_shape_lists_every_predicate_in_order() {
        let report = check_invariants(&[], &[], Scope::Session);
        let ids: Vec<PredicateId> = report.results.iter().map(|r| r.predicate).collect();
        assert_eq!(
            ids,
            vec![
                PredicateId::P1CausalMonotonicity,
                PredicateId::P2TypeShapePlausibility,
                PredicateId::P3IdentityCoherence,
                PredicateId::P4ReferentialClosure,
                PredicateId::P5RaritySanity,
            ]
        );
    }
}
