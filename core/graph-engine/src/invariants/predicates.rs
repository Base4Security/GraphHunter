//! Concrete predicate implementations for the invariant checker. Each
//! function returns a [`PredicateResult`] shaped so `InvariantReport`
//! can fold them into a uniform output.

use std::collections::{HashMap, HashSet};

use crate::entity::Entity;
use crate::relation::Relation;
use crate::types::{EntityType, RelationType};

use super::shape_catalog::ShapeCatalog;
use super::{DEFAULT_SAMPLE_CAP, PredicateId, PredicateResult, Scope, Violation};

fn label(r: &Relation) -> String {
    format!("{} -{:?}-> {}", r.source_id, r.rel_type, r.dest_id)
}

fn scope_dataset_filter(scope: &Scope, rel: &Relation) -> bool {
    match scope {
        Scope::Session => true,
        Scope::Dataset(target) => rel.dataset_id.as_deref() == Some(target.as_str()),
    }
}

fn dataset_of(r: &Relation) -> Option<String> {
    r.dataset_id.as_deref().map(|s| s.to_string())
}

/// **P1 Causal monotonicity.**
///
/// For every ordered pair of relations `(A, B)` such that
/// `A.dest_id == B.source_id`, we expect `B.timestamp >= A.timestamp`
/// — i.e. an entity cannot *emit* an outgoing edge before it has *received*
/// an incoming edge that brings it into existence. This holds for
/// causally-typed chains (Auth, Execute, Spawn, Write, Modify, Connect,
/// DNS) and is a first-order invariant over the edge set.
///
/// Algorithm: group relations by their `source_id`; for each source,
/// compare every incoming edge's timestamp against every outgoing
/// edge's timestamp. We surface up to `cap` concrete (A, B) pairs and
/// flag the pair by `B`'s label (the emitter that produced an edge
/// too early).
pub fn check_p1_causal_monotonicity(
    relations: &[Relation],
    scope: &Scope,
    cap: usize,
) -> PredicateResult {
    let mut checked: usize = 0;
    let mut violated: usize = 0;
    let mut samples: Vec<Violation> = Vec::new();

    // Precompute per-node earliest incoming timestamp. `min_incoming[id]`
    // is the earliest moment that node `id` was observed as the *dest*
    // of any edge in scope.
    let mut min_incoming: HashMap<&str, i64> = HashMap::new();
    for r in relations.iter().filter(|r| scope_dataset_filter(scope, r)) {
        let entry = min_incoming
            .entry(r.dest_id.as_str())
            .or_insert(r.timestamp);
        if r.timestamp < *entry {
            *entry = r.timestamp;
        }
    }

    // For every outgoing edge, check against the source's earliest
    // incoming timestamp.
    for r in relations.iter().filter(|r| scope_dataset_filter(scope, r)) {
        if let Some(&t_in) = min_incoming.get(r.source_id.as_str()) {
            checked += 1;
            if r.timestamp < t_in {
                violated += 1;
                if samples.len() < cap.min(DEFAULT_SAMPLE_CAP) {
                    samples.push(Violation {
                        predicate: PredicateId::P1CausalMonotonicity,
                        reason: format!(
                            "outgoing edge at ts={} precedes earliest incoming edge at ts={} for source {}",
                            r.timestamp, t_in, r.source_id
                        ),
                        relation_label: Some(label(r)),
                        timestamp: Some(r.timestamp),
                        dataset_id: dataset_of(r),
                    });
                }
            }
        }
    }

    PredicateResult {
        predicate: PredicateId::P1CausalMonotonicity,
        passed: violated == 0,
        checked,
        violated,
        samples,
        skipped_reason: None,
    }
}

/// **P2 Type-shape plausibility.**
///
/// Every relation's `(src_type, rel_type, dst_type)` triple must appear
/// in the shape catalog. User-defined rel_types (`RelationType::Other`)
/// and the DSL wildcard `RelationType::Any` are exempt — the catalog
/// targets only the concrete shipped relations. Entity types marked as
/// `Any` or `Other(_)` are also passed through.
///
/// Requires the entity list so each relation endpoint's type can be
/// resolved; relations whose endpoints are not present in scope are
/// skipped (that violation is P4's job, not P2's).
pub fn check_p2_type_shape_plausibility(
    entities: &[Entity],
    relations: &[Relation],
    scope: &Scope,
    catalog: &ShapeCatalog,
    cap: usize,
) -> PredicateResult {
    let mut checked: usize = 0;
    let mut violated: usize = 0;
    let mut samples: Vec<Violation> = Vec::new();

    // One pass over entities to build id → type map. Scope filtering
    // was already done in the caller.
    let type_of: HashMap<&str, &EntityType> = entities
        .iter()
        .map(|e| (e.id.as_str(), &e.entity_type))
        .collect();

    for r in relations.iter().filter(|r| scope_dataset_filter(scope, r)) {
        let (Some(&src_t), Some(&dst_t)) = (
            type_of.get(r.source_id.as_str()),
            type_of.get(r.dest_id.as_str()),
        ) else {
            // Endpoint missing — P4 will fire. P2 can't evaluate.
            continue;
        };

        checked += 1;

        if ShapeCatalog::rel_type_is_free(&r.rel_type)
            || ShapeCatalog::entity_type_is_free(src_t)
            || ShapeCatalog::entity_type_is_free(dst_t)
        {
            continue;
        }

        // Self-loops are checked as singletons.
        if r.source_id == r.dest_id {
            if !catalog.has_singleton(src_t, &r.rel_type) {
                violated += 1;
                if samples.len() < cap.min(DEFAULT_SAMPLE_CAP) {
                    samples.push(Violation {
                        predicate: PredicateId::P2TypeShapePlausibility,
                        reason: format!(
                            "self-loop shape {}×{:?} not in singleton catalog",
                            src_t, r.rel_type
                        ),
                        relation_label: Some(label(r)),
                        timestamp: Some(r.timestamp),
                        dataset_id: dataset_of(r),
                    });
                }
            }
            continue;
        }

        if !catalog.has_rule(src_t, &r.rel_type, dst_t) {
            violated += 1;
            if samples.len() < cap.min(DEFAULT_SAMPLE_CAP) {
                samples.push(Violation {
                    predicate: PredicateId::P2TypeShapePlausibility,
                    reason: format!("shape {}-{:?}->{} not in catalog", src_t, r.rel_type, dst_t),
                    relation_label: Some(label(r)),
                    timestamp: Some(r.timestamp),
                    dataset_id: dataset_of(r),
                });
            }
        }
    }

    PredicateResult {
        predicate: PredicateId::P2TypeShapePlausibility,
        passed: violated == 0,
        checked,
        violated,
        samples,
        skipped_reason: None,
    }
}

/// **P3 Identity coherence.**
///
/// No relation may have `source_id == dest_id` at the same timestamp
/// unless either (a) `rel_type == RelationType::Any` (hypothesis DSL
/// wildcard, never emitted by parsers) or (b) the `(entity_type, rel_type)`
/// pair is whitelisted as a legitimate singleton in the shape catalog
/// (the generic parser's fallback for rows that carry only one entity
/// field). Self-loops outside both exemptions typically indicate a
/// mapping bug where a field was wired to both source and dest roles.
///
/// When `catalog` is `None`, only the `Any` exemption applies — useful
/// for tests and MCP inputs that want the stricter original rule.
pub fn check_p3_identity_coherence(
    relations: &[Relation],
    scope: &Scope,
    catalog: Option<&ShapeCatalog>,
    cap: usize,
) -> PredicateResult {
    let mut checked: usize = 0;
    let mut violated: usize = 0;
    let mut samples: Vec<Violation> = Vec::new();

    for r in relations.iter().filter(|r| scope_dataset_filter(scope, r)) {
        checked += 1;

        if r.source_id != r.dest_id || matches!(r.rel_type, RelationType::Any) {
            continue;
        }

        // We can't resolve the entity type here without the entity list,
        // so singleton whitelisting keys on (rel_type) alone via the
        // catalog's rel-set. A tight "type-scoped" pass is P2's job.
        let allowed_as_singleton = catalog
            .map(|c| {
                // If any singleton uses this rel_type, accept. The type
                // check happens in P2.
                [
                    &EntityType::Host,
                    &EntityType::Process,
                    &EntityType::User,
                    &EntityType::IP,
                    &EntityType::Domain,
                    &EntityType::File,
                    &EntityType::URL,
                    &EntityType::Registry,
                ]
                .iter()
                .any(|t| c.has_singleton(t, &r.rel_type))
            })
            .unwrap_or(false);

        if allowed_as_singleton {
            continue;
        }

        violated += 1;
        if samples.len() < cap.min(DEFAULT_SAMPLE_CAP) {
            samples.push(Violation {
                predicate: PredicateId::P3IdentityCoherence,
                reason: format!(
                    "self-loop {} with concrete rel_type {:?} at ts={}",
                    r.source_id, r.rel_type, r.timestamp
                ),
                relation_label: Some(label(r)),
                timestamp: Some(r.timestamp),
                dataset_id: dataset_of(r),
            });
        }
    }

    PredicateResult {
        predicate: PredicateId::P3IdentityCoherence,
        passed: violated == 0,
        checked,
        violated,
        samples,
        skipped_reason: None,
    }
}

/// **P4 Referential closure.**
///
/// Every relation's `source_id` and `dest_id` must resolve to an entity
/// in the same scope. When `scope = Session` we accept any dataset;
/// when `scope = Dataset(d)` we only accept entities whose
/// `dataset_id == d`. Parse bugs that drop the source-or-dest entity
/// while keeping the edge (or that misspell identifiers) show up here.
pub fn check_p4_referential_closure(
    entities: &[Entity],
    relations: &[Relation],
    scope: &Scope,
    cap: usize,
) -> PredicateResult {
    let mut checked: usize = 0;
    let mut violated: usize = 0;
    let mut samples: Vec<Violation> = Vec::new();

    // Build an id set per scope.
    let entity_ids: HashSet<&str> = match scope {
        Scope::Session => entities.iter().map(|e| e.id.as_str()).collect(),
        Scope::Dataset(target) => entities
            .iter()
            .filter(|e| e.dataset_id.as_deref() == Some(target.as_str()))
            .map(|e| e.id.as_str())
            .collect(),
    };

    for r in relations.iter().filter(|r| scope_dataset_filter(scope, r)) {
        checked += 1;
        let missing_src = !entity_ids.contains(r.source_id.as_str());
        let missing_dst = !entity_ids.contains(r.dest_id.as_str());
        if missing_src || missing_dst {
            violated += 1;
            if samples.len() < cap.min(DEFAULT_SAMPLE_CAP) {
                let which = match (missing_src, missing_dst) {
                    (true, true) => "source and dest",
                    (true, false) => "source",
                    (false, true) => "dest",
                    (false, false) => unreachable!(),
                };
                samples.push(Violation {
                    predicate: PredicateId::P4ReferentialClosure,
                    reason: format!(
                        "dangling {}: {} -> {} at ts={}",
                        which, r.source_id, r.dest_id, r.timestamp
                    ),
                    relation_label: Some(label(r)),
                    timestamp: Some(r.timestamp),
                    dataset_id: dataset_of(r),
                });
            }
        }
    }

    PredicateResult {
        predicate: PredicateId::P4ReferentialClosure,
        passed: violated == 0,
        checked,
        violated,
        samples,
        skipped_reason: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::EntityType;

    fn ent(id: &str, t: EntityType) -> Entity {
        Entity::new(id, t)
    }

    fn rel(src: &str, dst: &str, rt: RelationType, ts: i64) -> Relation {
        Relation::new(src, dst, rt, ts)
    }

    // ──────────────────────────── P1 ────────────────────────────

    #[test]
    fn p1_detects_outgoing_before_incoming() {
        // cmd.exe was spawned at t=10 by explorer.exe, but according to
        // the bad mapping also "wrote" a file at t=5 — before it even
        // existed.
        let relations = vec![
            rel("explorer.exe", "cmd.exe", RelationType::Spawn, 10),
            rel("cmd.exe", "C:/loot.dat", RelationType::Write, 5),
        ];
        let result = check_p1_causal_monotonicity(&relations, &Scope::Session, 8);
        assert!(!result.passed, "P1 must fail on this fixture");
        assert_eq!(result.violated, 1);
        let s = &result.samples[0];
        assert_eq!(s.predicate, PredicateId::P1CausalMonotonicity);
        assert_eq!(s.timestamp, Some(5));
        assert!(s.reason.contains("precedes earliest incoming edge"));
    }

    #[test]
    fn p1_passes_on_non_decreasing_chain() {
        let relations = vec![
            rel("explorer.exe", "cmd.exe", RelationType::Spawn, 10),
            rel("cmd.exe", "whoami.exe", RelationType::Spawn, 20),
            rel("whoami.exe", "C:/out.txt", RelationType::Write, 30),
        ];
        let result = check_p1_causal_monotonicity(&relations, &Scope::Session, 8);
        assert!(result.passed);
        assert_eq!(result.violated, 0);
    }

    #[test]
    fn p1_leaves_roots_unchecked() {
        // alice is a source with no incoming — no constraint can be
        // violated, and the checker should not panic.
        let relations = vec![rel("alice", "dc-01", RelationType::Auth, 7)];
        let result = check_p1_causal_monotonicity(&relations, &Scope::Session, 8);
        assert!(result.passed);
        // 0 checked because "alice" has no recorded min_incoming.
        assert_eq!(result.checked, 0);
    }

    // ──────────────────────────── P3 ────────────────────────────

    #[test]
    fn p3_detects_same_ts_self_loop() {
        // (cmd.exe, Spawn, cmd.exe) — Spawn is not a whitelisted
        // singleton, so this fails even with the catalog.
        let relations = vec![rel("cmd.exe", "cmd.exe", RelationType::Spawn, 10)];
        let result = check_p3_identity_coherence(
            &relations,
            &Scope::Session,
            Some(super::super::default_shape_catalog()),
            8,
        );
        assert!(!result.passed);
        assert_eq!(result.violated, 1);
        let s = &result.samples[0];
        assert!(s.reason.contains("self-loop"));
    }

    #[test]
    fn p3_ignores_wildcard_any_self_loop() {
        let relations = vec![rel("cmd.exe", "cmd.exe", RelationType::Any, 10)];
        let result = check_p3_identity_coherence(&relations, &Scope::Session, None, 8);
        assert!(result.passed);
    }

    #[test]
    fn p3_accepts_whitelisted_singleton_under_catalog() {
        // (host, Connect, host) — singleton fallback emitted by the
        // generic parser; catalog whitelists (Host, Connect).
        let relations = vec![rel("dc-01", "dc-01", RelationType::Connect, 10)];
        let result = check_p3_identity_coherence(
            &relations,
            &Scope::Session,
            Some(super::super::default_shape_catalog()),
            8,
        );
        assert!(result.passed);
    }

    #[test]
    fn p3_stricter_without_catalog_flags_all_self_loops() {
        // Same singleton, but without catalog — strict rule wins.
        let relations = vec![rel("dc-01", "dc-01", RelationType::Connect, 10)];
        let result = check_p3_identity_coherence(&relations, &Scope::Session, None, 8);
        assert!(!result.passed);
        assert_eq!(result.violated, 1);
    }

    #[test]
    fn p3_passes_on_ordinary_edges() {
        let relations = vec![rel("a", "b", RelationType::Auth, 10)];
        let result = check_p3_identity_coherence(
            &relations,
            &Scope::Session,
            Some(super::super::default_shape_catalog()),
            8,
        );
        assert!(result.passed);
        assert_eq!(result.checked, 1);
    }

    // ──────────────────────────── P4 ────────────────────────────

    #[test]
    fn p4_detects_dangling_source() {
        let entities = vec![ent("dc-01", EntityType::Host)];
        let relations = vec![rel("alice", "dc-01", RelationType::Auth, 10)];
        let result = check_p4_referential_closure(&entities, &relations, &Scope::Session, 8);
        assert!(!result.passed);
        assert_eq!(result.violated, 1);
        assert!(result.samples[0].reason.contains("source"));
    }

    #[test]
    fn p4_detects_dangling_dest() {
        let entities = vec![ent("alice", EntityType::User)];
        let relations = vec![rel("alice", "dc-01", RelationType::Auth, 10)];
        let result = check_p4_referential_closure(&entities, &relations, &Scope::Session, 8);
        assert!(!result.passed);
        assert!(result.samples[0].reason.contains("dest"));
    }

    #[test]
    fn p4_detects_both_ends_missing() {
        let entities: Vec<Entity> = Vec::new();
        let relations = vec![rel("alice", "dc-01", RelationType::Auth, 10)];
        let result = check_p4_referential_closure(&entities, &relations, &Scope::Session, 8);
        assert!(!result.passed);
        assert!(result.samples[0].reason.contains("source and dest"));
    }

    #[test]
    fn p4_passes_when_both_ends_present() {
        let entities = vec![
            ent("alice", EntityType::User),
            ent("dc-01", EntityType::Host),
        ];
        let relations = vec![rel("alice", "dc-01", RelationType::Auth, 10)];
        let result = check_p4_referential_closure(&entities, &relations, &Scope::Session, 8);
        assert!(result.passed);
        assert_eq!(result.checked, 1);
    }

    // ──────────────────────────── P2 ────────────────────────────

    #[test]
    fn p2_passes_on_catalog_shapes() {
        let entities = vec![
            ent("alice", EntityType::User),
            ent("dc-01", EntityType::Host),
            ent("cmd.exe", EntityType::Process),
            ent("whoami.exe", EntityType::Process),
        ];
        let relations = vec![
            rel("alice", "dc-01", RelationType::Auth, 1),
            rel("alice", "cmd.exe", RelationType::Execute, 2),
            rel("cmd.exe", "whoami.exe", RelationType::Spawn, 3),
        ];
        let result = check_p2_type_shape_plausibility(
            &entities,
            &relations,
            &Scope::Session,
            super::super::default_shape_catalog(),
            8,
        );
        assert!(result.passed, "shapes from built-in parsers must pass");
        assert_eq!(result.violated, 0);
        assert_eq!(result.checked, 3);
    }

    #[test]
    fn p2_flags_implausible_shape() {
        // (File, Execute, IP) — not in any parser.
        let entities = vec![
            ent("C:/evil.dll", EntityType::File),
            ent("10.0.0.1", EntityType::IP),
        ];
        let relations = vec![rel("C:/evil.dll", "10.0.0.1", RelationType::Execute, 5)];
        let result = check_p2_type_shape_plausibility(
            &entities,
            &relations,
            &Scope::Session,
            super::super::default_shape_catalog(),
            8,
        );
        assert!(!result.passed);
        assert_eq!(result.violated, 1);
        let s = &result.samples[0];
        assert!(s.reason.contains("not in catalog"));
    }

    #[test]
    fn p2_passes_user_defined_rel_type() {
        let entities = vec![ent("alice", EntityType::User), ent("bob", EntityType::User)];
        let relations = vec![rel(
            "alice",
            "bob",
            RelationType::Other("Delegates".into()),
            5,
        )];
        let result = check_p2_type_shape_plausibility(
            &entities,
            &relations,
            &Scope::Session,
            super::super::default_shape_catalog(),
            8,
        );
        assert!(result.passed);
    }

    #[test]
    fn p2_accepts_whitelisted_singleton() {
        let entities = vec![ent("dc-01", EntityType::Host)];
        let relations = vec![rel("dc-01", "dc-01", RelationType::Connect, 5)];
        let result = check_p2_type_shape_plausibility(
            &entities,
            &relations,
            &Scope::Session,
            super::super::default_shape_catalog(),
            8,
        );
        assert!(result.passed);
    }

    #[test]
    fn p2_flags_non_whitelisted_singleton() {
        // (Host, Spawn, Host) is not a valid self-loop shape.
        let entities = vec![ent("dc-01", EntityType::Host)];
        let relations = vec![rel("dc-01", "dc-01", RelationType::Spawn, 5)];
        let result = check_p2_type_shape_plausibility(
            &entities,
            &relations,
            &Scope::Session,
            super::super::default_shape_catalog(),
            8,
        );
        assert!(!result.passed);
        assert!(result.samples[0].reason.contains("singleton catalog"));
    }

    #[test]
    fn p2_skips_relations_with_missing_endpoints() {
        // Dangling dest — P4's territory; P2 should not count or flag.
        let entities = vec![ent("alice", EntityType::User)];
        let relations = vec![rel("alice", "ghost", RelationType::Auth, 5)];
        let result = check_p2_type_shape_plausibility(
            &entities,
            &relations,
            &Scope::Session,
            super::super::default_shape_catalog(),
            8,
        );
        assert!(result.passed);
        assert_eq!(result.checked, 0);
    }

    // Sample cap respected — this matters for MCP payload budgets.
    #[test]
    fn sample_caps_are_honored() {
        // 32 dangling-dest relations; cap is 8.
        let entities = vec![ent("alice", EntityType::User)];
        let relations: Vec<Relation> = (0..32)
            .map(|i| rel("alice", &format!("missing-{i}"), RelationType::Auth, i))
            .collect();
        let result = check_p4_referential_closure(&entities, &relations, &Scope::Session, 8);
        assert_eq!(result.violated, 32);
        assert_eq!(result.samples.len(), 8);
    }
}
