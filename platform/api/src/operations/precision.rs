//! Detects patterns that match too much of the population to mean anything.
//!
//! `check_catalog_compatibility` already guards one failure mode: a
//! pattern whose types are absent from the graph, which returns zero
//! paths *by construction* rather than because the behaviour is absent.
//! This guards the mirror image, which had nothing watching it — a
//! pattern that fires on most of the population, where a big result set
//! reads as a big discovery.
//!
//! Both modes showed up in the same real investigation. The zero-result
//! side was flagged; this side produced 4,996 paths over a 4,627-user
//! corpus and had to be diagnosed by hand, after which the analyst
//! recorded it as a systemic false positive.

use std::collections::HashSet;
use std::sync::Arc;

use graph_hunter_core::{GraphHunter, Hypothesis};

use crate::dto::hunt::PatternPrecision;

/// Fraction of the population at or above which a pattern is called
/// non-discriminating. Overridable with `GRAPHHUNTER_PRECISION_THRESHOLD`
/// (a fraction, e.g. `0.35`).
pub const DEFAULT_THRESHOLD: f64 = 0.20;

/// Populations smaller than this are exempt.
///
/// Prevalence is meaningless on a handful of nodes: a demo graph with
/// four Users trips any percentage threshold the moment two of them
/// match, and warning there would train analysts to ignore the field.
const MIN_POPULATION: usize = 50;

fn threshold_from_env() -> f64 {
    std::env::var("GRAPHHUNTER_PRECISION_THRESHOLD")
        .ok()
        .and_then(|v| v.trim().parse::<f64>().ok())
        .filter(|v| *v > 0.0 && *v <= 1.0)
        .unwrap_or(DEFAULT_THRESHOLD)
}

/// Returns `Some` only when the pattern is non-discriminating.
///
/// Measured over *seed entities*, not paths: path count inflates with
/// fan-out (one user with 60 addresses contributes 60 paths but is one
/// account), so the honest question is "how much of the population does
/// this implicate", which is the first node of each path.
pub fn assess(
    hypothesis: &Hypothesis,
    paths: &[Vec<Arc<str>>],
    truncated: bool,
    graph: &GraphHunter,
) -> Option<PatternPrecision> {
    if paths.is_empty() {
        return None;
    }
    // A truncated result set cannot support a prevalence claim in either
    // direction. The matcher stopped enumerating at the cap, so the
    // entities observed here are a floor, not a measurement: a pattern
    // that truly implicates 60% of the population can look like 5% purely
    // because the cap landed early. Staying silent is the honest failure
    // mode -- found by running cat-021 against the real Keycloak graph,
    // where 3,081 paths came back flagged `truncated` and the guard
    // reported a comfortable prevalence it had no basis to report.
    if truncated {
        return None;
    }
    let seed_type = hypothesis.steps.first()?.origin_type.to_string();

    // `Any` seeds from every entity, so the population is the whole
    // graph rather than one type bucket.
    let population = if seed_type == "Any" {
        graph.entity_count()
    } else {
        graph
            .entity_type_counts()
            .into_iter()
            .find(|(t, _)| *t == seed_type)
            .map(|(_, n)| n)?
    };
    if population < MIN_POPULATION {
        return None;
    }

    let matched: HashSet<&str> = paths
        .iter()
        .filter_map(|p| p.first())
        .map(|s| s.as_ref())
        .collect();
    let matched_entities = matched.len();
    let prevalence = matched_entities as f64 / population as f64;

    let threshold = threshold_from_env();
    if prevalence < threshold {
        return None;
    }

    Some(PatternPrecision {
        note: format!(
            "This pattern matched {matched_entities} of {population} {seed_type} entities \
             ({:.0}% of the population). A pattern that fires on this share of a population \
             does not discriminate between normal and suspicious behaviour, so the result set \
             should not be read as findings. Narrow the pattern, or establish a per-entity \
             baseline first.",
            prevalence * 100.0
        ),
        seed_type,
        matched_entities,
        population,
        prevalence,
        threshold,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use graph_hunter_core::HypothesisStep;
    use graph_hunter_core::{Entity, EntityType, Relation, RelationType};

    fn graph_with_users(n: usize) -> GraphHunter {
        let mut g = GraphHunter::new();
        for i in 0..n {
            g.add_entity(Entity::new(format!("user{i}"), EntityType::User))
                .expect("add user");
            g.add_entity(Entity::new(format!("ip{i}"), EntityType::IP))
                .expect("add ip");
            g.add_relation(Relation::new(
                format!("user{i}"),
                format!("ip{i}"),
                RelationType::Auth,
                1000 + i as i64,
            ))
            .expect("add rel");
        }
        g
    }

    fn user_auth_ip() -> Hypothesis {
        Hypothesis {
            name: "t".into(),
            steps: vec![HypothesisStep {
                origin_type: EntityType::User,
                relation_type: RelationType::Auth,
                dest_type: EntityType::IP,
                edge_predicates: vec![],
                dest_predicates: vec![],
                origin_binding: None,
                dest_binding: None,
            }],
            k_simplicity: 1,
            aggregations: vec![],
            window_seconds: None,
            skew_tolerance_seconds: None,
            max_gap: None,
            shape: Default::default(),
        }
    }

    fn paths_for(users: impl Iterator<Item = usize>) -> Vec<Vec<Arc<str>>> {
        users
            .map(|i| {
                vec![
                    Arc::from(format!("user{i}").as_str()),
                    Arc::from(format!("ip{i}").as_str()),
                ]
            })
            .collect()
    }

    /// The cat-021 shape: nearly the whole population matches.
    #[test]
    fn flags_a_pattern_that_matches_most_of_the_population() {
        let g = graph_with_users(200);
        let paths = paths_for(0..180);
        let p = assess(&user_auth_ip(), &paths, false, &g).expect("must flag 90% prevalence");
        assert_eq!(p.seed_type, "User");
        assert_eq!(p.matched_entities, 180);
        assert_eq!(p.population, 200);
        assert!((p.prevalence - 0.9).abs() < 1e-9, "got {}", p.prevalence);
        assert!(
            p.note.contains("90%"),
            "note should quote the share: {}",
            p.note
        );
    }

    /// A genuinely selective pattern must stay silent, or the warning
    /// becomes noise and gets ignored.
    #[test]
    fn stays_quiet_for_a_selective_pattern() {
        let g = graph_with_users(200);
        let paths = paths_for(0..10); // 5%
        assert!(assess(&user_auth_ip(), &paths, false, &g).is_none());
    }

    /// Path count must not drive the verdict: one entity appearing in
    /// many paths is still one entity. Without this, high fan-out alone
    /// would trip the guard.
    #[test]
    fn counts_entities_not_paths() {
        let g = graph_with_users(200);
        // One user, 500 paths (the 62-addresses-per-user case).
        let paths: Vec<Vec<Arc<str>>> = (0..500)
            .map(|k| vec![Arc::from("user0"), Arc::from(format!("ip{k}").as_str())])
            .collect();
        assert!(
            assess(&user_auth_ip(), &paths, false, &g).is_none(),
            "500 paths from a single entity is 0.5% prevalence, not 250%"
        );
    }

    /// Percentages on tiny graphs are meaningless; demo fixtures would
    /// otherwise warn constantly.
    #[test]
    fn exempts_small_populations() {
        let g = graph_with_users(10);
        let paths = paths_for(0..9); // 90%, but of ten nodes
        assert!(assess(&user_auth_ip(), &paths, false, &g).is_none());
    }

    #[test]
    fn empty_results_are_not_a_precision_problem() {
        let g = graph_with_users(200);
        assert!(assess(&user_auth_ip(), &[], false, &g).is_none());
    }

    #[test]
    fn threshold_is_configurable() {
        let g = graph_with_users(200);
        let paths = paths_for(0..60); // 30%
        assert!(
            assess(&user_auth_ip(), &paths, false, &g).is_some(),
            "30% must trip the 20% default"
        );
        // SAFETY: restored before the test returns.
        unsafe { std::env::set_var("GRAPHHUNTER_PRECISION_THRESHOLD", "0.5") };
        let quiet = assess(&user_auth_ip(), &paths, false, &g);
        unsafe { std::env::remove_var("GRAPHHUNTER_PRECISION_THRESHOLD") };
        assert!(quiet.is_none(), "30% must not trip a 50% threshold");
    }

    /// A capped result set is a floor, not a measurement. Reporting a
    /// prevalence from it would understate exactly the case the guard
    /// exists for.
    #[test]
    fn stays_silent_on_truncated_results() {
        let g = graph_with_users(200);
        let paths = paths_for(0..180); // 90% -- would fire if complete
        assert!(
            assess(&user_auth_ip(), &paths, true, &g).is_none(),
            "must not judge prevalence from a truncated path set"
        );
        assert!(
            assess(&user_auth_ip(), &paths, false, &g).is_some(),
            "the same set, complete, must still fire"
        );
    }
}
