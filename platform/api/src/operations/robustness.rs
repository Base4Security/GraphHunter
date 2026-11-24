//! Attribution robustness (λ, ρ) over the session graph.

use std::collections::BTreeSet;

use graph_hunter_core::cancel::{self, CancelToken};
use graph_hunter_core::parse_dsl;
use graph_hunter_core::robustness::attribution_robustness;

use crate::dto::robustness::{
    AttributionRobustnessRequest, AttributionRobustnessResponse, DEFAULT_MAX_PAIRS,
    RobustnessSummary,
};
use crate::{ApiError, ApiResult, GraphHunterApi};

/// Ceiling on the pairs one request evaluates.
pub const MAX_PAIRS: usize = 5_000;
/// Ceilings on the shared-risk table a request may carry.
pub const MAX_DOMAIN_GROUPS: usize = 10_000;
pub const MAX_LABELS_PER_GROUP: usize = 50;

impl GraphHunterApi {
    /// λ and ρ for one attribution, or for every endpoint pair the
    /// hypothesis matches when the request names none.
    pub fn attribution_robustness(
        &self,
        req: AttributionRobustnessRequest,
    ) -> ApiResult<AttributionRobustnessResponse> {
        self.attribution_robustness_cancellable(req, &CancelToken::new())
    }

    /// Same, stopping early once `cancel` is cancelled: the hunt for pairs,
    /// each pair's cut and the ρ enumeration all poll it, and a cancelled
    /// run answers `ApiError::Timeout` instead of partial counts.
    pub fn attribution_robustness_cancellable(
        &self,
        req: AttributionRobustnessRequest,
        cancel: &CancelToken,
    ) -> ApiResult<AttributionRobustnessResponse> {
        let groups = &req.options.domains.groups;
        if groups.len() > MAX_DOMAIN_GROUPS
            || groups.values().any(|g| g.len() > MAX_LABELS_PER_GROUP)
        {
            return Err(ApiError::InvalidInput(format!(
                "domains.groups allows at most {MAX_DOMAIN_GROUPS} entries of                  {MAX_LABELS_PER_GROUP} labels each"
            )));
        }
        let hypothesis = parse_dsl(req.hypothesis_dsl.trim(), Some("robustness"))
            .map_err(|e| ApiError::InvalidInput(format!("invalid hypothesis: {e}")))?
            .hypothesis;
        if hypothesis.shape == graph_hunter_core::hypothesis::HypothesisShape::Graph {
            return Err(ApiError::InvalidInput(
                "robustness is computed for chain hypotheses; this one joins several groups".into(),
            ));
        }
        let max_pairs = req
            .max_pairs
            .unwrap_or(DEFAULT_MAX_PAIRS)
            .clamp(1, MAX_PAIRS);
        let timed_out = || ApiError::Timeout("attribution robustness was cancelled".into());
        let result = cancel::scope(cancel, || {
            self.with_graph_read(req.session.as_ref(), |graph| {
                let (pairs, truncated) = match (req.source.as_deref(), req.target.as_deref()) {
                    (Some(s), Some(t)) => (vec![(s.to_string(), t.to_string())], false),
                    (None, None) => {
                        let (paths, _) = graph
                            .search_temporal_pattern(&hypothesis, req.options.time_window, None)
                            .map_err(|e| ApiError::InvalidInput(e.to_string()))?;
                        if cancel.is_cancelled() {
                            return Err(timed_out());
                        }
                        let all: BTreeSet<(String, String)> = paths
                            .iter()
                            .filter_map(|p| Some((p.first()?.to_string(), p.last()?.to_string())))
                            .collect();
                        let truncated = all.len() > max_pairs;
                        (all.into_iter().take(max_pairs).collect(), truncated)
                    }
                    _ => {
                        return Err(ApiError::InvalidInput(
                            "give both source and target, or neither".into(),
                        ));
                    }
                };
                let mut out = AttributionRobustnessResponse {
                    summary: RobustnessSummary {
                        truncated,
                        ..Default::default()
                    },
                    pairs: Vec::with_capacity(pairs.len()),
                };
                for (s, t) in pairs {
                    if cancel.is_cancelled() {
                        return Err(timed_out());
                    }
                    let r = attribution_robustness(graph, &hypothesis, &s, &t, &req.options)
                        .map_err(|e| {
                            if cancel.is_cancelled() {
                                timed_out()
                            } else {
                                ApiError::InvalidInput(e)
                            }
                        })?;
                    let sum = &mut out.summary;
                    sum.pairs += 1;
                    if r.holds {
                        sum.holding += 1;
                        sum.lambda_exact += usize::from(r.lambda_exact);
                        sum.lambda_at_least_2 += usize::from(r.lambda_exact && r.lambda >= 2);
                        sum.rho_1 += usize::from(!r.single_domain_breaks.is_empty());
                        sum.gap += usize::from(r.gap());
                        sum.rho_unresolved += usize::from(r.rho().is_none());
                    }
                    out.pairs.push(r);
                }
                Ok(out)
            })
        });
        if cancel.is_cancelled() {
            return Err(timed_out());
        }
        result
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use graph_hunter_core::{Entity, EntityType, GraphHunter, Relation, RelationType};

    use super::*;
    use crate::state::Session;

    /// Two users reach the same process: alice through two records that
    /// both come from dataset "edr", bob through one record per dataset.
    fn api() -> GraphHunterApi {
        let mut g = GraphHunter::new();
        for u in ["alice@example.com", "bob@example.com"] {
            g.add_entity(Entity::new(u, EntityType::User)).unwrap();
        }
        for p in ["p1", "p2", "p3", "p4", "target"] {
            g.add_entity(Entity::new(p, EntityType::Process)).unwrap();
        }
        let edges = [
            ("alice@example.com", "p1", RelationType::Execute, 100, "edr"),
            ("p1", "target", RelationType::Spawn, 200, "sysmon"),
            ("alice@example.com", "p2", RelationType::Execute, 100, "edr"),
            ("p2", "target", RelationType::Spawn, 200, "sysmon-2"),
            ("bob@example.com", "p3", RelationType::Execute, 100, "edr"),
            ("p3", "target", RelationType::Spawn, 200, "sysmon"),
            (
                "bob@example.com",
                "p4",
                RelationType::Execute,
                100,
                "sentinel",
            ),
            ("p4", "target", RelationType::Spawn, 200, "sysmon-2"),
        ];
        for (s, d, r, t, ds) in edges {
            let mut rel = Relation::new(s, d, r, t);
            rel.dataset_id = Some(Arc::from(ds));
            g.add_relation(rel).unwrap();
        }
        g.sort_edges_by_timestamp().unwrap();
        let api = GraphHunterApi::new_noop();
        let session = Arc::new(Session::new("s", "s", g, 0));
        session.set_phase(crate::state::SessionPhase::Ready);
        api.sessions().insert(session);
        api.sessions().set_current(Some("s".to_string()));
        api
    }

    #[test]
    fn every_hunted_pair_is_counted_with_its_denominator() {
        let resp = api()
            .attribution_robustness(AttributionRobustnessRequest {
                hypothesis_dsl: "User -[Execute]-> Process -[Spawn]-> Process".into(),
                ..Default::default()
            })
            .unwrap();
        let s = &resp.summary;
        assert_eq!((s.pairs, s.holding), (2, 2));
        assert_eq!(s.lambda_at_least_2, 2);
        // alice's two records both need "edr"; bob's survive any one loss.
        assert_eq!((s.rho_1, s.gap), (1, 1));
        let alice = resp
            .pairs
            .iter()
            .find(|p| p.source == "alice@example.com")
            .unwrap();
        assert_eq!(alice.single_domain_breaks, vec!["edr".to_string()]);
    }

    #[test]
    fn a_named_pair_and_a_half_named_one() {
        let api = api();
        let one = api
            .attribution_robustness(AttributionRobustnessRequest {
                hypothesis_dsl: "User -[Execute]-> Process -[Spawn]-> Process".into(),
                source: Some("bob@example.com".into()),
                target: Some("target".into()),
                ..Default::default()
            })
            .unwrap();
        assert_eq!(one.pairs.len(), 1);
        assert_eq!(one.pairs[0].rho(), Some(2));
        let half = api.attribution_robustness(AttributionRobustnessRequest {
            hypothesis_dsl: "User -[Execute]-> Process -[Spawn]-> Process".into(),
            source: Some("bob@example.com".into()),
            ..Default::default()
        });
        assert!(half.is_err());
    }

    /// A cancelled run answers a timeout, never partial counts.
    #[test]
    fn a_cancelled_run_is_a_timeout() {
        let token = CancelToken::new();
        token.cancel();
        let r = api().attribution_robustness_cancellable(
            AttributionRobustnessRequest {
                hypothesis_dsl: "User -[Execute]-> Process -[Spawn]-> Process".into(),
                ..Default::default()
            },
            &token,
        );
        assert!(matches!(r, Err(ApiError::Timeout(_))), "{r:?}");
    }

    /// The caps hold whatever the caller sends.
    #[test]
    fn oversized_requests_are_bounded() {
        let mut req = AttributionRobustnessRequest {
            hypothesis_dsl: "User -[Execute]-> Process -[Spawn]-> Process".into(),
            max_pairs: Some(usize::MAX),
            ..Default::default()
        };
        req.options.max_exact_domains = usize::MAX;
        let resp = api().attribution_robustness(req.clone()).unwrap();
        assert_eq!(resp.summary.pairs, 2);

        req.options.domains.groups = (0..=MAX_DOMAIN_GROUPS)
            .map(|i| (i.to_string(), vec![i.to_string()]))
            .collect();
        assert!(matches!(
            api().attribution_robustness(req),
            Err(ApiError::InvalidInput(_))
        ));
    }
}
