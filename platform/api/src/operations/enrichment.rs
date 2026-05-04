//! Enrichment operations. Only `get_subnet_analysis` is migrated in P1
//! Fase 1 — `enrich_ip` stays on the Tauri legacy path because it needs
//! the app-level `GeoIpProvider` and `HttpGeoIpClient` services that
//! are not yet owned by the API crate (will move in the `ServiceRegistry`
//! step of Fase 2).

use std::collections::HashMap;

use graph_hunter_core::{ip_utils, types::EntityType};

use crate::dto::enrichment::{SubnetAnalysisRequest, SubnetAnalysisResponse, SubnetGroup};
use crate::{ApiResult, GraphHunterApi};

impl GraphHunterApi {
    /// Group the session's IP entities by /24 subnet, aggregating byte
    /// totals (when metadata carries them) and the top service
    /// categories seen via outgoing relations.
    ///
    /// Read-only. The legacy command used `with_current_graph_mut` but
    /// only reads — this is a read-only path in the canonical API.
    pub fn get_subnet_analysis(
        &self,
        req: SubnetAnalysisRequest,
    ) -> ApiResult<SubnetAnalysisResponse> {
        self.with_graph_read(req.session.as_ref(), |graph| {
            let ip_ids: Vec<String> = graph
                .entity_ids_for_type(&EntityType::IP)
                .unwrap_or_default();

            if ip_ids.is_empty() {
                return Ok(Vec::new());
            }

            let refs: Vec<&str> = ip_ids.iter().map(|s| s.as_str()).collect();
            let subnet_groups = ip_utils::group_by_subnet(&refs);

            let mut result = Vec::with_capacity(subnet_groups.len());
            for (subnet, ips) in subnet_groups {
                let is_internal = ips
                    .first()
                    .map(|ip| ip_utils::is_private(ip))
                    .unwrap_or(false);

                let mut total_bytes: u64 = 0;
                let mut has_bytes = false;
                let mut service_counts: HashMap<String, usize> = HashMap::new();

                for ip_str in &ips {
                    if let Some(entity) = graph.get_entity(ip_str) {
                        if let Some(b) = entity.metadata.get("bytes") {
                            if let Ok(n) = parse_bytes_str(b) {
                                total_bytes += n;
                                has_bytes = true;
                            }
                        }
                    }
                    for rel in graph.get_relations(ip_str) {
                        if let Some(cat) = rel.metadata.get("service_category") {
                            *service_counts.entry(cat.clone()).or_insert(0) += 1;
                        }
                    }
                }

                let mut top: Vec<(String, usize)> = service_counts.into_iter().collect();
                top.sort_by(|a, b| b.1.cmp(&a.1));
                let top_services: Vec<String> = top.into_iter().map(|(name, _)| name).collect();

                result.push(SubnetGroup {
                    subnet,
                    ip_count: ips.len(),
                    ips,
                    total_bytes: if has_bytes { Some(total_bytes) } else { None },
                    is_internal,
                    top_services,
                });
            }

            result.sort_by(|a, b| b.ip_count.cmp(&a.ip_count));
            Ok(result)
        })
    }
}

/// Parses a bytes string like `"5983237494"` or `"135.04 MB"` into raw
/// bytes. Kept private; the only caller is `get_subnet_analysis`.
fn parse_bytes_str(s: &str) -> Result<u64, ()> {
    let s = s.trim();
    if let Ok(n) = s.parse::<u64>() {
        return Ok(n);
    }
    let parts: Vec<&str> = s.split_whitespace().collect();
    if parts.len() == 2 {
        if let Ok(n) = parts[0].parse::<f64>() {
            let multiplier = match parts[1].to_uppercase().as_str() {
                "KB" => 1024.0_f64,
                "MB" => 1024.0_f64 * 1024.0,
                "GB" => 1024.0_f64 * 1024.0 * 1024.0,
                "TB" => 1024.0_f64 * 1024.0 * 1024.0 * 1024.0,
                _ => return Err(()),
            };
            return Ok((n * multiplier) as u64);
        }
    }
    Err(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_bytes_str_plain_number() {
        assert_eq!(parse_bytes_str("1024"), Ok(1024));
    }

    #[test]
    fn parse_bytes_str_units() {
        assert_eq!(parse_bytes_str("1 KB"), Ok(1024));
        assert_eq!(parse_bytes_str("1 MB"), Ok(1024 * 1024));
        assert_eq!(parse_bytes_str("2.5 MB"), Ok(2_621_440)); // 2.5 * 1024^2
        assert_eq!(parse_bytes_str("1 GB"), Ok(1024 * 1024 * 1024));
        assert_eq!(parse_bytes_str("1 TB"), Ok(1024u64 * 1024 * 1024 * 1024));
    }

    #[test]
    fn parse_bytes_str_unknown_unit_errors() {
        assert_eq!(parse_bytes_str("1 XB"), Err(()));
    }

    #[test]
    fn parse_bytes_str_garbage_errors() {
        assert_eq!(parse_bytes_str("hello"), Err(()));
        assert_eq!(parse_bytes_str(""), Err(()));
    }

    #[test]
    fn subnet_analysis_empty_graph_returns_empty() {
        use crate::state::Session;
        use graph_hunter_core::GraphHunter;
        use std::sync::Arc;

        let api = GraphHunterApi::new_noop();
        let s = Arc::new(Session::new("s1", "t", GraphHunter::new(), 0));
        api.sessions().insert(s);
        api.sessions().set_current(Some("s1".to_string()));

        let groups = api
            .get_subnet_analysis(SubnetAnalysisRequest::default())
            .expect("empty graph should be ok");
        assert!(groups.is_empty());
    }
}
