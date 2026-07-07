//! Enrichment operations. Only `get_subnet_analysis` is migrated in P1
//! Fase 1 — `enrich_ip` stays on the Tauri legacy path because it needs
//! the app-level `GeoIpProvider` and `HttpGeoIpClient` services that
//! are not yet owned by the API crate (will move in the `ServiceRegistry`
//! step of Fase 2).

use std::collections::{HashMap, HashSet};

use graph_hunter_core::{ip_utils, relation::Relation, types::EntityType};

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

            // 2026-05-06 (#14 fix follow-up): in real Sentinel sessions
            // an IP is almost always a *destination* (Auth target,
            // Connect target, DNS resolved target). The previous code
            // only walked outgoing relations from the IP, which left
            // these passive IPs with `top_services: []` even after the
            // first heuristic landed. Here we additionally walk
            // *incoming* edges via `reverse_adj`, materializing only
            // those relations that actually point at the IP. The two
            // sets are merged so an IP that's both source and target
            // (rare but possible for proxies) is counted once.
            let mut result = Vec::with_capacity(subnet_groups.len());
            for (subnet, ips) in subnet_groups {
                // 2026-05-06: previously `ips.first().is_private(...)`
                // — order-sensitive AND too narrow. A /64 grouping
                // `::1` (Loopback) plus `::ffff:172.20.5.61` (IPv4-
                // mapped Private) used to flicker between true/false
                // depending on iteration order, and never matched
                // because Loopback is not Private. Use `any()` over
                // the broader `is_internal` so the subnet is flagged
                // internal as long as one of its addresses qualifies.
                let is_internal = ips.iter().any(|ip| ip_utils::is_internal(ip));

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
                    // Outgoing relations from this IP (rare for
                    // Sentinel; common when the IP itself acts as the
                    // anchor, e.g. a proxy).
                    for rel in graph.get_relations(ip_str) {
                        accumulate_service(&rel, &mut service_counts);
                    }
                    // Incoming relations: walk every source that has
                    // an edge pointing at this IP and surface only the
                    // edges whose dest is the IP. This is what makes
                    // `Auth`/`Connect`/`DNS` show up as the dominant
                    // services for destination-only IPs.
                    let reverse_sids = graph.get_reverse_source_sids(ip_str);
                    if !reverse_sids.is_empty() {
                        let mut visited_sources: HashSet<&str> = HashSet::new();
                        for &source_sid in reverse_sids {
                            let source_id = graph.interner.resolve(source_sid);
                            if !visited_sources.insert(source_id) {
                                continue;
                            }
                            for rel in graph.get_relations(source_id) {
                                if rel.dest_id == *ip_str {
                                    accumulate_service(&rel, &mut service_counts);
                                }
                            }
                        }
                    }
                }

                let mut top: Vec<(String, usize)> = service_counts.into_iter().collect();
                top.sort_by(|a, b| b.1.cmp(&a.1));
                // Cap at 10 to keep the per-subnet payload bounded —
                // the long-tail ports are noise once the top
                // categories are visible.
                let top_services: Vec<String> = top
                    .into_iter()
                    .take(10)
                    .map(|(name, _)| name)
                    .collect();

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

/// Look up `service_category` then well-known port then relation type
/// and bump the corresponding bucket in `counts`. Shared between the
/// outgoing- and incoming-relation walks so both directions agree on
/// the inference order.
fn accumulate_service(rel: &Relation, counts: &mut HashMap<String, usize>) {
    let category = rel
        .metadata
        .get("service_category")
        .cloned()
        .or_else(|| {
            rel.metadata
                .get("dest_port")
                .or_else(|| rel.metadata.get("port"))
                .and_then(|p| p.parse::<u16>().ok())
                .and_then(service_for_port)
                .map(str::to_string)
        })
        .unwrap_or_else(|| format!("{}", rel.rel_type));
    *counts.entry(category).or_insert(0) += 1;
}

/// Map well-known ports to a human-readable service name. Returns
/// `None` for ephemeral/unknown ports — those fall through to the
/// relation-type fallback so we don't pollute the top with raw
/// numbers.
fn service_for_port(port: u16) -> Option<&'static str> {
    Some(match port {
        20 | 21 => "FTP",
        22 => "SSH",
        23 => "Telnet",
        25 | 465 | 587 => "SMTP",
        53 => "DNS",
        67 | 68 => "DHCP",
        69 => "TFTP",
        80 | 8000 | 8080 => "HTTP",
        88 => "Kerberos",
        110 => "POP3",
        123 => "NTP",
        135 => "RPC",
        137..=139 => "NetBIOS",
        143 | 993 => "IMAP",
        161 | 162 => "SNMP",
        389 => "LDAP",
        443 | 8443 => "HTTPS",
        445 => "SMB",
        514 => "Syslog",
        636 => "LDAPS",
        989 | 990 => "FTPS",
        995 => "POP3S",
        1433 => "MSSQL",
        1521 => "Oracle",
        1812 | 1813 => "RADIUS",
        2049 => "NFS",
        3268 | 3269 => "GlobalCatalog",
        3306 => "MySQL",
        3389 => "RDP",
        5432 => "PostgreSQL",
        5985 => "WinRM",
        5986 => "WinRM-S",
        5900..=5910 => "VNC",
        6379 => "Redis",
        9200 | 9300 => "Elasticsearch",
        27017 => "MongoDB",
        _ => return None,
    })
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
    fn service_for_port_well_known_subset() {
        assert_eq!(service_for_port(443), Some("HTTPS"));
        assert_eq!(service_for_port(53), Some("DNS"));
        assert_eq!(service_for_port(3389), Some("RDP"));
        assert_eq!(service_for_port(445), Some("SMB"));
        assert_eq!(service_for_port(22), Some("SSH"));
        assert_eq!(service_for_port(137), Some("NetBIOS"));
        assert_eq!(service_for_port(139), Some("NetBIOS"));
        assert_eq!(service_for_port(5901), Some("VNC"));
        // Ephemeral / unknown returns None so the caller falls back
        // to the relation type instead of "49152".
        assert_eq!(service_for_port(49152), None);
        assert_eq!(service_for_port(7777), None);
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
