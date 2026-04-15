use std::sync::Arc;

use serde::Serialize;
use tauri::State;

use graph_hunter_core::geoip::GeoIpResult;
use graph_hunter_core::types::EntityType;
use graph_hunter_core::{ip_utils, write_geoip_to_metadata};

use crate::error::CommandError;
use crate::helpers::with_current_graph_mut;
use crate::state::AppState;

/// Enriches a public IP entity with GeoIP data (country, city, ASN, ISP).
///
/// Tries the offline MaxMind provider first, then falls back to the HTTP
/// provider (ip-api.com). Writes results into the entity's metadata HashMap
/// so subsequent `get_node_details` calls include the enrichment data.
///
/// Returns `InvalidInput` for private/non-routable IPs.
#[tauri::command]
pub async fn cmd_enrich_ip(
    state: State<'_, Arc<AppState>>,
    ip: String,
) -> Result<GeoIpResult, CommandError> {
    // Validate: only enrich public IPs
    if !ip_utils::is_public(&ip) {
        return Err(CommandError::InvalidInput(format!(
            "IP {} is not a public/routable address. GeoIP enrichment is only available for external IPs.",
            ip
        )));
    }

    // Try offline MaxMind first
    let maxmind_result = {
        let provider = state.geoip_provider.lock().map_err(|e| {
            CommandError::Internal(format!("GeoIP provider lock poisoned: {e}"))
        })?;
        provider.as_ref().and_then(|p| p.lookup(&ip))
    };

    let result = if let Some(r) = maxmind_result {
        r
    } else {
        // Clone HttpClient arc out of the lock so we can drop the guard before await
        let http_client = {
            let guard = state.http_geoip_client.lock().map_err(|e| {
                CommandError::Internal(format!("HTTP GeoIP client lock poisoned: {e}"))
            })?;
            guard.clone()
        };
        match http_client {
            Some(client) => {
                let provider = graph_hunter_core::geoip::http::HttpGeoIpProvider::new(client);
                let cancel = tokio_util::sync::CancellationToken::new();
                provider
                    .lookup(&ip, cancel)
                    .await
                    .map_err(|e| CommandError::Internal(format!("GeoIP lookup failed: {e}")))?
            }
            None => {
                return Err(CommandError::Internal(
                    "No GeoIP provider available. Place GeoLite2 .mmdb files in the geoip directory or ensure network access for HTTP fallback.".into(),
                ));
            }
        }
    };

    // Write enrichment data into the entity's metadata
    with_current_graph_mut(state.as_ref(), |graph| {
        if let Some(entity) = graph.get_entity_mut(&ip) {
            write_geoip_to_metadata(&mut entity.metadata, &result);
        }
        Ok(())
    })?;

    Ok(result)
}

/// Subnet analysis: groups all IP entities in the graph by /24 subnet.
#[derive(Serialize, Clone)]
pub struct SubnetGroup {
    pub subnet: String,
    pub ip_count: usize,
    pub ips: Vec<String>,
    pub total_bytes: Option<u64>,
    pub is_internal: bool,
    pub top_services: Vec<String>,
}

#[tauri::command]
pub fn cmd_get_subnet_analysis(
    state: State<Arc<AppState>>,
) -> Result<Vec<SubnetGroup>, CommandError> {
    use std::collections::HashMap;

    with_current_graph_mut(state.as_ref(), |graph| {
        // Collect all IP entity IDs
        let ip_ids: Vec<String> = graph
            .entity_ids_for_type(&EntityType::IP)
            .unwrap_or_default();

        if ip_ids.is_empty() {
            return Ok(vec![]);
        }

        // Group by subnet
        let refs: Vec<&str> = ip_ids.iter().map(|s| s.as_str()).collect();
        let subnet_groups = ip_utils::group_by_subnet(&refs);

        let mut result = Vec::with_capacity(subnet_groups.len());
        for (subnet, ips) in subnet_groups {
            let is_internal = ips
                .first()
                .map(|ip| ip_utils::is_private(ip))
                .unwrap_or(false);

            // Aggregate bytes from entity metadata
            let mut total_bytes: u64 = 0;
            let mut has_bytes = false;
            let mut service_counts: HashMap<String, usize> = HashMap::new();

            for ip_str in &ips {
                if let Some(entity) = graph.get_entity(ip_str) {
                    // Try to parse bytes metadata
                    if let Some(b) = entity.metadata.get("bytes") {
                        if let Ok(n) = parse_bytes_str(b) {
                            total_bytes += n;
                            has_bytes = true;
                        }
                    }
                }

                // Find services connected to this IP via outgoing relations
                for rel in graph.get_relations(ip_str) {
                    if let Some(cat) = rel.metadata.get("service_category") {
                        *service_counts.entry(cat.clone()).or_insert(0) += 1;
                    }
                }
            }

            // Top services sorted by frequency
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

/// Parses a bytes string like "5983237494" or "135.04 MB" into raw bytes.
fn parse_bytes_str(s: &str) -> Result<u64, ()> {
    let s = s.trim();
    // Try plain integer first
    if let Ok(n) = s.parse::<u64>() {
        return Ok(n);
    }
    // Try "N.NN GB/MB/KB" format
    let parts: Vec<&str> = s.split_whitespace().collect();
    if parts.len() == 2 {
        if let Ok(n) = parts[0].parse::<f64>() {
            let multiplier = match parts[1].to_uppercase().as_str() {
                "KB" => 1024.0,
                "MB" => 1024.0 * 1024.0,
                "GB" => 1024.0 * 1024.0 * 1024.0,
                "TB" => 1024.0 * 1024.0 * 1024.0 * 1024.0,
                _ => return Err(()),
            };
            return Ok((n * multiplier) as u64);
        }
    }
    Err(())
}
