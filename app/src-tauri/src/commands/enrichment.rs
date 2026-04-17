//! IP enrichment + subnet analysis. Both delegate to the canonical
//! API; the GeoIP service (offline MaxMind + HTTP fallback + dataset-
//! metadata path) lives in `graph_hunter_api::operations::geoip`.

use std::sync::Arc;

use tauri::State;

use graph_hunter_api::dto::enrichment::{SubnetAnalysisRequest, SubnetGroup};
use graph_hunter_api::dto::geoip::EnrichIpRequest;
use graph_hunter_api::GraphHunterApi;
use graph_hunter_core::geoip::GeoIpResult;

use crate::error::CommandError;

/// Enriches a public IP entity with GeoIP data (country, city, ASN,
/// ISP). Tries offline MaxMind first, then HTTP fallback, then
/// dataset metadata. Returns `InvalidInput` for private IPs.
#[tauri::command]
pub async fn cmd_enrich_ip(
    api: State<'_, Arc<GraphHunterApi>>,
    ip: String,
) -> Result<GeoIpResult, CommandError> {
    api.enrich_ip(EnrichIpRequest { session: None, ip })
        .await
        .map_err(CommandError::from)
}

/// Group the session's IP entities by /24 subnet.
#[tauri::command]
pub fn cmd_get_subnet_analysis(
    api: State<Arc<GraphHunterApi>>,
) -> Result<Vec<SubnetGroup>, CommandError> {
    api.get_subnet_analysis(SubnetAnalysisRequest::default())
        .map_err(CommandError::from)
}
