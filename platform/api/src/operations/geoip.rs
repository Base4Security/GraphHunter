//! GeoIP enrichment + capabilities detection + `/health` probe.
//!
//! The shape of `enrich_ip`: try offline MaxMind first, then HTTP
//! fallback, then dataset-metadata fallback (if the ingest pipeline
//! already attached geo fields). Writes results back into the
//! session's entity metadata so subsequent `get_node_details` calls
//! include the enrichment data.

use crate::dto::geoip::{
    ApiTestResult, Capabilities, EnrichIpRequest, EnrichIpResponse, GraphState,
    GraphSummaryRequest, GraphSummaryWithCapabilities,
};
use crate::util::resolve_api_port;
use crate::{ApiError, ApiResult, GraphHunterApi};

use graph_hunter_core::{geoip, ip_utils, write_geoip_to_metadata};

impl GraphHunterApi {
    /// Detect which on-demand enrichment backends are available to the
    /// current process. Synchronous — just probes the two Mutexes.
    pub fn capabilities(&self) -> Capabilities {
        let geoip_mmdb = self
            .inner
            .geoip_provider
            .try_lock()
            .ok()
            .map(|g| g.is_some())
            .unwrap_or(false);
        let geoip_http = self
            .inner
            .http_geoip_client
            .try_lock()
            .ok()
            .map(|g| g.is_some())
            .unwrap_or(false);
        let geoip_any = geoip_mmdb || geoip_http;
        Capabilities {
            geoip: geoip_any,
            asn: geoip_mmdb,
            threat_intel: false,
        }
    }

    /// Enrich a public IP with GeoIP data (country, city, ASN, ISP).
    /// Writes results into the entity's metadata so subsequent
    /// `get_node_details` calls include the enrichment.
    ///
    /// Errors with [`ApiError::InvalidInput`] for private / non-
    /// routable IPs. Async because the HTTP fallback awaits reqwest.
    pub async fn enrich_ip(&self, req: EnrichIpRequest) -> ApiResult<EnrichIpResponse> {
        // 2026-05-06: distinguish "not an IP" from "not routable" so a
        // typo on the input doesn't read as "private IP". Parse first,
        // classify second.
        if req.ip.trim().parse::<std::net::IpAddr>().is_err() {
            return Err(ApiError::InvalidInput(format!(
                "`{}` is not a valid IPv4/IPv6 address. enrich expects something like `8.8.8.8` or `2001:db8::1`.",
                req.ip
            )));
        }
        if !ip_utils::is_public(&req.ip) {
            return Err(ApiError::InvalidInput(format!(
                "IP {} is not a public/routable address. GeoIP enrichment is only available for external IPs.",
                req.ip
            )));
        }

        // 1. Try offline MaxMind first.
        let maxmind_result = {
            let provider =
                self.inner.geoip_provider.lock().map_err(|e| {
                    ApiError::Internal(format!("GeoIP provider lock poisoned: {e}"))
                })?;
            provider.as_ref().and_then(|p| p.lookup(&req.ip))
        };

        let result = if let Some(r) = maxmind_result {
            r
        } else {
            // 2. HTTP fallback. Clone the client out of the lock so we
            // don't hold it across the await boundary.
            let http_client = {
                let guard = self.inner.http_geoip_client.lock().map_err(|e| {
                    ApiError::Internal(format!("HTTP GeoIP client lock poisoned: {e}"))
                })?;
                guard.clone()
            };
            match http_client {
                Some(client) => {
                    let provider = geoip::http::HttpGeoIpProvider::new(client);
                    let cancel = tokio_util::sync::CancellationToken::new();
                    provider
                        .lookup(&req.ip, cancel)
                        .await
                        .map_err(|e| ApiError::Upstream {
                            service: "http-geoip".into(),
                            message: format!("lookup failed: {e}"),
                        })?
                }
                None => {
                    // 3. Dataset-metadata fallback: the ingest pipeline
                    // may have already attached geo/location fields.
                    // Surface them clearly marked instead of erroring
                    // — feedback explicitly asked for this on
                    // capability-off tenants.
                    let fallback = self.with_graph_read(req.session.as_ref(), |graph| {
                        Ok(graph
                            .get_entity(&req.ip)
                            .and_then(|e| geoip::geoip_from_metadata(&e.metadata)))
                    })?;
                    match fallback {
                        Some(meta_result) => meta_result,
                        None => {
                            return Err(ApiError::InvalidInput(format!(
                                "GeoIP enrichment unavailable for {}: this process has no MaxMind \
                                provider, no HTTP fallback client, and the entity's metadata carries \
                                no geo_country / geo_city / location fields. Check `test_http_api.capabilities` \
                                and `get_graph_summary.capabilities` — both surface `geoip:false` in \
                                this state — so MCP clients should skip `enrich_ip` when the capability \
                                is off. Restore enrichment by placing a GeoLite2 `.mmdb` file in the \
                                app's geoip directory.",
                                req.ip
                            )));
                        }
                    }
                }
            }
        };

        // Write back unless the source is dataset metadata (writing
        // back would clobber `source` provenance on re-lookups).
        let is_from_dataset = matches!(
            result.source,
            Some(graph_hunter_core::geoip::GeoIpSource::DatasetMetadata)
        );
        if !is_from_dataset {
            self.with_graph_write(req.session.as_ref(), |graph| {
                if let Some(entity) = graph.get_entity_mut(&req.ip) {
                    write_geoip_to_metadata(&mut entity.metadata, &result);
                }
                Ok(())
            })?;
        }

        Ok(result)
    }

    /// Ping the local HTTP API health endpoint and report capabilities
    /// in the same response. Useful as a one-shot readiness probe.
    ///
    /// Synchronous: uses `std::thread::scope` + `reqwest::blocking`
    /// under the hood because the caller typically isn't in an async
    /// context when invoking this. The small window of blocking a
    /// runtime thread is acceptable — request timeout is 2s.
    pub fn test_http_api(&self) -> ApiResult<ApiTestResult> {
        use std::error::Error;

        let caps = self.capabilities();
        let port = resolve_api_port();
        let url = format!("http://127.0.0.1:{port}/health");
        let caps_for_thread = caps.clone();

        let result: ApiResult<ApiTestResult> = std::thread::scope(|s| {
            s.spawn(|| {
                // Quick TCP probe: can we reach the port at all?
                let addr = std::net::SocketAddr::from(([127, 0, 0, 1], port));
                let tcp_ok = std::net::TcpStream::connect_timeout(
                    &addr,
                    std::time::Duration::from_secs(2),
                )
                .is_ok();
                if !tcp_ok {
                    return Ok(ApiTestResult {
                        ok: false,
                        status: None,
                        message: format!(
                            "Cannot connect to 127.0.0.1:{port} — connection refused. Is the HTTP API thread running? Check the terminal for \"GraphHunter HTTP API listening\"."
                        ),
                        body: None,
                        capabilities: caps_for_thread.clone(),
                    });
                }

                let client = match reqwest::blocking::Client::builder()
                    .timeout(std::time::Duration::from_secs(5))
                    .build()
                {
                    Ok(c) => c,
                    Err(e) => {
                        return Err(ApiError::Internal(format!("reqwest build failed: {e}")))
                    }
                };
                match client.get(&url).send() {
                    Ok(resp) => {
                        let status = resp.status();
                        let code = status.as_u16();
                        let body = resp.text().ok();
                        let ok = status.is_success();
                        Ok(ApiTestResult {
                            ok,
                            status: Some(code),
                            message: if ok {
                                "API responded OK.".to_string()
                            } else {
                                format!("API returned HTTP {code}")
                            },
                            body,
                            capabilities: caps_for_thread.clone(),
                        })
                    }
                    Err(e) => {
                        let mut msg = e.to_string();
                        if let Some(source) = e.source() {
                            msg.push_str(" (");
                            msg.push_str(&source.to_string());
                            msg.push(')');
                        }
                        Ok(ApiTestResult {
                            ok: false,
                            status: None,
                            message: format!(
                                "Port {port} is open but HTTP request failed: {msg}"
                            ),
                            body: None,
                            capabilities: caps_for_thread.clone(),
                        })
                    }
                }
            })
            .join()
            .map_err(|_| ApiError::Internal("Test thread panicked".into()))?
        });
        result
    }

    /// Lightweight `(entity_count, relation_count)` for the current session,
    /// or `None` when no session is loaded (or the lock is momentarily
    /// contended). Lets `/health` report `graph_state` without paying for the
    /// full `get_graph_summary` (type distribution + top anomalies).
    pub fn current_graph_counts(&self) -> Option<(usize, usize)> {
        let session = self.sessions().current_session()?;
        let graph = session.graph.read().ok()?;
        Some((graph.entity_count(), graph.relation_count()))
    }

    /// The most recent `graph_build` record for the current session (§5
    /// `last_build`), or `None` when nothing has been materialized.
    pub fn current_last_build(&self) -> Option<crate::dto::sentinel::BuildRecord> {
        let session = self.sessions().current_session()?;
        session.last_build.read().ok()?.clone()
    }

    /// Graph summary + runtime capabilities in one shot. Frontend uses
    /// this to build its "at-a-glance" banner; MCP tools use it to
    /// decide whether to call `enrich_ip` at all.
    pub fn get_graph_summary(
        &self,
        req: GraphSummaryRequest,
    ) -> ApiResult<GraphSummaryWithCapabilities> {
        let summary = self.with_graph_read(req.session.as_ref(), |g| Ok(g.get_graph_summary()))?;
        let (graph_state, advisory) =
            GraphState::classify(summary.entity_count, summary.relation_count);
        // §5: surface the session's most recent build alongside the counts.
        let last_build = self
            .resolve_session(req.session.as_ref())
            .ok()
            .and_then(|s| s.last_build.read().ok().and_then(|b| b.clone()));
        Ok(GraphSummaryWithCapabilities {
            summary,
            capabilities: self.capabilities(),
            graph_state,
            advisory,
            last_build,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn graph_state_classify_thresholds() {
        // Empty: zero entities → advisory points at seed/schema.
        let (state, advisory) = GraphState::classify(0, 0);
        assert_eq!(state, GraphState::Empty);
        assert!(advisory.unwrap().contains("sentinel_seed"));

        // Partial: a seed-sized graph (few entities) → expand advisory.
        let (state, advisory) = GraphState::classify(3, 2);
        assert_eq!(state, GraphState::Partial);
        assert!(advisory.unwrap().contains("node_expand"));

        // Partial: entities but no edges is still not worth traversing.
        let (state, _) = GraphState::classify(50, 0);
        assert_eq!(state, GraphState::Partial);

        // Populated: enough entities and edges → no advisory.
        let (state, advisory) = GraphState::classify(50, 120);
        assert_eq!(state, GraphState::Populated);
        assert!(advisory.is_none());
    }

    #[test]
    fn capabilities_default_is_all_false() {
        let api = GraphHunterApi::new_noop();
        let caps = api.capabilities();
        assert!(!caps.geoip);
        assert!(!caps.asn);
        assert!(!caps.threat_intel);
    }

    #[test]
    fn graph_summary_surfaces_last_build() {
        use crate::dto::session::CreateSessionRequest;
        let api = GraphHunterApi::new_noop();
        api.create_session(CreateSessionRequest { name: Some("lb-test".into()) }).unwrap();
        // No build yet → last_build absent.
        let before = api.get_graph_summary(GraphSummaryRequest::default()).unwrap();
        assert!(before.last_build.is_none());

        // Record a build, then it must surface in the summary (§5).
        {
            let session = api.resolve_session(None).unwrap();
            *session.last_build.write().unwrap() =
                Some(crate::dto::sentinel::BuildRecord {
                    build_id: "build-abc123".into(),
                    proposal_id: "signinlogs-user-ip".into(),
                    at: 1_700_000_000,
                    entities_created: 1238,
                    relations_created: 4791,
                    merge_mode: "append".into(),
                });
        }
        let after = api.get_graph_summary(GraphSummaryRequest::default()).unwrap();
        let lb = after.last_build.expect("last_build surfaced");
        assert_eq!(lb.build_id, "build-abc123");
        assert_eq!(lb.relations_created, 4791);
    }

    #[tokio::test]
    async fn enrich_ip_rejects_private() {
        let api = GraphHunterApi::new_noop();
        // No session needed — early rejection before any graph access.
        let err = api
            .enrich_ip(EnrichIpRequest {
                session: None,
                ip: "192.168.1.1".into(),
            })
            .await
            .unwrap_err();
        assert!(matches!(err, ApiError::InvalidInput(_)));
    }
}
