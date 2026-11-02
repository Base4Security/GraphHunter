//! Live `HttpClient` backed by `reqwest`.
//!
//! `graph_hunter_sources::http_client` defines the `HttpClient` trait and
//! ships only `MockHttpClient`; its module docs describe wrapping
//! `reqwest::Client` and installing it "at startup" — but nothing ever
//! did. Every consumer that needed a live client therefore had none,
//! silently. The visible symptom was the ip-api.com GeoIP fallback: the
//! provider is constructed only when `http_geoip_client` holds a client
//! (`operations/geoip.rs`), that slot was never assigned by anyone, so
//! `enrich_ip` could never use the HTTP path and `capabilities.geoip`
//! reported `false` even on builds that compiled the `geoip` feature in.
//!
//! This module is that missing wrapper.

use std::collections::HashMap;
use std::time::Duration;

use graph_hunter_core::{HttpClient, HttpError, HttpMethod, HttpRequest, HttpResponse};
use tokio_util::sync::CancellationToken;

/// Default per-client timeout when a request carries no explicit one.
const DEFAULT_TIMEOUT: Duration = Duration::from_secs(30);

/// `reqwest`-backed [`HttpClient`].
pub struct ReqwestHttpClient {
    client: reqwest::Client,
}

impl ReqwestHttpClient {
    /// Builds a client with the default timeout.
    pub fn new() -> Result<Self, String> {
        Self::with_timeout(DEFAULT_TIMEOUT)
    }

    pub fn with_timeout(timeout: Duration) -> Result<Self, String> {
        let client = reqwest::Client::builder()
            .timeout(timeout)
            .build()
            .map_err(|e| format!("failed to build reqwest client: {e}"))?;
        Ok(Self { client })
    }
}

/// Maps a `reqwest::Error` onto the transport-agnostic [`HttpError`].
/// `is_builder`/`is_request` are non-retriable (bad URL, bad headers);
/// timeouts get their own variant so backoff logic can distinguish them
/// from connection failures.
fn map_err(e: reqwest::Error) -> HttpError {
    if e.is_timeout() {
        HttpError::Timeout
    } else if e.is_builder() || e.is_request() {
        HttpError::Invalid(e.to_string())
    } else {
        HttpError::Transport(e.to_string())
    }
}

#[async_trait::async_trait]
impl HttpClient for ReqwestHttpClient {
    async fn send(
        &self,
        req: HttpRequest,
        cancel: CancellationToken,
    ) -> Result<HttpResponse, HttpError> {
        if cancel.is_cancelled() {
            return Err(HttpError::Cancelled);
        }

        let method = match req.method {
            HttpMethod::Get => reqwest::Method::GET,
            HttpMethod::Post => reqwest::Method::POST,
            HttpMethod::Put => reqwest::Method::PUT,
            HttpMethod::Delete => reqwest::Method::DELETE,
        };

        let mut builder = self.client.request(method, &req.url);
        for (name, value) in &req.headers {
            builder = builder.header(name, value);
        }
        if let Some(body) = req.body {
            builder = builder.body(body);
        }
        if let Some(t) = req.timeout {
            builder = builder.timeout(t);
        }

        // The trait contract requires observing `cancel` and returning
        // `Cancelled` — racing the in-flight request against the token
        // drops the request future on cancellation.
        let response = tokio::select! {
            biased;
            _ = cancel.cancelled() => return Err(HttpError::Cancelled),
            res = builder.send() => res.map_err(map_err)?,
        };

        let status = response.status().as_u16();
        // Header names are lowercased by hyper; `HttpResponse::retry_after`
        // probes both cases, so storing them as received is correct.
        let headers: HashMap<String, String> = response
            .headers()
            .iter()
            .filter_map(|(k, v)| {
                v.to_str()
                    .ok()
                    .map(|v| (k.as_str().to_string(), v.to_string()))
            })
            .collect();

        let body = tokio::select! {
            biased;
            _ = cancel.cancelled() => return Err(HttpError::Cancelled),
            b = response.bytes() => b.map_err(map_err)?,
        };

        Ok(HttpResponse {
            status,
            headers,
            body,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builds_with_default_timeout() {
        assert!(ReqwestHttpClient::new().is_ok());
    }

    /// An already-cancelled token must short-circuit before any socket
    /// work — the trait contract's `Cancelled` case.
    #[tokio::test]
    async fn cancelled_token_short_circuits() {
        let client = ReqwestHttpClient::new().expect("client");
        let cancel = CancellationToken::new();
        cancel.cancel();
        let req = HttpRequest::get("http://127.0.0.1:9/never");
        let err = client.send(req, cancel).await.unwrap_err();
        assert!(matches!(err, HttpError::Cancelled), "got {err:?}");
    }

    /// A malformed URL is a builder error, not a transport error — it must
    /// never be retried by backoff logic.
    #[tokio::test]
    async fn bad_url_is_invalid_not_transport() {
        let client = ReqwestHttpClient::new().expect("client");
        let req = HttpRequest::get("not-a-url");
        let err = client
            .send(req, CancellationToken::new())
            .await
            .unwrap_err();
        assert!(matches!(err, HttpError::Invalid(_)), "got {err:?}");
    }
}
