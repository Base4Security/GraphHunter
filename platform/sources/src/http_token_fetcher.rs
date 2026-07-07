//! HTTP-backed implementation of [`TokenFetcher`] that hits the Azure AD
//! v2 token endpoint.
//!
//! Implements the service-principal `client_credentials` flow against
//! `https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/token`.
//! This is the fallback auth path from plan §7 for headless/CI use.
//! The interactive PKCE browser flow (the recommended path for desktop
//! use) lands in Phase 6 on top of the same `TokenFetcher` trait.
//!
//! The fetcher is generic over [`HttpClient`] so tests can plug in
//! [`crate::http_client::MockHttpClient`] without any real HTTP.
//! Production callers pass a `reqwest`-backed client at the Tauri app
//! layer (Phase 4+).
//!
//! ## Request shape
//!
//! ```text
//! POST https://login.microsoftonline.com/{tenant}/oauth2/v2.0/token
//! Content-Type: application/x-www-form-urlencoded
//!
//! client_id={client_id}
//! &scope={resource_scope}
//! &client_secret={client_secret}
//! &grant_type=client_credentials
//! ```
//!
//! ## Response shape (success)
//!
//! ```json
//! {
//!   "token_type": "Bearer",
//!   "expires_in": 3599,
//!   "ext_expires_in": 3599,
//!   "access_token": "eyJ0eXA..."
//! }
//! ```
//!
//! ## Response shape (error)
//!
//! ```json
//! {
//!   "error": "invalid_client",
//!   "error_description": "AADSTS7000215: Invalid client secret..."
//! }
//! ```
//!
//! The fetcher parses both shapes and maps server-side errors into
//! [`TokenError::Fetch`] with a concise message.

use async_trait::async_trait;
use bytes::Bytes;
use std::sync::Arc;
use tokio_util::sync::CancellationToken;

use crate::http_client::{HttpClient, HttpRequest, StatusClass};
use crate::token_cache::{TokenError, TokenFetcher, TokenKey};

/// The default Azure AD token endpoint. Overridable for tests against a
/// mock authorization server.
pub const DEFAULT_AAD_AUTHORITY: &str = "https://login.microsoftonline.com";

/// An [`HttpClient`]-backed [`TokenFetcher`] using the Azure AD OAuth2
/// v2 token endpoint.
pub struct HttpTokenFetcher {
    http: Arc<dyn HttpClient>,
    client_id: String,
    client_secret: String,
    authority: String,
}

impl HttpTokenFetcher {
    /// Constructs a fetcher for a given service principal. The caller
    /// provides the shared HTTP client and the client credentials; the
    /// fetcher derives the token endpoint URL per-request from the
    /// `TokenKey.tenant_id`.
    pub fn new(
        http: Arc<dyn HttpClient>,
        client_id: impl Into<String>,
        client_secret: impl Into<String>,
    ) -> Self {
        Self {
            http,
            client_id: client_id.into(),
            client_secret: client_secret.into(),
            authority: DEFAULT_AAD_AUTHORITY.to_string(),
        }
    }

    /// Overrides the authority base URL. Used by tests to point at a
    /// mock OAuth server on `http://127.0.0.1:PORT`.
    pub fn with_authority(mut self, authority: impl Into<String>) -> Self {
        self.authority = authority.into();
        self
    }

    fn build_url(&self, tenant_id: &str) -> String {
        format!("{}/{}/oauth2/v2.0/token", self.authority, tenant_id)
    }

    fn build_body(&self, scope: &str) -> Bytes {
        // Form-urlencoded. Azure AD accepts `scope` with both plain and
        // percent-encoded forms; we percent-encode defensively because
        // scopes contain `:` and `/` which are reserved in query strings.
        let encoded_scope = url_encode(scope);
        let encoded_client_id = url_encode(&self.client_id);
        let encoded_secret = url_encode(&self.client_secret);
        let body = format!(
            "client_id={}&scope={}&client_secret={}&grant_type=client_credentials",
            encoded_client_id, encoded_scope, encoded_secret
        );
        Bytes::from(body.into_bytes())
    }
}

/// Minimal percent-encoder for form bodies. Encodes everything that
/// isn't an unreserved character per RFC 3986. Done by hand to avoid
/// pulling `url`/`percent-encoding` crates into graph_hunter_core.
fn url_encode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(b as char)
            }
            _ => out.push_str(&format!("%{:02X}", b)),
        }
    }
    out
}

#[async_trait]
impl TokenFetcher for HttpTokenFetcher {
    async fn fetch(&self, key: &TokenKey) -> Result<(String, u64), TokenError> {
        let url = self.build_url(&key.tenant_id);
        let body = self.build_body(&key.resource_scope);

        let req = HttpRequest::post(url).with_form_body(body);

        let resp = self
            .http
            .send(req, CancellationToken::new())
            .await
            .map_err(|e| TokenError::Fetch(format!("http: {e}")))?;

        match resp.status_class() {
            StatusClass::Success => parse_success_body(&resp.body),
            StatusClass::ClientError => {
                // Try to extract `error_description` from the body for
                // a useful message; fall back to status code.
                let msg = parse_error_body(&resp.body)
                    .unwrap_or_else(|| format!("status {}", resp.status));
                Err(TokenError::Fetch(msg))
            }
            _ => Err(TokenError::Fetch(format!("status {}", resp.status))),
        }
    }
}

/// Parses a successful token response. Uses `serde_json` (already a
/// transitive dep through `simd-json`/`serde_json`).
fn parse_success_body(body: &Bytes) -> Result<(String, u64), TokenError> {
    #[derive(serde::Deserialize)]
    struct SuccessBody {
        access_token: String,
        expires_in: u64,
    }
    let parsed: SuccessBody = serde_json::from_slice(body)
        .map_err(|e| TokenError::Fetch(format!("parse success body: {e}")))?;
    Ok((parsed.access_token, parsed.expires_in))
}

/// Parses an error response, extracting `error_description` if present.
/// Returns `None` if the body isn't parseable — caller falls back to the
/// raw status code.
fn parse_error_body(body: &Bytes) -> Option<String> {
    #[derive(serde::Deserialize)]
    struct ErrorBody {
        #[serde(default)]
        error: Option<String>,
        #[serde(default)]
        error_description: Option<String>,
    }
    let parsed: ErrorBody = serde_json::from_slice(body).ok()?;
    // Prefer the short error code + the first line of the description
    // (AADSTS error descriptions can be multi-line and very long; the
    // caller logs it, and long log lines hurt triage).
    let short_desc = parsed
        .error_description
        .as_deref()
        .and_then(|s| s.lines().next())
        .unwrap_or("");
    match (parsed.error, short_desc) {
        (Some(e), "") => Some(e),
        (Some(e), d) => Some(format!("{e}: {d}")),
        (None, "") => None,
        (None, d) => Some(d.to_string()),
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::http_client::{MockHttpClient, MockResponse};

    fn make_client(responses: Vec<MockResponse>) -> Arc<MockHttpClient> {
        let client = Arc::new(MockHttpClient::new());
        // Pre-queue on a blocking runtime since the tests that consume
        // this are tokio tests.
        let client_clone = client.clone();
        tokio::runtime::Handle::try_current()
            .unwrap_or_else(|_| {
                tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .unwrap()
                    .handle()
                    .clone()
            })
            .block_on(async {
                for r in responses {
                    client_clone.push(r).await;
                }
            });
        client
    }

    #[tokio::test(flavor = "current_thread")]
    async fn successful_fetch_parses_token() {
        let mock = Arc::new(MockHttpClient::new());
        mock.push(MockResponse::json(
            r#"{"token_type":"Bearer","expires_in":3599,"ext_expires_in":3599,"access_token":"eyJ0eXA.mock"}"#,
        ))
        .await;

        let fetcher = HttpTokenFetcher::new(
            mock.clone() as Arc<dyn HttpClient>,
            "client-abc",
            "secret-xyz",
        );
        let key = TokenKey::new("tenant-1", "https://api.loganalytics.io/.default");
        let (token, expires_in) = fetcher.fetch(&key).await.unwrap();
        assert_eq!(token, "eyJ0eXA.mock");
        assert_eq!(expires_in, 3599);

        // Verify the recorded request shape.
        let req = &mock.recorded().await[0];
        assert!(req.url.contains("tenant-1"));
        assert!(req.url.contains("/oauth2/v2.0/token"));
        let body = req.body.as_ref().unwrap();
        let body_str = std::str::from_utf8(body).unwrap();
        assert!(body_str.contains("client_id=client-abc"));
        assert!(body_str.contains("grant_type=client_credentials"));
        assert!(body_str.contains("scope=https%3A%2F%2Fapi.loganalytics.io%2F.default"));
        assert!(body_str.contains("client_secret=secret-xyz"));
    }

    #[tokio::test(flavor = "current_thread")]
    async fn error_body_extracted_from_4xx() {
        let mock = Arc::new(MockHttpClient::new());
        mock.push(MockResponse {
            status: 401,
            headers: Vec::new(),
            body: Bytes::from_static(
                br#"{"error":"invalid_client","error_description":"AADSTS7000215: Invalid client secret provided.\r\nTrace ID: abc"}"#,
            ),
        })
        .await;

        let fetcher = HttpTokenFetcher::new(
            mock.clone() as Arc<dyn HttpClient>,
            "client-abc",
            "wrong-secret",
        );
        let key = TokenKey::new("tenant-1", "scope-x");
        let err = fetcher.fetch(&key).await.unwrap_err();
        match err {
            TokenError::Fetch(msg) => {
                assert!(msg.contains("invalid_client"), "got: {msg}");
                assert!(msg.contains("AADSTS7000215"), "got: {msg}");
                // Multi-line description should be truncated at the
                // first newline.
                assert!(!msg.contains("Trace ID"), "got: {msg}");
            }
        }
    }

    #[tokio::test(flavor = "current_thread")]
    async fn server_error_surfaces_status_code() {
        let mock = Arc::new(MockHttpClient::new());
        mock.push(MockResponse::server_error("upstream boom")).await;
        let fetcher =
            HttpTokenFetcher::new(mock.clone() as Arc<dyn HttpClient>, "client-abc", "secret");
        let key = TokenKey::new("tenant-1", "scope-x");
        let err = fetcher.fetch(&key).await.unwrap_err();
        match err {
            TokenError::Fetch(msg) => {
                assert!(msg.contains("500"), "got: {msg}");
            }
        }
    }

    #[tokio::test(flavor = "current_thread")]
    async fn malformed_success_body_returns_fetch_error() {
        let mock = Arc::new(MockHttpClient::new());
        mock.push(MockResponse::json(r#"{"not_a_token": true}"#))
            .await;
        let fetcher = HttpTokenFetcher::new(mock.clone() as Arc<dyn HttpClient>, "c", "s");
        let err = fetcher.fetch(&TokenKey::new("t", "s")).await.unwrap_err();
        match err {
            TokenError::Fetch(msg) => assert!(msg.contains("parse success body")),
        }
    }

    #[test]
    fn url_encode_handles_reserved_characters() {
        assert_eq!(
            url_encode("https://api.loganalytics.io/.default"),
            "https%3A%2F%2Fapi.loganalytics.io%2F.default"
        );
        assert_eq!(url_encode("hello_world.1-2"), "hello_world.1-2");
        assert_eq!(url_encode("a b+c"), "a%20b%2Bc");
    }

    #[test]
    fn build_url_concatenates_tenant() {
        let mock = Arc::new(MockHttpClient::new());
        let fetcher = HttpTokenFetcher::new(mock as Arc<dyn HttpClient>, "cid", "sec")
            .with_authority("http://127.0.0.1:8081");
        assert_eq!(
            fetcher.build_url("my-tenant"),
            "http://127.0.0.1:8081/my-tenant/oauth2/v2.0/token"
        );
    }

    // Quiet the unused-function warning — keep the helper in case a
    // future test wants bulk-queue semantics.
    #[allow(dead_code)]
    fn _unused_make_client_helper() {
        let _ = make_client;
    }
}
