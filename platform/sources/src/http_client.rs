//! Pluggable HTTP client abstraction used by every [`LogSource`] impl and
//! by [`HttpTokenFetcher`].
//!
//! ## Why a trait instead of depending on `reqwest` directly
//!
//! 1. **Disk-constrained dev machines.** Adding `reqwest` + `hyper` +
//!    `rustls` + transitive certs to `graph_hunter_core` expands the
//!    target directory by 500 MB–1 GB. On the current dev machine that
//!    margin doesn't exist. The trait defers the real HTTP dependency
//!    to whichever crate wires in the Source impls at runtime
//!    (`app/src-tauri` already has `reqwest` in its dep closure, so
//!    Phase 4 gets it for free).
//!
//! 2. **Unit testability.** With a trait, every Source impl can be
//!    exercised end-to-end with a `MockHttpClient` that returns canned
//!    responses — no `wiremock` crate, no Tokio HTTP listener, no
//!    flakiness from loopback sockets. Tests run in microseconds.
//!
//! 3. **Cancellation and timeout are concerns the implementation owns,
//!    not the caller.** Passing a `CancellationToken` through the trait
//!    keeps the cancellation story uniform across Source impls, which
//!    the existing `sentinel_connector.rs` polling loop needs.
//!
//! The intended production path is: at the Tauri-app layer (Phase 4),
//! implement `HttpClient` for a thin wrapper around `reqwest::Client`.
//! Pass `Arc<dyn HttpClient>` into `LogAnalyticsSource::new(...)` at
//! startup. The Source impl is reqwest-agnostic.
//!
//! [`LogSource`]: crate::LogSource
//! [`HttpTokenFetcher`]: crate::http_token_fetcher::HttpTokenFetcher

use async_trait::async_trait;
use bytes::Bytes;
use std::collections::HashMap;
use std::time::Duration;
use tokio_util::sync::CancellationToken;

/// HTTP methods we actually use. Not a full set — extend as needed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HttpMethod {
    Get,
    Post,
    Put,
    Delete,
}

impl HttpMethod {
    pub fn as_str(self) -> &'static str {
        match self {
            HttpMethod::Get => "GET",
            HttpMethod::Post => "POST",
            HttpMethod::Put => "PUT",
            HttpMethod::Delete => "DELETE",
        }
    }
}

/// An HTTP request. Owned data throughout — safe to move across tasks.
#[derive(Debug, Clone)]
pub struct HttpRequest {
    pub method: HttpMethod,
    pub url: String,
    /// Headers as `(name, value)` pairs. Not a `HashMap` because order can
    /// matter for some APIs (e.g., `Authorization` before `Content-Type`
    /// in certain diagnostic middleware).
    pub headers: Vec<(String, String)>,
    pub body: Option<Bytes>,
    /// Per-request timeout. `None` means use the client's default.
    pub timeout: Option<Duration>,
}

impl HttpRequest {
    pub fn get(url: impl Into<String>) -> Self {
        Self {
            method: HttpMethod::Get,
            url: url.into(),
            headers: Vec::new(),
            body: None,
            timeout: None,
        }
    }

    pub fn post(url: impl Into<String>) -> Self {
        Self {
            method: HttpMethod::Post,
            url: url.into(),
            headers: Vec::new(),
            body: None,
            timeout: None,
        }
    }

    pub fn with_header(mut self, name: impl Into<String>, value: impl Into<String>) -> Self {
        self.headers.push((name.into(), value.into()));
        self
    }

    pub fn with_bearer(self, token: &str) -> Self {
        self.with_header("Authorization", format!("Bearer {token}"))
    }

    pub fn with_json_body(mut self, body: Bytes) -> Self {
        self.headers
            .push(("Content-Type".to_string(), "application/json".to_string()));
        self.body = Some(body);
        self
    }

    pub fn with_form_body(mut self, body: Bytes) -> Self {
        self.headers.push((
            "Content-Type".to_string(),
            "application/x-www-form-urlencoded".to_string(),
        ));
        self.body = Some(body);
        self
    }

    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = Some(timeout);
        self
    }
}

/// An HTTP response. Body is held as `Bytes` so implementations can hand
/// ownership off without cloning (matches the `RawChunk.rows` contract).
#[derive(Debug, Clone)]
pub struct HttpResponse {
    pub status: u16,
    pub headers: HashMap<String, String>,
    pub body: Bytes,
}

impl HttpResponse {
    pub fn is_success(&self) -> bool {
        (200..300).contains(&self.status)
    }

    /// Returns the `Retry-After` header parsed as a `Duration` if present.
    /// Accepts only the "delta-seconds" form (integer); the HTTP-date form
    /// is not supported — Azure services use seconds universally.
    pub fn retry_after(&self) -> Option<Duration> {
        self.headers
            .get("retry-after")
            .or_else(|| self.headers.get("Retry-After"))
            .and_then(|v| v.parse::<u64>().ok())
            .map(Duration::from_secs)
    }

    /// Convenience for pattern-matching on the status code class.
    pub fn status_class(&self) -> StatusClass {
        match self.status {
            200..=299 => StatusClass::Success,
            300..=399 => StatusClass::Redirect,
            400..=499 => StatusClass::ClientError,
            500..=599 => StatusClass::ServerError,
            _ => StatusClass::Other,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StatusClass {
    Success,
    Redirect,
    ClientError,
    ServerError,
    Other,
}

/// Errors from an HTTP call. Implementations should map their native
/// errors (reqwest, hyper, native-tls, etc.) into this enum so the
/// Source impls can react uniformly without knowing the backend.
#[derive(Debug, Clone)]
pub enum HttpError {
    /// TCP / TLS / DNS failure. Transient; retry with backoff.
    Transport(String),
    /// Request exceeded the per-request or client-level timeout.
    Timeout,
    /// The request was cancelled via the `CancellationToken`.
    Cancelled,
    /// The backend refused to build the request (invalid URL, bad
    /// headers, etc.). Non-retriable.
    Invalid(String),
}

impl std::fmt::Display for HttpError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            HttpError::Transport(msg) => write!(f, "transport error: {msg}"),
            HttpError::Timeout => write!(f, "request timed out"),
            HttpError::Cancelled => write!(f, "request cancelled"),
            HttpError::Invalid(msg) => write!(f, "invalid request: {msg}"),
        }
    }
}

impl std::error::Error for HttpError {}

/// The trait every HTTP client implementation satisfies. Must be
/// `Send + Sync` so it can be shared across connector tasks via
/// `Arc<dyn HttpClient>`.
#[async_trait]
pub trait HttpClient: Send + Sync {
    /// Dispatches a request and waits for the response. Must observe
    /// `cancel` and return `HttpError::Cancelled` if the token is
    /// cancelled before the response arrives.
    async fn send(
        &self,
        req: HttpRequest,
        cancel: CancellationToken,
    ) -> Result<HttpResponse, HttpError>;
}

// ---------------------------------------------------------------------------
// Mock HTTP client for unit tests. Not feature-gated on `#[cfg(test)]`
// because downstream crates may want to use it for their own tests.
// ---------------------------------------------------------------------------

/// Pre-programmed mock response for a `MockHttpClient`.
#[derive(Debug, Clone)]
pub struct MockResponse {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub body: Bytes,
}

impl MockResponse {
    pub fn ok(body: Bytes) -> Self {
        Self {
            status: 200,
            headers: Vec::new(),
            body,
        }
    }

    pub fn json(body: &str) -> Self {
        Self {
            status: 200,
            headers: vec![("content-type".to_string(), "application/json".to_string())],
            body: Bytes::copy_from_slice(body.as_bytes()),
        }
    }

    pub fn throttled(retry_after_secs: u64) -> Self {
        Self {
            status: 429,
            headers: vec![("retry-after".to_string(), retry_after_secs.to_string())],
            body: Bytes::new(),
        }
    }

    pub fn unauthorized() -> Self {
        Self {
            status: 401,
            headers: Vec::new(),
            body: Bytes::new(),
        }
    }

    pub fn server_error(body: &str) -> Self {
        Self {
            status: 500,
            headers: Vec::new(),
            body: Bytes::copy_from_slice(body.as_bytes()),
        }
    }
}

/// A mock HTTP client that returns pre-programmed responses in order
/// and records every request. Intended for unit tests of Source and
/// TokenFetcher impls.
///
/// Construct with [`MockHttpClient::new`], push responses with
/// [`MockHttpClient::push`], then pass as `Arc<MockHttpClient>` into
/// the code under test. Inspect recorded requests via
/// [`MockHttpClient::recorded`].
pub struct MockHttpClient {
    responses: tokio::sync::Mutex<std::collections::VecDeque<MockResponse>>,
    recorded: tokio::sync::Mutex<Vec<HttpRequest>>,
}

impl MockHttpClient {
    pub fn new() -> Self {
        Self {
            responses: tokio::sync::Mutex::new(std::collections::VecDeque::new()),
            recorded: tokio::sync::Mutex::new(Vec::new()),
        }
    }

    /// Queues a response for the next call to `send`.
    pub async fn push(&self, response: MockResponse) {
        self.responses.lock().await.push_back(response);
    }

    /// Queues the same response for every subsequent call. Useful for
    /// tests that fire many retries and don't care which attempt gets
    /// which response.
    pub async fn push_many(&self, response: MockResponse, count: usize) {
        let mut q = self.responses.lock().await;
        for _ in 0..count {
            q.push_back(response.clone());
        }
    }

    /// Returns every request received so far, in order.
    pub async fn recorded(&self) -> Vec<HttpRequest> {
        self.recorded.lock().await.clone()
    }

    /// Returns the number of recorded requests.
    pub async fn call_count(&self) -> usize {
        self.recorded.lock().await.len()
    }
}

impl Default for MockHttpClient {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl HttpClient for MockHttpClient {
    async fn send(
        &self,
        req: HttpRequest,
        cancel: CancellationToken,
    ) -> Result<HttpResponse, HttpError> {
        if cancel.is_cancelled() {
            return Err(HttpError::Cancelled);
        }
        self.recorded.lock().await.push(req.clone());
        let response = {
            let mut q = self.responses.lock().await;
            q.pop_front()
        };
        match response {
            Some(resp) => Ok(HttpResponse {
                status: resp.status,
                headers: resp.headers.into_iter().collect(),
                body: resp.body,
            }),
            None => Err(HttpError::Transport(format!(
                "MockHttpClient: no queued response for {} {}",
                req.method.as_str(),
                req.url
            ))),
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test(flavor = "current_thread")]
    async fn mock_records_requests_and_serves_in_order() {
        let client = MockHttpClient::new();
        client.push(MockResponse::json(r#"{"a":1}"#)).await;
        client.push(MockResponse::unauthorized()).await;

        let r1 = client
            .send(
                HttpRequest::get("https://example.com/a"),
                CancellationToken::new(),
            )
            .await
            .unwrap();
        assert!(r1.is_success());
        assert_eq!(
            r1.headers.get("content-type"),
            Some(&"application/json".to_string())
        );
        assert_eq!(r1.body, Bytes::from_static(br#"{"a":1}"#));

        let r2 = client
            .send(
                HttpRequest::post("https://example.com/b"),
                CancellationToken::new(),
            )
            .await
            .unwrap();
        assert_eq!(r2.status, 401);
        assert!(!r2.is_success());

        assert_eq!(client.call_count().await, 2);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn mock_returns_cancelled_when_token_is_cancelled() {
        let client = MockHttpClient::new();
        client.push(MockResponse::ok(Bytes::new())).await;
        let cancel = CancellationToken::new();
        cancel.cancel();
        let err = client
            .send(HttpRequest::get("https://example.com"), cancel)
            .await
            .unwrap_err();
        matches!(err, HttpError::Cancelled);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn retry_after_parses_delta_seconds() {
        let client = MockHttpClient::new();
        client.push(MockResponse::throttled(42)).await;
        let resp = client
            .send(
                HttpRequest::get("https://example.com"),
                CancellationToken::new(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status, 429);
        assert_eq!(resp.retry_after(), Some(Duration::from_secs(42)));
        assert_eq!(resp.status_class(), StatusClass::ClientError);
    }

    #[test]
    fn request_builder_methods() {
        let req = HttpRequest::post("https://api.loganalytics.io/v1/workspaces/w/query")
            .with_bearer("abc123")
            .with_header("x-ms-client-request-id", "req-1")
            .with_json_body(Bytes::from_static(br#"{"query":"..."}"#));

        assert_eq!(req.method, HttpMethod::Post);
        assert_eq!(req.headers.len(), 3); // bearer, x-ms, content-type
        assert_eq!(req.headers[0].0, "Authorization");
        assert_eq!(req.headers[0].1, "Bearer abc123");
        assert!(req.body.is_some());
    }

    #[test]
    fn status_class_mapping() {
        let ok = HttpResponse {
            status: 200,
            headers: HashMap::new(),
            body: Bytes::new(),
        };
        assert_eq!(ok.status_class(), StatusClass::Success);

        let redirect = HttpResponse {
            status: 302,
            headers: HashMap::new(),
            body: Bytes::new(),
        };
        assert_eq!(redirect.status_class(), StatusClass::Redirect);

        let throttled = HttpResponse {
            status: 429,
            headers: HashMap::new(),
            body: Bytes::new(),
        };
        assert_eq!(throttled.status_class(), StatusClass::ClientError);

        let down = HttpResponse {
            status: 503,
            headers: HashMap::new(),
            body: Bytes::new(),
        };
        assert_eq!(down.status_class(), StatusClass::ServerError);
    }
}
