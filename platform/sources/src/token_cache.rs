//! Azure AD access-token cache with proactive refresh.
//!
//! Generalizes the existing `SentinelTokenCache` from
//! `graph_hunter_cli/src/siem/sentinel_streaming.rs` to hold tokens for
//! multiple Azure surfaces simultaneously. Keyed on
//! `(tenant_id, resource_scope)` because the Log Analytics API, Defender
//! XDR Advanced Hunting, Sentinel Data Lake v2, and Blob Storage each
//! authenticate against a different audience (`.default` scope) and
//! therefore need distinct access tokens even for the same tenant.
//!
//! Concurrency model: a single async [`RwLock`] protects the cache map.
//! Reads are on the fast path; the slow path upgrades to a write lock,
//! re-checks (in case another task refreshed concurrently), then fetches
//! via the pluggable [`TokenFetcher`] trait. This is the double-checked
//! locking pattern the existing `SentinelTokenCache` already uses,
//! extended across multiple keys.
//!
//! The [`TokenFetcher`] trait is the DIP hook that keeps this module
//! testable: the real HTTP fetcher lives in
//! `graph_hunter_core::sources::log_analytics` (and the other source
//! adapters in Phase 3); tests use a `Mutex<u32>`-backed mock that
//! counts calls to assert caching behavior.

use async_trait::async_trait;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::RwLock;

/// Default proactive-refresh horizon. If a cached token expires within
/// this duration from now, we refetch instead of returning it. Matches
/// the existing `SentinelTokenCache` default so the generalization is
/// behavior-preserving.
pub const DEFAULT_REFRESH_HORIZON: Duration = Duration::from_secs(60);

/// Key into the token cache. Two tokens with the same `tenant_id` but
/// different `resource_scope` are distinct cache entries because Azure
/// mints a separate access token per audience.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct TokenKey {
    pub tenant_id: String,
    pub resource_scope: String,
}

impl TokenKey {
    pub fn new(tenant_id: impl Into<String>, resource_scope: impl Into<String>) -> Self {
        Self {
            tenant_id: tenant_id.into(),
            resource_scope: resource_scope.into(),
        }
    }
}

/// A cached access token with its expiry deadline.
#[derive(Clone, Debug)]
pub struct CachedToken {
    pub access_token: String,
    pub expires_at: Instant,
}

impl CachedToken {
    /// Returns true if this token is still fresh — i.e., its expiry is
    /// more than `horizon` away from the current instant. Tokens within
    /// the horizon are treated as stale so the cache refetches before
    /// they actually expire.
    pub fn is_fresh(&self, horizon: Duration) -> bool {
        self.expires_at
            .checked_duration_since(Instant::now())
            .map(|remaining| remaining > horizon)
            .unwrap_or(false)
    }
}

/// Error variants from token acquisition. Kept small — the underlying
/// HTTP/auth error details are surfaced via `TokenError::Fetch(String)`
/// so this module stays independent of `reqwest`/`oauth2` specifics.
#[derive(Debug, Clone)]
pub enum TokenError {
    /// The fetcher returned an error (HTTP, auth rejection, parse
    /// failure). The inner string is the fetcher's error message.
    Fetch(String),
}

impl std::fmt::Display for TokenError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TokenError::Fetch(msg) => write!(f, "token fetch failed: {msg}"),
        }
    }
}

impl std::error::Error for TokenError {}

/// DIP trait for the "actually go fetch a token from Azure AD" step.
/// The real implementation (Phase 3) wraps `reqwest` to hit
/// `https://login.microsoftonline.com/{tenant}/oauth2/v2.0/token`.
/// Tests use an in-memory mock that counts calls.
#[async_trait]
pub trait TokenFetcher: Send + Sync {
    /// Fetches a new access token for the given `(tenant, scope)` pair.
    /// Returns the token string and its `expires_in` (seconds) as
    /// reported by the authorization server.
    async fn fetch(&self, key: &TokenKey) -> Result<(String, u64), TokenError>;
}

/// Azure AD access-token cache.
///
/// Thread-safe (send + sync via the inner `RwLock`). Construct once at
/// app startup and share via `Arc<AzureTokenCache>`. The per-source
/// polling loops and on-demand enrichment tasks call [`get_token`] on
/// every request and rely on the cache to amortize the auth round-trip.
pub struct AzureTokenCache {
    tokens: RwLock<HashMap<TokenKey, CachedToken>>,
    fetcher: Arc<dyn TokenFetcher>,
    refresh_horizon: Duration,
}

impl AzureTokenCache {
    pub fn new(fetcher: Arc<dyn TokenFetcher>) -> Self {
        Self {
            tokens: RwLock::new(HashMap::new()),
            fetcher,
            refresh_horizon: DEFAULT_REFRESH_HORIZON,
        }
    }

    /// Overrides the proactive-refresh horizon. Shorter = more refresh
    /// calls, fresher tokens. Longer = fewer calls, higher risk of
    /// serving a token that expires mid-request.
    pub fn with_refresh_horizon(mut self, horizon: Duration) -> Self {
        self.refresh_horizon = horizon;
        self
    }

    /// Returns a fresh access token for the given key. If the cached
    /// token is still fresh (more than `refresh_horizon` from expiry),
    /// returns it; otherwise fetches a new one.
    pub async fn get_token(&self, key: &TokenKey) -> Result<String, TokenError> {
        // Fast path: read lock.
        {
            let tokens = self.tokens.read().await;
            if let Some(cached) = tokens.get(key) {
                if cached.is_fresh(self.refresh_horizon) {
                    return Ok(cached.access_token.clone());
                }
            }
        }

        // Slow path: upgrade to write lock and re-check. Another task
        // may have refreshed this key in the gap between releasing the
        // read lock and acquiring the write lock.
        let mut tokens = self.tokens.write().await;
        if let Some(cached) = tokens.get(key) {
            if cached.is_fresh(self.refresh_horizon) {
                return Ok(cached.access_token.clone());
            }
        }

        let (access_token, expires_in) = self.fetcher.fetch(key).await?;
        let cached = CachedToken {
            access_token: access_token.clone(),
            expires_at: Instant::now() + Duration::from_secs(expires_in),
        };
        tokens.insert(key.clone(), cached);
        Ok(access_token)
    }

    /// Forces a refetch on the next `get_token` call by dropping the
    /// cached entry. Use this when an HTTP 401 rejects a token that the
    /// cache still considers fresh — for example, when the admin rotated
    /// the client secret or revoked the app.
    pub async fn invalidate(&self, key: &TokenKey) {
        let mut tokens = self.tokens.write().await;
        tokens.remove(key);
    }

    /// Drops every cached entry. Used on global sign-out.
    pub async fn clear(&self) {
        let mut tokens = self.tokens.write().await;
        tokens.clear();
    }

    /// Returns the number of cached entries. For metrics / debugging.
    pub async fn len(&self) -> usize {
        self.tokens.read().await.len()
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU32, Ordering};

    /// Mock fetcher that counts calls and returns a synthetic token
    /// whose expiry is configurable at construction. Used by every test
    /// in this file.
    struct CountingFetcher {
        calls: Arc<AtomicU32>,
        expires_in_seconds: u64,
    }

    impl CountingFetcher {
        fn new(expires_in_seconds: u64) -> (Arc<Self>, Arc<AtomicU32>) {
            let calls = Arc::new(AtomicU32::new(0));
            let fetcher = Arc::new(Self {
                calls: calls.clone(),
                expires_in_seconds,
            });
            (fetcher, calls)
        }
    }

    #[async_trait]
    impl TokenFetcher for CountingFetcher {
        async fn fetch(&self, key: &TokenKey) -> Result<(String, u64), TokenError> {
            let n = self.calls.fetch_add(1, Ordering::SeqCst) + 1;
            Ok((
                format!("token_{}_{}:{}", key.tenant_id, key.resource_scope, n),
                self.expires_in_seconds,
            ))
        }
    }

    #[tokio::test(flavor = "current_thread")]
    async fn first_call_fetches_second_call_caches() {
        let (fetcher, calls) = CountingFetcher::new(3600);
        let cache = AzureTokenCache::new(fetcher);
        let key = TokenKey::new("tenant-a", "https://api.loganalytics.io/.default");

        let t1 = cache.get_token(&key).await.unwrap();
        let t2 = cache.get_token(&key).await.unwrap();

        assert_eq!(t1, t2, "second call should return the cached token");
        assert_eq!(
            calls.load(Ordering::SeqCst),
            1,
            "fetcher should be called exactly once"
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn different_keys_get_independent_tokens() {
        let (fetcher, calls) = CountingFetcher::new(3600);
        let cache = AzureTokenCache::new(fetcher);

        let la_key = TokenKey::new("tenant-a", "https://api.loganalytics.io/.default");
        let xdr_key = TokenKey::new("tenant-a", "https://api.security.microsoft.com/.default");

        let la_token = cache.get_token(&la_key).await.unwrap();
        let xdr_token = cache.get_token(&xdr_key).await.unwrap();

        assert_ne!(
            la_token, xdr_token,
            "tokens for different scopes must be distinct"
        );
        assert_eq!(calls.load(Ordering::SeqCst), 2);
        assert_eq!(cache.len().await, 2);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn invalidate_forces_refetch() {
        let (fetcher, calls) = CountingFetcher::new(3600);
        let cache = AzureTokenCache::new(fetcher);
        let key = TokenKey::new("tenant-a", "https://api.loganalytics.io/.default");

        let t1 = cache.get_token(&key).await.unwrap();
        cache.invalidate(&key).await;
        let t2 = cache.get_token(&key).await.unwrap();

        assert_ne!(t1, t2, "after invalidate, a fresh fetch should happen");
        assert_eq!(calls.load(Ordering::SeqCst), 2);
        assert_eq!(cache.len().await, 1);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn clear_drops_all_entries() {
        let (fetcher, _calls) = CountingFetcher::new(3600);
        let cache = AzureTokenCache::new(fetcher);

        cache
            .get_token(&TokenKey::new("tenant-a", "scope-1"))
            .await
            .unwrap();
        cache
            .get_token(&TokenKey::new("tenant-b", "scope-2"))
            .await
            .unwrap();
        assert_eq!(cache.len().await, 2);

        cache.clear().await;
        assert_eq!(cache.len().await, 0);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn expired_token_triggers_refetch() {
        // expires_in = 1s and refresh_horizon = 5s → the token is always
        // considered stale (horizon > expiry-from-now) and every call
        // refetches.
        let (fetcher, calls) = CountingFetcher::new(1);
        let cache = AzureTokenCache::new(fetcher).with_refresh_horizon(Duration::from_secs(5));
        let key = TokenKey::new("tenant-a", "scope-x");

        let t1 = cache.get_token(&key).await.unwrap();
        let t2 = cache.get_token(&key).await.unwrap();
        assert_ne!(
            t1, t2,
            "token within refresh horizon should be refetched every time"
        );
        assert_eq!(calls.load(Ordering::SeqCst), 2);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn fetcher_error_propagates() {
        struct FailingFetcher;
        #[async_trait]
        impl TokenFetcher for FailingFetcher {
            async fn fetch(&self, _key: &TokenKey) -> Result<(String, u64), TokenError> {
                Err(TokenError::Fetch("401 unauthorized".to_string()))
            }
        }

        let cache = AzureTokenCache::new(Arc::new(FailingFetcher));
        let key = TokenKey::new("tenant-a", "scope-x");
        let result = cache.get_token(&key).await;
        assert!(result.is_err());
        assert_eq!(cache.len().await, 0, "failed fetch should NOT cache");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn concurrent_get_token_serializes_fetches() {
        // Fire 10 concurrent `get_token` calls for the same key. The
        // double-checked locking pattern should cause exactly ONE fetch,
        // with all 10 callers returning the same token.
        let (fetcher, calls) = CountingFetcher::new(3600);
        let cache = Arc::new(AzureTokenCache::new(fetcher));
        let key = TokenKey::new("tenant-a", "scope-x");

        let mut handles = Vec::new();
        for _ in 0..10 {
            let cache = cache.clone();
            let key = key.clone();
            handles.push(tokio::spawn(
                async move { cache.get_token(&key).await.unwrap() },
            ));
        }
        let mut tokens = Vec::new();
        for h in handles {
            tokens.push(h.await.unwrap());
        }
        // All 10 tokens should be identical.
        let first = &tokens[0];
        for t in &tokens {
            assert_eq!(t, first);
        }
        // The fetcher should have been called exactly once. If the
        // double-checked locking were broken, we'd see calls up to 10.
        assert_eq!(
            calls.load(Ordering::SeqCst),
            1,
            "expected exactly one fetch, got {}",
            calls.load(Ordering::SeqCst)
        );
    }
}
