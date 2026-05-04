//! Pluggable persistent storage for OAuth refresh tokens.
//!
//! This module defines the [`TokenStorage`] trait that abstracts over
//! "where do we keep the analyst's refresh token between app runs".
//! Plan §7 specifies three production backends for the full PKCE
//! path (Phase 6 Tauri layer):
//!
//! 1. **OS keychain** (via `keyring` crate) — default, platform-native
//!    secure storage. Lives at `app/src-tauri/src/auth/keyring_storage.rs`.
//! 2. **Encrypted file** — fallback for headless environments where
//!    keyring isn't available (CI, containers).
//! 3. **Memory only** — for tests and `client_credentials` flows that
//!    don't have a refresh token concept at all.
//!
//! This file provides #3 ([`InMemoryTokenStorage`]) and the shared
//! trait every backend implements. #1 and #2 land when the Tauri app
//! PKCE flow is wired in — at that point `app/src-tauri` implements
//! the trait against `keyring::Entry` and flips the default.
//!
//! The trait is separate from [`TokenFetcher`] on purpose:
//!
//! - `TokenFetcher` is "go to Azure AD and mint a new access token".
//! - `TokenStorage` is "remember the refresh token across app restarts".
//!
//! [`TokenFetcher`]: crate::token_cache::TokenFetcher

use async_trait::async_trait;
use std::collections::HashMap;
use std::sync::RwLock;

use crate::token_cache::TokenKey;

/// A stored refresh token plus its expiry deadline. Format is source-
/// agnostic; each storage backend serializes it however it wants.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredToken {
    /// The refresh token string (what goes into the `refresh_token`
    /// form field on the next `/token` call). This is a secret.
    pub refresh_token: String,
    /// Epoch seconds at which the refresh token stops being valid.
    /// Azure AD refresh tokens typically live 90 days or until
    /// revoked — whichever comes first. Storage backends use this
    /// to skip expired entries on load.
    pub expires_at_epoch_s: i64,
}

impl StoredToken {
    pub fn new(refresh_token: impl Into<String>, expires_at_epoch_s: i64) -> Self {
        Self {
            refresh_token: refresh_token.into(),
            expires_at_epoch_s,
        }
    }

    /// Returns true if the refresh token's expiry is in the past,
    /// according to the given `now` (epoch seconds).
    pub fn is_expired(&self, now_epoch_s: i64) -> bool {
        now_epoch_s >= self.expires_at_epoch_s
    }
}

/// Errors surfaced by a [`TokenStorage`] implementation.
#[derive(Debug, Clone)]
pub enum TokenStorageError {
    /// Underlying I/O failure (keychain read, file write, etc.).
    Io(String),
    /// Ciphertext corruption / decryption failure. The caller should
    /// treat this as "no token stored" and force a fresh sign-in.
    Crypto(String),
    /// The backend is not supported on this platform (e.g., keyring
    /// on a headless Linux container with no secret service). Callers
    /// should fall back to another backend.
    Unsupported(String),
}

impl std::fmt::Display for TokenStorageError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TokenStorageError::Io(msg) => write!(f, "token storage I/O error: {msg}"),
            TokenStorageError::Crypto(msg) => write!(f, "token storage crypto error: {msg}"),
            TokenStorageError::Unsupported(msg) => {
                write!(f, "token storage unsupported: {msg}")
            }
        }
    }
}

impl std::error::Error for TokenStorageError {}

/// Persistent store for OAuth refresh tokens.
///
/// Implementations MUST be `Send + Sync` so a single store can be
/// shared across the auth flow (PKCE) and the token cache via
/// `Arc<dyn TokenStorage>`.
///
/// All methods are async so backends can use async I/O (keyring is
/// synchronous today, but a future encrypted-file backend would use
/// `tokio::fs`).
#[async_trait]
pub trait TokenStorage: Send + Sync {
    /// Loads the stored refresh token for a key, if any.
    ///
    /// Returns `Ok(None)` if no token is stored. Expired tokens are
    /// NOT filtered here — the caller is responsible for checking
    /// `StoredToken::is_expired` so the caller controls the clock
    /// (useful for tests).
    async fn load(&self, key: &TokenKey) -> Result<Option<StoredToken>, TokenStorageError>;

    /// Saves (or overwrites) the refresh token for a key.
    async fn save(&self, key: &TokenKey, token: StoredToken) -> Result<(), TokenStorageError>;

    /// Removes the stored token for a key. `Ok(())` whether or not
    /// the key was present (idempotent).
    async fn delete(&self, key: &TokenKey) -> Result<(), TokenStorageError>;
}

// ---------------------------------------------------------------------------
// InMemoryTokenStorage
// ---------------------------------------------------------------------------

/// An in-memory [`TokenStorage`] backend. Used for:
///
/// - Unit tests that exercise the auth flow without touching the OS
///   keychain.
/// - `client_credentials` deployments that don't have a refresh
///   token concept — the store stays empty.
/// - Headless CI where OS keyring access is unreliable.
///
/// Tokens are stored in a `RwLock<HashMap>`. Thread-safe but NOT
/// durable — a process restart wipes everything.
pub struct InMemoryTokenStorage {
    inner: RwLock<HashMap<TokenKey, StoredToken>>,
}

impl InMemoryTokenStorage {
    pub fn new() -> Self {
        Self {
            inner: RwLock::new(HashMap::new()),
        }
    }

    /// Returns how many entries are currently stored. Used by tests
    /// and metrics.
    pub fn len(&self) -> usize {
        self.inner.read().unwrap().len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

impl Default for InMemoryTokenStorage {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl TokenStorage for InMemoryTokenStorage {
    async fn load(&self, key: &TokenKey) -> Result<Option<StoredToken>, TokenStorageError> {
        let map = self.inner.read().unwrap();
        Ok(map.get(key).cloned())
    }

    async fn save(&self, key: &TokenKey, token: StoredToken) -> Result<(), TokenStorageError> {
        let mut map = self.inner.write().unwrap();
        map.insert(key.clone(), token);
        Ok(())
    }

    async fn delete(&self, key: &TokenKey) -> Result<(), TokenStorageError> {
        let mut map = self.inner.write().unwrap();
        map.remove(key);
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn mk_key(tenant: &str, scope: &str) -> TokenKey {
        TokenKey::new(tenant, scope)
    }

    #[test]
    fn stored_token_expiry_check() {
        let token = StoredToken::new("rt_abc", 100);
        assert!(!token.is_expired(99));
        assert!(token.is_expired(100));
        assert!(token.is_expired(200));
    }

    #[tokio::test(flavor = "current_thread")]
    async fn load_missing_returns_none() {
        let store = InMemoryTokenStorage::new();
        let result = store
            .load(&mk_key("tenant-a", "https://api.loganalytics.io/.default"))
            .await
            .unwrap();
        assert!(result.is_none());
        assert!(store.is_empty());
    }

    #[tokio::test(flavor = "current_thread")]
    async fn save_and_load_roundtrip() {
        let store = InMemoryTokenStorage::new();
        let key = mk_key("tenant-a", "https://api.loganalytics.io/.default");
        let token = StoredToken::new("rt_xyz", 2_000_000_000);
        store.save(&key, token.clone()).await.unwrap();
        let loaded = store.load(&key).await.unwrap().unwrap();
        assert_eq!(loaded, token);
        assert_eq!(store.len(), 1);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn save_overwrites_existing() {
        let store = InMemoryTokenStorage::new();
        let key = mk_key("tenant-a", "scope-x");

        store
            .save(&key, StoredToken::new("old_token", 1000))
            .await
            .unwrap();
        store
            .save(&key, StoredToken::new("new_token", 2000))
            .await
            .unwrap();

        let loaded = store.load(&key).await.unwrap().unwrap();
        assert_eq!(loaded.refresh_token, "new_token");
        assert_eq!(loaded.expires_at_epoch_s, 2000);
        assert_eq!(store.len(), 1);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn delete_removes_entry() {
        let store = InMemoryTokenStorage::new();
        let key = mk_key("tenant-a", "scope-x");
        store
            .save(&key, StoredToken::new("rt", 1000))
            .await
            .unwrap();
        assert_eq!(store.len(), 1);

        store.delete(&key).await.unwrap();
        assert!(store.is_empty());
        assert!(store.load(&key).await.unwrap().is_none());
    }

    #[tokio::test(flavor = "current_thread")]
    async fn delete_missing_is_idempotent() {
        let store = InMemoryTokenStorage::new();
        let key = mk_key("tenant-a", "scope-x");
        // Should not error even though nothing is stored.
        store.delete(&key).await.unwrap();
        store.delete(&key).await.unwrap();
        assert!(store.is_empty());
    }

    #[tokio::test(flavor = "current_thread")]
    async fn different_keys_are_independent() {
        let store = InMemoryTokenStorage::new();
        let la_key = mk_key("tenant-a", "https://api.loganalytics.io/.default");
        let xdr_key = mk_key("tenant-a", "https://api.security.microsoft.com/.default");

        store
            .save(&la_key, StoredToken::new("la_token", 1000))
            .await
            .unwrap();
        store
            .save(&xdr_key, StoredToken::new("xdr_token", 2000))
            .await
            .unwrap();

        assert_eq!(store.len(), 2);
        assert_eq!(
            store.load(&la_key).await.unwrap().unwrap().refresh_token,
            "la_token"
        );
        assert_eq!(
            store.load(&xdr_key).await.unwrap().unwrap().refresh_token,
            "xdr_token"
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn dyn_token_storage_is_object_safe() {
        // Compile-time verification: trait can be stored as
        // `Arc<dyn TokenStorage>`. Breaks if the trait ever stops
        // being object-safe (e.g., via a generic method).
        use std::sync::Arc;
        let store: Arc<dyn TokenStorage> = Arc::new(InMemoryTokenStorage::new());
        let key = mk_key("tenant-a", "scope-x");
        let result = store.load(&key).await.unwrap();
        assert!(result.is_none());
    }
}
