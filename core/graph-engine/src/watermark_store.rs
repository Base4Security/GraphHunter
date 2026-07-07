//! Persistent watermark + source status store backed by SQLite.
//!
//! Every streaming source poller advances a per-table watermark that
//! answers the question "what's the most recent row I've already ingested
//! from this table?". Before this module, watermarks lived in an in-memory
//! `HashMap` (`graph_hunter_cli::siem::sentinel_streaming::SentinelWatermarkStore`)
//! which got dropped on process restart — meaning the next startup had to
//! re-query the last 24 hours (a configurable default), triggering large
//! duplicate inserts.
//!
//! This module replaces that with a persistent sqlite database that lives
//! alongside each session (`<session_dir>/ops.sqlite`). The store is
//! behind a trait so tests can use an in-memory sqlite and so Phase 9
//! can swap in a more sophisticated backend if needed (e.g., a
//! cross-session registry for multi-tenant setups).
//!
//! The schema covers three tables (see plan §4):
//!
//! - `watermarks` — per (source_id, tenant_id, workspace_id, table, partition)
//!   resume state. Both `last_timestamp` (ISO-8601 for KQL) and
//!   `last_blob_name` + `last_byte_offset` (for blob export) are stored
//!   because different sources resume differently.
//! - `source_status` — per-source connection state (`connected`,
//!   `disconnected`, `paused`, `auth_revoked`) + consecutive error
//!   counter + last failure reason. Used to skip sources that tripped
//!   the 3-strike auth breaker without user intervention (plan §9
//!   "Auth (revoked)" row).
//! - `enrichment_audit` — append-only log of on-demand enrichment
//!   queries. Entity IDs are stored as SHA-256 hashes, not plaintext,
//!   so the audit log is safe to retain for 90 days without leaking
//!   PII (plan §9 "Security operations").
//!
//! All writes are wrapped in short transactions. The store is async-safe
//! via an internal `tokio::sync::Mutex` around the rusqlite `Connection`
//! (which is `Send` but not `Sync` by default). A `tokio::time::interval`
//! in the polling loop calls `flush()` every 10 s so watermark advances
//! are durable without per-write fsync overhead.

use async_trait::async_trait;
use rusqlite::{Connection, params};
use std::path::Path;
use tokio::sync::Mutex;

use graph_hunter_sources::Watermark;

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

#[derive(Debug)]
pub enum WatermarkError {
    /// SQLite I/O or parse error. Always wraps the underlying rusqlite
    /// error so the caller can pattern-match if needed.
    Sqlite(rusqlite::Error),
    /// Failed to create the parent directory for the sqlite file.
    Io(std::io::Error),
}

impl std::fmt::Display for WatermarkError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            WatermarkError::Sqlite(e) => write!(f, "sqlite error: {e}"),
            WatermarkError::Io(e) => write!(f, "io error: {e}"),
        }
    }
}

impl std::error::Error for WatermarkError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            WatermarkError::Sqlite(e) => Some(e),
            WatermarkError::Io(e) => Some(e),
        }
    }
}

impl From<rusqlite::Error> for WatermarkError {
    fn from(e: rusqlite::Error) -> Self {
        WatermarkError::Sqlite(e)
    }
}

impl From<std::io::Error> for WatermarkError {
    fn from(e: std::io::Error) -> Self {
        WatermarkError::Io(e)
    }
}

// ---------------------------------------------------------------------------
// Domain types
// ---------------------------------------------------------------------------

/// Composite key for a watermark entry. Each field is part of the primary
/// key so a single workspace can hold independent watermarks per table and
/// per partition (the partition field is used by blob export for per-hour
/// subdirectories; KQL sources leave it empty).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct WatermarkKey {
    pub source_id: String,
    pub tenant_id: String,
    pub workspace_id: String,
    pub table_name: String,
    pub partition: String,
}

impl WatermarkKey {
    pub fn new(
        source_id: impl Into<String>,
        tenant_id: impl Into<String>,
        workspace_id: impl Into<String>,
        table_name: impl Into<String>,
    ) -> Self {
        Self {
            source_id: source_id.into(),
            tenant_id: tenant_id.into(),
            workspace_id: workspace_id.into(),
            table_name: table_name.into(),
            partition: String::new(),
        }
    }

    pub fn with_partition(mut self, partition: impl Into<String>) -> Self {
        self.partition = partition.into();
        self
    }
}

/// Per-source connection state. Persisted so a source that tripped the
/// auth breaker stays disconnected across restarts (no re-hammering) and
/// the UI can surface a "Reconnect" action.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SourceState {
    Connected,
    Disconnected,
    Paused,
    AuthRevoked,
}

impl SourceState {
    pub fn as_str(self) -> &'static str {
        match self {
            SourceState::Connected => "connected",
            SourceState::Disconnected => "disconnected",
            SourceState::Paused => "paused",
            SourceState::AuthRevoked => "auth_revoked",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "connected" => Some(SourceState::Connected),
            "disconnected" => Some(SourceState::Disconnected),
            "paused" => Some(SourceState::Paused),
            "auth_revoked" => Some(SourceState::AuthRevoked),
            _ => None,
        }
    }
}

#[derive(Debug, Clone)]
pub struct SourceStatus {
    pub source_id: String,
    pub state: SourceState,
    pub failure_reason: Option<String>,
    pub consecutive_errors: u32,
    pub updated_at: i64, // epoch seconds
}

/// Audit log entry for an on-demand enrichment query. Entity IDs are
/// stored as SHA-256 hashes (not plaintext) so the audit table is safe
/// to retain without leaking PII.
#[derive(Debug, Clone)]
pub struct EnrichmentAuditEntry {
    pub session_id: String,
    /// 32-byte SHA-256 hash of the entity ID (NOT plaintext).
    pub entity_hash: Vec<u8>,
    pub entity_type: String,
    pub source_id: String,
    pub time_from: String, // ISO-8601
    pub time_to: String,   // ISO-8601
    pub row_count: u64,
    pub duration_ms: u64,
    pub triggered_at: i64, // epoch seconds
}

// ---------------------------------------------------------------------------
// Trait
// ---------------------------------------------------------------------------

/// Persistent store for streaming source watermarks, status, and audit
/// log. Implementations must be `Send + Sync` so a single store can be
/// shared across connector tasks via `Arc<dyn WatermarkStore>`.
///
/// All methods are async so implementations can back onto sqlite, a
/// remote database, or an in-memory HashMap for tests without changing
/// callers.
#[async_trait]
pub trait WatermarkStore: Send + Sync {
    /// Reads the watermark for a given key. Returns `Ok(None)` if no
    /// watermark is stored yet (first poll for that table).
    async fn get(&self, key: &WatermarkKey) -> Result<Option<Watermark>, WatermarkError>;

    /// Writes or updates the watermark for a given key. Idempotent
    /// (`INSERT ... ON CONFLICT DO UPDATE`).
    async fn set(&self, key: &WatermarkKey, watermark: &Watermark) -> Result<(), WatermarkError>;

    /// Forces any pending writes to disk. Used by the shutdown hook and
    /// by the periodic flush timer in the polling loop.
    async fn flush(&self) -> Result<(), WatermarkError>;

    /// Reads the status record for a source. `Ok(None)` if the source
    /// has not been seen before.
    async fn get_source_status(
        &self,
        source_id: &str,
    ) -> Result<Option<SourceStatus>, WatermarkError>;

    /// Writes or updates the status record for a source.
    async fn set_source_status(&self, status: &SourceStatus) -> Result<(), WatermarkError>;

    /// Appends an enrichment audit entry.
    async fn append_enrichment_audit(
        &self,
        entry: &EnrichmentAuditEntry,
    ) -> Result<(), WatermarkError>;

    /// Returns the number of audit entries recorded since `since_epoch_s`.
    /// Used by the UI's "recent queries for this entity" view.
    async fn count_enrichment_audit_since(&self, since_epoch_s: i64)
    -> Result<u64, WatermarkError>;
}

// ---------------------------------------------------------------------------
// SQLite implementation
// ---------------------------------------------------------------------------

/// SQLite-backed watermark store. The `Connection` lives behind a
/// tokio `Mutex` because rusqlite's Connection is `Send` but not `Sync`
/// and we want all SQL to be serialized anyway (write-heavy workload,
/// read-sparse). A `tokio::task::block_in_place`-style escape hatch is
/// not needed because the writes are tiny (a handful of bytes each) and
/// the Mutex hold time is short.
pub struct SqliteWatermarkStore {
    conn: Mutex<Connection>,
}

impl SqliteWatermarkStore {
    /// Opens a sqlite file at the given path, creating the parent dirs
    /// and the schema if they don't exist.
    pub async fn open(path: impl AsRef<Path>) -> Result<Self, WatermarkError> {
        let path = path.as_ref();
        if let Some(parent) = path.parent() {
            if !parent.as_os_str().is_empty() {
                std::fs::create_dir_all(parent)?;
            }
        }
        let conn = Connection::open(path)?;
        Self::init_schema(&conn)?;
        Ok(Self {
            conn: Mutex::new(conn),
        })
    }

    /// Opens an in-memory sqlite database. Used by unit tests and by
    /// ephemeral sessions that don't need persistence.
    pub async fn open_in_memory() -> Result<Self, WatermarkError> {
        let conn = Connection::open_in_memory()?;
        Self::init_schema(&conn)?;
        Ok(Self {
            conn: Mutex::new(conn),
        })
    }

    fn init_schema(conn: &Connection) -> Result<(), rusqlite::Error> {
        // Use WAL for better concurrency between the background flush
        // timer and the polling-loop writes. `wal_autocheckpoint` is
        // default (1000 pages = ~4 MB) which is plenty for our workload.
        conn.execute_batch(
            r#"
            PRAGMA journal_mode = WAL;
            PRAGMA synchronous = NORMAL;

            CREATE TABLE IF NOT EXISTS watermarks (
                source_id       TEXT NOT NULL,
                tenant_id       TEXT NOT NULL,
                workspace_id    TEXT NOT NULL,
                table_name      TEXT NOT NULL,
                partition       TEXT NOT NULL DEFAULT '',
                watermark_value TEXT NOT NULL,
                updated_at      INTEGER NOT NULL,
                PRIMARY KEY (source_id, tenant_id, workspace_id, table_name, partition)
            );

            CREATE TABLE IF NOT EXISTS source_status (
                source_id          TEXT PRIMARY KEY,
                state              TEXT NOT NULL,
                failure_reason     TEXT,
                consecutive_errors INTEGER NOT NULL DEFAULT 0,
                updated_at         INTEGER NOT NULL
            );

            CREATE TABLE IF NOT EXISTS enrichment_audit (
                id             INTEGER PRIMARY KEY AUTOINCREMENT,
                session_id     TEXT NOT NULL,
                entity_hash    BLOB NOT NULL,
                entity_type    TEXT NOT NULL,
                source_id      TEXT NOT NULL,
                time_from      TEXT NOT NULL,
                time_to        TEXT NOT NULL,
                row_count      INTEGER NOT NULL,
                duration_ms    INTEGER NOT NULL,
                triggered_at   INTEGER NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_enrich_audit_time ON enrichment_audit(triggered_at DESC);
            CREATE INDEX IF NOT EXISTS idx_enrich_audit_hash ON enrichment_audit(entity_hash);
            "#,
        )?;
        Ok(())
    }
}

fn now_epoch_seconds() -> i64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

#[async_trait]
impl WatermarkStore for SqliteWatermarkStore {
    async fn get(&self, key: &WatermarkKey) -> Result<Option<Watermark>, WatermarkError> {
        let conn = self.conn.lock().await;
        let mut stmt = conn.prepare_cached(
            "SELECT watermark_value FROM watermarks
             WHERE source_id = ?1 AND tenant_id = ?2 AND workspace_id = ?3
               AND table_name = ?4 AND partition = ?5",
        )?;
        let result: rusqlite::Result<String> = stmt.query_row(
            params![
                key.source_id,
                key.tenant_id,
                key.workspace_id,
                key.table_name,
                key.partition,
            ],
            |row| row.get(0),
        );
        match result {
            Ok(v) => Ok(Some(Watermark::new(v))),
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(e) => Err(e.into()),
        }
    }

    async fn set(&self, key: &WatermarkKey, watermark: &Watermark) -> Result<(), WatermarkError> {
        let conn = self.conn.lock().await;
        conn.execute(
            "INSERT INTO watermarks
                (source_id, tenant_id, workspace_id, table_name, partition,
                 watermark_value, updated_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)
             ON CONFLICT (source_id, tenant_id, workspace_id, table_name, partition)
             DO UPDATE SET watermark_value = excluded.watermark_value,
                           updated_at = excluded.updated_at",
            params![
                key.source_id,
                key.tenant_id,
                key.workspace_id,
                key.table_name,
                key.partition,
                watermark.as_str(),
                now_epoch_seconds(),
            ],
        )?;
        Ok(())
    }

    async fn flush(&self) -> Result<(), WatermarkError> {
        // WAL checkpoint forces any pending writes to the main db file.
        // PASSIVE is a non-blocking checkpoint suitable for periodic
        // flushes; TRUNCATE would be more thorough but can block readers.
        let conn = self.conn.lock().await;
        conn.execute_batch("PRAGMA wal_checkpoint(PASSIVE);")?;
        Ok(())
    }

    async fn get_source_status(
        &self,
        source_id: &str,
    ) -> Result<Option<SourceStatus>, WatermarkError> {
        let conn = self.conn.lock().await;
        let mut stmt = conn.prepare_cached(
            "SELECT source_id, state, failure_reason, consecutive_errors, updated_at
             FROM source_status
             WHERE source_id = ?1",
        )?;
        let result: rusqlite::Result<SourceStatus> = stmt.query_row(params![source_id], |row| {
            let state_str: String = row.get(1)?;
            let state = SourceState::parse(&state_str).ok_or_else(|| {
                rusqlite::Error::FromSqlConversionFailure(
                    1,
                    rusqlite::types::Type::Text,
                    Box::new(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        format!("unknown source state: {state_str}"),
                    )),
                )
            })?;
            Ok(SourceStatus {
                source_id: row.get(0)?,
                state,
                failure_reason: row.get(2)?,
                consecutive_errors: row.get::<_, i64>(3)? as u32,
                updated_at: row.get(4)?,
            })
        });
        match result {
            Ok(s) => Ok(Some(s)),
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(e) => Err(e.into()),
        }
    }

    async fn set_source_status(&self, status: &SourceStatus) -> Result<(), WatermarkError> {
        let conn = self.conn.lock().await;
        conn.execute(
            "INSERT INTO source_status
                (source_id, state, failure_reason, consecutive_errors, updated_at)
             VALUES (?1, ?2, ?3, ?4, ?5)
             ON CONFLICT (source_id)
             DO UPDATE SET state = excluded.state,
                           failure_reason = excluded.failure_reason,
                           consecutive_errors = excluded.consecutive_errors,
                           updated_at = excluded.updated_at",
            params![
                status.source_id,
                status.state.as_str(),
                status.failure_reason,
                status.consecutive_errors as i64,
                status.updated_at,
            ],
        )?;
        Ok(())
    }

    async fn append_enrichment_audit(
        &self,
        entry: &EnrichmentAuditEntry,
    ) -> Result<(), WatermarkError> {
        let conn = self.conn.lock().await;
        conn.execute(
            "INSERT INTO enrichment_audit
                (session_id, entity_hash, entity_type, source_id,
                 time_from, time_to, row_count, duration_ms, triggered_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
            params![
                entry.session_id,
                entry.entity_hash,
                entry.entity_type,
                entry.source_id,
                entry.time_from,
                entry.time_to,
                entry.row_count as i64,
                entry.duration_ms as i64,
                entry.triggered_at,
            ],
        )?;
        Ok(())
    }

    async fn count_enrichment_audit_since(
        &self,
        since_epoch_s: i64,
    ) -> Result<u64, WatermarkError> {
        let conn = self.conn.lock().await;
        let count: i64 = conn.query_row(
            "SELECT COUNT(*) FROM enrichment_audit WHERE triggered_at >= ?1",
            params![since_epoch_s],
            |row| row.get(0),
        )?;
        Ok(count as u64)
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test(flavor = "current_thread")]
    async fn get_returns_none_for_missing_key() {
        let store = SqliteWatermarkStore::open_in_memory().await.unwrap();
        let key = WatermarkKey::new("la", "tenant-a", "ws-1", "SecurityEvent");
        assert!(store.get(&key).await.unwrap().is_none());
    }

    #[tokio::test(flavor = "current_thread")]
    async fn set_then_get_roundtrip() {
        let store = SqliteWatermarkStore::open_in_memory().await.unwrap();
        let key = WatermarkKey::new("la", "tenant-a", "ws-1", "SecurityEvent");
        let wm = Watermark::new("2026-04-09T12:00:00Z");

        store.set(&key, &wm).await.unwrap();
        let got = store.get(&key).await.unwrap();
        assert_eq!(got, Some(wm));
    }

    #[tokio::test(flavor = "current_thread")]
    async fn set_overwrites_existing() {
        let store = SqliteWatermarkStore::open_in_memory().await.unwrap();
        let key = WatermarkKey::new("la", "tenant-a", "ws-1", "SecurityEvent");

        store
            .set(&key, &Watermark::new("2026-04-09T10:00:00Z"))
            .await
            .unwrap();
        store
            .set(&key, &Watermark::new("2026-04-09T11:00:00Z"))
            .await
            .unwrap();

        let got = store.get(&key).await.unwrap().unwrap();
        assert_eq!(got.as_str(), "2026-04-09T11:00:00Z");
    }

    #[tokio::test(flavor = "current_thread")]
    async fn partition_key_is_distinct() {
        let store = SqliteWatermarkStore::open_in_memory().await.unwrap();
        let base = WatermarkKey::new("blob", "tenant-a", "ws-1", "SecurityEvent");
        let part_a = base.clone().with_partition("y=2026/m=04/d=09/h=10");
        let part_b = base.clone().with_partition("y=2026/m=04/d=09/h=11");

        store
            .set(&part_a, &Watermark::new("offset_100"))
            .await
            .unwrap();
        store
            .set(&part_b, &Watermark::new("offset_200"))
            .await
            .unwrap();

        assert_eq!(
            store.get(&part_a).await.unwrap().unwrap().as_str(),
            "offset_100"
        );
        assert_eq!(
            store.get(&part_b).await.unwrap().unwrap().as_str(),
            "offset_200"
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn persists_across_open() {
        // Open a file-backed store, write, close, reopen, verify.
        let tmp = tempfile::tempdir().unwrap();
        let db_path = tmp.path().join("ops.sqlite");

        {
            let store = SqliteWatermarkStore::open(&db_path).await.unwrap();
            let key = WatermarkKey::new("la", "tenant-a", "ws-1", "SigninLogs");
            store
                .set(&key, &Watermark::new("2026-04-09T08:00:00Z"))
                .await
                .unwrap();
            store.flush().await.unwrap();
        }
        {
            let store = SqliteWatermarkStore::open(&db_path).await.unwrap();
            let key = WatermarkKey::new("la", "tenant-a", "ws-1", "SigninLogs");
            let got = store.get(&key).await.unwrap().unwrap();
            assert_eq!(got.as_str(), "2026-04-09T08:00:00Z");
        }
    }

    #[tokio::test(flavor = "current_thread")]
    async fn source_status_roundtrip() {
        let store = SqliteWatermarkStore::open_in_memory().await.unwrap();

        assert!(store.get_source_status("la:ws-1").await.unwrap().is_none());

        let status = SourceStatus {
            source_id: "la:ws-1".to_string(),
            state: SourceState::AuthRevoked,
            failure_reason: Some("401 Unauthorized x3".to_string()),
            consecutive_errors: 3,
            updated_at: 1_234_567_890,
        };
        store.set_source_status(&status).await.unwrap();

        let got = store.get_source_status("la:ws-1").await.unwrap().unwrap();
        assert_eq!(got.state, SourceState::AuthRevoked);
        assert_eq!(got.consecutive_errors, 3);
        assert_eq!(got.failure_reason.as_deref(), Some("401 Unauthorized x3"));
    }

    #[tokio::test(flavor = "current_thread")]
    async fn source_status_update_in_place() {
        let store = SqliteWatermarkStore::open_in_memory().await.unwrap();
        let id = "la:ws-1".to_string();

        store
            .set_source_status(&SourceStatus {
                source_id: id.clone(),
                state: SourceState::Connected,
                failure_reason: None,
                consecutive_errors: 0,
                updated_at: 100,
            })
            .await
            .unwrap();

        // Same source_id — should update in place, not create a new row.
        store
            .set_source_status(&SourceStatus {
                source_id: id.clone(),
                state: SourceState::Paused,
                failure_reason: Some("memory pressure".to_string()),
                consecutive_errors: 0,
                updated_at: 200,
            })
            .await
            .unwrap();

        let got = store.get_source_status(&id).await.unwrap().unwrap();
        assert_eq!(got.state, SourceState::Paused);
        assert_eq!(got.updated_at, 200);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn enrichment_audit_append_and_count() {
        let store = SqliteWatermarkStore::open_in_memory().await.unwrap();

        let entry = EnrichmentAuditEntry {
            session_id: "sess-1".to_string(),
            entity_hash: vec![0xAB; 32],
            entity_type: "IpAddress".to_string(),
            source_id: "la:ws-1".to_string(),
            time_from: "2026-04-09T00:00:00Z".to_string(),
            time_to: "2026-04-09T23:59:59Z".to_string(),
            row_count: 1234,
            duration_ms: 567,
            triggered_at: 1_700_000_100,
        };
        store.append_enrichment_audit(&entry).await.unwrap();
        store.append_enrichment_audit(&entry).await.unwrap();

        // Two entries after the earliest; one after a later cutoff.
        assert_eq!(
            store
                .count_enrichment_audit_since(1_700_000_000)
                .await
                .unwrap(),
            2
        );
        assert_eq!(
            store
                .count_enrichment_audit_since(1_700_000_200)
                .await
                .unwrap(),
            0
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn source_state_parse_roundtrip() {
        for s in [
            SourceState::Connected,
            SourceState::Disconnected,
            SourceState::Paused,
            SourceState::AuthRevoked,
        ] {
            assert_eq!(SourceState::parse(s.as_str()), Some(s));
        }
        assert_eq!(SourceState::parse("unknown"), None);
    }
}
