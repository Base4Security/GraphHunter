//! SQLite persistence for drift batches (M5 Win 3 D5).
//!
//! The drift collector in [`super`] produces one [`DriftSnapshot`] per
//! parse batch. This store records those snapshots to a per-session
//! SQLite file so the Prometheus /metrics exporter (D6) and the
//! `schema_drift_detector` MCP tool (M5) can query historical drift
//! without keeping every batch in RAM.
//!
//! Schema:
//! * `drift_batches(id, dataset_id, observed_at, rows_observed)`
//! * `drift_field_tags(batch_id, field, type_tag, count)` — where
//!   `type_tag = 'null'` stores the null count and every other tag
//!   stores one bucket of the type histogram.
//!
//! `FieldDriftStats::total`, `.null`, `.non_null` are all derivable
//! from the tag rows so the schema is append-only and redundant
//! counters can't drift from each other.

use std::path::Path;

use rusqlite::{Connection, params};

use super::{DriftSnapshot, FieldDriftStats};

const SCHEMA: &str = r#"
CREATE TABLE IF NOT EXISTS drift_batches (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    dataset_id      TEXT    NOT NULL,
    observed_at     INTEGER NOT NULL,
    rows_observed   INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_drift_batches_dataset_at
    ON drift_batches(dataset_id, observed_at);

CREATE TABLE IF NOT EXISTS drift_field_tags (
    batch_id        INTEGER NOT NULL,
    field           TEXT    NOT NULL,
    type_tag        TEXT    NOT NULL,
    count           INTEGER NOT NULL,
    PRIMARY KEY (batch_id, field, type_tag),
    FOREIGN KEY (batch_id) REFERENCES drift_batches(id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_drift_field_tags_field
    ON drift_field_tags(field);
"#;

const NULL_TAG: &str = "null";

/// Errors surfaced by the drift store. Kept as a single concrete type
/// so callers can `?`-propagate without wrestling with trait objects.
#[derive(Debug)]
pub enum DriftStoreError {
    Sqlite(rusqlite::Error),
    Io(std::io::Error),
}

impl std::fmt::Display for DriftStoreError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DriftStoreError::Sqlite(e) => write!(f, "sqlite error: {e}"),
            DriftStoreError::Io(e) => write!(f, "io error: {e}"),
        }
    }
}

impl std::error::Error for DriftStoreError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            DriftStoreError::Sqlite(e) => Some(e),
            DriftStoreError::Io(e) => Some(e),
        }
    }
}

impl From<rusqlite::Error> for DriftStoreError {
    fn from(e: rusqlite::Error) -> Self {
        DriftStoreError::Sqlite(e)
    }
}

impl From<std::io::Error> for DriftStoreError {
    fn from(e: std::io::Error) -> Self {
        DriftStoreError::Io(e)
    }
}

/// Sqlite-backed drift store. Not thread-safe — wrap in a mutex if a
/// background aggregator needs concurrent access.
pub struct DriftStore {
    conn: Connection,
}

impl DriftStore {
    /// Open a store at `path`, creating the file (and parent dir) if
    /// needed. Idempotent against an existing schema.
    pub fn open<P: AsRef<Path>>(path: P) -> Result<Self, DriftStoreError> {
        if let Some(parent) = path.as_ref().parent() {
            if !parent.as_os_str().is_empty() {
                std::fs::create_dir_all(parent)?;
            }
        }
        let conn = Connection::open(path)?;
        conn.execute_batch(SCHEMA)?;
        Ok(Self { conn })
    }

    /// Open an in-memory store. Used by tests and the D6 Prometheus
    /// endpoint's smoke path.
    pub fn open_in_memory() -> Result<Self, DriftStoreError> {
        let conn = Connection::open_in_memory()?;
        conn.execute_batch(SCHEMA)?;
        Ok(Self { conn })
    }

    /// Record one parse-batch's drift snapshot under `dataset_id` at
    /// wall-clock `observed_at` (unix seconds — passed explicitly so
    /// tests are deterministic and the exporter can backfill).
    pub fn record_batch(
        &mut self,
        dataset_id: &str,
        observed_at_unix_s: i64,
        snapshot: &DriftSnapshot,
    ) -> Result<i64, DriftStoreError> {
        let tx = self.conn.transaction()?;
        tx.execute(
            "INSERT INTO drift_batches (dataset_id, observed_at, rows_observed) \
             VALUES (?1, ?2, ?3)",
            params![
                dataset_id,
                observed_at_unix_s,
                snapshot.rows_observed as i64
            ],
        )?;
        let batch_id = tx.last_insert_rowid();
        {
            let mut stmt = tx.prepare(
                "INSERT INTO drift_field_tags (batch_id, field, type_tag, count) \
                 VALUES (?1, ?2, ?3, ?4)",
            )?;
            for (field, stats) in &snapshot.fields {
                if stats.null > 0 {
                    stmt.execute(params![batch_id, field, NULL_TAG, stats.null as i64])?;
                }
                for (tag, count) in &stats.type_histogram {
                    stmt.execute(params![batch_id, field, tag, *count as i64])?;
                }
            }
        }
        tx.commit()?;
        Ok(batch_id)
    }

    /// Aggregate every batch for `dataset_id` whose `observed_at` is
    /// within `[since_unix_s, until_unix_s]` into a single snapshot.
    /// Returns an empty snapshot when no batches are found.
    pub fn aggregate_window(
        &self,
        dataset_id: &str,
        since_unix_s: i64,
        until_unix_s: i64,
    ) -> Result<DriftSnapshot, DriftStoreError> {
        let mut snap = DriftSnapshot::default();

        // rows_observed is simply the sum over matched batches.
        let rows: i64 = self.conn.query_row(
            "SELECT COALESCE(SUM(rows_observed), 0) \
             FROM drift_batches \
             WHERE dataset_id = ?1 AND observed_at BETWEEN ?2 AND ?3",
            params![dataset_id, since_unix_s, until_unix_s],
            |row| row.get(0),
        )?;
        snap.rows_observed = rows.max(0) as usize;

        let mut stmt = self.conn.prepare(
            "SELECT t.field, t.type_tag, SUM(t.count) AS total \
             FROM drift_field_tags t \
             JOIN drift_batches b ON b.id = t.batch_id \
             WHERE b.dataset_id = ?1 AND b.observed_at BETWEEN ?2 AND ?3 \
             GROUP BY t.field, t.type_tag",
        )?;
        let mut rows = stmt.query(params![dataset_id, since_unix_s, until_unix_s])?;
        while let Some(row) = rows.next()? {
            let field: String = row.get(0)?;
            let tag: String = row.get(1)?;
            let count: i64 = row.get(2)?;
            let count = count.max(0) as usize;

            let entry = snap
                .fields
                .entry(field)
                .or_insert_with(FieldDriftStats::default);
            entry.total += count;
            if tag == NULL_TAG {
                entry.null += count;
            } else {
                entry.non_null += count;
                *entry.type_histogram.entry(tag).or_default() += count;
            }
        }

        Ok(snap)
    }

    /// List dataset ids that have any recorded batch. Useful for the
    /// Prometheus exporter's "enumerate labels" call.
    pub fn known_datasets(&self) -> Result<Vec<String>, DriftStoreError> {
        let mut stmt = self
            .conn
            .prepare("SELECT DISTINCT dataset_id FROM drift_batches ORDER BY dataset_id")?;
        let rows = stmt.query_map([], |row| row.get::<_, String>(0))?;
        let mut out = Vec::new();
        for r in rows {
            out.push(r?);
        }
        Ok(out)
    }

    /// Delete every batch recorded before `before_unix_s`. Used by the
    /// retention job to keep drift.sqlite bounded.
    pub fn prune_older_than(&mut self, before_unix_s: i64) -> Result<usize, DriftStoreError> {
        let tx = self.conn.transaction()?;
        tx.execute(
            "DELETE FROM drift_field_tags WHERE batch_id IN \
             (SELECT id FROM drift_batches WHERE observed_at < ?1)",
            params![before_unix_s],
        )?;
        let deleted = tx.execute(
            "DELETE FROM drift_batches WHERE observed_at < ?1",
            params![before_unix_s],
        )?;
        tx.commit()?;
        Ok(deleted)
    }
}

#[cfg(test)]
mod tests {
    use super::super::DriftCollector;
    use super::*;
    use serde_json::json;

    fn snap_from(events: &[serde_json::Value]) -> DriftSnapshot {
        let mut c = DriftCollector::new();
        for e in events {
            c.observe_event(e);
        }
        c.into_snapshot()
    }

    #[test]
    fn record_and_read_back_single_batch() {
        let mut store = DriftStore::open_in_memory().expect("open");
        let snap = snap_from(&[
            json!({"src_ip": "10.0.0.1", "user": "alice"}),
            json!({"src_ip": "10.0.0.2", "user": ""}),
        ]);
        let id = store.record_batch("ds1", 1_700_000_000, &snap).unwrap();
        assert!(id > 0);

        let agg = store.aggregate_window("ds1", 0, 2_000_000_000).unwrap();
        assert_eq!(agg.rows_observed, 2);
        let src = agg.fields.get("src_ip").unwrap();
        assert_eq!(src.total, 2);
        assert_eq!(src.null, 0);
        assert_eq!(src.non_null, 2);
        assert_eq!(src.type_histogram.get("ip"), Some(&2));

        let user = agg.fields.get("user").unwrap();
        assert_eq!(user.total, 2);
        assert_eq!(user.null, 1);
        assert_eq!(user.non_null, 1);
        assert_eq!(user.type_histogram.get("string"), Some(&1));
        assert!(user.type_histogram.get("null").is_none());
    }

    #[test]
    fn window_filter_excludes_batches_out_of_range() {
        let mut store = DriftStore::open_in_memory().unwrap();
        let s = snap_from(&[json!({"f": "x"})]);
        store.record_batch("ds", 100, &s).unwrap();
        store.record_batch("ds", 200, &s).unwrap();
        store.record_batch("ds", 300, &s).unwrap();

        let mid = store.aggregate_window("ds", 150, 250).unwrap();
        assert_eq!(mid.rows_observed, 1);

        let full = store.aggregate_window("ds", 0, 1000).unwrap();
        assert_eq!(full.rows_observed, 3);
    }

    #[test]
    fn dataset_filter_isolates_snapshots() {
        let mut store = DriftStore::open_in_memory().unwrap();
        store
            .record_batch("dsA", 10, &snap_from(&[json!({"a": "1"})]))
            .unwrap();
        store
            .record_batch("dsB", 10, &snap_from(&[json!({"b": "2"})]))
            .unwrap();

        let a = store.aggregate_window("dsA", 0, 100).unwrap();
        assert!(a.fields.contains_key("a"));
        assert!(!a.fields.contains_key("b"));

        let b = store.aggregate_window("dsB", 0, 100).unwrap();
        assert!(b.fields.contains_key("b"));
        assert!(!b.fields.contains_key("a"));
    }

    #[test]
    fn known_datasets_lists_distinct_ids() {
        let mut store = DriftStore::open_in_memory().unwrap();
        let s = snap_from(&[json!({"x": "y"})]);
        store.record_batch("dsA", 1, &s).unwrap();
        store.record_batch("dsA", 2, &s).unwrap();
        store.record_batch("dsB", 3, &s).unwrap();
        assert_eq!(store.known_datasets().unwrap(), vec!["dsA", "dsB"]);
    }

    #[test]
    fn prune_removes_old_batches_only() {
        let mut store = DriftStore::open_in_memory().unwrap();
        let s = snap_from(&[json!({"f": "a"})]);
        store.record_batch("ds", 100, &s).unwrap();
        store.record_batch("ds", 200, &s).unwrap();
        store.record_batch("ds", 300, &s).unwrap();

        let pruned = store.prune_older_than(250).unwrap();
        assert_eq!(pruned, 2);

        let after = store.aggregate_window("ds", 0, 1000).unwrap();
        assert_eq!(after.rows_observed, 1);
    }

    #[test]
    fn disk_path_roundtrip() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("sub").join("drift.sqlite");
        {
            let mut s = DriftStore::open(&path).unwrap();
            s.record_batch("ds", 42, &snap_from(&[json!({"x": "y"})]))
                .unwrap();
        }
        // Re-open the same file — persistence should round-trip.
        let s2 = DriftStore::open(&path).unwrap();
        let agg = s2.aggregate_window("ds", 0, 1000).unwrap();
        assert_eq!(agg.rows_observed, 1);
        assert!(agg.fields.contains_key("x"));
    }
}
