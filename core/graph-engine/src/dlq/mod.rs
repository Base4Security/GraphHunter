//! Dead-letter queue: JSONL-sharded on-disk store of rows the ingest
//! pipeline refused (parse failure, invariant violation, schema-shape
//! mismatch).
//!
//! Design:
//!
//! - **One shard per file**, JSONL encoded (one record per line).
//!   Writes append; readers scan. Filenames are
//!   `dlq_<ts_ms>_<ctr>.jsonl` so lexicographic sort = chronological.
//! - **Rolling at 10k records or 8 MiB**, whichever comes first. The
//!   writer checks the active shard's size/line count under a mutex;
//!   at the threshold it rotates to a fresh filename. This bounds
//!   per-shard replay cost without demanding a timer thread.
//! - **Consumption = id-based filter-and-rewrite.** `consume(ids)`
//!   scans every shard, drops any record whose `dlq_id` is in the
//!   set, and rewrites the shard atomically (`.tmp` → `rename`).
//!   Empty shards are deleted. This is O(DLQ size) per consume but
//!   DLQs are expected to stay small relative to ingest throughput —
//!   if they don't, an ops human is already in the loop.
//! - **No in-memory state beyond the active shard**; on process
//!   restart the next `open` just lists existing shards and resumes
//!   writing to a new filename.
//!
//! Called from the ingest writer path (parse failures) and from the
//! invariant checker (P1/P4 violations post-ingest). Consumed by the
//! DLQ API ops (`list_dead_letters`, `reingest_dead_letter`).

use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::fs::{File, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

pub const DLQ_FILE_PREFIX: &str = "dlq_";
pub const DLQ_FILE_EXT: &str = "jsonl";
/// Shard rolls when it hits *either* limit. Values picked so a single
/// shard stays trivially loadable into memory for rewrite.
pub const SHARD_MAX_RECORDS: usize = 10_000;
pub const SHARD_MAX_BYTES: u64 = 8 * 1024 * 1024;

/// Why a row landed in the DLQ. Keeps the surface tight so UI filters
/// don't have to scan free-text reasons.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FailureKind {
    /// The parser (or VRL program) couldn't produce a triple.
    ParseFailure,
    /// P1 causal-monotonicity violation: child timestamp before parent.
    InvariantCausality,
    /// P4 referential-closure violation: endpoint not in dataset scope.
    InvariantReferential,
    /// P2 type-shape plausibility failure.
    InvariantTypeShape,
    /// Row produced zero triples (not necessarily a failure, but
    /// worth surfacing when a dataset inexplicably yields nothing).
    EmptyYield,
    /// Catch-all for row-level errors that don't fit above. Carries
    /// a free-text `reason` on the record.
    Other,
}

/// One dead-letter record. Sized to survive a JSON round trip — the
/// `raw_event` is carried verbatim so re-ingest is loss-free.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeadLetter {
    /// Stable id. Shard-qualified so `<shard>_<line>` can't collide
    /// across rotations.
    pub dlq_id: String,
    /// Original row (exact bytes, as utf-8). Whatever the source
    /// handed the parser.
    pub raw_event: String,
    pub failure_kind: FailureKind,
    pub reason: String,
    /// Dataset this row was being ingested into. `None` for rows
    /// intercepted before dataset resolution.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dataset_id: Option<String>,
    /// Source id (from `ParsedBatch.source_id`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_id: Option<String>,
    /// Epoch seconds at the moment the row was rejected.
    pub ts_received: i64,
}

#[derive(Debug)]
pub enum DlqError {
    Io(std::io::Error),
    Serialize(serde_json::Error),
    Deserialize {
        path: PathBuf,
        line: usize,
        source: serde_json::Error,
    },
}

impl std::fmt::Display for DlqError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DlqError::Io(e) => write!(f, "dlq I/O error: {e}"),
            DlqError::Serialize(e) => write!(f, "dlq serialize error: {e}"),
            DlqError::Deserialize { path, line, source } => {
                write!(
                    f,
                    "dlq deserialize error at {}:{line}: {source}",
                    path.display()
                )
            }
        }
    }
}

impl std::error::Error for DlqError {}

impl From<std::io::Error> for DlqError {
    fn from(e: std::io::Error) -> Self {
        DlqError::Io(e)
    }
}

impl From<serde_json::Error> for DlqError {
    fn from(e: serde_json::Error) -> Self {
        DlqError::Serialize(e)
    }
}

/// Append-only DLQ keyed to a directory.
pub struct DlqStore {
    dir: PathBuf,
    /// Guards the active shard so concurrent writers don't interleave
    /// partial lines.
    active: Mutex<ActiveShard>,
    /// Monotonic counter for dlq_id generation; keeps ids unique
    /// within a shard across simultaneous writes that share ts_ms.
    counter: AtomicU64,
}

struct ActiveShard {
    path: PathBuf,
    records: usize,
    bytes: u64,
}

impl DlqStore {
    /// Open (creating if missing) a DLQ store rooted at `dir`. A fresh
    /// shard is always allocated — pre-existing shards stay readable
    /// but we don't append to them to avoid races with concurrent
    /// processes over the same session dir.
    pub fn open(dir: impl Into<PathBuf>) -> Result<Self, DlqError> {
        let dir = dir.into();
        std::fs::create_dir_all(&dir)?;
        let seed = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_nanos() as u64)
            .unwrap_or(0);
        let active_path = dir.join(next_filename(seed));
        Ok(Self {
            dir,
            active: Mutex::new(ActiveShard {
                path: active_path,
                records: 0,
                bytes: 0,
            }),
            counter: AtomicU64::new(seed),
        })
    }

    pub fn dir(&self) -> &Path {
        &self.dir
    }

    /// Append one record. Returns its `dlq_id` so callers can cite it
    /// in logs / metrics. Rolls the shard if the caps are exceeded.
    pub fn append(&self, mut record: DeadLetter) -> Result<String, DlqError> {
        let mut active = self.active.lock().expect("dlq active lock poisoned");
        if active.records >= SHARD_MAX_RECORDS || active.bytes >= SHARD_MAX_BYTES {
            let ctr = self.counter.fetch_add(1, Ordering::Relaxed);
            active.path = self.dir.join(next_filename(ctr));
            active.records = 0;
            active.bytes = 0;
        }
        // Assign dlq_id if caller left it empty — they usually do.
        if record.dlq_id.is_empty() {
            let ctr = self.counter.fetch_add(1, Ordering::Relaxed);
            record.dlq_id = format!("{}-{}", active.records, ctr);
        }
        let id = record.dlq_id.clone();
        let mut line = serde_json::to_vec(&record)?;
        line.push(b'\n');
        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&active.path)?;
        file.write_all(&line)?;
        active.records += 1;
        active.bytes += line.len() as u64;
        Ok(id)
    }

    /// Read every record across every shard, chronological order.
    /// Skips malformed lines (logs via `tracing::warn` in real deploys
    /// — here we just surface as `Deserialize` error *for the first*
    /// malformed line so tests can assert).
    pub fn list_all(&self) -> Result<Vec<DeadLetter>, DlqError> {
        let mut out = Vec::new();
        for path in self.shards()? {
            let file = File::open(&path)?;
            for (line_no, line) in BufReader::new(file).lines().enumerate() {
                let line = line?;
                if line.trim().is_empty() {
                    continue;
                }
                let rec: DeadLetter =
                    serde_json::from_str(&line).map_err(|e| DlqError::Deserialize {
                        path: path.clone(),
                        line: line_no + 1,
                        source: e,
                    })?;
                out.push(rec);
            }
        }
        Ok(out)
    }

    /// Total record count without loading payloads. Uses a fast
    /// line-count on every shard.
    pub fn pending_count(&self) -> Result<usize, DlqError> {
        let mut count = 0;
        for path in self.shards()? {
            let file = File::open(&path)?;
            for line in BufReader::new(file).lines() {
                let line = line?;
                if !line.trim().is_empty() {
                    count += 1;
                }
            }
        }
        Ok(count)
    }

    /// Drop every record whose id is in `ids`. Rewrites shards
    /// atomically (`.tmp` + rename). Returns the number actually
    /// removed. Empty shards are deleted.
    pub fn consume(&self, ids: &HashSet<String>) -> Result<usize, DlqError> {
        if ids.is_empty() {
            return Ok(0);
        }
        let mut removed = 0usize;
        for path in self.shards()? {
            let file = File::open(&path)?;
            let mut kept: Vec<String> = Vec::new();
            for line in BufReader::new(file).lines() {
                let line = line?;
                if line.trim().is_empty() {
                    continue;
                }
                let rec: DeadLetter = match serde_json::from_str(&line) {
                    Ok(r) => r,
                    Err(_) => {
                        // Skip malformed lines rather than aborting the
                        // entire consume — a crashed writer might have
                        // left half a line behind.
                        continue;
                    }
                };
                if ids.contains(&rec.dlq_id) {
                    removed += 1;
                } else {
                    kept.push(line);
                }
            }
            if kept.is_empty() {
                std::fs::remove_file(&path)?;
                continue;
            }
            let tmp = path.with_extension(format!("{}.tmp", DLQ_FILE_EXT));
            {
                let mut out = File::create(&tmp)?;
                for l in &kept {
                    out.write_all(l.as_bytes())?;
                    out.write_all(b"\n")?;
                }
            }
            std::fs::rename(&tmp, &path)?;
        }
        Ok(removed)
    }

    /// Delete every shard. Used by tests and purge ops.
    pub fn clear(&self) -> Result<(), DlqError> {
        for path in self.shards()? {
            std::fs::remove_file(path)?;
        }
        let mut active = self.active.lock().expect("dlq active lock poisoned");
        active.records = 0;
        active.bytes = 0;
        Ok(())
    }

    fn shards(&self) -> Result<Vec<PathBuf>, DlqError> {
        let mut files = Vec::new();
        for entry in std::fs::read_dir(&self.dir)? {
            let entry = entry?;
            let path = entry.path();
            if !path.is_file() {
                continue;
            }
            let Some(name) = path.file_name().and_then(|n| n.to_str()) else {
                continue;
            };
            if !name.starts_with(DLQ_FILE_PREFIX) {
                continue;
            }
            let expected = format!(".{DLQ_FILE_EXT}");
            if !name.ends_with(&expected) {
                continue;
            }
            files.push(path);
        }
        files.sort();
        Ok(files)
    }
}

fn next_filename(ctr: u64) -> String {
    let ts_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0);
    format!(
        "{}{:016}_{:020}.{}",
        DLQ_FILE_PREFIX, ts_ms, ctr, DLQ_FILE_EXT
    )
}

// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn mk(raw: &str, kind: FailureKind) -> DeadLetter {
        DeadLetter {
            dlq_id: String::new(),
            raw_event: raw.into(),
            failure_kind: kind,
            reason: "test".into(),
            dataset_id: Some("ds-1".into()),
            source_id: Some("src-1".into()),
            ts_received: 0,
        }
    }

    #[test]
    fn append_then_list_round_trips() {
        let tmp = TempDir::new().unwrap();
        let dlq = DlqStore::open(tmp.path()).unwrap();
        let _id1 = dlq.append(mk("row-a", FailureKind::ParseFailure)).unwrap();
        let _id2 = dlq
            .append(mk("row-b", FailureKind::InvariantCausality))
            .unwrap();
        let all = dlq.list_all().unwrap();
        assert_eq!(all.len(), 2);
        assert_eq!(all[0].raw_event, "row-a");
        assert_eq!(all[1].failure_kind, FailureKind::InvariantCausality);
    }

    #[test]
    fn consume_removes_matching_ids_and_compacts_shards() {
        let tmp = TempDir::new().unwrap();
        let dlq = DlqStore::open(tmp.path()).unwrap();
        let id1 = dlq.append(mk("row-a", FailureKind::ParseFailure)).unwrap();
        let _id2 = dlq.append(mk("row-b", FailureKind::ParseFailure)).unwrap();
        let mut set = HashSet::new();
        set.insert(id1);
        let removed = dlq.consume(&set).unwrap();
        assert_eq!(removed, 1);
        let all = dlq.list_all().unwrap();
        assert_eq!(all.len(), 1);
        assert_eq!(all[0].raw_event, "row-b");
    }

    #[test]
    fn pending_count_matches_appended() {
        let tmp = TempDir::new().unwrap();
        let dlq = DlqStore::open(tmp.path()).unwrap();
        for i in 0..5 {
            dlq.append(mk(&format!("row-{i}"), FailureKind::Other))
                .unwrap();
        }
        assert_eq!(dlq.pending_count().unwrap(), 5);
    }

    #[test]
    fn clear_empties_every_shard() {
        let tmp = TempDir::new().unwrap();
        let dlq = DlqStore::open(tmp.path()).unwrap();
        dlq.append(mk("row-a", FailureKind::ParseFailure)).unwrap();
        dlq.clear().unwrap();
        assert_eq!(dlq.pending_count().unwrap(), 0);
    }

    #[test]
    fn consume_empty_set_is_noop() {
        let tmp = TempDir::new().unwrap();
        let dlq = DlqStore::open(tmp.path()).unwrap();
        dlq.append(mk("row-a", FailureKind::ParseFailure)).unwrap();
        let removed = dlq.consume(&HashSet::new()).unwrap();
        assert_eq!(removed, 0);
        assert_eq!(dlq.pending_count().unwrap(), 1);
    }
}
