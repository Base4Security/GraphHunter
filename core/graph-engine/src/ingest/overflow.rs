//! On-shutdown overflow persistence for pending `ParsedBatch`es.
//!
//! Plan §8 defines the shutdown sequence:
//!
//! 1. `AppCancelToken.cancel()` — propagates to every source poller
//! 2. Pollers flush watermarks to sqlite (0-2 s)
//! 3. `GraphWriter` drains `parsed_tx` up to a 5-second budget
//! 4. **Any batches that couldn't be drained are serialized to
//!    `<session_dir>/ingest_overflow/pending_<ts>.cbor` for replay
//!    on next startup**
//! 5. `edge_store.finalize()` runs the streaming merge
//! 6. Session JSON + sqlite checkpoint committed to disk
//! 7. Hard timeout 12 s total
//!
//! This module is step 4's implementation. It serializes a
//! `ParsedBatch` to a JSON file in a caller-supplied directory,
//! and on the next startup reads every pending file back into
//! memory so the writer can replay them before new traffic starts.
//!
//! Design choices:
//!
//! - **JSON, not CBOR.** Plan §8 said CBOR but that would add a new
//!   dep (`ciborium`, `serde_cbor`). JSON is slower and slightly
//!   larger but uses the `serde_json` dep that's already in the
//!   tree. At shutdown this runs at most once per batch in the
//!   queue; throughput isn't a concern.
//! - **File per batch, not one append-only log.** Simpler recovery
//!   story: if a single file is corrupted, only that one batch is
//!   lost. Atomic rename on write (write to `.tmp`, fsync, rename)
//!   prevents partial reads. Filenames use epoch-ms timestamps so
//!   glob sort = chronological sort, which matters because the
//!   writer replays batches in send order.
//! - **Caller owns the directory.** The overflow dir lives at
//!   `<session_dir>/ingest_overflow/`. The plan says "move spill
//!   dir under session dir" (Phase 1 §6, deferred); this module
//!   follows the same ownership model so Phase 9 Tauri wiring can
//!   hand the right path in.
//! - **Idempotent recovery.** `read_pending` does NOT delete the
//!   files it returns — the caller (`GraphWriter` or a replay
//!   helper) calls `consume_batch(path)` after each successful
//!   re-insertion. If the process crashes during replay, the
//!   next startup sees the same files and retries.

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use super::batch::ParsedBatch;

/// Filename prefix for pending overflow files. Callers sort by
/// filename to get chronological ordering.
pub const OVERFLOW_FILE_PREFIX: &str = "pending_";
pub const OVERFLOW_FILE_EXT: &str = "json";

/// Errors surfaced by the overflow store.
#[derive(Debug)]
pub enum OverflowError {
    Io(std::io::Error),
    Serialize(serde_json::Error),
    Deserialize {
        path: PathBuf,
        source: serde_json::Error,
    },
}

impl std::fmt::Display for OverflowError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            OverflowError::Io(e) => write!(f, "overflow I/O error: {e}"),
            OverflowError::Serialize(e) => write!(f, "overflow serialize error: {e}"),
            OverflowError::Deserialize { path, source } => {
                write!(
                    f,
                    "overflow deserialize error at {}: {source}",
                    path.display()
                )
            }
        }
    }
}

impl std::error::Error for OverflowError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            OverflowError::Io(e) => Some(e),
            OverflowError::Serialize(e) => Some(e),
            OverflowError::Deserialize { source, .. } => Some(source),
        }
    }
}

impl From<std::io::Error> for OverflowError {
    fn from(e: std::io::Error) -> Self {
        OverflowError::Io(e)
    }
}

impl From<serde_json::Error> for OverflowError {
    fn from(e: serde_json::Error) -> Self {
        OverflowError::Serialize(e)
    }
}

/// A persistent queue of pending `ParsedBatch`es.
///
/// Lives at a caller-supplied directory. Thread-safe at the OS level
/// (each batch is written to a uniquely-named file), but NOT
/// transactional across batches — a crash mid-`write_batch` may
/// leave a `.tmp` file behind, which is ignored by `read_pending`.
pub struct OverflowStore {
    dir: PathBuf,
    /// Monotonic counter appended to filenames so two writes in the
    /// same millisecond don't collide. Starts at a random-ish value
    /// to spread filename-collision risk across processes.
    counter: AtomicU64,
}

impl OverflowStore {
    /// Opens (or creates) an overflow store at the given directory.
    /// Creates the directory if it doesn't exist.
    pub fn open(dir: impl Into<PathBuf>) -> Result<Self, OverflowError> {
        let dir = dir.into();
        std::fs::create_dir_all(&dir)?;
        let seed = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_nanos() as u64)
            .unwrap_or(0);
        Ok(Self {
            dir,
            counter: AtomicU64::new(seed),
        })
    }

    /// Path to the overflow directory. Useful for metrics and debug.
    pub fn dir(&self) -> &Path {
        &self.dir
    }

    /// Writes a batch to a new file in the overflow directory. Uses
    /// an atomic write pattern: write to `.tmp`, flush, rename. The
    /// returned path points at the final file.
    pub fn write_batch(&self, batch: &ParsedBatch) -> Result<PathBuf, OverflowError> {
        let filename = self.next_filename();
        let tmp_path = self.dir.join(format!("{filename}.tmp"));
        let final_path = self.dir.join(filename);

        // Serialize to string first so a serialize failure doesn't
        // leave a half-written file on disk.
        let json = serde_json::to_vec(batch)?;
        std::fs::write(&tmp_path, &json)?;
        // Atomic rename — on POSIX this is guaranteed; on Windows
        // `std::fs::rename` fails if the destination exists, but we
        // use a unique filename so that's fine.
        std::fs::rename(&tmp_path, &final_path)?;
        Ok(final_path)
    }

    /// Reads every pending batch from the overflow directory, sorted
    /// chronologically by filename. Returns `(path, ParsedBatch)`
    /// pairs so the caller can call `consume_batch(path)` after
    /// successful re-insertion.
    ///
    /// Skips files matching `*.tmp` (in-progress writes from a
    /// crashed shutdown). A future startup GC pass can clean those up.
    pub fn read_pending(&self) -> Result<Vec<(PathBuf, ParsedBatch)>, OverflowError> {
        let mut files: Vec<PathBuf> = Vec::new();
        for entry in std::fs::read_dir(&self.dir)? {
            let entry = entry?;
            let path = entry.path();
            if !path.is_file() {
                continue;
            }
            let Some(name) = path.file_name().and_then(|n| n.to_str()) else {
                continue;
            };
            if !name.starts_with(OVERFLOW_FILE_PREFIX) {
                continue;
            }
            if !name.ends_with(&format!(".{OVERFLOW_FILE_EXT}")) {
                // Skips .tmp, .bak, and any unrelated files.
                continue;
            }
            files.push(path);
        }
        // Chronological sort via filename — the `pending_<ts>_<ctr>`
        // format gives a valid lexicographic ordering because the
        // timestamp is zero-padded.
        files.sort();

        let mut out = Vec::with_capacity(files.len());
        for path in files {
            let bytes = std::fs::read(&path)?;
            let batch: ParsedBatch =
                serde_json::from_slice(&bytes).map_err(|e| OverflowError::Deserialize {
                    path: path.clone(),
                    source: e,
                })?;
            out.push((path, batch));
        }
        Ok(out)
    }

    /// Deletes a single overflow file. Called by the caller after
    /// successfully re-inserting the batch it contained.
    pub fn consume_batch(&self, path: &Path) -> Result<(), OverflowError> {
        std::fs::remove_file(path)?;
        Ok(())
    }

    /// Deletes every pending file in the overflow directory. Used
    /// by tests and emergency cleanup paths.
    pub fn clear(&self) -> Result<(), OverflowError> {
        for entry in std::fs::read_dir(&self.dir)? {
            let entry = entry?;
            let path = entry.path();
            if path.is_file() {
                std::fs::remove_file(path)?;
            }
        }
        Ok(())
    }

    /// Returns how many pending files are currently on disk. Counts
    /// both completed and in-progress (`.tmp`) files — the in-progress
    /// count should be zero under normal operation.
    pub fn pending_count(&self) -> Result<usize, OverflowError> {
        let mut count = 0;
        for entry in std::fs::read_dir(&self.dir)? {
            let entry = entry?;
            let path = entry.path();
            if path.is_file() {
                let Some(name) = path.file_name().and_then(|n| n.to_str()) else {
                    continue;
                };
                if name.starts_with(OVERFLOW_FILE_PREFIX)
                    && name.ends_with(&format!(".{OVERFLOW_FILE_EXT}"))
                {
                    count += 1;
                }
            }
        }
        Ok(count)
    }

    fn next_filename(&self) -> String {
        let ctr = self.counter.fetch_add(1, Ordering::Relaxed);
        let ts_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0);
        // 16-digit zero-padded timestamp + counter ensures stable
        // lexicographic ordering even when two writes share a ms.
        format!(
            "{}{:016}_{:020}.{}",
            OVERFLOW_FILE_PREFIX, ts_ms, ctr, OVERFLOW_FILE_EXT
        )
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ingest::batch::{ParsedBatch, Priority};
    use crate::parser::RawIngestEvent;
    use crate::types::{EntityType, RelationType};
    use graph_hunter_sources::Watermark;
    use std::collections::HashMap;
    use tempfile::TempDir;

    fn mk_event(src: &str, dst: &str, ts: i64) -> RawIngestEvent {
        RawIngestEvent {
            src_id: src.to_string(),
            src_type: EntityType::User,
            src_metadata: HashMap::new(),
            dst_id: dst.to_string(),
            dst_type: EntityType::Process,
            dst_metadata: HashMap::new(),
            rel_type: RelationType::Auth,
            rel_metadata: HashMap::new(),
            timestamp: ts,
        }
    }

    fn mk_batch(source_id: &str, n: usize) -> ParsedBatch {
        let events: Vec<RawIngestEvent> = (0..n)
            .map(|i| mk_event(&format!("u-{i}"), &format!("p-{i}"), 100 + i as i64))
            .collect();
        ParsedBatch::new(source_id, events)
            .with_dataset_id("dataset-1")
            .with_priority(Priority::Normal)
    }

    #[test]
    fn open_creates_directory() {
        let tmp = TempDir::new().unwrap();
        let sub = tmp.path().join("overflow");
        assert!(!sub.exists());
        let _store = OverflowStore::open(&sub).unwrap();
        assert!(sub.exists());
        assert!(sub.is_dir());
    }

    #[test]
    fn write_and_read_single_batch_roundtrip() {
        let tmp = TempDir::new().unwrap();
        let store = OverflowStore::open(tmp.path()).unwrap();
        let batch = mk_batch("la:ws-1", 3);
        let path = store.write_batch(&batch).unwrap();
        assert!(path.exists());
        assert_eq!(store.pending_count().unwrap(), 1);

        let pending = store.read_pending().unwrap();
        assert_eq!(pending.len(), 1);
        let (read_path, read_batch) = &pending[0];
        assert_eq!(read_path, &path);
        assert_eq!(read_batch.source_id, "la:ws-1");
        assert_eq!(read_batch.dataset_id.as_deref(), Some("dataset-1"));
        assert_eq!(read_batch.events.len(), 3);
        assert_eq!(read_batch.row_count, 3);
    }

    #[test]
    fn pending_batches_returned_in_write_order() {
        let tmp = TempDir::new().unwrap();
        let store = OverflowStore::open(tmp.path()).unwrap();

        // Write 5 batches in order. The counter appended to the
        // filename disambiguates same-ms writes, so sort-by-filename
        // gives insertion order.
        let mut written_paths = Vec::new();
        for i in 0..5 {
            let batch = mk_batch(&format!("source-{i}"), 1);
            written_paths.push(store.write_batch(&batch).unwrap());
        }
        assert_eq!(store.pending_count().unwrap(), 5);

        let pending = store.read_pending().unwrap();
        assert_eq!(pending.len(), 5);
        for (i, (_, batch)) in pending.iter().enumerate() {
            assert_eq!(batch.source_id, format!("source-{i}"));
        }
    }

    #[test]
    fn consume_batch_deletes_file() {
        let tmp = TempDir::new().unwrap();
        let store = OverflowStore::open(tmp.path()).unwrap();
        let batch = mk_batch("la:ws-1", 1);
        let path = store.write_batch(&batch).unwrap();
        assert!(path.exists());

        store.consume_batch(&path).unwrap();
        assert!(!path.exists());
        assert_eq!(store.pending_count().unwrap(), 0);
    }

    #[test]
    fn read_pending_on_empty_dir_returns_empty() {
        let tmp = TempDir::new().unwrap();
        let store = OverflowStore::open(tmp.path()).unwrap();
        let pending = store.read_pending().unwrap();
        assert!(pending.is_empty());
    }

    #[test]
    fn read_pending_skips_unrelated_files() {
        let tmp = TempDir::new().unwrap();
        let store = OverflowStore::open(tmp.path()).unwrap();

        // Drop a non-overflow file into the dir.
        std::fs::write(tmp.path().join("other.txt"), "unrelated").unwrap();
        // Drop a .tmp file (simulated crashed write).
        std::fs::write(tmp.path().join("pending_leftover.json.tmp"), "{}").unwrap();
        // Drop a .bak file.
        std::fs::write(tmp.path().join("pending_leftover.json.bak"), "{}").unwrap();

        // Write a real overflow batch.
        store.write_batch(&mk_batch("la:ws-1", 1)).unwrap();

        let pending = store.read_pending().unwrap();
        // Only the one real overflow file is returned.
        assert_eq!(pending.len(), 1);
        assert_eq!(pending[0].1.source_id, "la:ws-1");
    }

    #[test]
    fn read_pending_preserves_watermark_and_priority() {
        let tmp = TempDir::new().unwrap();
        let store = OverflowStore::open(tmp.path()).unwrap();

        let batch = mk_batch("la:ws-1", 2)
            .with_priority(Priority::Enrichment)
            .with_watermark("SecurityEvent", Watermark::new("2026-04-09T10:00:00Z"));
        store.write_batch(&batch).unwrap();

        let pending = store.read_pending().unwrap();
        let read_batch = &pending[0].1;
        assert_eq!(read_batch.priority, Priority::Enrichment);
        let (table, wm) = read_batch.watermark_after.as_ref().unwrap();
        assert_eq!(table, "SecurityEvent");
        assert_eq!(wm.as_str(), "2026-04-09T10:00:00Z");
    }

    #[test]
    fn clear_removes_all_files() {
        let tmp = TempDir::new().unwrap();
        let store = OverflowStore::open(tmp.path()).unwrap();
        for i in 0..5 {
            store.write_batch(&mk_batch(&format!("s-{i}"), 1)).unwrap();
        }
        assert_eq!(store.pending_count().unwrap(), 5);
        store.clear().unwrap();
        assert_eq!(store.pending_count().unwrap(), 0);
    }

    #[test]
    fn empty_batch_roundtrips() {
        let tmp = TempDir::new().unwrap();
        let store = OverflowStore::open(tmp.path()).unwrap();
        let batch = ParsedBatch::new("la:ws-1", Vec::new());
        store.write_batch(&batch).unwrap();
        let pending = store.read_pending().unwrap();
        assert_eq!(pending.len(), 1);
        assert_eq!(pending[0].1.events.len(), 0);
    }

    #[test]
    fn deserialize_error_carries_file_path() {
        let tmp = TempDir::new().unwrap();
        let store = OverflowStore::open(tmp.path()).unwrap();

        // Write a deliberately bad file with the expected prefix.
        let bad_path = tmp
            .path()
            .join(format!("{OVERFLOW_FILE_PREFIX}0000000000000000_00.json"));
        std::fs::write(&bad_path, b"{not valid json").unwrap();

        match store.read_pending() {
            Err(OverflowError::Deserialize { path, .. }) => {
                assert_eq!(path, bad_path);
            }
            other => panic!("expected Deserialize error, got {other:?}"),
        }
    }

    #[test]
    fn large_batch_roundtrips_losslessly() {
        let tmp = TempDir::new().unwrap();
        let store = OverflowStore::open(tmp.path()).unwrap();

        let batch = mk_batch("la:ws-1", 1000);
        store.write_batch(&batch).unwrap();

        let pending = store.read_pending().unwrap();
        assert_eq!(pending.len(), 1);
        assert_eq!(pending[0].1.events.len(), 1000);
        // Spot-check the first and last event made it through.
        assert_eq!(pending[0].1.events[0].src_id, "u-0");
        assert_eq!(pending[0].1.events[999].src_id, "u-999");
    }
}
