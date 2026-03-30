//! Spillable edge store: keeps edges in RAM up to a memory budget,
//! then spills sorted runs to disk. After finalize() all edges are
//! accessible via mmap with an LRU cache.

use std::collections::HashMap;
use std::io::{Write, BufWriter};
use std::num::NonZeroUsize;
use std::sync::Mutex;

use crate::errors::SpillError;
use crate::interner::StrId;
use crate::relation::CompactRelation;

/// Magic number for spill file headers.
const SPILL_MAGIC: u32 = 0x47485350; // "GHSP"
/// Version of the spill file format.
const SPILL_VERSION: u32 = 1;
/// Size of a single CompactRelation record on disk (fixed layout).
const RECORD_SIZE: usize = std::mem::size_of::<CompactRelation>();
/// Default number of source-node entries the LRU cache holds.
const DEFAULT_LRU_CAPACITY: usize = 10_000;

/// Index entry: points to a range of records in the merged file.
#[derive(Clone, Debug)]
struct IndexEntry {
    offset: u64,  // byte offset in merged file
    count: u32,   // number of records
}

/// Spill file metadata.
struct SpillFile {
    _path: std::path::PathBuf,
    mmap: memmap2::Mmap,
    record_count: u64,
}

/// Spillable edge store that keeps edges in RAM up to a budget,
/// then spills to disk. After finalize(), provides indexed access.
pub struct SpillableEdgeStore {
    // --- Ingestion mode ---
    buffer: Vec<CompactRelation>,
    buffer_index: HashMap<StrId, Vec<u32>>, // sid -> indices in buffer
    memory_budget: usize,
    current_memory: usize,

    // --- Spill files ---
    spill_files: Vec<SpillFile>,
    temp_dir: Option<tempfile::TempDir>,

    // --- Merged (query mode) ---
    merged_mmap: Option<memmap2::Mmap>,
    merged_index: HashMap<StrId, IndexEntry>,

    // --- LRU cache (behind Mutex for interior mutability so get_edges can take &self) ---
    cache: Mutex<lru::LruCache<StrId, Vec<CompactRelation>>>,

    finalized: bool,
}

impl SpillableEdgeStore {
    /// Creates a new store with the given memory budget in bytes.
    /// Default: 2GB.
    pub fn new(memory_budget: usize) -> Self {
        Self {
            buffer: Vec::new(),
            buffer_index: HashMap::new(),
            memory_budget,
            current_memory: 0,
            spill_files: Vec::new(),
            temp_dir: None,
            merged_mmap: None,
            merged_index: HashMap::new(),
            cache: Mutex::new(lru::LruCache::new(
                NonZeroUsize::new(DEFAULT_LRU_CAPACITY).unwrap(),
            )),
            finalized: false,
        }
    }

    /// Creates a store with default 2GB budget.
    pub fn with_default_budget() -> Self {
        Self::new(2 * 1024 * 1024 * 1024) // 2GB
    }

    /// Appends a relation during ingestion.
    /// If the store was finalized, it automatically unfinalizes to accept new data.
    pub fn push(&mut self, rel: CompactRelation) -> Result<(), SpillError> {
        if self.finalized {
            // Unfinalize: move merged data back to buffer for continued ingestion
            self.finalized = false;
            // Buffer already contains sorted data from finalize; new pushes append to it
            // The index will be rebuilt on next finalize
            self.buffer_index.clear();
            for (i, r) in self.buffer.iter().enumerate() {
                self.buffer_index.entry(r.source_sid).or_default().push(i as u32);
            }
        }

        // Invalidate any cached entry for this source_sid (stale after new push)
        self.cache.lock().unwrap().pop(&rel.source_sid);

        let idx = self.buffer.len() as u32;
        self.buffer_index
            .entry(rel.source_sid)
            .or_default()
            .push(idx);
        self.buffer.push(rel);
        self.current_memory += RECORD_SIZE;

        if self.current_memory >= self.memory_budget {
            self.spill()?;
        }
        Ok(())
    }

    /// Returns the number of edges currently in the buffer (before finalize).
    pub fn buffer_len(&self) -> usize {
        self.buffer.len()
    }

    /// Whether the store has been finalized.
    pub fn is_finalized(&self) -> bool {
        self.finalized
    }

    /// Spills the current buffer to a sorted temp file.
    fn spill(&mut self) -> Result<(), SpillError> {
        if self.buffer.is_empty() {
            return Ok(());
        }

        // Sort by (source_sid, timestamp)
        self.buffer.sort_unstable_by(|a, b| {
            a.source_sid.index().cmp(&b.source_sid.index())
                .then(a.timestamp.cmp(&b.timestamp))
        });

        // Ensure temp dir exists
        if self.temp_dir.is_none() {
            self.temp_dir = Some(tempfile::tempdir().map_err(SpillError::TempDir)?);
        }
        let dir = self.temp_dir.as_ref().unwrap().path();
        let spill_path = dir.join(format!("spill_{}.bin", self.spill_files.len()));

        // Write header + records
        let file = std::fs::File::create(&spill_path).map_err(SpillError::Io)?;
        let mut writer = BufWriter::new(file);

        writer.write_all(&SPILL_MAGIC.to_le_bytes()).map_err(SpillError::Io)?;
        writer.write_all(&SPILL_VERSION.to_le_bytes()).map_err(SpillError::Io)?;
        let count = self.buffer.len() as u64;
        writer.write_all(&count.to_le_bytes()).map_err(SpillError::Io)?;

        // Write records as raw bytes
        for rel in &self.buffer {
            let bytes: &[u8] = unsafe {
                std::slice::from_raw_parts(
                    rel as *const CompactRelation as *const u8,
                    RECORD_SIZE,
                )
            };
            writer.write_all(bytes).map_err(SpillError::Io)?;
        }
        writer.flush().map_err(SpillError::Io)?;
        drop(writer);

        // Mmap the spill file
        let file = std::fs::File::open(&spill_path).map_err(SpillError::Io)?;
        let mmap = unsafe { memmap2::Mmap::map(&file).map_err(SpillError::Mmap)? };

        self.spill_files.push(SpillFile {
            _path: spill_path,
            mmap,
            record_count: count,
        });

        // Clear buffer
        self.buffer.clear();
        self.buffer_index.clear();
        self.current_memory = 0;
        Ok(())
    }

    /// Finalizes the store: merge-sorts all spill files + buffer into one
    /// indexed mmap file. For small datasets (no spills), just sorts in-place.
    pub fn finalize(&mut self) -> Result<(), SpillError> {
        if self.finalized {
            return Ok(());
        }

        // Clear any pre-finalization cache entries
        self.cache.lock().unwrap().clear();

        if self.spill_files.is_empty() {
            // No spills: sort buffer in-place, build index directly
            self.buffer.sort_unstable_by(|a, b| {
                a.source_sid.index().cmp(&b.source_sid.index())
                    .then(a.timestamp.cmp(&b.timestamp))
            });

            // Build index from sorted buffer
            self.merged_index.clear();
            let mut i = 0;
            while i < self.buffer.len() {
                let sid = self.buffer[i].source_sid;
                let start = i;
                while i < self.buffer.len() && self.buffer[i].source_sid == sid {
                    i += 1;
                }
                self.merged_index.insert(sid, IndexEntry {
                    offset: start as u64,
                    count: (i - start) as u32,
                });
            }

            self.finalized = true;
            return Ok(());
        }

        // Spill remaining buffer
        self.spill()?;

        // Merge-sort all spill files into one merged file
        let dir = self.temp_dir.as_ref().unwrap().path();
        let merged_path = dir.join("merged.bin");

        let file = std::fs::File::create(&merged_path).map_err(SpillError::Io)?;
        let mut writer = BufWriter::new(file);

        // Read all records from all spill files (they're already sorted)
        let mut all_records: Vec<CompactRelation> = Vec::new();
        for spill in &self.spill_files {
            let header_size = 16; // magic + version + count
            let data = &spill.mmap[header_size..];
            let records: &[CompactRelation] = unsafe {
                std::slice::from_raw_parts(
                    data.as_ptr() as *const CompactRelation,
                    spill.record_count as usize,
                )
            };
            all_records.extend_from_slice(records);
        }

        // Sort merged records
        all_records.sort_unstable_by(|a, b| {
            a.source_sid.index().cmp(&b.source_sid.index())
                .then(a.timestamp.cmp(&b.timestamp))
        });

        // Write header
        writer.write_all(&SPILL_MAGIC.to_le_bytes()).map_err(SpillError::Io)?;
        writer.write_all(&SPILL_VERSION.to_le_bytes()).map_err(SpillError::Io)?;
        let total_count = all_records.len() as u64;
        writer.write_all(&total_count.to_le_bytes()).map_err(SpillError::Io)?;

        // Write sorted records
        for rel in &all_records {
            let bytes: &[u8] = unsafe {
                std::slice::from_raw_parts(
                    rel as *const CompactRelation as *const u8,
                    RECORD_SIZE,
                )
            };
            writer.write_all(bytes).map_err(SpillError::Io)?;
        }

        // Write index
        let mut index_entries: Vec<(StrId, u64, u32)> = Vec::new();
        let mut i = 0;
        while i < all_records.len() {
            let sid = all_records[i].source_sid;
            let start = i;
            while i < all_records.len() && all_records[i].source_sid == sid {
                i += 1;
            }
            index_entries.push((sid, start as u64, (i - start) as u32));
        }

        let entry_count = index_entries.len() as u64;
        writer.write_all(&entry_count.to_le_bytes()).map_err(SpillError::Io)?;
        for (sid, offset, count) in &index_entries {
            writer.write_all(&(sid.index() as u32).to_le_bytes()).map_err(SpillError::Io)?;
            writer.write_all(&offset.to_le_bytes()).map_err(SpillError::Io)?;
            writer.write_all(&count.to_le_bytes()).map_err(SpillError::Io)?;
        }

        writer.flush().map_err(SpillError::Io)?;
        drop(writer);

        // Mmap merged file
        let file = std::fs::File::open(&merged_path).map_err(SpillError::Io)?;
        let mmap = unsafe { memmap2::Mmap::map(&file).map_err(SpillError::Mmap)? };

        // Build in-memory index
        self.merged_index.clear();
        for (sid, offset, count) in index_entries {
            self.merged_index.insert(sid, IndexEntry { offset, count });
        }

        self.merged_mmap = Some(mmap);

        // Clean up spill files (keep temp_dir alive for merged file)
        self.spill_files.clear();
        drop(all_records);

        self.finalized = true;
        Ok(())
    }

    /// Gets edges for a source node.
    ///
    /// Takes `&self` so it can be called during concurrent reads (hunts, MCP).
    /// For the finalized no-spill case, returns a slice directly from the sorted buffer.
    /// For the finalized mmap case, returns a slice directly from the mmap'd memory.
    /// For the unfinalized case (before finalize()), gathers edges from the buffer
    /// index into an internal cache and returns a slice from it. This enables
    /// backward-compatible usage where queries happen before finalization.
    pub fn get_edges(&self, sid: StrId) -> &[CompactRelation] {
        if !self.finalized {
            // Before finalization: edges are scattered in the buffer.
            // Use the buffer_index to find them, collect into cache, and
            // return a slice. The cache is behind a Mutex for interior mutability.
            if let Some(indices) = self.buffer_index.get(&sid) {
                if indices.is_empty() {
                    return &[];
                }
                let mut cache = self.cache.lock().unwrap();
                // Check if already cached
                if let Some(cached) = cache.get(&sid) {
                    // SAFETY: we return a reference tied to &self lifetime.
                    // The cache is only cleared on &mut self calls (clear/finalize).
                    // The Mutex ensures no concurrent mutation of the cache entry.
                    let ptr = cached.as_ptr();
                    let len = cached.len();
                    return unsafe { std::slice::from_raw_parts(ptr, len) };
                }
                let edges: Vec<CompactRelation> = indices.iter()
                    .map(|&idx| self.buffer[idx as usize])
                    .collect();
                cache.put(sid, edges);
                let cached = cache.peek(&sid).unwrap();
                let ptr = cached.as_ptr();
                let len = cached.len();
                return unsafe { std::slice::from_raw_parts(ptr, len) };
            }
            return &[];
        }

        // No spills case: data is in sorted buffer
        if self.merged_mmap.is_none() {
            if let Some(entry) = self.merged_index.get(&sid) {
                let start = entry.offset as usize;
                let end = start + entry.count as usize;
                if end <= self.buffer.len() {
                    return &self.buffer[start..end];
                }
            }
            return &[];
        }

        // Mmap case: return a slice directly from the mmap'd memory
        if let Some(entry) = self.merged_index.get(&sid) {
            if let Some(ref mmap) = self.merged_mmap {
                let header_size = 16;
                let byte_offset = header_size + (entry.offset as usize) * RECORD_SIZE;
                let byte_end = byte_offset + (entry.count as usize) * RECORD_SIZE;

                if byte_end <= mmap.len() {
                    return unsafe {
                        let ptr = mmap[byte_offset..byte_end].as_ptr() as *const CompactRelation;
                        std::slice::from_raw_parts(ptr, entry.count as usize)
                    };
                }
            }
        }

        &[]
    }

    /// Returns all edges as an iterator (for operations like to_snapshot).
    /// Only works after finalize.
    pub fn iter_all(&self) -> Box<dyn Iterator<Item = &CompactRelation> + '_> {
        if !self.finalized {
            return Box::new(self.buffer.iter());
        }

        if self.merged_mmap.is_none() {
            // No spills: data in buffer
            return Box::new(self.buffer.iter());
        }

        // Read from mmap
        if let Some(ref mmap) = self.merged_mmap {
            let header_size = 16;
            // Read total count from header
            if mmap.len() >= header_size {
                let count_bytes = &mmap[8..16];
                let count = u64::from_le_bytes([
                    count_bytes[0], count_bytes[1], count_bytes[2], count_bytes[3],
                    count_bytes[4], count_bytes[5], count_bytes[6], count_bytes[7],
                ]) as usize;
                let data = &mmap[header_size..header_size + count * RECORD_SIZE];
                let records: &[CompactRelation] = unsafe {
                    std::slice::from_raw_parts(
                        data.as_ptr() as *const CompactRelation,
                        count,
                    )
                };
                return Box::new(records.iter());
            }
        }

        Box::new(std::iter::empty())
    }

    /// Total number of edges stored.
    pub fn len(&self) -> usize {
        if self.finalized {
            if self.merged_mmap.is_none() {
                self.buffer.len()
            } else {
                self.merged_index.values().map(|e| e.count as usize).sum()
            }
        } else {
            self.buffer.len()
        }
    }

    /// Whether the store is empty.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Clears all data (for rebuild operations).
    pub fn clear(&mut self) {
        self.buffer.clear();
        self.buffer_index.clear();
        self.current_memory = 0;
        self.spill_files.clear();
        self.merged_mmap = None;
        self.merged_index.clear();
        self.cache.lock().unwrap().clear();
        self.finalized = false;
        // temp_dir will be cleaned up on drop
        self.temp_dir = None;
    }
}

impl Default for SpillableEdgeStore {
    fn default() -> Self {
        Self::with_default_budget()
    }
}

impl Clone for SpillableEdgeStore {
    fn clone(&self) -> Self {
        // Clone only works for non-spilled data
        let mut new = Self::new(self.memory_budget);
        new.buffer = self.buffer.clone();
        new.buffer_index = self.buffer_index.clone();
        new.current_memory = self.current_memory;
        new.merged_index = self.merged_index.clone();
        new.finalized = self.finalized;
        // Note: mmap, spill files, and cache are not cloned
        new
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::RelationType;

    fn make_sid(n: u32) -> StrId {
        StrId::from_raw(n)
    }

    #[test]
    fn basic_push_and_finalize() {
        let mut store = SpillableEdgeStore::new(1024 * 1024); // 1MB budget

        let rel = CompactRelation::new(
            make_sid(1), make_sid(2), &RelationType::Connect, 100
        );
        store.push(rel).unwrap();
        store.push(CompactRelation::new(
            make_sid(1), make_sid(3), &RelationType::Auth, 200
        )).unwrap();
        store.push(CompactRelation::new(
            make_sid(2), make_sid(3), &RelationType::Execute, 300
        )).unwrap();

        assert_eq!(store.len(), 3);
        store.finalize().unwrap();
        assert!(store.is_finalized());

        let edges = store.get_edges(make_sid(1));
        assert_eq!(edges.len(), 2);
        assert_eq!(edges[0].timestamp, 100); // sorted by timestamp
        assert_eq!(edges[1].timestamp, 200);
    }

    #[test]
    fn spill_and_merge() {
        // Very small budget to force spilling
        let mut store = SpillableEdgeStore::new(RECORD_SIZE * 2);

        for i in 0..10u32 {
            store.push(CompactRelation::new(
                make_sid(i % 3), make_sid(i + 10), &RelationType::Connect, i as i64 * 100
            )).unwrap();
        }

        store.finalize().unwrap();
        assert!(store.is_finalized());
        assert_eq!(store.len(), 10);

        // Check that edges for sid 0 are correct
        let edges = store.get_edges(make_sid(0));
        assert!(!edges.is_empty());
        // All should have source_sid == 0
        for e in edges {
            assert_eq!(e.source_sid, make_sid(0));
        }
    }

    #[test]
    fn empty_store() {
        let mut store = SpillableEdgeStore::new(1024);
        store.finalize().unwrap();
        assert!(store.is_empty());
        assert_eq!(store.get_edges(make_sid(1)).len(), 0);
    }

    #[test]
    fn clear_resets() {
        let mut store = SpillableEdgeStore::new(1024 * 1024);
        store.push(CompactRelation::new(
            make_sid(1), make_sid(2), &RelationType::Auth, 100
        )).unwrap();
        store.finalize().unwrap();
        assert_eq!(store.len(), 1);

        store.clear();
        assert!(!store.is_finalized());
        assert_eq!(store.len(), 0);
    }
}
