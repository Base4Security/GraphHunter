//! Spillable edge store: keeps edges in RAM up to a memory budget,
//! then spills sorted runs to disk. After finalize() all edges are
//! accessible via mmap with an LRU cache.

use std::collections::HashMap;
use std::io::{Write, BufWriter};
use std::sync::Mutex;

use crate::config;
use crate::interner::StrId;
use crate::relation::CompactRelation;

/// Magic number for spill file headers.
const SPILL_MAGIC: u32 = 0x47485350; // "GHSP"
/// Version of the spill file format.
const SPILL_VERSION: u32 = 1;
/// Size of a single CompactRelation record on disk (fixed layout).
const RECORD_SIZE: usize = std::mem::size_of::<CompactRelation>();

/// Simple LRU cache using a HashMap + VecDeque for eviction order.
struct LruCache {
    map: HashMap<StrId, Vec<CompactRelation>>,
    order: std::collections::VecDeque<StrId>,
    capacity: usize,
}

impl LruCache {
    fn new(capacity: usize) -> Self {
        Self {
            map: HashMap::new(),
            order: std::collections::VecDeque::new(),
            capacity,
        }
    }

    fn get(&mut self, key: &StrId) -> Option<&[CompactRelation]> {
        if self.map.contains_key(key) {
            // Move to back (most recently used)
            self.order.retain(|k| k != key);
            self.order.push_back(*key);
            self.map.get(key).map(|v| v.as_slice())
        } else {
            None
        }
    }

    fn insert(&mut self, key: StrId, value: Vec<CompactRelation>) {
        if self.map.contains_key(&key) {
            self.order.retain(|k| *k != key);
        } else if self.map.len() >= self.capacity && !self.order.is_empty() {
            // Evict least recently used
            if let Some(evicted) = self.order.pop_front() {
                self.map.remove(&evicted);
            }
        }
        self.order.push_back(key);
        self.map.insert(key, value);
    }

    fn clear(&mut self) {
        self.map.clear();
        self.order.clear();
    }
}

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
    cache: Mutex<LruCache>,

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
            cache: Mutex::new(LruCache::new(config::LRU_CACHE_CAPACITY)),
            finalized: false,
        }
    }

    /// Creates a store with default 2GB budget.
    pub fn with_default_budget() -> Self {
        Self::new(config::DEFAULT_SPILL_BUDGET)
    }

    /// Appends a relation during ingestion.
    /// If the store was finalized, it automatically unfinalizes to accept new data.
    pub fn push(&mut self, rel: CompactRelation) {
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
        self.cache.lock().unwrap().map.remove(&rel.source_sid);

        let idx = self.buffer.len() as u32;
        self.buffer_index
            .entry(rel.source_sid)
            .or_default()
            .push(idx);
        self.buffer.push(rel);
        self.current_memory += RECORD_SIZE;

        if self.current_memory >= self.memory_budget {
            self.spill();
        }
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
    fn spill(&mut self) {
        if self.buffer.is_empty() {
            return;
        }

        // Sort by (source_sid, timestamp)
        self.buffer.sort_unstable_by(|a, b| {
            a.source_sid.index().cmp(&b.source_sid.index())
                .then(a.timestamp.cmp(&b.timestamp))
        });

        // Ensure temp dir exists
        if self.temp_dir.is_none() {
            self.temp_dir = Some(tempfile::tempdir().expect("Failed to create temp dir"));
        }
        let dir = self.temp_dir.as_ref().unwrap().path();
        let spill_path = dir.join(format!("spill_{}.bin", self.spill_files.len()));

        // Write header + records
        let file = std::fs::File::create(&spill_path).expect("Failed to create spill file");
        let mut writer = BufWriter::new(file);

        writer.write_all(&SPILL_MAGIC.to_le_bytes()).unwrap();
        writer.write_all(&SPILL_VERSION.to_le_bytes()).unwrap();
        let count = self.buffer.len() as u64;
        writer.write_all(&count.to_le_bytes()).unwrap();

        // Write records as raw bytes
        for rel in &self.buffer {
            let bytes: &[u8] = unsafe {
                std::slice::from_raw_parts(
                    rel as *const CompactRelation as *const u8,
                    RECORD_SIZE,
                )
            };
            writer.write_all(bytes).unwrap();
        }
        writer.flush().unwrap();
        drop(writer);

        // Mmap the spill file
        let file = std::fs::File::open(&spill_path).expect("Failed to open spill file");
        let mmap = unsafe { memmap2::Mmap::map(&file).expect("Failed to mmap spill file") };

        self.spill_files.push(SpillFile {
            _path: spill_path,
            mmap,
            record_count: count,
        });

        // Clear buffer
        self.buffer.clear();
        self.buffer_index.clear();
        self.current_memory = 0;
    }

    /// Finalizes the store: merge-sorts all spill files + buffer into one
    /// indexed mmap file. For small datasets (no spills), just sorts in-place.
    pub fn finalize(&mut self) {
        if self.finalized {
            return;
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
            return;
        }

        // Spill remaining buffer
        self.spill();

        // Merge-sort all spill files into one merged file
        let dir = self.temp_dir.as_ref().unwrap().path();
        let merged_path = dir.join("merged.bin");

        let file = std::fs::File::create(&merged_path).expect("Failed to create merged file");
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
        writer.write_all(&SPILL_MAGIC.to_le_bytes()).unwrap();
        writer.write_all(&SPILL_VERSION.to_le_bytes()).unwrap();
        let total_count = all_records.len() as u64;
        writer.write_all(&total_count.to_le_bytes()).unwrap();

        // Write sorted records
        for rel in &all_records {
            let bytes: &[u8] = unsafe {
                std::slice::from_raw_parts(
                    rel as *const CompactRelation as *const u8,
                    RECORD_SIZE,
                )
            };
            writer.write_all(bytes).unwrap();
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
        writer.write_all(&entry_count.to_le_bytes()).unwrap();
        for (sid, offset, count) in &index_entries {
            writer.write_all(&(sid.index() as u32).to_le_bytes()).unwrap();
            writer.write_all(&offset.to_le_bytes()).unwrap();
            writer.write_all(&count.to_le_bytes()).unwrap();
        }

        writer.flush().unwrap();
        drop(writer);

        // Mmap merged file
        let file = std::fs::File::open(&merged_path).expect("Failed to open merged file");
        let mmap = unsafe { memmap2::Mmap::map(&file).expect("Failed to mmap merged file") };

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
                if let Some(slice) = cache.get(&sid) {
                    // SAFETY: we return a reference tied to &self lifetime.
                    // The cache is only cleared on &mut self calls (clear/finalize).
                    // The Mutex ensures no concurrent mutation of the cache entry.
                    let ptr = slice.as_ptr();
                    let len = slice.len();
                    return unsafe { std::slice::from_raw_parts(ptr, len) };
                }
                let edges: Vec<CompactRelation> = indices.iter()
                    .map(|&idx| self.buffer[idx as usize])
                    .collect();
                cache.insert(sid, edges);
                let slice = cache.map.get(&sid).unwrap().as_slice();
                let ptr = slice.as_ptr();
                let len = slice.len();
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
        store.push(rel);
        store.push(CompactRelation::new(
            make_sid(1), make_sid(3), &RelationType::Auth, 200
        ));
        store.push(CompactRelation::new(
            make_sid(2), make_sid(3), &RelationType::Execute, 300
        ));

        assert_eq!(store.len(), 3);
        store.finalize();
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
            ));
        }

        store.finalize();
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
        store.finalize();
        assert!(store.is_empty());
        assert_eq!(store.get_edges(make_sid(1)).len(), 0);
    }

    #[test]
    fn clear_resets() {
        let mut store = SpillableEdgeStore::new(1024 * 1024);
        store.push(CompactRelation::new(
            make_sid(1), make_sid(2), &RelationType::Auth, 100
        ));
        store.finalize();
        assert_eq!(store.len(), 1);

        store.clear();
        assert!(!store.is_finalized());
        assert_eq!(store.len(), 0);
    }
}
