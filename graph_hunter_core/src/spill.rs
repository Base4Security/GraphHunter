//! Spillable edge store: keeps edges in RAM up to a memory budget,
//! then spills sorted runs to disk. After finalize() all edges are
//! accessible via mmap with an LRU cache.

use std::cmp::Ordering;
use std::collections::{BinaryHeap, HashMap};
use std::io::{Write, BufWriter};
use std::num::NonZeroUsize;
use std::sync::Mutex;

use crate::config;
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

/// Cursor into a single spill file for the streaming k-way merge in
/// `finalize()`. Holds one buffered record (the "top" of this file's queue)
/// and the index of the next record to load.
///
/// Ordering is reversed on `(source_sid, timestamp, file_idx)` so that
/// `BinaryHeap<SpillCursor>` (a max-heap) behaves as a min-heap over the
/// sort key. The `file_idx` tiebreak ensures deterministic output when two
/// cursors have identical (source_sid, timestamp) — matches the behavior
/// of `sort_unstable_by` on the old materialized-Vec path.
#[derive(Clone, Copy)]
struct SpillCursor {
    file_idx: usize,
    next_record_idx: usize,
    total_records: usize,
    current: CompactRelation,
}

impl PartialEq for SpillCursor {
    fn eq(&self, other: &Self) -> bool {
        self.cmp(other) == Ordering::Equal
    }
}
impl Eq for SpillCursor {}
impl PartialOrd for SpillCursor {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}
impl Ord for SpillCursor {
    fn cmp(&self, other: &Self) -> Ordering {
        // Reverse so `BinaryHeap` pops the smallest key first.
        (
            other.current.source_sid.index(),
            other.current.timestamp,
            other.file_idx,
        )
            .cmp(&(
                self.current.source_sid.index(),
                self.current.timestamp,
                self.file_idx,
            ))
    }
}

/// Reads one `CompactRelation` from a spill-file mmap at the given record
/// index. Uses `ptr::read_unaligned` so the call is safe regardless of the
/// alignment story (`CompactRelation` is `#[repr(C)]` and naturally aligned
/// on the 32-byte record boundary today, but `read_unaligned` defends
/// against future layout drift at zero cost on x86/arm64).
///
/// # Safety
/// The caller must ensure `idx < record_count` for this spill file; the
/// only caller (`finalize` merge loop) enforces this via `total_records`.
#[inline]
fn read_record_at(mmap: &memmap2::Mmap, idx: usize) -> CompactRelation {
    // 16-byte header: magic u32 + version u32 + count u64.
    const HEADER_SIZE: usize = 16;
    let byte_offset = HEADER_SIZE + idx * RECORD_SIZE;
    unsafe {
        let ptr = mmap.as_ptr().add(byte_offset) as *const CompactRelation;
        std::ptr::read_unaligned(ptr)
    }
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
                NonZeroUsize::new(config::LRU_CACHE_CAPACITY).unwrap(),
            )),
            finalized: false,
        }
    }

    /// Creates a store with default 2GB budget.
    pub fn with_default_budget() -> Self {
        Self::new(config::DEFAULT_SPILL_BUDGET)
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

        // Spill remaining buffer so every record is on disk in a sorted run.
        self.spill()?;

        // Streaming k-way merge-sort all spill files into one merged file.
        //
        // Memory footprint: O(k) cursors + BufWriter buffer (64 KB), where
        // k = number of spill files. Independent of N (total records).
        //
        // The previous implementation materialized every record in a single
        // `Vec<CompactRelation>` before sorting, which OOMs at tera-scale
        // (a 28 GB EVTX produces ~200M edges × 32 B = 6.4 GB just for the
        // Vec, on top of the mmaps). This replacement keeps RSS bounded.
        //
        // Validated by `spikes/spill_kway_merge/` (Spike 2): on a 2M-record
        // workload, virtual-memory delta dropped from 91.8 MB to 0.23 MB
        // (~400× smaller) and throughput increased from 3.4 Mrec/s to
        // 6.0 Mrec/s because O(N log k) with k=4 beats O(N log N) plus the
        // Vec allocation overhead.
        let dir = self.temp_dir.as_ref().unwrap().path();
        let merged_path = dir.join("merged.bin");

        let file = std::fs::File::create(&merged_path).map_err(SpillError::Io)?;
        let mut writer = BufWriter::with_capacity(64 * 1024, file);

        // Total record count is known up-front from the spill headers.
        let total_count: u64 = self.spill_files.iter().map(|s| s.record_count).sum();

        // Write header.
        writer.write_all(&SPILL_MAGIC.to_le_bytes()).map_err(SpillError::Io)?;
        writer.write_all(&SPILL_VERSION.to_le_bytes()).map_err(SpillError::Io)?;
        writer.write_all(&total_count.to_le_bytes()).map_err(SpillError::Io)?;

        // Initialize one cursor per non-empty spill file. Each cursor holds
        // the first record of its file; the heap orders by (source_sid,
        // timestamp, file_idx) so popping gives the global minimum.
        let mut heap: BinaryHeap<SpillCursor> =
            BinaryHeap::with_capacity(self.spill_files.len());
        for (file_idx, spill) in self.spill_files.iter().enumerate() {
            if spill.record_count == 0 {
                continue;
            }
            let first = read_record_at(&spill.mmap, 0);
            heap.push(SpillCursor {
                file_idx,
                next_record_idx: 1,
                total_records: spill.record_count as usize,
                current: first,
            });
        }

        // Merge loop + incremental index construction. Records are popped in
        // (source_sid, timestamp) order, so we can build the per-source index
        // in a single pass by tracking source_sid transitions.
        let mut index_entries: Vec<(StrId, u64, u32)> = Vec::new();
        let mut current_sid: Option<StrId> = None;
        let mut current_sid_start: u64 = 0;
        let mut current_sid_count: u32 = 0;
        let mut emitted: u64 = 0;

        while let Some(cur) = heap.pop() {
            let sid = cur.current.source_sid;
            match current_sid {
                Some(prev) if prev == sid => {
                    current_sid_count += 1;
                }
                _ => {
                    if let Some(prev) = current_sid {
                        index_entries.push((prev, current_sid_start, current_sid_count));
                    }
                    current_sid = Some(sid);
                    current_sid_start = emitted;
                    current_sid_count = 1;
                }
            }

            // Write the record as raw bytes. `CompactRelation` is `#[repr(C)]`
            // with a fixed 32-byte layout so the transmute is sound.
            let bytes: &[u8] = unsafe {
                std::slice::from_raw_parts(
                    &cur.current as *const CompactRelation as *const u8,
                    RECORD_SIZE,
                )
            };
            writer.write_all(bytes).map_err(SpillError::Io)?;
            emitted += 1;

            // Advance the cursor: load the next record from the same spill.
            if cur.next_record_idx < cur.total_records {
                let next = read_record_at(
                    &self.spill_files[cur.file_idx].mmap,
                    cur.next_record_idx,
                );
                heap.push(SpillCursor {
                    file_idx: cur.file_idx,
                    next_record_idx: cur.next_record_idx + 1,
                    total_records: cur.total_records,
                    current: next,
                });
            }
            // Otherwise cursor is exhausted; drop it by not pushing back.
        }

        // Flush the final index entry (if any records were emitted).
        if let Some(prev) = current_sid {
            index_entries.push((prev, current_sid_start, current_sid_count));
        }

        debug_assert_eq!(
            emitted, total_count,
            "streaming merge emitted {} records but spill headers claim {}",
            emitted, total_count
        );

        // Write index section.
        let entry_count = index_entries.len() as u64;
        writer.write_all(&entry_count.to_le_bytes()).map_err(SpillError::Io)?;
        for (sid, offset, count) in &index_entries {
            writer.write_all(&(sid.index() as u32).to_le_bytes()).map_err(SpillError::Io)?;
            writer.write_all(&offset.to_le_bytes()).map_err(SpillError::Io)?;
            writer.write_all(&count.to_le_bytes()).map_err(SpillError::Io)?;
        }

        writer.flush().map_err(SpillError::Io)?;
        drop(writer);

        // Mmap merged file for query-time reads.
        let file = std::fs::File::open(&merged_path).map_err(SpillError::Io)?;
        let mmap = unsafe { memmap2::Mmap::map(&file).map_err(SpillError::Mmap)? };

        // Build in-memory index for O(1) sid → byte-range lookups.
        self.merged_index.clear();
        for (sid, offset, count) in index_entries {
            self.merged_index.insert(sid, IndexEntry { offset, count });
        }

        self.merged_mmap = Some(mmap);

        // Clean up spill files (temp_dir stays alive because it owns the
        // merged file we just mmap'd).
        self.spill_files.clear();

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

    /// Stress test for the streaming k-way merge: force many spill files with
    /// interleaved source_sid/timestamp keys, finalize, and verify:
    /// 1. Every edge is reachable via `get_edges`.
    /// 2. Returned slices are sorted by timestamp within each source.
    /// 3. The total edge count matches what was pushed.
    /// 4. The index covers every source that received at least one edge.
    ///
    /// This test exists because the streaming finalize replaces a previous
    /// impl that materialized every record in a single Vec before sorting.
    /// The spike at spikes/spill_kway_merge/ validated the algorithm in
    /// isolation; this test pins the in-place replacement.
    #[test]
    fn streaming_merge_many_spills_correctness() {
        // Small budget forces a spill every 4 records.
        let mut store = SpillableEdgeStore::new(RECORD_SIZE * 4);

        // Push 200 records across 10 source nodes with out-of-order timestamps
        // inside each spill run. The spill() path sorts each run, then
        // finalize() k-way-merges them. If the merge is correct, get_edges
        // must return timestamps in ascending order.
        let num_sources: u32 = 10;
        let edges_per_source: u32 = 20;
        let mut pushed: Vec<(u32, u32, i64)> = Vec::new();
        // Interleave across sources so every spill file spans multiple
        // source_sids — this forces the k-way merge to actually interleave.
        for ts_group in 0..edges_per_source {
            for src in 0..num_sources {
                let ts = (ts_group as i64) * 1000 + (src as i64);
                let dst = src + 100;
                store.push(CompactRelation::new(
                    make_sid(src),
                    make_sid(dst),
                    &RelationType::Execute,
                    ts,
                )).unwrap();
                pushed.push((src, dst, ts));
            }
        }

        store.finalize().unwrap();
        assert!(store.is_finalized());
        assert_eq!(store.len(), (num_sources * edges_per_source) as usize);

        // Verify each source's slice is timestamp-sorted and complete.
        for src in 0..num_sources {
            let edges = store.get_edges(make_sid(src));
            assert_eq!(
                edges.len(), edges_per_source as usize,
                "source {} has {} edges, expected {}",
                src, edges.len(), edges_per_source
            );
            for i in 1..edges.len() {
                assert!(
                    edges[i - 1].timestamp <= edges[i].timestamp,
                    "source {} edges not sorted: ts[{}]={} > ts[{}]={}",
                    src, i - 1, edges[i - 1].timestamp, i, edges[i].timestamp
                );
            }
            // All edges for this source should have source_sid == src.
            for (i, e) in edges.iter().enumerate() {
                assert_eq!(
                    e.source_sid, make_sid(src),
                    "source {} edge {} has wrong source_sid", src, i
                );
            }
        }

        // Querying a source that was never inserted should return empty.
        let edges = store.get_edges(make_sid(9999));
        assert!(edges.is_empty());
    }
}
