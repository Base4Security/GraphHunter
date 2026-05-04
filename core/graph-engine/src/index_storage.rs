//! Heavy-logs #2 — `IndexBacking<T>`: heap-or-mmap storage for sparse
//! index rows.
//!
//! The matcher's auxiliary indexes (k-hop reachability, NLF) allocate
//! one fixed-size record per "ranked" vertex. On a 100M-vertex EVTX
//! with ~30M ranked vertices, the temporal arrays alone occupy
//! ~4.3 GB after the sparse-storage refactor (`bb3c32c`). On hosts
//! with tight RAM budgets this is still a lot.
//!
//! `IndexBacking<T>` lets the index decide at build time whether to
//! keep the rows on the heap (fast for small graphs) or spill them to
//! a memory-mapped temp file (RAM bounded by the working set on
//! large graphs). Lookups are uniform: `.as_slice()` returns `&[T]`
//! either way and the matcher hot path doesn't need to know.
//!
//! Auto-trigger: `IndexBacking::build_with_writer(...)` picks the
//! backing based on the requested capacity and a budget threshold
//! (default 1 GiB, override via `GRAPHHUNTER_INDEX_HEAP_BUDGET`
//! bytes). Above the budget it spills; below it stays on the heap.
//! No user configuration required for the typical case — when the
//! user opens a 28 GB EVTX the index pages live on disk
//! transparently.
//!
//! Safety. `T` must be `Copy` and have a stable repr (use
//! `#[repr(C)]` on user-defined structs). The mmap variant
//! reinterprets the file's raw bytes as `&[T]`; this is safe when:
//!   * the file size equals `len * size_of::<T>()` (we enforce by
//!     constructing through `build_with_writer`);
//!   * the mmap pointer is aligned to `align_of::<T>()` (guaranteed
//!     by memmap's page alignment for any T whose alignment is ≤ a
//!     page, which covers every `T` we care about in this crate).

use std::io::{Seek, SeekFrom, Write};

/// Default heap budget below which `IndexBacking` stays in-memory.
/// Above this, it spills to a memory-mapped temp file. Override
/// via the `GRAPHHUNTER_INDEX_HEAP_BUDGET` env var (bytes); set to
/// 0 to force mmap on every build.
pub const DEFAULT_HEAP_BUDGET: usize = 1 << 30; // 1 GiB.

fn heap_budget() -> usize {
    std::env::var("GRAPHHUNTER_INDEX_HEAP_BUDGET")
        .ok()
        .and_then(|v| v.parse::<usize>().ok())
        .unwrap_or(DEFAULT_HEAP_BUDGET)
}

/// Sparse `[T]` storage backed by either a `Vec<T>` or a
/// memory-mapped temp file. Indexed read access via `as_slice()`.
pub enum IndexBacking<T: Copy> {
    Heap(Vec<T>),
    Mmap {
        // Holds the temp file alive; dropping `IndexBacking` drops
        // the file too (auto-cleanup). The mmap shares the same
        // backing fd, so the file isn't actually unlinked until
        // both are dropped.
        _file: tempfile::NamedTempFile,
        mmap: memmap2::Mmap,
        len: usize,
        _phantom: std::marker::PhantomData<T>,
    },
}

impl<T: Copy + 'static> IndexBacking<T> {
    /// Build the backing by invoking `writer` with a mutable slice
    /// of length `len`. Decides heap vs mmap based on
    /// `len * size_of::<T>()` against the configured budget.
    pub fn build_with_writer<F>(len: usize, init: T, writer: F) -> std::io::Result<Self>
    where
        F: FnOnce(&mut [T]),
    {
        Self::build_with_writer_budget(len, init, heap_budget(), writer)
    }

    /// Same as `build_with_writer` but with an explicit budget. Used
    /// by tests to avoid racing on the shared env var.
    pub fn build_with_writer_budget<F>(
        len: usize,
        init: T,
        budget: usize,
        writer: F,
    ) -> std::io::Result<Self>
    where
        F: FnOnce(&mut [T]),
    {
        let bytes = len.saturating_mul(std::mem::size_of::<T>());
        if bytes <= budget {
            let mut v = vec![init; len];
            writer(&mut v);
            return Ok(Self::Heap(v));
        }
        // Spill: allocate a temp file, fill it, mmap as read-only.
        let mut tf = tempfile::NamedTempFile::new()?;
        // Pre-extend the file. We write in chunks so we never
        // allocate a giant `Vec<T>` on the heap to hand to writer.
        // Strategy: stream zero-init bytes, then memmap mutable,
        // call writer, drop mmap, reopen read-only.
        let zero_chunk = vec![0u8; 1 << 20]; // 1 MiB scratch.
        let mut remaining = bytes;
        while remaining > 0 {
            let take = remaining.min(zero_chunk.len());
            tf.write_all(&zero_chunk[..take])?;
            remaining -= take;
        }
        tf.flush()?;
        tf.as_file_mut().sync_all().ok();
        tf.as_file_mut().seek(SeekFrom::Start(0))?;
        // Mutable mmap to let `writer` populate the rows in place.
        // SAFETY: we own the file for this scope, no other process
        // reads or writes it concurrently.
        let mut mmap_mut = unsafe { memmap2::MmapMut::map_mut(tf.as_file())? };
        // Reinterpret the byte buffer as `&mut [T]`.
        // SAFETY: mmap is page-aligned (≥ align_of::<T>() for any
        // realistic T); length matches len * size_of::<T>().
        let typed: &mut [T] = unsafe {
            std::slice::from_raw_parts_mut(mmap_mut.as_mut_ptr() as *mut T, len)
        };
        // Initialize all rows to `init`. We can't use `vec![init; len]`
        // because that would heap-allocate the very buffer we're trying
        // to keep off-heap; the per-element write is fine since `T: Copy`.
        for slot in typed.iter_mut() {
            *slot = init;
        }
        writer(typed);
        // Force pages to disk before flipping to read-only — otherwise
        // the read mmap would race against pending dirty pages on
        // some kernels.
        mmap_mut.flush()?;
        let mmap = mmap_mut.make_read_only()?;
        Ok(Self::Mmap {
            _file: tf,
            mmap,
            len,
            _phantom: std::marker::PhantomData,
        })
    }

    pub fn len(&self) -> usize {
        match self {
            Self::Heap(v) => v.len(),
            Self::Mmap { len, .. } => *len,
        }
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Read access uniform across both backings. Returns a `&[T]`
    /// view into the heap vector or the mmap'd region.
    pub fn as_slice(&self) -> &[T] {
        match self {
            Self::Heap(v) => v.as_slice(),
            Self::Mmap { mmap, len, .. } => unsafe {
                // SAFETY: see module docstring.
                std::slice::from_raw_parts(mmap.as_ptr() as *const T, *len)
            },
        }
    }

    /// Bytes occupied on the heap (for in-memory) or on disk (for
    /// mmap). Useful for the `/metrics` surface.
    pub fn bytes(&self) -> usize {
        self.len() * std::mem::size_of::<T>()
    }

    /// Whether the backing is mmap-spilled (true) or heap-resident
    /// (false). Surfaced through the perf-status command so the UI
    /// can show "indexes spilled" when relevant.
    pub fn is_spilled(&self) -> bool {
        matches!(self, Self::Mmap { .. })
    }

    /// L3 stage 2 — mutable slice over the heap-backed rows for
    /// in-place delta updates. Returns `None` when the backing is
    /// mmap-spilled (the underlying file is opened read-only after
    /// build, so post-init mutation is not supported).
    ///
    /// Callers that want to mutate must handle the `None` case by
    /// either rebuilding the entire `IndexBacking` or invalidating
    /// the cached index entirely. NlfTable's `try_record_edge` is
    /// the canonical example.
    pub fn heap_slice_mut(&mut self) -> Option<&mut [T]> {
        match self {
            Self::Heap(v) => Some(v.as_mut_slice()),
            Self::Mmap { .. } => None,
        }
    }
}

impl<T: Copy + 'static> std::fmt::Debug for IndexBacking<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("IndexBacking")
            .field("len", &self.len())
            .field("bytes", &self.bytes())
            .field("spilled", &self.is_spilled())
            .finish()
    }
}

impl<T: Copy + 'static> Default for IndexBacking<T> {
    fn default() -> Self {
        Self::Heap(Vec::new())
    }
}

impl<T: Copy + 'static> Clone for IndexBacking<T> {
    /// Cloning an `IndexBacking` always materializes the data into a
    /// fresh `Vec<T>`. The mmap variant cannot be cheaply cloned (we
    /// would have to either re-open the underlying file or duplicate
    /// the temp file), so we eagerly materialize. Callers who clone
    /// `KHopReach` are typically test code; production callers pass
    /// `&KHopReach` references.
    fn clone(&self) -> Self {
        Self::Heap(self.as_slice().to_vec())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn small_capacity_stays_heap() {
        // Generous budget: stays heap.
        let backing: IndexBacking<u64> =
            IndexBacking::build_with_writer_budget(8, 0u64, 1 << 30, |slice| {
                for (i, slot) in slice.iter_mut().enumerate() {
                    *slot = i as u64;
                }
            })
            .unwrap();
        assert!(!backing.is_spilled());
        assert_eq!(backing.as_slice(), &[0, 1, 2, 3, 4, 5, 6, 7]);
    }

    #[test]
    fn budget_zero_forces_mmap() {
        // Budget = 0 forces every non-empty build to spill.
        let backing: IndexBacking<u64> =
            IndexBacking::build_with_writer_budget(4, 0u64, 0, |slice| {
                for (i, slot) in slice.iter_mut().enumerate() {
                    *slot = (i as u64) * 10;
                }
            })
            .unwrap();
        assert!(backing.is_spilled());
        assert_eq!(backing.as_slice(), &[0, 10, 20, 30]);
    }

    #[test]
    fn empty_is_default_heap() {
        let backing: IndexBacking<u64> = IndexBacking::default();
        assert!(backing.is_empty());
        assert!(!backing.is_spilled());
    }
}
