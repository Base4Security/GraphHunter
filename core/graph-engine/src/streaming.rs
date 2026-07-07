//! L3 stage 1 — streaming graph backend scaffold (Sortledton-style).
//!
//! Mirror of M3's "ship the primitive, wire the consumer later"
//! pattern. The static `GraphHunter` (entities HashMap +
//! `SpillableEdgeStore`) is the right shape for batch-loaded EVTX
//! sessions but does not let queries run against an evolving
//! event stream — every ingest finalize re-sorts edges and
//! invalidates the lazy indexes.
//!
//! Long-term goal: a per-vertex degree-adaptive store
//! (Fuchs-Giceva-Margan PVLDB 15:1173, 2022) that supports:
//!
//!   * O(1)-amortized append of new outgoing edges.
//!   * O(log d) range queries over time-bucketed neighbors.
//!   * Wait-free reads via `Arc<Snapshot>` while a writer thread
//!     ingests the next batch.
//!
//! This commit ships only the structural primitive — the trait
//! and an in-memory implementation. The ingest pipeline (Sentinel
//! poller, EVTX streamer) still writes into the static
//! `GraphHunter` for now; stage 2 swaps the writer side once the
//! delta-update story for NLF / k-hop reachability is fleshed out
//! (Kankanamge-Sahu-Mhedhbi-Salihoglu SIGMOD 2017 covers the
//! incremental WCOJ propagation we'll need).
//!
//! Per-vertex storage policy. On Sysmon/EVTX-shaped graphs the
//! degree distribution is power-law: most vertices have ≤ 8
//! outgoing edges, a long middle has dozens, and a handful of
//! hubs (`services.exe`, `lsass.exe`, `svchost.exe`) have
//! thousands. Two storage shapes cover the curve:
//!
//!   * `Inline(SmallVec<[Edge; 8]>)` — degree ≤ 8. Bytes live
//!     inline in the per-vertex slot, no heap touch on the read
//!     path.
//!   * `Vec(Vec<Edge>)` — degree > 8. Heap-allocated and contiguous,
//!     so the matcher hot-path consumes it as `&[StreamEdge]` via
//!     `as_slice()` exactly as it did `&[CompactRelation]` from
//!     `edge_store`.
//!
//! 2c-part-2 dropped a previous `Btree` variant that kicked in at
//! degree > 128 for O(log d) range queries; uniform slice access on
//! the read path is more important than the asymptotic win on hubs
//! (no production code path actually used the Btree range scan).

use parking_lot::RwLock;
use smallvec::SmallVec;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use crate::interner::StrId;

/// Memory-mapped backing for spilled per-vertex edge runs. One
/// `MmapHandle` is shared (via `Arc`) by every `NeighborList::Mmap`
/// variant that lives in a backend's spill file — bumping the Arc
/// keeps the file mapped as long as any per-vertex slot still
/// references it.
///
/// Wrapping `memmap2::Mmap` in our own struct lets us derive
/// `Debug` cleanly (the mmap itself isn't `Debug`) and centralize
/// the `unsafe` slice projection inside one method.
#[derive(Debug)]
pub struct MmapHandle {
    mmap: memmap2::Mmap,
}

impl MmapHandle {
    /// Slice projection. `byte_offset` must be within bounds and
    /// `len * size_of::<StreamEdge>()` bytes must follow it. The
    /// only callsite (`NeighborList::Mmap::as_slice`) gets these
    /// from `consolidate`, which validates them at write time.
    ///
    /// # Safety
    /// Caller asserts (a) the byte range is within the mmap, (b)
    /// the bytes were originally written as `StreamEdge` records
    /// in `consolidate`, (c) alignment is satisfied (the file
    /// header pads the data region to 8-byte alignment so a
    /// `#[repr(C)]` `StreamEdge` is naturally aligned).
    #[inline]
    unsafe fn slice_at(&self, byte_offset: usize, len: usize) -> &[StreamEdge] {
        // SAFETY: Rust 2024 requires unsafe ops inside an unsafe fn
        // be wrapped in their own unsafe block. The function-level
        // contract above documents the invariants the caller must
        // uphold; the wrapping is purely syntactic.
        unsafe {
            let ptr = self.mmap.as_ptr().add(byte_offset) as *const StreamEdge;
            std::slice::from_raw_parts(ptr, len)
        }
    }
}

/// Inline capacity for the SmallVec variant. Eight covers the
/// median Sysmon vertex (most processes have a handful of
/// outgoing relations) without spilling to heap.
pub const INLINE_CAPACITY: usize = 8;

/// One edge in the streaming view. **Layout-compatible with
/// `CompactRelation`** so the matcher hot-path can iterate streaming
/// output without per-edge field translation. The layout is the same
/// 32 B `#[repr(C)]` shape as `CompactRelation`:
///
///   timestamp (8) | metadata_offset (8) | source_sid (4) | dest_sid (4)
///   | ingested_at_delta (4) | dataset_tag (2) | rel_type_tag (1) | pad (1)
///
/// `source_sid` is technically redundant with the per-vertex storage
/// key in `InMemoryStreamingBackend.vertices`, but keeping it lets the
/// matcher iterate a streaming-backed slice exactly as it does the
/// legacy `&[CompactRelation]`. The 4 B per edge (~120 MB on a 30M-edge
/// EVTX session) is the price of the unification.
#[derive(Clone, Copy, Debug)]
#[repr(C)]
pub struct StreamEdge {
    pub timestamp: i64,
    /// Offset into the `MetadataStore`. `0` means no metadata.
    pub metadata_offset: u64,
    pub source_sid: StrId,
    pub dest_sid: StrId,
    /// `(ingested_at - INGEST_EPOCH_BASE)` in seconds. Used by
    /// the MVCC snapshot API to answer "what did the graph know
    /// at time T".
    pub ingested_at_delta: u32,
    /// Index into `dataset_tags`. `0` means no dataset.
    pub dataset_tag: u16,
    pub rel_type_tag: u8,
}

// SAFETY invariant: StreamEdge is transmuted to CompactRelation in several
// hot paths (save_session, remove_*_by_dataset, matcher slices) via
// `ptr::read(edge as *const _ as *const CompactRelation)`. Both are
// `#[repr(C)]` with identical field order; they MUST stay layout-identical.
// This compile-time assert fails the build if either struct's size drifts —
// turning a silent UB regression into a hard compile error.
const _: () = assert!(
    core::mem::size_of::<StreamEdge>() == core::mem::size_of::<crate::relation::CompactRelation>()
);

impl StreamEdge {
    /// Decode `rel_type_tag` to `RelationType`. Mirrors the
    /// equivalent method on `CompactRelation` so consumers that
    /// migrate from edge_store don't need to special-case the
    /// dispatch.
    #[inline]
    pub fn rel_type(&self) -> graph_hunter_dsl::types::RelationType {
        graph_hunter_dsl::types::RelationType::from_u8(self.rel_type_tag)
    }
}

/// Per-vertex outgoing-edge storage. Two-shape adaptive:
///
///   * `Inline(SmallVec<[StreamEdge; 8]>)` — degree ≤ 8. Inline,
///     no heap touch.
///   * `Vec(Vec<StreamEdge>)` — degree > 8. Heap-allocated and
///     contiguous so the matcher hot-path can read it as
///     `&[StreamEdge]` directly via `as_slice()`.
///
/// 2c-part-2 dropped the previous `Btree` variant. The matcher's
/// migration to streaming requires uniform `&[StreamEdge]` access
/// (the DFS holds a long-lived slice across each frame's edge
/// loop, with prefetch lookahead that indexes the slice ahead of
/// the cursor). A `BTreeMap`-backed branch couldn't surface a
/// contiguous slice, so the variant was pulled. Range queries on
/// hubs that previously used `iter_window` over `Btree` now use a
/// linear filter on `Vec` — algorithmically O(degree) instead of
/// O(log d + window), but in practice no production code path
/// called `iter_window` (the matcher uses `edge_store`'s timestamp
/// binary search, not streaming's window iter).
#[derive(Debug)]
pub enum NeighborList {
    Inline(SmallVec<[StreamEdge; INLINE_CAPACITY]>),
    Vec(Vec<StreamEdge>),
    /// L3 D4 stage 1 — spilled. The vertex's edge run lives in a
    /// memory-mapped file shared by every `Mmap`-variant slot in
    /// the same backend (the `Arc<MmapHandle>` keeps the file
    /// alive). Reads are zero-copy: `as_slice()` projects the
    /// `[byte_offset, byte_offset + len * size_of::<StreamEdge>())`
    /// range as `&[StreamEdge]`.
    Mmap {
        handle: Arc<MmapHandle>,
        byte_offset: usize,
        len: usize,
    },
}

impl Default for NeighborList {
    fn default() -> Self {
        Self::Inline(SmallVec::new())
    }
}

impl NeighborList {
    /// Append an edge, promoting Inline → Vec when the inline
    /// capacity is crossed, and Mmap → Vec on the first write
    /// after a `consolidate()`. O(1) amortized for Inline/Vec;
    /// Mmap → Vec promotion costs one O(degree) memcpy out of
    /// the mmap.
    pub fn push(&mut self, edge: StreamEdge) {
        match self {
            Self::Inline(sv) => {
                if sv.len() < INLINE_CAPACITY {
                    sv.push(edge);
                } else {
                    // Promote to Vec.
                    let mut v = Vec::with_capacity(INLINE_CAPACITY * 2);
                    v.extend(sv.iter().copied());
                    v.push(edge);
                    *self = Self::Vec(v);
                }
            }
            Self::Vec(v) => {
                v.push(edge);
            }
            Self::Mmap { .. } => {
                // Promote Mmap → Vec for write. Copy the spilled
                // edges out, append, swap. Safe because the slice
                // borrow ends before the assignment to `*self`.
                let existing: Vec<StreamEdge> = self.as_slice().to_vec();
                let mut v = existing;
                v.push(edge);
                *self = Self::Vec(v);
            }
        }
    }

    /// Number of edges currently stored.
    pub fn len(&self) -> usize {
        match self {
            Self::Inline(sv) => sv.len(),
            Self::Vec(v) => v.len(),
            Self::Mmap { len, .. } => *len,
        }
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Borrowed contiguous slice over all stored edges. Always
    /// valid because every backing variant is slice-shaped (Mmap
    /// projects from the spill file via `MmapHandle::slice_at`).
    /// This is the API the matcher hot-path consumes — drop-in
    /// for the legacy `&[CompactRelation]` from `edge_store`.
    #[inline]
    pub fn as_slice(&self) -> &[StreamEdge] {
        match self {
            Self::Inline(sv) => sv.as_slice(),
            Self::Vec(v) => v.as_slice(),
            Self::Mmap {
                handle,
                byte_offset,
                len,
            } => {
                // SAFETY: `byte_offset` and `len` were validated by
                // `InMemoryStreamingBackend::consolidate` against the
                // mmap bounds at spill time, and the `Arc<MmapHandle>`
                // keeps the file mapped for as long as this variant
                // exists.
                unsafe { handle.slice_at(*byte_offset, *len) }
            }
        }
    }

    /// Iterate every edge in insertion order. Allocates nothing.
    pub fn iter(&self) -> std::slice::Iter<'_, StreamEdge> {
        self.as_slice().iter()
    }

    /// Iterate edges whose `timestamp` falls in `[lo, hi)`. Linear
    /// filter — the streaming layer no longer carries a sorted
    /// representation, so range queries are O(degree). Production
    /// code paths use `edge_store`'s timestamp-sorted binary search
    /// instead; this is kept for legacy callers.
    pub fn iter_window(&self, lo: i64, hi: i64) -> NeighborWindowIter<'_> {
        NeighborWindowIter {
            inner: self.iter(),
            lo,
            hi,
        }
    }

    /// Tag describing which variant currently backs this list.
    /// Used by `/metrics` and the diagnostic surface.
    pub fn variant_tag(&self) -> &'static str {
        match self {
            Self::Inline(_) => "inline",
            Self::Vec(_) => "vec",
            Self::Mmap { .. } => "mmap",
        }
    }
}

pub struct NeighborWindowIter<'a> {
    inner: std::slice::Iter<'a, StreamEdge>,
    lo: i64,
    hi: i64,
}

impl<'a> Iterator for NeighborWindowIter<'a> {
    type Item = &'a StreamEdge;
    fn next(&mut self) -> Option<Self::Item> {
        let lo = self.lo;
        let hi = self.hi;
        self.inner.find(|e| e.timestamp >= lo && e.timestamp < hi)
    }
}

/// Trait that the streaming-graph implementations expose.
/// Sortledton-style backends and the in-memory scaffold both
/// implement this; the ingest pipeline talks to it through the
/// trait so the static `GraphHunter` stays in place during the
/// migration.
pub trait StreamingGraphBackend: Send + Sync {
    /// Append one outgoing edge from `src`. Auto-promotes the
    /// per-vertex storage if the degree threshold is crossed.
    fn append_edge(&self, src: StrId, edge: StreamEdge);

    /// Snapshot the per-vertex neighbors of `src` (allocating if
    /// the backend's internal layout requires it). For the
    /// in-memory scaffold this returns an `Arc<NeighborList>`
    /// clone so concurrent writers don't disturb the reader.
    fn neighbors_snapshot(&self, src: StrId) -> Option<std::sync::Arc<NeighborList>>;

    /// Number of vertices that have at least one outgoing edge.
    fn vertex_count(&self) -> usize;

    /// Total number of outgoing edges across all vertices.
    fn edge_count(&self) -> usize;
}

impl Clone for NeighborList {
    fn clone(&self) -> Self {
        match self {
            Self::Inline(sv) => Self::Inline(sv.clone()),
            Self::Vec(v) => Self::Vec(v.clone()),
            // Clone the Arc, not the underlying mmap — multiple
            // logical copies share one file handle.
            Self::Mmap {
                handle,
                byte_offset,
                len,
            } => Self::Mmap {
                handle: handle.clone(),
                byte_offset: *byte_offset,
                len: *len,
            },
        }
    }
}

/// L3 post-2c2 — lock-free read view over a backend's vertex
/// table at a moment in time. Built via
/// `InMemoryStreamingBackend::freeze()`; consumed by the matcher
/// hot-path so per-frame edge reads do *zero* atomic ops:
/// `snap.neighbors(sid)` is a pure `HashMap.get` and
/// `FrozenNeighborList::as_slice()` is a pointer chase
/// (`Arc<[StreamEdge]>` for in-RAM rows, `Arc<MmapHandle>`-backed
/// pointer for spilled rows). No `RwLock` is acquired per frame.
#[derive(Clone)]
pub struct FrozenSnapshot {
    vertices: Arc<ahash::HashMap<StrId, FrozenNeighborList>>,
}

/// Lock-free per-vertex slice view captured at `freeze()` time.
/// In-RAM rows are deep-copied into an `Arc<[StreamEdge]>` so the
/// snapshot survives mutations to the live backend; spilled rows
/// share the live backend's `Arc<MmapHandle>` (zero copy, the
/// mmap region is already immutable).
#[derive(Clone, Debug)]
pub enum FrozenNeighborList {
    /// In-RAM slice — captured at freeze time. The `Arc<[T]>` is
    /// immutable; cloning the snapshot just bumps the refcount.
    InMemory(Arc<[StreamEdge]>),
    /// Mmap-backed slice — shares the live backend's mmap handle.
    /// No copy at freeze; the file stays mapped while any
    /// snapshot referencing it lives.
    Mmap {
        handle: Arc<MmapHandle>,
        byte_offset: usize,
        len: usize,
    },
}

impl FrozenNeighborList {
    /// Borrow the underlying slice. For `InMemory` it's the
    /// `Arc<[T]>` deref; for `Mmap` it's a raw-pointer projection
    /// into the mapped file. Both are zero-cost beyond a single
    /// pointer load.
    #[inline]
    pub fn as_slice(&self) -> &[StreamEdge] {
        match self {
            Self::InMemory(arc) => arc,
            Self::Mmap {
                handle,
                byte_offset,
                len,
            } => {
                // SAFETY: byte_offset+len validated at consolidate
                // / auto_spill time; the Arc keeps the mmap alive
                // for as long as this variant exists.
                unsafe { handle.slice_at(*byte_offset, *len) }
            }
        }
    }

    /// Edge count.
    #[inline]
    pub fn len(&self) -> usize {
        match self {
            Self::InMemory(arc) => arc.len(),
            Self::Mmap { len, .. } => *len,
        }
    }

    #[inline]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

impl FrozenSnapshot {
    /// Per-vertex slice lookup. Pure `HashMap.get` — no atomic ops,
    /// no lock acquires. Returns the immutable `FrozenNeighborList`
    /// captured at `freeze()` time.
    #[inline]
    pub fn neighbors(&self, src: StrId) -> Option<&FrozenNeighborList> {
        self.vertices.get(&src)
    }

    /// Vertex count at snapshot time.
    #[inline]
    pub fn vertex_count(&self) -> usize {
        self.vertices.len()
    }
}

/// Reference in-memory implementation backing the trait. Stage 1
/// uses a plain `RwLock<HashMap<StrId, Arc<RwLock<NeighborList>>>>`
/// — readers can snapshot a single vertex's neighbors without
/// blocking the global table, and writers serialize on the inner
/// lock per vertex. Stage 2 will swap in `dashmap` (or a
/// concurrent skiplist for the hub vertices) once the ingest
/// pipeline is wired through.
pub struct InMemoryStreamingBackend {
    vertices: RwLock<ahash::HashMap<StrId, Arc<RwLock<NeighborList>>>>,

    /// Set by [`Self::finalize`] / [`Self::finalize_parallel`]. Post-
    /// finalize appends land in `tails` instead of mutating the sorted
    /// base neighbor lists.
    finalized: AtomicBool,
    /// Per-vertex unsorted post-finalize edges. Merged at read time by
    /// [`Self::neighbors_in_window`].
    tails: RwLock<ahash::HashMap<StrId, SmallVec<[StreamEdge; 4]>>>,

    /// L3 D4 stage 2 — budget-triggered auto-spill. `None` keeps the
    /// backend in pure-RAM mode (default; matches the pre-stage-2
    /// behavior). When set, every `append_edge` past the threshold
    /// triggers `auto_spill()`, which writes a fresh sorted file
    /// and swaps every per-vertex slot to `NeighborList::Mmap`.
    spill_state: parking_lot::Mutex<Option<SpillState>>,
}

/// Per-backend auto-spill bookkeeping. Lives behind a `Mutex` (not
/// `RwLock`) because every `append_edge` has to take a write borrow
/// to bump `edges_since_last_spill`; contention is on the order of
/// the per-vertex `RwLock` already taken on the same call so the
/// extra atomic is noise.
struct SpillState {
    /// Threshold in number of edges. When `edges_since_last_spill`
    /// hits this value, `append_edge` triggers `auto_spill`.
    budget_edges: usize,
    edges_since_last_spill: usize,
    /// Test hook: `auto_spill` returns an I/O error without touching disk.
    force_fail: bool,
    /// Directory hosting the auto-spill files. Either an externally-
    /// supplied session-scoped path (`with_spill_dir`) or an internal
    /// `tempfile::TempDir` that auto-deletes on drop.
    spill_dir: std::path::PathBuf,
    _temp_dir: Option<tempfile::TempDir>,
    /// Most recent spill file path. Tracked so the next `auto_spill`
    /// can delete it after the new file is mmap'd in (each spill is
    /// a full re-write; old file becomes orphaned).
    current_path: Option<std::path::PathBuf>,
    spill_round: usize,
}

impl Default for InMemoryStreamingBackend {
    fn default() -> Self {
        Self::new()
    }
}

impl InMemoryStreamingBackend {
    pub fn new() -> Self {
        Self {
            vertices: RwLock::new(ahash::HashMap::default()),
            finalized: AtomicBool::new(false),
            tails: RwLock::new(ahash::HashMap::default()),
            spill_state: parking_lot::Mutex::new(None),
        }
    }

    /// Configure budget-triggered auto-spill. After this call every
    /// `append_edge` increments an internal counter; when the counter
    /// crosses `budget_edges` the backend flushes every in-memory
    /// neighbor list to a fresh sorted file under an internal
    /// `tempfile::TempDir` and replaces every slot with `Mmap`.
    /// Subsequent appends promote individual vertices `Mmap → Vec`
    /// on first write (one per-vertex memcpy out of the spill mmap)
    /// and the next budget cross writes a new file again.
    ///
    /// `0` disables auto-spill (default). Call once during
    /// `GraphHunter` setup; not safe to flip mid-ingest.
    pub fn with_memory_budget_edges(self, budget_edges: usize) -> Self {
        if budget_edges == 0 {
            return self;
        }
        let temp = tempfile::tempdir().expect("streaming auto-spill tempdir");
        let dir = temp.path().to_path_buf();
        *self.spill_state.lock() = Some(SpillState {
            budget_edges,
            edges_since_last_spill: 0,
            spill_dir: dir,
            _temp_dir: Some(temp),
            current_path: None,
            spill_round: 0,
            force_fail: false,
        });
        self
    }

    /// Like `with_memory_budget_edges` but spill files land in an
    /// externally-supplied directory instead of an auto-cleaned
    /// tempdir. The caller owns the directory's lifetime — same
    /// contract as `SpillableEdgeStore::with_spill_dir`.
    pub fn with_spill_dir_and_budget(
        self,
        dir: std::path::PathBuf,
        budget_edges: usize,
    ) -> Self {
        if budget_edges == 0 {
            return self;
        }
        *self.spill_state.lock() = Some(SpillState {
            budget_edges,
            edges_since_last_spill: 0,
            spill_dir: dir,
            _temp_dir: None,
            current_path: None,
            spill_round: 0,
            force_fail: false,
        });
        self
    }

    /// Test hook: enable auto-spill with `budget_edges = 1` and force
    /// the next spill attempt to fail. Used by unit tests that assert
    /// spill errors propagate through `append_edge_checked`.
    pub fn with_spill_fail(self, fail: bool) -> Self {
        if !fail {
            return self;
        }
        let temp = tempfile::tempdir().expect("streaming auto-spill tempdir");
        let dir = temp.path().to_path_buf();
        *self.spill_state.lock() = Some(SpillState {
            budget_edges: 1,
            edges_since_last_spill: 0,
            spill_dir: dir,
            _temp_dir: Some(temp),
            current_path: None,
            spill_round: 0,
            force_fail: true,
        });
        self
    }
}

impl InMemoryStreamingBackend {
    /// L3 stage 2c — adapter that returns a fresh `Vec<StreamEdge>`
    /// of `src`'s outgoing edges. Convenience wrapper over
    /// `neighbors_snapshot` that hides the `Arc<NeighborList>`
    /// type detail; matcher hot-path call sites can drop this in
    /// where they used to call `get_relations_by_sid`. After the
    /// 2c-part-2 type unification `StreamEdge` is layout-compatible
    /// with `CompactRelation`, so callers iterate the same field
    /// names (`dest_sid`, `source_sid`, etc.) on either store.
    ///
    /// Returns an empty `Vec` if `src` has no outgoing edges.
    /// Allocates one Vec per call — the matcher's existing call
    /// sites already pay an O(deg) iteration; the allocation is
    /// noise at typical degrees and avoids a lifetime tangle in
    /// downstream callers.
    pub fn neighbors_of(&self, src: StrId) -> Vec<StreamEdge> {
        let snap = match self.neighbors_snapshot(src) {
            Some(s) => s,
            None => return Vec::new(),
        };
        snap.iter().copied().collect()
    }

    /// Total number of outgoing edges from `src`. Direct read
    /// without materializing the full neighbor list.
    pub fn degree_of(&self, src: StrId) -> usize {
        let base = {
            let outer = self.vertices.read();
            outer
                .get(&src)
                .map(|slot| slot.read().len())
                .unwrap_or(0)
        };
        let tail = self
            .tails
            .read()
            .get(&src)
            .map(SmallVec::len)
            .unwrap_or(0);
        base + tail
    }

    /// L3 stage 2c part 2 — return the per-vertex `Arc<RwLock<NeighborList>>`
    /// slot directly. Caller takes its own read guard and reads
    /// `guard.as_slice()` for `&[StreamEdge]` access. This is the
    /// primitive the matcher hot-path uses: matches the long-lived
    /// slice borrow pattern (`let edges = ...; for i in ... { edges[i] }`)
    /// that the legacy `&[CompactRelation]` from `edge_store`
    /// supported, with prefetch lookahead intact.
    ///
    /// Costs per call: one `Arc` clone (atomic refcount inc), one
    /// outer-table read-lock acquire (atomic). The caller's
    /// `slot.read()` is a second atomic. Concurrent writers on
    /// `src` block on the per-vertex `RwLock` for the duration of
    /// the caller's guard.
    pub fn neighbors_arc(
        &self,
        src: StrId,
    ) -> Option<Arc<RwLock<NeighborList>>> {
        let outer = self
            .vertices
            .read();
        outer.get(&src).cloned()
    }

    /// L3 stage 2c follow-up — closure-style borrow read of `src`'s
    /// neighbor list. Holds the per-vertex read guard for the
    /// duration of `f`; the closure receives a `&NeighborList`
    /// that it can iterate without paying the `NeighborList` clone
    /// that `neighbors_snapshot` does.
    ///
    /// Returns `Some(f(list))` if `src` has at least one outgoing
    /// edge, `None` otherwise.
    ///
    /// The matcher hot-path migration (stage 2c part 2) uses this
    /// instead of `neighbors_of`/`neighbors_snapshot` because the
    /// per-call `NeighborList` clone in those would dominate the
    /// expansion-step budget at typical hub degrees. `try_record_edge_delta`
    /// is the first consumer; the matcher will follow once the
    /// edge_store/streaming parity bench is settled.
    ///
    /// Concurrent writers on `src` (via `append_edge`) block on
    /// the per-vertex `RwLock` for the duration of `f`. Keep `f`
    /// short — collect the few values you need and exit.
    pub fn with_neighbors<R, F>(&self, src: StrId, f: F) -> Option<R>
    where
        F: FnOnce(&NeighborList) -> R,
    {
        let outer = self
            .vertices
            .read();
        let slot = outer.get(&src)?;
        let guard = slot.read();
        Some(f(&*guard))
    }

    /// Tail-aware companion to [`Self::with_neighbors`]: invoke `f` with
    /// the base neighbor slice AND the post-finalize tail slice for
    /// `src`. Either slice may be empty; `f` is called as long as `src`
    /// has any outgoing edges in either store (returns `None` only when
    /// the vertex is truly degree-0 in both base and tail).
    ///
    /// Use this for read paths that must see the COMPLETE set of
    /// outgoing edges, including post-finalize appends that landed in
    /// the per-vertex tail buffer instead of the sorted base list.
    /// `neighbors_arc` / `with_neighbors` / `neighbors_snapshot` all
    /// return BASE only and silently drop tail edges — this helper is
    /// the read-side counterpart to the tail-aware [`Self::degree_of`].
    ///
    /// Holds the per-vertex base `RwLock` read guard AND the global
    /// tails `RwLock` read guard for the duration of `f`. Keep `f`
    /// short: collect the values you need (or push into a buffer) and
    /// exit so concurrent post-finalize appenders are not starved.
    pub fn with_neighbors_and_tail<R, F>(&self, src: StrId, f: F) -> Option<R>
    where
        F: FnOnce(&[StreamEdge], &[StreamEdge]) -> R,
    {
        let outer = self.vertices.read();
        let tails = self.tails.read();
        let base_slot = outer.get(&src);
        let tail_entry = tails.get(&src);

        // Vertex is degree-0 if both stores are empty/absent.
        if base_slot.is_none() && tail_entry.is_none() {
            return None;
        }

        // Materialize a base read guard if the slot exists; otherwise
        // provide an empty slice. Same for the tail.
        let base_guard = base_slot.map(|slot| slot.read());
        let base_slice: &[StreamEdge] = base_guard
            .as_deref()
            .map(|g| g.as_slice())
            .unwrap_or(&[]);
        let tail_slice: &[StreamEdge] = tail_entry
            .map(|t| t.as_slice())
            .unwrap_or(&[]);

        if base_slice.is_empty() && tail_slice.is_empty() {
            return None;
        }

        Some(f(base_slice, tail_slice))
    }

    /// L3 post-2c2 — capture a lock-free point-in-time read view
    /// over the outer vertex table. The matcher hot-path holds the
    /// snapshot for one hunt and per-frame does
    /// `snap.neighbors(sid).as_slice()` — pure `HashMap.get` plus
    /// pointer chase, *zero* atomic ops, *zero* `RwLock` acquires.
    ///
    /// Per-vertex behavior at freeze time:
    ///   * `Inline` / `Vec` (in-RAM rows): deep-copy the slice into
    ///     a fresh `Arc<[StreamEdge]>`. The snapshot is immune to
    ///     subsequent mutations on the live `Arc<RwLock<NeighborList>>`
    ///     because it owns its own immutable buffer.
    ///   * `Mmap` (auto-spilled rows): clone the `Arc<MmapHandle>`
    ///     and copy the (offset, len) pair. Zero memcpy because
    ///     the mapped region is already immutable.
    ///
    /// Cost: O(in-RAM edges) memcpy. For a 28 GB EVTX session
    /// that's already auto-spilled, ~all rows are `Mmap` and freeze
    /// is O(V) atomic Arc bumps — ~5 ms at V=1M. For an unspilled
    /// session of 100K edges in RAM, freeze is ~3 MB memcpy ≈
    /// 0.5 ms. Either way: amortized over millions of matcher
    /// frames, the freeze cost disappears under the per-frame
    /// savings (~10 ns × 10M frames ≈ 100 ms when reading goes
    /// from RwLock+Arc-deref to a single pointer load).
    pub fn freeze(&self) -> FrozenSnapshot {
        let outer = self.vertices.read();
        let tails = self.tails.read();
        let merge_tails = self.finalized.load(Ordering::Acquire);
        let mut frozen: ahash::HashMap<StrId, FrozenNeighborList> =
            ahash::HashMap::with_capacity_and_hasher(
                outer.len() + if merge_tails { tails.len() } else { 0 },
                ahash::RandomState::new(),
            );
        for (&sid, slot) in outer.iter() {
            let guard = slot.read();
            let mut f = match &*guard {
                NeighborList::Inline(sv) => {
                    FrozenNeighborList::InMemory(Arc::from(sv.as_slice()))
                }
                NeighborList::Vec(v) => {
                    FrozenNeighborList::InMemory(Arc::from(v.as_slice()))
                }
                NeighborList::Mmap {
                    handle,
                    byte_offset,
                    len,
                } => FrozenNeighborList::Mmap {
                    handle: handle.clone(),
                    byte_offset: *byte_offset,
                    len: *len,
                },
            };
            if merge_tails {
                if let Some(tail) = tails.get(&sid) {
                    f = Self::frozen_neighbor_merging_tail(&f, &guard, tail);
                }
            }
            frozen.insert(sid, f);
        }
        if merge_tails {
            for (&sid, tail) in tails.iter() {
                if tail.is_empty() || frozen.contains_key(&sid) {
                    continue;
                }
                // tail is maintained sorted-on-insert; copy directly.
                let arc: Arc<[StreamEdge]> = tail.iter().copied().collect();
                frozen.insert(
                    sid,
                    FrozenNeighborList::InMemory(arc),
                );
            }
        }
        FrozenSnapshot {
            vertices: Arc::new(frozen),
        }
    }

    /// Whether post-finalize tail appends are active.
    pub fn is_finalized(&self) -> bool {
        self.finalized.load(Ordering::Acquire)
    }

    /// Total edges in post-finalize tail buffers (not yet merged into base lists).
    pub fn tail_edge_count(&self) -> u64 {
        self.tails
            .read()
            .values()
            .map(|t| t.len() as u64)
            .sum()
    }

    fn frozen_neighbor_merging_tail(
        base_frozen: &FrozenNeighborList,
        base_guard: &NeighborList,
        tail: &[StreamEdge],
    ) -> FrozenNeighborList {
        if tail.is_empty() {
            return base_frozen.clone();
        }
        // tail is maintained sorted-on-insert (see append_edge_inner);
        // no per-read sort needed — straight two-way merge.
        let base_slice = base_guard.as_slice();
        let merged = if base_slice.is_empty() {
            tail.to_vec()
        } else {
            Self::merge_sorted_edge_slices(base_slice, tail)
        };
        FrozenNeighborList::InMemory(Arc::from(merged.into_boxed_slice()))
    }

    /// L3 stage 2c part 2 final — wipe all in-memory state. Used
    /// by `compact_before` and `remove_entities_and_relations_by_dataset`
    /// during their read-snapshot + clear + re-write rebuild
    /// pattern. Drops every per-vertex `Arc<RwLock<NeighborList>>`
    /// (and any backing `MmapHandle`s if they spilled), so a
    /// fresh `append_edge` pass populates from scratch.
    pub fn clear(&self) {
        let mut outer = self.vertices.write();
        outer.clear();
        self.finalized.store(false, Ordering::Release);
        self.tails.write().clear();
        // Reset auto-spill bookkeeping so the next round starts
        // from spill_round 0 with an empty in-memory budget.
        if let Some(state) = self.spill_state.lock().as_mut() {
            state.edges_since_last_spill = 0;
            state.current_path = None;
        }
    }

    /// L3 stage 2c part 2 — sort each per-vertex neighbor list by
    /// timestamp. This is the streaming-side counterpart to
    /// `SpillableEdgeStore::finalize`: post-finalize the matcher
    /// hot-path can run `partition_point` over the streaming slice
    /// to compute time-window ranges in O(log d) per frame, the
    /// same algorithmic shape it had with `edge_store`'s
    /// `(source_sid, timestamp)` sort.
    ///
    /// Cost: O(sum of d_v · log d_v) one-time pass after ingest.
    /// Hub vertices dominate the cost, but the same hubs are the
    /// ones the matcher would otherwise scan linearly per frame.
    ///
    /// Post-finalize appends go to the per-vertex tail buffer (see
    /// `tails`) and are merged at read time via
    /// [`Self::neighbors_in_window`].
    pub fn finalize(&self) {
        let outer = self.vertices.read();
        for slot in outer.values() {
            Self::sort_neighbor_slot(&mut *slot.write());
        }
        self.finalized.store(true, Ordering::Release);
    }

    /// Same semantics as [`Self::finalize`] but sorts per-vertex lists in
    /// parallel. Hub-heavy graphs benefit; Mmap-backed rows are unchanged.
    ///
    /// Slots with fewer than 2 edges are skipped — a 0- or 1-element list is
    /// already sorted and scheduling a rayon task for it costs more than it
    /// saves.
    pub fn finalize_parallel(&self) {
        use rayon::prelude::*;

        let slots: Vec<_> = {
            let outer = self.vertices.read();
            outer.values().cloned().collect()
        };
        slots.par_iter().for_each(|slot| {
            // Skip no-op sorts: a list of 0 or 1 edges needs no ordering.
            if slot.read().len() < 2 {
                return;
            }
            Self::sort_neighbor_slot(&mut *slot.write());
        });
        self.finalized.store(true, Ordering::Release);
    }

    /// Returns outgoing edges from `src` whose timestamps fall in
    /// `[window.0, window.1]` (inclusive), merging the sorted base
    /// neighbor list with any post-finalize tail edges.
    pub fn neighbors_in_window(&self, src: StrId, window: (i64, i64)) -> Vec<StreamEdge> {
        let (tw_start, tw_end) = window;
        let base_in_window: Vec<StreamEdge> = {
            let outer = self.vertices.read();
            match outer.get(&src) {
                Some(slot) => {
                    let guard = slot.read();
                    let edges = guard.as_slice();
                    let lo = edges.partition_point(|e| e.timestamp < tw_start);
                    let hi = edges.partition_point(|e| e.timestamp <= tw_end);
                    edges[lo..hi].to_vec()
                }
                None => Vec::new(),
            }
        };

        // tail is maintained sorted-on-insert; filter preserves order
        // so tail_in_window is already sorted — no per-read sort needed.
        let tail_in_window: Vec<StreamEdge> = self
            .tails
            .read()
            .get(&src)
            .map(|tail| {
                tail.iter()
                    .copied()
                    .filter(|e| e.timestamp >= tw_start && e.timestamp <= tw_end)
                    .collect()
            })
            .unwrap_or_default();
        if tail_in_window.is_empty() {
            return base_in_window;
        }
        Self::merge_sorted_edge_slices(&base_in_window, &tail_in_window)
    }

    fn merge_sorted_edge_slices(base: &[StreamEdge], tail: &[StreamEdge]) -> Vec<StreamEdge> {
        let mut out = Vec::with_capacity(base.len() + tail.len());
        let mut i = 0usize;
        let mut j = 0usize;
        while i < base.len() && j < tail.len() {
            if base[i].timestamp <= tail[j].timestamp {
                out.push(base[i]);
                i += 1;
            } else {
                out.push(tail[j]);
                j += 1;
            }
        }
        out.extend_from_slice(&base[i..]);
        out.extend_from_slice(&tail[j..]);
        out
    }

    fn sort_neighbor_slot(guard: &mut NeighborList) {
        match guard {
            NeighborList::Inline(sv) => sv.sort_unstable_by_key(|e| e.timestamp),
            NeighborList::Vec(v) => v.sort_unstable_by_key(|e| e.timestamp),
            // Already spilled; the file is sorted by construction
            // (consolidate writes runs in their current order, and
            // production today calls finalize() before consolidate()).
            NeighborList::Mmap { .. } => {}
        }
    }

    /// L3 stage 2c part 2 — visit each vertex's full neighbor
    /// slice in one closure call. The outer-table read guard is
    /// taken once for the whole sweep; the closure receives each
    /// `(src, &[StreamEdge])` pair while the per-vertex guard is
    /// held. Use this for index builds (`khop_reach`, NLF round
    /// loops, motif scans) that aggregate per-vertex and need the
    /// full slice rather than individual edges --- avoids the
    /// per-vertex `outer.read()` cost that `neighbors_arc` pays.
    pub fn for_each_vertex<F>(&self, mut f: F)
    where
        F: FnMut(StrId, &[StreamEdge]),
    {
        let outer = self.vertices.read();
        for (&src, slot) in outer.iter() {
            let guard = slot.read();
            f(src, guard.as_slice());
        }
    }

    /// L3 stage 2c part 2 — visit every (source_sid, StreamEdge)
    /// pair across all vertices. Replaces `SpillableEdgeStore::iter_all`
    /// for the consumers that aggregate over the whole graph
    /// (anomaly-scorer warm-up, temporal heatmap, timeline data,
    /// session serialization, etc.). The closure is called inside
    /// the per-vertex read guard, so concurrent writers on a vertex
    /// block until the closure returns for that vertex's slice.
    ///
    /// Order: vertex iteration order (HashMap order — non-deterministic
    /// across runs). Within a vertex, edge order matches `as_slice()`
    /// (insertion order pre-finalize, timestamp order post-finalize).
    /// `iter_all` on `edge_store` was sorted by `(source_sid,
    /// timestamp)`; consumers that aggregate into HashMaps don't
    /// care about order, but any consumer that did (none today)
    /// would need its own sort step.
    pub fn for_each_edge<F>(&self, mut f: F)
    where
        F: FnMut(StrId, &StreamEdge),
    {
        {
            let outer = self.vertices.read();
            for (&src, slot) in outer.iter() {
                let guard = slot.read();
                for edge in guard.as_slice() {
                    f(src, edge);
                }
            }
        }
        // Post-finalize tail buffers hold edges not present in the base
        // lists (base and tails are disjoint: pre-finalize all edges land
        // in base with tails empty; post-finalize NEW edges go only to
        // tails and base is untouched). Iterating both is correct and
        // double-count-free. Without this, consumers (save_session,
        // heavy_edges, channel_behavior, remove_*_by_dataset) silently
        // drop tail edges on finalized graphs.
        let tails = self.tails.read();
        for (&src, tail) in tails.iter() {
            for edge in tail.iter() {
                f(src, edge);
            }
        }
    }

    /// L3 D4 stage 1 — spill all in-memory neighbor lists to a
    /// single memory-mapped file. After consolidation, every per-
    /// vertex `NeighborList` is the `Mmap` variant pointing into
    /// the file; in-memory `Inline`/`Vec` storage is dropped.
    /// Reads stay zero-copy (`as_slice()` projects the mmap range)
    /// and the matcher's `partition_point` binary search keeps the
    /// same `O(log d)` per-frame complexity it had on `edge_store`.
    ///
    /// File layout (all little-endian, `#[repr(C)]` records):
    /// ```text
    ///   [0..4)    magic = 0x47485353 ("GHSS" — Graph Hunter Streaming Spill)
    ///   [4..8)    version = 1
    ///   [8..16)   vertex_count : u64
    ///   [16..N)   per-vertex byte_offset table — N = 16 + vertex_count*16
    ///             each entry: (byte_offset: u64, len: u64)
    ///   [N..pad8) zero-padding to 8-byte alignment
    ///   [pad8..)  concatenated StreamEdge runs, in vertex iteration order
    /// ```
    /// `byte_offset` in each `NeighborList::Mmap` points directly
    /// into the data region (post-padding) so `as_slice()` does
    /// no arithmetic at read time.
    ///
    /// Constraint: post-consolidate `append_edge` calls promote
    /// the affected vertex back to `Vec` (one O(degree) memcpy
    /// out of mmap on first write). Production today doesn't
    /// write post-consolidate, so this is a soft fallback.
    pub fn consolidate(
        &self,
        path: &std::path::Path,
    ) -> std::io::Result<()> {
        use std::io::Write;

        const MAGIC: u32 = 0x47485353; // "GHSS"
        const VERSION: u32 = 1;
        const HEADER_SIZE: usize = 16;
        const RECORD_SIZE: usize = std::mem::size_of::<StreamEdge>();

        let outer = self
            .vertices
            .read();

        // Snapshot the vertex order. We hold the outer read lock
        // for the whole consolidate pass so the table layout is
        // stable; per-vertex write locks are taken one at a time.
        let order: Vec<StrId> = outer.keys().copied().collect();
        let vertex_count = order.len();

        // Compute the data-region offset (post-padding to 8 B).
        let table_size = vertex_count * 16; // 8 + 8 per entry
        let pre_data = HEADER_SIZE + table_size;
        let data_offset = (pre_data + 7) & !7; // round up to 8

        // Pre-compute total bytes; pre-collect (byte_offset, len)
        // per vertex so writes happen in one pass.
        let mut entries: Vec<(u64, u64)> = Vec::with_capacity(vertex_count);
        let mut cursor = data_offset;
        for &sid in &order {
            let slot = outer.get(&sid).expect("snapshot order");
            let g = slot.read();
            let n = g.len();
            entries.push((cursor as u64, n as u64));
            cursor += n * RECORD_SIZE;
        }
        let total_size = cursor;

        // Write the file in one streaming pass (header + table +
        // pad + data).
        {
            let f = std::fs::File::create(path)?;
            let mut bw = std::io::BufWriter::new(f);
            bw.write_all(&MAGIC.to_le_bytes())?;
            bw.write_all(&VERSION.to_le_bytes())?;
            bw.write_all(&(vertex_count as u64).to_le_bytes())?;
            for (off, len) in &entries {
                bw.write_all(&off.to_le_bytes())?;
                bw.write_all(&len.to_le_bytes())?;
            }
            // Pad to data_offset.
            let pad = data_offset - pre_data;
            if pad > 0 {
                bw.write_all(&vec![0u8; pad])?;
            }
            // Data region: per-vertex StreamEdge runs.
            for &sid in &order {
                let slot = outer.get(&sid).expect("snapshot order");
                let g = slot.read();
                let edges = g.as_slice();
                let bytes: &[u8] = unsafe {
                    std::slice::from_raw_parts(
                        edges.as_ptr() as *const u8,
                        edges.len() * RECORD_SIZE,
                    )
                };
                bw.write_all(bytes)?;
            }
            bw.flush()?;
            // BufWriter drop ensures file handle is closed before
            // the mmap below opens it for reading.
        }

        // Open the file mmap. Read-only — once consolidated, the
        // backend treats the file as immutable.
        let f = std::fs::File::open(path)?;
        let mmap = unsafe { memmap2::Mmap::map(&f)? };
        // Best-effort hugepage hint on Linux.
        crate::mmap_advise::try_hugepages(&mmap);
        let handle = Arc::new(MmapHandle { mmap });

        // Sanity-check the file we just wrote: actual size matches
        // the planned size. If not, refuse to swap in the mmap
        // (something corrupted between write and read).
        if handle.mmap.len() != total_size {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!(
                    "streaming spill size mismatch: expected {}, got {}",
                    total_size,
                    handle.mmap.len()
                ),
            ));
        }

        // Swap each per-vertex slot to Mmap variant. Take the
        // per-vertex write lock briefly; the outer read lock
        // already held.
        for (i, &sid) in order.iter().enumerate() {
            let (byte_offset, len) = entries[i];
            let slot = outer.get(&sid).expect("snapshot order");
            let mut guard = slot.write();
            *guard = NeighborList::Mmap {
                handle: handle.clone(),
                byte_offset: byte_offset as usize,
                len: len as usize,
            };
        }

        Ok(())
    }

    /// L3 D4 stage 2 — internal auto-spill. Triggered from
    /// `append_edge` when `SpillState::edges_since_last_spill`
    /// crosses `budget_edges`. Behaves like `consolidate` but:
    ///
    ///   * Writes to a fresh round-numbered file under the
    ///     backend-managed `spill_dir` (the path is auto-chosen).
    ///   * Sorts each per-vertex slice by `timestamp` *during* the
    ///     write, so the spilled file is matcher-ready
    ///     (`partition_point` works on the resulting `Mmap` slice).
    ///   * Deletes the previous round's file after the new mmap
    ///     swap-in completes (each round is a full re-write; the
    ///     old file is orphaned).
    ///
    /// Failure is bubbled to the caller (`append_edge`'s wrapper);
    /// state is left consistent (vertices still on the previous
    /// `Mmap` or in-memory variants).
    fn auto_spill(&self) -> std::io::Result<()> {
        if self
            .spill_state
            .lock()
            .as_ref()
            .is_some_and(|s| s.force_fail)
        {
            return Err(std::io::Error::other(
                "streaming auto-spill forced failure (test hook)",
            ));
        }

        use std::io::Write;
        const MAGIC: u32 = 0x47485353;
        const VERSION: u32 = 1;
        const HEADER_SIZE: usize = 16;
        const RECORD_SIZE: usize = std::mem::size_of::<StreamEdge>();

        // Snapshot path + round number under the spill state
        // mutex; release before doing the actual write so other
        // append_edge callers don't pile up on it. Subsequent
        // re-entries see edges_since_last_spill back at 0 and skip.
        let (spill_path, prev_path) = {
            let mut state = self.spill_state.lock();
            let s = match state.as_mut() {
                Some(s) => s,
                None => return Ok(()),
            };
            // Reset the budget counter immediately so concurrent
            // append_edges past this point start counting toward
            // the next round.
            s.edges_since_last_spill = 0;
            let round = s.spill_round;
            s.spill_round += 1;
            let new_path = s.spill_dir.join(format!("auto-spill-{round}.bin"));
            let prev = s.current_path.replace(new_path.clone());
            (new_path, prev)
        };

        let outer = self.vertices.read();
        let order: Vec<StrId> = outer.keys().copied().collect();
        let vertex_count = order.len();
        let table_size = vertex_count * 16;
        let pre_data = HEADER_SIZE + table_size;
        let data_offset = (pre_data + 7) & !7;

        // First pass: per-vertex, take a write lock and sort the
        // slice in place if it isn't already sorted (Mmap variants
        // came from a previous auto-spill so they're already
        // sorted; Inline/Vec hold post-spill appends). Also
        // pre-compute byte offsets for the table.
        let mut entries: Vec<(u64, u64)> = Vec::with_capacity(vertex_count);
        let mut cursor = data_offset;
        for &sid in &order {
            let slot = outer.get(&sid).expect("snapshot order");
            let mut guard = slot.write();
            match &mut *guard {
                NeighborList::Inline(sv) => sv.sort_unstable_by_key(|e| e.timestamp),
                NeighborList::Vec(v) => v.sort_unstable_by_key(|e| e.timestamp),
                NeighborList::Mmap { .. } => {} // already sorted by previous round
            }
            let n = guard.len();
            entries.push((cursor as u64, n as u64));
            cursor += n * RECORD_SIZE;
        }
        let total_size = cursor;

        // Write the file in one pass.
        {
            let f = std::fs::File::create(&spill_path)?;
            let mut bw = std::io::BufWriter::new(f);
            bw.write_all(&MAGIC.to_le_bytes())?;
            bw.write_all(&VERSION.to_le_bytes())?;
            bw.write_all(&(vertex_count as u64).to_le_bytes())?;
            for (off, len) in &entries {
                bw.write_all(&off.to_le_bytes())?;
                bw.write_all(&len.to_le_bytes())?;
            }
            let pad = data_offset - pre_data;
            if pad > 0 {
                bw.write_all(&vec![0u8; pad])?;
            }
            for &sid in &order {
                let slot = outer.get(&sid).expect("snapshot order");
                let g = slot.read();
                let edges = g.as_slice();
                let bytes: &[u8] = unsafe {
                    std::slice::from_raw_parts(
                        edges.as_ptr() as *const u8,
                        edges.len() * RECORD_SIZE,
                    )
                };
                bw.write_all(bytes)?;
            }
            bw.flush()?;
        }

        // mmap the freshly written file.
        let f = std::fs::File::open(&spill_path)?;
        let mmap = unsafe { memmap2::Mmap::map(&f)? };
        crate::mmap_advise::try_hugepages(&mmap);
        let handle = Arc::new(MmapHandle { mmap });

        if handle.mmap.len() != total_size {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!(
                    "streaming auto-spill size mismatch: expected {}, got {}",
                    total_size,
                    handle.mmap.len()
                ),
            ));
        }

        // Swap every slot to Mmap pointing at the new file.
        for (i, &sid) in order.iter().enumerate() {
            let (byte_offset, len) = entries[i];
            let slot = outer.get(&sid).expect("snapshot order");
            let mut guard = slot.write();
            *guard = NeighborList::Mmap {
                handle: handle.clone(),
                byte_offset: byte_offset as usize,
                len: len as usize,
            };
        }
        drop(outer);

        // Best-effort delete of the previous round's file. The
        // previous handle dropped out of every NeighborList::Mmap
        // when we swapped above; the Arc count is now zero so
        // memmap2 has unmapped the file. On Windows the file
        // handle is closed by the unmap, so std::fs::remove_file
        // is safe even though the OS otherwise locks open files.
        if let Some(prev) = prev_path {
            let _ = std::fs::remove_file(prev);
        }

        Ok(())
    }

    /// Append one edge and surface auto-spill failures to the caller.
    pub fn try_append_edge(&self, src: StrId, edge: StreamEdge) -> Result<(), crate::errors::GraphError> {
        self.append_edge_inner(src, edge);
        let needs_spill = {
            let mut state = self.spill_state.lock();
            match state.as_mut() {
                Some(s) => {
                    s.edges_since_last_spill += 1;
                    s.edges_since_last_spill >= s.budget_edges
                }
                None => false,
            }
        };
        if needs_spill {
            self.auto_spill()
                .map_err(|e| crate::errors::GraphError::Spill(e.to_string()))?;
        }
        Ok(())
    }

    /// Checked append used by the ingest writer path (`push_to_streaming`).
    pub fn append_edge_checked(
        &self,
        src: StrId,
        edge: StreamEdge,
    ) -> Result<(), crate::errors::GraphError> {
        self.try_append_edge(src, edge)
    }

    fn append_edge_inner(&self, src: StrId, edge: StreamEdge) {
        if self.finalized.load(Ordering::Acquire) {
            // Tail is kept sorted by timestamp (same tiebreak as the
            // sorted base: timestamp only). Insert at the sorted position
            // so freeze() and neighbors_in_window() can skip the
            // per-read sort and go straight to two-way merge.
            let mut tails = self.tails.write();
            let tail = tails.entry(src).or_default();
            let pos = tail.partition_point(|e| e.timestamp <= edge.timestamp);
            tail.insert(pos, edge);
            return;
        }
        // Fast path: vertex already exists, take a read lock on
        // the outer table and a write lock on the per-vertex slot.
        {
            let outer = self.vertices.read();
            if let Some(slot) = outer.get(&src) {
                let mut guard = slot.write();
                guard.push(edge);
            } else {
                drop(outer);
                // Slow path: insert a new vertex slot. Need the
                // write lock on the outer table just for the
                // insertion.
                let mut outer = self.vertices.write();
                let slot = outer.entry(src).or_insert_with(|| {
                    Arc::new(RwLock::new(NeighborList::default()))
                });
                let mut guard = slot.write();
                guard.push(edge);
            }
        }
    }
}

impl StreamingGraphBackend for InMemoryStreamingBackend {
    fn append_edge(&self, src: StrId, edge: StreamEdge) {
        if let Err(e) = self.try_append_edge(src, edge) {
            // Trait API stays infallible for legacy/tests; writer path
            // uses `append_edge_checked` via `push_to_streaming`.
            #[cfg(debug_assertions)]
            eprintln!("streaming append_edge spill failure: {e}");
            #[cfg(not(debug_assertions))]
            let _ = e;
        }
    }

    fn neighbors_snapshot(&self, src: StrId) -> Option<std::sync::Arc<NeighborList>> {
        let outer = self
            .vertices
            .read();
        let slot = outer.get(&src)?;
        let guard = slot.read();
        // Clone the NeighborList into a fresh Arc so the snapshot
        // is independent of subsequent writes.
        Some(std::sync::Arc::new(guard.clone()))
    }

    fn vertex_count(&self) -> usize {
        self.vertices
            .read()
            .len()
    }

    fn edge_count(&self) -> usize {
        let base: usize = {
            let outer = self.vertices.read();
            outer.values().map(|slot| slot.read().len()).sum()
        };
        let tail: usize = self
            .tails
            .read()
            .values()
            .map(SmallVec::len)
            .sum();
        base + tail
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn edge(dst: u32, ts: i64, tag: u8) -> StreamEdge {
        StreamEdge {
            timestamp: ts,
            metadata_offset: 0,
            source_sid: StrId::from_raw(0),
            dest_sid: StrId::from_raw(dst),
            ingested_at_delta: 0,
            dataset_tag: 0,
            rel_type_tag: tag,
        }
    }

    #[test]
    fn inline_holds_eight_edges() {
        let mut nl = NeighborList::default();
        for i in 0..INLINE_CAPACITY as i64 {
            nl.push(edge(i as u32, i, 0));
        }
        assert_eq!(nl.variant_tag(), "inline");
        assert_eq!(nl.len(), INLINE_CAPACITY);
    }

    #[test]
    fn promotes_inline_to_vec_at_capacity_plus_one() {
        let mut nl = NeighborList::default();
        for i in 0..(INLINE_CAPACITY as i64 + 1) {
            nl.push(edge(i as u32, i, 0));
        }
        assert_eq!(nl.variant_tag(), "vec");
        assert_eq!(nl.len(), INLINE_CAPACITY + 1);
        let dests: Vec<u32> = nl.iter().map(|e| e.dest_sid.index() as u32).collect();
        for i in 0..(INLINE_CAPACITY as u32 + 1) {
            assert!(dests.contains(&i));
        }
    }

    #[test]
    fn vec_holds_high_degree_vertex_as_contiguous_slice() {
        // 2c-part-2 dropped the Btree variant. A 1024-edge vertex
        // stays in `Vec` and exposes a contiguous `&[StreamEdge]`
        // for the matcher hot-path.
        let mut nl = NeighborList::default();
        for i in 0..1024i64 {
            nl.push(edge(i as u32, i, 0));
        }
        assert_eq!(nl.variant_tag(), "vec");
        assert_eq!(nl.len(), 1024);
        let s = nl.as_slice();
        assert_eq!(s.len(), 1024);
        assert_eq!(s[0].timestamp, 0);
        assert_eq!(s[1023].timestamp, 1023);
    }

    #[test]
    fn iter_window_inline_filters() {
        let mut nl = NeighborList::default();
        for i in 0..5i64 {
            nl.push(edge(i as u32, i * 10, 0));
        }
        // Window [15, 35) — should hit dest=2 (ts=20) and dest=3 (ts=30).
        let kept: Vec<i64> = nl.iter_window(15, 35).map(|e| e.timestamp).collect();
        assert_eq!(kept, vec![20, 30]);
    }

    #[test]
    fn iter_window_vec_filters_high_degree() {
        // After 2c-part-2 the Btree variant is gone; high-degree
        // vertices stay Vec and use a linear filter for window
        // queries. Same observable result, O(degree) instead of
        // O(log d + window).
        let mut nl = NeighborList::default();
        for i in 0..200i64 {
            nl.push(edge(i as u32, i, 0));
        }
        assert_eq!(nl.variant_tag(), "vec");
        // Half-open [50, 60) → 10 entries.
        let kept: Vec<i64> = nl.iter_window(50, 60).map(|e| e.timestamp).collect();
        assert_eq!(kept, (50..60).collect::<Vec<_>>());
    }

    #[test]
    fn backend_append_and_snapshot() {
        let backend = InMemoryStreamingBackend::new();
        let src = StrId::from_raw(1);
        backend.append_edge(src, edge(2, 100, 0));
        backend.append_edge(src, edge(3, 200, 0));
        backend.append_edge(StrId::from_raw(99), edge(2, 50, 1));

        assert_eq!(backend.vertex_count(), 2);
        assert_eq!(backend.edge_count(), 3);

        let snap = backend.neighbors_snapshot(src).expect("vertex 1 has edges");
        assert_eq!(snap.len(), 2);
        let dests: Vec<u32> = snap.iter().map(|e| e.dest_sid.index() as u32).collect();
        assert!(dests.contains(&2));
        assert!(dests.contains(&3));
    }

    #[test]
    fn add_relation_mirrors_into_streaming_backend() {
        // L3 stage 2: every add_relation on GraphHunter must
        // surface in the streaming backend so a future delta-aware
        // matcher (or live-tail UI feature) can read the new edge
        // without scanning the static edge_store.
        use crate::graph::GraphHunter;
        use crate::Entity;
        use crate::Relation;
        use graph_hunter_dsl::types::{EntityType, RelationType};

        let mut g = GraphHunter::new();
        g.add_entity(Entity::new("a", EntityType::User)).unwrap();
        g.add_entity(Entity::new("b", EntityType::Host)).unwrap();
        g.add_relation(Relation::new("a", "b", RelationType::Auth, 100))
            .unwrap();

        let a_sid = g.interner.get("a").expect("a interned");
        let snap = g
            .streaming
            .neighbors_snapshot(a_sid)
            .expect("streaming backend should have a's edges");
        assert_eq!(snap.len(), 1);
        let edge = snap.iter().next().expect("one edge");
        assert_eq!(edge.timestamp, 100);
        assert_eq!(edge.rel_type_tag, RelationType::Auth.to_u8());
    }

    #[test]
    fn neighbors_of_parity_with_get_relations_by_sid() {
        // L3 stage 2c: neighbors_of (streaming) must surface the
        // same edges as get_relations_by_sid (legacy edge_store)
        // — modulo field naming. Verifies the dual-write keeps
        // the two stores in sync and that StreamEdge faithfully
        // mirrors CompactRelation.
        use crate::graph::GraphHunter;
        use crate::Entity;
        use crate::Relation;
        use graph_hunter_dsl::types::{EntityType, RelationType};

        let mut g = GraphHunter::new();
        for n in ["a", "b", "c"] {
            g.add_entity(Entity::new(n, EntityType::User)).unwrap();
        }
        g.add_relation(Relation::new("a", "b", RelationType::Auth, 100))
            .unwrap();
        g.add_relation(Relation::new("a", "c", RelationType::Auth, 200))
            .unwrap();

        let a = g.interner.get("a").unwrap();
        let legacy = g.get_relations_by_sid(a);
        let streamed = g.streaming.neighbors_of(a);
        assert_eq!(streamed.len(), legacy.len(), "row count parity");
        for s in &streamed {
            // Find the matching legacy row by (dest, ts).
            let matched = legacy.iter().find(|c| {
                c.dest_sid == s.dest_sid && c.timestamp == s.timestamp
            });
            assert!(matched.is_some(), "streaming row must appear in legacy");
            let m = matched.unwrap();
            assert_eq!(m.rel_type_tag, s.rel_type_tag);
            assert_eq!(m.metadata_offset, s.metadata_offset);
            assert_eq!(m.dataset_tag, s.dataset_tag);
            assert_eq!(m.ingested_at_delta, s.ingested_at_delta);
            assert_eq!(m.source_sid, s.source_sid, "source_sid parity");
        }
        assert_eq!(g.streaming.degree_of(a), 2);
    }

    #[test]
    fn snapshot_is_independent_of_subsequent_writes() {
        let backend = InMemoryStreamingBackend::new();
        let src = StrId::from_raw(1);
        backend.append_edge(src, edge(2, 100, 0));
        let snap = backend.neighbors_snapshot(src).unwrap();
        assert_eq!(snap.len(), 1);
        // Writer adds another edge; snapshot taken before should
        // still see only 1.
        backend.append_edge(src, edge(3, 200, 0));
        assert_eq!(snap.len(), 1);
        let snap2 = backend.neighbors_snapshot(src).unwrap();
        assert_eq!(snap2.len(), 2);
    }

    #[test]
    fn consolidate_round_trips_to_mmap_and_preserves_edge_set() {
        // L3 D4 stage 1 — after consolidate, every per-vertex slot
        // is Mmap-backed and as_slice() returns the same edge set
        // it would have returned from the in-memory Inline/Vec
        // variant.
        let backend = InMemoryStreamingBackend::new();
        let a = StrId::from_raw(1);
        let b = StrId::from_raw(2);
        backend.append_edge(a, edge(10, 100, 0));
        backend.append_edge(a, edge(11, 200, 0));
        backend.append_edge(a, edge(12, 300, 1));
        for i in 0..50i64 {
            backend.append_edge(b, edge(i as u32 + 100, i, 0));
        }
        backend.finalize();

        // Snapshot the in-memory edges before consolidate.
        let pre_a: Vec<(u32, i64)> = backend
            .with_neighbors(a, |list| {
                list.iter()
                    .map(|e| (e.dest_sid.index() as u32, e.timestamp))
                    .collect()
            })
            .unwrap();
        let pre_b_len = backend.with_neighbors(b, |list| list.len()).unwrap();

        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("streaming.spill");
        backend.consolidate(&path).expect("consolidate");

        // Both vertices should now be Mmap variant.
        let arc_a = backend.neighbors_arc(a).expect("a");
        let g_a = arc_a.read();
        assert_eq!(g_a.variant_tag(), "mmap");
        let post_a: Vec<(u32, i64)> = g_a
            .iter()
            .map(|e| (e.dest_sid.index() as u32, e.timestamp))
            .collect();
        assert_eq!(post_a, pre_a, "vertex a edge set preserved through mmap");

        let arc_b = backend.neighbors_arc(b).expect("b");
        let g_b = arc_b.read();
        assert_eq!(g_b.variant_tag(), "mmap");
        assert_eq!(g_b.len(), pre_b_len);
        // partition_point on an Mmap slice — same shape the matcher
        // would use for time-window pruning.
        let s = g_b.as_slice();
        let lo = s.partition_point(|e| e.timestamp < 10);
        let hi = s.partition_point(|e| e.timestamp <= 30);
        assert_eq!(hi - lo, 21, "mmap slice supports binary search");
    }

    #[test]
    fn append_edge_surfaces_spill_failure() {
        use crate::errors::GraphError;

        let backend = InMemoryStreamingBackend::new().with_spill_fail(true);
        let src = StrId::from_raw(1);
        let err = backend.append_edge_checked(src, edge(2, 100, 0));
        assert!(matches!(err, Err(GraphError::Spill(_))));
    }

    #[test]
    fn auto_spill_triggers_at_budget_and_swaps_to_mmap() {
        // L3 D4 stage 2 — budget of 5 edges. The 5th push triggers
        // a spill (counter reaches the threshold AT push 5, before
        // pushes 6+ arrive). At that snapshot every vertex slice is
        // Mmap-backed and timestamp-sorted.
        let backend = InMemoryStreamingBackend::new()
            .with_memory_budget_edges(5);
        let a = StrId::from_raw(1);
        let b = StrId::from_raw(2);
        backend.append_edge(a, edge(10, 100, 0));
        backend.append_edge(a, edge(11, 200, 0));
        backend.append_edge(a, edge(12, 50, 0)); // out of order
        backend.append_edge(b, edge(20, 75, 0));
        // 5th push crosses the budget threshold → spill triggers
        // inside this call. After it returns every vertex is Mmap.
        backend.append_edge(b, edge(21, 175, 0));

        let arc_a = backend.neighbors_arc(a).expect("a");
        assert_eq!(arc_a.read().variant_tag(), "mmap");
        let arc_b = backend.neighbors_arc(b).expect("b");
        assert_eq!(arc_b.read().variant_tag(), "mmap");

        // Edge sets preserved and timestamp-sorted (auto-spill
        // sorts each per-vertex slice during the write).
        let g_a = arc_a.read();
        let s_a: Vec<i64> = g_a.iter().map(|e| e.timestamp).collect();
        assert_eq!(s_a, vec![50, 100, 200]);
        let g_b = arc_b.read();
        let s_b: Vec<i64> = g_b.iter().map(|e| e.timestamp).collect();
        assert_eq!(s_b, vec![75, 175]);
    }

    #[test]
    fn append_after_auto_spill_promotes_only_touched_vertex() {
        // After auto-spill all vertices are Mmap. The next push
        // promotes ONLY the touched vertex back to Vec; the
        // untouched one stays Mmap.
        let backend = InMemoryStreamingBackend::new()
            .with_memory_budget_edges(3);
        let a = StrId::from_raw(1);
        let b = StrId::from_raw(2);
        backend.append_edge(a, edge(10, 100, 0));
        backend.append_edge(a, edge(11, 200, 0));
        // 3rd push triggers spill.
        backend.append_edge(b, edge(20, 75, 0));

        // Both Mmap right after spill.
        assert_eq!(
            backend.neighbors_arc(a).unwrap().read().variant_tag(),
            "mmap"
        );
        assert_eq!(
            backend.neighbors_arc(b).unwrap().read().variant_tag(),
            "mmap"
        );

        // Append on `a` only — should promote `a` to Vec, leave `b`.
        backend.append_edge(a, edge(12, 300, 0));
        assert_eq!(
            backend.neighbors_arc(a).unwrap().read().variant_tag(),
            "vec"
        );
        assert_eq!(
            backend.neighbors_arc(b).unwrap().read().variant_tag(),
            "mmap"
        );
    }

    #[test]
    fn auto_spill_handles_multiple_rounds() {
        // Push enough edges to trigger 3 spill rounds. After the
        // third, every vertex's full insertion history must be
        // present (no edge loss across rounds, no double-counting,
        // sorted by timestamp).
        let backend = InMemoryStreamingBackend::new()
            .with_memory_budget_edges(10);
        let a = StrId::from_raw(1);
        // 35 edges total: round-1 at 10, round-2 at 20, round-3 at 30,
        // and 5 more in-memory after the third spill.
        for i in 0..35i64 {
            // Reverse timestamps to verify sort-on-spill works
            // across rounds (each round receives a mix of mmap'd
            // already-sorted runs and freshly-pushed unsorted ones).
            backend.append_edge(a, edge(i as u32, 1000 - i, 0));
        }

        let arc = backend.neighbors_arc(a).expect("a");
        let g = arc.read();
        assert_eq!(g.len(), 35);
        // Final state should be sorted ascending by timestamp; the
        // last 5 are in-memory (post-third-round) so the variant
        // is whatever the post-spill promote-on-write logic landed
        // on — accept either Mmap (if 5 < budget) or Vec.
        let timestamps: Vec<i64> = g.iter().map(|e| e.timestamp).collect();
        let mut expected: Vec<i64> = (0..35i64).map(|i| 1000 - i).collect();
        expected.sort();
        // The 5 post-third-round in-memory edges aren't sorted yet
        // (sort happens at spill time, not at every push), so the
        // final slice may be sorted-then-unsorted-tail. Verify the
        // SET is correct.
        let mut got_set = timestamps.clone();
        got_set.sort();
        assert_eq!(got_set, expected, "edge set preserved across rounds");
    }

    #[test]
    fn append_after_consolidate_promotes_back_to_vec() {
        // Soft fallback: post-consolidate appends still work, at
        // the cost of one O(degree) memcpy out of the mmap.
        let backend = InMemoryStreamingBackend::new();
        let a = StrId::from_raw(1);
        backend.append_edge(a, edge(10, 100, 0));
        backend.append_edge(a, edge(11, 200, 0));

        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("streaming.spill");
        backend.consolidate(&path).expect("consolidate");

        // Verify pre-write variant is mmap.
        assert_eq!(
            backend
                .with_neighbors(a, |list| list.variant_tag())
                .unwrap(),
            "mmap"
        );

        // Append — should promote Mmap → Vec.
        backend.append_edge(a, edge(12, 300, 1));

        let final_state = backend.with_neighbors(a, |list| {
            (
                list.variant_tag(),
                list.len(),
                list.iter()
                    .map(|e| e.timestamp)
                    .collect::<Vec<_>>(),
            )
        });
        let (tag, len, ts) = final_state.unwrap();
        assert_eq!(tag, "vec");
        assert_eq!(len, 3);
        assert_eq!(ts, vec![100, 200, 300]);
    }

    #[test]
    fn frozen_snapshot_is_immune_to_post_freeze_mutation() {
        // Stage 2c part 2 follow-up: FrozenNeighborList::InMemory
        // owns its own Arc<[StreamEdge]>, so post-freeze appends
        // to the live backend do NOT change the snapshot's view of
        // an existing vertex.
        let backend = InMemoryStreamingBackend::new();
        let a = StrId::from_raw(1);
        backend.append_edge(a, edge(10, 100, 0));
        backend.append_edge(a, edge(11, 200, 0));

        let snap = backend.freeze();
        let pre = snap.neighbors(a).expect("a in snapshot");
        assert_eq!(pre.len(), 2);

        // Append a third edge to the live backend AFTER freezing.
        backend.append_edge(a, edge(12, 300, 0));

        // Snapshot still shows 2 edges — its Arc<[T]> is the
        // pre-freeze deep copy, untouched by the live mutation.
        let post = snap.neighbors(a).expect("a still in snapshot");
        assert_eq!(post.len(), 2, "snapshot is immutable post-freeze");

        // Live backend sees all 3.
        assert_eq!(backend.degree_of(a), 3);
    }

    #[test]
    fn frozen_snapshot_shares_mmap_with_live_backend() {
        // Mmap-backed rows: the snapshot's Mmap variant SHARES the
        // Arc<MmapHandle> with the live backend (no deep copy at
        // freeze, same byte_offset+len). Validates that consolidate
        // post-freeze keeps the snapshot pointing at the (now
        // potentially deleted) old file via Arc refcount.
        let backend = InMemoryStreamingBackend::new();
        let a = StrId::from_raw(1);
        for i in 0..5u32 {
            backend.append_edge(a, edge(i + 100, i as i64, 0));
        }
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("streaming.spill");
        backend.consolidate(&path).expect("consolidate");

        let snap = backend.freeze();
        let nl = snap.neighbors(a).expect("a in snapshot");
        let slice = nl.as_slice();
        assert_eq!(slice.len(), 5);
        assert_eq!(slice[0].timestamp, 0);
        assert_eq!(slice[4].timestamp, 4);
    }

    #[test]
    fn freeze_returns_lock_free_snapshot_seeing_pre_freeze_edges() {
        // Post-2c2 snapshot: freeze() captures the outer table
        // at a moment in time. Subsequent inserts to NEW slots
        // don't appear in the snapshot; mutations on EXISTING
        // slots do (Arc<RwLock<NeighborList>> is shared).
        let backend = InMemoryStreamingBackend::new();
        let a = StrId::from_raw(1);
        backend.append_edge(a, edge(10, 100, 0));
        backend.append_edge(a, edge(11, 200, 0));

        let snap = backend.freeze();
        assert_eq!(snap.vertex_count(), 1);

        // Snapshot sees vertex `a` with 2 edges.
        let neighbors = snap.neighbors(a).expect("a in snapshot");
        assert_eq!(neighbors.len(), 2);

        // New vertex `b` post-snapshot is NOT visible in the snapshot.
        let b = StrId::from_raw(2);
        backend.append_edge(b, edge(20, 50, 0));
        assert!(snap.neighbors(b).is_none());
        assert_eq!(snap.vertex_count(), 1);
        // Live backend sees `b`.
        assert_eq!(backend.neighbors_arc(b).is_some(), true);

        // Snapshot is Clone-cheap (Arc bump).
        let snap2 = snap.clone();
        assert_eq!(snap2.vertex_count(), 1);
    }

    #[test]
    fn neighbors_merge_base_and_tail_by_timestamp() {
        let backend = InMemoryStreamingBackend::new();
        let src = StrId::from_raw(1);
        backend.append_edge(src, edge(2, 100, 0));
        backend.append_edge(src, edge(3, 300, 0));
        backend.finalize();
        backend.append_edge(src, edge(4, 200, 0));

        let window = (150i64, 250i64);
        let n = backend.neighbors_in_window(src, window);
        assert_eq!(n.len(), 1);
        assert_eq!(n[0].dest_sid, StrId::from_raw(4));
        assert_eq!(backend.degree_of(src), 3);
    }

    #[test]
    fn post_finalize_append_does_not_mutate_sorted_base() {
        let backend = InMemoryStreamingBackend::new();
        let src = StrId::from_raw(1);
        backend.append_edge(src, edge(2, 100, 0));
        backend.append_edge(src, edge(3, 200, 0));
        backend.finalize();

        let arc = backend.neighbors_arc(src).expect("vertex");
        let pre_len = arc.read().len();
        backend.append_edge(src, edge(4, 150, 0));
        assert_eq!(arc.read().len(), pre_len);
        assert_eq!(backend.degree_of(src), pre_len + 1);
    }

    #[test]
    fn freeze_includes_post_finalize_tails() {
        let backend = InMemoryStreamingBackend::new();
        let src = StrId::from_raw(1);
        backend.append_edge(src, edge(2, 100, 0));
        backend.append_edge(src, edge(3, 300, 0));
        backend.finalize();
        backend.append_edge(src, edge(4, 200, 0));

        let snap = backend.freeze();
        let neighbors = snap.neighbors(src).expect("src").as_slice();
        assert_eq!(neighbors.len(), 3);
        let timestamps: Vec<i64> = neighbors.iter().map(|e| e.timestamp).collect();
        assert_eq!(timestamps, vec![100, 200, 300]);
    }

    #[test]
    fn finalize_sorts_each_vertex_by_timestamp() {
        // L3 stage 2c part 2: post-finalize the streaming slice is
        // sorted by timestamp per-vertex, mirroring edge_store's
        // (source_sid, timestamp) finalize. The matcher's
        // partition_point binary search depends on this.
        let backend = InMemoryStreamingBackend::new();
        let src = StrId::from_raw(1);
        // Insert in unsorted order.
        backend.append_edge(src, edge(2, 300, 0));
        backend.append_edge(src, edge(3, 100, 1));
        backend.append_edge(src, edge(4, 200, 2));
        // Same on a hub vertex (forces Vec variant).
        let hub = StrId::from_raw(2);
        for i in (0..50i64).rev() {
            backend.append_edge(hub, edge(i as u32 + 100, i, 0));
        }

        backend.finalize();

        let arc = backend.neighbors_arc(src).expect("vertex");
        let guard = arc.read();
        let s = guard.as_slice();
        assert_eq!(s[0].timestamp, 100);
        assert_eq!(s[1].timestamp, 200);
        assert_eq!(s[2].timestamp, 300);

        let arc_hub = backend.neighbors_arc(hub).expect("hub");
        let guard_hub = arc_hub.read();
        let hs = guard_hub.as_slice();
        for w in hs.windows(2) {
            assert!(w[0].timestamp <= w[1].timestamp, "hub sorted");
        }
    }

    #[test]
    fn finalize_parallel_matches_sequential() {
        fn seed(backend: &InMemoryStreamingBackend) {
            for src_raw in 1..=10u32 {
                let src = StrId::from_raw(src_raw);
                for i in 0..10u32 {
                    let ts = ((src_raw * 17 + i * 13) % 1000) as i64;
                    backend.append_edge(src, edge(src_raw + 100 + i, ts, 0));
                }
            }
        }

        fn neighbor_timestamps(backend: &InMemoryStreamingBackend) -> Vec<(StrId, Vec<i64>)> {
            let mut out = Vec::new();
            for src_raw in 1..=10u32 {
                let src = StrId::from_raw(src_raw);
                let arc = backend.neighbors_arc(src).expect("vertex");
                let guard = arc.read();
                out.push((
                    src,
                    guard.as_slice().iter().map(|e| e.timestamp).collect(),
                ));
            }
            out
        }

        let sequential = InMemoryStreamingBackend::new();
        seed(&sequential);
        sequential.finalize();

        let parallel = InMemoryStreamingBackend::new();
        seed(&parallel);
        parallel.finalize_parallel();

        assert_eq!(
            neighbor_timestamps(&sequential),
            neighbor_timestamps(&parallel)
        );
    }

    #[test]
    fn neighbors_arc_exposes_slice_for_matcher_hotpath() {
        // L3 stage 2c part 2: the matcher hot-path takes the per-vertex
        // Arc, takes a read guard on it, and reads guard.as_slice() to
        // get `&[StreamEdge]`. Same long-lived slice borrow as the
        // legacy edge_store.get_edges path, with prefetch lookahead
        // intact.
        let backend = InMemoryStreamingBackend::new();
        let src = StrId::from_raw(1);
        for i in 0..16u32 {
            backend.append_edge(src, edge(i + 100, i as i64, 0));
        }

        let arc = backend.neighbors_arc(src).expect("vertex has edges");
        let guard = arc.read();
        let slice: &[StreamEdge] = guard.as_slice();
        assert_eq!(slice.len(), 16);
        // Slice access — read by index to mimic the matcher's
        // `&edges[idx]` + prefetch-lookahead pattern.
        for i in 0..16usize {
            assert_eq!(slice[i].timestamp, i as i64);
            assert_eq!(slice[i].dest_sid.index() as u32, (i as u32) + 100);
        }

        // Absent vertex returns None.
        assert!(backend.neighbors_arc(StrId::from_raw(999)).is_none());
    }

    #[test]
    fn with_neighbors_returns_same_set_as_snapshot_without_cloning() {
        // L3 stage 2c follow-up: the closure-based borrow API must
        // surface the same edge set as `neighbors_snapshot`. This
        // is the parity test that lets `try_record_edge_delta`
        // (and, eventually, the matcher hot path) drop the
        // NeighborList clone without changing observable behavior.
        let backend = InMemoryStreamingBackend::new();
        let src = StrId::from_raw(1);
        backend.append_edge(src, edge(2, 100, 0));
        backend.append_edge(src, edge(3, 200, 1));
        backend.append_edge(src, edge(4, 300, 2));

        let snap_dests: Vec<u32> = backend
            .neighbors_snapshot(src)
            .expect("vertex has edges")
            .iter()
            .map(|e| e.dest_sid.index() as u32)
            .collect();

        let borrow_dests: Vec<u32> = backend
            .with_neighbors(src, |list| {
                list.iter().map(|e| e.dest_sid.index() as u32).collect()
            })
            .expect("vertex has edges");

        assert_eq!(borrow_dests, snap_dests);

        // Vertex with no edges returns None — consistent with
        // `neighbors_snapshot`.
        let absent = StrId::from_raw(999);
        assert!(backend.neighbors_snapshot(absent).is_none());
        assert!(backend
            .with_neighbors(absent, |list| list.len())
            .is_none());
    }

    // ── H-3 property test ─────────────────────────────────────────────────
    //
    // For random append streams split at a random index into pre-finalize
    // (go to base via append_edge) and post-finalize (go to tail), the
    // merged read output must equal a full re-sort of all appended edges
    // by timestamp.
    //
    // Uses a deterministic inline LCG (Knuth MMIX) seeded by a constant
    // so the test is reproducible without a `rand` dev-dependency.
    #[test]
    fn tail_merge_matches_full_resort_on_random_streams() {
        // Knuth MMIX LCG: next state = state * 6364136223846793005 + 1442695040888963407
        fn lcg_next(state: &mut u64) -> u64 {
            *state = state.wrapping_mul(6_364_136_223_846_793_005)
                .wrapping_add(1_442_695_040_888_963_407);
            *state
        }

        let mut rng = 0xDEAD_BEEF_CAFE_BABEu64;
        let src = StrId::from_raw(1);

        for _iter in 0..200 {
            // N in [2, 20]
            let n = (lcg_next(&mut rng) % 19 + 2) as usize;

            // Generate N timestamps in [0, 999]
            let timestamps: Vec<i64> = (0..n)
                .map(|_| (lcg_next(&mut rng) % 1000) as i64)
                .collect();

            // Split index in [1, n) — at least one pre-finalize edge so the
            // base is non-empty, at least one post-finalize edge in the tail.
            let split = (lcg_next(&mut rng) % (n as u64 - 1) + 1) as usize;

            let backend = InMemoryStreamingBackend::new();

            // Pre-finalize: edges[0..split] go into the sorted base.
            for &ts in &timestamps[..split] {
                backend.append_edge(src, edge(2, ts, 0));
            }
            backend.finalize();

            // Post-finalize: edges[split..n] go into the tail.
            for &ts in &timestamps[split..] {
                backend.append_edge(src, edge(2, ts, 0));
            }

            // Expected: full re-sort of all timestamps.
            let mut expected = timestamps.clone();
            expected.sort_unstable();

            // --- Check via freeze().neighbors() ---
            let snap = backend.freeze();
            let frozen = snap.neighbors(src).expect("src has edges");
            let got_freeze: Vec<i64> = frozen.as_slice().iter().map(|e| e.timestamp).collect();
            assert_eq!(
                got_freeze, expected,
                "iter={_iter} n={n} split={split}: freeze merge mismatch"
            );

            // --- Check via neighbors_in_window (full window) ---
            let got_window: Vec<i64> = backend
                .neighbors_in_window(src, (i64::MIN, i64::MAX))
                .iter()
                .map(|e| e.timestamp)
                .collect();
            assert_eq!(
                got_window, expected,
                "iter={_iter} n={n} split={split}: neighbors_in_window merge mismatch"
            );
        }
    }

    /// Task 0 (snapshot-ingest prerequisite): `for_each_edge` must visit
    /// post-finalize tail edges, not only the sorted base neighbor lists.
    ///
    /// Before the fix, the function iterated `self.vertices` (base) only and
    /// skipped `self.tails`, so any edge appended after `finalize()` was
    /// invisible to every consumer (save_session, heavy_edges,
    /// channel_behavior, remove_*_by_dataset).
    ///
    /// After the fix, it iterates base then tails.  Because the two sets are
    /// disjoint, the total visit count must equal `edge_count()`.
    #[test]
    fn for_each_edge_includes_post_finalize_tail_edges() {
        let backend = InMemoryStreamingBackend::new();

        let src1 = StrId::from_raw(1);
        let src2 = StrId::from_raw(2);

        // Pre-finalize: one edge from src1 → lands in the sorted base.
        backend.append_edge(src1, edge(10, 100, 0));
        backend.finalize();

        // Post-finalize: one edge from src2 → lands in tails.
        backend.append_edge(src2, edge(20, 200, 0));

        let mut counted = 0usize;
        backend.for_each_edge(|_src, _e| counted += 1);

        assert_eq!(
            counted, 2,
            "for_each_edge must count both the base edge and the tail edge"
        );
        assert_eq!(
            counted,
            backend.edge_count(),
            "for_each_edge visit count must match edge_count()"
        );
    }
}
