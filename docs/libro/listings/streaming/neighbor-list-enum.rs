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
