/// Reference in-memory implementation backing the trait. Stage 1
/// uses a plain `RwLock<HashMap<StrId, Arc<RwLock<NeighborList>>>>`
/// — readers can snapshot a single vertex's neighbors without
/// blocking the global table, and writers serialize on the inner
/// lock per vertex. Stage 2 will swap in `dashmap` (or a
/// concurrent skiplist for the hub vertices) once the ingest
/// pipeline is wired through.
pub struct InMemoryStreamingBackend {
    vertices: RwLock<ahash::HashMap<StrId, Arc<RwLock<NeighborList>>>>,

    /// L3 D4 stage 2 — budget-triggered auto-spill. `None` keeps the
    /// backend in pure-RAM mode (default; matches the pre-stage-2
    /// behavior). When set, every `append_edge` past the threshold
    /// triggers `auto_spill()`, which writes a fresh sorted file
    /// and swaps every per-vertex slot to `NeighborList::Mmap`.
    spill_state: parking_lot::Mutex<Option<SpillState>>,
}
