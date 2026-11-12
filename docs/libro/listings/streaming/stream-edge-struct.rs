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
