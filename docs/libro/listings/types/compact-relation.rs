/// Memory-efficient edge representation for the adjacency list.
///
/// **Layout note (2026-04-07 repack):** the previous field order was
/// [source_sid, dest_sid, rel_type_tag, timestamp, metadata_offset, dataset_tag]
/// which under `#[repr(C)]` produced 40 bytes due to padding before `timestamp`
/// (i64 alignment) and after `dataset_tag` (struct alignment to 8). Reordering
/// from largest to smallest alignment compacts inline data to 27 bytes plus
/// 5 bytes of trailing struct-alignment padding → **32 bytes** total.
///
/// **MVCC note (P3):** the 5 bytes of trailing padding were free real
/// estate. `ingested_at_delta: u32` reclaims 4 of them; the struct
/// stays at 32 bytes. The delta is stored against
/// [`INGEST_EPOCH_BASE`] (2024-01-01 UTC); `fn ingested_at()` adds it
/// back. Range covers ~136 years from the epoch base — well beyond
/// any realistic retention window. `Default` produces `0`, which
/// resolves to the epoch itself; legacy loaders that don't populate
/// the field surface as "ingested at 2024-01-01" rather than NaN.
///
/// This is a 20% saving over the previous 40-byte layout (~1.6 GB on a
/// 28 GB EVTX with ~200M relations). Going further to 27 bytes requires
/// `#[repr(C, packed)]`, which complicates field references and is deferred.
///
/// Compared to the full `Relation` struct (~200 B), this is still ~84% smaller.
/// Metadata is stored externally in `MetadataStore`, referenced by offset.
#[derive(Clone, Copy, Debug)]
#[repr(C)]
pub struct CompactRelation {
    pub timestamp: i64,       // 8 bytes (align 8) — placed first to avoid pre-padding
    pub metadata_offset: u64, // 8 bytes (0 = no metadata)
    pub source_sid: StrId,    // 4 bytes
    pub dest_sid: StrId,      // 4 bytes
    /// Seconds since [`INGEST_EPOCH_BASE`] — the moment this edge was
    /// written to the graph, independent of the event's own
    /// [`timestamp`]. Used by the P3 MVCC snapshot API to answer
    /// "what did the graph know at time T".
    pub ingested_at_delta: u32, // 4 bytes
    pub dataset_tag: u16,     // 2 bytes (index into dataset_tags vec, 0 = none)
    pub rel_type_tag: u8,     // 1 byte
                              // 31 bytes inline + 1 byte trailing struct-alignment padding (mult. of 8) = 32 B.
}
