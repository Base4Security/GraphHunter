//! PCAP / PCAPNG offline ingestor.
//!
//! Wraps [`crate::pcap::pcap_ingest_streaming`] behind the
//! [`StreamingIngestor`] trait. Zero behavior change vs. the
//! pre-refactor `if`-branch in `load_data_streaming` — same flow
//! aggregator (256K-flow cap, NetFlow-default idle timeouts, FIN/RST
//! immediate emit), same L7 decoders (TLS SNI, DNS, HTTP Host), same
//! batch flush.

use std::path::Path;

use super::{IngestContext, StreamingIngestor};
use crate::pcap::pcap_ingest_streaming;
use crate::pcap_preview::{file_looks_like_pcap, path_is_pcap};

pub struct PcapIngestor;

impl PcapIngestor {
    pub fn new() -> Self {
        Self
    }
}

impl Default for PcapIngestor {
    fn default() -> Self {
        Self::new()
    }
}

impl StreamingIngestor for PcapIngestor {
    fn name(&self) -> &'static str {
        "pcap"
    }

    fn aliases(&self) -> &'static [&'static str] {
        &["pcapng"]
    }

    fn extensions(&self) -> &'static [&'static str] {
        &["pcap", "pcapng", "cap"]
    }

    /// Confidence scoring:
    /// - Magic match for libpcap or pcapng (`a1b2c3d4` / `a1b23c4d` /
    ///   `0a0d0d0a` byte sequences with the correct byte order): `255`.
    /// - Extension match (`.pcap` / `.pcapng` / `.cap`) with magic that
    ///   doesn't confirm: `150`. This catches captures whose magic
    ///   bytes are obscured by an enclosing wrapper (very rare; usually
    ///   the cap-file is fine and we just hit a short read).
    ///
    /// Magic-byte detection delegates to the canonical helpers in
    /// [`crate::pcap_preview`] so any future format-family additions
    /// (e.g. PCAPNG version bumps) only need updating in one place.
    fn sniff(&self, path: &Path, magic: &[u8]) -> Option<u8> {
        if Self::magic_matches_pcap(magic) {
            return Some(255);
        }
        let path_str = path.to_string_lossy();
        if path_is_pcap(&path_str) {
            // Extension match — try the on-disk helper which re-reads
            // the file (some edge cases: zero-byte stub files, files
            // where the OS returned a truncated read for the magic
            // buffer). Matches pre-refactor `file_looks_like_pcap`
            // semantics.
            if file_looks_like_pcap(&path_str) {
                return Some(255);
            }
            return Some(150);
        }
        None
    }

    fn ingest(&self, ctx: IngestContext<'_>) -> Result<(usize, usize), String> {
        pcap_ingest_streaming(
            ctx.path,
            ctx.session,
            ctx.dataset_id,
            ctx.emitter,
            ctx.job_id,
        )
    }
}

impl PcapIngestor {
    /// Inline copy of [`crate::pcap_preview::file_looks_like_pcap`]'s
    /// byte-level check so callers that already have the magic buffer
    /// don't pay a second `File::open` syscall.
    fn magic_matches_pcap(magic: &[u8]) -> bool {
        if magic.len() < 4 {
            return false;
        }
        let m = &magic[..4];
        // libpcap classic + nanosecond variants.
        m == [0xa1, 0xb2, 0xc3, 0xd4]
            || m == [0xd4, 0xc3, 0xb2, 0xa1]
            || m == [0xa1, 0xb2, 0x3c, 0x4d]
            || m == [0x4d, 0x3c, 0xb2, 0xa1]
            // PCAPNG Section Header Block magic.
            || m == [0x0a, 0x0d, 0x0d, 0x0a]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn magic_matches_known_pcap_signatures() {
        assert!(PcapIngestor::magic_matches_pcap(&[0xa1, 0xb2, 0xc3, 0xd4]));
        assert!(PcapIngestor::magic_matches_pcap(&[0xd4, 0xc3, 0xb2, 0xa1]));
        assert!(PcapIngestor::magic_matches_pcap(&[0xa1, 0xb2, 0x3c, 0x4d]));
        assert!(PcapIngestor::magic_matches_pcap(&[0x4d, 0x3c, 0xb2, 0xa1]));
        assert!(PcapIngestor::magic_matches_pcap(&[0x0a, 0x0d, 0x0d, 0x0a]));
    }

    #[test]
    fn magic_rejects_other_bytes() {
        assert!(!PcapIngestor::magic_matches_pcap(b"ElfFile\0"));
        assert!(!PcapIngestor::magic_matches_pcap(b"{\"event"));
        assert!(!PcapIngestor::magic_matches_pcap(&[]));
        assert!(!PcapIngestor::magic_matches_pcap(&[0xa1, 0xb2]));
    }
}
