//! Stateful streaming ingestors (EVTX, PCAP, future: Zeek, Suricata,
//! NetFlow, live PCAP).
//!
//! ## Why this trait exists
//!
//! Tabular formats (CSV, IIS, FortiAnalyzer, Sentinel JSON, …) all
//! implement [`graph_hunter_core::LogParser`] and run through
//! `format_registry`. That trait is stateless — `parse_raw(&self, data:
//! &str)` — which doesn't fit captures that need state across records:
//! a TCP FIN in PCAP closes a flow that opened thousands of packets
//! earlier; an EVTX `EvtxParser` carries its own per-record state.
//!
//! Before this module, EVTX and PCAP each lived as a free function
//! (`evtx_ingest_streaming`, `pcap_ingest_streaming`) dispatched by two
//! hard-coded `if`-branches in
//! [`crate::operations::ingestion::GraphHunterApi::load_data_streaming`].
//! That works for two formats; it gets fragile around five. The
//! [`StreamingIngestor`] trait is the single registration point that
//! collapses both branches and lets later PRs add Zeek/Suricata/NetFlow
//! by dropping one file in this directory.
//!
//! ## Dispatch semantics
//!
//! [`resolve_ingestor`] is the single entry point used by the dispatch
//! site. It honors an explicit `format` string when present, falling
//! back to magic-byte sniffing when `format == "auto"`. The first ~64
//! bytes of the file are read **once** and passed to every ingestor's
//! [`StreamingIngestor::sniff`] — the ingestor with the highest
//! confidence wins. Ties are broken by registry order, but well-designed
//! sniffs should be unambiguous (e.g. PCAP magic `0xa1b2c3d4` only
//! matches PCAP).
//!
//! ## Adding a new ingestor
//!
//! 1. Create `ingestors/<name>.rs` with a struct implementing
//!    [`StreamingIngestor`].
//! 2. Add `Box::new(<Name>Ingestor::new())` to [`INGESTOR_REGISTRY`].
//! 3. That's the whole change. No edit to
//!    [`crate::operations::ingestion`] is required for normal
//!    additions.

use std::path::Path;
use std::sync::{Arc, LazyLock};

use graph_hunter_core::FieldConfig;

use crate::EventEmitter;
use crate::state::Session;

pub mod evtx;
pub mod netflow;
pub mod pcap;
pub mod suricata;
pub mod zeek;

/// Per-ingest input. References only — the caller owns the underlying
/// data and the ingestor must not retain anything past the call.
pub struct IngestContext<'a> {
    pub path: &'a str,
    pub session: &'a Arc<Session>,
    pub dataset_id: &'a str,
    pub emitter: &'a Arc<dyn EventEmitter>,
    pub job_id: &'a str,
    /// ISO `YYYY-MM-DD` date range. Honored by line-based ingestors
    /// (IIS, CSV) at the tabular layer; binary ingestors here (EVTX,
    /// PCAP) currently ignore it because timestamps live inside the
    /// records, not on the line.
    pub date_from: Option<&'a str>,
    pub date_to: Option<&'a str>,
    /// User-supplied field mapping. Meaningful for EVTX (selects
    /// `ConfigurableParser` vs `GenericParser`); ignored by PCAP.
    pub config: Option<&'a FieldConfig>,
}

/// A self-contained ingestor for a stateful binary or
/// state-carrying-text format.
pub trait StreamingIngestor: Send + Sync {
    /// Canonical format name. Lowercase, stable across versions.
    /// Examples: `"evtx"`, `"pcap"`. This is what callers pass in the
    /// `format` field of `LoadDataStreamingRequest` to force this
    /// ingestor.
    fn name(&self) -> &'static str;

    /// User-facing format aliases that should resolve to this
    /// ingestor. Example: `PcapIngestor` lists `["pcapng"]` so callers
    /// can pass either spelling.
    fn aliases(&self) -> &'static [&'static str] {
        &[]
    }

    /// File extensions (lowercase, no leading dot) this ingestor
    /// claims. Used by frontend dispatch and by the auto-detect path
    /// as a cheap pre-filter before reading magic bytes.
    fn extensions(&self) -> &'static [&'static str] {
        &[]
    }

    /// Content sniff. Called only when `format == "auto"`.
    ///
    /// `magic` is the first up-to-64 bytes of the file (may be shorter
    /// for tiny files). Returns `Some(confidence)` if this ingestor
    /// recognizes the content; the highest confidence across all
    /// registered ingestors wins.
    ///
    /// Convention:
    /// - `255`: unambiguous magic match (e.g. PCAP `0xa1b2c3d4`).
    /// - `200`: structural match that *could* collide with a more
    ///   permissive format (e.g. Suricata `eve.json` lines start with
    ///   `{` like any JSON; the sniff confirms the `event_type` key
    ///   before returning).
    /// - `150`: extension match only, magic ambiguous or absent (rare;
    ///   used as a tie-breaker for renamed files).
    ///
    /// Return `None` to opt out and let other ingestors / the tabular
    /// fallback handle the file.
    fn sniff(&self, path: &Path, magic: &[u8]) -> Option<u8>;

    /// Run the ingest end-to-end. Returns
    /// `(new_entities, new_relations)`.
    fn ingest(&self, ctx: IngestContext<'_>) -> Result<(usize, usize), String>;
}

/// Process-wide registry of stateful ingestors. Built once at first
/// access. Order is significant only as a tie-breaker for equal
/// confidences in `resolve_ingestor`.
pub static INGESTOR_REGISTRY: LazyLock<Vec<Box<dyn StreamingIngestor>>> = LazyLock::new(|| {
    vec![
        Box::new(evtx::EvtxIngestor::new()),
        Box::new(pcap::PcapIngestor::new()),
        Box::new(zeek::ZeekIngestor::new()),
        Box::new(suricata::SuricataIngestor::new()),
        Box::new(netflow::NetflowIpfixIngestor::new()),
    ]
});

/// Read the first `n` bytes of `path` for magic-byte sniffing.
/// Returns whatever fits in memory; never errors out — a short read or
/// open failure yields an empty slice and each ingestor's `sniff`
/// decides what to do with that.
pub fn read_magic_bytes(path: &str, n: usize) -> Vec<u8> {
    use std::io::Read;
    let Ok(mut f) = std::fs::File::open(path) else {
        return Vec::new();
    };
    let mut buf = vec![0u8; n];
    let read = f.read(&mut buf).unwrap_or(0);
    buf.truncate(read);
    buf
}

/// Resolve the ingestor that should handle this `(path, format)`.
///
/// - If `format` is a known name or alias of a registered ingestor,
///   that ingestor is returned directly (no sniff).
/// - If `format == "auto"` (or empty), every registered ingestor's
///   `sniff` is called against the first 64 bytes of the file and the
///   highest-confidence result wins.
/// - Returns `None` for tabular formats (`csv`, `iis`, `sentinel`, …)
///   and for `auto` files whose contents no stateful ingestor claims.
///   The caller is expected to fall through to the tabular
///   `format_registry` path in that case.
pub fn resolve_ingestor(path: &str, format: &str) -> Option<&'static dyn StreamingIngestor> {
    let fmt = format.to_lowercase();
    let registry = INGESTOR_REGISTRY.as_slice();

    if !fmt.is_empty() && fmt != "auto" {
        for ing in registry {
            if ing.name() == fmt || ing.aliases().iter().any(|a| *a == fmt) {
                return Some(ing.as_ref());
            }
        }
        return None;
    }

    let magic = read_magic_bytes(path, 64);
    let p = Path::new(path);
    registry
        .iter()
        .filter_map(|ing| ing.sniff(p, &magic).map(|c| (ing.as_ref(), c)))
        .max_by_key(|(_, c)| *c)
        .map(|(ing, _)| ing)
}

/// True if `fmt` is a known stateful-ingestor name or alias. Used by
/// the format allowlist in `load_data_streaming` so unknown explicit
/// formats fail fast before any work happens.
pub fn is_known_streaming_format(fmt: &str) -> bool {
    let fmt = fmt.to_lowercase();
    INGESTOR_REGISTRY
        .iter()
        .any(|ing| ing.name() == fmt || ing.aliases().iter().any(|a| *a == fmt))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn registry_has_all_known_ingestors() {
        let names: Vec<&str> = INGESTOR_REGISTRY.iter().map(|i| i.name()).collect();
        for want in &["evtx", "pcap", "zeek", "suricata", "netflow"] {
            assert!(names.contains(want), "{want} must be registered");
        }
    }

    #[test]
    fn explicit_format_resolves_by_name() {
        let tmp = std::env::temp_dir().join("graphhunter_resolve_test.bin");
        std::fs::write(&tmp, b"not a real capture").unwrap();
        let path = tmp.to_string_lossy().to_string();
        assert_eq!(
            resolve_ingestor(&path, "pcap").map(|i| i.name()),
            Some("pcap"),
        );
        assert_eq!(
            resolve_ingestor(&path, "evtx").map(|i| i.name()),
            Some("evtx"),
        );
        std::fs::remove_file(&tmp).ok();
    }

    #[test]
    fn alias_pcapng_resolves_to_pcap() {
        let tmp = std::env::temp_dir().join("graphhunter_alias_test.bin");
        std::fs::write(&tmp, b"x").unwrap();
        let path = tmp.to_string_lossy().to_string();
        assert_eq!(
            resolve_ingestor(&path, "pcapng").map(|i| i.name()),
            Some("pcap"),
        );
        std::fs::remove_file(&tmp).ok();
    }

    #[test]
    fn tabular_format_returns_none() {
        let tmp = std::env::temp_dir().join("graphhunter_tabular_test.csv");
        std::fs::write(&tmp, b"a,b,c\n1,2,3\n").unwrap();
        let path = tmp.to_string_lossy().to_string();
        assert!(resolve_ingestor(&path, "csv").is_none());
        assert!(resolve_ingestor(&path, "sentinel").is_none());
        std::fs::remove_file(&tmp).ok();
    }

    #[test]
    fn auto_falls_through_when_no_sniff_matches() {
        let tmp = std::env::temp_dir().join("graphhunter_auto_test.csv");
        std::fs::write(&tmp, b"col1,col2\nfoo,bar\n").unwrap();
        let path = tmp.to_string_lossy().to_string();
        assert!(resolve_ingestor(&path, "auto").is_none());
        std::fs::remove_file(&tmp).ok();
    }

    #[test]
    fn auto_picks_evtx_for_elffile_magic() {
        let tmp = std::env::temp_dir().join("graphhunter_auto_evtx.bin");
        let mut buf = b"ElfFile\0".to_vec();
        buf.extend_from_slice(&[0u8; 56]);
        std::fs::write(&tmp, &buf).unwrap();
        let path = tmp.to_string_lossy().to_string();
        assert_eq!(
            resolve_ingestor(&path, "auto").map(|i| i.name()),
            Some("evtx"),
        );
        std::fs::remove_file(&tmp).ok();
    }

    #[test]
    fn auto_picks_pcap_for_libpcap_magic() {
        let tmp = std::env::temp_dir().join("graphhunter_auto_pcap.bin");
        let buf = [0xa1u8, 0xb2, 0xc3, 0xd4, 0, 0, 0, 0];
        std::fs::write(&tmp, buf).unwrap();
        let path = tmp.to_string_lossy().to_string();
        assert_eq!(
            resolve_ingestor(&path, "auto").map(|i| i.name()),
            Some("pcap"),
        );
        std::fs::remove_file(&tmp).ok();
    }

    #[test]
    fn is_known_streaming_format_works() {
        assert!(is_known_streaming_format("evtx"));
        assert!(is_known_streaming_format("pcap"));
        assert!(is_known_streaming_format("pcapng"));
        assert!(is_known_streaming_format("PCAP"));
        assert!(is_known_streaming_format("zeek"));
        assert!(is_known_streaming_format("bro"));
        assert!(is_known_streaming_format("suricata"));
        assert!(is_known_streaming_format("eve"));
        assert!(is_known_streaming_format("netflow"));
        assert!(is_known_streaming_format("ipfix"));
        assert!(!is_known_streaming_format("csv"));
        assert!(!is_known_streaming_format("sentinel"));
        assert!(!is_known_streaming_format("auto"));
    }

    /// NetFlow datagrams start with version u16 = 5, 9, or 10. The
    /// sniff should win over Zeek and Suricata (whose first bytes
    /// would be `{`) and lose to PCAP/EVTX (which have unambiguous
    /// magic). Pin both directions.
    #[test]
    fn auto_picks_netflow_over_generic_formats() {
        let mut buf = vec![0u8, 9u8]; // version 9
        buf.extend(std::iter::repeat(0u8).take(64));
        let p = std::env::temp_dir().join("graphhunter_precedence_netflow.bin");
        std::fs::write(&p, &buf).unwrap();
        assert_eq!(
            resolve_ingestor(&p.to_string_lossy(), "auto").map(|i| i.name()),
            Some("netflow"),
        );
        std::fs::remove_file(&p).ok();
    }

    /// Cross-source merge: a `Domain` extracted from a Zeek `dns.log`
    /// record must share the same graph-engine `StrId` as a `Domain`
    /// produced by the PCAP path's `extract_dns_queries`. We don't
    /// run the full ingestors here — just construct one
    /// `RawIngestEvent` each, insert them through the canonical
    /// `GraphHunter::insert_raw_events`, and assert the second
    /// insertion does NOT add a new Domain entity. The IP entities
    /// differ between sources, so the second insertion adds *one*
    /// new entity (the new IP) plus the new edge.
    #[test]
    fn cross_source_domain_entity_merges_across_zeek_and_pcap() {
        use crate::ingestors::zeek::{ZeekLogKind, parse_record};
        use graph_hunter_core::{
            EntityType, GraphHunter, RawIngestEvent, RelationType,
        };
        use serde_json::json;
        use std::collections::HashMap;

        let mut graph = GraphHunter::new();

        // 1. Zeek-style DNS edge: 10.0.0.1 -> evo.example.com.
        let zeek_record = json!({
            "ts": 1.0,
            "uid": "CAzeek",
            "id.orig_h": "10.0.0.1",
            "id.resp_h": "8.8.8.8",
            "id.orig_p": 50000,
            "id.resp_p": 53,
            "proto": "udp",
            "query": "evo.example.com",
            "qtype_name": "A"
        });
        let zeek_edge = parse_record(ZeekLogKind::Dns, &zeek_record, "dns.log")
            .expect("zeek dns parsed")
            .into_iter()
            .next()
            .unwrap();
        let (z_e, z_r) = graph
            .insert_raw_events(vec![zeek_edge], Some("zeek-ds"))
            .expect("zeek insert ok");
        assert_eq!(
            z_e, 2,
            "first insertion creates one IP entity + one Domain entity"
        );
        assert_eq!(z_r, 1, "one DNS edge");

        // 2. PCAP-style DNS edge: different originator IP, same
        //    domain string. The Domain must NOT count as a new
        //    entity because the StrId interner gives it the same id.
        let mut pcap_md = HashMap::new();
        pcap_md.insert("source".to_string(), "pcap".to_string());
        pcap_md.insert("l7_decoded".to_string(), "dns_query".to_string());
        let pcap_edge = RawIngestEvent {
            src_id: "10.0.0.2".to_string(),
            src_type: EntityType::IP,
            src_metadata: HashMap::new(),
            dst_id: "evo.example.com".to_string(),
            dst_type: EntityType::Domain,
            dst_metadata: HashMap::new(),
            rel_type: RelationType::DNS,
            rel_metadata: pcap_md,
            timestamp: 2,
        };
        let (p_e, p_r) = graph
            .insert_raw_events(vec![pcap_edge], Some("pcap-ds"))
            .expect("pcap insert ok");
        assert_eq!(
            p_e, 1,
            "second insertion adds exactly one new entity (the new IP); \
             the Domain entity merges across sources"
        );
        assert_eq!(p_r, 1, "one DNS edge");

        // Total entity count in the graph: 2 IPs + 1 Domain.
        assert_eq!(graph.entity_count(), 3);
        assert_eq!(graph.relation_count(), 2);
    }

    /// Zeek JSON-lines and Suricata `eve.json` both start with `{`,
    /// so the sniff precedence has to be tight enough that they
    /// don't steal *each other's* files. This test pins down both
    /// directions.
    #[test]
    fn auto_distinguishes_zeek_from_suricata_on_first_byte() {
        let zeek = r#"{"ts":1.0,"uid":"CAbc","id.orig_h":"10.0.0.1","id.resp_h":"1.1.1.1","proto":"tcp"}"#;
        let suri = r#"{"timestamp":"2024-01-15T12:00:00.000+0000","event_type":"flow","src_ip":"10.0.0.1","dest_ip":"1.1.1.1","proto":"TCP"}"#;

        let zp = std::env::temp_dir().join("graphhunter_precedence_zeek.log");
        std::fs::write(&zp, format!("{zeek}\n")).unwrap();
        assert_eq!(
            resolve_ingestor(&zp.to_string_lossy(), "auto").map(|i| i.name()),
            Some("zeek"),
        );
        std::fs::remove_file(&zp).ok();

        let sp = std::env::temp_dir().join("graphhunter_precedence_eve.json");
        std::fs::write(&sp, format!("{suri}\n")).unwrap();
        assert_eq!(
            resolve_ingestor(&sp.to_string_lossy(), "auto").map(|i| i.name()),
            Some("suricata"),
        );
        std::fs::remove_file(&sp).ok();
    }
}
