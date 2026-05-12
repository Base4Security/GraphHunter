//! NetFlow v5 / v9 / IPFIX ingestor.
//!
//! Reads a binary file of concatenated NetFlow datagrams (raw
//! UDP-dump form), parses each via [`crate::netflow::parse_packet`],
//! and emits one `IP -[Connect]-> IP` edge per flow record. Templates
//! carried in v9/IPFIX Template FlowSets persist across packets in
//! the same observation domain for the duration of the ingest.
//!
//! **Trust the sensor**: one record = one edge. Records that
//! describe the same conversation in opposite directions land as
//! two parallel edges — that's how the exporter saw them and we
//! don't second-guess. Same policy as the Zeek / Suricata
//! ingestors in PR2.
//!
//! ## File format
//!
//! Concatenated raw NetFlow datagrams. The first two bytes are
//! always the wire version (`5`, `9`, or `10` big-endian) so the
//! sniff is unambiguous. nfdump's proprietary `.nfcapd` format
//! (per-block headers + extension records) is out of scope —
//! convert with `nfdump -E` or similar first.

use std::collections::HashMap;
use std::path::Path;

use graph_hunter_core::{EntityType, RawIngestEvent, RelationType};

use super::{IngestContext, StreamingIngestor};
use crate::ingestors::zeek::{emit_progress, flush};
use crate::netflow::{NetflowRecord, NetflowVersion, TemplateCache, detect_version, parse_packet};

const BATCH_FLUSH_SIZE: usize = 5_000;
const PROGRESS_EVERY_N_RECORDS: u64 = 5_000;
/// Cap on how much of the file we read into memory at once. NetFlow
/// captures rotate every few minutes, so individual files are
/// typically < 100 MB. 512 MB is a generous safety ceiling.
const MAX_FILE_BYTES: usize = 512 * 1024 * 1024;

pub struct NetflowIpfixIngestor;

impl NetflowIpfixIngestor {
    pub fn new() -> Self {
        Self
    }
}

impl Default for NetflowIpfixIngestor {
    fn default() -> Self {
        Self::new()
    }
}

impl StreamingIngestor for NetflowIpfixIngestor {
    fn name(&self) -> &'static str {
        "netflow"
    }

    fn aliases(&self) -> &'static [&'static str] {
        &["ipfix", "netflow_v5", "netflow_v9"]
    }

    /// `.nf` / `.nflow` aren't real conventions on disk so we don't
    /// claim any file extension — content sniff is the only path.
    fn extensions(&self) -> &'static [&'static str] {
        &[]
    }

    /// Confidence `240`: the first `u16` is one of three exact
    /// values (5/9/10). The window of collision with other formats
    /// is tiny (a TIFF file would start with `0x4949` or `0x4D4D`, a
    /// PNG with `0x8950`, etc.), so this is a near-magic sniff but
    /// not the explicit 4-byte magic of PCAP.
    fn sniff(&self, _path: &Path, magic: &[u8]) -> Option<u8> {
        if detect_version(magic).is_some() {
            Some(240)
        } else {
            None
        }
    }

    fn ingest(&self, ctx: IngestContext<'_>) -> Result<(usize, usize), String> {
        let data = read_capture_file(ctx.path)?;
        let bytes_total = data.len() as u64;
        let source_file = Path::new(ctx.path)
            .file_name()
            .and_then(|s| s.to_str())
            .unwrap_or("")
            .to_string();

        let mut cache = TemplateCache::new();
        let mut total_new_entities = 0usize;
        let mut total_new_relations = 0usize;
        let mut pending: Vec<RawIngestEvent> = Vec::with_capacity(BATCH_FLUSH_SIZE);
        let mut records_seen = 0u64;
        let mut packets_seen = 0u64;
        let mut pos = 0usize;

        while pos < data.len() {
            let (records, consumed) = match parse_packet(&data[pos..], &mut cache) {
                Some(v) => v,
                None => {
                    // Skip one byte and try to resync. Real captures
                    // sometimes have a stray padding byte between
                    // datagrams. If a full resync fails the loop
                    // will hit EOF and terminate cleanly.
                    pos += 1;
                    continue;
                }
            };
            pos += consumed;
            packets_seen += 1;
            for r in records {
                if let Some(ev) = record_to_event(&r, &source_file) {
                    pending.push(ev);
                    records_seen += 1;
                }
            }
            if pending.len() >= BATCH_FLUSH_SIZE {
                flush(
                    &mut pending,
                    ctx.session,
                    ctx.dataset_id,
                    &mut total_new_entities,
                    &mut total_new_relations,
                )?;
            }
            if records_seen > 0 && records_seen.is_multiple_of(PROGRESS_EVERY_N_RECORDS) {
                emit_progress(
                    ctx.emitter,
                    pos as u64,
                    bytes_total,
                    total_new_entities,
                    total_new_relations,
                );
            }
        }
        if !pending.is_empty() {
            flush(
                &mut pending,
                ctx.session,
                ctx.dataset_id,
                &mut total_new_entities,
                &mut total_new_relations,
            )?;
        }
        tracing::info!(
            "netflow ingest: packets={} records={} entities={} relations={}",
            packets_seen,
            records_seen,
            total_new_entities,
            total_new_relations,
        );
        Ok((total_new_entities, total_new_relations))
    }
}

fn read_capture_file(path: &str) -> Result<Vec<u8>, String> {
    use std::io::Read;
    let mut f = std::fs::File::open(path)
        .map_err(|e| format!("Failed to open NetFlow file '{path}': {e}"))?;
    let size = f.metadata().map(|m| m.len() as usize).unwrap_or(0);
    if size > MAX_FILE_BYTES {
        return Err(format!(
            "NetFlow file '{path}' is {size} bytes — over the {MAX_FILE_BYTES}-byte cap. \
             Split the capture with `nfdump -B -t <window> -w out` and ingest each piece."
        ));
    }
    let mut buf = Vec::with_capacity(size);
    f.read_to_end(&mut buf)
        .map_err(|e| format!("Read failed on '{path}': {e}"))?;
    Ok(buf)
}

/// Map a normalised [`NetflowRecord`] to one `IP -[Connect]-> IP`
/// graph edge with full sensor-trust metadata.
pub(crate) fn record_to_event(r: &NetflowRecord, source_file: &str) -> Option<RawIngestEvent> {
    if r.src_ip.is_empty() || r.dst_ip.is_empty() {
        return None;
    }
    let mut md: HashMap<String, String> = HashMap::with_capacity(20);
    md.insert("source".to_string(), source_string(r.version).to_string());
    if !source_file.is_empty() {
        md.insert("source_file".to_string(), source_file.to_string());
    }
    md.insert(
        "sensor_uid".to_string(),
        format!("{}:{}", r.exporter_domain_id, r.sequence),
    );
    md.insert("exporter_domain_id".to_string(), r.exporter_domain_id.to_string());
    md.insert("flow_sequence".to_string(), r.sequence.to_string());
    md.insert(
        "netflow_version".to_string(),
        netflow_version_str(r.version).to_string(),
    );
    md.insert("protocol".to_string(), proto_name(r.protocol).to_string());
    md.insert("protocol_num".to_string(), r.protocol.to_string());
    if r.src_port != 0 {
        md.insert("src_port".to_string(), r.src_port.to_string());
    }
    if r.dst_port != 0 {
        md.insert("dst_port".to_string(), r.dst_port.to_string());
    }
    md.insert("bytes_fwd".to_string(), r.bytes.to_string());
    md.insert("packets_fwd".to_string(), r.packets.to_string());
    if r.duration_ms > 0 {
        md.insert("duration_ms".to_string(), r.duration_ms.to_string());
    }
    if r.tcp_flags != 0 && r.protocol == 6 {
        md.insert("tcp_flags".to_string(), tcp_flags_str(r.tcp_flags));
    }
    Some(RawIngestEvent {
        src_id: r.src_ip.clone(),
        src_type: EntityType::IP,
        src_metadata: HashMap::new(),
        dst_id: r.dst_ip.clone(),
        dst_type: EntityType::IP,
        dst_metadata: HashMap::new(),
        rel_type: RelationType::Connect,
        rel_metadata: md,
        timestamp: r.start_secs,
    })
}

fn source_string(v: NetflowVersion) -> &'static str {
    match v {
        NetflowVersion::V5 => "netflow_v5",
        NetflowVersion::V9 => "netflow_v9",
        NetflowVersion::Ipfix => "ipfix",
    }
}

fn netflow_version_str(v: NetflowVersion) -> &'static str {
    match v {
        NetflowVersion::V5 => "5",
        NetflowVersion::V9 => "9",
        NetflowVersion::Ipfix => "10",
    }
}

fn proto_name(p: u8) -> &'static str {
    match p {
        1 => "ICMP",
        2 => "IGMP",
        6 => "TCP",
        17 => "UDP",
        47 => "GRE",
        50 => "ESP",
        51 => "AH",
        58 => "ICMPv6",
        132 => "SCTP",
        _ => "Other",
    }
}

fn tcp_flags_str(flags: u8) -> String {
    let mut parts: Vec<&str> = Vec::new();
    if flags & 0x01 != 0 { parts.push("FIN"); }
    if flags & 0x02 != 0 { parts.push("SYN"); }
    if flags & 0x04 != 0 { parts.push("RST"); }
    if flags & 0x08 != 0 { parts.push("PSH"); }
    if flags & 0x10 != 0 { parts.push("ACK"); }
    if flags & 0x20 != 0 { parts.push("URG"); }
    parts.join(",")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::netflow::NetflowVersion;

    fn sample_record(version: NetflowVersion) -> NetflowRecord {
        NetflowRecord {
            src_ip: "10.0.0.1".to_string(),
            dst_ip: "1.1.1.1".to_string(),
            src_port: 54321,
            dst_port: 443,
            protocol: 6,
            bytes: 1500,
            packets: 42,
            tcp_flags: 0x18,
            start_secs: 1_700_000_000,
            duration_ms: 1234,
            exporter_domain_id: 7,
            sequence: 100,
            version,
        }
    }

    #[test]
    fn record_to_event_populates_full_metadata() {
        let r = sample_record(NetflowVersion::V9);
        let ev = record_to_event(&r, "test.bin").expect("event");
        assert_eq!(ev.src_id, "10.0.0.1");
        assert_eq!(ev.dst_id, "1.1.1.1");
        assert_eq!(ev.src_type, EntityType::IP);
        assert_eq!(ev.dst_type, EntityType::IP);
        assert_eq!(ev.rel_type, RelationType::Connect);
        assert_eq!(ev.timestamp, 1_700_000_000);
        let m = &ev.rel_metadata;
        assert_eq!(m.get("source").map(String::as_str), Some("netflow_v9"));
        assert_eq!(m.get("sensor_uid").map(String::as_str), Some("7:100"));
        assert_eq!(m.get("netflow_version").map(String::as_str), Some("9"));
        assert_eq!(m.get("protocol").map(String::as_str), Some("TCP"));
        assert_eq!(m.get("src_port").map(String::as_str), Some("54321"));
        assert_eq!(m.get("dst_port").map(String::as_str), Some("443"));
        assert_eq!(m.get("bytes_fwd").map(String::as_str), Some("1500"));
        assert_eq!(m.get("packets_fwd").map(String::as_str), Some("42"));
        assert_eq!(m.get("duration_ms").map(String::as_str), Some("1234"));
        // 0x18 = PSH (0x08) + ACK (0x10).
        assert_eq!(m.get("tcp_flags").map(String::as_str), Some("PSH,ACK"));
    }

    #[test]
    fn record_to_event_omits_tcp_flags_for_udp() {
        let mut r = sample_record(NetflowVersion::V5);
        r.protocol = 17; // UDP
        r.tcp_flags = 0x18; // garbage — must NOT be surfaced for UDP
        let ev = record_to_event(&r, "").expect("event");
        assert!(!ev.rel_metadata.contains_key("tcp_flags"));
        assert_eq!(ev.rel_metadata.get("protocol").map(String::as_str), Some("UDP"));
    }

    #[test]
    fn record_to_event_skips_empty_ips() {
        let mut r = sample_record(NetflowVersion::Ipfix);
        r.src_ip.clear();
        assert!(record_to_event(&r, "").is_none());
    }

    #[test]
    fn sniff_matches_known_versions_only() {
        let ing = NetflowIpfixIngestor::new();
        let p = Path::new("anyfile");
        assert_eq!(ing.sniff(p, &[0, 5]), Some(240));
        assert_eq!(ing.sniff(p, &[0, 9]), Some(240));
        assert_eq!(ing.sniff(p, &[0, 10]), Some(240));
        assert_eq!(ing.sniff(p, &[0, 7]), None);
        assert_eq!(ing.sniff(p, &[]), None);
        // Common collision candidates — must not match.
        assert_eq!(ing.sniff(p, b"PK\x03\x04"), None); // ZIP
        assert_eq!(ing.sniff(p, &[0xa1, 0xb2, 0xc3, 0xd4]), None); // PCAP magic
    }
}
