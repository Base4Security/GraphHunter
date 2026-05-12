//! PCAP / PCAPNG offline preview helpers.
//!
//! Reads the first ~10K packets of a capture file and computes a
//! non-tabular summary (top src/dst IPs, top dst ports, protocol mix,
//! time span). PCAP files are binary and don't fit the row/header
//! preview model that backs [`crate::operations::ingestion::preview_ingest`],
//! so PCAP gets its own preview surface — a separate Tauri command and
//! MCP tool, dispatched by file extension in the UI.
//!
//! PR1 scope: preview only. The full streaming flow ingest path lives
//! in PR2 (`platform/api/src/pcap.rs`, mirroring `evtx_ingest_streaming`).

use std::collections::HashMap;
use std::fs::File;
use std::io::Read;

use serde::{Deserialize, Serialize};

/// How many packets to decode for the preview. Bounded so a multi-GB
/// capture still previews in well under a second.
pub const PREVIEW_MAX_PACKETS: usize = 10_000;

/// How many entries to surface in each top-N list.
pub const TOP_N: usize = 10;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PcapPreviewResult {
    /// "pcap" or "pcapng" — matches the magic-byte family on disk.
    pub format: String,
    pub file_size: u64,
    /// Packets actually decoded (≤ [`PREVIEW_MAX_PACKETS`]).
    pub packets_sampled: usize,
    /// Linear extrapolation from sampled bytes; rough — meant to give
    /// the analyst an order-of-magnitude estimate before commit.
    pub packet_count_estimate: u64,
    pub time_span: Option<TimeSpan>,
    pub protocol_mix: Vec<ProtocolCount>,
    pub top_src_ips: Vec<IpCount>,
    pub top_dst_ips: Vec<IpCount>,
    pub top_dst_ports: Vec<PortCount>,
    /// Soft warnings (truncated file, undecodable packets, etc.).
    /// Empty when nothing notable happened.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub warnings: Vec<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TimeSpan {
    pub first_unix_secs: i64,
    pub last_unix_secs: i64,
    pub duration_secs: i64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ProtocolCount {
    /// "TCP" | "UDP" | "ICMP" | "ICMPv6" | "Other".
    pub protocol: String,
    pub packets: u64,
    pub bytes: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct IpCount {
    pub ip: String,
    pub packets: u64,
    pub bytes: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PortCount {
    pub port: u16,
    /// "TCP" or "UDP".
    pub protocol: String,
    /// Resolved well-known service name (e.g. "HTTPS", "DNS") or
    /// `None` for ephemeral / unrecognized ports.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub service: Option<String>,
    pub packets: u64,
}

/// True when the path's extension is one of `.pcap`, `.pcapng`, `.cap`.
pub fn path_is_pcap(path: &str) -> bool {
    std::path::Path::new(path)
        .extension()
        .map(|e| {
            let lower = e.to_string_lossy().to_lowercase();
            matches!(lower.as_str(), "pcap" | "pcapng" | "cap")
        })
        .unwrap_or(false)
}

/// Cheap magic-byte sniff. Reads the first 4 bytes and checks against
/// the known PCAP/PCAPNG signatures:
///   * `a1 b2 c3 d4` — PCAP, big-endian, μs timestamps.
///   * `d4 c3 b2 a1` — PCAP, little-endian, μs timestamps.
///   * `a1 b2 3c 4d` — PCAP, big-endian, ns timestamps.
///   * `4d 3c b2 a1` — PCAP, little-endian, ns timestamps.
///   * `0a 0d 0d 0a` — PCAPNG Section Header Block.
pub fn file_looks_like_pcap(path: &str) -> bool {
    let Ok(mut f) = File::open(path) else {
        return false;
    };
    let mut buf = [0u8; 4];
    if f.read_exact(&mut buf).is_err() {
        return false;
    }
    matches!(
        buf,
        [0xa1, 0xb2, 0xc3, 0xd4]
            | [0xd4, 0xc3, 0xb2, 0xa1]
            | [0xa1, 0xb2, 0x3c, 0x4d]
            | [0x4d, 0x3c, 0xb2, 0xa1]
            | [0x0a, 0x0d, 0x0d, 0x0a]
    )
}

/// Format family by magic bytes. Returns `"pcap"`, `"pcapng"`, or
/// `"unknown"`. The unknown case still lets the caller emit a sane
/// preview shape, just with `format: "unknown"`.
pub fn pcap_format_name(path: &str) -> &'static str {
    let Ok(mut f) = File::open(path) else {
        return "unknown";
    };
    let mut buf = [0u8; 4];
    if f.read_exact(&mut buf).is_err() {
        return "unknown";
    }
    match buf {
        [0x0a, 0x0d, 0x0d, 0x0a] => "pcapng",
        [0xa1, 0xb2, 0xc3, 0xd4]
        | [0xd4, 0xc3, 0xb2, 0xa1]
        | [0xa1, 0xb2, 0x3c, 0x4d]
        | [0x4d, 0x3c, 0xb2, 0xa1] => "pcap",
        _ => "unknown",
    }
}

/// Read up to [`PREVIEW_MAX_PACKETS`] packets and summarize.
///
/// Never fails on per-packet decode errors — those become entries in
/// `warnings` and the rest of the file continues. The only hard error
/// is failing to open or stat the file at all.
pub fn pcap_preview_sample(path: &str) -> Result<PcapPreviewResult, String> {
    use pcap_parser::{PcapBlockOwned, PcapError, create_reader};

    let file_size = std::fs::metadata(path)
        .map(|m| m.len())
        .map_err(|e| format!("stat '{path}': {e}"))?;

    let format = pcap_format_name(path).to_string();

    let file = File::open(path).map_err(|e| format!("open '{path}': {e}"))?;
    let mut reader = create_reader(65_536, file)
        .map_err(|e| format!("pcap reader init: {e:?}"))?;

    let mut state = PreviewState::new();
    let mut warnings: Vec<String> = Vec::new();
    let mut total_pkt_bytes: u64 = 0;
    let mut undecodable: u64 = 0;
    // Per-interface ts_resol (PCAPNG only). Default = 6 (microseconds).
    let mut if_tsresol: Vec<u8> = Vec::new();
    // Legacy PCAP global timestamp resolution (microseconds vs nanoseconds).
    // Set when we see the LegacyHeader. Default = microseconds.
    let mut legacy_nanos = false;

    loop {
        if state.packets_sampled >= PREVIEW_MAX_PACKETS {
            break;
        }
        match reader.next() {
            Ok((offset, block)) => {
                match block {
                    PcapBlockOwned::LegacyHeader(hdr) => {
                        legacy_nanos = hdr.magic_number == 0xa1b2_3c4d
                            || hdr.magic_number == 0x4d3c_b2a1;
                    }
                    PcapBlockOwned::Legacy(pkt) => {
                        let ts_secs = pkt.ts_sec as i64;
                        // For legacy PCAP the second field is either μs
                        // or ns — disambiguated by the file magic.
                        let _sub = if legacy_nanos {
                            pkt.ts_usec as i64
                        } else {
                            (pkt.ts_usec as i64).saturating_mul(1_000)
                        };
                        state.observe(pkt.data, ts_secs);
                        total_pkt_bytes += pkt.origlen as u64;
                    }
                    PcapBlockOwned::NG(ng) => {
                        observe_ng_block(
                            &ng,
                            &mut state,
                            &mut if_tsresol,
                            &mut total_pkt_bytes,
                            &mut undecodable,
                        );
                    }
                }
                reader.consume(offset);
            }
            Err(PcapError::Eof) => break,
            Err(PcapError::Incomplete(_)) => {
                if reader.refill().is_err() {
                    break;
                }
            }
            Err(e) => {
                warnings.push(format!("parse error: {e:?}"));
                break;
            }
        }
    }

    if undecodable > 0 {
        warnings.push(format!(
            "{undecodable} packet(s) could not be decoded at L2-L4 (non-Ethernet linktype or truncated frame)"
        ));
    }

    let packet_count_estimate = if state.packets_sampled > 0 && total_pkt_bytes > 0 {
        let avg = (total_pkt_bytes / state.packets_sampled as u64).max(1);
        // Rough; assumes the rest of the file has similar density.
        // Won't be exact for PCAPNG (block overhead) but gives an order
        // of magnitude.
        file_size / avg
    } else {
        0
    };

    Ok(state.finalize(format, file_size, packet_count_estimate, warnings))
}

fn observe_ng_block(
    block: &pcap_parser::pcapng::Block<'_>,
    state: &mut PreviewState,
    if_tsresol: &mut Vec<u8>,
    total_pkt_bytes: &mut u64,
    undecodable: &mut u64,
) {
    use pcap_parser::pcapng::Block;

    match block {
        Block::SectionHeader(_) => {
            // A new section resets interface IDs.
            if_tsresol.clear();
        }
        Block::InterfaceDescription(idb) => {
            // if_tsresol option (code 9). Default 6 = microseconds.
            let resol = idb
                .options
                .iter()
                .find(|o| o.code == pcap_parser::pcapng::OptionCode::IfTsresol)
                .and_then(|o| o.value.first().copied())
                .unwrap_or(6);
            if_tsresol.push(resol);
        }
        Block::EnhancedPacket(epb) => {
            let resol = if_tsresol
                .get(epb.if_id as usize)
                .copied()
                .unwrap_or(6);
            let raw = ((epb.ts_high as u64) << 32) | (epb.ts_low as u64);
            let ts_secs = ng_raw_to_secs(raw, resol);
            if !state.observe(epb.data, ts_secs) {
                *undecodable += 1;
            }
            *total_pkt_bytes += epb.origlen as u64;
        }
        Block::SimplePacket(spb) => {
            // SimplePacket has no timestamp; pass 0 so it counts but
            // doesn't perturb the time span.
            if !state.observe(spb.data, 0) {
                *undecodable += 1;
            }
            *total_pkt_bytes += spb.origlen as u64;
        }
        _ => {
            // NameResolution, InterfaceStatistics, etc. — ignored.
        }
    }
}

/// PCAPNG `if_tsresol`:
///   high bit (`0x80`) set ⇒ 2^N units per second.
///   else                  ⇒ 10^N units per second.
fn ng_raw_to_secs(raw: u64, resol: u8) -> i64 {
    let exp = (resol & 0x7F) as u32;
    let units_per_sec: u128 = if (resol & 0x80) != 0 {
        1u128 << exp.min(63)
    } else {
        10u128.checked_pow(exp).unwrap_or(1_000_000)
    };
    (raw as u128 / units_per_sec.max(1)) as i64
}

struct PreviewState {
    packets_sampled: usize,
    first_ts: Option<i64>,
    last_ts: Option<i64>,
    proto_mix: HashMap<&'static str, (u64, u64)>,
    src_ips: HashMap<String, (u64, u64)>,
    dst_ips: HashMap<String, (u64, u64)>,
    dst_ports: HashMap<(u16, &'static str), u64>,
}

impl PreviewState {
    fn new() -> Self {
        Self {
            packets_sampled: 0,
            first_ts: None,
            last_ts: None,
            proto_mix: HashMap::new(),
            src_ips: HashMap::new(),
            dst_ips: HashMap::new(),
            dst_ports: HashMap::new(),
        }
    }

    /// Decode L2-L4 and update aggregates. Returns `false` when the
    /// frame couldn't be decoded (counts toward `undecodable`).
    fn observe(&mut self, data: &[u8], ts_secs: i64) -> bool {
        self.packets_sampled += 1;
        if ts_secs > 0 {
            self.first_ts = Some(self.first_ts.map_or(ts_secs, |t| t.min(ts_secs)));
            self.last_ts = Some(self.last_ts.map_or(ts_secs, |t| t.max(ts_secs)));
        }
        let bytes = data.len() as u64;
        let Ok(parsed) = etherparse::PacketHeaders::from_ethernet_slice(data) else {
            return false;
        };
        let (src_ip, dst_ip) = match parsed.net.as_ref() {
            Some(etherparse::NetHeaders::Ipv4(h, _)) => (
                fmt_ipv4(&h.source),
                fmt_ipv4(&h.destination),
            ),
            Some(etherparse::NetHeaders::Ipv6(h, _)) => (
                fmt_ipv6(&h.source),
                fmt_ipv6(&h.destination),
            ),
            _ => return false,
        };
        let entry = self.src_ips.entry(src_ip.clone()).or_insert((0, 0));
        entry.0 += 1;
        entry.1 += bytes;
        let entry = self.dst_ips.entry(dst_ip.clone()).or_insert((0, 0));
        entry.0 += 1;
        entry.1 += bytes;

        let (proto_name, dst_port_pair) = match parsed.transport.as_ref() {
            Some(etherparse::TransportHeader::Tcp(t)) => {
                ("TCP", Some((t.destination_port, "TCP" as &'static str)))
            }
            Some(etherparse::TransportHeader::Udp(u)) => {
                ("UDP", Some((u.destination_port, "UDP" as &'static str)))
            }
            Some(etherparse::TransportHeader::Icmpv4(_)) => ("ICMP", None),
            Some(etherparse::TransportHeader::Icmpv6(_)) => ("ICMPv6", None),
            _ => ("Other", None),
        };
        let pm = self.proto_mix.entry(proto_name).or_insert((0, 0));
        pm.0 += 1;
        pm.1 += bytes;
        if let Some(key) = dst_port_pair {
            *self.dst_ports.entry(key).or_insert(0) += 1;
        }
        true
    }

    fn finalize(
        self,
        format: String,
        file_size: u64,
        packet_count_estimate: u64,
        warnings: Vec<String>,
    ) -> PcapPreviewResult {
        let time_span = match (self.first_ts, self.last_ts) {
            (Some(f), Some(l)) => Some(TimeSpan {
                first_unix_secs: f,
                last_unix_secs: l,
                duration_secs: l.saturating_sub(f),
            }),
            _ => None,
        };
        let mut protocol_mix: Vec<ProtocolCount> = self
            .proto_mix
            .into_iter()
            .map(|(p, (pkts, bytes))| ProtocolCount {
                protocol: p.to_string(),
                packets: pkts,
                bytes,
            })
            .collect();
        protocol_mix.sort_by(|a, b| b.packets.cmp(&a.packets));

        let top_src_ips = topn_ip(self.src_ips);
        let top_dst_ips = topn_ip(self.dst_ips);

        let mut port_pairs: Vec<((u16, &'static str), u64)> = self.dst_ports.into_iter().collect();
        port_pairs.sort_by(|a, b| b.1.cmp(&a.1));
        let top_dst_ports: Vec<PortCount> = port_pairs
            .into_iter()
            .take(TOP_N)
            .map(|((port, proto), packets)| PortCount {
                port,
                protocol: proto.to_string(),
                service: port_to_service_name(port, proto),
                packets,
            })
            .collect();

        PcapPreviewResult {
            format,
            file_size,
            packets_sampled: self.packets_sampled,
            packet_count_estimate,
            time_span,
            protocol_mix,
            top_src_ips,
            top_dst_ips,
            top_dst_ports,
            warnings,
        }
    }
}

fn topn_ip(m: HashMap<String, (u64, u64)>) -> Vec<IpCount> {
    let mut v: Vec<(String, (u64, u64))> = m.into_iter().collect();
    v.sort_by(|a, b| b.1.0.cmp(&a.1.0));
    v.into_iter()
        .take(TOP_N)
        .map(|(ip, (pkts, bytes))| IpCount {
            ip,
            packets: pkts,
            bytes,
        })
        .collect()
}

fn fmt_ipv4(o: &[u8; 4]) -> String {
    format!("{}.{}.{}.{}", o[0], o[1], o[2], o[3])
}

fn fmt_ipv6(o: &[u8; 16]) -> String {
    // Compose 8 groups of 16 bits; std::net::Ipv6Addr does canonical
    // shortening for us.
    let a = std::net::Ipv6Addr::new(
        u16::from_be_bytes([o[0], o[1]]),
        u16::from_be_bytes([o[2], o[3]]),
        u16::from_be_bytes([o[4], o[5]]),
        u16::from_be_bytes([o[6], o[7]]),
        u16::from_be_bytes([o[8], o[9]]),
        u16::from_be_bytes([o[10], o[11]]),
        u16::from_be_bytes([o[12], o[13]]),
        u16::from_be_bytes([o[14], o[15]]),
    );
    a.to_string()
}

/// High-value well-known ports. The PCAP analyst's signal is
/// dominated by these; ephemeral / unrecognized ports stay `None`.
///
/// Exposed (`pub`) so the flow-ingest path in [`crate::pcap`] can tag
/// the same `service` value onto Connect edges without duplicating
/// the lookup table.
pub fn port_to_service_name(port: u16, proto: &str) -> Option<String> {
    let n = match (port, proto) {
        (53, _) => "DNS",
        (80, "TCP") => "HTTP",
        (443, "TCP") => "HTTPS",
        (8080, "TCP") => "HTTP-Alt",
        (22, "TCP") => "SSH",
        (3389, "TCP") => "RDP",
        (445, "TCP") => "SMB",
        (139, "TCP") => "NetBIOS-SSN",
        (88, "TCP") => "Kerberos",
        (389, "TCP") => "LDAP",
        (636, "TCP") => "LDAPS",
        (25, "TCP") => "SMTP",
        (465, "TCP") => "SMTPS",
        (587, "TCP") => "SMTP-Submission",
        (110, "TCP") => "POP3",
        (143, "TCP") => "IMAP",
        (993, "TCP") => "IMAPS",
        (135, "TCP") => "RPC",
        (853, "TCP") => "DoT",
        (123, "UDP") => "NTP",
        (161, "UDP") => "SNMP",
        (500, "UDP") => "IKE",
        (4500, "UDP") => "IKE-NAT-T",
        _ => return None,
    };
    Some(n.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn path_is_pcap_matches_known_extensions() {
        assert!(path_is_pcap("/tmp/foo.pcap"));
        assert!(path_is_pcap("/tmp/foo.PCAP"));
        assert!(path_is_pcap("/tmp/foo.pcapng"));
        assert!(path_is_pcap("/tmp/foo.cap"));
        assert!(!path_is_pcap("/tmp/foo.evtx"));
        assert!(!path_is_pcap("/tmp/foo.csv"));
        assert!(!path_is_pcap("/tmp/no_ext"));
    }

    fn write_temp(bytes: &[u8]) -> tempfile::NamedTempFile {
        let mut tmp = tempfile::NamedTempFile::new().expect("tempfile");
        tmp.write_all(bytes).expect("write");
        tmp.flush().expect("flush");
        tmp
    }

    #[test]
    fn file_looks_like_pcap_recognizes_all_magic_variants() {
        let cases: &[&[u8]] = &[
            &[0xa1, 0xb2, 0xc3, 0xd4, 0, 0, 0, 0],
            &[0xd4, 0xc3, 0xb2, 0xa1, 0, 0, 0, 0],
            &[0xa1, 0xb2, 0x3c, 0x4d, 0, 0, 0, 0],
            &[0x4d, 0x3c, 0xb2, 0xa1, 0, 0, 0, 0],
            &[0x0a, 0x0d, 0x0d, 0x0a, 0, 0, 0, 0],
        ];
        for c in cases {
            let tmp = write_temp(c);
            let p = tmp.path().to_string_lossy().to_string();
            assert!(file_looks_like_pcap(&p), "missed magic {:?}", &c[..4]);
        }
    }

    #[test]
    fn file_looks_like_pcap_rejects_non_pcap() {
        let tmp = write_temp(b"PK\x03\x04zip-archive");
        let p = tmp.path().to_string_lossy().to_string();
        assert!(!file_looks_like_pcap(&p));
    }

    #[test]
    fn pcap_format_name_disambiguates() {
        let pcap = write_temp(&[0xd4, 0xc3, 0xb2, 0xa1, 0, 0]);
        let pcapng = write_temp(&[0x0a, 0x0d, 0x0d, 0x0a, 0, 0]);
        let junk = write_temp(b"hello");
        assert_eq!(pcap_format_name(&pcap.path().to_string_lossy()), "pcap");
        assert_eq!(pcap_format_name(&pcapng.path().to_string_lossy()), "pcapng");
        assert_eq!(pcap_format_name(&junk.path().to_string_lossy()), "unknown");
    }

    /// Build a minimal LE-microsecond legacy PCAP with one TCP packet
    /// 192.168.1.10:54321 → 1.1.1.1:443 carrying 0 payload bytes.
    fn minimal_pcap_one_tcp_packet() -> Vec<u8> {
        let mut out = Vec::<u8>::new();
        // Global header (LE, μs, snaplen 65535, linktype 1 = Ethernet)
        out.extend_from_slice(&0xa1b2c3d4u32.to_be_bytes()); // magic BE = μs PCAP
        out.extend_from_slice(&2u16.to_be_bytes()); // version major
        out.extend_from_slice(&4u16.to_be_bytes()); // version minor
        out.extend_from_slice(&0i32.to_be_bytes()); // thiszone
        out.extend_from_slice(&0u32.to_be_bytes()); // sigfigs
        out.extend_from_slice(&65535u32.to_be_bytes()); // snaplen
        out.extend_from_slice(&1u32.to_be_bytes()); // linktype = Ethernet

        // Build packet: 14B Ethernet + 20B IPv4 + 20B TCP = 54B
        let mut pkt = Vec::<u8>::new();
        // Ethernet: dst MAC, src MAC, ethertype 0x0800
        pkt.extend_from_slice(&[0x11, 0x22, 0x33, 0x44, 0x55, 0x66]);
        pkt.extend_from_slice(&[0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]);
        pkt.extend_from_slice(&[0x08, 0x00]);
        // IPv4: 20B header, src 192.168.1.10, dst 1.1.1.1, proto TCP
        let ip_header_start = pkt.len();
        pkt.push(0x45); // version + IHL
        pkt.push(0x00); // DSCP/ECN
        pkt.extend_from_slice(&40u16.to_be_bytes()); // total length = 20 IP + 20 TCP
        pkt.extend_from_slice(&0u16.to_be_bytes()); // identification
        pkt.extend_from_slice(&0x4000u16.to_be_bytes()); // flags + fragment offset (DF)
        pkt.push(64); // TTL
        pkt.push(6); // protocol = TCP
        pkt.extend_from_slice(&0u16.to_be_bytes()); // header checksum (placeholder)
        pkt.extend_from_slice(&[192, 168, 1, 10]);
        pkt.extend_from_slice(&[1, 1, 1, 1]);
        // Patch the IP checksum so etherparse's strict validator accepts it.
        let ip_csum = ones_complement_sum(&pkt[ip_header_start..ip_header_start + 20]);
        let cs_pos = ip_header_start + 10;
        pkt[cs_pos..cs_pos + 2].copy_from_slice(&ip_csum.to_be_bytes());
        // TCP: src port 54321, dst port 443, seq 0, ack 0, offset 5, flags SYN
        pkt.extend_from_slice(&54321u16.to_be_bytes());
        pkt.extend_from_slice(&443u16.to_be_bytes());
        pkt.extend_from_slice(&0u32.to_be_bytes());
        pkt.extend_from_slice(&0u32.to_be_bytes());
        pkt.push(0x50); // data offset = 5 words << 4
        pkt.push(0x02); // SYN
        pkt.extend_from_slice(&8192u16.to_be_bytes()); // window
        pkt.extend_from_slice(&0u16.to_be_bytes()); // checksum (etherparse doesn't validate by default)
        pkt.extend_from_slice(&0u16.to_be_bytes()); // urgent

        // Record header (BE because of the magic): ts_sec, ts_usec, incl_len, orig_len
        out.extend_from_slice(&1_700_000_000u32.to_be_bytes());
        out.extend_from_slice(&0u32.to_be_bytes());
        out.extend_from_slice(&(pkt.len() as u32).to_be_bytes());
        out.extend_from_slice(&(pkt.len() as u32).to_be_bytes());
        out.extend_from_slice(&pkt);
        out
    }

    fn ones_complement_sum(bytes: &[u8]) -> u16 {
        let mut sum: u32 = 0;
        let mut i = 0;
        while i + 1 < bytes.len() {
            sum += u16::from_be_bytes([bytes[i], bytes[i + 1]]) as u32;
            i += 2;
        }
        if i < bytes.len() {
            sum += (bytes[i] as u32) << 8;
        }
        while sum >> 16 != 0 {
            sum = (sum & 0xFFFF) + (sum >> 16);
        }
        !(sum as u16)
    }

    #[test]
    fn preview_handles_single_tcp_packet() {
        let bytes = minimal_pcap_one_tcp_packet();
        let tmp = write_temp(&bytes);
        let p = tmp.path().to_string_lossy().to_string();
        let result = pcap_preview_sample(&p).expect("preview ok");
        assert_eq!(result.format, "pcap");
        assert!(result.packets_sampled >= 1, "expected ≥1 packet decoded");
        assert!(
            result
                .protocol_mix
                .iter()
                .any(|p| p.protocol == "TCP" && p.packets >= 1),
            "expected TCP in mix, got {:?}",
            result.protocol_mix
        );
        assert!(
            result.top_dst_ports.iter().any(|p| p.port == 443),
            "expected dst port 443, got {:?}",
            result.top_dst_ports
        );
        assert!(
            result.top_src_ips.iter().any(|i| i.ip == "192.168.1.10"),
            "expected src IP 192.168.1.10, got {:?}",
            result.top_src_ips
        );
        assert!(
            result.top_dst_ports.iter().any(|p| p.service.as_deref() == Some("HTTPS")),
            "expected HTTPS service tag on 443"
        );
        assert!(result.time_span.is_some(), "expected a time span");
    }

    #[test]
    fn preview_on_empty_file_returns_empty_result() {
        let tmp = write_temp(b"");
        let p = tmp.path().to_string_lossy().to_string();
        // Empty file fails the reader init — surface as error string.
        assert!(pcap_preview_sample(&p).is_err());
    }

    #[test]
    fn preview_on_truncated_file_does_not_panic() {
        let mut bytes = minimal_pcap_one_tcp_packet();
        bytes.truncate(28); // global header + half of the record header
        let tmp = write_temp(&bytes);
        let p = tmp.path().to_string_lossy().to_string();
        // Either error or empty result is acceptable — we just must
        // not panic and must produce a finite output.
        let _ = pcap_preview_sample(&p);
    }
}
