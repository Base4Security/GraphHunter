//! Offline PCAP / PCAPNG flow ingest.
//!
//! Mirror of [`crate::evtx::evtx_ingest_streaming`]: read the capture,
//! aggregate packets into 5-tuple flows, emit `IP -[Connect]-> IP`
//! edges with rich metadata into the session's graph.
//!
//! PR2 scope: L3/L4 only. No DNS / TLS SNI / HTTP Host decode (PR3).
//!
//! ## Why this isn't a `LogParser`
//!
//! The `LogParser` trait is stateless (`parse_raw(&self, data: &str)`).
//! Flow aggregation needs state across packets — a FIN at frame N
//! closes the flow that opened at frame 1. So PCAP gets a free
//! function with a local [`FlowAggregator`] just like EVTX gets
//! `evtx_ingest_streaming`. The `FormatDescriptor` in the registry
//! exists for dispatch / preview, but its `make_parser` is never
//! called on the ingest path.
//!
//! ## Aggregator policy
//!
//! - **5-tuple flow key**: `(src_ip, dst_ip, src_port, dst_port, proto)`.
//!   The "src" is whichever side sent the *first* packet of the flow.
//!   Reverse-direction packets land on the same flow as `_rev` counters.
//! - **Eviction**:
//!   - TCP FIN/RST → emit immediately, `flow_complete=true`.
//!   - Idle sweep every 10K packets: any flow whose `last_us` is older
//!     than the per-proto timeout fires. Defaults match the canonical
//!     NetFlow values: TCP 300s, UDP 60s, ICMP 30s, other 120s.
//!   - Hard cap 256K active flows. At cap, evict the 1024 oldest as
//!     `flow_complete=false` (never drop — incomplete signal is still
//!     signal).
//!   - EOF: flush every remaining flow with `flow_complete = (FIN || RST)`.
//! - **Batching**: every 5K emitted flows, hand the batch off to
//!   `GraphHunter::insert_raw_events` and yield the write lock. Keeps
//!   the canvas responsive on multi-GB captures.
//! - **flow_id**: UUID v7 derived from the current wall clock at
//!   emission time. v7 is monotonic, so the IDs sort by emission time
//!   even when two flows share the same Unix-second `timestamp` (the
//!   graph store does not dedup parallel multi-edges).

use std::collections::HashMap;
use std::fs::File;
use std::sync::Arc;

use graph_hunter_core::{EntityType, RawIngestEvent, RelationType};
use uuid::Uuid;

use crate::EventEmitter;
use crate::events::events::INGEST_PROGRESS;
use crate::pcap_l7::{
    TlsClientHelloInfo, detect_smb2_command, extract_dns_queries, extract_ftp_user,
    extract_http_host, extract_ssh_banner, extract_tls_client_hello, smb2_command_name,
};
use crate::pcap_l7_auth::{
    KerberosPrincipal, extract_kerberos_principal, extract_ldap_bind_dn, extract_ntlm_type3,
};
use crate::pcap_preview::port_to_service_name;
use crate::state::Session;

/// Known DoH (DNS-over-HTTPS) provider hostnames. SNI ∈ this list on
/// a TCP/443 flow means the encrypted traffic is almost certainly DNS
/// queries we can't see — surface that as a `suspected_doh` metadata
/// flag rather than pretend the traffic is generic HTTPS.
const DOH_PROVIDERS: &[&str] = &[
    "dns.google",
    "cloudflare-dns.com",
    "dns.cloudflare.com",
    "one.one.one.one",
    "dns.quad9.net",
    "dns9.quad9.net",
    "dns.adguard.com",
    "doh.opendns.com",
    "mozilla.cloudflare-dns.com",
    "dns.nextdns.io",
];

/// Maximum number of simultaneously active flows. ~320 B per
/// `FlowState` (with string IPs and metadata), so 256K ≈ 80 MB.
const FLOW_CAP: usize = 256_000;
/// When the cap is hit, evict this many of the oldest flows at once
/// rather than scanning per-insert.
const EVICT_AT_ONCE: usize = 1024;
/// How often (in packets) to walk active flows looking for idle
/// expiries. 10K packets at ~700K pps is ~14 ms — light.
const IDLE_SWEEP_EVERY_N_PACKETS: u64 = 10_000;
/// Number of completed flows to accumulate before flushing the batch
/// to `GraphHunter::insert_raw_events`. Picked to balance write-lock
/// hold time against per-call overhead.
const BATCH_FLUSH_SIZE: usize = 5_000;
/// Emit `ingest-progress` every N packets read.
const PROGRESS_EVERY_N_PACKETS: u64 = 5_000;

// Per-protocol idle timeouts (microseconds). Match NetFlow defaults.
const TCP_IDLE_US: u128 = 300 * 1_000_000;
const UDP_IDLE_US: u128 = 60 * 1_000_000;
const ICMP_IDLE_US: u128 = 30 * 1_000_000;
const OTHER_IDLE_US: u128 = 120 * 1_000_000;

// IP protocol numbers (RFC 5237).
const PROTO_TCP: u8 = 6;
const PROTO_UDP: u8 = 17;
const PROTO_ICMP: u8 = 1;
const PROTO_ICMP6: u8 = 58;

// TCP flag bits.
const FLAG_FIN: u8 = 0x01;
const FLAG_SYN: u8 = 0x02;
const FLAG_RST: u8 = 0x04;
const FLAG_PSH: u8 = 0x08;
const FLAG_ACK: u8 = 0x10;
const FLAG_URG: u8 = 0x20;

/// Read a PCAP / PCAPNG capture and ingest its 5-tuple flows into the
/// session's graph. Returns `(new_entities, new_relations)`.
pub fn pcap_ingest_streaming(
    path: &str,
    session: &Arc<Session>,
    dataset_id: &str,
    emitter: &Arc<dyn EventEmitter>,
    _job_id: &str,
) -> Result<(usize, usize), String> {
    use pcap_parser::{PcapBlockOwned, PcapError, create_reader};

    let pcap_file = std::path::Path::new(path)
        .file_name()
        .and_then(|p| p.to_str())
        .unwrap_or("")
        .to_string();
    let file_size = std::fs::metadata(path).map(|m| m.len()).unwrap_or(0);
    let file = File::open(path).map_err(|e| format!("open '{path}': {e}"))?;
    let mut reader =
        create_reader(65_536, file).map_err(|e| format!("pcap reader init: {e:?}"))?;

    let mut aggregator = FlowAggregator::new(pcap_file);
    let mut if_tsresol: Vec<u8> = Vec::new();
    let mut legacy_nanos = false;
    let mut packets_seen: u64 = 0;
    let mut undecodable: u64 = 0;
    let mut last_progress: u64 = 0;

    let mut total_new_entities: usize = 0;
    let mut total_new_relations: usize = 0;

    loop {
        match reader.next() {
            Ok((offset, block)) => {
                match block {
                    PcapBlockOwned::LegacyHeader(hdr) => {
                        legacy_nanos = hdr.magic_number == 0xa1b2_3c4d
                            || hdr.magic_number == 0x4d3c_b2a1;
                    }
                    PcapBlockOwned::Legacy(pkt) => {
                        let ts_us = if legacy_nanos {
                            (pkt.ts_sec as u128) * 1_000_000
                                + (pkt.ts_usec as u128) / 1_000
                        } else {
                            (pkt.ts_sec as u128) * 1_000_000 + (pkt.ts_usec as u128)
                        };
                        if !aggregator.observe(pkt.data, ts_us) {
                            undecodable += 1;
                        }
                        packets_seen += 1;
                    }
                    PcapBlockOwned::NG(ng) => {
                        if observe_ng_block(&ng, &mut aggregator, &mut if_tsresol) {
                            packets_seen += 1;
                        } else if matches!(
                            ng,
                            pcap_parser::pcapng::Block::EnhancedPacket(_)
                                | pcap_parser::pcapng::Block::SimplePacket(_)
                        ) {
                            // It was a packet-bearing block but we
                            // failed to decode L2-L4.
                            packets_seen += 1;
                            undecodable += 1;
                        }
                    }
                }
                reader.consume(offset);

                if packets_seen > 0 && packets_seen % IDLE_SWEEP_EVERY_N_PACKETS == 0 {
                    aggregator.sweep_idle();
                }
                if aggregator.pending_emit.len() >= BATCH_FLUSH_SIZE {
                    flush_to_graph(
                        &mut aggregator,
                        session,
                        dataset_id,
                        &mut total_new_entities,
                        &mut total_new_relations,
                    )?;
                }
                if packets_seen - last_progress >= PROGRESS_EVERY_N_PACKETS {
                    emitter.emit(
                        INGEST_PROGRESS,
                        serde_json::json!({
                            "phase": "parsing",
                            "bytes_read": packets_seen,
                            "bytes_total": file_size,
                            "entities": total_new_entities,
                            "relations": total_new_relations,
                        }),
                    );
                    last_progress = packets_seen;
                }
            }
            Err(PcapError::Eof) => break,
            Err(PcapError::Incomplete(_)) => {
                if reader.refill().is_err() {
                    break;
                }
            }
            Err(_) => break,
        }
    }

    // EOF: drain whatever is still active.
    aggregator.flush_all();
    flush_to_graph(
        &mut aggregator,
        session,
        dataset_id,
        &mut total_new_entities,
        &mut total_new_relations,
    )?;

    if undecodable > 0 {
        tracing::warn!(
            "PCAP ingest: {undecodable} packet(s) failed L2-L4 decode (non-Ethernet linktype or truncated frame)"
        );
    }

    Ok((total_new_entities, total_new_relations))
}

/// Returns `true` when the block was a packet that contributed to the
/// aggregator state (decoded successfully). Non-packet blocks return
/// `false`.
fn observe_ng_block(
    block: &pcap_parser::pcapng::Block<'_>,
    aggregator: &mut FlowAggregator,
    if_tsresol: &mut Vec<u8>,
) -> bool {
    use pcap_parser::pcapng::Block;
    match block {
        Block::SectionHeader(_) => {
            // Each new section resets interface IDs.
            if_tsresol.clear();
            false
        }
        Block::InterfaceDescription(idb) => {
            let resol = idb
                .options
                .iter()
                .find(|o| o.code == pcap_parser::pcapng::OptionCode::IfTsresol)
                .and_then(|o| o.value.first().copied())
                .unwrap_or(6);
            if_tsresol.push(resol);
            false
        }
        Block::EnhancedPacket(epb) => {
            let resol = if_tsresol.get(epb.if_id as usize).copied().unwrap_or(6);
            let raw = ((epb.ts_high as u64) << 32) | (epb.ts_low as u64);
            let ts_us = ng_raw_to_us(raw, resol);
            aggregator.observe(epb.data, ts_us)
        }
        Block::SimplePacket(spb) => aggregator.observe(spb.data, 0),
        _ => false,
    }
}

/// Convert a PCAPNG raw timestamp to microseconds. `resol` is the
/// IDB's `if_tsresol`:
///   high bit set ⇒ 2^N units per second
///   else         ⇒ 10^N units per second
fn ng_raw_to_us(raw: u64, resol: u8) -> u128 {
    let exp = (resol & 0x7F) as u32;
    let units_per_sec: u128 = if (resol & 0x80) != 0 {
        1u128 << exp.min(63)
    } else {
        10u128.checked_pow(exp).unwrap_or(1_000_000)
    };
    (raw as u128).saturating_mul(1_000_000) / units_per_sec.max(1)
}

#[derive(Hash, Eq, PartialEq, Clone, Debug)]
struct FlowKey {
    src_ip: String,
    dst_ip: String,
    src_port: u16,
    dst_port: u16,
    proto: u8,
}

#[derive(Clone, Debug, Default)]
struct FlowState {
    first_us: u128,
    last_us: u128,
    packets_fwd: u32,
    packets_rev: u32,
    bytes_fwd: u64,
    bytes_rev: u64,
    tcp_flags_union: u8,
    fin_seen: bool,
    rst_seen: bool,
    // ── L7 (PR3) ─────────────────────────────────────────────────
    /// Originator IP at the moment of flow creation. Needed at emit
    /// time to attribute SNI / Host / DNS to the right side when the
    /// flow direction is canonicalized.
    src_ip_for_l7: String,
    /// TLS SNI captured from the first ClientHello on the flow.
    l7_sni: Option<String>,
    /// HTTP Host header captured from the first request line.
    l7_http_host: Option<String>,
    /// JA3 MD5 hex.
    l7_ja3: Option<String>,
    /// Set when TLS 1.3 ECH was observed (SNI deliberately hidden).
    l7_ech_seen: bool,
    // ── PR1a additions ───────────────────────────────────────────
    /// SSH banner observed on TCP/22 in either direction. Kept as a
    /// fingerprint for client / server identification (e.g.
    /// `SSH-2.0-OpenSSH_9.4`).
    l7_ssh_banner: Option<String>,
    /// FTP `USER` argument observed on the client side of a TCP/21
    /// flow. Fuels the secondary `User -[Auth]-> IP` edge.
    l7_ftp_user: Option<String>,
    /// SMB2 command opcode of the first SMB2 message observed. Used
    /// for `service` metadata + `l7_decoded` honesty. User extraction
    /// from the embedded NTLMSSP / Kerberos blob is PR1b scope.
    l7_smb2_command: Option<u16>,
    /// ICMP type byte of the first ICMP datagram observed on this
    /// flow. ICMP "flows" collapse on (src_ip, dst_ip, proto) so this
    /// reflects whichever type opened the conversation.
    icmp_type: Option<u8>,
    /// ICMP code byte of the first ICMP datagram observed on this
    /// flow. Paired with `icmp_type`.
    icmp_code: Option<u8>,
    // ── PR1b auth-protocol additions ─────────────────────────────
    /// Kerberos client principal (`cname`) extracted from the first
    /// AS-REQ or TGS-REQ seen on the flow. Fuels the secondary
    /// `User -[Auth]-> IP` edge.
    l7_kerberos_user: Option<String>,
    /// Whether the Kerberos request was AS-REQ or TGS-REQ. Surfaced
    /// as metadata so a hunt can separate initial auth from ticket
    /// renewal.
    l7_kerberos_kind: Option<&'static str>,
    /// LDAP bind DN (e.g. `CN=alice,DC=example,DC=com`).
    l7_ldap_user: Option<String>,
    /// NTLMSSP Type 3 UserName. May be set from SMB2 SESSION_SETUP
    /// or any other TCP payload that wraps an NTLM Type 3 message.
    l7_ntlm_user: Option<String>,
    /// NTLMSSP Type 3 DomainName, paired with `l7_ntlm_user`. May
    /// be empty (Negotiate Anonymous).
    l7_ntlm_domain: Option<String>,
}

#[derive(Copy, Clone)]
enum Direction {
    Forward,
    Reverse,
}

pub(crate) struct FlowAggregator {
    active: HashMap<FlowKey, FlowState>,
    pending_emit: Vec<RawIngestEvent>,
    pcap_file: String,
    /// Tracks the highest packet timestamp seen so far (μs). Used as
    /// "now" for idle sweeps so the policy is anchored to packet time,
    /// not wall time.
    latest_ts_us: u128,
}

impl FlowAggregator {
    fn new(pcap_file: String) -> Self {
        Self {
            active: HashMap::new(),
            pending_emit: Vec::new(),
            pcap_file,
            latest_ts_us: 0,
        }
    }

    /// Decode L2-L4, fold the packet into its flow, peek L7 when
    /// possible. Returns `true` when L2-L4 decode succeeded.
    fn observe(&mut self, data: &[u8], ts_us: u128) -> bool {
        if ts_us > self.latest_ts_us {
            self.latest_ts_us = ts_us;
        }
        let Ok(parsed) = etherparse::PacketHeaders::from_ethernet_slice(data) else {
            return false;
        };
        let (src_ip, dst_ip, proto) = match parsed.net.as_ref() {
            Some(etherparse::NetHeaders::Ipv4(h, _)) => (
                fmt_ipv4(&h.source),
                fmt_ipv4(&h.destination),
                u8::from(h.protocol),
            ),
            Some(etherparse::NetHeaders::Ipv6(h, _)) => (
                fmt_ipv6(&h.source),
                fmt_ipv6(&h.destination),
                u8::from(h.next_header),
            ),
            _ => return false,
        };
        let mut pkt_icmp_type: Option<u8> = None;
        let mut pkt_icmp_code: Option<u8> = None;
        let (src_port, dst_port, tcp_flags, is_fin, is_rst) =
            match parsed.transport.as_ref() {
                Some(etherparse::TransportHeader::Tcp(t)) => {
                    let mut flags = 0u8;
                    if t.fin { flags |= FLAG_FIN; }
                    if t.syn { flags |= FLAG_SYN; }
                    if t.rst { flags |= FLAG_RST; }
                    if t.psh { flags |= FLAG_PSH; }
                    if t.ack { flags |= FLAG_ACK; }
                    if t.urg { flags |= FLAG_URG; }
                    (t.source_port, t.destination_port, flags, t.fin, t.rst)
                }
                Some(etherparse::TransportHeader::Udp(u)) => {
                    (u.source_port, u.destination_port, 0, false, false)
                }
                Some(etherparse::TransportHeader::Icmpv4(h)) => {
                    // `Icmpv4Type` is a sum type that recovers
                    // type/code from variant data — easier to round-
                    // trip through `to_bytes()` and read offsets 0-1.
                    let bytes = h.to_bytes();
                    if bytes.len() >= 2 {
                        pkt_icmp_type = Some(bytes[0]);
                        pkt_icmp_code = Some(bytes[1]);
                    }
                    (0, 0, 0, false, false)
                }
                Some(etherparse::TransportHeader::Icmpv6(h)) => {
                    let bytes = h.to_bytes();
                    if bytes.len() >= 2 {
                        pkt_icmp_type = Some(bytes[0]);
                        pkt_icmp_code = Some(bytes[1]);
                    }
                    (0, 0, 0, false, false)
                }
                _ => (0, 0, 0, false, false),
            };
        let bytes = data.len() as u64;
        let payload: &[u8] = parsed.payload.slice();

        // ── DNS (immediate L7 edges, not aggregated) ──────────────
        // UDP/53 carries one or more DNS questions per packet. Each
        // emits its own `IP -[DNS]-> Domain` edge keyed on this
        // packet's timestamp. The L4 Connect edge from the underlying
        // UDP flow is still emitted at flush time as usual.
        if proto == PROTO_UDP && (src_port == 53 || dst_port == 53) {
            let queries = extract_dns_queries(payload);
            if !queries.is_empty() {
                let ts_secs = (ts_us / 1_000_000) as i64;
                // Heuristic: when dst_port == 53 the local side asked
                // the remote resolver. When src_port == 53 it's a
                // response (which still carries the QNAMEs in the
                // question section that mirrors the query). Both
                // cases attribute the query to the querier.
                let querier = if dst_port == 53 { &src_ip } else { &dst_ip };
                for qname in queries {
                    self.pending_emit.push(dns_edge(
                        querier.clone(),
                        qname,
                        ts_secs,
                        &self.pcap_file,
                    ));
                }
            }
        }

        // ── Kerberos UDP/88 (decoded into the flow, not emitted
        //    as a separate per-packet edge) ──────────────────────
        // Only client → KDC carries the cname. Responses share the
        // tag bytes but the response body wraps a different
        // structure — extract_kerberos_principal naturally rejects
        // them, but gating by dst_port == 88 is cheaper.
        let mut pkt_kerberos: Option<KerberosPrincipal> = None;
        if proto == PROTO_UDP && dst_port == 88 {
            pkt_kerberos = extract_kerberos_principal(payload);
        }

        let fwd_key = FlowKey {
            src_ip: src_ip.clone(),
            dst_ip: dst_ip.clone(),
            src_port,
            dst_port,
            proto,
        };
        let rev_key = FlowKey {
            src_ip: dst_ip.clone(),
            dst_ip: src_ip.clone(),
            src_port: dst_port,
            dst_port: src_port,
            proto,
        };

        // Match against existing flow in either direction.
        let matched: Option<(FlowKey, Direction)> = if self.active.contains_key(&fwd_key) {
            Some((fwd_key.clone(), Direction::Forward))
        } else if self.active.contains_key(&rev_key) {
            Some((rev_key, Direction::Reverse))
        } else {
            None
        };

        let close_now = match matched {
            Some((key, dir)) => {
                let close = {
                    let state = self
                        .active
                        .get_mut(&key)
                        .expect("matched flow must exist");
                    state.last_us = ts_us;
                    match dir {
                        Direction::Forward => {
                            state.packets_fwd = state.packets_fwd.saturating_add(1);
                            state.bytes_fwd = state.bytes_fwd.saturating_add(bytes);
                        }
                        Direction::Reverse => {
                            state.packets_rev = state.packets_rev.saturating_add(1);
                            state.bytes_rev = state.bytes_rev.saturating_add(bytes);
                        }
                    }
                    state.tcp_flags_union |= tcp_flags;
                    if is_fin {
                        state.fin_seen = true;
                    }
                    if is_rst {
                        state.rst_seen = true;
                    }
                    // L7 peek on TCP flows we haven't decoded yet.
                    if proto == PROTO_TCP && !payload.is_empty() {
                        peek_tcp_l7(state, payload);
                    }
                    // ICMP type/code: keep whatever the flow saw first.
                    if state.icmp_type.is_none() {
                        state.icmp_type = pkt_icmp_type;
                        state.icmp_code = pkt_icmp_code;
                    }
                    // UDP/88 Kerberos: same first-wins policy.
                    if state.l7_kerberos_user.is_none() {
                        if let Some(p) = pkt_kerberos.as_ref() {
                            state.l7_kerberos_user = Some(p.cname.clone());
                            state.l7_kerberos_kind = Some(p.kind);
                        }
                    }
                    state.fin_seen || state.rst_seen
                };
                if close { Some(key) } else { None }
            }
            None => {
                if self.active.len() >= FLOW_CAP {
                    self.evict_oldest(EVICT_AT_ONCE);
                }
                let (krb_user, krb_kind) = match pkt_kerberos {
                    Some(p) => (Some(p.cname), Some(p.kind)),
                    None => (None, None),
                };
                let mut new_state = FlowState {
                    first_us: ts_us,
                    last_us: ts_us,
                    packets_fwd: 1,
                    packets_rev: 0,
                    bytes_fwd: bytes,
                    bytes_rev: 0,
                    tcp_flags_union: tcp_flags,
                    fin_seen: is_fin,
                    rst_seen: is_rst,
                    src_ip_for_l7: src_ip.clone(),
                    icmp_type: pkt_icmp_type,
                    icmp_code: pkt_icmp_code,
                    l7_kerberos_user: krb_user,
                    l7_kerberos_kind: krb_kind,
                    ..FlowState::default()
                };
                if proto == PROTO_TCP && !payload.is_empty() {
                    peek_tcp_l7(&mut new_state, payload);
                }
                let close = new_state.fin_seen || new_state.rst_seen;
                self.active.insert(fwd_key.clone(), new_state);
                if close { Some(fwd_key) } else { None }
            }
        };

        if let Some(key) = close_now {
            if let Some(state) = self.active.remove(&key) {
                self.emit(key, state, true);
            }
        }
        true
    }

    fn evict_oldest(&mut self, n: usize) {
        let mut ages: Vec<(FlowKey, u128)> = self
            .active
            .iter()
            .map(|(k, s)| (k.clone(), s.last_us))
            .collect();
        ages.sort_by_key(|(_, t)| *t);
        for (k, _) in ages.into_iter().take(n) {
            if let Some(state) = self.active.remove(&k) {
                self.emit(k, state, false);
            }
        }
    }

    fn sweep_idle(&mut self) {
        let now = self.latest_ts_us;
        let to_emit: Vec<FlowKey> = self
            .active
            .iter()
            .filter_map(|(k, s)| {
                let timeout = idle_timeout_us(k.proto);
                if now.saturating_sub(s.last_us) > timeout {
                    Some(k.clone())
                } else {
                    None
                }
            })
            .collect();
        for k in to_emit {
            if let Some(state) = self.active.remove(&k) {
                let complete = state.fin_seen || state.rst_seen;
                self.emit(k, state, complete);
            }
        }
    }

    fn flush_all(&mut self) {
        let all: Vec<FlowKey> = self.active.keys().cloned().collect();
        for k in all {
            if let Some(state) = self.active.remove(&k) {
                let complete = state.fin_seen || state.rst_seen;
                self.emit(k, state, complete);
            }
        }
    }

    fn emit(&mut self, key: FlowKey, state: FlowState, flow_complete: bool) {
        let flow_id = Uuid::now_v7();
        let proto_str = proto_name(key.proto);
        let timestamp = (state.first_us / 1_000_000) as i64;
        let mut rel_metadata: HashMap<String, String> = HashMap::with_capacity(24);
        rel_metadata.insert("source".to_string(), "pcap".to_string());
        if !self.pcap_file.is_empty() {
            rel_metadata.insert("pcap_file".to_string(), self.pcap_file.clone());
        }
        rel_metadata.insert("flow_id".to_string(), flow_id.to_string());
        rel_metadata.insert("flow_complete".to_string(), flow_complete.to_string());
        rel_metadata.insert("protocol".to_string(), proto_str.to_string());
        if key.src_port != 0 {
            rel_metadata.insert("src_port".to_string(), key.src_port.to_string());
        }
        if key.dst_port != 0 {
            rel_metadata.insert("dst_port".to_string(), key.dst_port.to_string());
        }
        if let Some(svc) = port_to_service_name(key.dst_port, proto_str) {
            rel_metadata.insert("service".to_string(), svc);
        }
        rel_metadata.insert("packets_fwd".to_string(), state.packets_fwd.to_string());
        rel_metadata.insert("packets_rev".to_string(), state.packets_rev.to_string());
        rel_metadata.insert("bytes_fwd".to_string(), state.bytes_fwd.to_string());
        rel_metadata.insert("bytes_rev".to_string(), state.bytes_rev.to_string());
        rel_metadata.insert("first_us".to_string(), state.first_us.to_string());
        rel_metadata.insert("last_us".to_string(), state.last_us.to_string());
        let duration_us = state.last_us.saturating_sub(state.first_us);
        rel_metadata.insert(
            "duration_ms".to_string(),
            (duration_us / 1_000).to_string(),
        );
        if key.proto == PROTO_TCP {
            rel_metadata.insert("tcp_flags".to_string(), fmt_tcp_flags(state.tcp_flags_union));
        }
        // ── ICMP type/code on the L4 edge ─────────────────────────
        // Always surface them when present, regardless of L7 decode.
        // Two flows of the same (src,dst,proto) but different
        // type/code still collapse to one edge — we keep whichever
        // was seen first (see observe()).
        if let Some(t) = state.icmp_type {
            rel_metadata.insert("icmp_type".to_string(), t.to_string());
        }
        if let Some(c) = state.icmp_code {
            rel_metadata.insert("icmp_code".to_string(), c.to_string());
        }
        // ── L7 honesty + secondary edges ────────────────────────
        let mut secondary_domains: Vec<(String, &'static str)> = Vec::new();
        let l7_decoded = if let Some(sni) = state.l7_sni.as_ref() {
            rel_metadata.insert("sni".to_string(), sni.clone());
            if is_doh_provider(sni) {
                rel_metadata.insert("suspected_doh".to_string(), "true".to_string());
            }
            secondary_domains.push((sni.clone(), "tls_sni"));
            "tls_sni"
        } else if let Some(host) = state.l7_http_host.as_ref() {
            rel_metadata.insert("http_host".to_string(), host.clone());
            secondary_domains.push((host.clone(), "http_host"));
            "http_host"
        } else if let Some(banner) = state.l7_ssh_banner.as_ref() {
            rel_metadata.insert("ssh_banner".to_string(), banner.clone());
            "ssh_banner"
        } else if let Some(user) = state.l7_ftp_user.as_ref() {
            // Username on the L4 edge for visibility; the User entity
            // and the User -[Auth]-> IP edge are pushed below.
            rel_metadata.insert("ftp_user".to_string(), user.clone());
            "ftp_user"
        } else if let Some(cmd) = state.l7_smb2_command {
            rel_metadata.insert("smb2_command".to_string(), cmd.to_string());
            if let Some(name) = smb2_command_name(cmd) {
                rel_metadata.insert("smb2_command_name".to_string(), name.to_string());
            }
            "smb2"
        } else if state.l7_kerberos_user.is_some() {
            if let Some(u) = state.l7_kerberos_user.as_ref() {
                rel_metadata.insert("kerberos_user".to_string(), u.clone());
            }
            if let Some(k) = state.l7_kerberos_kind {
                rel_metadata.insert("kerberos_kind".to_string(), k.to_string());
            }
            "kerberos"
        } else if let Some(dn) = state.l7_ldap_user.as_ref() {
            rel_metadata.insert("ldap_user".to_string(), dn.clone());
            "ldap_bind"
        } else if let Some(u) = state.l7_ntlm_user.as_ref() {
            rel_metadata.insert("ntlm_user".to_string(), u.clone());
            if let Some(d) = state.l7_ntlm_domain.as_ref() {
                rel_metadata.insert("ntlm_domain".to_string(), d.clone());
            }
            "ntlm_auth"
        } else if state.l7_ech_seen {
            rel_metadata.insert("tls_ech".to_string(), "true".to_string());
            "encrypted"
        } else if key.proto == PROTO_TCP && key.dst_port == 853 {
            rel_metadata.insert("suspected_dot".to_string(), "true".to_string());
            "encrypted"
        } else {
            "none"
        };
        rel_metadata.insert("l7_decoded".to_string(), l7_decoded.to_string());
        if let Some(ja3) = state.l7_ja3.as_ref() {
            rel_metadata.insert("ja3".to_string(), ja3.clone());
        }

        // Primary L4 Connect edge.
        self.pending_emit.push(RawIngestEvent {
            src_id: key.src_ip.clone(),
            src_type: EntityType::IP,
            src_metadata: HashMap::new(),
            dst_id: key.dst_ip.clone(),
            dst_type: EntityType::IP,
            dst_metadata: HashMap::new(),
            rel_type: RelationType::Connect,
            rel_metadata,
            timestamp,
        });

        // Secondary `IP -[Connect]-> Domain` edges from L7 signal.
        // The "querier" / "client" IP is the flow originator
        // (`state.src_ip_for_l7`), not the rev side.
        let l7_src = if state.src_ip_for_l7.is_empty() {
            key.src_ip.clone()
        } else {
            state.src_ip_for_l7.clone()
        };
        for (domain, kind) in secondary_domains {
            let mut md = HashMap::with_capacity(8);
            md.insert("source".to_string(), "pcap".to_string());
            if !self.pcap_file.is_empty() {
                md.insert("pcap_file".to_string(), self.pcap_file.clone());
            }
            md.insert("flow_id".to_string(), flow_id.to_string());
            md.insert("l7_decoded".to_string(), kind.to_string());
            md.insert(kind.to_string(), "true".to_string()); // sni / http_host flag
            md.insert("dst_port".to_string(), key.dst_port.to_string());
            self.pending_emit.push(RawIngestEvent {
                src_id: l7_src.clone(),
                src_type: EntityType::IP,
                src_metadata: HashMap::new(),
                dst_id: domain,
                dst_type: EntityType::Domain,
                dst_metadata: HashMap::new(),
                rel_type: RelationType::Connect,
                rel_metadata: md,
                timestamp,
            });
        }

        // ── PR1a: User -[Auth]-> IP edge from FTP USER command ────
        // The plan flag said `User -[Auth]-> Host`, but a PCAP only
        // gives us the destination IP — `Host` is for hostnames from
        // other sources (Sysmon Computer field, Sentinel device
        // identity). Tag the dst as `IP` so the entity merges with
        // the L4 endpoint we already created. Hunts that want to
        // chain User->Host->… can still do so once any other source
        // bridges IP <-> Host.
        if let Some(user) = state.l7_ftp_user.as_ref() {
            let mut md = HashMap::with_capacity(6);
            md.insert("source".to_string(), "pcap".to_string());
            if !self.pcap_file.is_empty() {
                md.insert("pcap_file".to_string(), self.pcap_file.clone());
            }
            md.insert("flow_id".to_string(), flow_id.to_string());
            md.insert("l7_decoded".to_string(), "ftp_user".to_string());
            md.insert("protocol".to_string(), "FTP".to_string());
            md.insert("dst_port".to_string(), key.dst_port.to_string());
            self.pending_emit.push(RawIngestEvent {
                src_id: user.clone(),
                src_type: EntityType::User,
                src_metadata: HashMap::new(),
                dst_id: key.dst_ip.clone(),
                dst_type: EntityType::IP,
                dst_metadata: HashMap::new(),
                rel_type: RelationType::Auth,
                rel_metadata: md,
                timestamp,
            });
        }

        // ── PR1b: User -[Auth]-> IP edges from auth protocols ─────
        // Kerberos: cname → dst_ip (which is the KDC for AS-REQ,
        // the application server for TGS-REQ; without sname
        // extraction we use the L4 dst).
        if let Some(user) = state.l7_kerberos_user.as_ref() {
            let mut md = HashMap::with_capacity(8);
            md.insert("source".to_string(), "pcap".to_string());
            if !self.pcap_file.is_empty() {
                md.insert("pcap_file".to_string(), self.pcap_file.clone());
            }
            md.insert("flow_id".to_string(), flow_id.to_string());
            md.insert("l7_decoded".to_string(), "kerberos".to_string());
            md.insert("protocol".to_string(), "Kerberos".to_string());
            if let Some(k) = state.l7_kerberos_kind {
                md.insert("kerberos_kind".to_string(), k.to_string());
            }
            md.insert("dst_port".to_string(), key.dst_port.to_string());
            self.pending_emit.push(RawIngestEvent {
                src_id: user.clone(),
                src_type: EntityType::User,
                src_metadata: HashMap::new(),
                dst_id: key.dst_ip.clone(),
                dst_type: EntityType::IP,
                dst_metadata: HashMap::new(),
                rel_type: RelationType::Auth,
                rel_metadata: md,
                timestamp,
            });
        }
        // LDAP: full DN → LDAP server IP. The DN is the canonical
        // AD entity id, so cross-source merge with EVTX
        // `Security 4624.TargetUserSid` works as soon as that
        // parser also normalises to DN form.
        if let Some(dn) = state.l7_ldap_user.as_ref() {
            let mut md = HashMap::with_capacity(6);
            md.insert("source".to_string(), "pcap".to_string());
            if !self.pcap_file.is_empty() {
                md.insert("pcap_file".to_string(), self.pcap_file.clone());
            }
            md.insert("flow_id".to_string(), flow_id.to_string());
            md.insert("l7_decoded".to_string(), "ldap_bind".to_string());
            md.insert("protocol".to_string(), "LDAP".to_string());
            md.insert("dst_port".to_string(), key.dst_port.to_string());
            self.pending_emit.push(RawIngestEvent {
                src_id: dn.clone(),
                src_type: EntityType::User,
                src_metadata: HashMap::new(),
                dst_id: key.dst_ip.clone(),
                dst_type: EntityType::IP,
                dst_metadata: HashMap::new(),
                rel_type: RelationType::Auth,
                rel_metadata: md,
                timestamp,
            });
        }
        // NTLM: `DOMAIN\\user` (or bare `user` when domain is empty).
        // The DOMAIN-prefixed form matches what Sysmon Security
        // event 4624 reports in `TargetUserName`, so the User
        // entity merges across PCAP and EVTX out of the box.
        if let Some(user) = state.l7_ntlm_user.as_ref() {
            let user_id = match state.l7_ntlm_domain.as_ref() {
                Some(d) if !d.is_empty() => format!("{d}\\{user}"),
                _ => user.clone(),
            };
            let mut md = HashMap::with_capacity(8);
            md.insert("source".to_string(), "pcap".to_string());
            if !self.pcap_file.is_empty() {
                md.insert("pcap_file".to_string(), self.pcap_file.clone());
            }
            md.insert("flow_id".to_string(), flow_id.to_string());
            md.insert("l7_decoded".to_string(), "ntlm_auth".to_string());
            md.insert("protocol".to_string(), "NTLM".to_string());
            md.insert("ntlm_user".to_string(), user.clone());
            if let Some(d) = state.l7_ntlm_domain.as_ref() {
                md.insert("ntlm_domain".to_string(), d.clone());
            }
            md.insert("dst_port".to_string(), key.dst_port.to_string());
            self.pending_emit.push(RawIngestEvent {
                src_id: user_id,
                src_type: EntityType::User,
                src_metadata: HashMap::new(),
                dst_id: key.dst_ip.clone(),
                dst_type: EntityType::IP,
                dst_metadata: HashMap::new(),
                rel_type: RelationType::Auth,
                rel_metadata: md,
                timestamp,
            });
        }
    }
}

/// Build an `IP -[DNS]-> Domain` edge for one query observed inside a
/// DNS packet. The Domain entity merges with any Domain ingested from
/// other sources (Sysmon DNS events, Sentinel SigninLogs, …) — same
/// `StrId` in the interner, so cross-source hunts work out of the box.
fn dns_edge(querier_ip: String, qname: String, timestamp: i64, pcap_file: &str) -> RawIngestEvent {
    let mut md = HashMap::with_capacity(6);
    md.insert("source".to_string(), "pcap".to_string());
    if !pcap_file.is_empty() {
        md.insert("pcap_file".to_string(), pcap_file.to_string());
    }
    md.insert("l7_decoded".to_string(), "dns_query".to_string());
    md.insert("qname".to_string(), qname.clone());
    RawIngestEvent {
        src_id: querier_ip,
        src_type: EntityType::IP,
        src_metadata: HashMap::new(),
        dst_id: qname,
        dst_type: EntityType::Domain,
        dst_metadata: HashMap::new(),
        rel_type: RelationType::DNS,
        rel_metadata: md,
        timestamp,
    }
}

/// Try every L7 decoder we know about, cheapest byte-prefix check
/// first. Each decoder is idempotent and runs only when its slot is
/// still empty, so per-packet cost is one byte compare per slot after
/// the first hit. Returns as soon as any decoder claims the payload.
fn peek_tcp_l7(state: &mut FlowState, payload: &[u8]) {
    if state.l7_sni.is_none() && !state.l7_ech_seen {
        if let Some(info) = extract_tls_client_hello(payload) {
            apply_tls_info(state, info);
            return;
        }
    }
    if state.l7_http_host.is_none() {
        if let Some(host) = extract_http_host(payload) {
            state.l7_http_host = Some(host);
            return;
        }
    }
    if state.l7_ssh_banner.is_none() {
        if let Some(banner) = extract_ssh_banner(payload) {
            state.l7_ssh_banner = Some(banner);
            return;
        }
    }
    if state.l7_ftp_user.is_none() {
        if let Some(user) = extract_ftp_user(payload) {
            state.l7_ftp_user = Some(user);
            return;
        }
    }
    if state.l7_smb2_command.is_none() {
        if let Some(cmd) = detect_smb2_command(payload) {
            state.l7_smb2_command = Some(cmd);
            // SESSION_SETUP carries the NTLMSSP blob — scan the
            // rest of the payload for a Type 3 message and harvest
            // the username if found. Other SMB2 commands don't
            // carry auth material so we skip them.
            if cmd == 0x0001 && state.l7_ntlm_user.is_none() {
                if let Some(info) = extract_ntlm_type3(payload) {
                    state.l7_ntlm_user = Some(info.user);
                    if !info.domain.is_empty() {
                        state.l7_ntlm_domain = Some(info.domain);
                    }
                }
            }
            return;
        }
    }
    // Kerberos AS-REQ / TGS-REQ on TCP/88 (or anywhere — the byte
    // prefix is unambiguous). Cheap prefix check: 0x6a or 0x6c
    // before any walking.
    if state.l7_kerberos_user.is_none() && krb_byte_prefix_plausible(payload) {
        if let Some(p) = extract_kerberos_principal(payload) {
            state.l7_kerberos_user = Some(p.cname);
            state.l7_kerberos_kind = Some(p.kind);
            return;
        }
    }
    // LDAP bindRequest on TCP/389 (3268 GC). The outer SEQUENCE
    // tag `0x30` is universal enough that we run the full parser
    // and rely on its fast-fail.
    if state.l7_ldap_user.is_none() && payload.starts_with(&[0x30]) {
        if let Some(dn) = extract_ldap_bind_dn(payload) {
            state.l7_ldap_user = Some(dn);
            return;
        }
    }
    // Stand-alone NTLM Type 3 (HTTP-NTLM-Auth, raw SMB without
    // SMB2 header, …). Only run when the cheap signature byte
    // search hits — the search itself is O(n) per packet and we
    // don't want to pay that for non-NTLM traffic.
    if state.l7_ntlm_user.is_none() && payload_contains_ntlmssp(payload) {
        if let Some(info) = extract_ntlm_type3(payload) {
            state.l7_ntlm_user = Some(info.user);
            if !info.domain.is_empty() {
                state.l7_ntlm_domain = Some(info.domain);
            }
        }
    }
}

/// Kerberos requests start with the application-tag byte 0x6a
/// (AS-REQ) or 0x6c (TGS-REQ). TCP framing prepends a 4-byte
/// length — so the byte at offset 0 *or* 4 is the candidate.
fn krb_byte_prefix_plausible(payload: &[u8]) -> bool {
    payload.first().is_some_and(|b| *b == 0x6a || *b == 0x6c)
        || payload
            .get(4)
            .is_some_and(|b| *b == 0x6a || *b == 0x6c)
}

/// Cheap pre-flight for [`extract_ntlm_type3`]: just confirm the
/// payload contains the literal "NTLMSSP\\0" anywhere in the first
/// 16 KB. Avoids paying the parser's bounds-checked walks on
/// payloads that obviously don't have NTLM content.
fn payload_contains_ntlmssp(payload: &[u8]) -> bool {
    let scan = &payload[..payload.len().min(16 * 1024)];
    scan.windows(8).any(|w| w == b"NTLMSSP\0")
}

fn apply_tls_info(state: &mut FlowState, info: TlsClientHelloInfo) {
    if info.sni.is_some() {
        state.l7_sni = info.sni;
    }
    if state.l7_ja3.is_none() {
        state.l7_ja3 = info.ja3_hash;
    }
    if info.ech_detected {
        state.l7_ech_seen = true;
    }
}

fn is_doh_provider(sni: &str) -> bool {
    let s = sni.to_ascii_lowercase();
    DOH_PROVIDERS
        .iter()
        .any(|p| s == *p || s.ends_with(&format!(".{p}")))
}

fn flush_to_graph(
    aggregator: &mut FlowAggregator,
    session: &Arc<Session>,
    dataset_id: &str,
    total_new_entities: &mut usize,
    total_new_relations: &mut usize,
) -> Result<(), String> {
    if aggregator.pending_emit.is_empty() {
        return Ok(());
    }
    let events: Vec<RawIngestEvent> = std::mem::take(&mut aggregator.pending_emit);
    let (ne, nr) = match session.graph.write() {
        Ok(mut graph) => graph
            .insert_raw_events(events, Some(dataset_id))
            .map_err(|e| e.to_string())?,
        Err(_) => return Err("Graph lock poisoned".to_string()),
    };
    *total_new_entities += ne;
    *total_new_relations += nr;
    Ok(())
}

fn idle_timeout_us(proto: u8) -> u128 {
    match proto {
        PROTO_TCP => TCP_IDLE_US,
        PROTO_UDP => UDP_IDLE_US,
        PROTO_ICMP | PROTO_ICMP6 => ICMP_IDLE_US,
        _ => OTHER_IDLE_US,
    }
}

fn proto_name(p: u8) -> &'static str {
    match p {
        PROTO_TCP => "TCP",
        PROTO_UDP => "UDP",
        PROTO_ICMP => "ICMP",
        PROTO_ICMP6 => "ICMPv6",
        _ => "Other",
    }
}

fn fmt_tcp_flags(flags: u8) -> String {
    let mut v: Vec<&str> = Vec::with_capacity(6);
    if flags & FLAG_FIN != 0 { v.push("FIN"); }
    if flags & FLAG_SYN != 0 { v.push("SYN"); }
    if flags & FLAG_RST != 0 { v.push("RST"); }
    if flags & FLAG_PSH != 0 { v.push("PSH"); }
    if flags & FLAG_ACK != 0 { v.push("ACK"); }
    if flags & FLAG_URG != 0 { v.push("URG"); }
    v.join(",")
}

fn fmt_ipv4(o: &[u8; 4]) -> String {
    format!("{}.{}.{}.{}", o[0], o[1], o[2], o[3])
}

fn fmt_ipv6(o: &[u8; 16]) -> String {
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

#[cfg(test)]
mod tests {
    use super::*;

    fn new_agg() -> FlowAggregator {
        FlowAggregator::new("test.pcap".to_string())
    }

    /// Hand-build an Ethernet/IPv4/TCP frame with the given fields.
    /// Returns the bytes you can feed to `FlowAggregator::observe`.
    fn tcp_frame(
        src_ip: [u8; 4],
        dst_ip: [u8; 4],
        src_port: u16,
        dst_port: u16,
        flags: u8,
    ) -> Vec<u8> {
        let mut f = Vec::<u8>::new();
        // Ethernet
        f.extend_from_slice(&[0, 0, 0, 0, 0, 1]);
        f.extend_from_slice(&[0, 0, 0, 0, 0, 2]);
        f.extend_from_slice(&[0x08, 0x00]);
        // IPv4 (20B header, no options)
        let ip_start = f.len();
        f.push(0x45);
        f.push(0x00);
        f.extend_from_slice(&40u16.to_be_bytes()); // total length
        f.extend_from_slice(&0u16.to_be_bytes());
        f.extend_from_slice(&0x4000u16.to_be_bytes());
        f.push(64);
        f.push(6);
        f.extend_from_slice(&0u16.to_be_bytes()); // checksum placeholder
        f.extend_from_slice(&src_ip);
        f.extend_from_slice(&dst_ip);
        let csum = ip_checksum(&f[ip_start..ip_start + 20]);
        f[ip_start + 10..ip_start + 12].copy_from_slice(&csum.to_be_bytes());
        // TCP
        f.extend_from_slice(&src_port.to_be_bytes());
        f.extend_from_slice(&dst_port.to_be_bytes());
        f.extend_from_slice(&0u32.to_be_bytes()); // seq
        f.extend_from_slice(&0u32.to_be_bytes()); // ack
        f.push(0x50); // data offset = 5
        f.push(flags);
        f.extend_from_slice(&8192u16.to_be_bytes());
        f.extend_from_slice(&0u16.to_be_bytes()); // checksum
        f.extend_from_slice(&0u16.to_be_bytes());
        f
    }

    fn ip_checksum(bytes: &[u8]) -> u16 {
        let mut sum: u32 = 0;
        let mut i = 0;
        while i + 1 < bytes.len() {
            sum += u16::from_be_bytes([bytes[i], bytes[i + 1]]) as u32;
            i += 2;
        }
        while sum >> 16 != 0 {
            sum = (sum & 0xFFFF) + (sum >> 16);
        }
        !(sum as u16)
    }

    #[test]
    fn syn_then_fin_emits_one_complete_flow() {
        let mut agg = new_agg();
        let syn = tcp_frame([10, 0, 0, 1], [1, 1, 1, 1], 54321, 443, FLAG_SYN);
        let fin = tcp_frame([10, 0, 0, 1], [1, 1, 1, 1], 54321, 443, FLAG_FIN | FLAG_ACK);
        assert!(agg.observe(&syn, 1_000_000));
        assert!(agg.observe(&fin, 2_500_000));
        // FIN should have moved the flow to pending_emit.
        assert_eq!(agg.active.len(), 0, "FIN should close the flow");
        assert_eq!(agg.pending_emit.len(), 1, "exactly one flow emitted");
        let ev = &agg.pending_emit[0];
        assert_eq!(ev.src_id, "10.0.0.1");
        assert_eq!(ev.dst_id, "1.1.1.1");
        assert_eq!(ev.src_type, EntityType::IP);
        assert_eq!(ev.dst_type, EntityType::IP);
        assert_eq!(ev.rel_type, RelationType::Connect);
        assert_eq!(ev.timestamp, 1); // first_us = 1_000_000 → 1 second
        let m = &ev.rel_metadata;
        assert_eq!(m.get("source").map(String::as_str), Some("pcap"));
        assert_eq!(m.get("flow_complete").map(String::as_str), Some("true"));
        assert_eq!(m.get("protocol").map(String::as_str), Some("TCP"));
        assert_eq!(m.get("dst_port").map(String::as_str), Some("443"));
        assert_eq!(m.get("service").map(String::as_str), Some("HTTPS"));
        assert_eq!(m.get("packets_fwd").map(String::as_str), Some("2"));
        assert_eq!(m.get("packets_rev").map(String::as_str), Some("0"));
        // duration = last_us (2_500_000) - first_us (1_000_000) = 1_500_000 μs = 1500 ms.
        assert_eq!(m.get("duration_ms").map(String::as_str), Some("1500"));
        assert!(m.contains_key("flow_id"));
        assert_eq!(m.get("l7_decoded").map(String::as_str), Some("none"));
        let flags = m.get("tcp_flags").expect("tcp_flags");
        assert!(flags.contains("SYN"));
        assert!(flags.contains("FIN"));
    }

    #[test]
    fn reverse_packets_count_as_rev() {
        let mut agg = new_agg();
        let fwd = tcp_frame([10, 0, 0, 1], [1, 1, 1, 1], 54321, 443, FLAG_SYN);
        let rev = tcp_frame([1, 1, 1, 1], [10, 0, 0, 1], 443, 54321, FLAG_SYN | FLAG_ACK);
        agg.observe(&fwd, 1_000_000);
        agg.observe(&rev, 1_500_000);
        assert_eq!(agg.active.len(), 1, "still one flow, fwd direction owner");
        let state = agg.active.values().next().unwrap();
        assert_eq!(state.packets_fwd, 1);
        assert_eq!(state.packets_rev, 1);
        assert!(state.bytes_rev > 0);
    }

    #[test]
    fn idle_sweep_emits_stale_tcp_flow() {
        let mut agg = new_agg();
        let pkt = tcp_frame([10, 0, 0, 1], [1, 1, 1, 1], 54321, 443, FLAG_SYN);
        agg.observe(&pkt, 1_000_000);
        // Advance "now" by feeding a packet for a different flow far
        // in the future — older than TCP idle (300s).
        let unrelated = tcp_frame([10, 0, 0, 2], [2, 2, 2, 2], 55555, 80, FLAG_SYN);
        agg.observe(&unrelated, 1_000_000 + TCP_IDLE_US + 1);
        agg.sweep_idle();
        // The first flow timed out → emitted as flow_complete=false.
        let emitted = &agg.pending_emit;
        assert!(
            emitted.iter().any(|e| e.dst_id == "1.1.1.1"),
            "stale flow should have been swept"
        );
        let stale = emitted
            .iter()
            .find(|e| e.dst_id == "1.1.1.1")
            .unwrap();
        assert_eq!(
            stale.rel_metadata.get("flow_complete").map(String::as_str),
            Some("false")
        );
    }

    #[test]
    fn flush_all_drains_active() {
        let mut agg = new_agg();
        let pkt = tcp_frame([10, 0, 0, 1], [1, 1, 1, 1], 54321, 443, FLAG_SYN);
        agg.observe(&pkt, 1_000_000);
        assert_eq!(agg.active.len(), 1);
        agg.flush_all();
        assert_eq!(agg.active.len(), 0);
        assert_eq!(agg.pending_emit.len(), 1);
    }

    #[test]
    fn evict_oldest_keeps_newer_flows() {
        let mut agg = new_agg();
        // Three flows, distinct 5-tuples, increasing timestamps.
        for i in 1..=3u8 {
            let p = tcp_frame([10, 0, 0, i], [1, 1, 1, 1], 50000 + i as u16, 443, FLAG_SYN);
            agg.observe(&p, i as u128 * 1_000_000);
        }
        assert_eq!(agg.active.len(), 3);
        agg.evict_oldest(1);
        assert_eq!(agg.active.len(), 2);
        // The earliest (10.0.0.1) should be gone.
        assert!(!agg.active.keys().any(|k| k.src_ip == "10.0.0.1"));
        assert!(agg.active.keys().any(|k| k.src_ip == "10.0.0.3"));
        // And the evicted one was emitted with flow_complete=false.
        assert_eq!(agg.pending_emit.len(), 1);
        assert_eq!(
            agg.pending_emit[0]
                .rel_metadata
                .get("flow_complete")
                .map(String::as_str),
            Some("false")
        );
    }

    #[test]
    fn proto_name_covers_all_constants() {
        assert_eq!(proto_name(PROTO_TCP), "TCP");
        assert_eq!(proto_name(PROTO_UDP), "UDP");
        assert_eq!(proto_name(PROTO_ICMP), "ICMP");
        assert_eq!(proto_name(PROTO_ICMP6), "ICMPv6");
        assert_eq!(proto_name(99), "Other");
    }

    #[test]
    fn tcp_flag_formatting_in_canonical_order() {
        assert_eq!(fmt_tcp_flags(FLAG_SYN), "SYN");
        assert_eq!(fmt_tcp_flags(FLAG_SYN | FLAG_ACK), "SYN,ACK");
        assert_eq!(fmt_tcp_flags(FLAG_FIN | FLAG_ACK), "FIN,ACK");
        assert_eq!(fmt_tcp_flags(0xFF), "FIN,SYN,RST,PSH,ACK,URG");
    }

    #[test]
    fn ng_raw_to_us_handles_microseconds_default() {
        // resol = 6 means 10^6 units per sec → input is already μs.
        assert_eq!(ng_raw_to_us(1_500_000, 6), 1_500_000);
    }

    #[test]
    fn ng_raw_to_us_handles_nanoseconds() {
        // resol = 9 means 10^9 units per sec → input is ns. 1500ms = 1.5e9 ns → 1.5e6 μs.
        assert_eq!(ng_raw_to_us(1_500_000_000, 9), 1_500_000);
    }

    // ── PR1a integration: end-to-end L7 emission through the aggregator ──

    /// Same as `tcp_frame` but appends an L7 payload after the TCP
    /// header. Adjusts the IPv4 `total_length` so etherparse parses
    /// the full frame.
    fn tcp_frame_with_payload(
        src_ip: [u8; 4],
        dst_ip: [u8; 4],
        src_port: u16,
        dst_port: u16,
        flags: u8,
        payload: &[u8],
    ) -> Vec<u8> {
        let mut f = Vec::<u8>::new();
        f.extend_from_slice(&[0, 0, 0, 0, 0, 1]);
        f.extend_from_slice(&[0, 0, 0, 0, 0, 2]);
        f.extend_from_slice(&[0x08, 0x00]);
        let ip_start = f.len();
        f.push(0x45);
        f.push(0x00);
        let total_len = (20 + 20 + payload.len()) as u16;
        f.extend_from_slice(&total_len.to_be_bytes());
        f.extend_from_slice(&0u16.to_be_bytes());
        f.extend_from_slice(&0x4000u16.to_be_bytes());
        f.push(64);
        f.push(6);
        f.extend_from_slice(&0u16.to_be_bytes());
        f.extend_from_slice(&src_ip);
        f.extend_from_slice(&dst_ip);
        let csum = ip_checksum(&f[ip_start..ip_start + 20]);
        f[ip_start + 10..ip_start + 12].copy_from_slice(&csum.to_be_bytes());
        f.extend_from_slice(&src_port.to_be_bytes());
        f.extend_from_slice(&dst_port.to_be_bytes());
        f.extend_from_slice(&0u32.to_be_bytes());
        f.extend_from_slice(&0u32.to_be_bytes());
        f.push(0x50);
        f.push(flags);
        f.extend_from_slice(&8192u16.to_be_bytes());
        f.extend_from_slice(&0u16.to_be_bytes());
        f.extend_from_slice(&0u16.to_be_bytes());
        f.extend_from_slice(payload);
        f
    }

    /// Ethernet/IPv4/ICMP packet with the given type and code.
    fn icmp_frame(
        src_ip: [u8; 4],
        dst_ip: [u8; 4],
        icmp_type: u8,
        icmp_code: u8,
    ) -> Vec<u8> {
        let mut f = Vec::<u8>::new();
        f.extend_from_slice(&[0, 0, 0, 0, 0, 1]);
        f.extend_from_slice(&[0, 0, 0, 0, 0, 2]);
        f.extend_from_slice(&[0x08, 0x00]);
        let ip_start = f.len();
        f.push(0x45);
        f.push(0x00);
        let total_len = (20 + 8) as u16; // 20 IP + 8 minimum ICMP
        f.extend_from_slice(&total_len.to_be_bytes());
        f.extend_from_slice(&0u16.to_be_bytes());
        f.extend_from_slice(&0x4000u16.to_be_bytes());
        f.push(64);
        f.push(1); // proto = ICMP
        f.extend_from_slice(&0u16.to_be_bytes());
        f.extend_from_slice(&src_ip);
        f.extend_from_slice(&dst_ip);
        let csum = ip_checksum(&f[ip_start..ip_start + 20]);
        f[ip_start + 10..ip_start + 12].copy_from_slice(&csum.to_be_bytes());
        // ICMP datagram: type(1) + code(1) + checksum(2) + rest(4).
        f.push(icmp_type);
        f.push(icmp_code);
        f.extend_from_slice(&0u16.to_be_bytes()); // checksum
        f.extend_from_slice(&[0u8; 4]); // identifier + sequence
        f
    }

    #[test]
    fn ssh_banner_surfaces_on_emit() {
        let mut agg = new_agg();
        let banner = b"SSH-2.0-OpenSSH_9.4\r\n";
        let pkt = tcp_frame_with_payload(
            [10, 0, 0, 1], [1, 1, 1, 1], 50000, 22, FLAG_SYN | FLAG_ACK, banner,
        );
        agg.observe(&pkt, 1_000_000);
        agg.flush_all();
        let ev = agg
            .pending_emit
            .iter()
            .find(|e| e.dst_id == "1.1.1.1" && e.rel_type == RelationType::Connect)
            .expect("L4 edge emitted");
        let m = &ev.rel_metadata;
        assert_eq!(m.get("l7_decoded").map(String::as_str), Some("ssh_banner"));
        assert_eq!(
            m.get("ssh_banner").map(String::as_str),
            Some("SSH-2.0-OpenSSH_9.4"),
        );
    }

    #[test]
    fn ftp_user_emits_secondary_user_auth_edge() {
        let mut agg = new_agg();
        let pkt = tcp_frame_with_payload(
            [10, 0, 0, 1], [1, 1, 1, 1], 50001, 21, FLAG_SYN, b"USER alice\r\n",
        );
        agg.observe(&pkt, 1_000_000);
        agg.flush_all();

        // Primary Connect edge tagged with ftp_user.
        let l4 = agg
            .pending_emit
            .iter()
            .find(|e| e.rel_type == RelationType::Connect)
            .expect("L4 connect edge");
        assert_eq!(
            l4.rel_metadata.get("l7_decoded").map(String::as_str),
            Some("ftp_user"),
        );
        assert_eq!(
            l4.rel_metadata.get("ftp_user").map(String::as_str),
            Some("alice"),
        );

        // Secondary User -[Auth]-> IP edge.
        let auth = agg
            .pending_emit
            .iter()
            .find(|e| e.rel_type == RelationType::Auth)
            .expect("User -[Auth]-> IP edge emitted");
        assert_eq!(auth.src_id, "alice");
        assert_eq!(auth.src_type, EntityType::User);
        assert_eq!(auth.dst_id, "1.1.1.1");
        assert_eq!(auth.dst_type, EntityType::IP);
        assert_eq!(
            auth.rel_metadata.get("protocol").map(String::as_str),
            Some("FTP"),
        );
    }

    #[test]
    fn smb2_command_surfaces_on_emit() {
        let mut agg = new_agg();
        // 64-byte SMB2 header with SESSION_SETUP (cmd=0x0001).
        let mut hdr = vec![0u8; 64];
        hdr[0..4].copy_from_slice(b"\xfeSMB");
        hdr[4..6].copy_from_slice(&0x0040u16.to_le_bytes());
        hdr[12..14].copy_from_slice(&0x0001u16.to_le_bytes());
        let pkt = tcp_frame_with_payload(
            [10, 0, 0, 1], [1, 1, 1, 1], 50002, 445, FLAG_PSH | FLAG_ACK, &hdr,
        );
        agg.observe(&pkt, 1_000_000);
        agg.flush_all();
        let ev = agg
            .pending_emit
            .iter()
            .find(|e| e.rel_type == RelationType::Connect)
            .expect("L4 edge");
        assert_eq!(
            ev.rel_metadata.get("l7_decoded").map(String::as_str),
            Some("smb2"),
        );
        assert_eq!(
            ev.rel_metadata.get("smb2_command").map(String::as_str),
            Some("1"),
        );
        assert_eq!(
            ev.rel_metadata.get("smb2_command_name").map(String::as_str),
            Some("SESSION_SETUP"),
        );
    }

    // ── PR1b integration: Kerberos / LDAP / NTLM end-to-end ─────

    fn udp_frame_with_payload(
        src_ip: [u8; 4],
        dst_ip: [u8; 4],
        src_port: u16,
        dst_port: u16,
        payload: &[u8],
    ) -> Vec<u8> {
        let mut f = Vec::<u8>::new();
        f.extend_from_slice(&[0, 0, 0, 0, 0, 1]);
        f.extend_from_slice(&[0, 0, 0, 0, 0, 2]);
        f.extend_from_slice(&[0x08, 0x00]);
        let ip_start = f.len();
        f.push(0x45);
        f.push(0x00);
        let total_len = (20 + 8 + payload.len()) as u16;
        f.extend_from_slice(&total_len.to_be_bytes());
        f.extend_from_slice(&0u16.to_be_bytes());
        f.extend_from_slice(&0x4000u16.to_be_bytes());
        f.push(64);
        f.push(17); // proto = UDP
        f.extend_from_slice(&0u16.to_be_bytes());
        f.extend_from_slice(&src_ip);
        f.extend_from_slice(&dst_ip);
        let csum = ip_checksum(&f[ip_start..ip_start + 20]);
        f[ip_start + 10..ip_start + 12].copy_from_slice(&csum.to_be_bytes());
        // UDP header: src(2) + dst(2) + length(2) + checksum(2).
        f.extend_from_slice(&src_port.to_be_bytes());
        f.extend_from_slice(&dst_port.to_be_bytes());
        let udp_len = (8 + payload.len()) as u16;
        f.extend_from_slice(&udp_len.to_be_bytes());
        f.extend_from_slice(&0u16.to_be_bytes()); // checksum
        f.extend_from_slice(payload);
        f
    }

    /// Build the minimal Kerberos AS-REQ DER blob that
    /// `extract_kerberos_principal` accepts. Mirrors the test
    /// helper in `pcap_l7_auth.rs` but inlined here so we don't
    /// expose the helper to the world.
    fn build_minimal_as_req(cname: &str) -> Vec<u8> {
        const ASN1_SEQ: u8 = 0x30;
        const ASN1_GS: u8 = 0x1b;
        const CTX1: u8 = 0xa1;
        let mut name_seq_of: Vec<u8> = Vec::new();
        name_seq_of.push(ASN1_GS);
        name_seq_of.push(cname.len() as u8);
        name_seq_of.extend_from_slice(cname.as_bytes());
        let mut name_string = vec![ASN1_SEQ, name_seq_of.len() as u8];
        name_string.extend_from_slice(&name_seq_of);
        let mut name_string_tagged = vec![CTX1, name_string.len() as u8];
        name_string_tagged.extend_from_slice(&name_string);
        let mut princ_seq = vec![ASN1_SEQ, name_string_tagged.len() as u8];
        princ_seq.extend_from_slice(&name_string_tagged);
        let mut cname_tagged = vec![CTX1, princ_seq.len() as u8];
        cname_tagged.extend_from_slice(&princ_seq);
        let mut body_seq = vec![ASN1_SEQ, cname_tagged.len() as u8];
        body_seq.extend_from_slice(&cname_tagged);
        let mut req_body_tagged = vec![0xa4, body_seq.len() as u8];
        req_body_tagged.extend_from_slice(&body_seq);
        let mut req_seq = vec![ASN1_SEQ, req_body_tagged.len() as u8];
        req_seq.extend_from_slice(&req_body_tagged);
        let mut outer = vec![0x6a, req_seq.len() as u8];
        outer.extend_from_slice(&req_seq);
        outer
    }

    #[test]
    fn kerberos_udp88_emits_user_auth_edge() {
        let mut agg = new_agg();
        let payload = build_minimal_as_req("alice");
        let pkt = udp_frame_with_payload([10, 0, 0, 1], [10, 0, 0, 10], 50000, 88, &payload);
        agg.observe(&pkt, 1_000_000);
        agg.flush_all();

        // Primary Connect edge tagged with kerberos_user.
        let connect = agg
            .pending_emit
            .iter()
            .find(|e| e.rel_type == RelationType::Connect && e.dst_id == "10.0.0.10")
            .expect("L4 connect emitted");
        let m = &connect.rel_metadata;
        assert_eq!(m.get("l7_decoded").map(String::as_str), Some("kerberos"));
        assert_eq!(m.get("kerberos_user").map(String::as_str), Some("alice"));
        assert_eq!(m.get("kerberos_kind").map(String::as_str), Some("AS-REQ"));

        // Secondary User -[Auth]-> IP edge.
        let auth = agg
            .pending_emit
            .iter()
            .find(|e| e.rel_type == RelationType::Auth && e.src_id == "alice")
            .expect("User -[Auth]-> IP edge emitted");
        assert_eq!(auth.src_type, EntityType::User);
        assert_eq!(auth.dst_id, "10.0.0.10");
        assert_eq!(auth.dst_type, EntityType::IP);
        assert_eq!(
            auth.rel_metadata.get("protocol").map(String::as_str),
            Some("Kerberos"),
        );
    }

    #[test]
    fn ldap_tcp_emits_user_auth_edge_with_dn() {
        const ASN1_SEQ: u8 = 0x30;
        const ASN1_INT: u8 = 0x02;
        const ASN1_OS: u8 = 0x04;
        const LDAP_BIND: u8 = 0x60;
        let dn = "CN=alice,DC=example,DC=com";
        let mut body: Vec<u8> = vec![ASN1_INT, 0x01, 0x03];
        body.push(ASN1_OS);
        body.push(dn.len() as u8);
        body.extend_from_slice(dn.as_bytes());
        let mut bind = vec![LDAP_BIND, body.len() as u8];
        bind.extend_from_slice(&body);
        let mut inner: Vec<u8> = vec![ASN1_INT, 0x01, 0x01];
        inner.extend_from_slice(&bind);
        let mut msg = vec![ASN1_SEQ, inner.len() as u8];
        msg.extend_from_slice(&inner);

        let mut agg = new_agg();
        let pkt = tcp_frame_with_payload(
            [10, 0, 0, 1], [10, 0, 0, 20], 50001, 389, FLAG_PSH | FLAG_ACK, &msg,
        );
        agg.observe(&pkt, 1_000_000);
        agg.flush_all();

        let auth = agg
            .pending_emit
            .iter()
            .find(|e| e.rel_type == RelationType::Auth)
            .expect("User -[Auth]-> IP edge emitted");
        assert_eq!(auth.src_id, "CN=alice,DC=example,DC=com");
        assert_eq!(auth.src_type, EntityType::User);
        assert_eq!(auth.dst_id, "10.0.0.20");
        assert_eq!(
            auth.rel_metadata.get("protocol").map(String::as_str),
            Some("LDAP"),
        );
    }

    #[test]
    fn smb2_ntlm_emits_domain_user_auth_edge() {
        // SMB2 SESSION_SETUP header (64 B) + NTLMSSP Type 3 blob
        // immediately after. We synthesize the minimal NTLM Type 3
        // that the decoder accepts.
        let user = "alice";
        let domain = "EXAMPLE";
        // Encode user + domain as UTF-16-LE (Negotiate Unicode).
        let user_utf16: Vec<u8> = user
            .encode_utf16()
            .flat_map(|u| u.to_le_bytes())
            .collect();
        let dom_utf16: Vec<u8> = domain
            .encode_utf16()
            .flat_map(|u| u.to_le_bytes())
            .collect();
        let mut ntlm = vec![0u8; 64];
        ntlm[0..8].copy_from_slice(b"NTLMSSP\0");
        ntlm[8..12].copy_from_slice(&3u32.to_le_bytes());
        ntlm[60..64].copy_from_slice(&1u32.to_le_bytes()); // unicode flag
        let dom_off = 64u32;
        let user_off = dom_off + dom_utf16.len() as u32;
        ntlm[28..30].copy_from_slice(&(dom_utf16.len() as u16).to_le_bytes());
        ntlm[30..32].copy_from_slice(&(dom_utf16.len() as u16).to_le_bytes());
        ntlm[32..36].copy_from_slice(&dom_off.to_le_bytes());
        ntlm[36..38].copy_from_slice(&(user_utf16.len() as u16).to_le_bytes());
        ntlm[38..40].copy_from_slice(&(user_utf16.len() as u16).to_le_bytes());
        ntlm[40..44].copy_from_slice(&user_off.to_le_bytes());
        ntlm.extend_from_slice(&dom_utf16);
        ntlm.extend_from_slice(&user_utf16);

        // SMB2 SESSION_SETUP (cmd=0x0001) header.
        let mut smb = vec![0u8; 64];
        smb[0..4].copy_from_slice(b"\xfeSMB");
        smb[4..6].copy_from_slice(&0x0040u16.to_le_bytes());
        smb[12..14].copy_from_slice(&0x0001u16.to_le_bytes());
        smb.extend_from_slice(&ntlm);

        let mut agg = new_agg();
        let pkt = tcp_frame_with_payload(
            [10, 0, 0, 1], [10, 0, 0, 30], 50002, 445, FLAG_PSH | FLAG_ACK, &smb,
        );
        agg.observe(&pkt, 1_000_000);
        agg.flush_all();

        let connect = agg
            .pending_emit
            .iter()
            .find(|e| e.rel_type == RelationType::Connect)
            .expect("L4 edge");
        // SMB2 wins l7_decoded over NTLM because the chain visits
        // SMB2 first; that's intentional and documented in emit().
        assert_eq!(
            connect.rel_metadata.get("l7_decoded").map(String::as_str),
            Some("smb2"),
        );

        let auth = agg
            .pending_emit
            .iter()
            .find(|e| e.rel_type == RelationType::Auth)
            .expect("User -[Auth]-> IP edge emitted");
        assert_eq!(auth.src_id, "EXAMPLE\\alice");
        assert_eq!(auth.src_type, EntityType::User);
        assert_eq!(auth.dst_id, "10.0.0.30");
        assert_eq!(
            auth.rel_metadata.get("protocol").map(String::as_str),
            Some("NTLM"),
        );
        assert_eq!(
            auth.rel_metadata.get("ntlm_user").map(String::as_str),
            Some("alice"),
        );
        assert_eq!(
            auth.rel_metadata.get("ntlm_domain").map(String::as_str),
            Some("EXAMPLE"),
        );
    }

    #[test]
    fn icmp_type_code_on_connect_edge() {
        let mut agg = new_agg();
        // ICMP type 8 (Echo Request), code 0.
        let pkt = icmp_frame([10, 0, 0, 1], [1, 1, 1, 1], 8, 0);
        agg.observe(&pkt, 1_000_000);
        agg.flush_all();
        let ev = agg
            .pending_emit
            .iter()
            .find(|e| e.dst_id == "1.1.1.1")
            .expect("ICMP edge");
        assert_eq!(
            ev.rel_metadata.get("protocol").map(String::as_str),
            Some("ICMP"),
        );
        assert_eq!(
            ev.rel_metadata.get("icmp_type").map(String::as_str),
            Some("8"),
        );
        assert_eq!(
            ev.rel_metadata.get("icmp_code").map(String::as_str),
            Some("0"),
        );
    }
}
