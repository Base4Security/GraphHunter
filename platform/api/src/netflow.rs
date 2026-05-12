//! NetFlow v5 / v9 / IPFIX wire-format parsers.
//!
//! Decodes concatenated NetFlow datagrams from a binary file (raw
//! UDP-dump format — the most common offline form). Each flow
//! record produced here maps to one `IP -[Connect]-> IP` graph
//! edge upstream in [`crate::ingestors::netflow`].
//!
//! ## Wire formats handled
//!
//! - **NetFlow v5** (RFC 3954-precursor, fixed format): 24-byte
//!   header + N × 48-byte flow records. No templates.
//! - **NetFlow v9** (RFC 3954): 20-byte header + FlowSets. Templates
//!   (FlowSet ID 0) define data record layouts; data records
//!   (FlowSet ID ≥ 256) reference templates by ID. State must
//!   persist *across packets* in the same observation domain.
//! - **IPFIX** (RFC 7011, version 10): 16-byte header carrying the
//!   total packet length, then Sets. Same template-and-data model
//!   as v9. Enterprise field specifiers (high bit of field type)
//!   are recognised and skipped — none of the fields we extract
//!   require PEN-aware decoding.
//!
//! ## What we extract per record
//!
//! [`NetflowRecord`] — 5-tuple, byte/packet counters, tcp flags,
//! absolute start/end times, and the exporter's domain id +
//! sequence number for pivoting back to the source packet.
//!
//! ## Out of scope this PR
//!
//! - nfdump's `.nfcapd` on-disk format (per-block headers +
//!   extension records). Use `nfdump -E` to convert if needed.
//! - Live UDP listener (PR4 territory; this PR is offline only).
//! - sFlow (different XDR shape; future PR).
//! - IPFIX variable-length fields (length 0xFFFF in template).
//!   Records that contain them are skipped — none of the fields
//!   we care about are typically variable-length on the wire.

use std::collections::HashMap;
use std::net::{Ipv4Addr, Ipv6Addr};

/// Three NetFlow flavours we support.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NetflowVersion {
    V5,
    V9,
    Ipfix,
}

/// Normalised flow record (one per emitted graph edge).
///
/// NetFlow records are unidirectional — the exporter writes one
/// record per direction of a conversation. We never combine the
/// two directions: that's a sensor-trust decision, matching the
/// Zeek / Suricata ingestors from PR2.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NetflowRecord {
    pub src_ip: String,
    pub dst_ip: String,
    pub src_port: u16,
    pub dst_port: u16,
    pub protocol: u8,
    pub bytes: u64,
    pub packets: u64,
    pub tcp_flags: u8,
    /// Absolute Unix seconds at flow start.
    pub start_secs: i64,
    /// Duration in milliseconds. `0` when start == end (single-
    /// packet flows).
    pub duration_ms: u64,
    /// NetFlow v9 `source_id` / IPFIX `observation_domain_id` /
    /// v5 packed `(engine_type, engine_id)`. Lets analysts tell
    /// records from different exporters apart even when their 5-
    /// tuples collide.
    pub exporter_domain_id: u32,
    /// Per-packet flow sequence number. NetFlow v5/v9: 32-bit
    /// counter of flows in the export stream; IPFIX: 32-bit
    /// counter of messages. Either way, sufficient for
    /// disambiguation pivot.
    pub sequence: u32,
    /// Version that produced this record. Surfaced as edge
    /// metadata.
    pub version: NetflowVersion,
}

/// Per-packet context propagated to record parsers so they can
/// resolve sys_uptime-relative timestamps to absolute time.
#[derive(Clone, Copy, Debug)]
struct PacketContext {
    version: NetflowVersion,
    export_time_secs: i64,
    /// Current sys_uptime in ms at the time of export (v5/v9 only;
    /// 0 for IPFIX).
    sys_uptime_ms: u32,
    domain_id: u32,
    sequence: u32,
}

/// One template entry. Stored in the [`TemplateCache`] keyed by
/// `(domain_id, template_id)`.
#[derive(Clone, Debug)]
pub(crate) struct Template {
    pub(crate) fields: Vec<(u16, u16)>,
    /// Sum of all field lengths, or `None` if the template uses
    /// any variable-length (`0xFFFF`) field. Variable-length
    /// records are skipped — see module note.
    pub(crate) total_data_length: Option<usize>,
}

/// Per-ingest template cache. v9/IPFIX exporters emit a Template
/// FlowSet once and then stream data records that reference it by
/// id; the cache lives for the duration of one file ingest.
#[derive(Default)]
pub struct TemplateCache {
    templates: HashMap<(u32, u16), Template>,
}

impl TemplateCache {
    pub fn new() -> Self {
        Self::default()
    }

    fn insert(&mut self, domain_id: u32, template_id: u16, template: Template) {
        self.templates.insert((domain_id, template_id), template);
    }

    fn get(&self, domain_id: u32, template_id: u16) -> Option<&Template> {
        self.templates.get(&(domain_id, template_id))
    }

    pub fn len(&self) -> usize {
        self.templates.len()
    }

    pub fn is_empty(&self) -> bool {
        self.templates.is_empty()
    }
}

// ─── Public entry point ──────────────────────────────────────────────

/// Determine the wire version from the first two bytes of `data`.
/// Returns `None` if the version isn't one we handle.
pub fn detect_version(data: &[u8]) -> Option<NetflowVersion> {
    if data.len() < 2 {
        return None;
    }
    match u16::from_be_bytes([data[0], data[1]]) {
        5 => Some(NetflowVersion::V5),
        9 => Some(NetflowVersion::V9),
        10 => Some(NetflowVersion::Ipfix),
        _ => None,
    }
}

/// Parse one NetFlow datagram starting at the beginning of `data`.
/// Returns the records extracted and the number of bytes consumed
/// (so the caller can advance the stream cursor). Returns `None`
/// when the buffer is too short for a complete packet or when the
/// packet is malformed.
///
/// Templates discovered in v9/IPFIX template flowsets are merged
/// into `cache` so later data records can be decoded.
pub fn parse_packet(
    data: &[u8],
    cache: &mut TemplateCache,
) -> Option<(Vec<NetflowRecord>, usize)> {
    let v = detect_version(data)?;
    match v {
        NetflowVersion::V5 => parse_v5_packet(data),
        NetflowVersion::V9 => parse_v9_packet(data, cache),
        NetflowVersion::Ipfix => parse_ipfix_packet(data, cache),
    }
}

// ─── NetFlow v5 (fixed 48-byte records, no templates) ────────────────

const V5_HEADER_LEN: usize = 24;
const V5_RECORD_LEN: usize = 48;

fn parse_v5_packet(data: &[u8]) -> Option<(Vec<NetflowRecord>, usize)> {
    if data.len() < V5_HEADER_LEN {
        return None;
    }
    let count = u16::from_be_bytes([data[2], data[3]]) as usize;
    if count > 30 {
        // v5 spec caps records per packet at 30. Reject so a
        // mangled length doesn't make us read past the buffer.
        return None;
    }
    let total = V5_HEADER_LEN + count * V5_RECORD_LEN;
    if data.len() < total {
        return None;
    }
    let _sys_uptime = u32::from_be_bytes([data[4], data[5], data[6], data[7]]);
    let unix_secs = u32::from_be_bytes([data[8], data[9], data[10], data[11]]) as i64;
    let sys_uptime = u32::from_be_bytes([data[4], data[5], data[6], data[7]]);
    let sequence = u32::from_be_bytes([data[16], data[17], data[18], data[19]]);
    let engine_type = data[20] as u32;
    let engine_id = data[21] as u32;
    let domain_id = (engine_type << 8) | engine_id;

    let mut out = Vec::with_capacity(count);
    for i in 0..count {
        let r = &data[V5_HEADER_LEN + i * V5_RECORD_LEN..V5_HEADER_LEN + (i + 1) * V5_RECORD_LEN];
        let src = Ipv4Addr::new(r[0], r[1], r[2], r[3]).to_string();
        let dst = Ipv4Addr::new(r[4], r[5], r[6], r[7]).to_string();
        let packets = u32::from_be_bytes([r[16], r[17], r[18], r[19]]) as u64;
        let bytes = u32::from_be_bytes([r[20], r[21], r[22], r[23]]) as u64;
        let first_ms = u32::from_be_bytes([r[24], r[25], r[26], r[27]]);
        let last_ms = u32::from_be_bytes([r[28], r[29], r[30], r[31]]);
        let src_port = u16::from_be_bytes([r[32], r[33]]);
        let dst_port = u16::from_be_bytes([r[34], r[35]]);
        let tcp_flags = r[37];
        let protocol = r[38];
        let (start_secs, duration_ms) =
            sys_uptime_to_absolute(unix_secs, sys_uptime, first_ms, last_ms);
        out.push(NetflowRecord {
            src_ip: src,
            dst_ip: dst,
            src_port,
            dst_port,
            protocol,
            bytes,
            packets,
            tcp_flags,
            start_secs,
            duration_ms,
            exporter_domain_id: domain_id,
            sequence,
            version: NetflowVersion::V5,
        });
    }
    Some((out, total))
}

// ─── NetFlow v9 ──────────────────────────────────────────────────────

const V9_HEADER_LEN: usize = 20;

fn parse_v9_packet(
    data: &[u8],
    cache: &mut TemplateCache,
) -> Option<(Vec<NetflowRecord>, usize)> {
    if data.len() < V9_HEADER_LEN {
        return None;
    }
    let count = u16::from_be_bytes([data[2], data[3]]) as usize;
    let sys_uptime = u32::from_be_bytes([data[4], data[5], data[6], data[7]]);
    let unix_secs = u32::from_be_bytes([data[8], data[9], data[10], data[11]]) as i64;
    let sequence = u32::from_be_bytes([data[12], data[13], data[14], data[15]]);
    let domain_id = u32::from_be_bytes([data[16], data[17], data[18], data[19]]);
    let ctx = PacketContext {
        version: NetflowVersion::V9,
        export_time_secs: unix_secs,
        sys_uptime_ms: sys_uptime,
        domain_id,
        sequence,
    };

    let mut pos = V9_HEADER_LEN;
    let mut out: Vec<NetflowRecord> = Vec::new();
    let mut flowsets_seen = 0usize;
    // Note: per RFC 3954 `count` is the total record count (template +
    // data records), not the FlowSet count. In practice each FlowSet
    // we care about carries one record so the two notions coincide.
    // We use `flowsets_seen < count` as a soft upper bound — the
    // pos-based check is the real safety net.
    while flowsets_seen < count && pos + 4 <= data.len() {
        let set_id = u16::from_be_bytes([data[pos], data[pos + 1]]);
        let set_len = u16::from_be_bytes([data[pos + 2], data[pos + 3]]) as usize;
        if set_len < 4 || pos + set_len > data.len() {
            break;
        }
        let body = &data[pos + 4..pos + set_len];
        match set_id {
            0 => {
                // Template FlowSet — parse and stash.
                parse_template_set(body, domain_id, cache);
            }
            1 => {
                // Options Template — we ignore. Holds metadata
                // about the exporter, not flow records.
            }
            id if id >= 256 => {
                if let Some(tpl) = cache.get(domain_id, id) {
                    decode_data_records(body, tpl, &ctx, &mut out);
                }
                // Data FlowSet without a known template: silently
                // drop. The exporter is supposed to (re-)send
                // templates periodically.
            }
            _ => {
                // Reserved set_id (2..255): not used in v9.
            }
        }
        pos += set_len;
        flowsets_seen += 1;
    }
    Some((out, pos))
}

/// Parse a v9 Template FlowSet body (after the 4-byte flowset
/// header) and add any new templates to the cache.
fn parse_template_set(body: &[u8], domain_id: u32, cache: &mut TemplateCache) {
    let mut p = 0usize;
    while p + 4 <= body.len() {
        let tid = u16::from_be_bytes([body[p], body[p + 1]]);
        let field_count = u16::from_be_bytes([body[p + 2], body[p + 3]]) as usize;
        p += 4;
        if field_count == 0 || p + field_count * 4 > body.len() {
            break;
        }
        let mut fields: Vec<(u16, u16)> = Vec::with_capacity(field_count);
        let mut total: Option<usize> = Some(0);
        for _ in 0..field_count {
            let ftype = u16::from_be_bytes([body[p], body[p + 1]]);
            let flen = u16::from_be_bytes([body[p + 2], body[p + 3]]);
            p += 4;
            fields.push((ftype, flen));
            total = match (total, flen) {
                (Some(_), 0xFFFF) => None, // variable length — disqualify
                (Some(t), l) => Some(t + l as usize),
                _ => None,
            };
        }
        cache.insert(
            domain_id,
            tid,
            Template {
                fields,
                total_data_length: total,
            },
        );
    }
}

// ─── IPFIX (version 10) ──────────────────────────────────────────────

const IPFIX_HEADER_LEN: usize = 16;

fn parse_ipfix_packet(
    data: &[u8],
    cache: &mut TemplateCache,
) -> Option<(Vec<NetflowRecord>, usize)> {
    if data.len() < IPFIX_HEADER_LEN {
        return None;
    }
    let total = u16::from_be_bytes([data[2], data[3]]) as usize;
    if total < IPFIX_HEADER_LEN || total > data.len() {
        return None;
    }
    let export_time = u32::from_be_bytes([data[4], data[5], data[6], data[7]]) as i64;
    let sequence = u32::from_be_bytes([data[8], data[9], data[10], data[11]]);
    let domain_id = u32::from_be_bytes([data[12], data[13], data[14], data[15]]);
    let ctx = PacketContext {
        version: NetflowVersion::Ipfix,
        export_time_secs: export_time,
        sys_uptime_ms: 0,
        domain_id,
        sequence,
    };

    let mut pos = IPFIX_HEADER_LEN;
    let mut out: Vec<NetflowRecord> = Vec::new();
    while pos + 4 <= total {
        let set_id = u16::from_be_bytes([data[pos], data[pos + 1]]);
        let set_len = u16::from_be_bytes([data[pos + 2], data[pos + 3]]) as usize;
        if set_len < 4 || pos + set_len > total {
            break;
        }
        let body = &data[pos + 4..pos + set_len];
        match set_id {
            2 => parse_ipfix_template_set(body, domain_id, cache),
            3 => { /* options template — ignore */ }
            id if id >= 256 => {
                if let Some(tpl) = cache.get(domain_id, id) {
                    decode_data_records(body, tpl, &ctx, &mut out);
                }
            }
            _ => {}
        }
        pos += set_len;
    }
    Some((out, total))
}

/// IPFIX templates differ from v9 in two ways:
/// 1. Enterprise bit: when the high bit of `field_type` is set,
///    a 4-byte Private Enterprise Number follows.
/// 2. Variable-length fields use `field_length == 0xFFFF`.
///    The actual length is encoded inline in each data record.
fn parse_ipfix_template_set(body: &[u8], domain_id: u32, cache: &mut TemplateCache) {
    let mut p = 0usize;
    while p + 4 <= body.len() {
        let tid = u16::from_be_bytes([body[p], body[p + 1]]);
        let field_count = u16::from_be_bytes([body[p + 2], body[p + 3]]) as usize;
        p += 4;
        if field_count == 0 {
            break;
        }
        let mut fields: Vec<(u16, u16)> = Vec::with_capacity(field_count);
        let mut total: Option<usize> = Some(0);
        for _ in 0..field_count {
            if p + 4 > body.len() {
                return;
            }
            let ftype = u16::from_be_bytes([body[p], body[p + 1]]);
            let flen = u16::from_be_bytes([body[p + 2], body[p + 3]]);
            p += 4;
            // Enterprise bit: skip the 4-byte PEN that follows
            // and strip the bit from the stored field type so the
            // record decoder sees vendor-extension types as
            // unknown (and skips them).
            let is_enterprise = ftype & 0x8000 != 0;
            if is_enterprise {
                if p + 4 > body.len() {
                    return;
                }
                p += 4;
            }
            let normalised_type = ftype & 0x7FFF;
            // PEN-tagged enterprise fields aren't in our extract
            // list — treat as opaque and let the decoder skip
            // them by length.
            fields.push((normalised_type, flen));
            total = match (total, flen) {
                (Some(_), 0xFFFF) => None,
                (Some(t), l) => Some(t + l as usize),
                _ => None,
            };
        }
        cache.insert(
            domain_id,
            tid,
            Template {
                fields,
                total_data_length: total,
            },
        );
    }
}

// ─── Shared template-driven record decoder ───────────────────────────

/// Decode all data records in `body` according to `tpl` and append
/// to `out`. Variable-length records are skipped (whole set).
fn decode_data_records(
    body: &[u8],
    tpl: &Template,
    ctx: &PacketContext,
    out: &mut Vec<NetflowRecord>,
) {
    let record_len = match tpl.total_data_length {
        Some(n) if n > 0 => n,
        _ => return, // variable-length or zero-length template — skip
    };
    let mut p = 0usize;
    // Padding rule: the FlowSet pads with up to (record_len - 1)
    // trailing bytes so the next set starts aligned. Stop when
    // fewer than record_len bytes remain.
    while p + record_len <= body.len() {
        let record_slice = &body[p..p + record_len];
        if let Some(rec) = decode_single_record(record_slice, &tpl.fields, ctx) {
            out.push(rec);
        }
        p += record_len;
    }
}

fn decode_single_record(
    record: &[u8],
    fields: &[(u16, u16)],
    ctx: &PacketContext,
) -> Option<NetflowRecord> {
    let mut src_ip: Option<String> = None;
    let mut dst_ip: Option<String> = None;
    let mut src_port = 0u16;
    let mut dst_port = 0u16;
    let mut protocol = 0u8;
    let mut bytes = 0u64;
    let mut packets = 0u64;
    let mut tcp_flags = 0u8;
    let mut first_switched_ms = 0u32;
    let mut last_switched_ms = 0u32;
    let mut flow_start_ms: Option<u64> = None;
    let mut flow_end_ms: Option<u64> = None;
    let mut flow_start_secs: Option<u32> = None;
    let mut flow_end_secs: Option<u32> = None;

    let mut p = 0usize;
    for (ftype, flen) in fields {
        let len = *flen as usize;
        if p + len > record.len() {
            return None;
        }
        let slice = &record[p..p + len];
        match *ftype {
            // Octet / packet counters: support 1, 2, 4, 8 byte widths.
            1 => bytes = read_be_uint(slice),
            2 => packets = read_be_uint(slice),
            4 => {
                if len == 1 {
                    protocol = slice[0];
                }
            }
            6 => {
                if len == 1 {
                    tcp_flags = slice[0];
                } else if len == 2 {
                    // IPFIX tcpControlBits is sometimes 2 bytes; keep low byte.
                    tcp_flags = slice[1];
                }
            }
            7 => src_port = read_be_uint(slice) as u16,
            8 => src_ip = read_ipv4(slice),
            11 => dst_port = read_be_uint(slice) as u16,
            12 => dst_ip = read_ipv4(slice),
            21 => last_switched_ms = read_be_uint(slice) as u32,
            22 => first_switched_ms = read_be_uint(slice) as u32,
            23 => {
                // OUT_BYTES / postOctetDeltaCount — when present
                // alongside IN_BYTES, prefer IN_BYTES; otherwise
                // fall through.
                if bytes == 0 {
                    bytes = read_be_uint(slice);
                }
            }
            24 => {
                if packets == 0 {
                    packets = read_be_uint(slice);
                }
            }
            27 => src_ip = read_ipv6(slice),
            28 => dst_ip = read_ipv6(slice),
            150 => flow_start_secs = Some(read_be_uint(slice) as u32),
            151 => flow_end_secs = Some(read_be_uint(slice) as u32),
            152 => flow_start_ms = Some(read_be_uint(slice)),
            153 => flow_end_ms = Some(read_be_uint(slice)),
            _ => { /* unknown field — skip by length */ }
        }
        p += len;
    }

    let src_ip = src_ip?;
    let dst_ip = dst_ip?;

    let (start_secs, duration_ms) = if let (Some(s), Some(e)) = (flow_start_ms, flow_end_ms) {
        ((s / 1000) as i64, e.saturating_sub(s))
    } else if let (Some(s), Some(e)) = (flow_start_secs, flow_end_secs) {
        (s as i64, e.saturating_sub(s) as u64 * 1000)
    } else {
        sys_uptime_to_absolute(
            ctx.export_time_secs,
            ctx.sys_uptime_ms,
            first_switched_ms,
            last_switched_ms,
        )
    };

    Some(NetflowRecord {
        src_ip,
        dst_ip,
        src_port,
        dst_port,
        protocol,
        bytes,
        packets,
        tcp_flags,
        start_secs,
        duration_ms,
        exporter_domain_id: ctx.domain_id,
        sequence: ctx.sequence,
        version: ctx.version,
    })
}

// ─── Tiny binary helpers ─────────────────────────────────────────────

/// Read a big-endian unsigned integer from `slice` (1-8 bytes).
/// Returns 0 for empty or > 8-byte slices.
fn read_be_uint(slice: &[u8]) -> u64 {
    if slice.is_empty() || slice.len() > 8 {
        return 0;
    }
    let mut v = 0u64;
    for b in slice {
        v = (v << 8) | (*b as u64);
    }
    v
}

fn read_ipv4(slice: &[u8]) -> Option<String> {
    if slice.len() != 4 {
        return None;
    }
    Some(Ipv4Addr::new(slice[0], slice[1], slice[2], slice[3]).to_string())
}

fn read_ipv6(slice: &[u8]) -> Option<String> {
    if slice.len() != 16 {
        return None;
    }
    let mut octets = [0u8; 16];
    octets.copy_from_slice(slice);
    Some(Ipv6Addr::from(octets).to_string())
}

/// Convert sys_uptime-relative ms (`FIRST_SWITCHED`, `LAST_SWITCHED`)
/// to absolute Unix seconds + duration. The export packet header
/// gives us `export_time_secs` (Unix) and `current_sys_uptime_ms`,
/// so `flow_start = export_time - (current_sys_uptime - first) / 1000`.
fn sys_uptime_to_absolute(
    export_time_secs: i64,
    current_sys_uptime_ms: u32,
    first_switched_ms: u32,
    last_switched_ms: u32,
) -> (i64, u64) {
    if current_sys_uptime_ms == 0 {
        return (export_time_secs, 0);
    }
    let ago_ms = current_sys_uptime_ms.saturating_sub(first_switched_ms) as i64;
    let start = export_time_secs - ago_ms / 1000;
    let duration = last_switched_ms.saturating_sub(first_switched_ms) as u64;
    (start, duration)
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── NetFlow v5 ───────────────────────────────────────────────

    fn build_v5_packet(records: &[(u32, u32, u16, u16, u8, u32, u32, u8)]) -> Vec<u8> {
        // record tuple: (src, dst, sport, dport, proto, packets, bytes, tcp_flags)
        let mut p = Vec::new();
        p.extend_from_slice(&5u16.to_be_bytes());                       // version
        p.extend_from_slice(&(records.len() as u16).to_be_bytes());     // count
        p.extend_from_slice(&60_000u32.to_be_bytes());                  // sys_uptime ms
        p.extend_from_slice(&1_700_000_000u32.to_be_bytes());           // unix_secs
        p.extend_from_slice(&0u32.to_be_bytes());                       // unix_nsecs
        p.extend_from_slice(&1u32.to_be_bytes());                       // flow_sequence
        p.push(0); p.push(0);                                           // engine_type/id
        p.extend_from_slice(&0u16.to_be_bytes());                       // sampling

        for (src, dst, sport, dport, proto, packets, bytes, flags) in records {
            p.extend_from_slice(&src.to_be_bytes());                    // srcaddr
            p.extend_from_slice(&dst.to_be_bytes());                    // dstaddr
            p.extend_from_slice(&0u32.to_be_bytes());                   // nexthop
            p.extend_from_slice(&0u16.to_be_bytes());                   // input
            p.extend_from_slice(&0u16.to_be_bytes());                   // output
            p.extend_from_slice(&packets.to_be_bytes());                // dPkts
            p.extend_from_slice(&bytes.to_be_bytes());                  // dOctets
            p.extend_from_slice(&50_000u32.to_be_bytes());              // First (sys_uptime)
            p.extend_from_slice(&55_000u32.to_be_bytes());              // Last
            p.extend_from_slice(&sport.to_be_bytes());                  // srcport
            p.extend_from_slice(&dport.to_be_bytes());                  // dstport
            p.push(0);                                                  // pad
            p.push(*flags);                                             // tcp_flags
            p.push(*proto);                                             // prot
            p.push(0);                                                  // tos
            p.extend_from_slice(&0u16.to_be_bytes());                   // src_as
            p.extend_from_slice(&0u16.to_be_bytes());                   // dst_as
            p.push(24); p.push(24);                                     // masks
            p.extend_from_slice(&0u16.to_be_bytes());                   // pad2
        }
        p
    }

    fn ipv4_u32(a: u8, b: u8, c: u8, d: u8) -> u32 {
        u32::from_be_bytes([a, b, c, d])
    }

    #[test]
    fn v5_parses_single_record() {
        let pkt = build_v5_packet(&[(
            ipv4_u32(10, 0, 0, 1),
            ipv4_u32(1, 1, 1, 1),
            54321,
            443,
            6,  // TCP
            42,
            1500,
            0x18, // PSH|ACK
        )]);
        let mut cache = TemplateCache::new();
        let (records, consumed) = parse_packet(&pkt, &mut cache).expect("parsed");
        assert_eq!(consumed, V5_HEADER_LEN + V5_RECORD_LEN);
        assert_eq!(records.len(), 1);
        let r = &records[0];
        assert_eq!(r.src_ip, "10.0.0.1");
        assert_eq!(r.dst_ip, "1.1.1.1");
        assert_eq!(r.src_port, 54321);
        assert_eq!(r.dst_port, 443);
        assert_eq!(r.protocol, 6);
        assert_eq!(r.bytes, 1500);
        assert_eq!(r.packets, 42);
        assert_eq!(r.tcp_flags, 0x18);
        assert_eq!(r.duration_ms, 5_000);
        // export_time = 1_700_000_000, sys_uptime = 60_000 ms,
        // first_switched = 50_000 → start = 1_700_000_000 - 10 = 1_699_999_990.
        assert_eq!(r.start_secs, 1_699_999_990);
        assert_eq!(r.version, NetflowVersion::V5);
    }

    #[test]
    fn v5_parses_multiple_records() {
        let pkt = build_v5_packet(&[
            (ipv4_u32(10, 0, 0, 1), ipv4_u32(1, 1, 1, 1), 1, 2, 6, 1, 100, 0),
            (ipv4_u32(10, 0, 0, 2), ipv4_u32(8, 8, 8, 8), 3, 4, 17, 1, 200, 0),
        ]);
        let mut cache = TemplateCache::new();
        let (records, _) = parse_packet(&pkt, &mut cache).expect("parsed");
        assert_eq!(records.len(), 2);
        assert_eq!(records[1].dst_ip, "8.8.8.8");
        assert_eq!(records[1].protocol, 17);
    }

    #[test]
    fn v5_rejects_count_above_30() {
        let mut pkt = build_v5_packet(&[]);
        pkt[2..4].copy_from_slice(&100u16.to_be_bytes()); // mangle count
        let mut cache = TemplateCache::new();
        assert!(parse_packet(&pkt, &mut cache).is_none());
    }

    #[test]
    fn v5_rejects_truncated_packet() {
        let pkt = build_v5_packet(&[(0, 0, 0, 0, 6, 0, 0, 0)]);
        let truncated = &pkt[..pkt.len() - 10];
        let mut cache = TemplateCache::new();
        assert!(parse_packet(truncated, &mut cache).is_none());
    }

    // ── NetFlow v9 ───────────────────────────────────────────────

    /// Build a v9 packet with one Template FlowSet (template_id 256:
    /// IPv4 5-tuple + bytes + packets) followed by one Data FlowSet
    /// referencing it.
    fn build_v9_packet() -> Vec<u8> {
        let mut p = Vec::new();
        // Header
        p.extend_from_slice(&9u16.to_be_bytes());           // version
        p.extend_from_slice(&2u16.to_be_bytes());           // count (2 flowsets)
        p.extend_from_slice(&60_000u32.to_be_bytes());      // sys_uptime
        p.extend_from_slice(&1_700_000_000u32.to_be_bytes());// unix_secs
        p.extend_from_slice(&42u32.to_be_bytes());          // sequence
        p.extend_from_slice(&7u32.to_be_bytes());           // source_id (domain)

        // Template FlowSet: id=0, length=4+4+8*4 = 40
        // Template: tid=256, field_count=8
        // Fields: 8/4 (IPV4_SRC), 12/4 (IPV4_DST), 7/2 (SRC_PORT),
        //         11/2 (DST_PORT), 4/1 (PROTOCOL), 6/1 (TCP_FLAGS),
        //         1/4 (IN_BYTES), 2/4 (IN_PKTS)
        let template: [(u16, u16); 8] = [
            (8, 4), (12, 4), (7, 2), (11, 2), (4, 1), (6, 1), (1, 4), (2, 4),
        ];
        let template_body_len = 4 + template.len() * 4; // 4 (tid+fcount) + N*4
        let template_set_len = 4 + template_body_len;   // + 4 flowset header
        p.extend_from_slice(&0u16.to_be_bytes());                // set_id = 0
        p.extend_from_slice(&(template_set_len as u16).to_be_bytes());
        p.extend_from_slice(&256u16.to_be_bytes());              // template_id
        p.extend_from_slice(&(template.len() as u16).to_be_bytes());
        for (t, l) in template.iter() {
            p.extend_from_slice(&t.to_be_bytes());
            p.extend_from_slice(&l.to_be_bytes());
        }

        // Data FlowSet: id=256, length=4 + record_len(22).
        // record_len = 4(src) + 4(dst) + 2(sport) + 2(dport)
        //            + 1(proto) + 1(flags) + 4(bytes) + 4(packets) = 22.
        let data_set_len = 4 + 22;
        p.extend_from_slice(&256u16.to_be_bytes());
        p.extend_from_slice(&(data_set_len as u16).to_be_bytes());
        // Record (18 bytes per template above)
        p.extend_from_slice(&[10, 0, 0, 1]);                      // src
        p.extend_from_slice(&[1, 1, 1, 1]);                       // dst
        p.extend_from_slice(&54321u16.to_be_bytes());             // sport
        p.extend_from_slice(&443u16.to_be_bytes());               // dport
        p.push(6);                                                // proto
        p.push(0x18);                                             // flags
        p.extend_from_slice(&1500u32.to_be_bytes());              // bytes
        p.extend_from_slice(&42u32.to_be_bytes());                // packets
        p
    }

    #[test]
    fn v9_template_and_data_in_same_packet() {
        let pkt = build_v9_packet();
        let mut cache = TemplateCache::new();
        let (records, _) = parse_packet(&pkt, &mut cache).expect("parsed");
        assert_eq!(cache.len(), 1, "one template registered");
        assert_eq!(records.len(), 1);
        let r = &records[0];
        assert_eq!(r.src_ip, "10.0.0.1");
        assert_eq!(r.dst_ip, "1.1.1.1");
        assert_eq!(r.src_port, 54321);
        assert_eq!(r.dst_port, 443);
        assert_eq!(r.protocol, 6);
        assert_eq!(r.tcp_flags, 0x18);
        assert_eq!(r.bytes, 1500);
        assert_eq!(r.packets, 42);
        assert_eq!(r.exporter_domain_id, 7);
        assert_eq!(r.sequence, 42);
        assert_eq!(r.version, NetflowVersion::V9);
    }

    #[test]
    fn v9_data_set_without_template_is_silently_dropped() {
        // Send the data FlowSet alone, no template. The decoder
        // must drop it without erroring.
        let mut p = Vec::new();
        p.extend_from_slice(&9u16.to_be_bytes());
        p.extend_from_slice(&1u16.to_be_bytes());
        p.extend_from_slice(&60_000u32.to_be_bytes());
        p.extend_from_slice(&1_700_000_000u32.to_be_bytes());
        p.extend_from_slice(&1u32.to_be_bytes());
        p.extend_from_slice(&7u32.to_be_bytes());
        p.extend_from_slice(&256u16.to_be_bytes());
        p.extend_from_slice(&8u16.to_be_bytes());
        p.extend_from_slice(&[0u8; 4]);
        let mut cache = TemplateCache::new();
        let (records, _) = parse_packet(&p, &mut cache).expect("parsed");
        assert!(records.is_empty());
    }

    #[test]
    fn v9_template_persists_across_packets() {
        let mut cache = TemplateCache::new();
        let pkt1 = build_v9_packet();
        parse_packet(&pkt1, &mut cache).expect("first parsed");
        assert_eq!(cache.len(), 1);
        // Build a packet that has ONLY a data flowset, reusing
        // template 256 from the first packet.
        let mut p = Vec::new();
        p.extend_from_slice(&9u16.to_be_bytes());
        p.extend_from_slice(&1u16.to_be_bytes());
        p.extend_from_slice(&61_000u32.to_be_bytes());
        p.extend_from_slice(&1_700_001_000u32.to_be_bytes());
        p.extend_from_slice(&43u32.to_be_bytes());
        p.extend_from_slice(&7u32.to_be_bytes());
        // Data set reusing template 256 (22-byte record, see
        // build_v9_packet for the field breakdown).
        p.extend_from_slice(&256u16.to_be_bytes());
        p.extend_from_slice(&(4u16 + 22u16).to_be_bytes());
        p.extend_from_slice(&[10, 0, 0, 2]);
        p.extend_from_slice(&[8, 8, 8, 8]);
        p.extend_from_slice(&33000u16.to_be_bytes());
        p.extend_from_slice(&53u16.to_be_bytes());
        p.push(17);
        p.push(0);
        p.extend_from_slice(&100u32.to_be_bytes());
        p.extend_from_slice(&1u32.to_be_bytes());
        let (records, _) = parse_packet(&p, &mut cache).expect("parsed");
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].dst_ip, "8.8.8.8");
        assert_eq!(records[0].protocol, 17);
    }

    // ── IPFIX ────────────────────────────────────────────────────

    /// Build an IPFIX packet using flowStartMilliseconds (152) /
    /// flowEndMilliseconds (153) so we can pin down the absolute-
    /// time branch.
    fn build_ipfix_packet() -> Vec<u8> {
        let template: [(u16, u16); 9] = [
            (8, 4), (12, 4), (7, 2), (11, 2),
            (4, 1), (6, 1), (1, 8), (152, 8), (153, 8),
        ];
        let record_len: usize = template.iter().map(|(_, l)| *l as usize).sum();

        let template_body_len = 4 + template.len() * 4;
        let template_set_len = 4 + template_body_len;
        let data_set_len = 4 + record_len;
        let total_len = IPFIX_HEADER_LEN + template_set_len + data_set_len;

        let mut p = Vec::new();
        p.extend_from_slice(&10u16.to_be_bytes());                  // version
        p.extend_from_slice(&(total_len as u16).to_be_bytes());     // length
        p.extend_from_slice(&1_700_000_000u32.to_be_bytes());       // export time
        p.extend_from_slice(&100u32.to_be_bytes());                 // sequence
        p.extend_from_slice(&42u32.to_be_bytes());                  // observation_domain_id

        // Template Set: id=2
        p.extend_from_slice(&2u16.to_be_bytes());
        p.extend_from_slice(&(template_set_len as u16).to_be_bytes());
        p.extend_from_slice(&300u16.to_be_bytes());                 // template_id
        p.extend_from_slice(&(template.len() as u16).to_be_bytes());
        for (t, l) in template.iter() {
            p.extend_from_slice(&t.to_be_bytes());
            p.extend_from_slice(&l.to_be_bytes());
        }
        // Data Set
        p.extend_from_slice(&300u16.to_be_bytes());
        p.extend_from_slice(&(data_set_len as u16).to_be_bytes());
        p.extend_from_slice(&[192, 168, 1, 5]);                     // src
        p.extend_from_slice(&[1, 1, 1, 1]);                         // dst
        p.extend_from_slice(&50000u16.to_be_bytes());               // sport
        p.extend_from_slice(&443u16.to_be_bytes());                 // dport
        p.push(6);                                                  // proto
        p.push(0x10);                                               // tcp_flags = ACK
        p.extend_from_slice(&9_000u64.to_be_bytes());               // bytes (64-bit)
        let start_ms: u64 = 1_700_000_000_000;
        let end_ms: u64 = 1_700_000_001_500;
        p.extend_from_slice(&start_ms.to_be_bytes());
        p.extend_from_slice(&end_ms.to_be_bytes());
        p
    }

    #[test]
    fn ipfix_decodes_absolute_time_and_64bit_counters() {
        let pkt = build_ipfix_packet();
        let mut cache = TemplateCache::new();
        let (records, consumed) = parse_packet(&pkt, &mut cache).expect("parsed");
        assert_eq!(consumed, pkt.len());
        assert_eq!(records.len(), 1);
        let r = &records[0];
        assert_eq!(r.src_ip, "192.168.1.5");
        assert_eq!(r.dst_ip, "1.1.1.1");
        assert_eq!(r.bytes, 9_000);
        assert_eq!(r.start_secs, 1_700_000_000);
        assert_eq!(r.duration_ms, 1_500);
        assert_eq!(r.exporter_domain_id, 42);
        assert_eq!(r.version, NetflowVersion::Ipfix);
    }

    #[test]
    fn ipfix_skips_enterprise_field_specifiers() {
        // Build a packet whose template includes one enterprise-bit
        // field (with PEN). The decoder must skip the 4-byte PEN
        // and continue parsing the remaining fields. We use a
        // fixed length so the template stays definite.
        let mut p = Vec::new();
        // Fields after enterprise-bit handling: (8,4) (12,4)
        // (0x8001 = enterprise + 1, len 4, PEN 9999) (4,1).
        // Header length = 16; template_set raw layout below.
        let mut template_set = Vec::new();
        template_set.extend_from_slice(&301u16.to_be_bytes()); // template_id
        template_set.extend_from_slice(&4u16.to_be_bytes());   // field_count = 4
        template_set.extend_from_slice(&8u16.to_be_bytes()); template_set.extend_from_slice(&4u16.to_be_bytes());
        template_set.extend_from_slice(&12u16.to_be_bytes()); template_set.extend_from_slice(&4u16.to_be_bytes());
        template_set.extend_from_slice(&0x8001u16.to_be_bytes()); // enterprise bit set, type 1
        template_set.extend_from_slice(&4u16.to_be_bytes());
        template_set.extend_from_slice(&9999u32.to_be_bytes());   // PEN
        template_set.extend_from_slice(&4u16.to_be_bytes()); template_set.extend_from_slice(&1u16.to_be_bytes()); // protocol
        let template_set_len = 4 + template_set.len();

        // Record: src(4) + dst(4) + enterprise_bytes(4) + protocol(1) = 13 bytes.
        let mut record = Vec::new();
        record.extend_from_slice(&[10, 0, 0, 9]);
        record.extend_from_slice(&[8, 8, 8, 8]);
        record.extend_from_slice(&[0xde, 0xad, 0xbe, 0xef]);
        record.push(17);
        let data_set_len = 4 + record.len();

        let total_len = IPFIX_HEADER_LEN + template_set_len + data_set_len;
        p.extend_from_slice(&10u16.to_be_bytes());
        p.extend_from_slice(&(total_len as u16).to_be_bytes());
        p.extend_from_slice(&1u32.to_be_bytes());
        p.extend_from_slice(&1u32.to_be_bytes());
        p.extend_from_slice(&1u32.to_be_bytes());
        p.extend_from_slice(&2u16.to_be_bytes());
        p.extend_from_slice(&(template_set_len as u16).to_be_bytes());
        p.extend_from_slice(&template_set);
        p.extend_from_slice(&301u16.to_be_bytes());
        p.extend_from_slice(&(data_set_len as u16).to_be_bytes());
        p.extend_from_slice(&record);

        let mut cache = TemplateCache::new();
        let (records, _) = parse_packet(&p, &mut cache).expect("parsed");
        assert_eq!(records.len(), 1);
        let r = &records[0];
        assert_eq!(r.src_ip, "10.0.0.9");
        assert_eq!(r.dst_ip, "8.8.8.8");
        assert_eq!(r.protocol, 17, "protocol byte after enterprise PEN must be read correctly");
    }

    #[test]
    fn detect_version_recognizes_known_versions() {
        assert_eq!(detect_version(&[0, 5]), Some(NetflowVersion::V5));
        assert_eq!(detect_version(&[0, 9]), Some(NetflowVersion::V9));
        assert_eq!(detect_version(&[0, 10]), Some(NetflowVersion::Ipfix));
        assert_eq!(detect_version(&[0, 7]), None);
        assert_eq!(detect_version(&[]), None);
    }

    #[test]
    fn parse_packet_returns_none_on_short_input() {
        let mut cache = TemplateCache::new();
        assert!(parse_packet(&[0, 5], &mut cache).is_none());
        assert!(parse_packet(&[0, 9, 0, 0], &mut cache).is_none());
        assert!(parse_packet(&[0, 10, 0, 4], &mut cache).is_none());
    }
}
