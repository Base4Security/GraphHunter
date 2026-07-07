//! Suricata `eve.json` ingestor.
//!
//! Suricata is an IDS/IPS that writes all its observations into one
//! line-delimited JSON file (`eve.json`) with an `event_type` field
//! that says what each record is (`flow`, `alert`, `dns`, `http`,
//! `tls`, `smb`, `krb5`, …). One line = one event.
//!
//! Like the Zeek ingestor, we **trust the sensor**: no re-aggregation,
//! one graph edge per record, Suricata's own `flow_id` preserved as
//! `sensor_uid` so analysts can pivot back.
//!
//! ## Scope (PR2)
//!
//! Event types handled:
//! - `flow`  → `IP -[Connect]-> IP` (5-tuple + bytes + duration).
//! - `dns`   → `IP -[DNS]-> Domain` (queries only; responses ignored).
//! - `http`  → `IP -[Connect]-> Domain` (Host header).
//! - `tls`   → `IP -[Connect]-> Domain` (SNI + JA3).
//! - `alert` → tags the underlying `IP -[Connect]-> IP` edge with
//!   `suricata_alert_signature`, `suricata_alert_severity`, and
//!   `suricata_alert_category`. An alert without flow context still
//!   emits the L4 edge so the alert isn't silently dropped.
//!
//! Deferred to PR1b: `smb`, `krb5` (need the User-entity story
//! shared with PCAP / Zeek Kerberos+SMB decoders).
//!
//! ## Sniff
//!
//! The defining tell of `eve.json` is the `event_type` field on the
//! first JSON object. Generic JSON-lines (e.g. arbitrary application
//! logs) almost never carry that exact key, so the confidence is
//! `200` — high enough to beat any future fallback path, low enough
//! to lose to PCAP/EVTX magic.

use std::collections::HashMap;
use std::io::{BufRead, BufReader};
use std::path::Path;

use graph_hunter_core::{EntityType, RawIngestEvent, RelationType};

use super::{IngestContext, StreamingIngestor};
use crate::ingestors::zeek::{emit_progress, flush, read_first_line};

const BATCH_FLUSH_SIZE: usize = 5_000;
const PROGRESS_EVERY_N_LINES: u64 = 5_000;

pub struct SuricataIngestor;

impl SuricataIngestor {
    pub fn new() -> Self {
        Self
    }
}

impl Default for SuricataIngestor {
    fn default() -> Self {
        Self::new()
    }
}

impl StreamingIngestor for SuricataIngestor {
    fn name(&self) -> &'static str {
        "suricata"
    }

    fn aliases(&self) -> &'static [&'static str] {
        &["eve"]
    }

    /// Same reasoning as Zeek: don't claim `.json` outright — too
    /// generic, would steal arbitrary JSON files from the tabular
    /// pipeline.
    fn extensions(&self) -> &'static [&'static str] {
        &[]
    }

    /// Confidence `200`: the first JSON object has an `event_type`
    /// field whose value is one of the well-known Suricata event
    /// names. We require the value match too — `"event_type":
    /// "user_login"` (some other tool) shouldn't qualify.
    fn sniff(&self, path: &Path, _magic: &[u8]) -> Option<u8> {
        let line = read_first_line(path)?;
        let v: serde_json::Value = serde_json::from_str(&line).ok()?;
        let evt = v.as_object()?.get("event_type")?.as_str()?;
        if is_known_suricata_event(evt) {
            Some(200)
        } else {
            None
        }
    }

    fn ingest(&self, ctx: IngestContext<'_>) -> Result<(usize, usize), String> {
        let file = std::fs::File::open(ctx.path)
            .map_err(|e| format!("Failed to open Suricata eve.json '{}': {e}", ctx.path))?;
        let bytes_total = file.metadata().map(|m| m.len()).unwrap_or(0);
        let reader = BufReader::with_capacity(8 * 1024 * 1024, file);
        let source_file = Path::new(ctx.path)
            .file_name()
            .and_then(|s| s.to_str())
            .unwrap_or("")
            .to_string();

        let mut total_new_entities = 0usize;
        let mut total_new_relations = 0usize;
        let mut pending: Vec<RawIngestEvent> = Vec::with_capacity(BATCH_FLUSH_SIZE);
        let mut lines_seen = 0u64;
        let mut bytes_seen = 0u64;

        for line in reader.lines() {
            let line = match line {
                Ok(s) => s,
                Err(_) => continue,
            };
            bytes_seen = bytes_seen.saturating_add(line.len() as u64 + 1);
            lines_seen += 1;
            if line.trim().is_empty() {
                continue;
            }
            let v: serde_json::Value = match serde_json::from_str(&line) {
                Ok(v) => v,
                Err(_) => continue,
            };
            if let Some(ev) = parse_record(&v, &source_file) {
                pending.push(ev);
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
            if lines_seen.is_multiple_of(PROGRESS_EVERY_N_LINES) {
                emit_progress(
                    ctx.emitter,
                    bytes_seen,
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
        Ok((total_new_entities, total_new_relations))
    }
}

// ─── Internals ───────────────────────────────────────────────────────

pub(crate) fn is_known_suricata_event(s: &str) -> bool {
    matches!(
        s,
        "flow" | "alert" | "dns" | "http" | "tls" | "smb" | "krb5" | "ssh" | "netflow"
    )
}

/// Parse a single Suricata record. Returns `None` for event types
/// we don't map (e.g. `stats`, `fileinfo`).
pub(crate) fn parse_record(
    v: &serde_json::Value,
    source_file: &str,
) -> Option<RawIngestEvent> {
    let evt = v.get("event_type").and_then(|x| x.as_str())?;
    match evt {
        "flow" => parse_flow(v, source_file),
        "alert" => parse_alert(v, source_file),
        "dns" => parse_dns(v, source_file),
        "http" => parse_http(v, source_file),
        "tls" => parse_tls(v, source_file),
        "krb5" => parse_krb5(v, source_file),
        "smb" => parse_smb(v, source_file),
        _ => None,
    }
}

fn parse_flow(v: &serde_json::Value, source_file: &str) -> Option<RawIngestEvent> {
    let (src_ip, dst_ip, src_port, dst_port, proto) = suricata_5tuple(v)?;
    let ts = suricata_ts(v).unwrap_or(0);
    let mut md = HashMap::with_capacity(16);
    base_metadata(&mut md, v, source_file, "flow", &proto, src_port, dst_port);
    if let Some(flow) = v.get("flow").and_then(|f| f.as_object()) {
        if let Some(b) = flow.get("bytes_toserver").and_then(|x| x.as_u64()) {
            md.insert("bytes_fwd".to_string(), b.to_string());
        }
        if let Some(b) = flow.get("bytes_toclient").and_then(|x| x.as_u64()) {
            md.insert("bytes_rev".to_string(), b.to_string());
        }
        if let Some(p) = flow.get("pkts_toserver").and_then(|x| x.as_u64()) {
            md.insert("packets_fwd".to_string(), p.to_string());
        }
        if let Some(p) = flow.get("pkts_toclient").and_then(|x| x.as_u64()) {
            md.insert("packets_rev".to_string(), p.to_string());
        }
        if let Some(s) = flow.get("state").and_then(|x| x.as_str()) {
            md.insert("flow_state".to_string(), s.to_string());
        }
    }
    if let Some(app) = v.get("app_proto").and_then(|x| x.as_str()) {
        md.insert("service".to_string(), app.to_string());
    }
    Some(RawIngestEvent {
        src_id: src_ip,
        src_type: EntityType::IP,
        src_metadata: HashMap::new(),
        dst_id: dst_ip,
        dst_type: EntityType::IP,
        dst_metadata: HashMap::new(),
        rel_type: RelationType::Connect,
        rel_metadata: md,
        timestamp: ts,
    })
}

fn parse_alert(v: &serde_json::Value, source_file: &str) -> Option<RawIngestEvent> {
    // Tag the underlying L4 edge with alert details. Suricata alerts
    // always carry the 5-tuple of the offending packet.
    let (src_ip, dst_ip, src_port, dst_port, proto) = suricata_5tuple(v)?;
    let ts = suricata_ts(v).unwrap_or(0);
    let mut md = HashMap::with_capacity(16);
    base_metadata(&mut md, v, source_file, "alert", &proto, src_port, dst_port);
    let alert = v.get("alert").and_then(|a| a.as_object())?;
    if let Some(s) = alert.get("signature").and_then(|x| x.as_str()) {
        md.insert("suricata_alert_signature".to_string(), s.to_string());
    }
    if let Some(s) = alert.get("category").and_then(|x| x.as_str()) {
        md.insert("suricata_alert_category".to_string(), s.to_string());
    }
    if let Some(sev) = alert.get("severity").and_then(|x| x.as_u64()) {
        md.insert("suricata_alert_severity".to_string(), sev.to_string());
    }
    if let Some(sid) = alert.get("signature_id").and_then(|x| x.as_u64()) {
        md.insert("suricata_alert_sid".to_string(), sid.to_string());
    }
    Some(RawIngestEvent {
        src_id: src_ip,
        src_type: EntityType::IP,
        src_metadata: HashMap::new(),
        dst_id: dst_ip,
        dst_type: EntityType::IP,
        dst_metadata: HashMap::new(),
        rel_type: RelationType::Connect,
        rel_metadata: md,
        timestamp: ts,
    })
}

fn parse_dns(v: &serde_json::Value, source_file: &str) -> Option<RawIngestEvent> {
    let (src_ip, dst_ip, src_port, dst_port, proto) = suricata_5tuple(v)?;
    let dns = v.get("dns").and_then(|d| d.as_object())?;
    // We only emit edges for queries. Responses repeat the same
    // rrname and would double-count.
    let dns_type = dns.get("type").and_then(|x| x.as_str()).unwrap_or("");
    if dns_type != "query" {
        return None;
    }
    let qname = dns.get("rrname").and_then(|x| x.as_str())?.to_string();
    if qname.is_empty() {
        return None;
    }
    let ts = suricata_ts(v).unwrap_or(0);
    let mut md = HashMap::with_capacity(10);
    base_metadata(&mut md, v, source_file, "dns", &proto, src_port, dst_port);
    md.insert("l7_decoded".to_string(), "dns_query".to_string());
    md.insert("qname".to_string(), qname.clone());
    if let Some(t) = dns.get("rrtype").and_then(|x| x.as_str()) {
        md.insert("qtype".to_string(), t.to_string());
    }
    md.insert("resolver".to_string(), dst_ip);
    Some(RawIngestEvent {
        src_id: src_ip,
        src_type: EntityType::IP,
        src_metadata: HashMap::new(),
        dst_id: qname,
        dst_type: EntityType::Domain,
        dst_metadata: HashMap::new(),
        rel_type: RelationType::DNS,
        rel_metadata: md,
        timestamp: ts,
    })
}

fn parse_http(v: &serde_json::Value, source_file: &str) -> Option<RawIngestEvent> {
    let (src_ip, _dst_ip, src_port, dst_port, proto) = suricata_5tuple(v)?;
    let http = v.get("http").and_then(|h| h.as_object())?;
    let host = http
        .get("hostname")
        .or_else(|| http.get("http_host"))
        .and_then(|x| x.as_str())?
        .to_string();
    if host.is_empty() {
        return None;
    }
    let ts = suricata_ts(v).unwrap_or(0);
    let mut md = HashMap::with_capacity(10);
    base_metadata(&mut md, v, source_file, "http", &proto, src_port, dst_port);
    md.insert("l7_decoded".to_string(), "http_host".to_string());
    md.insert("http_host".to_string(), host.clone());
    if let Some(m) = http.get("http_method").and_then(|x| x.as_str()) {
        md.insert("http_method".to_string(), m.to_string());
    }
    if let Some(s) = http.get("status").and_then(|x| x.as_u64()) {
        md.insert("http_status".to_string(), s.to_string());
    }
    Some(RawIngestEvent {
        src_id: src_ip,
        src_type: EntityType::IP,
        src_metadata: HashMap::new(),
        dst_id: host,
        dst_type: EntityType::Domain,
        dst_metadata: HashMap::new(),
        rel_type: RelationType::Connect,
        rel_metadata: md,
        timestamp: ts,
    })
}

fn parse_tls(v: &serde_json::Value, source_file: &str) -> Option<RawIngestEvent> {
    let (src_ip, _dst_ip, src_port, dst_port, proto) = suricata_5tuple(v)?;
    let tls = v.get("tls").and_then(|t| t.as_object())?;
    let sni = tls.get("sni").and_then(|x| x.as_str())?.to_string();
    if sni.is_empty() {
        return None;
    }
    let ts = suricata_ts(v).unwrap_or(0);
    let mut md = HashMap::with_capacity(10);
    base_metadata(&mut md, v, source_file, "tls", &proto, src_port, dst_port);
    md.insert("l7_decoded".to_string(), "tls_sni".to_string());
    md.insert("sni".to_string(), sni.clone());
    if let Some(ja3) = tls
        .get("ja3")
        .and_then(|j| j.as_object())
        .and_then(|m| m.get("hash"))
        .and_then(|x| x.as_str())
    {
        md.insert("ja3".to_string(), ja3.to_string());
    }
    if let Some(ja3s) = tls
        .get("ja3s")
        .and_then(|j| j.as_object())
        .and_then(|m| m.get("hash"))
        .and_then(|x| x.as_str())
    {
        md.insert("ja3s".to_string(), ja3s.to_string());
    }
    if let Some(v_) = tls.get("version").and_then(|x| x.as_str()) {
        md.insert("tls_version".to_string(), v_.to_string());
    }
    Some(RawIngestEvent {
        src_id: src_ip,
        src_type: EntityType::IP,
        src_metadata: HashMap::new(),
        dst_id: sni,
        dst_type: EntityType::Domain,
        dst_metadata: HashMap::new(),
        rel_type: RelationType::Connect,
        rel_metadata: md,
        timestamp: ts,
    })
}

fn parse_krb5(v: &serde_json::Value, source_file: &str) -> Option<RawIngestEvent> {
    let (_, dst_ip, src_port, dst_port, proto) = suricata_5tuple(v)?;
    let krb5 = v.get("krb5").and_then(|k| k.as_object())?;
    let msg_type = krb5.get("msg_type").and_then(|x| x.as_str()).unwrap_or("");
    // Only request messages carry the cname; responses repeat it
    // but at this point in the conversation the AS-REQ/TGS-REQ
    // edge is already in the graph.
    let kind = match msg_type {
        "AS-REQ" => "AS-REQ",
        "TGS-REQ" => "TGS-REQ",
        _ => return None,
    };
    let cname = krb5.get("cname").and_then(|x| x.as_str())?.to_string();
    if cname.is_empty() {
        return None;
    }
    let ts = suricata_ts(v).unwrap_or(0);
    let mut md = HashMap::with_capacity(12);
    base_metadata(&mut md, v, source_file, "krb5", &proto, src_port, dst_port);
    md.insert("l7_decoded".to_string(), "kerberos".to_string());
    md.insert("kerberos_kind".to_string(), kind.to_string());
    md.insert("kerberos_user".to_string(), cname.clone());
    if let Some(r) = krb5.get("realm").and_then(|x| x.as_str()) {
        md.insert("kerberos_realm".to_string(), r.to_string());
    }
    if let Some(s) = krb5.get("sname").and_then(|x| x.as_str()) {
        md.insert("kerberos_service".to_string(), s.to_string());
    }
    Some(RawIngestEvent {
        src_id: cname,
        src_type: EntityType::User,
        src_metadata: HashMap::new(),
        dst_id: dst_ip,
        dst_type: EntityType::IP,
        dst_metadata: HashMap::new(),
        rel_type: RelationType::Auth,
        rel_metadata: md,
        timestamp: ts,
    })
}

fn parse_smb(v: &serde_json::Value, source_file: &str) -> Option<RawIngestEvent> {
    // Only emit a User-Auth edge when Suricata actually decoded the
    // NTLMSSP blob inside SESSION_SETUP. Other SMB commands (READ,
    // WRITE, …) don't carry authentication material; they'd land
    // as duplicate connect edges with no User signal.
    let (_, dst_ip, src_port, dst_port, proto) = suricata_5tuple(v)?;
    let smb = v.get("smb").and_then(|s| s.as_object())?;
    let ntlm = smb.get("ntlmssp").and_then(|n| n.as_object())?;
    let user = ntlm.get("user").and_then(|x| x.as_str())?.to_string();
    if user.is_empty() {
        return None;
    }
    let domain = ntlm
        .get("domain")
        .and_then(|x| x.as_str())
        .unwrap_or("")
        .to_string();
    let user_id = if domain.is_empty() {
        user.clone()
    } else {
        format!("{domain}\\{user}")
    };
    let ts = suricata_ts(v).unwrap_or(0);
    let mut md = HashMap::with_capacity(12);
    base_metadata(&mut md, v, source_file, "smb", &proto, src_port, dst_port);
    md.insert("l7_decoded".to_string(), "ntlm_auth".to_string());
    md.insert("protocol".to_string(), "NTLM".to_string());
    md.insert("ntlm_user".to_string(), user);
    if !domain.is_empty() {
        md.insert("ntlm_domain".to_string(), domain);
    }
    if let Some(cmd) = smb.get("command").and_then(|x| x.as_str()) {
        md.insert("smb_command".to_string(), cmd.to_string());
    }
    if let Some(d) = smb.get("dialect").and_then(|x| x.as_str()) {
        md.insert("smb_dialect".to_string(), d.to_string());
    }
    Some(RawIngestEvent {
        src_id: user_id,
        src_type: EntityType::User,
        src_metadata: HashMap::new(),
        dst_id: dst_ip,
        dst_type: EntityType::IP,
        dst_metadata: HashMap::new(),
        rel_type: RelationType::Auth,
        rel_metadata: md,
        timestamp: ts,
    })
}

// ─── Helpers ─────────────────────────────────────────────────────────

fn suricata_5tuple(v: &serde_json::Value) -> Option<(String, String, u16, u16, String)> {
    let src_ip = v.get("src_ip").and_then(|x| x.as_str())?.to_string();
    let dst_ip = v.get("dest_ip").and_then(|x| x.as_str())?.to_string();
    let src_port = v
        .get("src_port")
        .and_then(|x| x.as_u64())
        .map(|n| n as u16)
        .unwrap_or(0);
    let dst_port = v
        .get("dest_port")
        .and_then(|x| x.as_u64())
        .map(|n| n as u16)
        .unwrap_or(0);
    let proto = v
        .get("proto")
        .and_then(|x| x.as_str())
        .unwrap_or("unknown")
        .to_string();
    Some((src_ip, dst_ip, src_port, dst_port, proto))
}

/// Parse the ISO 8601 timestamp Suricata emits, e.g.
/// `2024-01-15T12:34:56.789012+0000`. Returns whole seconds since
/// epoch, `None` if the field is missing or unparseable.
pub(crate) fn suricata_ts(v: &serde_json::Value) -> Option<i64> {
    let s = v.get("timestamp").and_then(|t| t.as_str())?;
    // chrono's DateTime parser accepts both `+0000` and `+00:00`
    // offsets via `parse_from_str` with `%z`, and `from_rfc3339`
    // handles `+00:00`. Try the rfc3339 path first since it's the
    // strict form; fall back to a permissive parser for Suricata's
    // common `+0000` (no colon) form.
    if let Ok(dt) = chrono::DateTime::parse_from_rfc3339(s) {
        return Some(dt.timestamp());
    }
    if let Ok(dt) = chrono::DateTime::parse_from_str(s, "%Y-%m-%dT%H:%M:%S%.f%z") {
        return Some(dt.timestamp());
    }
    None
}

fn base_metadata(
    md: &mut HashMap<String, String>,
    v: &serde_json::Value,
    source_file: &str,
    event_type: &str,
    proto: &str,
    src_port: u16,
    dst_port: u16,
) {
    md.insert("source".to_string(), "suricata".to_string());
    md.insert("event_type".to_string(), event_type.to_string());
    if !source_file.is_empty() {
        md.insert("source_file".to_string(), source_file.to_string());
    }
    if let Some(fid) = v.get("flow_id").and_then(|x| x.as_u64()) {
        md.insert("sensor_uid".to_string(), fid.to_string());
    }
    if let Some(iface) = v.get("in_iface").and_then(|x| x.as_str()) {
        md.insert("in_iface".to_string(), iface.to_string());
    }
    md.insert("protocol".to_string(), proto.to_uppercase());
    if src_port != 0 {
        md.insert("src_port".to_string(), src_port.to_string());
    }
    if dst_port != 0 {
        md.insert("dst_port".to_string(), dst_port.to_string());
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn tmp(name: &str, body: &str) -> std::path::PathBuf {
        let p = std::env::temp_dir().join(name);
        std::fs::write(&p, body).unwrap();
        p
    }

    #[test]
    fn sniff_accepts_eve_json_with_event_type() {
        let body = r#"{"timestamp":"2024-01-15T12:00:00.000+0000","event_type":"flow","src_ip":"10.0.0.1","dest_ip":"1.1.1.1","proto":"TCP"}"#;
        let p = tmp("suricata_sniff_eve.json", &format!("{body}\n"));
        let ing = SuricataIngestor::new();
        assert_eq!(ing.sniff(&p, &[]), Some(200));
        std::fs::remove_file(&p).ok();
    }

    #[test]
    fn sniff_rejects_event_type_with_unknown_value() {
        // Some other tool's JSON-lines might use `event_type`. Only
        // accept values we recognise as Suricata's vocabulary.
        let body = r#"{"event_type":"user_login","actor":"alice"}"#;
        let p = tmp("suricata_sniff_other.json", &format!("{body}\n"));
        let ing = SuricataIngestor::new();
        assert_eq!(ing.sniff(&p, &[]), None);
        std::fs::remove_file(&p).ok();
    }

    #[test]
    fn sniff_rejects_generic_json_without_event_type() {
        let body = r#"{"foo":"bar","src_ip":"10.0.0.1"}"#;
        let p = tmp("suricata_sniff_generic.json", &format!("{body}\n"));
        let ing = SuricataIngestor::new();
        assert_eq!(ing.sniff(&p, &[]), None);
        std::fs::remove_file(&p).ok();
    }

    #[test]
    fn parse_flow_event() {
        let v = json!({
            "timestamp": "2024-01-15T12:00:00.000+0000",
            "event_type": "flow",
            "flow_id": 12345,
            "src_ip": "10.0.0.1",
            "src_port": 50000,
            "dest_ip": "1.1.1.1",
            "dest_port": 443,
            "proto": "TCP",
            "app_proto": "tls",
            "flow": {
                "bytes_toserver": 500,
                "bytes_toclient": 9000,
                "pkts_toserver": 8,
                "pkts_toclient": 12,
                "state": "established"
            }
        });
        let e = parse_record(&v, "eve.json").expect("parsed");
        assert_eq!(e.src_id, "10.0.0.1");
        assert_eq!(e.dst_id, "1.1.1.1");
        assert_eq!(e.rel_type, RelationType::Connect);
        let m = &e.rel_metadata;
        assert_eq!(m.get("source").map(String::as_str), Some("suricata"));
        assert_eq!(m.get("event_type").map(String::as_str), Some("flow"));
        assert_eq!(m.get("sensor_uid").map(String::as_str), Some("12345"));
        assert_eq!(m.get("bytes_fwd").map(String::as_str), Some("500"));
        assert_eq!(m.get("bytes_rev").map(String::as_str), Some("9000"));
        assert_eq!(m.get("flow_state").map(String::as_str), Some("established"));
        assert_eq!(m.get("service").map(String::as_str), Some("tls"));
    }

    #[test]
    fn parse_alert_tags_l4_edge() {
        let v = json!({
            "timestamp": "2024-01-15T12:00:00.000+0000",
            "event_type": "alert",
            "src_ip": "10.0.0.1", "src_port": 50000,
            "dest_ip": "1.1.1.1", "dest_port": 443,
            "proto": "TCP",
            "alert": {
                "signature_id": 2014321,
                "signature": "ET POLICY Suspicious User-Agent",
                "category": "Misc Attack",
                "severity": 3
            }
        });
        let e = parse_record(&v, "").expect("parsed");
        assert_eq!(e.rel_type, RelationType::Connect);
        let m = &e.rel_metadata;
        assert_eq!(
            m.get("suricata_alert_signature").map(String::as_str),
            Some("ET POLICY Suspicious User-Agent"),
        );
        assert_eq!(
            m.get("suricata_alert_category").map(String::as_str),
            Some("Misc Attack"),
        );
        assert_eq!(
            m.get("suricata_alert_severity").map(String::as_str),
            Some("3"),
        );
        assert_eq!(
            m.get("suricata_alert_sid").map(String::as_str),
            Some("2014321"),
        );
    }

    #[test]
    fn parse_dns_query_only() {
        let v = json!({
            "timestamp": "2024-01-15T12:00:00.000+0000",
            "event_type": "dns",
            "src_ip": "10.0.0.1", "dest_ip": "8.8.8.8",
            "src_port": 50000, "dest_port": 53,
            "proto": "UDP",
            "dns": { "type": "query", "rrname": "evo.example.com", "rrtype": "A" }
        });
        let e = parse_record(&v, "").expect("parsed");
        assert_eq!(e.dst_id, "evo.example.com");
        assert_eq!(e.dst_type, EntityType::Domain);
        assert_eq!(e.rel_type, RelationType::DNS);
        assert_eq!(
            e.rel_metadata.get("qname").map(String::as_str),
            Some("evo.example.com"),
        );
    }

    #[test]
    fn parse_dns_response_skipped() {
        let v = json!({
            "event_type": "dns",
            "src_ip": "8.8.8.8", "dest_ip": "10.0.0.1",
            "proto": "UDP",
            "dns": { "type": "answer", "rrname": "evo.example.com" }
        });
        assert!(parse_record(&v, "").is_none());
    }

    #[test]
    fn parse_http_event() {
        let v = json!({
            "event_type": "http",
            "src_ip": "10.0.0.1", "dest_ip": "1.1.1.1",
            "src_port": 50000, "dest_port": 80,
            "proto": "TCP",
            "http": {
                "hostname": "evo.example.com",
                "http_method": "GET",
                "status": 200
            }
        });
        let e = parse_record(&v, "").expect("parsed");
        assert_eq!(e.dst_id, "evo.example.com");
        assert_eq!(e.dst_type, EntityType::Domain);
        assert_eq!(
            e.rel_metadata.get("http_method").map(String::as_str),
            Some("GET"),
        );
        assert_eq!(
            e.rel_metadata.get("http_status").map(String::as_str),
            Some("200"),
        );
    }

    #[test]
    fn parse_tls_event_with_ja3() {
        let v = json!({
            "event_type": "tls",
            "src_ip": "10.0.0.1", "dest_ip": "1.1.1.1",
            "src_port": 50000, "dest_port": 443,
            "proto": "TCP",
            "tls": {
                "sni": "evo.example.com",
                "version": "TLS 1.3",
                "ja3": { "hash": "aaaa1111" },
                "ja3s": { "hash": "bbbb2222" }
            }
        });
        let e = parse_record(&v, "").expect("parsed");
        assert_eq!(e.dst_id, "evo.example.com");
        let m = &e.rel_metadata;
        assert_eq!(m.get("ja3").map(String::as_str), Some("aaaa1111"));
        assert_eq!(m.get("ja3s").map(String::as_str), Some("bbbb2222"));
        assert_eq!(m.get("tls_version").map(String::as_str), Some("TLS 1.3"));
    }

    #[test]
    fn parse_returns_none_for_stats_event() {
        let v = json!({"event_type": "stats", "stats": {"uptime": 100}});
        assert!(parse_record(&v, "").is_none());
    }

    #[test]
    fn suricata_ts_parses_common_eve_format() {
        // Suricata's default uses no colon in the timezone offset.
        let v = json!({"timestamp": "2024-01-15T12:00:00.123456+0000"});
        let ts = suricata_ts(&v).expect("parsed");
        // 2024-01-15T12:00:00 UTC = 1_705_320_000
        assert_eq!(ts, 1_705_320_000);
    }

    #[test]
    fn suricata_ts_also_parses_rfc3339() {
        let v = json!({"timestamp": "2024-01-15T12:00:00+00:00"});
        assert_eq!(suricata_ts(&v), Some(1_705_320_000));
    }

    #[test]
    fn is_known_suricata_event_classifies_correctly() {
        for s in &["flow", "alert", "dns", "http", "tls", "smb", "krb5", "ssh"] {
            assert!(is_known_suricata_event(s), "want true for {s}");
        }
        for s in &["", "stats", "fileinfo", "user_login"] {
            assert!(!is_known_suricata_event(s), "want false for {s}");
        }
    }

    #[test]
    fn parse_krb5_as_req_emits_user_auth_edge() {
        let v = json!({
            "timestamp": "2024-01-15T12:00:00+00:00",
            "event_type": "krb5",
            "src_ip": "10.0.0.1", "src_port": 50000,
            "dest_ip": "10.0.0.10", "dest_port": 88,
            "proto": "UDP",
            "krb5": {
                "msg_type": "AS-REQ",
                "cname": "alice",
                "realm": "EXAMPLE.COM",
                "sname": "krbtgt/EXAMPLE.COM"
            }
        });
        let e = parse_record(&v, "").expect("parsed");
        assert_eq!(e.src_id, "alice");
        assert_eq!(e.src_type, EntityType::User);
        assert_eq!(e.dst_id, "10.0.0.10");
        assert_eq!(e.rel_type, RelationType::Auth);
        let m = &e.rel_metadata;
        assert_eq!(m.get("kerberos_kind").map(String::as_str), Some("AS-REQ"));
        assert_eq!(m.get("kerberos_realm").map(String::as_str), Some("EXAMPLE.COM"));
        assert_eq!(
            m.get("kerberos_service").map(String::as_str),
            Some("krbtgt/EXAMPLE.COM"),
        );
    }

    #[test]
    fn parse_krb5_response_is_skipped() {
        let v = json!({
            "event_type": "krb5",
            "src_ip": "10.0.0.10", "dest_ip": "10.0.0.1",
            "proto": "UDP",
            "krb5": { "msg_type": "AS-REP", "cname": "alice" }
        });
        assert!(parse_record(&v, "").is_none());
    }

    #[test]
    fn parse_smb_with_ntlmssp_emits_user_auth_edge() {
        let v = json!({
            "event_type": "smb",
            "src_ip": "10.0.0.1", "src_port": 50001,
            "dest_ip": "10.0.0.30", "dest_port": 445,
            "proto": "TCP",
            "smb": {
                "command": "SMB2_COMMAND_SESSION_SETUP",
                "dialect": "3.1.1",
                "ntlmssp": {
                    "user": "alice",
                    "domain": "EXAMPLE",
                    "host": "WS-001"
                }
            }
        });
        let e = parse_record(&v, "").expect("parsed");
        assert_eq!(e.src_id, "EXAMPLE\\alice");
        assert_eq!(e.src_type, EntityType::User);
        assert_eq!(e.dst_id, "10.0.0.30");
        let m = &e.rel_metadata;
        assert_eq!(m.get("ntlm_user").map(String::as_str), Some("alice"));
        assert_eq!(m.get("ntlm_domain").map(String::as_str), Some("EXAMPLE"));
        assert_eq!(m.get("smb_dialect").map(String::as_str), Some("3.1.1"));
    }

    #[test]
    fn parse_smb_without_ntlmssp_skipped() {
        let v = json!({
            "event_type": "smb",
            "src_ip": "10.0.0.1", "dest_ip": "10.0.0.30",
            "proto": "TCP",
            "smb": { "command": "SMB2_COMMAND_READ", "dialect": "3.1.1" }
        });
        assert!(parse_record(&v, "").is_none());
    }
}
