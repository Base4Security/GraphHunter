//! Zeek (formerly Bro) JSON-lines ingestor.
//!
//! Zeek is a passive network analysis platform that emits one JSON
//! object per observed event into typed log files (`conn.log`,
//! `dns.log`, `http.log`, `ssl.log`, …). This ingestor consumes those
//! JSON-lines files directly and emits one graph edge per Zeek
//! record — **trusting the sensor**: we do *not* re-run the records
//! through a 5-tuple aggregator. Each line's Zeek `uid` is preserved
//! on the resulting edge as `sensor_uid` so an analyst can pivot
//! back to the source record.
//!
//! ## Scope (PR2)
//!
//! - `conn.log`  → `IP -[Connect]-> IP` (5-tuple + duration + bytes).
//! - `dns.log`   → `IP -[DNS]-> Domain` (one edge per `query`).
//! - `http.log`  → `IP -[Connect]-> Domain` (Host header).
//! - `ssl.log`   → `IP -[Connect]-> Domain` (SNI).
//!
//! Out of scope until PR1b: `kerberos.log`, `smb_files.log` (need
//! the User-entity story shared with the PCAP Kerberos/NTLM
//! decoders). Out of scope this initiative: TSV variant
//! (`#separator \\x09`), gzipped logs (`.log.gz`). Both common but
//! orthogonal to the graph-ingest path.
//!
//! ## Detection
//!
//! Sniff prefers filename when present (`conn.log` → conn parser)
//! but falls back to first-record field inspection: a JSON object
//! with `id.orig_h` + `uid` keys is Zeek; the presence of `query`
//! / `host` / `server_name` then narrows to dns / http / ssl. We
//! intentionally do NOT claim file extension `.log` in
//! [`StreamingIngestor::extensions`] — that string is too generic.

use std::collections::HashMap;
use std::io::{BufRead, BufReader};
use std::path::Path;
use std::sync::Arc;

use graph_hunter_core::{EntityType, RawIngestEvent, RelationType};

use super::{IngestContext, StreamingIngestor};
use crate::EventEmitter;
use crate::events::events::INGEST_PROGRESS;
use crate::state::Session;

/// Batch threshold mirrors PCAP / EVTX: 5K events between graph
/// writes keeps the canvas responsive while amortising lock cost.
const BATCH_FLUSH_SIZE: usize = 5_000;
const PROGRESS_EVERY_N_LINES: u64 = 5_000;
const SNIFF_PEEK_BYTES: usize = 4096;

/// Identifies which Zeek log type this file contains. Driven by
/// filename when conclusive, otherwise inferred from the first
/// record's fields.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ZeekLogKind {
    Conn,
    Dns,
    Http,
    Ssl,
    /// `kerberos.log` — produces `User -[Auth]-> IP` edges.
    Kerberos,
    /// Recognised as Zeek-shaped (`id.orig_h` + `uid`) but the
    /// specific log type isn't one we map. Ingest treats it like
    /// a `conn.log` for the 5-tuple if those fields are present,
    /// otherwise skips the record.
    Generic,
}

/// JSON-lines Zeek log ingestor. Registered in `INGESTOR_REGISTRY`.
pub struct ZeekIngestor;

impl ZeekIngestor {
    pub fn new() -> Self {
        Self
    }
}

impl Default for ZeekIngestor {
    fn default() -> Self {
        Self::new()
    }
}

impl StreamingIngestor for ZeekIngestor {
    fn name(&self) -> &'static str {
        "zeek"
    }

    fn aliases(&self) -> &'static [&'static str] {
        &["bro"]
    }

    /// `.log` is too generic to claim outright — many tools write
    /// `.log` files. Detection rests on content sniff.
    fn extensions(&self) -> &'static [&'static str] {
        &[]
    }

    /// Confidence:
    /// - `200` when the first JSON line carries `id.orig_h` + `uid`
    ///   *and* the filename hints at a known Zeek log (e.g.
    ///   `conn.log` / `dns.log`).
    /// - `180` when only the field shape matches — there's some
    ///   risk a generic JSON-lines file happens to use those keys
    ///   (very unlikely), so we score below the unambiguous magic
    ///   formats (PCAP/EVTX = 255) but above any future fallback.
    /// - `None` otherwise.
    fn sniff(&self, path: &Path, _magic: &[u8]) -> Option<u8> {
        let peek = match read_first_line(path) {
            Some(s) => s,
            None => return None,
        };
        let v = serde_json::from_str::<serde_json::Value>(&peek).ok()?;
        let obj = v.as_object()?;
        // Zeek's defining keys: `uid` (Connection UID, format `CXXXX`)
        // and `id.orig_h` (originator IP). The flat form is the
        // default for Zeek 5+; the nested `id.orig_h` form is what
        // some custom builds emit — accept either.
        let has_uid = obj
            .get("uid")
            .and_then(|v| v.as_str())
            .map(|s| s.starts_with('C'))
            .unwrap_or(false);
        let has_orig_h = obj.get("id.orig_h").is_some()
            || obj
                .get("id")
                .and_then(|v| v.as_object())
                .and_then(|m| m.get("orig_h"))
                .is_some();
        if !(has_uid && has_orig_h) {
            return None;
        }
        if zeek_kind_from_filename(path).is_some() {
            Some(200)
        } else {
            Some(180)
        }
    }

    fn ingest(&self, ctx: IngestContext<'_>) -> Result<(usize, usize), String> {
        let kind = resolve_kind(ctx.path)?;
        let file = std::fs::File::open(ctx.path)
            .map_err(|e| format!("Failed to open Zeek log '{}': {e}", ctx.path))?;
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
            if let Some(ev) = parse_record(kind, &v, &source_file) {
                pending.extend(ev);
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

// ─── Internal helpers (pub(crate) so tests reach them) ───────────────

pub(crate) fn read_first_line(path: &Path) -> Option<String> {
    use std::io::Read;
    let mut f = std::fs::File::open(path).ok()?;
    let mut buf = vec![0u8; SNIFF_PEEK_BYTES];
    let n = f.read(&mut buf).ok()?;
    buf.truncate(n);
    let s = String::from_utf8_lossy(&buf).to_string();
    let line = s.split('\n').next().unwrap_or("").trim().to_string();
    if line.is_empty() { None } else { Some(line) }
}

/// Map a Zeek log filename to the log type it carries. Recognises
/// both `conn.log` and rotated forms like `conn.21-12-00-00.log`.
pub(crate) fn zeek_kind_from_filename(path: &Path) -> Option<ZeekLogKind> {
    let name = path.file_name().and_then(|s| s.to_str())?.to_lowercase();
    if name.starts_with("conn.") || name == "conn.log" {
        Some(ZeekLogKind::Conn)
    } else if name.starts_with("dns.") || name == "dns.log" {
        Some(ZeekLogKind::Dns)
    } else if name.starts_with("http.") || name == "http.log" {
        Some(ZeekLogKind::Http)
    } else if name.starts_with("ssl.") || name == "ssl.log" {
        Some(ZeekLogKind::Ssl)
    } else if name.starts_with("kerberos.") || name == "kerberos.log" {
        Some(ZeekLogKind::Kerberos)
    } else {
        None
    }
}

/// Fall back to inferring the kind from the first record's field
/// shape when the filename doesn't tell us. Tries the most
/// discriminating fields first.
pub(crate) fn zeek_kind_from_first_record(v: &serde_json::Value) -> ZeekLogKind {
    let obj = match v.as_object() {
        Some(o) => o,
        None => return ZeekLogKind::Generic,
    };
    if obj.contains_key("query") {
        ZeekLogKind::Dns
    } else if obj.contains_key("server_name") || obj.contains_key("ja3") {
        ZeekLogKind::Ssl
    } else if obj.contains_key("host") && obj.contains_key("uri") {
        ZeekLogKind::Http
    } else if obj.contains_key("request_type")
        && (obj.contains_key("client") || obj.contains_key("service"))
    {
        ZeekLogKind::Kerberos
    } else if obj.contains_key("proto") {
        // Both conn.log and many others have `proto`, but conn.log
        // is the most common Zeek log absent more specific markers.
        ZeekLogKind::Conn
    } else {
        ZeekLogKind::Generic
    }
}

fn resolve_kind(path: &str) -> Result<ZeekLogKind, String> {
    let p = Path::new(path);
    if let Some(k) = zeek_kind_from_filename(p) {
        return Ok(k);
    }
    let first = read_first_line(p)
        .ok_or_else(|| format!("Zeek log appears empty: {path}"))?;
    let v: serde_json::Value = serde_json::from_str(&first)
        .map_err(|e| format!("First line is not valid JSON in '{path}': {e}"))?;
    Ok(zeek_kind_from_first_record(&v))
}

/// Parse one Zeek JSON record into 0..N graph edges. `dns` is the
/// only kind that produces multiple edges per record (unused for
/// now — we emit one DNS edge per record, ignoring `answers`).
pub(crate) fn parse_record(
    kind: ZeekLogKind,
    v: &serde_json::Value,
    source_file: &str,
) -> Option<Vec<RawIngestEvent>> {
    match kind {
        ZeekLogKind::Conn | ZeekLogKind::Generic => parse_conn(v, source_file).map(|e| vec![e]),
        ZeekLogKind::Dns => parse_dns(v, source_file).map(|e| vec![e]),
        ZeekLogKind::Http => parse_http(v, source_file).map(|e| vec![e]),
        ZeekLogKind::Ssl => parse_ssl(v, source_file).map(|e| vec![e]),
        ZeekLogKind::Kerberos => parse_kerberos(v, source_file).map(|e| vec![e]),
    }
}

fn parse_conn(v: &serde_json::Value, source_file: &str) -> Option<RawIngestEvent> {
    let (src_ip, dst_ip, src_port, dst_port, proto) = zeek_5tuple(v)?;
    let ts = zeek_ts(v).unwrap_or(0);
    let mut md = HashMap::with_capacity(16);
    base_metadata(&mut md, v, source_file, "conn", proto, src_port, dst_port);
    if let Some(s) = v.get("service").and_then(|x| x.as_str()) {
        md.insert("service".to_string(), s.to_string());
    }
    if let Some(d) = v.get("duration").and_then(|x| x.as_f64()) {
        md.insert("duration_ms".to_string(), ((d * 1000.0) as u64).to_string());
    }
    if let Some(b) = v.get("orig_bytes").and_then(|x| x.as_u64()) {
        md.insert("bytes_fwd".to_string(), b.to_string());
    }
    if let Some(b) = v.get("resp_bytes").and_then(|x| x.as_u64()) {
        md.insert("bytes_rev".to_string(), b.to_string());
    }
    if let Some(p) = v.get("orig_pkts").and_then(|x| x.as_u64()) {
        md.insert("packets_fwd".to_string(), p.to_string());
    }
    if let Some(p) = v.get("resp_pkts").and_then(|x| x.as_u64()) {
        md.insert("packets_rev".to_string(), p.to_string());
    }
    if let Some(s) = v.get("conn_state").and_then(|x| x.as_str()) {
        md.insert("conn_state".to_string(), s.to_string());
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
    let (src_ip, dst_ip, src_port, dst_port, proto) = zeek_5tuple(v)?;
    let qname = v.get("query").and_then(|x| x.as_str()).map(str::to_string)?;
    if qname.is_empty() {
        return None;
    }
    let ts = zeek_ts(v).unwrap_or(0);
    let mut md = HashMap::with_capacity(10);
    base_metadata(&mut md, v, source_file, "dns", proto, src_port, dst_port);
    md.insert("l7_decoded".to_string(), "dns_query".to_string());
    md.insert("qname".to_string(), qname.clone());
    if let Some(q) = v.get("qtype_name").and_then(|x| x.as_str()) {
        md.insert("qtype".to_string(), q.to_string());
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
    let (src_ip, _dst_ip, src_port, dst_port, proto) = zeek_5tuple(v)?;
    let host = v.get("host").and_then(|x| x.as_str()).map(str::to_string)?;
    if host.is_empty() {
        return None;
    }
    let ts = zeek_ts(v).unwrap_or(0);
    let mut md = HashMap::with_capacity(10);
    base_metadata(&mut md, v, source_file, "http", proto, src_port, dst_port);
    md.insert("l7_decoded".to_string(), "http_host".to_string());
    md.insert("http_host".to_string(), host.clone());
    if let Some(m) = v.get("method").and_then(|x| x.as_str()) {
        md.insert("http_method".to_string(), m.to_string());
    }
    if let Some(s) = v.get("status_code").and_then(|x| x.as_u64()) {
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

fn parse_ssl(v: &serde_json::Value, source_file: &str) -> Option<RawIngestEvent> {
    let (src_ip, _dst_ip, src_port, dst_port, proto) = zeek_5tuple(v)?;
    let sni = v
        .get("server_name")
        .and_then(|x| x.as_str())
        .map(str::to_string)?;
    if sni.is_empty() {
        return None;
    }
    let ts = zeek_ts(v).unwrap_or(0);
    let mut md = HashMap::with_capacity(10);
    base_metadata(&mut md, v, source_file, "ssl", proto, src_port, dst_port);
    md.insert("l7_decoded".to_string(), "tls_sni".to_string());
    md.insert("sni".to_string(), sni.clone());
    if let Some(j) = v.get("ja3").and_then(|x| x.as_str()) {
        md.insert("ja3".to_string(), j.to_string());
    }
    if let Some(v_) = v.get("version").and_then(|x| x.as_str()) {
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

fn parse_kerberos(v: &serde_json::Value, source_file: &str) -> Option<RawIngestEvent> {
    // kerberos.log carries the 5-tuple but the wire-relevant entity
    // is the `client` principal authenticating against the KDC at
    // `id.resp_h`. We emit `User -[Auth]-> IP` directly.
    let (_, dst_ip, src_port, dst_port, proto) = zeek_5tuple(v)?;
    let client = v
        .get("client")
        .and_then(|x| x.as_str())
        .map(str::to_string)?;
    if client.is_empty() {
        return None;
    }
    let request_type = v.get("request_type").and_then(|x| x.as_str()).unwrap_or("");
    let kind = match request_type {
        "AS" => "AS-REQ",
        "TGS" => "TGS-REQ",
        _ => return None,
    };
    let ts = zeek_ts(v).unwrap_or(0);
    let mut md = HashMap::with_capacity(12);
    base_metadata(&mut md, v, source_file, "kerberos", proto, src_port, dst_port);
    md.insert("l7_decoded".to_string(), "kerberos".to_string());
    md.insert("kerberos_kind".to_string(), kind.to_string());
    md.insert("kerberos_user".to_string(), client.clone());
    if let Some(svc) = v.get("service").and_then(|x| x.as_str()) {
        md.insert("kerberos_service".to_string(), svc.to_string());
    }
    if let Some(success) = v.get("success").and_then(|x| x.as_bool()) {
        md.insert("success".to_string(), success.to_string());
    }
    if let Some(err) = v.get("error_msg").and_then(|x| x.as_str()) {
        md.insert("kerberos_error".to_string(), err.to_string());
    }
    Some(RawIngestEvent {
        src_id: client,
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

// ─── Field extraction helpers ────────────────────────────────────────

/// Extract the 5-tuple from a Zeek record, accepting either the
/// flat (`id.orig_h`) or nested (`id.orig_h` inside `id`) form.
fn zeek_5tuple(v: &serde_json::Value) -> Option<(String, String, u16, u16, String)> {
    fn s_str(v: &serde_json::Value) -> Option<String> {
        v.as_str().map(str::to_string)
    }
    fn s_port(v: &serde_json::Value) -> Option<u16> {
        v.as_u64().map(|n| n as u16)
    }
    let nested = v.get("id").and_then(|n| n.as_object());
    let src_ip = v
        .get("id.orig_h")
        .and_then(s_str)
        .or_else(|| nested.and_then(|n| n.get("orig_h")).and_then(s_str))?;
    let dst_ip = v
        .get("id.resp_h")
        .and_then(s_str)
        .or_else(|| nested.and_then(|n| n.get("resp_h")).and_then(s_str))?;
    let src_port = v
        .get("id.orig_p")
        .and_then(s_port)
        .or_else(|| nested.and_then(|n| n.get("orig_p")).and_then(s_port))
        .unwrap_or(0);
    let dst_port = v
        .get("id.resp_p")
        .and_then(s_port)
        .or_else(|| nested.and_then(|n| n.get("resp_p")).and_then(s_port))
        .unwrap_or(0);
    let proto = v
        .get("proto")
        .and_then(s_str)
        .unwrap_or_else(|| "unknown".to_string());
    Some((src_ip, dst_ip, src_port, dst_port, proto))
}

/// Parse a Zeek `ts` value (decimal seconds since epoch) to whole
/// seconds. Returns `None` if the field is absent or malformed.
pub(crate) fn zeek_ts(v: &serde_json::Value) -> Option<i64> {
    v.get("ts").and_then(|t| t.as_f64()).map(|f| f as i64)
}

fn base_metadata(
    md: &mut HashMap<String, String>,
    v: &serde_json::Value,
    source_file: &str,
    log_kind: &str,
    proto: String,
    src_port: u16,
    dst_port: u16,
) {
    md.insert("source".to_string(), "zeek".to_string());
    md.insert("zeek_log".to_string(), log_kind.to_string());
    if !source_file.is_empty() {
        md.insert("source_file".to_string(), source_file.to_string());
    }
    if let Some(uid) = v.get("uid").and_then(|u| u.as_str()) {
        md.insert("sensor_uid".to_string(), uid.to_string());
    }
    md.insert("protocol".to_string(), proto.to_uppercase());
    if src_port != 0 {
        md.insert("src_port".to_string(), src_port.to_string());
    }
    if dst_port != 0 {
        md.insert("dst_port".to_string(), dst_port.to_string());
    }
}

// ─── Streaming shared with the Suricata ingestor ─────────────────────

pub(crate) fn flush(
    pending: &mut Vec<RawIngestEvent>,
    session: &Arc<Session>,
    dataset_id: &str,
    total_new_entities: &mut usize,
    total_new_relations: &mut usize,
) -> Result<(), String> {
    if pending.is_empty() {
        return Ok(());
    }
    let events: Vec<RawIngestEvent> = std::mem::take(pending);
    let (ne, nr) = match session.graph.write() {
        Ok(mut g) => g
            .insert_raw_events(events, Some(dataset_id))
            .map_err(|e| e.to_string())?,
        Err(_) => return Err("Graph lock poisoned".to_string()),
    };
    *total_new_entities += ne;
    *total_new_relations += nr;
    Ok(())
}

pub(crate) fn emit_progress(
    emitter: &Arc<dyn EventEmitter>,
    bytes_read: u64,
    bytes_total: u64,
    entities: usize,
    relations: usize,
) {
    emitter.emit(
        INGEST_PROGRESS,
        serde_json::json!({
            "phase": "parsing",
            "bytes_read": bytes_read,
            "bytes_total": bytes_total,
            "entities": entities,
            "relations": relations,
        }),
    );
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

    /// Write a fixture inside a fresh subdirectory so we can give it
    /// a real Zeek filename like `conn.log` without colliding with
    /// other test runs.
    fn tmp_in_subdir(subdir: &str, name: &str, body: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(subdir);
        std::fs::create_dir_all(&dir).unwrap();
        let p = dir.join(name);
        std::fs::write(&p, body).unwrap();
        p
    }

    #[test]
    fn sniff_accepts_zeek_json_with_filename_hint() {
        let body = r#"{"ts":1.0,"uid":"CAbcde","id.orig_h":"10.0.0.1","id.resp_h":"1.1.1.1","proto":"tcp"}"#;
        let p = tmp_in_subdir(
            "gh_zeek_sniff_hint",
            "conn.log",
            &format!("{body}\n"),
        );
        let ing = ZeekIngestor::new();
        assert_eq!(ing.sniff(&p, &[]), Some(200));
        std::fs::remove_file(&p).ok();
    }

    #[test]
    fn sniff_accepts_zeek_without_filename_hint() {
        // No `.log` filename suffix — only the field shape gives it away.
        let body = r#"{"ts":1.0,"uid":"CAbcde","id.orig_h":"10.0.0.1","id.resp_h":"1.1.1.1","proto":"tcp"}"#;
        let p = tmp("zeek_sniff_unknown.txt", &format!("{body}\n"));
        let ing = ZeekIngestor::new();
        assert_eq!(ing.sniff(&p, &[]), Some(180));
        std::fs::remove_file(&p).ok();
    }

    #[test]
    fn sniff_rejects_generic_json() {
        // No Zeek-specific keys.
        let body = r#"{"foo": "bar"}"#;
        let p = tmp("zeek_sniff_generic.json", &format!("{body}\n"));
        let ing = ZeekIngestor::new();
        assert_eq!(ing.sniff(&p, &[]), None);
        std::fs::remove_file(&p).ok();
    }

    #[test]
    fn sniff_rejects_zeek_with_non_c_uid() {
        // Real Zeek UIDs always start with 'C'. A record with `uid`
        // that doesn't is almost certainly someone else's `uid` field.
        let body = r#"{"uid":"abc","id.orig_h":"10.0.0.1"}"#;
        let p = tmp("zeek_sniff_bad_uid.json", &format!("{body}\n"));
        let ing = ZeekIngestor::new();
        assert_eq!(ing.sniff(&p, &[]), None);
        std::fs::remove_file(&p).ok();
    }

    #[test]
    fn parse_conn_extracts_5tuple_and_bytes() {
        let v = json!({
            "ts": 1614556800.5,
            "uid": "CAbcde",
            "id.orig_h": "10.0.0.1",
            "id.orig_p": 54321,
            "id.resp_h": "1.1.1.1",
            "id.resp_p": 443,
            "proto": "tcp",
            "service": "ssl",
            "duration": 1.234,
            "orig_bytes": 100,
            "resp_bytes": 2000,
            "orig_pkts": 5,
            "resp_pkts": 10,
            "conn_state": "SF"
        });
        let evs = parse_record(ZeekLogKind::Conn, &v, "conn.log").expect("parsed");
        assert_eq!(evs.len(), 1);
        let e = &evs[0];
        assert_eq!(e.src_id, "10.0.0.1");
        assert_eq!(e.dst_id, "1.1.1.1");
        assert_eq!(e.src_type, EntityType::IP);
        assert_eq!(e.dst_type, EntityType::IP);
        assert_eq!(e.rel_type, RelationType::Connect);
        assert_eq!(e.timestamp, 1614556800);
        let m = &e.rel_metadata;
        assert_eq!(m.get("source").map(String::as_str), Some("zeek"));
        assert_eq!(m.get("sensor_uid").map(String::as_str), Some("CAbcde"));
        assert_eq!(m.get("protocol").map(String::as_str), Some("TCP"));
        assert_eq!(m.get("src_port").map(String::as_str), Some("54321"));
        assert_eq!(m.get("dst_port").map(String::as_str), Some("443"));
        assert_eq!(m.get("service").map(String::as_str), Some("ssl"));
        assert_eq!(m.get("duration_ms").map(String::as_str), Some("1234"));
        assert_eq!(m.get("bytes_fwd").map(String::as_str), Some("100"));
        assert_eq!(m.get("bytes_rev").map(String::as_str), Some("2000"));
        assert_eq!(m.get("conn_state").map(String::as_str), Some("SF"));
    }

    #[test]
    fn parse_conn_handles_nested_id_form() {
        let v = json!({
            "ts": 1.0,
            "uid": "CAxyz",
            "id": { "orig_h": "192.168.1.5", "resp_h": "8.8.8.8",
                    "orig_p": 33333, "resp_p": 53 },
            "proto": "udp"
        });
        let e = parse_record(ZeekLogKind::Conn, &v, "")
            .expect("parsed")
            .into_iter()
            .next()
            .unwrap();
        assert_eq!(e.src_id, "192.168.1.5");
        assert_eq!(e.dst_id, "8.8.8.8");
        assert_eq!(e.rel_metadata.get("protocol").map(String::as_str), Some("UDP"));
    }

    #[test]
    fn parse_dns_produces_ip_to_domain_edge() {
        let v = json!({
            "ts": 2.0,
            "uid": "CAabcd",
            "id.orig_h": "10.0.0.1",
            "id.orig_p": 50000,
            "id.resp_h": "8.8.8.8",
            "id.resp_p": 53,
            "proto": "udp",
            "query": "evo.example.com",
            "qtype_name": "A"
        });
        let e = parse_record(ZeekLogKind::Dns, &v, "dns.log")
            .expect("parsed")
            .into_iter()
            .next()
            .unwrap();
        assert_eq!(e.src_id, "10.0.0.1");
        assert_eq!(e.dst_id, "evo.example.com");
        assert_eq!(e.dst_type, EntityType::Domain);
        assert_eq!(e.rel_type, RelationType::DNS);
        let m = &e.rel_metadata;
        assert_eq!(m.get("l7_decoded").map(String::as_str), Some("dns_query"));
        assert_eq!(m.get("qname").map(String::as_str), Some("evo.example.com"));
        assert_eq!(m.get("qtype").map(String::as_str), Some("A"));
        assert_eq!(m.get("resolver").map(String::as_str), Some("8.8.8.8"));
    }

    #[test]
    fn parse_dns_skips_empty_query() {
        let v = json!({
            "ts": 2.0, "uid": "CAabcd",
            "id.orig_h": "10.0.0.1", "id.resp_h": "8.8.8.8",
            "proto": "udp", "query": ""
        });
        assert!(parse_record(ZeekLogKind::Dns, &v, "").is_none());
    }

    #[test]
    fn parse_http_produces_ip_to_domain_edge() {
        let v = json!({
            "ts": 3.0,
            "uid": "CAhttp",
            "id.orig_h": "10.0.0.1",
            "id.resp_h": "1.1.1.1",
            "id.orig_p": 50001,
            "id.resp_p": 80,
            "proto": "tcp",
            "host": "evo.example.com",
            "uri": "/index",
            "method": "GET",
            "status_code": 200
        });
        let e = parse_record(ZeekLogKind::Http, &v, "")
            .expect("parsed")
            .into_iter()
            .next()
            .unwrap();
        assert_eq!(e.dst_id, "evo.example.com");
        assert_eq!(e.dst_type, EntityType::Domain);
        assert_eq!(e.rel_type, RelationType::Connect);
        let m = &e.rel_metadata;
        assert_eq!(m.get("http_method").map(String::as_str), Some("GET"));
        assert_eq!(m.get("http_status").map(String::as_str), Some("200"));
        assert_eq!(m.get("l7_decoded").map(String::as_str), Some("http_host"));
    }

    #[test]
    fn parse_ssl_produces_ip_to_domain_edge_with_sni() {
        let v = json!({
            "ts": 4.0,
            "uid": "CAssl",
            "id.orig_h": "10.0.0.1",
            "id.resp_h": "1.1.1.1",
            "id.orig_p": 50002,
            "id.resp_p": 443,
            "proto": "tcp",
            "server_name": "evo.example.com",
            "version": "TLSv13",
            "ja3": "abc123"
        });
        let e = parse_record(ZeekLogKind::Ssl, &v, "")
            .expect("parsed")
            .into_iter()
            .next()
            .unwrap();
        assert_eq!(e.dst_id, "evo.example.com");
        let m = &e.rel_metadata;
        assert_eq!(m.get("sni").map(String::as_str), Some("evo.example.com"));
        assert_eq!(m.get("ja3").map(String::as_str), Some("abc123"));
        assert_eq!(m.get("tls_version").map(String::as_str), Some("TLSv13"));
    }

    #[test]
    fn parse_record_returns_none_on_missing_5tuple() {
        let v = json!({"ts": 1.0, "uid": "CAbad"});
        assert!(parse_record(ZeekLogKind::Conn, &v, "").is_none());
    }

    #[test]
    fn kind_from_filename_handles_rotated_names() {
        let cases = [
            ("conn.log", Some(ZeekLogKind::Conn)),
            ("conn.21-12-00-00.log", Some(ZeekLogKind::Conn)),
            ("dns.log", Some(ZeekLogKind::Dns)),
            ("HTTP.log", Some(ZeekLogKind::Http)),
            ("ssl.log", Some(ZeekLogKind::Ssl)),
            ("totally_unrelated.log", None),
        ];
        for (name, want) in cases {
            assert_eq!(
                zeek_kind_from_filename(Path::new(name)),
                want,
                "filename {name}"
            );
        }
    }

    #[test]
    fn kind_from_first_record_falls_back_to_field_shape() {
        let conn = json!({"id.orig_h": "1.1.1.1", "proto": "tcp"});
        assert_eq!(zeek_kind_from_first_record(&conn), ZeekLogKind::Conn);
        let dns = json!({"query": "ex.com"});
        assert_eq!(zeek_kind_from_first_record(&dns), ZeekLogKind::Dns);
        let http = json!({"host": "x", "uri": "/"});
        assert_eq!(zeek_kind_from_first_record(&http), ZeekLogKind::Http);
        let ssl = json!({"server_name": "x"});
        assert_eq!(zeek_kind_from_first_record(&ssl), ZeekLogKind::Ssl);
        let krb = json!({"request_type": "AS", "client": "alice/EXAMPLE.COM"});
        assert_eq!(zeek_kind_from_first_record(&krb), ZeekLogKind::Kerberos);
        let unknown = json!({"random": "field"});
        assert_eq!(zeek_kind_from_first_record(&unknown), ZeekLogKind::Generic);
    }

    #[test]
    fn parse_kerberos_emits_user_auth_edge_with_request_type() {
        let v = json!({
            "ts": 5.0,
            "uid": "CAkrb",
            "id.orig_h": "10.0.0.1",
            "id.resp_h": "10.0.0.10",
            "id.orig_p": 50000,
            "id.resp_p": 88,
            "proto": "udp",
            "request_type": "AS",
            "client": "alice/EXAMPLE.COM",
            "service": "krbtgt/EXAMPLE.COM",
            "success": true
        });
        let e = parse_record(ZeekLogKind::Kerberos, &v, "kerberos.log")
            .expect("parsed")
            .into_iter()
            .next()
            .unwrap();
        assert_eq!(e.src_id, "alice/EXAMPLE.COM");
        assert_eq!(e.src_type, EntityType::User);
        assert_eq!(e.dst_id, "10.0.0.10");
        assert_eq!(e.dst_type, EntityType::IP);
        assert_eq!(e.rel_type, RelationType::Auth);
        let m = &e.rel_metadata;
        assert_eq!(m.get("l7_decoded").map(String::as_str), Some("kerberos"));
        assert_eq!(m.get("kerberos_kind").map(String::as_str), Some("AS-REQ"));
        assert_eq!(
            m.get("kerberos_service").map(String::as_str),
            Some("krbtgt/EXAMPLE.COM"),
        );
        assert_eq!(m.get("success").map(String::as_str), Some("true"));
    }

    #[test]
    fn parse_kerberos_rejects_unknown_request_type() {
        let v = json!({
            "ts": 1.0, "uid": "CAkrb",
            "id.orig_h": "10.0.0.1", "id.resp_h": "10.0.0.10",
            "proto": "udp",
            "request_type": "BLEH",
            "client": "alice"
        });
        assert!(parse_record(ZeekLogKind::Kerberos, &v, "").is_none());
    }
}
