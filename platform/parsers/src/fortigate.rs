//! Native FortiGate firewall log parser (task #65).
//!
//! Bypasses the generic CSV + `ConfigurableParser` pipeline because the
//! shared heuristics in `field_preview.rs` mis-map FortiGate-shaped
//! data in four specific ways:
//!
//! 1. **BUG-1** any column whose name contains `port` is typed
//!    `EntityType::IP` (`suggest_entity_type` ~line 393). This pulls
//!    `dstport`/`srcport` into the IP namespace and pollutes the graph
//!    with fake IP nodes whose IDs are port numbers (`80`, `443`).
//! 2. **BUG-2** dotted-string values are auto-classed as
//!    `EntityType::Domain`, which then forces
//!    `RelationType::DNS`. IPS signature names like
//!    `FortiOS.SSL.VPN.Custom.Information.Disclosure` get demoted to a
//!    Domain node with a DNS edge — wrong by every axis.
//! 3. **BUG-3** `infer_relation_from_action` maps the action verbs
//!    `dropped` / `close` to `RelationType::Delete`. For firewall data
//!    these are policy verdicts, not deletions; the edge type must
//!    stay `Connect`.
//! 4. **BUG-4** `FieldRole::Metadata` is a no-op for *edge* metadata
//!    because the framework only attaches metadata to entities. That
//!    means `action`, `severity`, `policyname` and the rest of the
//!    forensically relevant fields never reach `Relation::metadata`
//!    through the generic path.
//!
//! This parser hard-codes the correct mapping:
//!
//! This parser hard-codes the correct mapping. Up to 5 triples per line:
//! `srcip -[Connect]-> dstip` (always); `srcip -[SNAT]-> transip` when
//! source-NATted; `dstip -[Exposes]-> Service("dstip:port")` when `dstport`
//! present (the `dstip` node is deduped by the graph layer); and
//! `srcip -[MatchedPolicy]-> Policy(policyname)` when `policyname` present.
//! `devname` deliberately does *not* become a Host node — every event would
//! link back to it, creating a star hub that dominates centrality measures
//! (PageRank/degree).

use std::collections::HashMap;

use chrono::{DateTime, NaiveDateTime};

use graph_hunter_core::entity::Entity;
use graph_hunter_core::parser::{LogParser, ParsedTriple};
use graph_hunter_core::relation::Relation;
use graph_hunter_core::types::{EntityType, RelationType};

// NOTE on input modes: this parser deliberately exposes only the two
// modes that are actually reachable from production wiring:
//   * raw KV log lines (default `LogParser::parse` path),
//   * CSV-with-headers (auto-detected when the first line has commas
//     but no `=`).
// An earlier draft also shipped an `xlsx` entry point behind the
// `xlsx` cargo feature, but it took a `&Path` and could not be reached
// through `LogParser::parse(&str)` — the registry has no `.xlsx`
// extension hook (see `platform/api/src/format_registry.rs`
// `resolve_format_with_ext`) and no caller existed in the repo. Rather
// than ship dead code + the `calamine` transitive dependency (zip,
// xml, regex), the xlsx mode was removed; if/when xlsx ingest is
// scoped, it will need its own dispatch since the trait can't accept a
// path.

/// Fields propagated from a FortiGate KV line onto every emitted
/// `Relation::metadata`. Order is preserved across inserts so callers
/// reading the HashMap see a stable shape; the order itself is the
/// "operationally interesting first" ordering analysts use when
/// triaging.
const EDGE_METADATA_FIELDS: &[&str] = &[
    "action",
    "severity",
    "service",
    "proto",
    "srcport",
    "dstport",
    "policyid",
    "policyname",
    "duration",
    "sentbyte",
    "rcvdbyte",
    "sentpkt",
    "rcvdpkt",
    "trandisp",
    "transip",
    "transport",
    "app",
    "dstcountry",
    "srccountry",
    "devname",
    "logid",
    "subtype",
];

/// Native FortiGate parser. Accepts two input shapes both routed
/// through `LogParser::parse(&str)`:
///  * raw KV log lines (one event per newline-terminated record),
///  * CSV with a header row (header cell becomes the KV key, body cell
///    becomes the value).
#[derive(Debug, Default, Clone)]
pub struct FortiGateParser;

impl FortiGateParser {
    pub fn new() -> Self {
        Self
    }

    /// CSV-with-headers entry point. The first non-empty line is taken
    /// as the header row. Each subsequent row is reconstructed into the
    /// canonical FortiGate KV-line shape (`key="value" key="value"
    /// ...`) and fed back through [`parse_kv_line`].
    pub fn parse_csv(&self, csv: &str) -> Vec<ParsedTriple> {
        let mut lines = csv.lines();
        let header_line = loop {
            match lines.next() {
                Some(l) if l.trim().is_empty() => continue,
                Some(l) => break l,
                None => return Vec::new(),
            }
        };
        let headers = split_csv_row(header_line);
        let mut out = Vec::new();
        for line in lines {
            if line.trim().is_empty() {
                continue;
            }
            let cells = split_csv_row(line);
            let kv = synthesize_kv_line(&headers, &cells);
            out.extend(parse_kv_line(&kv));
        }
        out
    }

}

impl LogParser for FortiGateParser {
    fn parse(&self, data: &str) -> Vec<ParsedTriple> {
        let trimmed = data.trim_start();
        if trimmed.is_empty() {
            return Vec::new();
        }
        // CSV-with-headers heuristic: if the first non-blank line has
        // no `=` characters but does have a comma, treat it as a CSV
        // header. Any FortiGate KV log line will always contain `=`.
        let first = trimmed.lines().find(|l| !l.trim().is_empty()).unwrap_or("");
        if !first.contains('=') && first.contains(',') {
            return self.parse_csv(data);
        }
        let mut out = Vec::new();
        for line in data.lines() {
            if line.trim().is_empty() {
                continue;
            }
            out.extend(parse_kv_line(line));
        }
        out
    }
}

/// Content sniffer used by `format_registry::detect_fortigate`. Strict:
/// looks for the FortiGate-specific KV signature (`srcip=` or
/// `dstip=`, optionally quoted) so generic syslog text doesn't false-
/// match. A FortiGate CSV export (header row) is also recognised.
pub fn looks_like_fortigate(contents: &str) -> bool {
    // Fast prefix probe — only look at the first ~8 KiB so a 1 GiB log
    // file doesn't get fully scanned.
    let probe = if contents.len() > 8192 {
        &contents[..8192]
    } else {
        contents
    };
    // KV-line shape: `srcip="..."` or `srcip=...`.
    let has_kv_marker = probe.contains("srcip=\"")
        || probe.contains("dstip=\"")
        || probe.contains(" srcip=")
        || probe.contains(" dstip=")
        || probe.starts_with("srcip=")
        || probe.starts_with("dstip=");
    if has_kv_marker {
        return true;
    }
    // CSV-header shape: first line has both `srcip` and `dstip` as
    // comma-separated headers. Pinning to BOTH keeps generic CSVs that
    // happen to mention `srcip` from sliding into this branch.
    if let Some(first) = probe.lines().find(|l| !l.trim().is_empty()) {
        if first.contains(',') && !first.contains('=') {
            let lower = first.to_ascii_lowercase();
            return lower.contains("srcip") && lower.contains("dstip");
        }
    }
    false
}

// ── KV line parsing ─────────────────────────────────────────────────

/// Parse one FortiGate KV log line into 0..5 triples.
///
/// Returns (empty if `srcip`/`dstip` not both present):
/// * `srcip -[Connect]-> dstip` (always);
/// * `srcip -[SNAT]-> transip` if `trandisp=="snat"` and `transip` present;
/// * `dstip -[Exposes]-> Service("dstip:port")` if `dstport` present;
/// * `srcip -[MatchedPolicy]-> Policy(policyname)` if `policyname` present;
/// * `srcip -[Triggered]-> attack` if an `attack` field is present (IPS event).
fn parse_kv_line(line: &str) -> Vec<ParsedTriple> {
    let kv = extract_kv_pairs(line);
    let srcip = match kv.get("srcip") {
        Some(v) if !v.is_empty() => v.clone(),
        _ => return Vec::new(),
    };
    let dstip = match kv.get("dstip") {
        Some(v) if !v.is_empty() => v.clone(),
        _ => return Vec::new(),
    };
    let timestamp = derive_timestamp(&kv);
    let edge_meta = collect_edge_metadata(&kv);

    let mut triples = Vec::new();

    // Triple 1: srcip -[Connect]-> dstip
    let src = Entity::new(&srcip, EntityType::IP);
    let dst = Entity::new(&dstip, EntityType::IP);
    let mut rel = Relation::new(&srcip, &dstip, RelationType::Connect, timestamp);
    rel.metadata = edge_meta.clone();
    triples.push((src.clone(), rel, dst));

    // Satellite triple: srcip -[SNAT]-> transip (only on source NAT).
    if kv.get("trandisp").map(|d| d == "snat").unwrap_or(false) {
        if let Some(transip) = kv.get("transip").filter(|v| !v.is_empty()) {
            let egress = Entity::new(transip, EntityType::IP);
            let rel_snat = Relation::new(
                &srcip,
                transip,
                RelationType::Other("SNAT".to_string()),
                timestamp,
            );
            triples.push((src.clone(), rel_snat, egress));
        }
    }

    // Satellite triple: dstip -[Exposes]-> Service("dstip:port").
    if let Some(port) = kv.get("dstport").filter(|v| !v.is_empty()) {
        let svc_id = format!("{dstip}:{port}");
        let mut svc = Entity::new(&svc_id, EntityType::Service);
        svc.metadata.insert("port".into(), port.clone());
        if let Some(name) = kv.get("service").filter(|v| !v.is_empty()) {
            svc.metadata.insert("service".into(), name.clone());
        }
        // `dst` was moved into the Connect triple; rebuild from &dstip (same id, deduped by graph).
        let dst_node = Entity::new(&dstip, EntityType::IP);
        let rel_exp = Relation::new(
            &dstip,
            &svc_id,
            RelationType::Other("Exposes".to_string()),
            timestamp,
        );
        triples.push((dst_node, rel_exp, svc));
    }

    // Satellite triple: srcip -[MatchedPolicy]-> Policy(policyname).
    if let Some(policy_name) = kv.get("policyname").filter(|v| !v.is_empty()) {
        let mut policy = Entity::new(policy_name, EntityType::Other("Policy".to_string()));
        if let Some(pid) = kv.get("policyid").filter(|v| !v.is_empty()) {
            policy.metadata.insert("policyid".into(), pid.clone());
        }
        if let Some(dev) = kv.get("devname").filter(|v| !v.is_empty()) {
            policy.metadata.insert("devname".into(), dev.clone());
        }
        let rel_pol = Relation::new(
            &srcip,
            policy_name,
            RelationType::Other("MatchedPolicy".to_string()),
            timestamp,
        );
        triples.push((src.clone(), rel_pol, policy));
    }

    // Triple (IPS): srcip -[Triggered]-> attack
    if let Some(attack) = kv.get("attack").filter(|v| !v.is_empty()) {
        let sig = Entity::new(attack, EntityType::Other("Signature".to_string()));
        let mut rel2 = Relation::new(
            &srcip,
            attack,
            RelationType::Other("Triggered".to_string()),
            timestamp,
        );
        rel2.metadata = edge_meta;
        triples.push((src, rel2, sig));
    }
    triples
}

/// Pull the configured edge-metadata fields off a parsed KV map.
fn collect_edge_metadata(kv: &HashMap<String, String>) -> HashMap<String, String> {
    let mut out = HashMap::new();
    for field in EDGE_METADATA_FIELDS {
        if let Some(v) = kv.get(*field) {
            if !v.is_empty() {
                out.insert((*field).into(), v.clone());
            }
        }
    }
    // Preserve the raw timestamp shape if either component is present
    // — handy for analyst-side timeline reconstruction.
    if let Some(t) = kv.get("timestamp") {
        out.insert("timestamp_raw".into(), t.clone());
    } else if let (Some(d), Some(t)) = (kv.get("date"), kv.get("time")) {
        out.insert("timestamp_raw".into(), format!("{d} {t}"));
    }
    out
}

/// Derive the Relation::timestamp (epoch seconds) from a FortiGate KV
/// map. Tries, in order:
///  1. `timestamp=` already-numeric epoch (handles `s`, `ms`, `us`, `ns`),
///  1b. `timestamp=` as ISO 8601 string (FortiGate `.final.csv` shape),
///  2. `eventtime=` (FortiOS 6.x+ ns-since-epoch), numeric then ISO,
///  3. `date=YYYY-MM-DD` + `time=HH:MM:SS` combined as naive UTC,
///  4. 0 + `eprintln!` warn (parser never errors / drops the row;
///     downstream tooling sorts by 0 so existing semantics are preserved).
///
/// Bug #69: FortiGate `.final.csv` exports carry the timestamp as a
/// single STRING `YYYY-MM-DDTHH:MM:SS` cell, which the original
/// numeric-only branch silently dropped to 0 — leaving every emitted
/// Relation with `timestamp:0` and `graph_summary.time_range = null`.
fn derive_timestamp(kv: &HashMap<String, String>) -> i64 {
    // 1. Numeric epoch (s/ms/us/ns) in `timestamp=`
    if let Some(raw) = kv.get("timestamp") {
        if let Ok(ts) = raw.parse::<i64>() {
            return normalize_epoch(ts);
        }
        // 1b. String ISO 8601 in `timestamp=` (FortiGate `.final.csv`).
        if let Some(epoch) = parse_iso_timestamp(raw) {
            return epoch;
        }
    }
    // 2. Numeric epoch in `eventtime=`; defensively also accept ISO.
    if let Some(raw) = kv.get("eventtime") {
        if let Ok(ts) = raw.parse::<i64>() {
            return normalize_epoch(ts);
        }
        if let Some(epoch) = parse_iso_timestamp(raw) {
            return epoch;
        }
    }
    // 3. Combined `date=` + `time=`.
    if let (Some(d), Some(t)) = (kv.get("date"), kv.get("time")) {
        let combined = format!("{d} {t}");
        for fmt in &["%Y-%m-%d %H:%M:%S", "%Y/%m/%d %H:%M:%S", "%Y-%m-%dT%H:%M:%S"] {
            if let Ok(dt) = NaiveDateTime::parse_from_str(&combined, fmt) {
                return dt.and_utc().timestamp();
            }
        }
    }
    // 4. Fall back to 0 + warn. We deliberately preserve the row (a
    //    null/0 timestamp is better than dropped data for syslog-style
    //    inputs whose field shape varies across FortiOS versions).
    eprintln!(
        "Warning: FortiGate parser could not derive timestamp from KV \
         (timestamp={:?}, eventtime={:?}, date={:?}, time={:?})",
        kv.get("timestamp"),
        kv.get("eventtime"),
        kv.get("date"),
        kv.get("time"),
    );
    0
}

/// Parse an ISO 8601 timestamp into Unix epoch seconds.
///
/// Accepts FortiGate's actual shape `YYYY-MM-DDTHH:MM:SS` (treated as
/// UTC), plus defensive variants:
///   * trailing `Z`         (`...:25Z`)
///   * fractional seconds   (`...:25.123`)
///   * explicit offset      (`...:25+02:00`, `...:25-05:00`)
///
/// Mirrors the cascade in `core/graph-engine/src/sentinel.rs` so the
/// two parsers agree on what counts as a parseable timestamp.
fn parse_iso_timestamp(ts: &str) -> Option<i64> {
    let trimmed = ts.trim();
    // 1. RFC 3339 / ISO 8601 with timezone offset (e.g. `...+00:00`, `...Z`).
    if let Ok(dt) = DateTime::parse_from_rfc3339(trimmed) {
        return Some(dt.timestamp());
    }
    // 2. Naive UTC, no fractional seconds (FortiGate's actual `.final.csv` shape).
    if let Ok(dt) =
        NaiveDateTime::parse_from_str(trimmed.trim_end_matches('Z'), "%Y-%m-%dT%H:%M:%S")
    {
        return Some(dt.and_utc().timestamp());
    }
    // 3. Naive UTC with fractional seconds.
    if let Ok(dt) =
        NaiveDateTime::parse_from_str(trimmed.trim_end_matches('Z'), "%Y-%m-%dT%H:%M:%S%.f")
    {
        return Some(dt.and_utc().timestamp());
    }
    None
}

/// FortiOS variants store epoch in seconds, milliseconds, microseconds
/// or nanoseconds. Normalise to seconds using order-of-magnitude buckets
/// (≥1e18: ns, ≥1e15: us, ≥1e12: ms, else s).
fn normalize_epoch(v: i64) -> i64 {
    let av = v.unsigned_abs();
    if av >= 1_000_000_000_000_000_000 {
        v / 1_000_000_000
    } else if av >= 1_000_000_000_000_000 {
        v / 1_000_000
    } else if av >= 1_000_000_000_000 {
        v / 1_000
    } else {
        v
    }
}

/// Tiny hand-rolled KV parser. Recognises `key="quoted value with spaces"`
/// and `key=bareword`. Keys are `[A-Za-z0-9_-]+` (anchored on `=`). The
/// parser is whitespace-delimited otherwise and tolerant of multiple
/// spaces, leading whitespace, and embedded `,` inside quoted values.
fn extract_kv_pairs(line: &str) -> HashMap<String, String> {
    let mut out = HashMap::new();
    let bytes = line.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        // skip ws/separators
        while i < bytes.len() && (bytes[i] == b' ' || bytes[i] == b'\t' || bytes[i] == b',') {
            i += 1;
        }
        if i >= bytes.len() {
            break;
        }
        // read key
        let key_start = i;
        while i < bytes.len() {
            let c = bytes[i];
            if c.is_ascii_alphanumeric() || c == b'_' || c == b'-' {
                i += 1;
            } else {
                break;
            }
        }
        if i >= bytes.len() || bytes[i] != b'=' || i == key_start {
            // Not a KV start — advance to next whitespace and retry.
            while i < bytes.len() && bytes[i] != b' ' && bytes[i] != b'\t' {
                i += 1;
            }
            continue;
        }
        let key = &line[key_start..i];
        i += 1; // skip '='
        // read value
        let value: String = if i < bytes.len() && bytes[i] == b'"' {
            i += 1;
            let v_start = i;
            while i < bytes.len() && bytes[i] != b'"' {
                i += 1;
            }
            let v = &line[v_start..i.min(bytes.len())];
            if i < bytes.len() {
                i += 1;
            } // skip closing quote
            v.to_string()
        } else {
            let v_start = i;
            while i < bytes.len()
                && bytes[i] != b' '
                && bytes[i] != b'\t'
                && bytes[i] != b','
            {
                i += 1;
            }
            line[v_start..i].to_string()
        };
        out.insert(key.to_ascii_lowercase(), value);
    }
    out
}

// ── CSV row splitting (RFC-4180 lite, shared with cognito-style quoting) ──

fn split_csv_row(line: &str) -> Vec<String> {
    let mut fields = Vec::new();
    let mut current = String::new();
    let mut in_quotes = false;
    let mut chars = line.chars().peekable();
    while let Some(ch) = chars.next() {
        match ch {
            '"' => {
                if in_quotes {
                    if chars.peek() == Some(&'"') {
                        current.push('"');
                        chars.next();
                    } else {
                        in_quotes = false;
                    }
                } else {
                    in_quotes = true;
                }
            }
            ',' if !in_quotes => {
                fields.push(std::mem::take(&mut current));
            }
            _ => current.push(ch),
        }
    }
    fields.push(current);
    fields
}

/// Reconstruct a FortiGate KV line from a header row + a body row.
/// Escapes embedded `"` inside cell values so the result is parseable
/// by [`extract_kv_pairs`]. Skips empty header cells defensively.
fn synthesize_kv_line(headers: &[String], cells: &[String]) -> String {
    let mut out = String::new();
    for (i, h) in headers.iter().enumerate() {
        let key = h.trim();
        if key.is_empty() {
            continue;
        }
        let raw = cells.get(i).map(|s| s.as_str()).unwrap_or("");
        // Drop quotes from the cell so they can't terminate the KV
        // quoted-string early. FortiGate field values never carry `"`
        // literals in practice.
        let v = raw.replace('"', "");
        if !out.is_empty() {
            out.push(' ');
        }
        out.push_str(key);
        out.push('=');
        out.push('"');
        out.push_str(&v);
        out.push('"');
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    const KV_LINE_WITH_ATTACK: &str = concat!(
        r#"date="2026-05-28" time="14:14:20" devname="FW-CORE-01" "#,
        r#"srcip="172.25.15.1" dstip="192.168.53.96" srcport="51920" dstport="443" "#,
        r#"action="dropped" severity="high" service="HTTPS" proto="6" "#,
        r#"policyid="42" policyname="DENY_GUEST_TO_DC" sentbyte="1024" rcvdbyte="0" "#,
        r#"sentpkt="4" attack="FortiOS.SSL.VPN.Custom.Information.Disclosure""#,
    );

    const KV_LINE_NO_ATTACK: &str = concat!(
        r#"date="2026-05-28" time="14:14:21" "#,
        r#"srcip="10.0.0.5" dstip="10.0.0.10" dstport="80" "#,
        r#"action="close" severity="low" service="HTTP""#,
    );

    #[test]
    fn looks_like_fortigate_recognizes_kv_line() {
        assert!(looks_like_fortigate(KV_LINE_WITH_ATTACK));
        assert!(looks_like_fortigate(KV_LINE_NO_ATTACK));
        assert!(!looks_like_fortigate(
            r#"{"Type":"SecurityEvent","EventID":4624}"#
        ));
        assert!(!looks_like_fortigate("plain text with no markers"));
    }

    #[test]
    fn parses_kv_line_emits_connect_and_triggered_triples() {
        let parser = FortiGateParser::new();
        let triples = parser.parse(KV_LINE_WITH_ATTACK);
        // KV_LINE_WITH_ATTACK has dstport + policyname + attack → Connect + Exposes + MatchedPolicy + Triggered = 4.
        assert_eq!(
            triples.len(),
            4,
            "expected 4 triples (Connect + Exposes + MatchedPolicy + Triggered), got {}",
            triples.len()
        );

        // Connect triple: srcip -[Connect]-> dstip.
        let (ref src, ref rel, ref dst) = triples
            .iter()
            .find(|(_, r, _)| r.rel_type == RelationType::Connect)
            .map(|(a, b, c)| (a, b, c))
            .expect("Connect triple must be present");
        assert_eq!(src.id, "172.25.15.1");
        assert_eq!(src.entity_type, EntityType::IP);
        assert_eq!(dst.id, "192.168.53.96");
        assert_eq!(dst.entity_type, EntityType::IP);
        assert_eq!(rel.rel_type, RelationType::Connect);
        // Edge metadata must surface the policy verdict + severity.
        assert_eq!(rel.metadata.get("action").map(|s| s.as_str()), Some("dropped"));
        assert_eq!(rel.metadata.get("severity").map(|s| s.as_str()), Some("high"));
        assert_eq!(rel.metadata.get("dstport").map(|s| s.as_str()), Some("443"));
        assert_eq!(rel.metadata.get("policyname").map(|s| s.as_str()), Some("DENY_GUEST_TO_DC"));
        assert_eq!(rel.metadata.get("devname").map(|s| s.as_str()), Some("FW-CORE-01"));

        // Triggered triple: srcip -[Triggered]-> attack (Signature).
        let (ref src2, ref rel2, ref dst2) = triples
            .iter()
            .find(|(_, r, _)| r.rel_type == RelationType::Other("Triggered".to_string()))
            .map(|(a, b, c)| (a, b, c))
            .expect("Triggered triple must be present");
        assert_eq!(src2.id, "172.25.15.1");
        assert_eq!(dst2.id, "FortiOS.SSL.VPN.Custom.Information.Disclosure");
        assert_eq!(
            dst2.entity_type,
            EntityType::Other("Signature".to_string()),
            "attack must be Other(\"Signature\"), NOT Domain"
        );
        assert_eq!(
            rel2.rel_type,
            RelationType::Other("Triggered".to_string()),
            "attack edge must be Triggered, NOT DNS"
        );
    }

    #[test]
    fn dropped_close_actions_never_emit_delete_or_dns() {
        let parser = FortiGateParser::new();
        for line in &[KV_LINE_WITH_ATTACK, KV_LINE_NO_ATTACK] {
            let triples = parser.parse(line);
            for (_, rel, _) in &triples {
                assert_ne!(
                    rel.rel_type,
                    RelationType::Delete,
                    "FortiGate 'dropped'/'close' must not become Delete"
                );
                assert_ne!(
                    rel.rel_type,
                    RelationType::DNS,
                    "FortiGate edges must not be DNS"
                );
            }
        }
    }

    #[test]
    fn dstport_never_becomes_an_entity() {
        let parser = FortiGateParser::new();
        let triples = parser.parse(KV_LINE_WITH_ATTACK);
        for (src, _, dst) in &triples {
            for ent in [src, dst] {
                // No entity should be typed as IP with a port-shaped ID.
                if ent.entity_type == EntityType::IP {
                    assert!(
                        ent.id.contains('.') || ent.id.contains(':'),
                        "IP entity '{}' looks like a port number — port leaked into IP namespace",
                        ent.id
                    );
                    // Defensive against the specific port values in the test fixture.
                    assert_ne!(ent.id, "443", "dstport must not be promoted to IP entity");
                    assert_ne!(ent.id, "51920", "srcport must not be promoted to IP entity");
                    assert_ne!(ent.id, "80", "dstport must not be promoted to IP entity");
                }
            }
        }
    }

    #[test]
    fn devname_does_not_become_a_host_entity() {
        let parser = FortiGateParser::new();
        let triples = parser.parse(KV_LINE_WITH_ATTACK);
        for (src, _, dst) in &triples {
            for ent in [src, dst] {
                assert_ne!(
                    ent.id, "FW-CORE-01",
                    "devname must stay on rel.metadata, not become a Host"
                );
                assert_ne!(
                    ent.entity_type,
                    EntityType::Host,
                    "no Host entities should be emitted"
                );
            }
        }
        // …but devname must be on edge metadata.
        let (_, rel, _) = triples
            .iter()
            .find(|(_, r, _)| r.rel_type == RelationType::Connect)
            .expect("Connect triple");
        assert_eq!(rel.metadata.get("devname").map(|s| s.as_str()), Some("FW-CORE-01"));
    }

    #[test]
    fn timestamp_combines_date_and_time() {
        let parser = FortiGateParser::new();
        let triples = parser.parse(KV_LINE_NO_ATTACK);
        // KV_LINE_NO_ATTACK has dstport=80 → Connect + Exposes = 2 triples.
        assert_eq!(triples.len(), 2);
        let ts = triples[0].1.timestamp;
        // Expected epoch is computed from chrono — no magic constants.
        let expected = NaiveDateTime::parse_from_str(
            "2026-05-28T14:14:21",
            "%Y-%m-%dT%H:%M:%S",
        )
        .unwrap()
        .and_utc()
        .timestamp();
        assert_eq!(ts, expected);
        assert_ne!(ts, 0, "bug #69 regression: ts must not fall back to 0");
    }

    /// Bug #69 primary regression: FortiGate `.final.csv` exports ship a
    /// single STRING `timestamp=YYYY-MM-DDTHH:MM:SS` cell. The original
    /// numeric-only parse silently dropped this to 0. Assert the new
    /// ISO-string branch picks it up.
    #[test]
    fn timestamp_iso_string_in_timestamp_field() {
        let line = r#"timestamp="2026-05-21T23:18:25" devname="FW-CORE-01" srcip="172.25.15.1" dstip="192.168.53.96" dstport="443" action="dropped""#;
        let parser = FortiGateParser::new();
        let triples = parser.parse(line);
        // dstport="443" → Connect + Exposes = 2 triples.
        assert_eq!(triples.len(), 2, "expected Connect + Exposes triples");
        let ts = triples[0].1.timestamp;
        let expected = NaiveDateTime::parse_from_str(
            "2026-05-21T23:18:25",
            "%Y-%m-%dT%H:%M:%S",
        )
        .unwrap()
        .and_utc()
        .timestamp();
        assert_eq!(ts, expected);
        assert_ne!(ts, 0, "bug #69 regression: ISO timestamp must parse, not fall back to 0");
        // metadata.timestamp_raw should still carry the original ISO string for analyst inspection.
        assert_eq!(
            triples[0].1.metadata.get("timestamp_raw").map(|s| s.as_str()),
            Some("2026-05-21T23:18:25")
        );
    }

    /// Defensive: accept `Z`, millisecond, and offset suffixes too.
    #[test]
    fn timestamp_iso_defensive_variants_all_parse() {
        let expected_naive = NaiveDateTime::parse_from_str(
            "2026-05-21T23:18:25",
            "%Y-%m-%dT%H:%M:%S",
        )
        .unwrap()
        .and_utc()
        .timestamp();

        let parser = FortiGateParser::new();
        // (a) trailing Z
        let line_z = r#"timestamp="2026-05-21T23:18:25Z" srcip="1.1.1.1" dstip="2.2.2.2""#;
        assert_eq!(parser.parse(line_z)[0].1.timestamp, expected_naive);
        // (b) millis
        let line_ms = r#"timestamp="2026-05-21T23:18:25.123" srcip="1.1.1.1" dstip="2.2.2.2""#;
        assert_eq!(parser.parse(line_ms)[0].1.timestamp, expected_naive);
        // (c) explicit +00:00 offset → identical epoch
        let line_off = r#"timestamp="2026-05-21T23:18:25+00:00" srcip="1.1.1.1" dstip="2.2.2.2""#;
        assert_eq!(parser.parse(line_off)[0].1.timestamp, expected_naive);
        // (d) explicit -05:00 offset → epoch shifts by +5h
        let line_neg = r#"timestamp="2026-05-21T23:18:25-05:00" srcip="1.1.1.1" dstip="2.2.2.2""#;
        assert_eq!(
            parser.parse(line_neg)[0].1.timestamp,
            expected_naive + 5 * 3600
        );
    }

    /// Negative: missing/malformed timestamp must fall back to 0 (not
    /// panic, not drop the row). Preserves the "never drop rows" contract.
    #[test]
    fn timestamp_missing_or_malformed_falls_back_to_zero() {
        let parser = FortiGateParser::new();
        // (a) no timestamp / date / time at all
        let line_none = r#"srcip="1.1.1.1" dstip="2.2.2.2" action="allow""#;
        let triples_none = parser.parse(line_none);
        assert_eq!(triples_none.len(), 1, "row must NOT be dropped");
        assert_eq!(triples_none[0].1.timestamp, 0);
        // (b) malformed ISO string
        let line_bad = r#"timestamp="not-a-date" srcip="1.1.1.1" dstip="2.2.2.2""#;
        let triples_bad = parser.parse(line_bad);
        assert_eq!(triples_bad.len(), 1, "row must NOT be dropped on malformed ts");
        assert_eq!(triples_bad[0].1.timestamp, 0);
        // (c) empty-string timestamp (chrono parsers all reject empty → 0 fallback)
        let line_empty = r#"timestamp="" srcip="1.1.1.1" dstip="2.2.2.2""#;
        let triples_empty = parser.parse(line_empty);
        assert_eq!(triples_empty.len(), 1, "row must NOT be dropped on empty ts");
        assert_eq!(triples_empty[0].1.timestamp, 0);
        // (d) date-only ISO ("YYYY-MM-DD") — no time component, all chrono
        // parsers fail because they require HH:MM:SS → 0 fallback preserves row.
        let line_date_only = r#"timestamp="2026-05-21" srcip="1.1.1.1" dstip="2.2.2.2""#;
        let triples_date_only = parser.parse(line_date_only);
        assert_eq!(triples_date_only.len(), 1, "row must NOT be dropped on date-only ts");
        assert_eq!(triples_date_only[0].1.timestamp, 0);
    }

    /// Bug #69 multi-emission guard: an IPS event yields a Connect AND a
    /// Triggered edge — both must carry the SAME parsed (non-zero) timestamp,
    /// derived from a single parse of the line.
    #[test]
    fn timestamp_shared_across_connect_and_triggered_emissions() {
        let line = r#"timestamp="2026-05-21T23:18:25" devname="FW-CORE-01" srcip="172.25.15.1" dstip="192.168.53.96" dstport="443" action="dropped" attack="FortiOS.SSL.VPN.Custom.Information.Disclosure""#;
        let parser = FortiGateParser::new();
        let triples = parser.parse(line);
        // dstport="443" + attack → Connect + Exposes + Triggered = 3 triples.
        assert_eq!(triples.len(), 3, "expected Connect + Exposes + Triggered triples");
        let connect_triple = triples.iter().find(|(_, r, _)| r.rel_type == RelationType::Connect).expect("Connect triple");
        let triggered_triple = triples.iter().find(|(_, r, _)| r.rel_type == RelationType::Other("Triggered".to_string())).expect("Triggered triple");
        let ts_connect = connect_triple.1.timestamp;
        let ts_triggered = triggered_triple.1.timestamp;
        assert_ne!(ts_connect, 0, "Connect ts must be parsed, not 0");
        assert_ne!(ts_triggered, 0, "Triggered ts must be parsed, not 0");
        assert_eq!(
            ts_connect, ts_triggered,
            "both emissions from the same event must share the same timestamp"
        );
        // Confirm both edges are correctly typed too (regression guard).
        assert_eq!(connect_triple.1.rel_type, RelationType::Connect);
        assert_eq!(
            triggered_triple.1.rel_type,
            RelationType::Other("Triggered".to_string())
        );
    }

    #[test]
    fn missing_srcip_or_dstip_skips_event() {
        let parser = FortiGateParser::new();
        assert!(parser.parse(r#"date="2026-05-28" srcip="1.2.3.4" action="allow""#).is_empty());
        assert!(parser.parse(r#"date="2026-05-28" dstip="1.2.3.4" action="allow""#).is_empty());
    }

    #[test]
    fn csv_with_headers_path() {
        let csv = concat!(
            "date,time,srcip,dstip,dstport,action,severity\n",
            "2026-05-28,14:14:20,172.25.15.1,192.168.53.96,443,dropped,high\n",
            "2026-05-28,14:14:21,10.0.0.5,10.0.0.10,80,close,low\n",
        );
        let parser = FortiGateParser::new();
        let triples = parser.parse(csv);
        // 2 CSV rows, each with dstport → Connect + Exposes per row = 4 total.
        assert_eq!(triples.len(), 4);
        let (ref src, ref rel, ref dst) = triples[0];
        assert_eq!(src.id, "172.25.15.1");
        assert_eq!(dst.id, "192.168.53.96");
        assert_eq!(rel.rel_type, RelationType::Connect);
        assert_eq!(rel.metadata.get("action").map(|s| s.as_str()), Some("dropped"));
        assert_eq!(rel.metadata.get("dstport").map(|s| s.as_str()), Some("443"));
    }

    /// Bug #69 end-to-end: a `.final.csv` export with a single `timestamp`
    /// ISO column (no separate date/time) must produce Relations with the
    /// parsed epoch — not the 0 fallback. This is the exact customer shape.
    #[test]
    fn csv_with_headers_iso_timestamp_column() {
        let csv = concat!(
            "timestamp,srcip,dstip,dstport,action\n",
            "2026-05-21T23:18:25,1.1.1.1,2.2.2.2,443,allow\n",
        );
        let parser = FortiGateParser::new();
        let triples = parser.parse(csv);
        // dstport=443 → Connect + Exposes = 2 triples.
        assert_eq!(triples.len(), 2);
        // Expected epoch: 2026-05-21T23:18:25 UTC
        let expected = chrono::NaiveDate::from_ymd_opt(2026, 5, 21)
            .unwrap()
            .and_hms_opt(23, 18, 25)
            .unwrap()
            .and_utc()
            .timestamp();
        assert_eq!(
            triples[0].1.timestamp, expected,
            "single-column ISO `timestamp` must be parsed, not 0"
        );
        assert_ne!(triples[0].1.timestamp, 0);
    }

    #[test]
    fn bare_value_kv_pairs_are_accepted() {
        // Some FortiGate exports omit quoting on simple alphanumeric
        // values; the parser must still find srcip/dstip.
        // No dstport → only Connect, no Exposes.
        let line = "date=2026-05-28 time=14:14:20 srcip=1.1.1.1 dstip=2.2.2.2 action=allow";
        let parser = FortiGateParser::new();
        let triples = parser.parse(line);
        assert_eq!(triples.len(), 1);
        assert_eq!(triples[0].0.id, "1.1.1.1");
        assert_eq!(triples[0].2.id, "2.2.2.2");
        assert_eq!(
            triples[0].1.metadata.get("action").map(|s| s.as_str()),
            Some("allow")
        );
    }

    #[test]
    fn snat_flow_emits_all_satellite_nodes() {
        let line = r#"date=2026-05-28 time=14:14:20 devname="FW_FGT_VPN" srcip="172.25.15.1" dstip="192.168.53.96" dstport=9699 action=close policyid=348 policyname="MIGRACION TELECARGA" service="TELECARGA" trandisp="snat" transip="128.36.11.249""#;
        let triples = parse_kv_line(line);

        let connect = triples.iter().find(|(_, r, _)| r.rel_type == RelationType::Connect).expect("Connect edge");
        assert_eq!(connect.0.id, "172.25.15.1");
        assert_eq!(connect.2.id, "192.168.53.96");

        let snat = triples.iter().find(|(_, r, _)| r.rel_type == RelationType::Other("SNAT".to_string())).expect("SNAT edge");
        assert_eq!(snat.0.id, "172.25.15.1");
        assert_eq!(snat.2.id, "128.36.11.249");
        assert_eq!(snat.2.entity_type, EntityType::IP);

        let exp = triples.iter().find(|(_, r, _)| r.rel_type == RelationType::Other("Exposes".to_string())).expect("Exposes edge");
        assert_eq!(exp.0.id, "192.168.53.96");
        assert_eq!(exp.2.id, "192.168.53.96:9699");
        assert_eq!(exp.2.entity_type, EntityType::Service);
        assert_eq!(exp.2.metadata.get("port").map(String::as_str), Some("9699"));
        assert_eq!(exp.2.metadata.get("service").map(String::as_str), Some("TELECARGA"));

        let pol = triples.iter().find(|(_, r, _)| r.rel_type == RelationType::Other("MatchedPolicy".to_string())).expect("MatchedPolicy edge");
        assert_eq!(pol.0.id, "172.25.15.1");
        assert_eq!(pol.2.id, "MIGRACION TELECARGA");
        assert_eq!(pol.2.entity_type, EntityType::Other("Policy".to_string()));
        assert_eq!(pol.2.metadata.get("policyid").map(String::as_str), Some("348"));

        assert_eq!(triples.len(), 4, "SNAT flow with dstport+policyname+snat => Connect+SNAT+Exposes+MatchedPolicy");
    }

    #[test]
    fn noop_flow_emits_no_snat_edge() {
        let line = r#"date=2026-05-28 time=14:14:13 devname="FW_FGT_INTERNO" srcip="172.25.15.1" dstip="192.168.53.96" dstport=9181 action=close policyid=1710 policyname="SGDC-551684_I" trandisp="noop""#;
        let triples = parse_kv_line(line);
        assert!(triples.iter().all(|(_, r, _)| r.rel_type != RelationType::Other("SNAT".to_string())), "noop flow must not emit a SNAT edge");
        assert!(triples.iter().any(|(_, r, _)| r.rel_type == RelationType::Other("Exposes".to_string())));
        assert!(triples.iter().any(|(_, r, _)| r.rel_type == RelationType::Other("MatchedPolicy".to_string())));
        assert!(triples.iter().any(|(_, r, _)| r.rel_type == RelationType::Connect));
    }

    #[test]
    fn missing_policy_emits_no_policy_edge() {
        let line = r#"srcip="10.0.0.1" dstip="10.0.0.2" dstport=443 action=close trandisp="noop""#;
        let triples = parse_kv_line(line);
        assert!(triples.iter().all(|(_, r, _)| r.rel_type != RelationType::Other("MatchedPolicy".to_string())), "no policyname -> no MatchedPolicy edge");
        let exp = triples.iter().find(|(_, r, _)| r.rel_type == RelationType::Other("Exposes".to_string())).expect("Exposes edge");
        assert_eq!(exp.2.id, "10.0.0.2:443");
    }

    #[test]
    fn extract_kv_handles_quoted_value_with_dots() {
        let kv = extract_kv_pairs(
            r#"attack="FortiOS.SSL.VPN.Custom.Information.Disclosure" action="dropped""#,
        );
        assert_eq!(
            kv.get("attack").map(|s| s.as_str()),
            Some("FortiOS.SSL.VPN.Custom.Information.Disclosure")
        );
        assert_eq!(kv.get("action").map(|s| s.as_str()), Some("dropped"));
    }
}
