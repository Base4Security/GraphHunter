//! Native FortiWeb WAF log parser (attack `alog` + event `elog`).
//!
//! # Why this is not the FortiGate parser
//!
//! Both are Fortinet key/value logs, and both arrived in this corpus named
//! `.csv`. They are not the same shape:
//!
//! | | FortiGate | FortiWeb |
//! |---|---|---|
//! | separator | space | comma |
//! | endpoints | `srcip` / `dstip` | `src` / `dst` |
//! | log id | `logid="0101039944"` | `log_id=20000008` |
//! | device | `devname` | `device_id` |
//! | line start | `date=` | vendor prefix, then `date=` |
//!
//! [`looks_like_fortigate`](crate::fortigate::looks_like_fortigate) keys on
//! `srcip=`/`dstip=`, which FortiWeb never emits, so a FortiWeb file fell
//! through every detector to the generic `csv` fallback. `CsvParser` then
//! saw one enormous unnamed column per line and produced nothing useful —
//! no error, just an almost-empty graph.
//!
//! # Three shape hazards this parser handles
//!
//! 1. **A vendor prefix before `date=`.** Lines begin with a short
//!    forwarding header (`v015….`) glued to the first key, so a naive KV
//!    scan reads the key as `v015xxxxdate` and the `date` field vanishes.
//!    [`strip_record_prefix`] slices from the first `date=` instead of
//!    assuming a fixed prefix width, since that header is vendor/version
//!    specific.
//! 2. **Whole `key=value` pairs wrapped in quotes.** FortiWeb writes
//!    `vd="root","timezone=(GMT-3:00)Buenos Aires, Georgetown"` — the
//!    quotes span the `=`, and the value itself contains a comma. Tokens
//!    are therefore split on commas *outside* quotes, then unwrapped.
//! 3. **Multi-line values.** When the attack payload is multi-line (an
//!    Elasticsearch RCE body, say) FortiWeb writes the raw newlines into
//!    `msg="…"`. The ingest layer keeps such a record whole
//!    (`StreamMode::Quoted`); this parser must therefore accept a record
//!    that spans several physical lines, so it splits input on record
//!    boundaries rather than on `\n`.
//!
//! # Emitted triples
//!
//! Up to five per record, all anchored on the attacking source IP so a
//! traversal from one IP reaches what it hit, what it tripped, and where:
//!
//! * `src -[Connect]-> dst` — the network fact (always, when both present);
//! * `src -[Triggered]-> Signature(signature_id)` — the WAF verdict;
//! * `src -[Request]-> URL(http_url)` — what was actually requested;
//! * `src -[Targets]-> Domain(http_host)` — which virtual host;
//! * `src -[MatchedPolicy]-> Policy(policy)` — which WAF policy fired.
//!
//! In the attack log `device_id` deliberately does **not** become a node:
//! every one of a million records would link back to it, producing a star
//! hub that dominates PageRank and degree centrality. It travels as edge
//! metadata. This mirrors the `devname` decision in [`crate::fortigate`].
//!
//! # The event log is a second shape
//!
//! `elog` records carry no `src` — their subject is an administrator, not
//! an attacker — so they get their own triple
//! (`User -[Auth|Modify]-> Appliance`) in [`parse_admin_record`], behind a
//! filter that drops the appliance's own daemon housekeeping. Treating
//! them as "not an attack record" and returning nothing, as this parser
//! first did, made a 36 MB `elog` ingest as an empty graph.
//!
//! Here `device_id` *is* a node, and the hub argument above does not
//! apply in reverse: after the filter only ~1.2 k administrator actions
//! remain, and the appliance is the thing they were performed on.

use std::collections::HashMap;

use chrono::NaiveDateTime;

use graph_hunter_core::entity::Entity;
use graph_hunter_core::parser::{LogParser, ParsedTriple};
use graph_hunter_core::relation::Relation;
use graph_hunter_core::types::{EntityType, RelationType};

/// Fields copied onto every edge produced by a record. Chosen for triage:
/// what the WAF did, how bad it judged it, and enough request context to
/// pivot without re-reading the raw log.
const EDGE_METADATA_FIELDS: &[&str] = &[
    "action",
    "severity_level",
    "main_type",
    "sub_type",
    "type",
    "subtype",
    "http_method",
    "http_agent",
    "http_version",
    "service",
    "proto",
    "dst_port",
    "src_port",
    "threat_level",
    "threat_weight",
    "srccountry",
    "policy",
    "signature_subclass",
    "signature_cve_id",
    "owasp_top10",
    "owasp_api_top10",
    "client_level",
    "bot_info",
    "content_switch_name",
    "server_pool_name",
    "user_name",
    "device_id",
    "log_id",
    "msg_id",
    "http_session_id",
    "msg",
    "status",
    "ui",
    "user",
];

/// Values FortiWeb writes when a field is simply absent. Treating them as
/// real would mint entities like `Signature("N/A")` that every unrelated
/// record links to — a synthetic hub, the exact artefact the `device_id`
/// exclusion above avoids.
fn is_placeholder(v: &str) -> bool {
    v.is_empty() || v.eq_ignore_ascii_case("n/a") || v.eq_ignore_ascii_case("none")
}

/// True when `contents` looks like a FortiWeb log.
///
/// Anchored on `log_id=` (underscored — FortiGate writes `logid=`) plus a
/// comma-separated KV body. Requiring both keeps this off FortiGate files
/// and off ordinary CSVs that merely contain the word `date`.
pub fn looks_like_fortiweb(contents: &str) -> bool {
    // Fast prefix probe — never scan a multi-GB file to answer this.
    let probe = if contents.len() > 8192 {
        // Cut on a char boundary: `contents` is a &str and slicing mid
        // UTF-8 sequence would panic on logs carrying non-ASCII payloads.
        match contents
            .char_indices()
            .take_while(|(i, _)| *i <= 8192)
            .last()
        {
            Some((i, c)) => &contents[..i + c.len_utf8()],
            None => contents,
        }
    } else {
        contents
    };
    let Some(first) = probe.lines().find(|l| !l.trim().is_empty()) else {
        return false;
    };
    let head = first.trim_start_matches('\u{feff}');
    // FortiGate's space-delimited KV must never land here.
    if head.contains("srcip=") || head.contains("dstip=") || head.contains("devname=") {
        return false;
    }
    let has_log_id = head.contains("log_id=");
    let has_date = head.contains("date=");
    let comma_kv = head.contains(",") && head.contains("=");
    // `device_id=FWB…` and `main_type=` are FortiWeb-only; either one
    // corroborates a file whose first line lacks `log_id`.
    let corroborating = head.contains("device_id=")
        || head.contains("main_type=")
        || head.contains("severity_level=")
        || head.contains("http_host=");
    has_date && comma_kv && (has_log_id || corroborating)
}

/// Slice a record so it starts at its first `date=` key.
///
/// FortiWeb prefixes each record with a short forwarding header that is
/// glued directly to the first key (`…date=2026-08-01`). Left in place, the
/// KV scan reads `…date` as the key name and the record loses its date
/// entirely — which then silently costs every edge its timestamp.
///
/// The search is bounded: a line whose `date=` appears far in is not a
/// prefixed record but some other text, and slicing to it would corrupt it.
fn strip_record_prefix(record: &str) -> &str {
    let r = record.trim_start_matches('\u{feff}').trim_start();
    if r.starts_with("date=") {
        return r;
    }
    const MAX_PREFIX: usize = 64;
    let window = &r[..r.len().min(MAX_PREFIX)];
    match window.find("date=") {
        Some(i) => &r[i..],
        None => r,
    }
}

/// Split a record body into `key -> value`, honouring FortiWeb quoting.
///
/// Separators are commas **outside** quotes. A token may be entirely
/// wrapped in quotes with the `=` inside it
/// (`"timezone=(GMT-3:00)Buenos Aires, Georgetown"`), so the outer quotes
/// are stripped before the key/value split rather than after.
fn extract_pairs(record: &str) -> HashMap<String, String> {
    let mut out = HashMap::new();
    for token in split_outside_quotes(record) {
        let token = token.trim();
        if token.is_empty() {
            continue;
        }
        // Unwrap a token whose quotes span the `=`.
        let token = if token.len() >= 2 && token.starts_with('"') && token.ends_with('"') {
            &token[1..token.len() - 1]
        } else {
            token
        };
        let Some(eq) = token.find('=') else { continue };
        let key = token[..eq].trim();
        if key.is_empty() {
            continue;
        }
        let raw_value = token[eq + 1..].trim();
        out.insert(key.to_ascii_lowercase(), unquote(raw_value));
    }
    out
}

/// Split on commas that are not inside a double-quoted run. Backslash
/// escapes an inner quote, matching how FortiWeb writes captured payloads.
fn split_outside_quotes(s: &str) -> Vec<&str> {
    let bytes = s.as_bytes();
    let mut out = Vec::new();
    let mut start = 0usize;
    let mut in_quotes = false;
    let mut i = 0usize;
    while i < bytes.len() {
        match bytes[i] {
            b'\\' if in_quotes => i += 2,
            b'"' => {
                in_quotes = !in_quotes;
                i += 1;
            }
            b',' if !in_quotes => {
                out.push(&s[start..i]);
                start = i + 1;
                i += 1;
            }
            _ => i += 1,
        }
    }
    if start <= s.len() {
        out.push(&s[start..]);
    }
    out
}

/// Strip surrounding quotes and undo backslash escapes.
fn unquote(v: &str) -> String {
    let inner = if v.len() >= 2 && v.starts_with('"') && v.ends_with('"') {
        &v[1..v.len() - 1]
    } else {
        v
    };
    if !inner.contains('\\') {
        return inner.to_string();
    }
    let mut out = String::with_capacity(inner.len());
    let mut chars = inner.chars();
    while let Some(c) = chars.next() {
        if c == '\\' {
            match chars.next() {
                Some(next) => out.push(next),
                None => out.push('\\'),
            }
        } else {
            out.push(c);
        }
    }
    out
}

/// Collapse an epoch of unknown precision (s / ms / us / ns) to seconds.
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

/// Epoch seconds for a record: `eventtime` (ns) first, then `date`+`time`.
///
/// Falls back to 0 rather than dropping the record — a null timestamp is
/// recoverable, a discarded attack record is not.
fn derive_timestamp(kv: &HashMap<String, String>) -> i64 {
    if let Some(raw) = kv.get("eventtime")
        && let Ok(ts) = raw.parse::<i64>()
    {
        return normalize_epoch(ts);
    }
    if let (Some(d), Some(t)) = (kv.get("date"), kv.get("time")) {
        let combined = format!("{d} {t}");
        for fmt in &[
            "%Y-%m-%d %H:%M:%S",
            "%Y/%m/%d %H:%M:%S",
            "%Y-%m-%dT%H:%M:%S",
        ] {
            if let Ok(dt) = NaiveDateTime::parse_from_str(&combined, fmt) {
                return dt.and_utc().timestamp();
            }
        }
    }
    0
}

fn collect_edge_metadata(kv: &HashMap<String, String>) -> HashMap<String, String> {
    let mut out = HashMap::new();
    for field in EDGE_METADATA_FIELDS {
        if let Some(v) = kv.get(*field)
            && !is_placeholder(v)
        {
            out.insert((*field).to_string(), v.clone());
        }
    }
    if let (Some(d), Some(t)) = (kv.get("date"), kv.get("time")) {
        out.insert("timestamp_raw".into(), format!("{d} {t}"));
    }
    out
}

fn other(id: &str, ty: &str) -> Entity {
    Entity::new(id, EntityType::Other(ty.into()))
}

/// Actions that are an authentication rather than a configuration change.
const ADMIN_AUTH_ACTIONS: &[&str] = &["login", "logout"];

/// Parse an `elog` record — the appliance's own event log.
///
/// These carry no `src`, so the attack-shaped triples above do not apply.
/// Their subject is an administrator acting on the appliance:
///
/// * `User(user) -[Auth]-> Appliance(device_id)` for `login` / `logout`;
/// * `User(user) -[Modify]-> Appliance(device_id)` for `edit`, `add`,
///   `delete`, `backup` and friends.
///
/// # The noise filter
///
/// 97 % of a real `elog` is the appliance talking to itself:
/// `user=daemon, ui=daemon, action=update` — signature-database refreshes
/// and health checks, roughly 99 k records in the 36 MB corpus this was
/// written against. Emitting those would hang a 99 000-edge star off the
/// appliance node, burying the ~1 200 genuine administrator actions and
/// dominating every centrality measure — the same hub hazard that keeps
/// `device_id` off the graph elsewhere in this parser.
///
/// So an event is kept only when it is attributable to a human-reachable
/// interface: `subtype=admin`, or a `ui` that is not the internal daemon
/// (`sshd`, `GUI`, `jsconsole`). The filter is on the *interface*, not on
/// the username, so a renamed service account cannot smuggle noise in.
fn parse_admin_record(kv: &HashMap<String, String>) -> Vec<ParsedTriple> {
    let Some(user) = kv.get("user").filter(|v| !is_placeholder(v)) else {
        return Vec::new();
    };
    let Some(device) = kv.get("device_id").filter(|v| !is_placeholder(v)) else {
        return Vec::new();
    };
    let ui = kv.get("ui").map(String::as_str).unwrap_or("");
    let is_admin_subtype = kv.get("subtype").map(|s| s == "admin").unwrap_or(false);
    let human_interface = !ui.is_empty() && !ui.eq_ignore_ascii_case("daemon");
    if !is_admin_subtype && !human_interface {
        return Vec::new();
    }

    let timestamp = derive_timestamp(kv);
    let mut meta = collect_edge_metadata(kv);
    meta.insert("source_log".into(), "elog".into());

    let action = kv.get("action").map(String::as_str).unwrap_or("");
    let rel_type = if ADMIN_AUTH_ACTIONS.contains(&action) {
        RelationType::Auth
    } else {
        RelationType::Modify
    };

    let mut rel = Relation::new(user, device, rel_type, timestamp);
    rel.metadata = meta;
    let mut appliance = other(device, "Appliance");
    appliance
        .metadata
        .insert("vendor".into(), "fortiweb".into());
    vec![(Entity::new(user, EntityType::User), rel, appliance)]
}

/// Parse one FortiWeb record (which may span several physical lines).
fn parse_record(record: &str) -> Vec<ParsedTriple> {
    let body = strip_record_prefix(record);
    let kv = extract_pairs(body);
    let src = match kv.get("src") {
        Some(v) if !is_placeholder(v) => v.clone(),
        // No source IP: this is an `elog` record, the appliance's own
        // event log. It has a different subject — an administrator, not
        // an attacker — so it gets its own shape below rather than being
        // dropped. Returning nothing here is what made a 36 MB elog
        // ingest as an empty graph.
        _ => return parse_admin_record(&kv),
    };
    let timestamp = derive_timestamp(&kv);
    let meta = collect_edge_metadata(&kv);
    let mut triples = Vec::new();

    let src_entity = Entity::new(&src, EntityType::IP);

    // 1. src -[Connect]-> dst
    if let Some(dst) = kv.get("dst").filter(|v| !is_placeholder(v)) {
        let mut rel = Relation::new(&src, dst, RelationType::Connect, timestamp);
        rel.metadata = meta.clone();
        triples.push((src_entity.clone(), rel, Entity::new(dst, EntityType::IP)));
    }

    // 2. src -[Triggered]-> Signature
    if let Some(sig) = kv.get("signature_id").filter(|v| !is_placeholder(v)) {
        let mut rel = Relation::new(
            &src,
            sig,
            RelationType::Other("Triggered".into()),
            timestamp,
        );
        rel.metadata = meta.clone();
        let mut node = other(sig, "Signature");
        // The human-readable name lives on the node, not the edge: it is
        // a property of the signature, identical across every record that
        // trips it.
        if let Some(sub) = kv.get("signature_subclass").filter(|v| !is_placeholder(v)) {
            node.metadata.insert("subclass".into(), sub.clone());
        }
        if let Some(o) = kv.get("owasp_top10").filter(|v| !is_placeholder(v)) {
            node.metadata.insert("owasp_top10".into(), o.clone());
        }
        triples.push((src_entity.clone(), rel, node));
    }

    // 3. src -[Request]-> URL
    if let Some(url) = kv.get("http_url").filter(|v| !is_placeholder(v)) {
        let mut rel = Relation::new(&src, url, RelationType::Other("Request".into()), timestamp);
        rel.metadata = meta.clone();
        triples.push((src_entity.clone(), rel, Entity::new(url, EntityType::URL)));
    }

    // 4. src -[Targets]-> Domain
    if let Some(host) = kv.get("http_host").filter(|v| !is_placeholder(v)) {
        let mut rel = Relation::new(&src, host, RelationType::Other("Targets".into()), timestamp);
        rel.metadata = meta.clone();
        triples.push((
            src_entity.clone(),
            rel,
            Entity::new(host, EntityType::Domain),
        ));
    }

    // 5. src -[MatchedPolicy]-> Policy
    if let Some(policy) = kv.get("policy").filter(|v| !is_placeholder(v)) {
        let mut rel = Relation::new(
            &src,
            policy,
            RelationType::Other("MatchedPolicy".into()),
            timestamp,
        );
        rel.metadata = meta.clone();
        triples.push((src_entity.clone(), rel, other(policy, "Policy")));
    }

    triples
}

/// Split a chunk into records.
///
/// A record starts at a `date=` key at the beginning of a physical line
/// (optionally behind the vendor prefix). Any line that does not open a new
/// record is a continuation of the previous one — that is how a multi-line
/// attack payload stays attached to the record that captured it instead of
/// becoming orphan garbage lines.
fn split_records(data: &str) -> Vec<&str> {
    let mut out: Vec<&str> = Vec::new();
    let mut current_start: Option<usize> = None;
    let mut offset = 0usize;
    for line in data.split_inclusive('\n') {
        let starts_record = strip_record_prefix(line).starts_with("date=");
        if starts_record {
            if let Some(s) = current_start {
                out.push(&data[s..offset]);
            }
            current_start = Some(offset);
        }
        offset += line.len();
    }
    if let Some(s) = current_start {
        out.push(&data[s..]);
    }
    out
}

pub struct FortiWebParser;

impl Default for FortiWebParser {
    fn default() -> Self {
        Self::new()
    }
}

impl FortiWebParser {
    pub fn new() -> Self {
        Self
    }
}

impl LogParser for FortiWebParser {
    fn parse(&self, data: &str) -> Vec<ParsedTriple> {
        let mut out = Vec::new();
        for record in split_records(data) {
            out.extend(parse_record(record));
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ATTACK: &str = "v015xxxxdate=2026-08-01,time=22:34:07,log_id=20000008,msg_id=000000000001,device_id=FWBVMSTM00000001,eventtime=1785634447670281764,vd=\"root\",\"timezone=(GMT-3:00)Buenos Aires, Georgetown\",type=attack,pri=alert,main_type=\"Signature Detection\",sub_type=\"Information Disclosure\",trigger_policy=\"N/A\",severity_level=Low,proto=tcp,service=https/tls1.3,action=Alert,policy=\"SP_EJEMPLO\",src=198.51.100.5,src_port=46672,dst=10.0.9.10,dst_port=80,http_method=post,http_url=\"/api/auth0/register\",http_host=\"24app.example.com.ar\",signature_id=\"080080001\",signature_cve_id=\"N/A\",srccountry=\"Argentina\",owasp_top10=\"A02:2021-Cryptographic Failures\"\n";

    const EVENT: &str = "v015xxxxdate=2025-08-25,time=08:02:23,log_id=11005401,msg_id=000000000002,device_id=FWBVMSTM00000001,eventtime=1756119743526402955,vd=\"root\",type=event,subtype=\"system\",pri=notice,user=daemon,ui=daemon,action=update,status=success,msg=\"Fortiweb FSCI update succeeded\"\n";

    #[test]
    fn detects_fortiweb() {
        assert!(looks_like_fortiweb(ATTACK));
        assert!(looks_like_fortiweb(EVENT));
    }

    /// FortiGate's space-delimited KV shares the `date=`/`time=` opening
    /// but belongs to a different parser. If this ever returns true the
    /// registry order decides which parser wins, and FortiGate data would
    /// silently lose its `srcip -> dstip` edges.
    #[test]
    fn does_not_claim_fortigate() {
        let fgt = "date=2026-08-24 time=23:59:59 eventtime=1787626798373917051 logid=\"0101039944\" type=\"event\" subtype=\"vpn\" devname=\"FW01\" srcip=1.2.3.4 dstip=5.6.7.8\n";
        assert!(!looks_like_fortiweb(fgt));
    }

    #[test]
    fn does_not_claim_plain_csv() {
        assert!(!looks_like_fortiweb("a,b,c\n1,2,3\n"));
        assert!(!looks_like_fortiweb("{\"a\":1}\n"));
    }

    /// The vendor prefix is glued to the first key. If it is not stripped
    /// the key parses as `v015xxxxdate` and every edge loses its
    /// timestamp — a silent, whole-file data-quality loss.
    #[test]
    fn strips_vendor_prefix_and_keeps_the_date() {
        let kv = extract_pairs(strip_record_prefix(ATTACK.trim_end()));
        assert_eq!(kv.get("date").map(String::as_str), Some("2026-08-01"));
        assert_eq!(kv.get("time").map(String::as_str), Some("22:34:07"));
        assert!(!kv.contains_key("v015xxxxdate"));
    }

    /// `"timezone=(GMT-3:00)Buenos Aires, Georgetown"` wraps the `=` in
    /// quotes AND contains a comma. Splitting naively on commas would cut
    /// it in half and corrupt the following key.
    #[test]
    fn handles_quoted_pair_containing_a_comma() {
        let kv = extract_pairs(strip_record_prefix(ATTACK.trim_end()));
        assert_eq!(
            kv.get("timezone").map(String::as_str),
            Some("(GMT-3:00)Buenos Aires, Georgetown")
        );
        // The key right after it must survive intact.
        assert_eq!(kv.get("type").map(String::as_str), Some("attack"));
    }

    #[test]
    fn attack_record_emits_five_triples() {
        let triples = FortiWebParser::new().parse(ATTACK);
        let rels: Vec<String> = triples
            .iter()
            .map(|(_, r, _)| r.rel_type.to_string())
            .collect();
        assert!(rels.contains(&"Connect".to_string()), "{rels:?}");
        assert!(rels.contains(&"Triggered".to_string()), "{rels:?}");
        assert!(rels.contains(&"Request".to_string()), "{rels:?}");
        assert!(rels.contains(&"Targets".to_string()), "{rels:?}");
        assert!(rels.contains(&"MatchedPolicy".to_string()), "{rels:?}");
        assert_eq!(triples.len(), 5, "{rels:?}");
        for (s, _, _) in &triples {
            assert_eq!(s.id, "198.51.100.5");
            assert_eq!(s.entity_type, EntityType::IP);
        }
    }

    #[test]
    fn timestamp_comes_from_eventtime_nanoseconds() {
        let triples = FortiWebParser::new().parse(ATTACK);
        // 1785634447670281764 ns -> 1785634447 s
        assert_eq!(triples[0].1.timestamp, 1_785_634_447);
    }

    /// `N/A` and `none` are absence markers. Minting nodes for them would
    /// create a hub every unrelated record points at, wrecking centrality.
    #[test]
    fn placeholder_values_do_not_become_entities() {
        let triples = FortiWebParser::new().parse(ATTACK);
        let ids: Vec<&str> = triples.iter().map(|(_, _, d)| d.id.as_str()).collect();
        assert!(!ids.iter().any(|i| i.eq_ignore_ascii_case("n/a")));
        assert!(!ids.iter().any(|i| i.eq_ignore_ascii_case("none")));
        // signature_cve_id="N/A" must not have become an edge either.
        assert!(
            !triples
                .iter()
                .any(|(_, r, _)| r.metadata.contains_key("signature_cve_id"))
        );
    }

    /// The appliance's own daemon housekeeping — 97 % of a real `elog` —
    /// must NOT reach the graph: 99 k such records would hang a star off
    /// the appliance node and bury the ~1.2 k genuine admin actions.
    #[test]
    fn daemon_housekeeping_is_filtered_out() {
        assert!(FortiWebParser::new().parse(EVENT).is_empty());
    }

    /// …but a real administrator action must land, or a 36 MB elog
    /// ingests as an empty graph (which is what it used to do).
    #[test]
    fn admin_login_over_ssh_emits_an_auth_edge() {
        let login = "v015xxxxdate=2025-08-25,time=09:14:02,log_id=11005401,device_id=FWBVMSTM00000001,eventtime=1756119743526402955,type=event,subtype=\"admin\",pri=notice,user=usr_fortigate,ui=sshd,action=login,status=success,msg=\"User logged in\"
";
        let triples = FortiWebParser::new().parse(login);
        assert_eq!(triples.len(), 1);
        let (src, rel, dst) = &triples[0];
        assert_eq!(src.id, "usr_fortigate");
        assert_eq!(src.entity_type, EntityType::User);
        assert_eq!(rel.rel_type, RelationType::Auth);
        assert_eq!(dst.id, "FWBVMSTM00000001");
        assert_eq!(dst.entity_type, EntityType::Other("Appliance".into()));
        assert_eq!(rel.metadata.get("ui").map(String::as_str), Some("sshd"));
    }

    /// A configuration change is a different verb from a login — the
    /// distinction is what makes "who deleted a policy" answerable.
    #[test]
    fn admin_config_change_emits_a_modify_edge() {
        let del = "v015xxxxdate=2025-08-25,time=09:20:00,log_id=11005401,device_id=FWB1,eventtime=1756119743526402955,type=event,subtype=\"admin\",user=admfortiweb,ui=GUI,action=delete,status=success,msg=\"policy removed\"
";
        let triples = FortiWebParser::new().parse(del);
        assert_eq!(triples.len(), 1);
        assert_eq!(triples[0].1.rel_type, RelationType::Modify);
        assert_eq!(
            triples[0].1.metadata.get("action").map(String::as_str),
            Some("delete")
        );
    }

    /// The filter keys on the interface, not the username, so renaming a
    /// service account cannot smuggle 99 k housekeeping edges in.
    #[test]
    fn filter_keys_on_interface_not_username() {
        let renamed = "v015xxxxdate=2025-08-25,time=09:20:00,log_id=1,device_id=FWB1,type=event,subtype=\"system\",user=not_daemon_anymore,ui=daemon,action=update,status=success
";
        assert!(FortiWebParser::new().parse(renamed).is_empty());
    }

    /// The case that motivated the quote-aware ingest path: a captured
    /// multi-line payload is ONE record. Splitting it per physical line
    /// would produce four garbage records and lose the attack.
    #[test]
    fn multiline_payload_stays_one_record() {
        let multiline = "v015xxxxdate=2026-08-02,time=00:03:09,log_id=20000008,device_id=FWB1,eventtime=1785639789477787277,type=attack,severity_level=High,action=Alert,src=198.51.100.99,dst=10.0.9.10,http_method=post,http_url=\"/_search?pretty\",http_host=\"24onboarding.example.com.ar\",signature_id=\"090030001\",msg=\"Parameter({\n  \\\"size\\\": 1,\n  \\\"query\\\": { }\n})\"\n";
        let records = split_records(multiline);
        assert_eq!(
            records.len(),
            1,
            "payload was shredded into {} records",
            records.len()
        );

        let triples = FortiWebParser::new().parse(multiline);
        // Connect + Triggered + Request + Targets = 4 (no policy field).
        assert_eq!(triples.len(), 4);
        let msg = triples[0].1.metadata.get("msg").expect("msg metadata");
        assert!(msg.contains("\"size\": 1"), "escapes not undone: {msg}");
    }

    /// Two records back to back must not bleed into each other.
    #[test]
    fn consecutive_records_are_independent() {
        let two = format!("{ATTACK}{ATTACK}");
        assert_eq!(split_records(&two).len(), 2);
        assert_eq!(FortiWebParser::new().parse(&two).len(), 10);
    }

    /// A BOM at the head of the file must not hide the first record.
    #[test]
    fn leading_bom_does_not_swallow_the_first_record() {
        let with_bom = format!("\u{feff}{ATTACK}");
        assert!(looks_like_fortiweb(&with_bom));
        assert_eq!(FortiWebParser::new().parse(&with_bom).len(), 5);
    }
}
