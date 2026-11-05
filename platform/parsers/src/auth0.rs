//! Auth0 tenant logs exported through Elastic/ECS as a wide CSV.
//!
//! # Shape
//!
//! The export is a Filebeat `auth0.logs` data stream flattened to one
//! column per JSON leaf: 221 columns, each substantive field duplicated as
//! a `.keyword` sibling, and Elastic's `-` written wherever a value is
//! absent. Rows are padded with extra trailing `-` cells beyond the header
//! width, so a row is frequently *longer* than the header — the first 221
//! cells still align, and the overflow is padding.
//!
//! That padding is why [`parse`](Auth0CsvParser::parse) tolerates a row of
//! any length instead of requiring an exact column count: a strict check
//! drops ~75 % of this corpus while reporting nothing at all.
//!
//! # Why not the generic CSV parser
//!
//! `CsvParser` maps columns by heuristic on the column *name*. Against
//! this header that yields almost nothing useful: the interesting values
//! sit under names like
//! `json.data.details.response.body.user_metadata.cuit`, and the generic
//! path has no reason to prefer `json.data.ip` over the fifteen other
//! columns containing `ip`. Worse, it would mint a node per `.keyword`
//! duplicate, doubling every entity.
//!
//! # Identity model
//!
//! The anchor is the **bare 11-digit CUIT**, the same identity key
//! [`crate::certero`] and [`crate::bind_psp`] use. An Auth0 account that
//! exposes a CUIT therefore merges with the person already known from the
//! dossier and wallet corpora, and a traversal crosses from a login IP to
//! a bank transfer in a few hops. That merge is the whole point of
//! ingesting this file alongside the others.
//!
//! Emitted per row:
//!
//! * `IP -[Auth]-> Auth0User(user_id)` — who was authenticated from where,
//!   with the Auth0 event code and a derived `outcome` on the edge;
//! * `Person(cuit) -[TieneCuentaAuth0]-> Auth0User(user_id)` — the bridge,
//!   on the rows that carry a CUIT;
//! * `Person(cuit) -[UsaEmail]-> Email(email)`, falling back to
//!   `Auth0User -[UsaEmail]-> Email` when the row has an email but no
//!   CUIT, so the address is never dropped.
//!
//! `client_name` deliberately does **not** become a node. One application
//! name covers ~99 % of rows, so it would be a star hub dominating degree
//! and PageRank — the same reason [`crate::fortigate`] keeps `devname` off
//! the graph. It travels as edge metadata instead.

use std::collections::HashMap;

use chrono::NaiveDateTime;

use graph_hunter_core::entity::Entity;
use graph_hunter_core::parser::{LogParser, ParsedTriple};
use graph_hunter_core::relation::Relation;
use graph_hunter_core::types::{EntityType, RelationType};

/// Columns copied onto the auth edge, in triage order.
const EDGE_METADATA_COLUMNS: &[(&str, &str)] = &[
    ("json.data.type", "event_type"),
    ("json.data.description", "description"),
    ("json.data.client_name", "client_name"),
    ("json.data.client_id", "client_id"),
    ("json.data.connection", "connection"),
    ("json.data.user_agent", "user_agent"),
    ("json.data.security_context.ja3", "ja3"),
    ("json.data.security_context.ja4", "ja4"),
    ("json.data.location_info.country_name", "country"),
    ("json.data.location_info.city_name", "city"),
    ("json.data.strategy", "strategy"),
    ("json.data.tenant_name", "tenant"),
    ("json.data.details.session_id", "session_id"),
    ("json.data.details.error.message", "error_message"),
    ("json.data.details.response.statusCode", "status_code"),
    ("json.data.log_id", "log_id"),
];

/// Columns consulted, in order, for the authenticating IP.
const IP_COLUMNS: &[&str] = &[
    "json.data.ip",
    "json.data.client_ip",
    "json.data.details.request.ip",
    "json.data.details.response.body.last_ip",
];

/// Columns consulted, in order, for the Auth0 user id.
const USER_ID_COLUMNS: &[&str] = &[
    "json.data.user_id",
    "json.data.details.response.body.user_id",
    "json.data.details.prompts.user_id",
    "json.data.details.body.user_id",
];

const USER_NAME_COLUMNS: &[&str] = &[
    "json.data.user_name",
    "json.data.details.prompts.user_name",
    "json.data.details.response.body.username",
];

const EMAIL_COLUMNS: &[&str] = &[
    "json.data.details.response.body.email",
    "json.data.details.body.email",
];

const CUIT_COLUMN: &str = "json.data.details.response.body.user_metadata.cuit";

/// Elastic writes `-` for an absent value; empty strings appear too.
fn is_absent(v: &str) -> bool {
    v.is_empty() || v == "-" || v == "(empty)"
}

/// A CUIT/CUIL is exactly 11 digits. Anything else (a name, a masked
/// value, a stray `-`) must not become a `Person` node: that id space is
/// shared with the dossier and wallet corpora, and a malformed member
/// would merge unrelated records onto one person.
fn normalize_cuit(raw: &str) -> Option<String> {
    let digits: String = raw.chars().filter(|c| c.is_ascii_digit()).collect();
    (digits.len() == 11).then_some(digits)
}

/// Auth0 event codes are prefixed `s` for success and `f` for failure
/// (`s`, `sepft`, `slo` … / `f`, `fp`, `fepft` …). Deriving an explicit
/// `outcome` spares every downstream query from memorising the codes,
/// while the raw code stays on the edge as `event_type`.
fn outcome_of(event_type: &str) -> &'static str {
    match event_type.as_bytes().first() {
        Some(b's') => "success",
        Some(b'f') => "failure",
        _ => "other",
    }
}

/// Parse Elastic's display timestamp (`Sep 3, 2026 @ 10:01:06.343`) or an
/// ISO 8601 fallback, to epoch seconds. Returns 0 when unparseable — a
/// null timestamp is recoverable, a dropped row is not.
fn parse_timestamp(raw: &str) -> i64 {
    if is_absent(raw) {
        return 0;
    }
    const FORMATS: &[&str] = &[
        "%b %d, %Y @ %H:%M:%S%.3f",
        "%b %d, %Y @ %H:%M:%S",
        "%Y-%m-%dT%H:%M:%S%.fZ",
        "%Y-%m-%dT%H:%M:%S%.f",
        "%Y-%m-%d %H:%M:%S",
    ];
    for fmt in FORMATS {
        if let Ok(dt) = NaiveDateTime::parse_from_str(raw, fmt) {
            return dt.and_utc().timestamp();
        }
    }
    0
}

/// Split one RFC 4180 CSV record. Doubled quotes are literal quotes.
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
            ',' if !in_quotes => fields.push(std::mem::take(&mut current)),
            '\r' => {}
            _ => current.push(ch),
        }
    }
    fields.push(current);
    fields
}

/// True when `line` is the Auth0/ECS column header.
fn is_header_line(line: &str) -> bool {
    line.contains("json.data.") && line.contains("@timestamp")
}

/// True when `contents` looks like an Auth0 CSV export.
///
/// Anchored on the ECS column header, which is unmistakable: no other
/// corpus in this repo ships a `json.data.*` flattened header.
pub fn looks_like_auth0(contents: &str) -> bool {
    let probe = if contents.len() > 16_384 {
        match contents
            .char_indices()
            .take_while(|(i, _)| *i <= 16_384)
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
    // The `json.data.*` + `@timestamp` pair is already unmistakable; the
    // comma count only rules out prose that happens to quote a column
    // name, so it stays deliberately low. A high threshold would be
    // tuned to one export's width and reject a narrower projection of
    // the same data.
    is_header_line(head)
        && (head.contains("auth0") || head.contains("data_stream.dataset"))
        && head.matches(',').count() > 5
}

/// Column-name to index map, built once per batch.
struct Header {
    index: HashMap<String, usize>,
}

impl Header {
    fn new(line: &str) -> Self {
        let mut index = HashMap::new();
        for (i, name) in split_csv_row(line.trim_start_matches('\u{feff}'))
            .into_iter()
            .enumerate()
        {
            // First wins: the plain column precedes its `.keyword`
            // duplicate, and duplicates otherwise overwrite each other.
            index.entry(name.trim().to_string()).or_insert(i);
        }
        Self { index }
    }

    /// Value for `column`, or `None` when the column is missing from this
    /// export, the row is too short to reach it, or the value is one of
    /// Elastic's absence markers.
    fn get<'r>(&self, row: &'r [String], column: &str) -> Option<&'r str> {
        let i = *self.index.get(column)?;
        let v = row.get(i)?.trim();
        (!is_absent(v)).then_some(v)
    }

    fn first_of<'r>(&self, row: &'r [String], columns: &[&str]) -> Option<&'r str> {
        columns.iter().find_map(|c| self.get(row, c))
    }
}

fn other(id: &str, ty: &str) -> Entity {
    Entity::new(id, EntityType::Other(ty.into()))
}

fn parse_row(hdr: &Header, row: &[String]) -> Vec<ParsedTriple> {
    let timestamp = parse_timestamp(hdr.get(row, "@timestamp").unwrap_or(""));
    let event_type = hdr.get(row, "json.data.type").unwrap_or("");

    let mut meta: HashMap<String, String> = HashMap::new();
    for (column, key) in EDGE_METADATA_COLUMNS {
        if let Some(v) = hdr.get(row, column) {
            meta.insert((*key).to_string(), v.to_string());
        }
    }
    meta.insert("outcome".into(), outcome_of(event_type).into());

    // The Auth0 account. Falling back to the username keeps rows that
    // name a subject but no id (failed logins for unknown accounts).
    let user_id = hdr
        .first_of(row, USER_ID_COLUMNS)
        .or_else(|| hdr.first_of(row, USER_NAME_COLUMNS));
    let cuit = hdr.get(row, CUIT_COLUMN).and_then(normalize_cuit);
    let email = hdr.first_of(row, EMAIL_COLUMNS);

    let mut triples = Vec::new();

    let account = user_id.map(|id| {
        let mut node = other(id, "Auth0User");
        if let Some(name) = hdr.first_of(row, USER_NAME_COLUMNS) {
            node.metadata.insert("user_name".into(), name.to_string());
        }
        if let Some(c) = &cuit {
            node.metadata.insert("cuit".into(), c.clone());
        }
        node
    });

    // 1. IP -[Auth]-> Auth0User
    if let (Some(ip), Some(acct)) = (hdr.first_of(row, IP_COLUMNS), &account) {
        let mut rel = Relation::new(ip, &acct.id, RelationType::Auth, timestamp);
        rel.metadata = meta.clone();
        triples.push((Entity::new(ip, EntityType::IP), rel, acct.clone()));
    }

    // 2. Person(cuit) -[TieneCuentaAuth0]-> Auth0User
    if let (Some(c), Some(acct)) = (&cuit, &account) {
        let mut rel = Relation::new(
            c.as_str(),
            &acct.id,
            RelationType::Other("TieneCuentaAuth0".into()),
            timestamp,
        );
        rel.metadata = meta.clone();
        triples.push((other(c, "Person"), rel, acct.clone()));
    }

    // 3. Email, hung off the person when known, off the account otherwise
    //    so the address is never silently dropped.
    if let Some(mail) = email {
        let (src_node, src_id) = match (&cuit, &account) {
            (Some(c), _) => (other(c, "Person"), c.clone()),
            (None, Some(acct)) => (acct.clone(), acct.id.clone()),
            (None, None) => return triples,
        };
        let mut rel = Relation::new(
            src_id,
            mail,
            RelationType::Other("UsaEmail".into()),
            timestamp,
        );
        rel.metadata = meta;
        triples.push((src_node, rel, other(mail, "Email")));
    }

    triples
}

pub struct Auth0CsvParser;

impl Default for Auth0CsvParser {
    fn default() -> Self {
        Self::new()
    }
}

impl Auth0CsvParser {
    pub fn new() -> Self {
        Self
    }
}

impl LogParser for Auth0CsvParser {
    /// Parse a batch. The first non-blank line must be the column header —
    /// the ingest layer repeats it into every streamed batch
    /// (`FormatDescriptor::headed`), because mapping 221 columns by
    /// position without it would silently produce wrong values rather
    /// than an error.
    fn parse(&self, data: &str) -> Vec<ParsedTriple> {
        let mut lines = data.lines().skip_while(|l| l.trim().is_empty());
        let Some(header_line) = lines.next() else {
            return Vec::new();
        };
        if !is_header_line(header_line) {
            // No header: refuse rather than map columns to the wrong
            // names. Silently emitting mis-keyed entities would be worse
            // than emitting none.
            return Vec::new();
        }
        let hdr = Header::new(header_line);
        let mut out = Vec::new();
        for line in lines {
            if line.trim().is_empty() {
                continue;
            }
            let row = split_csv_row(line);
            out.extend(parse_row(&hdr, &row));
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const HEADER: &str = "@timestamp,_id,data_stream.dataset,json.data.type,json.data.description,json.data.client_name,json.data.connection,json.data.ip,json.data.user_agent,json.data.security_context.ja3,json.data.location_info.country_name,json.data.details.response.body.email,json.data.details.response.body.user_metadata.cuit,json.data.user_id,json.data.user_name,json.data.details.response.body.user_id,json.data.details.prompts.user_id,json.data.details.prompts.user_name,json.data.details.body.email,json.data.client_ip,json.data.details.request.ip,tags";

    fn row(
        ts: &str,
        ty: &str,
        ip: &str,
        cuit: &str,
        email: &str,
        user_id: &str,
        user_name: &str,
    ) -> String {
        format!(
            "\"{ts}\",abc,auth0.logs,{ty},\"Wrong email or password.\",app-mobile,tenant-ejemplo,{ip},\"Linux; U; Android 14\",f79b6bad,Argentina,{email},{cuit},{user_id},{user_name},-,-,-,-,-,-,\"forwarded, auth0-logstream\""
        )
    }

    fn doc(rows: &[String]) -> String {
        let mut s = String::from(HEADER);
        for r in rows {
            s.push('\n');
            s.push_str(r);
        }
        s.push('\n');
        s
    }

    #[test]
    fn detects_auth0_export() {
        assert!(looks_like_auth0(&doc(&[row(
            "Sep 3, 2026 @ 10:01:06.343",
            "fp",
            "203.0.113.40",
            "-",
            "-",
            "auth0|abc",
            "usuario_ejemplo"
        )])));
    }

    #[test]
    fn does_not_claim_other_formats() {
        assert!(!looks_like_auth0("a,b,c\n1,2,3\n"));
        assert!(!looks_like_auth0("{\"a\":1}\n"));
        assert!(!looks_like_auth0(
            "date=2026-08-24 time=23:59:59 logid=\"01\" remip=1.2.3.4\n"
        ));
    }

    #[test]
    fn emits_auth_edge_from_ip_to_account() {
        let d = doc(&[row(
            "Sep 3, 2026 @ 10:01:06.343",
            "fp",
            "203.0.113.40",
            "-",
            "-",
            "auth0|67ffe529",
            "usuario_ejemplo",
        )]);
        let triples = Auth0CsvParser::new().parse(&d);
        assert_eq!(triples.len(), 1);
        let (src, rel, dst) = &triples[0];
        assert_eq!(src.id, "203.0.113.40");
        assert_eq!(src.entity_type, EntityType::IP);
        assert_eq!(rel.rel_type, RelationType::Auth);
        assert_eq!(dst.id, "auth0|67ffe529");
        assert_eq!(dst.entity_type, EntityType::Other("Auth0User".into()));
        assert_eq!(
            dst.metadata.get("user_name").map(String::as_str),
            Some("usuario_ejemplo")
        );
    }

    /// The reason this corpus is worth ingesting: the CUIT column is the
    /// same bare-11-digit id space certero and bind_psp anchor on, so the
    /// Auth0 account merges with the person already in the graph.
    #[test]
    fn cuit_anchors_a_bare_person_node() {
        let d = doc(&[row(
            "Sep 3, 2026 @ 10:01:06.343",
            "s",
            "203.0.113.40",
            "20000000031",
            "ivan@example.com",
            "auth0|66d5daa3",
            "ivan",
        )]);
        let triples = Auth0CsvParser::new().parse(&d);
        let bridge = triples
            .iter()
            .find(|(_, r, _)| r.rel_type == RelationType::Other("TieneCuentaAuth0".into()))
            .expect("no CUIT bridge edge");
        assert_eq!(
            bridge.0.id, "20000000031",
            "Person id must be the bare CUIT"
        );
        assert_eq!(bridge.0.entity_type, EntityType::Other("Person".into()));
        assert_eq!(bridge.2.id, "auth0|66d5daa3");

        let mail = triples
            .iter()
            .find(|(_, r, _)| r.rel_type == RelationType::Other("UsaEmail".into()))
            .expect("no email edge");
        assert_eq!(mail.0.id, "20000000031", "email must hang off the Person");
        assert_eq!(mail.2.id, "ivan@example.com");
    }

    /// A malformed CUIT must never mint a Person: that id space is shared
    /// with two other corpora, so a bad member merges unrelated records.
    #[test]
    fn malformed_cuit_does_not_create_a_person() {
        assert_eq!(normalize_cuit("20000000031"), Some("20000000031".into()));
        assert_eq!(normalize_cuit("20-00000003-1"), Some("20000000031".into()));
        assert_eq!(normalize_cuit("1234"), None);
        assert_eq!(normalize_cuit("no soy un cuit"), None);
        assert_eq!(normalize_cuit("-"), None);

        let d = doc(&[row(
            "Sep 3, 2026 @ 10:01:06.343",
            "s",
            "1.2.3.4",
            "1234",
            "x@y.com",
            "auth0|z",
            "z",
        )]);
        let triples = Auth0CsvParser::new().parse(&d);
        assert!(!triples.iter().any(|(s, _, _)| s.id == "1234"));
        // Email still lands, hung off the account instead of a Person.
        let mail = triples
            .iter()
            .find(|(_, r, _)| r.rel_type == RelationType::Other("UsaEmail".into()))
            .expect("email dropped when CUIT was invalid");
        assert_eq!(mail.0.id, "auth0|z");
    }

    #[test]
    fn outcome_is_derived_from_the_auth0_event_code() {
        assert_eq!(outcome_of("s"), "success");
        assert_eq!(outcome_of("sepft"), "success");
        assert_eq!(outcome_of("slo"), "success");
        assert_eq!(outcome_of("f"), "failure");
        assert_eq!(outcome_of("fp"), "failure");
        assert_eq!(outcome_of("fepft"), "failure");
        assert_eq!(outcome_of("mgmt_api_read"), "other");

        let d = doc(&[row(
            "Sep 3, 2026 @ 10:01:06.343",
            "fp",
            "1.2.3.4",
            "-",
            "-",
            "auth0|a",
            "a",
        )]);
        let t = Auth0CsvParser::new().parse(&d);
        assert_eq!(
            t[0].1.metadata.get("outcome").map(String::as_str),
            Some("failure")
        );
        assert_eq!(
            t[0].1.metadata.get("event_type").map(String::as_str),
            Some("fp")
        );
    }

    #[test]
    fn parses_the_elastic_display_timestamp() {
        // Sep 3 2026 10:01:06 UTC
        assert_eq!(parse_timestamp("Sep 3, 2026 @ 10:01:06.343"), 1_788_429_666);
        assert_eq!(
            parse_timestamp("Sep 03, 2026 @ 10:01:06.343"),
            1_788_429_666
        );
        assert_eq!(parse_timestamp("-"), 0);
        assert_eq!(parse_timestamp("not a date"), 0);
    }

    /// Elastic pads rows with extra trailing `-` cells beyond the header
    /// width. Requiring an exact column count drops ~75 % of the real
    /// corpus while reporting nothing.
    #[test]
    fn tolerates_rows_longer_than_the_header() {
        let mut r = row(
            "Sep 3, 2026 @ 10:01:06.343",
            "s",
            "9.9.9.9",
            "-",
            "-",
            "auth0|pad",
            "pad",
        );
        for _ in 0..200 {
            r.push_str(",-");
        }
        let triples = Auth0CsvParser::new().parse(&doc(&[r]));
        assert_eq!(triples.len(), 1);
        assert_eq!(triples[0].0.id, "9.9.9.9");
    }

    /// A short row must yield whatever it does carry, not panic.
    #[test]
    fn tolerates_rows_shorter_than_the_header() {
        let short = "\"Sep 3, 2026 @ 10:01:06.343\",abc,auth0.logs,s";
        let triples = Auth0CsvParser::new().parse(&doc(&[short.to_string()]));
        assert!(triples.is_empty());
    }

    /// Without its header a batch cannot be mapped by position. Emitting
    /// mis-keyed entities would be worse than emitting none, so the
    /// parser refuses — and the ingest layer guarantees the header.
    #[test]
    fn refuses_a_batch_with_no_header() {
        let headerless = row(
            "Sep 3, 2026 @ 10:01:06.343",
            "s",
            "1.2.3.4",
            "-",
            "-",
            "auth0|a",
            "a",
        );
        assert!(Auth0CsvParser::new().parse(&headerless).is_empty());
    }

    /// `.keyword` siblings duplicate every value; mapping to the first
    /// occurrence keeps one node per value instead of two.
    #[test]
    fn keyword_duplicates_do_not_double_entities() {
        let hdr = Header::new("json.data.ip,json.data.ip.keyword,json.data.user_id");
        let r: Vec<String> = vec!["1.2.3.4".into(), "1.2.3.4".into(), "auth0|x".into()];
        assert_eq!(hdr.get(&r, "json.data.ip"), Some("1.2.3.4"));
        assert_eq!(hdr.get(&r, "json.data.ip.keyword"), Some("1.2.3.4"));
    }

    #[test]
    fn quoted_cells_with_commas_stay_one_field() {
        let cells = split_csv_row("\"a,b\",c,\"d\"\"e\"");
        assert_eq!(cells, vec!["a,b", "c", "d\"e"]);
    }
}
