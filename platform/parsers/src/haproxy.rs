use std::collections::HashMap;

use graph_hunter_core::entity::Entity;
use graph_hunter_core::parser::{LogParser, ParseError, ParsedTriple, ParseStats, RawIngestEvent};
use graph_hunter_core::relation::Relation;
use graph_hunter_core::types::{EntityType, RelationType};

/// Parser for HAProxy HTTP log format (`option httplog` / `httpslog`).
///
/// A typical line looks like:
/// ```text
///  186.19.87.186:36696 [10/Jun/2026:00:00:27.428] https~ be_pool/srv_01 0/0/0/1/1 \
///  200 659 - - --NI 619/611/1/0/0 0/0 "GET https://host.example/api/x HTTP/2.0"
/// ```
///
/// The leading, space-delimited prefix carries the client `ip:port`, the
/// bracketed accept date, the frontend, the `backend/server` pair, the
/// timers, status, bytes, captured cookies, the termination state, the
/// connection counters and the queues. The trailing quoted field holds the
/// HTTP request line (`METHOD URL PROTO`).
///
/// Each data line produces up to three triples:
///   1. client IP -[Connect]-> requested domain   (metadata: method, status, backend)
///   2. client IP -[Read|Write]-> URL path         (when a path is present)
///   3. requested domain -[Connect]-> backend host (proxy routing, when both present)
pub struct HaproxyParser;

/// Fields extracted from one HAProxy HTTP log line.
struct HaproxyRecord<'a> {
    client_ip: &'a str,
    domain: &'a str,
    url: String,
    method: &'a str,
    status: &'a str,
    backend: &'a str,
    server: &'a str,
    timestamp: i64,
}

/// Splits a single HAProxy line into its component fields. Returns `None`
/// for blank lines or lines that don't carry the minimum prefix shape
/// (client + bracketed date). The trailing quoted HTTP request is optional
/// (TCP-log lines and `<BADREQ>` rows simply yield empty method/url/domain).
fn parse_haproxy_line(line: &str) -> Option<HaproxyRecord<'_>> {
    let line = line.trim();
    if line.is_empty() {
        return None;
    }

    // Separate the quoted HTTP request (which contains spaces) from the
    // space-delimited prefix. Use the first and last double-quote so an
    // embedded quote inside the URL doesn't truncate the request.
    let (prefix, request) = match (line.find('"'), line.rfind('"')) {
        (Some(a), Some(b)) if b > a => (&line[..a], &line[a + 1..b]),
        _ => (line, ""),
    };

    let toks: Vec<&str> = prefix.split_whitespace().collect();
    // Need at least client_ip, date, frontend, backend/server, timers, status.
    if toks.len() < 6 {
        return None;
    }

    // client `ip:port` -> strip the port (last colon keeps IPv6 intact).
    let client_ip = toks[0].rsplit_once(':').map(|(ip, _)| ip).unwrap_or(toks[0]);
    if client_ip.is_empty() {
        return None;
    }

    // `[10/Jun/2026:00:00:27.428]` -> Unix epoch seconds.
    let timestamp = parse_haproxy_datetime(toks[1].trim_start_matches('[').trim_end_matches(']'));

    // `backend/server` (e.g. `be_pool/srv_01`). `server` may be absent.
    let (backend, server) = toks[3].split_once('/').unwrap_or((toks[3], ""));

    let status = toks.get(5).copied().unwrap_or("-");

    // Quoted request: `METHOD URL PROTO`.
    let mut rtoks = request.split_whitespace();
    let method = rtoks.next().unwrap_or("");
    let raw_url = rtoks.next().unwrap_or("");
    let (domain, url) = split_url(raw_url);

    Some(HaproxyRecord {
        client_ip,
        domain,
        url,
        method,
        status,
        backend,
        server,
        timestamp,
    })
}

/// Splits a request-line URL into `(domain, path)`. Absolute URLs
/// (`https://host/path?q`) yield the host and the query-stripped path;
/// relative URLs (`/path?q`) yield an empty domain and the stripped path.
/// The query string is dropped to keep URL-node cardinality bounded — at
/// HAProxy volumes the per-request query (cache-busters, tokens) would
/// otherwise mint a unique node per line.
fn split_url(raw: &str) -> (&str, String) {
    let without_scheme = raw
        .strip_prefix("https://")
        .or_else(|| raw.strip_prefix("http://"));

    let (domain, path) = match without_scheme {
        Some(rest) => match rest.find('/') {
            Some(slash) => (&rest[..slash], &rest[slash..]),
            None => (rest, "/"),
        },
        // Relative URL (or non-URL like `<BADREQ>`): no domain.
        None => ("", raw),
    };

    let path_no_query = path.split('?').next().unwrap_or(path);
    (domain, path_no_query.to_string())
}

/// Builds the 1–3 triples for one parsed record. Shared by `parse` and
/// `try_parse` so both paths agree on the emitted graph shape.
fn record_to_triples(rec: &HaproxyRecord<'_>) -> Vec<ParsedTriple> {
    let mut triples = Vec::new();

    let mut meta = HashMap::new();
    if !rec.method.is_empty() {
        meta.insert("method".to_string(), rec.method.to_string());
    }
    if rec.status != "-" && !rec.status.is_empty() {
        meta.insert("status".to_string(), rec.status.to_string());
    }
    if !rec.backend.is_empty() && rec.backend != "-" {
        meta.insert("backend".to_string(), rec.backend.to_string());
    }

    // Triple 1: client IP -[Connect]-> requested domain.
    if !rec.domain.is_empty() {
        let src = Entity::new(rec.client_ip, EntityType::IP);
        let dst = Entity::new(rec.domain, EntityType::Domain);
        let mut rel = Relation::new(rec.client_ip, rec.domain, RelationType::Connect, rec.timestamp);
        rel.metadata = meta.clone();
        triples.push((src, rel, dst));
    }

    // Triple 2: client IP -[Read|Write]-> URL path.
    if !rec.url.is_empty() && rec.url != "/" {
        let rel_type = match rec.method {
            "GET" | "HEAD" | "OPTIONS" | "TRACE" => RelationType::Read,
            "POST" | "PUT" | "DELETE" | "PATCH" => RelationType::Write,
            _ => RelationType::Connect,
        };
        let src = Entity::new(rec.client_ip, EntityType::IP);
        let dst = Entity::new(&rec.url, EntityType::URL);
        let rel = Relation::new(rec.client_ip, &rec.url, rel_type, rec.timestamp);
        triples.push((src, rel, dst));
    }

    // Triple 3: requested domain -[Connect]-> backend server (proxy routing).
    if !rec.domain.is_empty() && !rec.server.is_empty() && rec.server != "-" {
        let src = Entity::new(rec.domain, EntityType::Domain);
        let dst = Entity::new(rec.server, EntityType::Host);
        let rel = Relation::new(rec.domain, rec.server, RelationType::Connect, rec.timestamp);
        triples.push((src, rel, dst));
    }

    triples
}

/// Flat-event variant of [`record_to_triples`]. Emits `RawIngestEvent`s
/// directly so the raw ingest path never materializes the 448-byte
/// `ParsedTriple` intermediate (2 `Entity` + 1 `Relation`, each carrying a
/// `HashMap`). On a whole-file parse that intermediate doubles peak RAM;
/// at HAProxy volumes it's the difference between a bounded ingest and an
/// out-of-memory abort.
fn record_to_raw_events(rec: &HaproxyRecord<'_>) -> Vec<RawIngestEvent> {
    let mut events = Vec::new();

    let mut meta = HashMap::new();
    if !rec.method.is_empty() {
        meta.insert("method".to_string(), rec.method.to_string());
    }
    if rec.status != "-" && !rec.status.is_empty() {
        meta.insert("status".to_string(), rec.status.to_string());
    }
    if !rec.backend.is_empty() && rec.backend != "-" {
        meta.insert("backend".to_string(), rec.backend.to_string());
    }

    // Triple 1: client IP -[Connect]-> requested domain.
    if !rec.domain.is_empty() {
        events.push(RawIngestEvent {
            src_id: rec.client_ip.to_string(),
            src_type: EntityType::IP,
            src_metadata: HashMap::new(),
            dst_id: rec.domain.to_string(),
            dst_type: EntityType::Domain,
            dst_metadata: HashMap::new(),
            rel_type: RelationType::Connect,
            rel_metadata: meta,
            timestamp: rec.timestamp,
            raw_line: None,
        });
    }

    // Triple 2: client IP -[Read|Write]-> URL path.
    if !rec.url.is_empty() && rec.url != "/" {
        let rel_type = match rec.method {
            "GET" | "HEAD" | "OPTIONS" | "TRACE" => RelationType::Read,
            "POST" | "PUT" | "DELETE" | "PATCH" => RelationType::Write,
            _ => RelationType::Connect,
        };
        events.push(RawIngestEvent {
            src_id: rec.client_ip.to_string(),
            src_type: EntityType::IP,
            src_metadata: HashMap::new(),
            dst_id: rec.url.clone(),
            dst_type: EntityType::URL,
            dst_metadata: HashMap::new(),
            rel_type,
            rel_metadata: HashMap::new(),
            timestamp: rec.timestamp,
            raw_line: None,
        });
    }

    // Triple 3: requested domain -[Connect]-> backend server.
    if !rec.domain.is_empty() && !rec.server.is_empty() && rec.server != "-" {
        events.push(RawIngestEvent {
            src_id: rec.domain.to_string(),
            src_type: EntityType::Domain,
            src_metadata: HashMap::new(),
            dst_id: rec.server.to_string(),
            dst_type: EntityType::Host,
            dst_metadata: HashMap::new(),
            rel_type: RelationType::Connect,
            rel_metadata: HashMap::new(),
            timestamp: rec.timestamp,
            raw_line: None,
        });
    }

    events
}

impl LogParser for HaproxyParser {
    fn parse(&self, data: &str) -> Vec<ParsedTriple> {
        let mut triples = Vec::new();
        for line in data.lines() {
            if let Some(rec) = parse_haproxy_line(line) {
                triples.extend(record_to_triples(&rec));
            }
        }
        triples
    }

    /// Per-row `Result` variant (DLQ-aware). Surfaces two classes of
    /// per-line failure the bare `parse` path swallows:
    /// 1. A non-blank line that doesn't split into the HAProxy prefix
    ///    shape — emits `ParseError::MalformedRow`.
    /// 2. A line that parses but yields no triples (no domain and no
    ///    usable path, e.g. a TCP-log line or `<BADREQ>`) — emits
    ///    `ParseError::MissingField`.
    ///
    /// Blank lines are structural and are not surfaced as errors.
    fn try_parse(&self, data: &str) -> Vec<Result<ParsedTriple, ParseError>> {
        let mut out: Vec<Result<ParsedTriple, ParseError>> = Vec::new();
        for (lineno, raw_line) in data.lines().enumerate() {
            if raw_line.trim().is_empty() {
                continue;
            }
            match parse_haproxy_line(raw_line) {
                None => out.push(Err(ParseError::MalformedRow {
                    line: lineno,
                    reason: "line does not match the HAProxy HTTP-log prefix shape".to_string(),
                })),
                Some(rec) => {
                    let triples = record_to_triples(&rec);
                    if triples.is_empty() {
                        out.push(Err(ParseError::MissingField(format!(
                            "domain|url (line {}: no requested host or path to anchor a triple)",
                            lineno
                        ))));
                    } else {
                        out.extend(triples.into_iter().map(Ok));
                    }
                }
            }
        }
        out
    }

    /// Emits `RawIngestEvent`s directly, bypassing the `ParsedTriple`
    /// intermediate the default `parse_raw` builds. Halves peak RAM on
    /// large parses (the consumer is `insert_raw_events`).
    fn parse_raw(&self, data: &str) -> Vec<RawIngestEvent> {
        let mut events = Vec::new();
        for line in data.lines() {
            if let Some(rec) = parse_haproxy_line(line) {
                events.extend(record_to_raw_events(&rec));
            }
        }
        events
    }

    fn parse_raw_with_stats(&self, data: &str) -> (Vec<RawIngestEvent>, ParseStats) {
        (self.parse_raw(data), ParseStats::default())
    }
}

/// Parses a HAProxy accept-date (`10/Jun/2026:00:00:27.428`, no timezone,
/// millisecond precision) into Unix epoch seconds. Returns 0 on failure so
/// a single malformed date never drops an otherwise-usable row.
fn parse_haproxy_datetime(s: &str) -> i64 {
    if s.is_empty() {
        return 0;
    }
    chrono::NaiveDateTime::parse_from_str(s, "%d/%b/%Y:%H:%M:%S%.3f")
        .map(|dt| dt.and_utc().timestamp())
        .unwrap_or(0)
}

/// Returns `true` if the sampled text looks like a HAProxy HTTP log.
///
/// Discriminators (vs. Apache/Nginx combined, which share the `[date]
/// "METHOD ... HTTP/x"` shape):
/// - the client token carries an `ip:port` (HAProxy logs the source port);
/// - the bracketed accept date is a *single* whitespace-free token
///   (`[10/Jun/2026:00:00:27.428]`), whereas Apache embeds a space before
///   the timezone (`[10/Oct/2000:13:55:36 -0700]`) and so splits in two;
/// - the line contains an `HTTP/` request token.
pub fn looks_like_haproxy(contents: &str) -> bool {
    // Only scan the first ~8 KiB so a multi-GB log isn't read in full.
    let probe = if contents.len() > 8192 {
        &contents[..8192]
    } else {
        contents
    };

    for line in probe.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        let toks: Vec<&str> = trimmed.split_whitespace().collect();
        if toks.len() < 4 {
            return false;
        }
        let client_has_port = toks[0].contains(':');
        let date_is_single_token = toks[1].starts_with('[') && toks[1].ends_with(']');
        let has_http = trimmed.contains("HTTP/");
        return client_has_port && date_is_single_token && has_http;
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE_LOG: &str = " 186.19.87.186:36696 [10/Jun/2026:00:00:27.428] https~ cluster_pps_wss/wss_pps_i10 0/0/0/1/1 200 659 - - --NI 619/611/1/0/0 0/0 \"OPTIONS https://www1.hospitalitaliano.org.ar/wssPortal/api/log/guardarNuevoLog/2507896/INICIO HTTP/2.0\"
 102.128.167.58:42778 [10/Jun/2026:00:00:27.452] https~ be_confluence_prod/confluence_prod_01 0/0/0/4/4 200 1281 - - --VN 619/611/2/2/0 0/0 \"POST https://confluence.hospitalitaliano.org.ar/rest/wrm/2.0/resources?_=123 HTTP/2.0\"
";

    #[test]
    fn detects_haproxy() {
        assert!(looks_like_haproxy(SAMPLE_LOG));
    }

    #[test]
    fn rejects_apache_combined() {
        // Apache: bare IP (no port) and a space-split date with timezone.
        let apache =
            "127.0.0.1 - frank [10/Oct/2000:13:55:36 -0700] \"GET /apache_pb.gif HTTP/1.0\" 200 2326";
        assert!(!looks_like_haproxy(apache));
    }

    #[test]
    fn rejects_non_http_text() {
        assert!(!looks_like_haproxy("just some plain text\nwith no structure"));
        assert!(!looks_like_haproxy("{\"Type\":\"SecurityEvent\"}"));
    }

    #[test]
    fn parse_emits_domain_url_and_backend_triples() {
        let triples = HaproxyParser.parse(SAMPLE_LOG);
        // Line 1: Connect->domain, Read->url, domain->server  = 3
        // Line 2: Connect->domain, Write->url, domain->server = 3
        assert_eq!(triples.len(), 6);
    }

    #[test]
    fn parse_connect_to_domain_triple() {
        let triples = HaproxyParser.parse(SAMPLE_LOG);
        let (src, rel, dst) = &triples[0];
        assert_eq!(src.id, "186.19.87.186");
        assert_eq!(src.entity_type, EntityType::IP);
        assert_eq!(dst.id, "www1.hospitalitaliano.org.ar");
        assert_eq!(dst.entity_type, EntityType::Domain);
        assert_eq!(rel.rel_type, RelationType::Connect);
        assert_eq!(rel.metadata.get("method").unwrap(), "OPTIONS");
        assert_eq!(rel.metadata.get("status").unwrap(), "200");
        assert_eq!(rel.metadata.get("backend").unwrap(), "cluster_pps_wss");
    }

    #[test]
    fn parse_url_path_strips_query_and_uses_method_verb() {
        let triples = HaproxyParser.parse(SAMPLE_LOG);
        // triples[1] is line 1's URL edge (OPTIONS => Read).
        let (_, rel1, dst1) = &triples[1];
        assert_eq!(dst1.id, "/wssPortal/api/log/guardarNuevoLog/2507896/INICIO");
        assert_eq!(dst1.entity_type, EntityType::URL);
        assert_eq!(rel1.rel_type, RelationType::Read);

        // triples[4] is line 2's URL edge (POST => Write, query stripped).
        let (_, rel2, dst2) = &triples[4];
        assert_eq!(dst2.id, "/rest/wrm/2.0/resources");
        assert_eq!(rel2.rel_type, RelationType::Write);
    }

    #[test]
    fn parse_domain_to_backend_server_triple() {
        let triples = HaproxyParser.parse(SAMPLE_LOG);
        let (src, rel, dst) = &triples[2];
        assert_eq!(src.id, "www1.hospitalitaliano.org.ar");
        assert_eq!(src.entity_type, EntityType::Domain);
        assert_eq!(dst.id, "wss_pps_i10");
        assert_eq!(dst.entity_type, EntityType::Host);
        assert_eq!(rel.rel_type, RelationType::Connect);
    }

    #[test]
    fn timestamp_parses_haproxy_date() {
        // 10/Jun/2026:00:00:27.428 UTC == 1781049627 (seconds; ms truncated)
        assert_eq!(parse_haproxy_datetime("10/Jun/2026:00:00:27.428"), 1781049627);
        assert_eq!(parse_haproxy_datetime(""), 0);
        assert_eq!(parse_haproxy_datetime("garbage"), 0);
    }

    #[test]
    fn try_parse_flags_malformed_line() {
        let data = "186.19.87.186:36696 [10/Jun/2026:00:00:27.428] https~ be/srv 0/0/0/1/1 200 659 - - --NI 0/0/0/0/0 0/0 \"GET https://h.example/a HTTP/2.0\"\nnot a haproxy line";
        let results = HaproxyParser.try_parse(data);
        assert!(results.iter().any(|r| r.is_err()));
        assert!(results.iter().any(|r| r.is_ok()));
    }

    #[test]
    fn relative_url_yields_no_domain_triple() {
        // Some HAProxy setups log a relative request target.
        let data = " 10.0.0.5:5000 [10/Jun/2026:00:00:27.428] fe be/srv 0/0/0/1/1 200 100 - - ---- 0/0/0/0/0 0/0 \"GET /health HTTP/1.1\"";
        let triples = HaproxyParser.parse(data);
        // No domain => only the URL edge survives.
        assert_eq!(triples.len(), 1);
        assert_eq!(triples[0].2.id, "/health");
        assert_eq!(triples[0].2.entity_type, EntityType::URL);
    }
}
