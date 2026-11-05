use std::collections::HashMap;

use graph_hunter_core::entity::Entity;
use graph_hunter_core::parser::{LogParser, ParseError, ParseStats, ParsedTriple, RawIngestEvent};
use graph_hunter_core::relation::Relation;
use graph_hunter_core::types::{EntityType, RelationType};

/// Parser for HAProxy HTTP log format (`option httplog` / `httpslog`).
///
/// A typical line looks like:
/// ```text
///  203.0.113.86:36696 [10/Jun/2026:00:00:27.428] https~ be_pool/srv_01 0/0/0/1/1 \
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
    let client_ip = toks[0]
        .rsplit_once(':')
        .map(|(ip, _)| ip)
        .unwrap_or(toks[0]);
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

/// Escape hatch: set `GRAPHHUNTER_URL_KEEP_IDS` to keep raw path
/// identifiers instead of collapsing them. Read once — this sits on a path
/// that runs once per log line.
fn keep_raw_path_ids() -> bool {
    static KEEP: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    *KEEP.get_or_init(|| std::env::var_os("GRAPHHUNTER_URL_KEEP_IDS").is_some())
}

fn is_numeric_id(seg: &str) -> bool {
    !seg.is_empty() && seg.bytes().all(|b| b.is_ascii_digit())
}

/// `8-4-4-4-12` hex, the canonical UUID rendering.
fn is_uuid(seg: &str) -> bool {
    seg.len() == 36
        && seg.bytes().enumerate().all(|(i, b)| match i {
            8 | 13 | 18 | 23 => b == b'-',
            _ => b.is_ascii_hexdigit(),
        })
}

/// Collapses identifier-shaped path segments (`/credencial/5982994` →
/// `/credencial/{id}`) so URL-node cardinality tracks the API's endpoint
/// surface instead of its traffic volume.
///
/// This is the same bound `split_url` already enforces by dropping the
/// query string, applied where the identifiers actually are: REST APIs put
/// them in the path. Measured on a real portal log, raw paths grew roughly
/// linearly — 39.254 distinct in 193k lines, one new path every five
/// requests — which at full volume means millions of URL entities in a map
/// that does not spill to disk. Collapsing them converges instead: 1.683
/// distinct over the same lines, and still flattening.
///
/// It also sharpens the signal. One client hitting `/credencial/{id}` five
/// thousand times is a pattern a hunter can see; five thousand singleton
/// nodes are noise. And on the logs that motivated this, the collapsed
/// segments were patient identifiers, which have no business becoming
/// entity IDs.
fn normalize_path_ids(path: &str) -> String {
    let mut out = String::with_capacity(path.len());
    for (i, seg) in path.split('/').enumerate() {
        if i > 0 {
            out.push('/');
        }
        if is_numeric_id(seg) {
            out.push_str("{id}");
        } else if is_uuid(seg) {
            out.push_str("{uuid}");
        } else {
            out.push_str(seg);
        }
    }
    out
}

/// Splits a request-line URL into `(domain, path)`. Absolute URLs
/// (`https://host/path?q`) yield the host and the query-stripped path;
/// relative URLs (`/path?q`) yield an empty domain and the stripped path.
/// The query string is dropped, and identifier-shaped path segments are
/// collapsed (see [`normalize_path_ids`]), to keep URL-node cardinality
/// bounded — at HAProxy volumes either one would otherwise mint a unique
/// node per request.
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
    let bounded = if keep_raw_path_ids() {
        path_no_query.to_string()
    } else {
        normalize_path_ids(path_no_query)
    };
    (domain, bounded)
}

/// Builds the 1–3 triples for one parsed record. Shared by `parse` and
/// `try_parse` so both paths agree on the emitted graph shape.
/// Per-request metadata (`method`, `status`, `backend`) shared by both the
/// triple and raw-event paths. Extracted so the two cannot drift: they
/// disagreeing about which edge carries `status` is the difference between
/// a hunt being able to filter on 401s and not.
fn build_meta(rec: &HaproxyRecord<'_>) -> HashMap<String, String> {
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
    meta
}

/// Anchor for the backend edge. HAProxy always knows which server it
/// routed to, but the *requested host* only exists when the client sent an
/// absolute request target. With a relative target (`GET /api/x`) the
/// domain is unknown, so the backend edge hangs off the client IP instead
/// of being dropped — the routing fact is observed either way.
///
/// The asymmetry is deliberate and matters when writing hypotheses:
/// absolute-target traffic yields `IP -> Domain -> Host`, relative-target
/// traffic yields `IP -> Host` directly.
fn backend_anchor<'a>(rec: &'a HaproxyRecord<'a>) -> (&'a str, EntityType) {
    if rec.domain.is_empty() {
        (rec.client_ip, EntityType::IP)
    } else {
        (rec.domain, EntityType::Domain)
    }
}

fn record_to_triples(rec: &HaproxyRecord<'_>) -> Vec<ParsedTriple> {
    let mut triples = Vec::new();
    let meta = build_meta(rec);

    // Triple 1: client IP -[Connect]-> requested domain.
    if !rec.domain.is_empty() {
        let src = Entity::new(rec.client_ip, EntityType::IP);
        let dst = Entity::new(rec.domain, EntityType::Domain);
        let mut rel = Relation::new(
            rec.client_ip,
            rec.domain,
            RelationType::Connect,
            rec.timestamp,
        );
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
        let mut rel = Relation::new(rec.client_ip, &rec.url, rel_type, rec.timestamp);
        // With no domain edge to carry it, the URL edge is the only place
        // `method`/`status` can live — without this, relative-target traffic
        // is unfilterable by response code.
        if rec.domain.is_empty() {
            rel.metadata = meta.clone();
        }
        triples.push((src, rel, dst));
    }

    // Triple 3: backend routing, anchored per `backend_anchor`.
    if !rec.server.is_empty() && rec.server != "-" {
        let (src_id, src_type) = backend_anchor(rec);
        let src = Entity::new(src_id, src_type);
        let dst = Entity::new(rec.server, EntityType::Host);
        let rel = Relation::new(src_id, rec.server, RelationType::Connect, rec.timestamp);
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

    // Exactly one edge owns the metadata: the domain edge when there is one,
    // the URL edge otherwise. `take` makes that single ownership explicit and
    // keeps this hot path (one call per log line) free of a per-line clone.
    let mut meta = Some(build_meta(rec));

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
            rel_metadata: meta.take().unwrap_or_default(),
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
            // Only claims the metadata when triple 1 did not: with a relative
            // request target this is the sole edge that can carry status.
            rel_metadata: if rec.domain.is_empty() {
                meta.take().unwrap_or_default()
            } else {
                HashMap::new()
            },
            timestamp: rec.timestamp,
            raw_line: None,
        });
    }

    // Triple 3: backend routing, anchored per `backend_anchor`.
    if !rec.server.is_empty() && rec.server != "-" {
        let (src_id, src_type) = backend_anchor(rec);
        events.push(RawIngestEvent {
            src_id: src_id.to_string(),
            src_type,
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

/// Extracts the accept-date from a raw HAProxy line as ISO `YYYY-MM-DD`
/// bytes, for the ingest range filter.
///
/// That filter works by probing the first 10 bytes of a line for an ISO
/// date, which suits IIS and CSV. HAProxy puts its date in the *second*
/// token and in `DD/Mon/YYYY` form (`[06/Aug/2026:00:00:09.930]`), so the
/// probe never fired and a HAProxy ingest silently ignored the range —
/// the operator asked for one day and got twenty. Normalizing here lets
/// the same lexicographic comparison work, since ISO dates sort as bytes.
///
/// Returns `None` for anything that is not a recognizable HAProxy date;
/// callers must leave such lines unfiltered rather than drop them.
pub fn haproxy_iso_date(line: &[u8]) -> Option<[u8; 10]> {
    let open = line.iter().position(|&b| b == b'[')?;
    let d = line.get(open + 1..open + 12)?; // `DD/Mon/YYYY`
    if d[2] != b'/' || d[6] != b'/' {
        return None;
    }
    let month: &[u8; 2] = match &d[3..6] {
        b"Jan" => b"01",
        b"Feb" => b"02",
        b"Mar" => b"03",
        b"Apr" => b"04",
        b"May" => b"05",
        b"Jun" => b"06",
        b"Jul" => b"07",
        b"Aug" => b"08",
        b"Sep" => b"09",
        b"Oct" => b"10",
        b"Nov" => b"11",
        b"Dec" => b"12",
        _ => return None,
    };
    if !d[0].is_ascii_digit() || !d[1].is_ascii_digit() || !d[7].is_ascii_digit() {
        return None;
    }
    let mut out = [b'-'; 10];
    out[0..4].copy_from_slice(&d[7..11]); // YYYY
    out[5..7].copy_from_slice(month);
    out[8..10].copy_from_slice(&d[0..2]); // DD
    Some(out)
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

    const SAMPLE_LOG: &str = " 203.0.113.86:36696 [10/Jun/2026:00:00:27.428] https~ be_portal/portal_01 0/0/0/1/1 200 659 - - --NI 619/611/1/0/0 0/0 \"OPTIONS https://www1.example.org/portal/api/log/guardarNuevoLog/1000001/INICIO HTTP/2.0\"
 198.51.100.58:42778 [10/Jun/2026:00:00:27.452] https~ be_wiki/wiki_01 0/0/0/4/4 200 1281 - - --VN 619/611/2/2/0 0/0 \"POST https://wiki.example.org/rest/wrm/2.0/resources?_=123 HTTP/2.0\"
";

    #[test]
    fn detects_haproxy() {
        assert!(looks_like_haproxy(SAMPLE_LOG));
    }

    #[test]
    fn rejects_apache_combined() {
        // Apache: bare IP (no port) and a space-split date with timezone.
        let apache = "127.0.0.1 - frank [10/Oct/2000:13:55:36 -0700] \"GET /apache_pb.gif HTTP/1.0\" 200 2326";
        assert!(!looks_like_haproxy(apache));
    }

    #[test]
    fn rejects_non_http_text() {
        assert!(!looks_like_haproxy(
            "just some plain text\nwith no structure"
        ));
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
        assert_eq!(src.id, "203.0.113.86");
        assert_eq!(src.entity_type, EntityType::IP);
        assert_eq!(dst.id, "www1.example.org");
        assert_eq!(dst.entity_type, EntityType::Domain);
        assert_eq!(rel.rel_type, RelationType::Connect);
        assert_eq!(rel.metadata.get("method").unwrap(), "OPTIONS");
        assert_eq!(rel.metadata.get("status").unwrap(), "200");
        assert_eq!(rel.metadata.get("backend").unwrap(), "be_portal");
    }

    #[test]
    fn parse_url_path_strips_query_and_uses_method_verb() {
        let triples = HaproxyParser.parse(SAMPLE_LOG);
        // triples[1] is line 1's URL edge (OPTIONS => Read).
        let (_, rel1, dst1) = &triples[1];
        // `1000001` collapses: URL nodes name endpoints, not records.
        assert_eq!(dst1.id, "/portal/api/log/guardarNuevoLog/{id}/INICIO");
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
        assert_eq!(src.id, "www1.example.org");
        assert_eq!(src.entity_type, EntityType::Domain);
        assert_eq!(dst.id, "portal_01");
        assert_eq!(dst.entity_type, EntityType::Host);
        assert_eq!(rel.rel_type, RelationType::Connect);
    }

    #[test]
    fn path_ids_collapse_so_url_nodes_track_endpoints_not_traffic() {
        // The real shape from the log that motivated this: the identifier
        // is in the path, not the query string, so stripping the query
        // bounded nothing.
        assert_eq!(
            normalize_path_ids("/portal/api/perfil/credencial/1000002"),
            "/portal/api/perfil/credencial/{id}"
        );
        // Two requests for different records collapse to one node.
        assert_eq!(
            normalize_path_ids("/api/medicos/1000003"),
            normalize_path_ids("/api/medicos/9999999")
        );
        assert_eq!(
            normalize_path_ids("/s/550e8400-e29b-41d4-a716-446655440000/x"),
            "/s/{uuid}/x"
        );
    }

    #[test]
    fn path_normalization_leaves_real_endpoint_names_alone() {
        // Version-ish and alphanumeric segments must survive, or the
        // collapse would merge genuinely different endpoints.
        assert_eq!(
            normalize_path_ids("/rest/wrm/2.0/resources"),
            "/rest/wrm/2.0/resources"
        );
        assert_eq!(normalize_path_ids("/api/v2/users"), "/api/v2/users");
        assert_eq!(normalize_path_ids("/health"), "/health");
        assert_eq!(normalize_path_ids("/"), "/");
        // A 36-char non-hex segment is not a UUID.
        assert_eq!(
            normalize_path_ids("/zzze8400-e29b-41d4-a716-44665544zzzz"),
            "/zzze8400-e29b-41d4-a716-44665544zzzz"
        );
    }

    #[test]
    fn iso_date_normalizes_the_bracketed_accept_date() {
        // The real shape, leading space and all.
        let line = b" 198.51.100.140:44164 [06/Aug/2026:00:00:09.930] https~ be/srv 0/0/1/1/1 200 1 - - --NI 0/0/0/0/0 0/0 \"GET /x HTTP/1.1\"";
        assert_eq!(haproxy_iso_date(line).as_ref(), Some(b"2026-08-06"));
    }

    #[test]
    fn iso_date_sorts_lexicographically_across_months() {
        // The whole point of normalizing: `Aug` < `Jun` as text but August
        // is the later month. ISO bytes put them back in real order.
        let aug = haproxy_iso_date(b" ip [06/Aug/2026:00:00:00.000] x").unwrap();
        let jun = haproxy_iso_date(b" ip [06/Jun/2026:00:00:00.000] x").unwrap();
        assert!(jun < aug, "June must sort before August");
    }

    #[test]
    fn iso_date_rejects_non_haproxy_shapes() {
        // Must return None, not a guess: the caller leaves undatable lines
        // unfiltered, and a wrong guess would silently drop real rows.
        assert_eq!(haproxy_iso_date(b"no brackets here"), None);
        assert_eq!(haproxy_iso_date(b" ip [not-a-date] x"), None);
        assert_eq!(haproxy_iso_date(b" ip [06/Xxx/2026:00:00:00.000] x"), None);
        assert_eq!(haproxy_iso_date(b" ip ["), None);
    }

    #[test]
    fn timestamp_parses_haproxy_date() {
        // 10/Jun/2026:00:00:27.428 UTC == 1781049627 (seconds; ms truncated)
        assert_eq!(
            parse_haproxy_datetime("10/Jun/2026:00:00:27.428"),
            1781049627
        );
        assert_eq!(parse_haproxy_datetime(""), 0);
        assert_eq!(parse_haproxy_datetime("garbage"), 0);
    }

    #[test]
    fn try_parse_flags_malformed_line() {
        let data = "203.0.113.86:36696 [10/Jun/2026:00:00:27.428] https~ be/srv 0/0/0/1/1 200 659 - - --NI 0/0/0/0/0 0/0 \"GET https://h.example/a HTTP/2.0\"\nnot a haproxy line";
        let results = HaproxyParser.try_parse(data);
        assert!(results.iter().any(|r| r.is_err()));
        assert!(results.iter().any(|r| r.is_ok()));
    }

    /// A relative request target (`GET /health`, no absolute URL) is the
    /// norm for API backends: in a real 15 GB portal log, 74% of lines had
    /// one. HAProxy still records which server it routed to, so dropping
    /// the backend edge threw away an observed fact — the graph came back
    /// with no backends at all for that traffic.
    const RELATIVE: &str = " 10.0.0.5:5000 [10/Jun/2026:00:00:27.428] fe be/srv 0/0/0/1/1 401 100 - - ---- 0/0/0/0/0 0/0 \"GET /health HTTP/1.1\"";

    #[test]
    fn relative_url_still_anchors_the_backend_on_the_client_ip() {
        let triples = HaproxyParser.parse(RELATIVE);
        // URL edge + backend edge. No domain edge: there is no domain.
        assert_eq!(triples.len(), 2);
        assert!(
            !triples
                .iter()
                .any(|(_, _, d)| d.entity_type == EntityType::Domain),
            "a relative target has no host to build a Domain node from"
        );

        let (src, rel, dst) = &triples[1];
        assert_eq!(src.id, "10.0.0.5");
        assert_eq!(src.entity_type, EntityType::IP);
        assert_eq!(dst.id, "srv");
        assert_eq!(dst.entity_type, EntityType::Host);
        assert_eq!(rel.rel_type, RelationType::Connect);
    }

    #[test]
    fn relative_url_edge_carries_status_so_it_stays_filterable() {
        // The domain edge normally owns method/status. With no domain edge
        // the metadata used to be dropped on the floor, which made the whole
        // relative-target corpus unfilterable by response code.
        let triples = HaproxyParser.parse(RELATIVE);
        let (_, url_rel, dst) = &triples[0];
        assert_eq!(dst.entity_type, EntityType::URL);
        assert_eq!(
            url_rel.metadata.get("status").map(String::as_str),
            Some("401")
        );
        assert_eq!(
            url_rel.metadata.get("method").map(String::as_str),
            Some("GET")
        );
    }

    #[test]
    fn absolute_url_keeps_metadata_on_the_domain_edge() {
        // Regression guard: the fix must not move metadata for logs that do
        // carry an absolute target, or existing hunts change meaning.
        let triples = HaproxyParser.parse(SAMPLE_LOG);
        let (_, domain_rel, dst) = &triples[0];
        assert_eq!(dst.entity_type, EntityType::Domain);
        assert_eq!(
            domain_rel.metadata.get("status").map(String::as_str),
            Some("200")
        );
        // ...and the URL edge stays bare, as before.
        assert!(triples[1].1.metadata.is_empty());
    }

    /// The streaming ingest path calls `parse_raw`, not `parse`. The two
    /// drifting is exactly how a fix lands in tests and never reaches the
    /// multi-GB ingest that needed it.
    #[test]
    fn raw_event_path_matches_the_triple_path_for_relative_targets() {
        let triples = HaproxyParser.parse(RELATIVE);
        let events = HaproxyParser.parse_raw(RELATIVE);
        assert_eq!(events.len(), triples.len());

        let backend = events
            .iter()
            .find(|e| e.dst_type == EntityType::Host)
            .expect("raw path must emit the backend edge too");
        assert_eq!(backend.src_id, "10.0.0.5");
        assert_eq!(backend.src_type, EntityType::IP);
        assert_eq!(backend.dst_id, "srv");

        let url = events
            .iter()
            .find(|e| e.dst_type == EntityType::URL)
            .expect("raw path must emit the URL edge");
        assert_eq!(
            url.rel_metadata.get("status").map(String::as_str),
            Some("401")
        );
    }
}
