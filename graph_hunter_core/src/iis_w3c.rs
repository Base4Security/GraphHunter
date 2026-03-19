use std::collections::HashMap;

use crate::entity::Entity;
use crate::parser::{LogParser, ParsedTriple};
use crate::relation::Relation;
use crate::types::{EntityType, RelationType};

/// Parser for IIS / W3C Extended Log Format files.
///
/// Handles the space-delimited, `#Fields:`-directed log format produced by
/// Microsoft Internet Information Services. Supports mid-file field header
/// changes (which occur after log rotation within a single file).
///
/// Each data line produces up to three triples:
///   1. client IP  -[Connect]-> server IP
///   2. client IP  -[Read|Write]-> URL path
///   3. username   -[Auth]-> server IP   (when username is present)
pub struct IisW3cParser;

impl LogParser for IisW3cParser {
    fn parse(&self, data: &str) -> Vec<ParsedTriple> {
        let mut triples = Vec::new();
        let mut fields: Vec<String> = Vec::new();

        for line in data.lines() {
            let line = line.trim();
            if line.is_empty() {
                continue;
            }

            // Comment/metadata lines
            if line.starts_with('#') {
                if let Some(rest) = line.strip_prefix("#Fields:") {
                    fields = rest
                        .trim()
                        .split_whitespace()
                        .map(|s| s.to_lowercase().to_string())
                        .collect();
                }
                continue;
            }

            // Skip data lines until we have a field header
            if fields.is_empty() {
                continue;
            }

            let values: Vec<&str> = line.split_whitespace().collect();
            if values.len() < fields.len() {
                continue;
            }

            // Build field -> value map for this line
            let mut fmap: HashMap<&str, &str> = HashMap::with_capacity(fields.len());
            for (i, fname) in fields.iter().enumerate() {
                if i < values.len() {
                    fmap.insert(fname.as_str(), values[i]);
                }
            }

            let client_ip = fmap.get("c-ip").copied().unwrap_or("-");
            let server_ip = fmap.get("s-ip").copied().unwrap_or("-");
            let uri_stem = fmap.get("cs-uri-stem").copied().unwrap_or("-");
            let method = fmap.get("cs-method").copied().unwrap_or("-");
            let username = fmap.get("cs-username").copied().unwrap_or("-");
            let status = fmap.get("sc-status").copied().unwrap_or("-");

            // Parse timestamp from date + time columns
            let date_str = fmap.get("date").copied().unwrap_or("");
            let time_str = fmap.get("time").copied().unwrap_or("");
            let timestamp = parse_w3c_datetime(date_str, time_str);

            // Must have at least client and server IP to produce useful triples
            if client_ip == "-" || server_ip == "-" {
                continue;
            }

            // Lightweight metadata: only method + status (2 small strings).
            // Skipping user_agent/referer/time_taken saves ~150 bytes × millions of relations.
            let mut meta = HashMap::new();
            if method != "-" {
                meta.insert("method".into(), method.into());
            }
            if status != "-" {
                meta.insert("status".into(), status.into());
            }

            // Triple 1: client_ip -[Connect]-> server_ip
            let src = Entity::new(client_ip, EntityType::IP);
            let dst = Entity::new(server_ip, EntityType::Host);
            let mut rel =
                Relation::new(client_ip, server_ip, RelationType::Connect, timestamp);
            rel.metadata = meta;
            triples.push((src, rel, dst));

            // Triple 2: client_ip -[Read|Write]-> uri_stem
            if uri_stem != "-" && uri_stem != "/" {
                let rel_type = match method {
                    "GET" | "HEAD" | "OPTIONS" => RelationType::Read,
                    "POST" | "PUT" | "DELETE" | "PATCH" => RelationType::Write,
                    _ => RelationType::Connect,
                };
                let src2 = Entity::new(client_ip, EntityType::IP);
                let dst2 = Entity::new(uri_stem, EntityType::URL);
                let rel2 =
                    Relation::new(client_ip, uri_stem, rel_type, timestamp);
                triples.push((src2, rel2, dst2));
            }

            // Triple 3: user -[Auth]-> server_ip (only when a real username is present)
            if username != "-" && !username.is_empty() {
                let src3 = Entity::new(username, EntityType::User);
                let dst3 = Entity::new(server_ip, EntityType::Host);
                let rel3 =
                    Relation::new(username, server_ip, RelationType::Auth, timestamp);
                triples.push((src3, rel3, dst3));
            }
        }

        triples
    }
}

/// Parses W3C date ("2025-06-30") and time ("05:43:03") into Unix epoch seconds.
fn parse_w3c_datetime(date: &str, time: &str) -> i64 {
    if date.is_empty() || time.is_empty() {
        return 0;
    }
    let datetime_str = format!("{} {}", date, time);
    chrono::NaiveDateTime::parse_from_str(&datetime_str, "%Y-%m-%d %H:%M:%S")
        .map(|dt| dt.and_utc().timestamp())
        .unwrap_or(0)
}

/// Returns `true` if the text looks like an IIS W3C Extended Log file.
///
/// Checks for the `#Software: Microsoft Internet Information Services` header
/// or an IIS-style `#Fields:` line containing characteristic field names.
pub fn looks_like_iis_w3c(text: &str) -> bool {
    for line in text.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with("#Software:") && trimmed.contains("Internet Information Services")
        {
            return true;
        }
        if let Some(rest) = trimmed.strip_prefix("#Fields:") {
            let lower = rest.to_lowercase();
            // IIS fields always include s-ip, c-ip, and cs-method
            if lower.contains("s-ip") && lower.contains("c-ip") && lower.contains("cs-method")
            {
                return true;
            }
        }
        // Stop scanning after the first non-comment line to avoid reading the
        // whole file on non-IIS input.
        if !trimmed.is_empty() && !trimmed.starts_with('#') {
            break;
        }
    }
    false
}

/// Extracts the last `#Fields:` header line found in the given text.
/// Returns `None` if no fields header is present.
pub fn extract_fields_header(text: &str) -> Option<String> {
    let mut last: Option<String> = None;
    for line in text.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with("#Fields:") {
            last = Some(trimmed.to_string());
        }
    }
    last
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE_LOG: &str = "\
#Software: Microsoft Internet Information Services 10.0
#Version: 1.0
#Date: 2025-06-30 05:43:03
#Fields: date time s-ip cs-method cs-uri-stem cs-uri-query s-port cs-username c-ip cs(User-Agent) cs(Referer) sc-status sc-substatus sc-win32-status time-taken
2025-06-30 05:43:03 10.7.20.69 GET /attach/profilephotos/18512.jpg 1751262183029 443 - 186.182.168.89 Mozilla/5.0+Windows https://example.com/dashboard 500 19 1330 240
2025-06-30 05:44:10 10.7.20.69 POST /api/upload - 443 admin 192.168.1.50 curl/7.68.0 - 200 0 0 120
";

    #[test]
    fn iis_parse_basic() {
        let parser = IisW3cParser;
        let triples = parser.parse(SAMPLE_LOG);

        // First data line: GET => Connect + Read (uri != "/")  => 2 triples
        // Second data line: POST with username => Connect + Write + Auth => 3 triples
        assert_eq!(triples.len(), 5);
    }

    #[test]
    fn iis_parse_connect_triple() {
        let parser = IisW3cParser;
        let triples = parser.parse(SAMPLE_LOG);

        // First triple: client IP -> Connect -> server IP
        let (src, rel, dst) = &triples[0];
        assert_eq!(src.id, "186.182.168.89");
        assert_eq!(src.entity_type, EntityType::IP);
        assert_eq!(dst.id, "10.7.20.69");
        assert_eq!(dst.entity_type, EntityType::Host);
        assert_eq!(rel.rel_type, RelationType::Connect);
        assert_eq!(rel.metadata.get("method").unwrap(), "GET");
        assert_eq!(rel.metadata.get("status").unwrap(), "500");
    }

    #[test]
    fn iis_parse_read_triple() {
        let parser = IisW3cParser;
        let triples = parser.parse(SAMPLE_LOG);

        // Second triple: client IP -> Read -> URL
        let (src, rel, dst) = &triples[1];
        assert_eq!(src.id, "186.182.168.89");
        assert_eq!(dst.id, "/attach/profilephotos/18512.jpg");
        assert_eq!(dst.entity_type, EntityType::URL);
        assert_eq!(rel.rel_type, RelationType::Read);
    }

    #[test]
    fn iis_parse_write_triple() {
        let parser = IisW3cParser;
        let triples = parser.parse(SAMPLE_LOG);

        // Fourth triple: POST => Write
        let (src, rel, dst) = &triples[3];
        assert_eq!(src.id, "192.168.1.50");
        assert_eq!(dst.id, "/api/upload");
        assert_eq!(dst.entity_type, EntityType::URL);
        assert_eq!(rel.rel_type, RelationType::Write);
    }

    #[test]
    fn iis_parse_auth_triple() {
        let parser = IisW3cParser;
        let triples = parser.parse(SAMPLE_LOG);

        // Fifth triple: user -> Auth -> server
        let (src, rel, dst) = &triples[4];
        assert_eq!(src.id, "admin");
        assert_eq!(src.entity_type, EntityType::User);
        assert_eq!(dst.id, "10.7.20.69");
        assert_eq!(dst.entity_type, EntityType::Host);
        assert_eq!(rel.rel_type, RelationType::Auth);
    }

    #[test]
    fn iis_parse_timestamp() {
        let parser = IisW3cParser;
        let triples = parser.parse(SAMPLE_LOG);
        // 2025-06-30 05:43:03 UTC
        assert_eq!(triples[0].1.timestamp, 1751262183);
    }

    #[test]
    fn iis_parse_multiple_fields_headers() {
        let log = "\
#Fields: date time s-ip cs-method cs-uri-stem s-port cs-username c-ip sc-status
2025-01-01 00:00:00 10.0.0.1 GET /page1 80 - 1.2.3.4 200
#Fields: date time s-ip cs-method cs-uri-stem c-ip sc-status
2025-01-01 00:01:00 10.0.0.2 POST /page2 5.6.7.8 201
";
        let parser = IisW3cParser;
        let triples = parser.parse(log);

        // First section: Connect + Read = 2 triples
        // Second section: new #Fields, Connect + Write = 2 triples
        assert_eq!(triples.len(), 4);
        // Verify second section used updated fields
        assert_eq!(triples[2].0.id, "5.6.7.8"); // c-ip from second layout
        assert_eq!(triples[2].2.id, "10.0.0.2"); // s-ip from second layout
    }

    #[test]
    fn iis_parse_skip_no_fields_header() {
        let log = "\
#Software: Microsoft Internet Information Services 10.0
2025-01-01 00:00:00 10.0.0.1 GET /page1 80 - 1.2.3.4 200
";
        let parser = IisW3cParser;
        let triples = parser.parse(log);
        // No #Fields: header, so data lines are skipped
        assert!(triples.is_empty());
    }

    #[test]
    fn iis_parse_skip_dash_only_ips() {
        let log = "\
#Fields: date time s-ip cs-method cs-uri-stem c-ip sc-status
2025-01-01 00:00:00 - GET /page1 - 200
";
        let parser = IisW3cParser;
        let triples = parser.parse(log);
        assert!(triples.is_empty());
    }

    #[test]
    fn iis_detect_software_header() {
        let text = "#Software: Microsoft Internet Information Services 10.0\n#Version: 1.0\n";
        assert!(looks_like_iis_w3c(text));
    }

    #[test]
    fn iis_detect_fields_header() {
        let text = "#Fields: date time s-ip cs-method cs-uri-stem c-ip sc-status\n";
        assert!(looks_like_iis_w3c(text));
    }

    #[test]
    fn iis_detect_negative() {
        assert!(!looks_like_iis_w3c("{\"EventID\": 1}"));
        assert!(!looks_like_iis_w3c("timestamp,source,destination"));
    }

    #[test]
    fn iis_extract_fields_header() {
        let text = "\
#Software: IIS
#Fields: date time s-ip c-ip
some data
#Fields: date time s-ip c-ip cs-method
more data
";
        let header = extract_fields_header(text).unwrap();
        assert_eq!(header, "#Fields: date time s-ip c-ip cs-method");
    }

    #[test]
    fn iis_user_agent_plus_decode() {
        let log = "\
#Fields: date time s-ip cs-method cs-uri-stem c-ip cs(User-Agent) sc-status
2025-01-01 00:00:00 10.0.0.1 GET /page 1.2.3.4 Mozilla/5.0+(Windows+NT+10.0) 200
";
        let parser = IisW3cParser;
        let triples = parser.parse(log);
        let ua = triples[0].1.metadata.get("user_agent").unwrap();
        assert_eq!(ua, "Mozilla/5.0 (Windows NT 10.0)");
    }
}
