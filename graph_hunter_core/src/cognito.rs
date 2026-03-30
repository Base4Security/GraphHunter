use std::collections::HashMap;

use chrono::{DateTime, NaiveDateTime};
use serde_json::Value;

use crate::entity::Entity;
use crate::parser::{LogParser, ParsedTriple};
use crate::relation::Relation;
use crate::types::{EntityType, RelationType};

/// Parser for AWS Cognito authentication logs.
///
/// Supports three related formats from the same auth system:
///
/// | Format                     | Triples Produced                                          |
/// |----------------------------|-----------------------------------------------------------|
/// | Notifications CSV          | IP -[Auth]-> User, User -[Auth]-> Service("cognito")      |
/// | PreAuthentication Lambda   | User -[Auth]-> Service("cognito-pool")                    |
/// | PostAuthentication Lambda  | User -[Auth]-> Service("cognito-pool")                    |
///
/// ## Format Detection
///
/// - If the input starts with `[` it is treated as a CloudWatch JSON array
///   (Pre/Post authentication Lambda logs).
/// - If the first line contains `__typename` or `metadata` it is treated as
///   the Cognito notifications CSV.
///
/// User entities use the Cognito `userName` (a UUID/sub) as their ID, which
/// allows correlation across all three file types.
pub struct CognitoParser;

impl LogParser for CognitoParser {
    fn parse(&self, data: &str) -> Vec<ParsedTriple> {
        let trimmed = data.trim();
        if trimmed.is_empty() {
            return Vec::new();
        }

        if trimmed.starts_with('[') {
            parse_cloudwatch_json(trimmed)
        } else {
            parse_notifications_csv(data)
        }
    }
}

/// Returns `true` if the data looks like one of the Cognito auth formats.
pub fn looks_like_cognito(data: &str) -> bool {
    data.contains("userPoolId")
        || data.contains("PreAuthentication")
        || data.contains("PostAuthentication")
        || data.contains("riskDecision")
}

// ─── Notifications CSV ──────────────────────────────────────────────────────

/// Parses the Cognito notifications CSV format.
///
/// The CSV contains a `metadata` column whose value is a Python dict string
/// (single-quoted keys/values with nested dicts). We extract fields via simple
/// string matching rather than attempting to parse it as JSON.
fn parse_notifications_csv(data: &str) -> Vec<ParsedTriple> {
    let mut triples = Vec::new();
    let mut lines = data.lines();

    // Parse header to find column indices
    let header = match lines.next() {
        Some(h) => h,
        None => return triples,
    };
    let headers = parse_csv_row(header);
    let col_idx = |name: &str| headers.iter().position(|h| h == name);

    let idx_metadata = col_idx("metadata");
    let idx_created_at = col_idx("createdAt");
    let idx_customer_id = col_idx("customerId");

    for line in lines {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }

        let cols = parse_csv_row(line);

        // Extract the metadata Python dict string
        let metadata_str = idx_metadata
            .and_then(|i| cols.get(i))
            .map(|s| s.as_str())
            .unwrap_or("");

        // Extract timestamp
        let timestamp = idx_created_at
            .and_then(|i| cols.get(i))
            .and_then(|ts| parse_iso_timestamp(ts))
            .unwrap_or(0);

        // Extract userName from metadata (the Cognito sub/UUID)
        let user_name = extract_py_dict_value(metadata_str, "userName")
            .unwrap_or_default();
        // Fallback: use customerId column if userName not in metadata
        let user_id = if user_name.is_empty() {
            idx_customer_id
                .and_then(|i| cols.get(i))
                .map(|s| s.to_string())
                .unwrap_or_default()
        } else {
            user_name
        };
        if user_id.is_empty() {
            continue;
        }

        let ip_address = extract_py_dict_value(metadata_str, "ipAddress")
            .unwrap_or_default();
        let risk_decision = extract_py_dict_value(metadata_str, "riskDecision")
            .unwrap_or_default();
        let city = extract_py_dict_value(metadata_str, "city")
            .unwrap_or_default();
        let country = extract_py_dict_value(metadata_str, "country")
            .unwrap_or_default();
        let device_name = extract_py_dict_value(metadata_str, "deviceName")
            .unwrap_or_default();
        let event_type = extract_py_dict_value(metadata_str, "eventType")
            .unwrap_or_default();
        let challenges = extract_py_dict_value(metadata_str, "challenges")
            .unwrap_or_default();
        let client_id = extract_py_dict_value(metadata_str, "clientId")
            .unwrap_or_default();

        // Build relation metadata (only non-empty values)
        let mut rel_meta = HashMap::new();
        if !risk_decision.is_empty() {
            rel_meta.insert("riskDecision".into(), risk_decision.clone());
        }
        if !city.is_empty() {
            rel_meta.insert("city".into(), city);
        }
        if !country.is_empty() {
            rel_meta.insert("country".into(), country);
        }
        if !device_name.is_empty() {
            rel_meta.insert("deviceName".into(), device_name);
        }
        if !event_type.is_empty() {
            rel_meta.insert("eventType".into(), event_type);
        }
        if !challenges.is_empty() {
            rel_meta.insert("challenges".into(), challenges);
        }

        let user_entity = Entity::new(&user_id, EntityType::User);

        // Triple 1: IP -[Auth]-> User (if IP is present)
        if !ip_address.is_empty() {
            let ip_entity = Entity::new(&ip_address, EntityType::IP);
            let mut rel = Relation::new(
                &ip_address,
                &user_id,
                RelationType::Auth,
                timestamp,
            );
            rel.metadata = rel_meta.clone();
            // Flag high-risk sign-ins
            if risk_decision == "ACCOUNT_TAKEOVER" {
                rel.metadata
                    .insert("alert".into(), "ACCOUNT_TAKEOVER".into());
            }
            triples.push((ip_entity, rel, user_entity.clone()));
        }

        // Triple 2: User -[Auth]-> Service
        let service_name = if client_id.is_empty() {
            "cognito".to_string()
        } else {
            client_id
        };
        let service_entity = Entity::new(&service_name, EntityType::Service);
        let mut rel2 = Relation::new(
            &user_id,
            &service_name,
            RelationType::Auth,
            timestamp,
        );
        rel2.metadata = rel_meta;
        triples.push((user_entity, rel2, service_entity));
    }

    triples
}

/// Parses a single CSV row, respecting quoted fields that may contain commas.
fn parse_csv_row(line: &str) -> Vec<String> {
    let mut fields = Vec::new();
    let mut current = String::new();
    let mut in_quotes = false;
    let mut chars = line.chars().peekable();

    while let Some(ch) = chars.next() {
        match ch {
            '"' => {
                if in_quotes {
                    // Check for escaped quote ("")
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
                fields.push(current.trim().to_string());
                current = String::new();
            }
            _ => {
                current.push(ch);
            }
        }
    }
    fields.push(current.trim().to_string());
    fields
}

/// Extracts a value from a Python dict string like `{'key': 'value', ...}`.
///
/// Looks for the pattern `'key': 'value'` and returns the value.
/// Also handles `'key': "value"` and unquoted values like `'key': None`.
fn extract_py_dict_value(dict_str: &str, key: &str) -> Option<String> {
    // Pattern: 'key': 'value' or 'key': "value"
    let patterns = [
        format!("'{}': '", key),
        format!("'{}': \"", key),
    ];

    for pattern in &patterns {
        if let Some(start) = dict_str.find(pattern.as_str()) {
            let value_start = start + pattern.len();
            let closing_char = if pattern.ends_with('\'') { '\'' } else { '"' };
            if let Some(end) = dict_str[value_start..].find(closing_char) {
                let value = &dict_str[value_start..value_start + end];
                if value != "None" {
                    return Some(value.to_string());
                }
            }
        }
    }

    // Handle unquoted values like 'key': None or 'key': True
    let unquoted = format!("'{}': ", key);
    if let Some(start) = dict_str.find(&unquoted) {
        let value_start = start + unquoted.len();
        let rest = &dict_str[value_start..];
        // Value ends at comma, closing brace, or end of string
        let end = rest
            .find(|c: char| c == ',' || c == '}')
            .unwrap_or(rest.len());
        let value = rest[..end].trim();
        if value != "None" && !value.is_empty() {
            return Some(value.to_string());
        }
    }

    None
}

// ─── CloudWatch JSON (Pre/Post Authentication Lambda) ───────────────────────

/// Parses CloudWatch log entries from Pre/Post Authentication Lambda functions.
fn parse_cloudwatch_json(data: &str) -> Vec<ParsedTriple> {
    let mut triples = Vec::new();

    // Parse each JSON object individually. For real files, each object is on its own line.
    // For test data or pretty-printed JSON, fall back to full array parse.
    let trimmed = data.trim();

    // Try line-by-line first (fast path for real CloudWatch exports)
    let mut entries: Vec<Value> = Vec::new();
    for line in trimmed.lines() {
        let line = line.trim().trim_start_matches('[').trim_start_matches(',').trim();
        if line.starts_with('{') {
            let json_str = if line.ends_with(',') { &line[..line.len()-1] } else { line };
            let json_str = json_str.trim_end_matches(']');
            if let Ok(v) = serde_json::from_str::<Value>(json_str) {
                entries.push(v);
            }
        }
    }

    // Fallback: if line-by-line found nothing, try full array parse (for tests/small files)
    if entries.is_empty() {
        if let Ok(arr) = serde_json::from_str::<Vec<Value>>(trimmed) {
            entries = arr;
        }
    }

    for entry in &entries {
        let timestamp_ms = entry
            .get("timestamp")
            .and_then(|v| v.as_i64())
            .unwrap_or(0);
        let timestamp = timestamp_ms / 1000; // Convert ms to seconds

        let message = match entry.get("message").and_then(|v| v.as_str()) {
            Some(m) => m,
            None => continue,
        };

        // Check for the structured input message:
        // "INFO\tInput for PreAuthentication -> {...}"
        // "INFO\tInput for PostAuthentication -> {...}"
        if let Some(json_start) = message.find("-> {") {
            let json_str = message[json_start + 3..].trim();
            if let Ok(payload) = serde_json::from_str::<Value>(json_str) {
                let user_name = payload
                    .get("userName")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string();

                if user_name.is_empty() {
                    continue;
                }

                let email = payload
                    .pointer("/request/userAttributes/email")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string();

                let phone = payload
                    .pointer("/request/userAttributes/phone_number")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string();

                let trigger_source = payload
                    .get("triggerSource")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string();

                let mut rel_meta = HashMap::new();
                if !email.is_empty() {
                    rel_meta.insert("email".into(), email);
                }
                if !phone.is_empty() {
                    rel_meta.insert("phone".into(), phone);
                }
                if !trigger_source.is_empty() {
                    rel_meta.insert("triggerSource".into(), trigger_source);
                }

                // Determine auth phase from message
                let phase = if message.contains("PreAuthentication") {
                    "PreAuthentication"
                } else {
                    "PostAuthentication"
                };
                rel_meta.insert("phase".into(), phase.into());

                let user_entity = Entity::new(&user_name, EntityType::User);
                let service_entity =
                    Entity::new("cognito-pool", EntityType::Service);
                let mut rel = Relation::new(
                    &user_name,
                    "cognito-pool",
                    RelationType::Auth,
                    timestamp,
                );
                rel.metadata = rel_meta;
                triples.push((user_entity, rel, service_entity));
            }
            continue;
        }

        // Check for status messages:
        // "[PreAuth] LOGIN ALLOWED FOR USER <uuid>"
        // "[PreAuth] LOGIN DENIED FOR USER <uuid>"
        // "[PostAuth] AUTHENTICATION COMPLETE FOR USER <uuid>"
        if let Some(user_id) = extract_status_user(message) {
            let mut rel_meta = HashMap::new();
            if message.contains("LOGIN ALLOWED") {
                rel_meta.insert("authResult".into(), "ALLOWED".into());
            } else if message.contains("LOGIN DENIED") {
                rel_meta.insert("authResult".into(), "DENIED".into());
            } else if message.contains("AUTHENTICATION COMPLETE") {
                rel_meta.insert("authResult".into(), "COMPLETE".into());
            }

            let user_entity = Entity::new(&user_id, EntityType::User);
            let service_entity =
                Entity::new("cognito-pool", EntityType::Service);
            let mut rel = Relation::new(
                &user_id,
                "cognito-pool",
                RelationType::Auth,
                timestamp,
            );
            rel.metadata = rel_meta;
            triples.push((user_entity, rel, service_entity));
        }
    }

    triples
}

/// Extracts the user UUID from status messages like
/// `[PreAuth] LOGIN ALLOWED FOR USER <uuid>` or
/// `[PostAuth] AUTHENTICATION COMPLETE FOR USER <uuid>`.
fn extract_status_user(message: &str) -> Option<String> {
    // Look for "FOR USER " followed by a UUID-like string
    let marker = "FOR USER ";
    if let Some(pos) = message.find(marker) {
        let rest = message[pos + marker.len()..].trim();
        // Take the first whitespace-delimited token (the UUID)
        let user_id = rest.split_whitespace().next().unwrap_or("").to_string();
        if !user_id.is_empty() {
            return Some(user_id);
        }
    }
    None
}

/// Parses an ISO 8601 timestamp string into Unix epoch seconds.
fn parse_iso_timestamp(ts: &str) -> Option<i64> {
    let trimmed = ts.trim();
    if trimmed.is_empty() {
        return None;
    }
    // Try RFC 3339 / ISO 8601 with timezone
    if let Ok(dt) = DateTime::parse_from_rfc3339(trimmed) {
        return Some(dt.timestamp());
    }
    // Without fractional seconds, with Z
    if let Ok(dt) = NaiveDateTime::parse_from_str(
        trimmed.trim_end_matches('Z'),
        "%Y-%m-%dT%H:%M:%S",
    ) {
        return Some(dt.and_utc().timestamp());
    }
    // With fractional seconds
    if let Ok(dt) = NaiveDateTime::parse_from_str(
        trimmed.trim_end_matches('Z'),
        "%Y-%m-%dT%H:%M:%S%.f",
    ) {
        return Some(dt.and_utc().timestamp());
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_py_dict_value() {
        let d = "{'ipAddress': '1.2.3.4', 'userName': 'abc-123', 'riskDecision': 'PASS'}";
        assert_eq!(
            extract_py_dict_value(d, "ipAddress"),
            Some("1.2.3.4".into())
        );
        assert_eq!(
            extract_py_dict_value(d, "userName"),
            Some("abc-123".into())
        );
        assert_eq!(
            extract_py_dict_value(d, "riskDecision"),
            Some("PASS".into())
        );
        assert_eq!(extract_py_dict_value(d, "missing"), None);
    }

    #[test]
    fn test_extract_py_dict_value_none() {
        let d = "{'deviceName': None, 'city': 'Lima'}";
        assert_eq!(extract_py_dict_value(d, "deviceName"), None);
        assert_eq!(
            extract_py_dict_value(d, "city"),
            Some("Lima".into())
        );
    }

    #[test]
    fn test_parse_csv_row_with_quoted_commas() {
        let row = r#"NotifAuth,"{'key': 'a, b'}",2024-01-15T00:00:00Z"#;
        let fields = parse_csv_row(row);
        assert_eq!(fields.len(), 3);
        assert_eq!(fields[0], "NotifAuth");
        assert_eq!(fields[1], "{'key': 'a, b'}");
        assert_eq!(fields[2], "2024-01-15T00:00:00Z");
    }

    #[test]
    fn test_looks_like_cognito() {
        assert!(looks_like_cognito(
            r#"{"userPoolId":"us-east-1_abc"}"#
        ));
        assert!(looks_like_cognito("PreAuthentication trigger"));
        assert!(looks_like_cognito("riskDecision: PASS"));
        assert!(!looks_like_cognito("SecurityEvent"));
    }

    #[test]
    fn test_notifications_csv_parsing() {
        let csv = r#"__typename,metadata,createdAt,type,customerId
NotifAuth,"{'ipAddress': '10.0.0.1', 'userName': 'user-uuid-1', 'riskDecision': 'PASS', 'city': 'Lima', 'country': 'Peru', 'deviceName': 'Chrome', 'eventType': 'SignIn', 'challenges': 'Password:Success', 'clientId': 'app123'}",2024-03-15T10:30:00Z,AUTH,customer-1"#;

        let parser = CognitoParser;
        let triples = parser.parse(csv);
        // Should produce 2 triples: IP->User and User->Service
        assert_eq!(triples.len(), 2);

        let (ref src, ref rel, ref dst) = triples[0];
        assert_eq!(src.id, "10.0.0.1");
        assert_eq!(src.entity_type, EntityType::IP);
        assert_eq!(dst.id, "user-uuid-1");
        assert_eq!(dst.entity_type, EntityType::User);
        assert_eq!(rel.rel_type, RelationType::Auth);
        assert_eq!(rel.metadata.get("city").map(|s| s.as_str()), Some("Lima"));

        let (ref src2, ref rel2, ref dst2) = triples[1];
        assert_eq!(src2.id, "user-uuid-1");
        assert_eq!(src2.entity_type, EntityType::User);
        assert_eq!(dst2.id, "app123");
        assert_eq!(dst2.entity_type, EntityType::Service);
        assert_eq!(rel2.rel_type, RelationType::Auth);
    }

    #[test]
    fn test_cloudwatch_pre_auth_parsing() {
        let json = r#"[
            {
                "timestamp": 1710500000000,
                "message": "INFO\tInput for PreAuthentication -> {\"version\":\"1\",\"userName\":\"user-uuid-2\",\"triggerSource\":\"PreAuthentication_Authentication\",\"request\":{\"userAttributes\":{\"email\":\"test@example.com\",\"phone_number\":\"+1234567890\"}}}"
            },
            {
                "timestamp": 1710500001000,
                "message": "[PreAuth] LOGIN ALLOWED FOR USER user-uuid-2"
            }
        ]"#;

        let parser = CognitoParser;
        let triples = parser.parse(json);
        assert_eq!(triples.len(), 2);

        // First triple: structured auth event
        let (ref src, ref rel, ref dst) = triples[0];
        assert_eq!(src.id, "user-uuid-2");
        assert_eq!(src.entity_type, EntityType::User);
        assert_eq!(dst.id, "cognito-pool");
        assert_eq!(dst.entity_type, EntityType::Service);
        assert_eq!(
            rel.metadata.get("email").map(|s| s.as_str()),
            Some("test@example.com")
        );
        assert_eq!(
            rel.metadata.get("phase").map(|s| s.as_str()),
            Some("PreAuthentication")
        );

        // Second triple: status confirmation
        let (ref src2, ref rel2, _) = triples[1];
        assert_eq!(src2.id, "user-uuid-2");
        assert_eq!(
            rel2.metadata.get("authResult").map(|s| s.as_str()),
            Some("ALLOWED")
        );
    }

    #[test]
    fn test_cloudwatch_post_auth_parsing() {
        let json = r#"[
            {
                "timestamp": 1710500002000,
                "message": "INFO\tInput for PostAuthentication -> {\"version\":\"1\",\"userName\":\"user-uuid-3\",\"triggerSource\":\"PostAuthentication_Authentication\",\"request\":{\"userAttributes\":{\"email\":\"user3@example.com\"}}}"
            },
            {
                "timestamp": 1710500003000,
                "message": "[PostAuth] AUTHENTICATION COMPLETE FOR USER user-uuid-3"
            }
        ]"#;

        let parser = CognitoParser;
        let triples = parser.parse(json);
        assert_eq!(triples.len(), 2);

        let (ref src, ref rel, _) = triples[0];
        assert_eq!(src.id, "user-uuid-3");
        assert_eq!(
            rel.metadata.get("phase").map(|s| s.as_str()),
            Some("PostAuthentication")
        );

        let (_, ref rel2, _) = triples[1];
        assert_eq!(
            rel2.metadata.get("authResult").map(|s| s.as_str()),
            Some("COMPLETE")
        );
    }

    #[test]
    fn test_iso_timestamp_parsing() {
        assert_eq!(
            parse_iso_timestamp("2024-03-15T10:30:00Z"),
            Some(1710498600)
        );
        assert!(parse_iso_timestamp("2024-03-15T10:30:00.123Z").is_some());
        assert_eq!(parse_iso_timestamp(""), None);
    }

    #[test]
    fn test_extract_status_user() {
        assert_eq!(
            extract_status_user("[PreAuth] LOGIN ALLOWED FOR USER abc-123"),
            Some("abc-123".into())
        );
        assert_eq!(
            extract_status_user("[PostAuth] AUTHENTICATION COMPLETE FOR USER xyz-789"),
            Some("xyz-789".into())
        );
        assert_eq!(
            extract_status_user("[PreAuth] LOGIN DENIED FOR USER bad-user"),
            Some("bad-user".into())
        );
        assert_eq!(extract_status_user("some random message"), None);
    }
}
