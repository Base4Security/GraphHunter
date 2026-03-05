use chrono::{DateTime, NaiveDateTime};
use rayon::prelude::*;
use serde_json::Value;

use crate::entity::Entity;
use crate::parser::{LogParser, ParsedTriple};
use crate::relation::Relation;
use crate::types::{EntityType, RelationType};

/// Detected Sentinel table type for a log record.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SentinelTable {
    SecurityEvent,
    SigninLogs,
    DeviceProcessEvents,
    DeviceNetworkEvents,
    DeviceFileEvents,
    CommonSecurityLog,
    Unknown,
}

/// Parser for Azure Sentinel (Microsoft Sentinel) log exports.
///
/// Supports the following Sentinel tables:
///
/// | Table                  | Triples Produced                                           |
/// |------------------------|------------------------------------------------------------|
/// | SecurityEvent (4624/25)| User -[Auth]-> Host                                        |
/// | SecurityEvent (4688)   | User -[Execute]-> Process, Parent -[Execute]-> Child       |
/// | SecurityEvent (4663)   | Process -[Read]-> File                                     |
/// | SigninLogs             | User -[Auth]-> IP                                          |
/// | DeviceProcessEvents    | User -[Execute]-> Process, Parent -[Execute]-> Child       |
/// | DeviceNetworkEvents    | Host -[Connect]-> IP                                       |
/// | DeviceFileEvents       | Process -[Write/Read]-> File                               |
/// | CommonSecurityLog      | IP(src) -[Connect]-> IP(dst)                               |
///
/// # Expected JSON Format
///
/// The parser accepts either:
/// - A JSON array of event objects: `[{...}, {...}]`
/// - Newline-delimited JSON (NDJSON): one event per line
///
/// Each record is auto-classified by its `Type` field (preferred) or by
/// heuristic field presence (fallback).
///
/// Timestamps are parsed from `TimeGenerated` or `Timestamp` fields using
/// ISO 8601 format.
pub struct SentinelJsonParser;

impl SentinelJsonParser {
    /// Parses an ISO 8601 timestamp into Unix epoch seconds.
    ///
    /// Handles: `2024-01-15T14:30:00Z`, `2024-01-15T14:30:00.1234567Z`,
    /// and `2024-01-15T14:30:00+00:00`.
    fn parse_timestamp(ts: &str) -> Option<i64> {
        let trimmed = ts.trim();
        // Try RFC 3339 / ISO 8601 with timezone
        if let Ok(dt) = DateTime::parse_from_rfc3339(trimmed) {
            return Some(dt.timestamp());
        }
        // Try without fractional seconds but with Z
        if let Ok(dt) = NaiveDateTime::parse_from_str(
            trimmed.trim_end_matches('Z'),
            "%Y-%m-%dT%H:%M:%S",
        ) {
            return Some(dt.and_utc().timestamp());
        }
        // Try with fractional seconds (chrono %.f)
        if let Ok(dt) = NaiveDateTime::parse_from_str(
            trimmed.trim_end_matches('Z'),
            "%Y-%m-%dT%H:%M:%S%.f",
        ) {
            return Some(dt.and_utc().timestamp());
        }
        None
    }

    /// Extracts a non-empty string from a JSON value.
    fn extract_str<'a>(event: &'a Value, key: &str) -> Option<&'a str> {
        event
            .get(key)
            .and_then(|v| v.as_str())
            .filter(|s| !s.is_empty())
    }

    /// Extracts EventID as u64 (Sentinel SecurityEvent uses integer or string).
    fn extract_event_id(event: &Value) -> Option<u64> {
        event.get("EventID").and_then(|v| {
            v.as_u64().or_else(|| v.as_str().and_then(|s| s.parse().ok()))
        })
    }

    /// Extracts timestamp from either `TimeGenerated` or `Timestamp` fields.
    fn extract_timestamp(event: &Value) -> i64 {
        Self::extract_str(event, "TimeGenerated")
            .or_else(|| Self::extract_str(event, "Timestamp"))
            .and_then(Self::parse_timestamp)
            .unwrap_or(0)
    }

    /// Auto-detects the Sentinel table type for a record.
    ///
    /// Priority:
    /// 1. Explicit `Type` field (always present in real Sentinel exports)
    /// 2. Heuristic field presence (fallback for manual/test data)
    fn detect_table(event: &Value) -> SentinelTable {
        // Priority 1: Explicit Type field
        if let Some(type_val) = Self::extract_str(event, "Type") {
            return match type_val {
                "SecurityEvent" => SentinelTable::SecurityEvent,
                "SigninLogs" => SentinelTable::SigninLogs,
                "DeviceProcessEvents" => SentinelTable::DeviceProcessEvents,
                "DeviceNetworkEvents" => SentinelTable::DeviceNetworkEvents,
                "DeviceFileEvents" => SentinelTable::DeviceFileEvents,
                "CommonSecurityLog" => SentinelTable::CommonSecurityLog,
                _ => SentinelTable::Unknown,
            };
        }

        // Priority 2: Heuristic detection by field presence
        if event.get("EventID").is_some() && event.get("Computer").is_some() {
            return SentinelTable::SecurityEvent;
        }
        if event.get("UserPrincipalName").is_some()
            || event.get("AppDisplayName").is_some()
            || event.get("IPAddress").is_some() && event.get("ResultType").is_some()
        {
            return SentinelTable::SigninLogs;
        }
        if event.get("InitiatingProcessFileName").is_some()
            && event.get("FileName").is_some()
            && event.get("FolderPath").is_some()
        {
            // Check if it has ActionType that looks like file events
            if let Some(action) = Self::extract_str(event, "ActionType") {
                if action.contains("File") {
                    return SentinelTable::DeviceFileEvents;
                }
            }
            return SentinelTable::DeviceProcessEvents;
        }
        if event.get("RemoteIP").is_some() || event.get("RemotePort").is_some() {
            return SentinelTable::DeviceNetworkEvents;
        }
        if event.get("SourceIP").is_some() && event.get("DestinationIP").is_some() {
            return SentinelTable::CommonSecurityLog;
        }

        SentinelTable::Unknown
    }

    /// Dispatches a single event to the appropriate table parser.
    fn parse_event(event: &Value) -> Vec<ParsedTriple> {
        match Self::detect_table(event) {
            SentinelTable::SecurityEvent => Self::parse_security_event(event),
            SentinelTable::SigninLogs => Self::parse_signin_logs(event),
            SentinelTable::DeviceProcessEvents => Self::parse_device_process_events(event),
            SentinelTable::DeviceNetworkEvents => Self::parse_device_network_events(event),
            SentinelTable::DeviceFileEvents => Self::parse_device_file_events(event),
            SentinelTable::CommonSecurityLog => Self::parse_common_security_log(event),
            SentinelTable::Unknown => Vec::new(),
        }
    }

    // ── Table Parsers ──

    /// SecurityEvent table (Windows Security Event Log via Sentinel).
    ///
    /// - EventID 4624/4625: User -[Auth]-> Host (with IP in metadata)
    /// - EventID 4688: User -[Execute]-> Process + Parent -[Execute]-> Child
    /// - EventID 4663: Process -[Read]-> File
    fn parse_security_event(event: &Value) -> Vec<ParsedTriple> {
        let event_id = match Self::extract_event_id(event) {
            Some(id) => id,
            None => return Vec::new(),
        };
        let timestamp = Self::extract_timestamp(event);

        match event_id {
            4624 | 4625 => Self::parse_security_event_auth(event, timestamp, event_id),
            4688 => Self::parse_security_event_process(event, timestamp),
            4663 => Self::parse_security_event_file_access(event, timestamp),
            _ => Vec::new(),
        }
    }

    /// SecurityEvent 4624 (logon success) / 4625 (logon failure).
    /// Produces: User -[Auth]-> Host
    fn parse_security_event_auth(event: &Value, timestamp: i64, event_id: u64) -> Vec<ParsedTriple> {
        let account = Self::extract_str(event, "TargetUserName")
            .or_else(|| Self::extract_str(event, "Account"));
        let computer = Self::extract_str(event, "Computer");

        let (account, computer) = match (account, computer) {
            (Some(a), Some(c)) => (a, c),
            _ => return Vec::new(),
        };

        let user = Entity::new(account, EntityType::User);
        let mut host = Entity::new(computer, EntityType::Host);

        if let Some(ip) = Self::extract_str(event, "IpAddress") {
            host.metadata.insert("source_ip".into(), ip.into());
        }

        let status = if event_id == 4624 { "Success" } else { "Failure" };
        let mut rel = Relation::new(&user.id, &host.id, RelationType::Auth, timestamp);
        rel.metadata.insert("event_id".into(), event_id.to_string());
        rel.metadata.insert("status".into(), status.into());

        if let Some(logon_type) = event.get("LogonType").and_then(|v| {
            v.as_u64().map(|n| n.to_string()).or_else(|| v.as_str().map(|s| s.to_string()))
        }) {
            rel.metadata.insert("logon_type".into(), logon_type);
        }

        vec![(user, rel, host)]
    }

    /// SecurityEvent 4688 (process creation).
    /// Produces: User -[Execute]-> Process + Parent -[Execute]-> Child
    fn parse_security_event_process(event: &Value, timestamp: i64) -> Vec<ParsedTriple> {
        let mut triples = Vec::new();

        let process_name = match Self::extract_str(event, "NewProcessName")
            .or_else(|| Self::extract_str(event, "Process"))
        {
            Some(v) => v,
            None => return triples,
        };

        let mut child = Entity::new(process_name, EntityType::Process);
        if let Some(pid) = event.get("NewProcessId").and_then(|v| {
            v.as_u64().map(|n| n.to_string()).or_else(|| v.as_str().map(|s| s.to_string()))
        }) {
            child.metadata.insert("pid".into(), pid);
        }
        if let Some(cmdline) = Self::extract_str(event, "CommandLine") {
            child.metadata.insert("cmdline".into(), cmdline.into());
        }
        if let Some(computer) = Self::extract_str(event, "Computer") {
            child.metadata.insert("computer".into(), computer.into());
        }

        // Triple 1: User -[Execute]-> Process
        if let Some(account) = Self::extract_str(event, "SubjectUserName")
            .or_else(|| Self::extract_str(event, "Account"))
        {
            let user = Entity::new(account, EntityType::User);
            let rel = Relation::new(&user.id, &child.id, RelationType::Execute, timestamp);
            triples.push((user, rel, child.clone()));
        }

        // Triple 2: Parent -[Execute]-> Child
        if let Some(parent_name) = Self::extract_str(event, "ParentProcessName") {
            let parent = Entity::new(parent_name, EntityType::Process);
            let rel = Relation::new(&parent.id, &child.id, RelationType::Execute, timestamp);
            triples.push((parent, rel, child));
        }

        triples
    }

    /// SecurityEvent 4663 (object access / file read).
    /// Produces: Process -[Read]-> File
    fn parse_security_event_file_access(event: &Value, timestamp: i64) -> Vec<ParsedTriple> {
        let process = match Self::extract_str(event, "ProcessName") {
            Some(v) => v,
            None => return Vec::new(),
        };
        let object = match Self::extract_str(event, "ObjectName") {
            Some(v) => v,
            None => return Vec::new(),
        };

        let src = Entity::new(process, EntityType::Process);
        let dst = Entity::new(object, EntityType::File);
        let rel = Relation::new(&src.id, &dst.id, RelationType::Read, timestamp);

        vec![(src, rel, dst)]
    }

    /// SigninLogs table (Azure AD sign-in logs).
    /// Produces: User -[Auth]-> IP
    fn parse_signin_logs(event: &Value) -> Vec<ParsedTriple> {
        let timestamp = Self::extract_timestamp(event);

        let user = match Self::extract_str(event, "UserPrincipalName")
            .or_else(|| Self::extract_str(event, "UserDisplayName"))
        {
            Some(v) => v,
            None => return Vec::new(),
        };
        let ip = match Self::extract_str(event, "IPAddress") {
            Some(v) => v,
            None => return Vec::new(),
        };

        let user_entity = Entity::new(user, EntityType::User);
        let mut ip_entity = Entity::new(ip, EntityType::IP);

        if let Some(app) = Self::extract_str(event, "AppDisplayName") {
            ip_entity.metadata.insert("app".into(), app.into());
        }
        if let Some(loc) = Self::extract_str(event, "LocationDetails") {
            ip_entity.metadata.insert("location".into(), loc.into());
        }
        // Also check Location as a simpler field
        if let Some(loc) = Self::extract_str(event, "Location") {
            ip_entity.metadata.insert("location".into(), loc.into());
        }

        let mut rel = Relation::new(&user_entity.id, &ip_entity.id, RelationType::Auth, timestamp);

        if let Some(status) = event.get("ResultType").and_then(|v| {
            v.as_u64().map(|n| n.to_string()).or_else(|| v.as_str().map(|s| s.to_string()))
        }) {
            let status_str = if status == "0" { "Success" } else { "Failure" };
            rel.metadata.insert("status".into(), status_str.into());
        }
        if let Some(app) = Self::extract_str(event, "AppDisplayName") {
            rel.metadata.insert("app".into(), app.into());
        }

        vec![(user_entity, rel, ip_entity)]
    }

    /// DeviceProcessEvents table (MDE process events).
    /// Produces: User -[Execute]-> Process + Parent -[Execute]-> Child
    fn parse_device_process_events(event: &Value) -> Vec<ParsedTriple> {
        let timestamp = Self::extract_timestamp(event);
        let mut triples = Vec::new();

        let file_name = match Self::extract_str(event, "FileName") {
            Some(v) => v,
            None => return triples,
        };

        // Build full path if available
        let process_id = Self::extract_str(event, "FolderPath").unwrap_or(file_name);

        let mut child = Entity::new(process_id, EntityType::Process);
        if let Some(cmdline) = Self::extract_str(event, "ProcessCommandLine") {
            child.metadata.insert("cmdline".into(), cmdline.into());
        }
        if let Some(device) = Self::extract_str(event, "DeviceName") {
            child.metadata.insert("device".into(), device.into());
        }
        if let Some(sha256) = Self::extract_str(event, "SHA256") {
            child.metadata.insert("sha256".into(), sha256.into());
        }

        // Triple 1: User -[Execute]-> Process
        if let Some(account) = Self::extract_str(event, "AccountName")
            .or_else(|| Self::extract_str(event, "InitiatingProcessAccountName"))
        {
            let user = Entity::new(account, EntityType::User);
            let rel = Relation::new(&user.id, &child.id, RelationType::Execute, timestamp);
            triples.push((user, rel, child.clone()));
        }

        // Triple 2: Parent -[Execute]-> Child
        if let Some(parent) = Self::extract_str(event, "InitiatingProcessFileName") {
            let parent_path = Self::extract_str(event, "InitiatingProcessFolderPath")
                .unwrap_or(parent);
            let parent_entity = Entity::new(parent_path, EntityType::Process);
            let rel = Relation::new(&parent_entity.id, &child.id, RelationType::Execute, timestamp);
            triples.push((parent_entity, rel, child));
        }

        triples
    }

    /// DeviceNetworkEvents table (MDE network events).
    /// Produces: Host -[Connect]-> IP
    fn parse_device_network_events(event: &Value) -> Vec<ParsedTriple> {
        let timestamp = Self::extract_timestamp(event);

        let device = match Self::extract_str(event, "DeviceName") {
            Some(v) => v,
            None => return Vec::new(),
        };
        let remote_ip = match Self::extract_str(event, "RemoteIP") {
            Some(v) => v,
            None => return Vec::new(),
        };

        let source = Entity::new(device, EntityType::Host);
        let mut dest = Entity::new(remote_ip, EntityType::IP);

        if let Some(port) = event.get("RemotePort").and_then(|v| {
            v.as_u64().map(|n| n.to_string()).or_else(|| v.as_str().map(|s| s.to_string()))
        }) {
            dest.metadata.insert("remote_port".into(), port);
        }
        if let Some(url) = Self::extract_str(event, "RemoteUrl") {
            dest.metadata.insert("url".into(), url.into());
        }
        if let Some(proto) = Self::extract_str(event, "Protocol") {
            dest.metadata.insert("protocol".into(), proto.into());
        }

        let mut rel = Relation::new(&source.id, &dest.id, RelationType::Connect, timestamp);
        if let Some(action) = Self::extract_str(event, "ActionType") {
            rel.metadata.insert("action".into(), action.into());
        }
        if let Some(local_port) = event.get("LocalPort").and_then(|v| {
            v.as_u64().map(|n| n.to_string()).or_else(|| v.as_str().map(|s| s.to_string()))
        }) {
            rel.metadata.insert("local_port".into(), local_port);
        }

        vec![(source, rel, dest)]
    }

    /// DeviceFileEvents table (MDE file events).
    /// Produces: Process -[Write]-> File (for FileCreated/FileModified)
    ///           Process -[Read]-> File  (for FileRead)
    fn parse_device_file_events(event: &Value) -> Vec<ParsedTriple> {
        let timestamp = Self::extract_timestamp(event);

        let process = match Self::extract_str(event, "InitiatingProcessFileName") {
            Some(v) => v,
            None => return Vec::new(),
        };
        let file_name = match Self::extract_str(event, "FileName") {
            Some(v) => v,
            None => return Vec::new(),
        };

        let process_path = Self::extract_str(event, "InitiatingProcessFolderPath")
            .unwrap_or(process);
        let file_path = Self::extract_str(event, "FolderPath").unwrap_or(file_name);

        let src = Entity::new(process_path, EntityType::Process);
        let mut dst = Entity::new(file_path, EntityType::File);

        if let Some(sha256) = Self::extract_str(event, "SHA256") {
            dst.metadata.insert("sha256".into(), sha256.into());
        }

        // Determine relation type based on ActionType
        let rel_type = match Self::extract_str(event, "ActionType") {
            Some(action) if action.contains("Read") => RelationType::Read,
            _ => RelationType::Write, // Default: FileCreated, FileModified, etc.
        };

        let rel = Relation::new(&src.id, &dst.id, rel_type, timestamp);
        vec![(src, rel, dst)]
    }

    /// CommonSecurityLog table (CEF/syslog from firewalls, proxies, etc.).
    /// Produces: IP(src) -[Connect]-> IP(dst)
    fn parse_common_security_log(event: &Value) -> Vec<ParsedTriple> {
        let timestamp = Self::extract_timestamp(event);

        let src_ip = match Self::extract_str(event, "SourceIP") {
            Some(v) => v,
            None => return Vec::new(),
        };
        let dst_ip = match Self::extract_str(event, "DestinationIP") {
            Some(v) => v,
            None => return Vec::new(),
        };

        let source = Entity::new(src_ip, EntityType::IP);
        let mut dest = Entity::new(dst_ip, EntityType::IP);

        if let Some(port) = event.get("DestinationPort").and_then(|v| {
            v.as_u64().map(|n| n.to_string()).or_else(|| v.as_str().map(|s| s.to_string()))
        }) {
            dest.metadata.insert("dest_port".into(), port);
        }

        let mut rel = Relation::new(&source.id, &dest.id, RelationType::Connect, timestamp);
        if let Some(vendor) = Self::extract_str(event, "DeviceVendor") {
            rel.metadata.insert("vendor".into(), vendor.into());
        }
        if let Some(action) = Self::extract_str(event, "DeviceAction")
            .or_else(|| Self::extract_str(event, "Activity"))
        {
            rel.metadata.insert("action".into(), action.into());
        }
        if let Some(proto) = Self::extract_str(event, "Protocol") {
            rel.metadata.insert("protocol".into(), proto.into());
        }

        vec![(source, rel, dest)]
    }
}

impl LogParser for SentinelJsonParser {
    fn parse(&self, data: &str) -> Vec<ParsedTriple> {
        let trimmed = data.trim();

        // Try JSON array first (simd-json for speed)
        if trimmed.starts_with('[') {
            let mut buf = trimmed.as_bytes().to_vec();
            if let Ok(events) = simd_json::serde::from_slice::<Vec<Value>>(&mut buf) {
                return events
                    .par_iter()
                    .flat_map(|event| Self::parse_event(event))
                    .collect();
            }
        }

        // Fall back to NDJSON (one JSON object per line)
        let lines: Vec<&str> = trimmed.lines().filter(|l| !l.trim().is_empty()).collect();
        lines
            .par_iter()
            .filter_map(|line| {
                let mut buf = line.as_bytes().to_vec();
                simd_json::serde::from_slice::<Value>(&mut buf).ok()
            })
            .flat_map(|event| Self::parse_event(&event))
            .collect()
    }
}
