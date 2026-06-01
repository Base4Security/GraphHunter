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
        if let Ok(dt) =
            NaiveDateTime::parse_from_str(trimmed.trim_end_matches('Z'), "%Y-%m-%dT%H:%M:%S")
        {
            return Some(dt.and_utc().timestamp());
        }
        // Try with fractional seconds (chrono %.f)
        if let Ok(dt) =
            NaiveDateTime::parse_from_str(trimmed.trim_end_matches('Z'), "%Y-%m-%dT%H:%M:%S%.f")
        {
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
            v.as_u64()
                .or_else(|| v.as_str().and_then(|s| s.parse().ok()))
        })
    }

    /// Extracts timestamp from either `TimeGenerated` or `Timestamp` fields.
    ///
    /// Returns `None` when no valid timestamp is found, so callers can skip
    /// events rather than silently producing edges with Unix-epoch-zero.
    fn extract_timestamp(event: &Value) -> Option<i64> {
        let raw = Self::extract_str(event, "TimeGenerated")
            .or_else(|| Self::extract_str(event, "Timestamp"));
        match raw {
            Some(ts) => match Self::parse_timestamp(ts) {
                Some(epoch) => Some(epoch),
                None => {
                    eprintln!("Warning: failed to parse Sentinel timestamp: {:?}", ts);
                    None
                }
            },
            None => {
                eprintln!("Warning: Sentinel event has no TimeGenerated or Timestamp field");
                None
            }
        }
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
            eprintln!(
                "Warning: table type detected via heuristic (fields: EventID, Computer), not explicit Type field"
            );
            return SentinelTable::SecurityEvent;
        }
        if event.get("UserPrincipalName").is_some()
            || event.get("AppDisplayName").is_some()
            || event.get("IPAddress").is_some() && event.get("ResultType").is_some()
        {
            eprintln!(
                "Warning: table type detected via heuristic (fields: UserPrincipalName/AppDisplayName/IPAddress+ResultType), not explicit Type field"
            );
            return SentinelTable::SigninLogs;
        }
        if event.get("InitiatingProcessFileName").is_some()
            && event.get("FileName").is_some()
            && event.get("FolderPath").is_some()
        {
            // Check if it has ActionType that looks like file events
            if let Some(action) = Self::extract_str(event, "ActionType") {
                if action.contains("File") {
                    eprintln!(
                        "Warning: table type detected via heuristic (fields: InitiatingProcessFileName, FileName, FolderPath, ActionType={action}), not explicit Type field"
                    );
                    return SentinelTable::DeviceFileEvents;
                }
            }
            eprintln!(
                "Warning: table type detected via heuristic (fields: InitiatingProcessFileName, FileName, FolderPath), not explicit Type field"
            );
            return SentinelTable::DeviceProcessEvents;
        }
        if event.get("RemoteIP").is_some() || event.get("RemotePort").is_some() {
            eprintln!(
                "Warning: table type detected via heuristic (fields: RemoteIP/RemotePort), not explicit Type field"
            );
            return SentinelTable::DeviceNetworkEvents;
        }
        if event.get("SourceIP").is_some() && event.get("DestinationIP").is_some() {
            eprintln!(
                "Warning: table type detected via heuristic (fields: SourceIP, DestinationIP), not explicit Type field"
            );
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
        let timestamp = match Self::extract_timestamp(event) {
            Some(ts) => ts,
            None => return Vec::new(),
        };

        match event_id {
            4624 | 4625 => Self::parse_security_event_auth(event, timestamp, event_id),
            4688 => Self::parse_security_event_process(event, timestamp),
            4663 => Self::parse_security_event_file_access(event, timestamp),
            _ => Vec::new(),
        }
    }

    /// SecurityEvent 4624 (logon success) / 4625 (logon failure).
    /// Produces: User -[Auth]-> Host
    fn parse_security_event_auth(
        event: &Value,
        timestamp: i64,
        event_id: u64,
    ) -> Vec<ParsedTriple> {
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

        let status = if event_id == 4624 {
            "Success"
        } else {
            "Failure"
        };
        let mut rel = Relation::new(&user.id, &host.id, RelationType::Auth, timestamp);
        rel.metadata.insert("event_id".into(), event_id.to_string());
        rel.metadata.insert("status".into(), status.into());

        if let Some(logon_type) = event.get("LogonType").and_then(|v| {
            v.as_u64()
                .map(|n| n.to_string())
                .or_else(|| v.as_str().map(|s| s.to_string()))
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
            v.as_u64()
                .map(|n| n.to_string())
                .or_else(|| v.as_str().map(|s| s.to_string()))
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
        let timestamp = match Self::extract_timestamp(event) {
            Some(ts) => ts,
            None => return Vec::new(),
        };

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

        let mut rel = Relation::new(
            &user_entity.id,
            &ip_entity.id,
            RelationType::Auth,
            timestamp,
        );

        if let Some(status) = event.get("ResultType").and_then(|v| {
            v.as_u64()
                .map(|n| n.to_string())
                .or_else(|| v.as_str().map(|s| s.to_string()))
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
        let timestamp = match Self::extract_timestamp(event) {
            Some(ts) => ts,
            None => return Vec::new(),
        };
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
            let parent_path =
                Self::extract_str(event, "InitiatingProcessFolderPath").unwrap_or(parent);
            let parent_entity = Entity::new(parent_path, EntityType::Process);
            let rel = Relation::new(
                &parent_entity.id,
                &child.id,
                RelationType::Execute,
                timestamp,
            );
            triples.push((parent_entity, rel, child));
        }

        triples
    }

    /// DeviceNetworkEvents table (MDE network events).
    /// Produces: Host -[Connect]-> IP
    fn parse_device_network_events(event: &Value) -> Vec<ParsedTriple> {
        let timestamp = match Self::extract_timestamp(event) {
            Some(ts) => ts,
            None => return Vec::new(),
        };

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
            v.as_u64()
                .map(|n| n.to_string())
                .or_else(|| v.as_str().map(|s| s.to_string()))
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
            v.as_u64()
                .map(|n| n.to_string())
                .or_else(|| v.as_str().map(|s| s.to_string()))
        }) {
            rel.metadata.insert("local_port".into(), local_port);
        }

        vec![(source, rel, dest)]
    }

    /// DeviceFileEvents table (MDE file events).
    /// Produces: Process -[Write]-> File (for FileCreated/FileModified)
    ///           Process -[Read]-> File  (for FileRead)
    fn parse_device_file_events(event: &Value) -> Vec<ParsedTriple> {
        let timestamp = match Self::extract_timestamp(event) {
            Some(ts) => ts,
            None => return Vec::new(),
        };

        let process = match Self::extract_str(event, "InitiatingProcessFileName") {
            Some(v) => v,
            None => return Vec::new(),
        };
        let file_name = match Self::extract_str(event, "FileName") {
            Some(v) => v,
            None => return Vec::new(),
        };

        let process_path =
            Self::extract_str(event, "InitiatingProcessFolderPath").unwrap_or(process);
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
        let timestamp = match Self::extract_timestamp(event) {
            Some(ts) => ts,
            None => return Vec::new(),
        };

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
            v.as_u64()
                .map(|n| n.to_string())
                .or_else(|| v.as_str().map(|s| s.to_string()))
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

impl SentinelJsonParser {
    /// Raw-event dispatch — mirrors `parse_event` but emits
    /// `RawIngestEvent` directly without going through the
    /// `(Entity, Relation, Entity)` tuple.
    fn parse_event_raw(event: &Value) -> Vec<crate::parser::RawIngestEvent> {
        match Self::detect_table(event) {
            SentinelTable::SecurityEvent => Self::parse_security_event_raw(event),
            SentinelTable::SigninLogs => Self::parse_signin_logs_raw(event),
            SentinelTable::DeviceProcessEvents => Self::parse_device_process_events_raw(event),
            SentinelTable::DeviceNetworkEvents => Self::parse_device_network_events_raw(event),
            SentinelTable::DeviceFileEvents => Self::parse_device_file_events_raw(event),
            SentinelTable::CommonSecurityLog => Self::parse_common_security_log_raw(event),
            SentinelTable::Unknown => Vec::new(),
        }
    }

    fn parse_security_event_raw(event: &Value) -> Vec<crate::parser::RawIngestEvent> {
        let event_id = match Self::extract_event_id(event) {
            Some(id) => id,
            None => return Vec::new(),
        };
        let timestamp = match Self::extract_timestamp(event) {
            Some(ts) => ts,
            None => return Vec::new(),
        };
        match event_id {
            4624 | 4625 => Self::parse_security_event_auth_raw(event, timestamp, event_id),
            4688 => Self::parse_security_event_process_raw(event, timestamp),
            4663 => Self::parse_security_event_file_access_raw(event, timestamp),
            _ => Vec::new(),
        }
    }

    fn parse_security_event_auth_raw(
        event: &Value,
        timestamp: i64,
        event_id: u64,
    ) -> Vec<crate::parser::RawIngestEvent> {
        use crate::parser::RawIngestEvent;
        use std::collections::HashMap;
        let account = Self::extract_str(event, "TargetUserName")
            .or_else(|| Self::extract_str(event, "Account"));
        let computer = Self::extract_str(event, "Computer");
        let (account, computer) = match (account, computer) {
            (Some(a), Some(c)) => (a, c),
            _ => return Vec::new(),
        };
        let mut host_meta: HashMap<String, String> = HashMap::new();
        if let Some(ip) = Self::extract_str(event, "IpAddress") {
            host_meta.insert("source_ip".into(), ip.into());
        }
        let status = if event_id == 4624 { "Success" } else { "Failure" };
        let mut rel_meta: HashMap<String, String> = HashMap::new();
        rel_meta.insert("event_id".into(), event_id.to_string());
        rel_meta.insert("status".into(), status.into());
        if let Some(logon_type) = event.get("LogonType").and_then(|v| {
            v.as_u64()
                .map(|n| n.to_string())
                .or_else(|| v.as_str().map(|s| s.to_string()))
        }) {
            rel_meta.insert("logon_type".into(), logon_type);
        }
        vec![RawIngestEvent {
            src_id: account.into(),
            src_type: EntityType::User,
            src_metadata: HashMap::new(),
            dst_id: computer.into(),
            dst_type: EntityType::Host,
            dst_metadata: host_meta,
            rel_type: RelationType::Auth,
            rel_metadata: rel_meta,
            timestamp,
        }]
    }

    fn parse_security_event_process_raw(
        event: &Value,
        timestamp: i64,
    ) -> Vec<crate::parser::RawIngestEvent> {
        use crate::parser::RawIngestEvent;
        use std::collections::HashMap;
        let process_name = match Self::extract_str(event, "NewProcessName")
            .or_else(|| Self::extract_str(event, "Process"))
        {
            Some(v) => v,
            None => return Vec::new(),
        };
        let mut child_meta: HashMap<String, String> = HashMap::new();
        if let Some(pid) = event.get("NewProcessId").and_then(|v| {
            v.as_u64()
                .map(|n| n.to_string())
                .or_else(|| v.as_str().map(|s| s.to_string()))
        }) {
            child_meta.insert("pid".into(), pid);
        }
        if let Some(cmdline) = Self::extract_str(event, "CommandLine") {
            child_meta.insert("cmdline".into(), cmdline.into());
        }
        if let Some(computer) = Self::extract_str(event, "Computer") {
            child_meta.insert("computer".into(), computer.into());
        }

        let mut events = Vec::with_capacity(2);
        let mut child_meta_consumed = false;
        if let Some(account) = Self::extract_str(event, "SubjectUserName")
            .or_else(|| Self::extract_str(event, "Account"))
        {
            let dst_meta = std::mem::take(&mut child_meta);
            child_meta_consumed = true;
            events.push(RawIngestEvent {
                src_id: account.into(),
                src_type: EntityType::User,
                src_metadata: HashMap::new(),
                dst_id: process_name.into(),
                dst_type: EntityType::Process,
                dst_metadata: dst_meta,
                rel_type: RelationType::Execute,
                rel_metadata: HashMap::new(),
                timestamp,
            });
        }
        if let Some(parent_name) = Self::extract_str(event, "ParentProcessName") {
            let dst_meta = if child_meta_consumed {
                HashMap::new()
            } else {
                std::mem::take(&mut child_meta)
            };
            events.push(RawIngestEvent {
                src_id: parent_name.into(),
                src_type: EntityType::Process,
                src_metadata: HashMap::new(),
                dst_id: process_name.into(),
                dst_type: EntityType::Process,
                dst_metadata: dst_meta,
                rel_type: RelationType::Execute,
                rel_metadata: HashMap::new(),
                timestamp,
            });
        }
        events
    }

    fn parse_security_event_file_access_raw(
        event: &Value,
        timestamp: i64,
    ) -> Vec<crate::parser::RawIngestEvent> {
        use crate::parser::RawIngestEvent;
        use std::collections::HashMap;
        let process = match Self::extract_str(event, "ProcessName") {
            Some(v) => v,
            None => return Vec::new(),
        };
        let object = match Self::extract_str(event, "ObjectName") {
            Some(v) => v,
            None => return Vec::new(),
        };
        vec![RawIngestEvent {
            src_id: process.into(),
            src_type: EntityType::Process,
            src_metadata: HashMap::new(),
            dst_id: object.into(),
            dst_type: EntityType::File,
            dst_metadata: HashMap::new(),
            rel_type: RelationType::Read,
            rel_metadata: HashMap::new(),
            timestamp,
        }]
    }

    fn parse_signin_logs_raw(event: &Value) -> Vec<crate::parser::RawIngestEvent> {
        use crate::parser::RawIngestEvent;
        use std::collections::HashMap;
        let timestamp = match Self::extract_timestamp(event) {
            Some(ts) => ts,
            None => return Vec::new(),
        };
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
        let mut ip_meta: HashMap<String, String> = HashMap::new();
        if let Some(app) = Self::extract_str(event, "AppDisplayName") {
            ip_meta.insert("app".into(), app.into());
        }
        if let Some(loc) = Self::extract_str(event, "LocationDetails") {
            ip_meta.insert("location".into(), loc.into());
        }
        if let Some(loc) = Self::extract_str(event, "Location") {
            ip_meta.insert("location".into(), loc.into());
        }
        let mut rel_meta: HashMap<String, String> = HashMap::new();
        if let Some(status) = event.get("ResultType").and_then(|v| {
            v.as_u64()
                .map(|n| n.to_string())
                .or_else(|| v.as_str().map(|s| s.to_string()))
        }) {
            let status_str = if status == "0" { "Success" } else { "Failure" };
            rel_meta.insert("status".into(), status_str.into());
        }
        if let Some(app) = Self::extract_str(event, "AppDisplayName") {
            rel_meta.insert("app".into(), app.into());
        }
        vec![RawIngestEvent {
            src_id: user.into(),
            src_type: EntityType::User,
            src_metadata: HashMap::new(),
            dst_id: ip.into(),
            dst_type: EntityType::IP,
            dst_metadata: ip_meta,
            rel_type: RelationType::Auth,
            rel_metadata: rel_meta,
            timestamp,
        }]
    }

    fn parse_device_process_events_raw(event: &Value) -> Vec<crate::parser::RawIngestEvent> {
        use crate::parser::RawIngestEvent;
        use std::collections::HashMap;
        let timestamp = match Self::extract_timestamp(event) {
            Some(ts) => ts,
            None => return Vec::new(),
        };
        let file_name = match Self::extract_str(event, "FileName") {
            Some(v) => v,
            None => return Vec::new(),
        };
        let process_id = Self::extract_str(event, "FolderPath").unwrap_or(file_name);

        let mut child_meta: HashMap<String, String> = HashMap::new();
        if let Some(cmdline) = Self::extract_str(event, "ProcessCommandLine") {
            child_meta.insert("cmdline".into(), cmdline.into());
        }
        if let Some(device) = Self::extract_str(event, "DeviceName") {
            child_meta.insert("device".into(), device.into());
        }
        if let Some(sha256) = Self::extract_str(event, "SHA256") {
            child_meta.insert("sha256".into(), sha256.into());
        }

        let mut events = Vec::with_capacity(2);
        let mut child_meta_consumed = false;
        if let Some(account) = Self::extract_str(event, "AccountName")
            .or_else(|| Self::extract_str(event, "InitiatingProcessAccountName"))
        {
            let dst_meta = std::mem::take(&mut child_meta);
            child_meta_consumed = true;
            events.push(RawIngestEvent {
                src_id: account.into(),
                src_type: EntityType::User,
                src_metadata: HashMap::new(),
                dst_id: process_id.into(),
                dst_type: EntityType::Process,
                dst_metadata: dst_meta,
                rel_type: RelationType::Execute,
                rel_metadata: HashMap::new(),
                timestamp,
            });
        }
        if let Some(parent) = Self::extract_str(event, "InitiatingProcessFileName") {
            let parent_path =
                Self::extract_str(event, "InitiatingProcessFolderPath").unwrap_or(parent);
            let dst_meta = if child_meta_consumed {
                HashMap::new()
            } else {
                std::mem::take(&mut child_meta)
            };
            events.push(RawIngestEvent {
                src_id: parent_path.into(),
                src_type: EntityType::Process,
                src_metadata: HashMap::new(),
                dst_id: process_id.into(),
                dst_type: EntityType::Process,
                dst_metadata: dst_meta,
                rel_type: RelationType::Execute,
                rel_metadata: HashMap::new(),
                timestamp,
            });
        }
        events
    }

    fn parse_device_network_events_raw(event: &Value) -> Vec<crate::parser::RawIngestEvent> {
        use crate::parser::RawIngestEvent;
        use std::collections::HashMap;
        let timestamp = match Self::extract_timestamp(event) {
            Some(ts) => ts,
            None => return Vec::new(),
        };
        let device = match Self::extract_str(event, "DeviceName") {
            Some(v) => v,
            None => return Vec::new(),
        };
        let remote_ip = match Self::extract_str(event, "RemoteIP") {
            Some(v) => v,
            None => return Vec::new(),
        };
        let mut dest_meta: HashMap<String, String> = HashMap::new();
        if let Some(port) = event.get("RemotePort").and_then(|v| {
            v.as_u64()
                .map(|n| n.to_string())
                .or_else(|| v.as_str().map(|s| s.to_string()))
        }) {
            dest_meta.insert("remote_port".into(), port);
        }
        if let Some(url) = Self::extract_str(event, "RemoteUrl") {
            dest_meta.insert("url".into(), url.into());
        }
        if let Some(proto) = Self::extract_str(event, "Protocol") {
            dest_meta.insert("protocol".into(), proto.into());
        }
        let mut rel_meta: HashMap<String, String> = HashMap::new();
        if let Some(action) = Self::extract_str(event, "ActionType") {
            rel_meta.insert("action".into(), action.into());
        }
        if let Some(local_port) = event.get("LocalPort").and_then(|v| {
            v.as_u64()
                .map(|n| n.to_string())
                .or_else(|| v.as_str().map(|s| s.to_string()))
        }) {
            rel_meta.insert("local_port".into(), local_port);
        }
        vec![RawIngestEvent {
            src_id: device.into(),
            src_type: EntityType::Host,
            src_metadata: HashMap::new(),
            dst_id: remote_ip.into(),
            dst_type: EntityType::IP,
            dst_metadata: dest_meta,
            rel_type: RelationType::Connect,
            rel_metadata: rel_meta,
            timestamp,
        }]
    }

    fn parse_device_file_events_raw(event: &Value) -> Vec<crate::parser::RawIngestEvent> {
        use crate::parser::RawIngestEvent;
        use std::collections::HashMap;
        let timestamp = match Self::extract_timestamp(event) {
            Some(ts) => ts,
            None => return Vec::new(),
        };
        let process = match Self::extract_str(event, "InitiatingProcessFileName") {
            Some(v) => v,
            None => return Vec::new(),
        };
        let file_name = match Self::extract_str(event, "FileName") {
            Some(v) => v,
            None => return Vec::new(),
        };
        let process_path =
            Self::extract_str(event, "InitiatingProcessFolderPath").unwrap_or(process);
        let file_path = Self::extract_str(event, "FolderPath").unwrap_or(file_name);
        let mut file_meta: HashMap<String, String> = HashMap::new();
        if let Some(sha256) = Self::extract_str(event, "SHA256") {
            file_meta.insert("sha256".into(), sha256.into());
        }
        let rel_type = match Self::extract_str(event, "ActionType") {
            Some(action) if action.contains("Read") => RelationType::Read,
            _ => RelationType::Write,
        };
        vec![RawIngestEvent {
            src_id: process_path.into(),
            src_type: EntityType::Process,
            src_metadata: HashMap::new(),
            dst_id: file_path.into(),
            dst_type: EntityType::File,
            dst_metadata: file_meta,
            rel_type,
            rel_metadata: HashMap::new(),
            timestamp,
        }]
    }

    fn parse_common_security_log_raw(event: &Value) -> Vec<crate::parser::RawIngestEvent> {
        use crate::parser::RawIngestEvent;
        use std::collections::HashMap;
        let timestamp = match Self::extract_timestamp(event) {
            Some(ts) => ts,
            None => return Vec::new(),
        };
        let src_ip = match Self::extract_str(event, "SourceIP") {
            Some(v) => v,
            None => return Vec::new(),
        };
        let dst_ip = match Self::extract_str(event, "DestinationIP") {
            Some(v) => v,
            None => return Vec::new(),
        };
        let mut dest_meta: HashMap<String, String> = HashMap::new();
        if let Some(port) = event.get("DestinationPort").and_then(|v| {
            v.as_u64()
                .map(|n| n.to_string())
                .or_else(|| v.as_str().map(|s| s.to_string()))
        }) {
            dest_meta.insert("dest_port".into(), port);
        }
        let mut rel_meta: HashMap<String, String> = HashMap::new();
        if let Some(vendor) = Self::extract_str(event, "DeviceVendor") {
            rel_meta.insert("vendor".into(), vendor.into());
        }
        if let Some(action) = Self::extract_str(event, "DeviceAction")
            .or_else(|| Self::extract_str(event, "Activity"))
        {
            rel_meta.insert("action".into(), action.into());
        }
        if let Some(proto) = Self::extract_str(event, "Protocol") {
            rel_meta.insert("protocol".into(), proto.into());
        }
        vec![RawIngestEvent {
            src_id: src_ip.into(),
            src_type: EntityType::IP,
            src_metadata: HashMap::new(),
            dst_id: dst_ip.into(),
            dst_type: EntityType::IP,
            dst_metadata: dest_meta,
            rel_type: RelationType::Connect,
            rel_metadata: rel_meta,
            timestamp,
        }]
    }

    /// Decodes the input into a `Vec<Value>` using the same JSON-array +
    /// NDJSON fallback logic `parse` uses, so stats and triples see the
    /// exact same row stream.
    fn collect_events(data: &str) -> Vec<Value> {
        use rayon::prelude::*;
        let trimmed = data.trim();
        if trimmed.starts_with('[') {
            let mut buf = trimmed.as_bytes().to_vec();
            if let Ok(events) = simd_json::serde::from_slice::<Vec<Value>>(&mut buf) {
                return events;
            }
        }
        trimmed
            .par_lines()
            .filter(|l| !l.trim().is_empty())
            .filter_map(|line| {
                let mut buf = line.as_bytes().to_vec();
                simd_json::serde::from_slice::<Value>(&mut buf).ok()
            })
            .collect()
    }
}

impl LogParser for SentinelJsonParser {
    fn parse(&self, data: &str) -> Vec<ParsedTriple> {
        use rayon::prelude::*;
        let trimmed = data.trim();

        if trimmed.starts_with('[') {
            let mut buf = trimmed.as_bytes().to_vec();
            if let Ok(events) = simd_json::serde::from_slice::<Vec<Value>>(&mut buf) {
                return events
                    .par_iter()
                    .flat_map(|event| Self::parse_event(event))
                    .collect();
            }
        }

        // NDJSON fast path: fuse line-parse and event-parse.
        trimmed
            .par_lines()
            .filter(|l| !l.trim().is_empty())
            .flat_map_iter(|line| {
                let mut buf = line.as_bytes().to_vec();
                let event = simd_json::serde::from_slice::<Value>(&mut buf).ok();
                event
                    .map(|e| Self::parse_event(&e))
                    .unwrap_or_default()
                    .into_iter()
            })
            .collect()
    }

    fn parse_with_stats(&self, data: &str) -> (Vec<ParsedTriple>, crate::parser::ParseStats) {
        let events = Self::collect_events(data);
        crate::generic::parse_events_with_stats(&events, |ev| Self::parse_event(ev))
    }

    /// Sentinel Result variant (RH-P1-012).
    ///
    /// Surfaces two classes of per-row failures the bare `parse` path used
    /// to swallow:
    /// 1. NDJSON line that fails `simd_json` decode — emits
    ///    `ParseError::Encoding`.
    /// 2. Decoded event that yields zero triples (no known schema fits) —
    ///    emits `ParseError::MalformedRow` with the same skip-reason text
    ///    that `parse_with_stats` already aggregates.
    ///
    /// Top-level JSON arrays fall back to the legacy `parse` path lifted
    /// into `Ok(_)` — they don't have a meaningful per-line failure model
    /// because the array decode is all-or-nothing.
    fn try_parse(&self, data: &str) -> Vec<Result<ParsedTriple, crate::parser::ParseError>> {
        let trimmed = data.trim();

        // Array-shaped JSON: all-or-nothing decode. If decode fails, surface
        // a single Encoding error; otherwise lift each emitted triple to Ok.
        if trimmed.starts_with('[') {
            let mut buf = trimmed.as_bytes().to_vec();
            return match simd_json::serde::from_slice::<Vec<Value>>(&mut buf) {
                Ok(events) => {
                    let mut out: Vec<Result<ParsedTriple, crate::parser::ParseError>> = Vec::new();
                    for (lineno, event) in events.iter().enumerate() {
                        let triples = Self::parse_event(event);
                        if triples.is_empty() {
                            out.push(Err(crate::parser::ParseError::MalformedRow {
                                line: lineno,
                                reason: crate::generic::classify_skip_reason(event).to_string(),
                            }));
                        } else {
                            for t in triples {
                                out.push(Ok(t));
                            }
                        }
                    }
                    out
                }
                Err(e) => vec![Err(crate::parser::ParseError::Encoding(format!(
                    "top-level JSON array decode failed: {}",
                    e
                )))],
            };
        }

        // NDJSON path: one line at a time. Surface both decode failures and
        // zero-triple events as Err so the DLQ sees both classes.
        let mut out: Vec<Result<ParsedTriple, crate::parser::ParseError>> = Vec::new();
        for (lineno, line) in trimmed.lines().enumerate() {
            if line.trim().is_empty() {
                continue;
            }
            let mut buf = line.as_bytes().to_vec();
            match simd_json::serde::from_slice::<Value>(&mut buf) {
                Ok(event) => {
                    let triples = Self::parse_event(&event);
                    if triples.is_empty() {
                        out.push(Err(crate::parser::ParseError::MalformedRow {
                            line: lineno,
                            reason: crate::generic::classify_skip_reason(&event).to_string(),
                        }));
                    } else {
                        for t in triples {
                            out.push(Ok(t));
                        }
                    }
                }
                Err(e) => {
                    out.push(Err(crate::parser::ParseError::Encoding(format!(
                        "NDJSON line {} decode failed: {}",
                        lineno, e
                    ))));
                }
            }
        }
        out
    }

    /// Efficient override of the default `parse_rows`: iterates pre-decoded
    /// `serde_json::Value` rows and dispatches to `parse_event` directly.
    ///
    /// This is the Phase 4 fix for the `normalize_response` double-parse
    /// in `graph_hunter_cli::siem::sentinel_streaming`. When the streaming
    /// ingest pipeline pre-decodes a Log Analytics / Advanced Hunting
    /// response into rows, it calls this method instead of rebuilding a
    /// JSON string and re-parsing it. Avoids a GB-scale allocation per
    /// poll at tera-scale.
    ///
    /// Uses the same `rayon::par_iter` fan-out as `parse()` so throughput
    /// is identical on large row sets.
    fn parse_rows(&self, rows: &[Value]) -> Vec<ParsedTriple> {
        rows.par_iter()
            .flat_map(|event| Self::parse_event(event))
            .collect()
    }

    /// Native raw-event override. Mirrors `parse()` but emits
    /// `RawIngestEvent` directly via `parse_event_raw`, skipping the
    /// `(Entity, Relation, Entity)` tuple allocation per triple.
    /// Each handler that emits multiple triples sharing a dst entity
    /// (security_event_process, device_process_events) applies the
    /// dst-metadata-skip-on-second-emission optimization, removing
    /// the legacy `child.clone()` HashMap deep-copy.
    fn parse_raw(&self, data: &str) -> Vec<crate::parser::RawIngestEvent> {
        use rayon::prelude::*;
        let trimmed = data.trim();

        if trimmed.starts_with('[') {
            let mut buf = trimmed.as_bytes().to_vec();
            if let Ok(events) = simd_json::serde::from_slice::<Vec<Value>>(&mut buf) {
                return events
                    .par_iter()
                    .flat_map(|event| Self::parse_event_raw(event))
                    .collect();
            }
        }

        trimmed
            .par_lines()
            .filter(|l| !l.trim().is_empty())
            .flat_map_iter(|line| {
                let mut buf = line.as_bytes().to_vec();
                let event = simd_json::serde::from_slice::<Value>(&mut buf).ok();
                event
                    .map(|e| Self::parse_event_raw(&e))
                    .unwrap_or_default()
                    .into_iter()
            })
            .collect()
    }

    /// Native raw-event-with-stats override. Mirrors `parse_raw` but
    /// also populates the minimal-stats subset:
    /// `rows_seen`, `rows_with_triples`, `rows_skipped`. Per-field
    /// occurrence + skip classification + drift are left empty since
    /// they require a per-event `Value` walk that the raw path
    /// avoids — see `LogParser::parse_raw_with_stats` docstring for
    /// the trade-off.
    fn parse_raw_with_stats(
        &self,
        data: &str,
    ) -> (Vec<crate::parser::RawIngestEvent>, crate::parser::ParseStats) {
        use rayon::prelude::*;
        let trimmed = data.trim();

        if trimmed.starts_with('[') {
            let (triples, stats) = self.parse_with_stats(data);
            let events: Vec<crate::parser::RawIngestEvent> = triples
                .into_iter()
                .map(crate::parser::RawIngestEvent::from_parsed_triple)
                .collect();
            return (events, stats);
        }

        let per_line: Vec<(Vec<crate::parser::RawIngestEvent>, bool)> = trimmed
            .par_lines()
            .filter(|l| !l.trim().is_empty())
            .map(|line| {
                let mut buf = line.as_bytes().to_vec();
                let event = simd_json::serde::from_slice::<Value>(&mut buf).ok();
                let events = event
                    .map(|e| Self::parse_event_raw(&e))
                    .unwrap_or_default();
                let produced = !events.is_empty();
                (events, produced)
            })
            .collect();

        let mut stats = crate::parser::ParseStats::default();
        stats.rows_seen = per_line.len();
        let mut all_events: Vec<crate::parser::RawIngestEvent> = Vec::new();
        for (events, produced) in per_line {
            if produced {
                stats.rows_with_triples += 1;
            } else {
                stats.rows_skipped += 1;
            }
            all_events.extend(events);
        }
        (all_events, stats)
    }
}

/// Inverse of the parser's column→entity mapping: for an entity type,
/// the `(Sentinel table name, columns)` pairs where a value of that type
/// can appear. Used to build entity-scoped hydration KQL.
///
/// MUST stay in sync with what the table parsers above read — the
/// `map_covers_every_parser_identifier_column` test enforces this.
/// TODO(owner): tune columns to your tenant (e.g. add `LocalIP` for IP,
/// `SHA256` for Process) — these lines define how complete hydration is.
pub fn sentinel_entity_targets(
    ty: &crate::types::EntityType,
) -> &'static [(&'static str, &'static [&'static str])] {
    use crate::types::EntityType;
    match ty {
        EntityType::User => &[
            ("SecurityEvent", &["TargetUserName", "Account", "SubjectUserName"]),
            ("SigninLogs", &["UserPrincipalName", "UserDisplayName"]),
            ("DeviceProcessEvents", &["AccountName", "InitiatingProcessAccountName"]),
        ],
        EntityType::IP => &[
            ("SigninLogs", &["IPAddress"]),
            ("DeviceNetworkEvents", &["RemoteIP"]),
            ("CommonSecurityLog", &["SourceIP", "DestinationIP"]),
        ],
        EntityType::Host => &[
            ("SecurityEvent", &["Computer"]),
            ("DeviceNetworkEvents", &["DeviceName"]),
        ],
        EntityType::Process => &[
            ("SecurityEvent", &["NewProcessName", "ParentProcessName", "ProcessName", "Process"]),
            ("DeviceProcessEvents", &["FolderPath", "FileName", "InitiatingProcessFolderPath"]),
            ("DeviceFileEvents", &["InitiatingProcessFolderPath", "InitiatingProcessFileName"]),
        ],
        EntityType::File => &[
            ("SecurityEvent", &["ObjectName"]),
            ("DeviceFileEvents", &["FolderPath", "FileName"]),
        ],
        _ => &[],
    }
}

/// Escapes a value for embedding in a KQL double-quoted string literal.
/// KQL string literals escape `"` and `\` with a backslash.
pub fn kql_escape(value: &str) -> String {
    value.replace('\\', "\\\\").replace('"', "\\\"")
}

/// Builds an entity-scoped hydration query for one Sentinel table.
/// Shape: `<table> | <time_filter> | where C1 == "v" or C2 == "v" | take N`.
/// `time_filter` is a pre-rendered clause beginning with `where`. `value`
/// is escaped internally.
///
/// # Precondition
/// `time_filter` is interpolated verbatim and must be a valid KQL clause
/// beginning with `where` (e.g. `"where TimeGenerated > ago(24h)"`).
/// `columns` must not be empty; passing an empty slice will panic.
pub fn build_hydration_kql(
    table: &str,
    columns: &[&str],
    value: &str,
    time_filter: &str,
    take: u32,
) -> String {
    assert!(!columns.is_empty(), "build_hydration_kql: columns must not be empty");
    let escaped = kql_escape(value);
    let predicate = columns
        .iter()
        .map(|c| format!("{c} == \"{escaped}\""))
        .collect::<Vec<_>>()
        .join(" or ");
    format!("{table} | {time_filter} | where {predicate} | take {take}")
}

#[cfg(test)]
mod hydration_tests {
    use super::*;
    use crate::types::EntityType;

    #[test]
    fn targets_for_ip_cover_three_tables() {
        let targets = sentinel_entity_targets(&EntityType::IP);
        let tables: Vec<&str> = targets.iter().map(|(t, _)| *t).collect();
        assert!(tables.contains(&"SigninLogs"));
        assert!(tables.contains(&"DeviceNetworkEvents"));
        assert!(tables.contains(&"CommonSecurityLog"));
    }

    #[test]
    fn targets_for_user_include_signin_upn() {
        let targets = sentinel_entity_targets(&EntityType::User);
        let signin = targets.iter().find(|(t, _)| *t == "SigninLogs")
            .expect("User targets should include SigninLogs");
        assert!(signin.1.contains(&"UserPrincipalName"));
    }

    #[test]
    fn targets_for_unmapped_type_are_empty() {
        assert!(sentinel_entity_targets(&EntityType::Domain).is_empty());
        assert!(sentinel_entity_targets(&EntityType::Any).is_empty());
    }

    /// Declarative source of truth: every (table, column) the parsers read as
    /// an entity *identifier* (not metadata), grouped by entity type. When a
    /// parser starts reading a new identifier column, add it here AND to
    /// `sentinel_entity_targets` — this test fails until both match.
    fn parser_identifier_columns() -> &'static [(crate::types::EntityType, &'static str, &'static str)]
    {
        use crate::types::EntityType as E;
        &[
            (E::User, "SecurityEvent", "TargetUserName"),
            (E::User, "SecurityEvent", "Account"),
            (E::User, "SecurityEvent", "SubjectUserName"),
            (E::User, "SigninLogs", "UserPrincipalName"),
            (E::User, "SigninLogs", "UserDisplayName"),
            (E::User, "DeviceProcessEvents", "AccountName"),
            (E::User, "DeviceProcessEvents", "InitiatingProcessAccountName"),
            (E::IP, "SigninLogs", "IPAddress"),
            (E::IP, "DeviceNetworkEvents", "RemoteIP"),
            (E::IP, "CommonSecurityLog", "SourceIP"),
            (E::IP, "CommonSecurityLog", "DestinationIP"),
            (E::Host, "SecurityEvent", "Computer"),
            (E::Host, "DeviceNetworkEvents", "DeviceName"),
            (E::Process, "SecurityEvent", "NewProcessName"),
            (E::Process, "SecurityEvent", "ParentProcessName"),
            (E::Process, "SecurityEvent", "ProcessName"),
            (E::Process, "SecurityEvent", "Process"),
            (E::Process, "DeviceProcessEvents", "FolderPath"),
            (E::Process, "DeviceProcessEvents", "FileName"),
            (E::Process, "DeviceProcessEvents", "InitiatingProcessFolderPath"),
            (E::Process, "DeviceFileEvents", "InitiatingProcessFolderPath"),
            (E::Process, "DeviceFileEvents", "InitiatingProcessFileName"),
            (E::File, "SecurityEvent", "ObjectName"),
            (E::File, "DeviceFileEvents", "FolderPath"),
            (E::File, "DeviceFileEvents", "FileName"),
        ]
    }

    #[test]
    fn kql_escape_neutralizes_quotes_and_backslashes() {
        assert_eq!(kql_escape(r#"a"b\c"#), r#"a\"b\\c"#);
        assert_eq!(kql_escape("plain"), "plain");
    }

    #[test]
    fn hydration_kql_builds_or_clause_across_columns() {
        let kql = build_hydration_kql(
            "CommonSecurityLog",
            &["SourceIP", "DestinationIP"],
            "10.0.0.1",
            "where TimeGenerated > ago(24h)",
            5000,
        );
        assert_eq!(
            kql,
            r#"CommonSecurityLog | where TimeGenerated > ago(24h) | where SourceIP == "10.0.0.1" or DestinationIP == "10.0.0.1" | take 5000"#
        );
    }

    #[test]
    fn hydration_kql_escapes_value() {
        let kql = build_hydration_kql(
            "SigninLogs",
            &["UserPrincipalName"],
            r#"ev"il"#,
            "where TimeGenerated > ago(1h)",
            100,
        );
        assert!(kql.contains(r#"UserPrincipalName == "ev\"il""#), "value not escaped: {kql}");
    }

    #[test]
    #[should_panic(expected = "columns must not be empty")]
    fn hydration_kql_panics_on_empty_columns() {
        let _ = build_hydration_kql("SigninLogs", &[], "x", "where TimeGenerated > ago(1h)", 100);
    }

    #[test]
    fn map_covers_every_parser_identifier_column() {
        for (ty, table, column) in parser_identifier_columns() {
            let targets = sentinel_entity_targets(ty);
            let covered = targets
                .iter()
                .any(|(t, cols)| t == table && cols.contains(column));
            assert!(
                covered,
                "parser reads {column} in {table} as {ty:?}, but sentinel_entity_targets omits it",
            );
        }
    }
}
