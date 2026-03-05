use chrono::NaiveDateTime;
use rayon::prelude::*;
use serde_json::Value;

use crate::entity::Entity;
use crate::parser::{LogParser, ParsedTriple};
use crate::relation::Relation;
use crate::types::{EntityType, RelationType};

/// Parser for Sysmon, Windows Security, PowerShell, and Winlogbeat events exported as JSON.
///
/// Supports the following Event IDs:
///
/// **Sysmon (EID 1–29)**
///
/// | Event ID | Name                 | Triples Produced                                          |
/// |----------|----------------------|-----------------------------------------------------------|
/// | 1        | Process Create       | User -[Execute]-> Process, Process -[Spawn]-> Process     |
/// | 2        | File Time Changed    | Process -[Modify]-> File                                  |
/// | 3        | Network Connection   | Host -[Connect]-> IP, Process -[Connect]-> IP             |
/// | 5        | Process Terminated   | Process -[Delete]-> Host                                  |
/// | 7        | Image Load           | Process -[Read]-> File                                    |
/// | 8        | CreateRemoteThread   | Process -[Execute]-> Process                              |
/// | 9        | RawAccessRead        | Process -[Read]-> File                                    |
/// | 10       | Process Access       | Process -[Read]-> Process                                 |
/// | 11       | File Create          | Process -[Write]-> File                                   |
/// | 12       | Registry Create/Del  | Process -[Modify]-> Registry                              |
/// | 13       | Registry Value Set   | Process -[Modify]-> Registry                              |
/// | 15       | File Stream Hash     | Process -[Write]-> File                                   |
/// | 17       | Pipe Created         | Process -[Write]-> File                                   |
/// | 18       | Pipe Connected       | Process -[Connect]-> File                                 |
/// | 22       | DNS Query            | Process -[DNS]-> Domain                                   |
/// | 23       | File Delete          | Process -[Delete]-> File                                  |
///
/// **Windows Security (EID 4xxx–5xxx)**
///
/// | Event ID | Name                 | Triples Produced                                          |
/// |----------|----------------------|-----------------------------------------------------------|
/// | 4624     | Logon Success        | User -[Auth]-> Host                                       |
/// | 4625     | Logon Failure        | User -[Auth]-> Host                                       |
/// | 4688     | Process Create       | User -[Execute]-> Process, Process -[Spawn]-> Process     |
/// | 4689     | Process Terminated   | Process -[Delete]-> Host                                  |
/// | 4663     | Object Access        | Process -[Read]-> File/Registry                           |
/// | 5145     | Network Share        | User -[Read]-> File                                       |
/// | 5156     | WFP Connection       | Process -[Connect]-> IP                                   |
///
/// **PowerShell**
///
/// | Event ID | Name                 | Triples Produced                                          |
/// |----------|----------------------|-----------------------------------------------------------|
/// | 4104     | Script Block Logging | Host -[Execute]-> Process                                 |
///
/// # Expected JSON Format
///
/// The parser accepts either:
/// - A JSON array of event objects: `[{...}, {...}]`
/// - Newline-delimited JSON (NDJSON): one event per line
///
/// Supports both standard Sysmon format (`EventID`, `UtcTime`) and Winlogbeat format
/// (`event_id`, `@timestamp`, fields nested inside `event_data`).
///
/// Timestamps are tried in order: `UtcTime` → `EventTime` → `@timestamp`.
pub struct SysmonJsonParser;

impl SysmonJsonParser {
    /// Parses a timestamp string into Unix epoch seconds.
    ///
    /// Supports:
    /// - Sysmon: "2024-01-15 14:30:00.123"
    /// - Security: "2020-09-21 18:58:30"
    /// - ISO 8601: "2019-05-14T22:31:14.252Z"
    fn parse_timestamp(ts: &str) -> Option<i64> {
        let trimmed = ts.trim();
        NaiveDateTime::parse_from_str(trimmed, "%Y-%m-%d %H:%M:%S%.f")
            .or_else(|_| NaiveDateTime::parse_from_str(trimmed, "%Y-%m-%d %H:%M:%S"))
            .or_else(|_| NaiveDateTime::parse_from_str(trimmed, "%Y-%m-%dT%H:%M:%S%.fZ"))
            .or_else(|_| NaiveDateTime::parse_from_str(trimmed, "%Y-%m-%dT%H:%M:%SZ"))
            .map(|dt| dt.and_utc().timestamp())
            .ok()
    }

    /// Extracts a non-empty string from a JSON value, returning None for
    /// missing, null, or empty-string fields.
    fn extract_str<'a>(event: &'a Value, key: &str) -> Option<&'a str> {
        event
            .get(key)
            .and_then(|v| v.as_str())
            .filter(|s| !s.is_empty())
    }

    /// Normalizes a Winlogbeat or standard event into (event_id, effective_event).
    ///
    /// For Winlogbeat events (`event_data` dict present), merges the nested fields
    /// into a top-level object so downstream handlers can use the same field names.
    /// For standard events, returns the event as-is.
    fn normalize_event(event: &Value) -> Option<(u64, std::borrow::Cow<'_, Value>)> {
        // Try EventID first (standard), then event_id (Winlogbeat). Accept u64 or i64 (EVTX/some parsers emit i64).
        let event_id = event
            .get("EventID")
            .and_then(|v| v.as_u64().or_else(|| v.as_i64().map(|i| i as u64)))
            .or_else(|| {
                event
                    .get("event_id")
                    .and_then(|v| v.as_u64().or_else(|| v.as_i64().map(|i| i as u64)))
            })?;

        if let Some(event_data) = event.get("event_data").and_then(|v| v.as_object()) {
            // Winlogbeat: merge event_data fields into a new top-level object
            let mut merged = serde_json::Map::new();
            // Copy top-level fields first
            if let Some(obj) = event.as_object() {
                for (k, v) in obj {
                    if k != "event_data" {
                        merged.insert(k.clone(), v.clone());
                    }
                }
            }
            // Overlay event_data fields (these take priority for Sysmon field names)
            for (k, v) in event_data {
                merged.insert(k.clone(), v.clone());
            }
            // Propagate hostname variants
            if !merged.contains_key("Computer") {
                if let Some(host) = event
                    .get("computer_name")
                    .or_else(|| event.get("Hostname"))
                    .or_else(|| event.get("host_name"))
                {
                    merged.insert("Computer".to_string(), host.clone());
                }
            }
            Some((event_id, std::borrow::Cow::Owned(Value::Object(merged))))
        } else {
            Some((event_id, std::borrow::Cow::Borrowed(event)))
        }
    }

    /// Parses a single event object into zero or more triples.
    fn parse_event(event: &Value) -> Vec<ParsedTriple> {
        let (event_id, effective) = match Self::normalize_event(event) {
            Some(pair) => pair,
            None => return Vec::new(),
        };
        let ev = effective.as_ref();

        // Timestamp fallback chain: UtcTime → EventTime → @timestamp
        let timestamp = Self::extract_str(ev, "UtcTime")
            .or_else(|| Self::extract_str(ev, "EventTime"))
            .or_else(|| Self::extract_str(ev, "@timestamp"))
            .and_then(Self::parse_timestamp)
            .unwrap_or(0);

        match event_id {
            // Sysmon events
            1 => Self::parse_process_create(ev, timestamp),
            2 => Self::parse_file_time_changed(ev, timestamp),
            3 => Self::parse_network_connection(ev, timestamp),
            5 => Self::parse_process_terminated(ev, timestamp),
            7 => Self::parse_image_load(ev, timestamp),
            8 => Self::parse_create_remote_thread(ev, timestamp),
            9 => Self::parse_raw_access_read(ev, timestamp),
            10 => Self::parse_process_access(ev, timestamp),
            11 => Self::parse_file_create(ev, timestamp),
            12 | 13 => Self::parse_registry_event(ev, timestamp),
            15 => Self::parse_file_stream_hash(ev, timestamp),
            17 => Self::parse_pipe_created(ev, timestamp),
            18 => Self::parse_pipe_connected(ev, timestamp),
            22 => Self::parse_dns_query(ev, timestamp),
            23 => Self::parse_file_delete(ev, timestamp),
            // Windows Security events
            4624 | 4625 => Self::parse_security_logon(ev, event_id, timestamp),
            4688 => Self::parse_security_process_create(ev, timestamp),
            4689 => Self::parse_security_process_terminated(ev, timestamp),
            4663 => Self::parse_security_object_access(ev, timestamp),
            5145 => Self::parse_security_network_share(ev, timestamp),
            5156 => Self::parse_security_wfp_connection(ev, timestamp),
            // PowerShell
            4104 => Self::parse_powershell_script_block(ev, timestamp),
            _ => Vec::new(),
        }
    }

    // ══════════════════════════════════════════════════════════════
    // Sysmon Event Handlers
    // ══════════════════════════════════════════════════════════════

    /// Event 1: Process Create
    ///
    /// Produces:
    /// - User -[Execute]-> Process (child)
    /// - Process (parent) -[Spawn]-> Process (child)
    fn parse_process_create(event: &Value, timestamp: i64) -> Vec<ParsedTriple> {
        let mut triples = Vec::new();

        let image = match Self::extract_str(event, "Image") {
            Some(v) => v,
            None => return triples,
        };

        // Build child process entity with metadata
        let mut child = Entity::new(image, EntityType::Process);
        if let Some(pid) = event.get("ProcessId").and_then(|v| v.as_u64()) {
            child.metadata.insert("pid".into(), pid.to_string());
        }
        if let Some(cmdline) = Self::extract_str(event, "CommandLine") {
            child.metadata.insert("cmdline".into(), cmdline.into());
        }
        if let Some(computer) = Self::extract_str(event, "Computer") {
            child.metadata.insert("computer".into(), computer.into());
        }

        // Triple 1: User -[Execute]-> Process
        if let Some(user_name) = Self::extract_str(event, "User") {
            let user_entity = Entity::new(user_name, EntityType::User);
            let rel = Relation::new(&user_entity.id, &child.id, RelationType::Execute, timestamp);
            triples.push((user_entity, rel, child.clone()));
        }

        // Triple 2: ParentProcess -[Spawn]-> ChildProcess
        if let Some(parent_image) = Self::extract_str(event, "ParentImage") {
            let mut parent = Entity::new(parent_image, EntityType::Process);
            if let Some(ppid) = event.get("ParentProcessId").and_then(|v| v.as_u64()) {
                parent.metadata.insert("pid".into(), ppid.to_string());
            }
            let rel = Relation::new(&parent.id, &child.id, RelationType::Spawn, timestamp);
            triples.push((parent, rel, child));
        }

        triples
    }

    /// Event 2: File Creation Time Changed (Timestomping)
    ///
    /// Produces: Process -[Modify]-> File
    fn parse_file_time_changed(event: &Value, timestamp: i64) -> Vec<ParsedTriple> {
        let image = match Self::extract_str(event, "Image") {
            Some(v) => v,
            None => return Vec::new(),
        };
        let target = match Self::extract_str(event, "TargetFilename") {
            Some(v) => v,
            None => return Vec::new(),
        };

        let process = Entity::new(image, EntityType::Process);
        let file = Entity::new(target, EntityType::File);
        let mut rel = Relation::new(&process.id, &file.id, RelationType::Modify, timestamp);
        if let Some(creation) = Self::extract_str(event, "CreationUtcTime") {
            rel.metadata
                .insert("creation_utc_time".into(), creation.into());
        }
        if let Some(prev) = Self::extract_str(event, "PreviousCreationUtcTime") {
            rel.metadata
                .insert("previous_creation_utc_time".into(), prev.into());
        }
        vec![(process, rel, file)]
    }

    /// Event 3: Network Connection
    ///
    /// Produces:
    /// - Host (source computer) -[Connect]-> IP (destination)
    /// - Process -[Connect]-> IP (destination)
    fn parse_network_connection(event: &Value, timestamp: i64) -> Vec<ParsedTriple> {
        let dest_ip = match Self::extract_str(event, "DestinationIp") {
            Some(v) => v,
            None => return Vec::new(),
        };

        // Source is the computer/host generating the event
        let source_name = Self::extract_str(event, "Computer")
            .or_else(|| Self::extract_str(event, "Hostname"))
            .or_else(|| Self::extract_str(event, "SourceHostname"))
            .unwrap_or("unknown-host");

        let mut source = Entity::new(source_name, EntityType::Host);
        if let Some(src_ip) = Self::extract_str(event, "SourceIp") {
            source.metadata.insert("source_ip".into(), src_ip.into());
        }
        if let Some(src_port) = Self::extract_str(event, "SourcePort") {
            source.metadata.insert("source_port".into(), src_port.into());
        }

        let mut dest = Entity::new(dest_ip, EntityType::IP);
        if let Some(dst_port) = Self::extract_str(event, "DestinationPort") {
            dest.metadata.insert("dest_port".into(), dst_port.into());
        }
        if let Some(dst_host) = Self::extract_str(event, "DestinationHostname") {
            dest.metadata.insert("hostname".into(), dst_host.into());
        }
        if let Some(proto) = Self::extract_str(event, "Protocol") {
            dest.metadata.insert("protocol".into(), proto.into());
        }

        let mut rel = Relation::new(&source.id, &dest.id, RelationType::Connect, timestamp);
        if let Some(image) = Self::extract_str(event, "Image") {
            rel.metadata.insert("image".into(), image.into());
        }

        let mut triples = vec![(source, rel, dest.clone())];

        // Triple 2: Process -[Connect]-> IP
        if let Some(image) = Self::extract_str(event, "Image") {
            let process = Entity::new(image, EntityType::Process);
            let rel2 = Relation::new(&process.id, &dest.id, RelationType::Connect, timestamp);
            triples.push((process, rel2, dest));
        }

        triples
    }

    /// Event 5: Process Terminated
    ///
    /// Produces: Process -[Delete]-> Host
    fn parse_process_terminated(event: &Value, timestamp: i64) -> Vec<ParsedTriple> {
        let image = match Self::extract_str(event, "Image") {
            Some(v) => v,
            None => return Vec::new(),
        };

        let host_name = Self::extract_str(event, "Computer")
            .or_else(|| Self::extract_str(event, "Hostname"))
            .unwrap_or("unknown-host");

        let mut process = Entity::new(image, EntityType::Process);
        if let Some(pid) = event.get("ProcessId").and_then(|v| v.as_u64()) {
            process.metadata.insert("pid".into(), pid.to_string());
        }
        let host = Entity::new(host_name, EntityType::Host);
        let rel = Relation::new(&process.id, &host.id, RelationType::Delete, timestamp);
        vec![(process, rel, host)]
    }

    /// Event 7: Image Load (DLL Load)
    ///
    /// Produces: Process -[Read]-> File
    fn parse_image_load(event: &Value, timestamp: i64) -> Vec<ParsedTriple> {
        let image = match Self::extract_str(event, "Image") {
            Some(v) => v,
            None => return Vec::new(),
        };
        let image_loaded = match Self::extract_str(event, "ImageLoaded") {
            Some(v) => v,
            None => return Vec::new(),
        };

        let process = Entity::new(image, EntityType::Process);
        let mut file = Entity::new(image_loaded, EntityType::File);
        if let Some(signed) = Self::extract_str(event, "Signed") {
            file.metadata.insert("signed".into(), signed.into());
        }
        if let Some(sig_status) = Self::extract_str(event, "SignatureStatus") {
            file.metadata
                .insert("signature_status".into(), sig_status.into());
        }
        if let Some(hashes) = Self::extract_str(event, "Hashes") {
            file.metadata.insert("hashes".into(), hashes.into());
        }

        let rel = Relation::new(&process.id, &file.id, RelationType::Read, timestamp);
        vec![(process, rel, file)]
    }

    /// Event 8: CreateRemoteThread (Thread Injection)
    ///
    /// Produces: Process (source) -[Execute]-> Process (target)
    fn parse_create_remote_thread(event: &Value, timestamp: i64) -> Vec<ParsedTriple> {
        let source_image = match Self::extract_str(event, "SourceImage") {
            Some(v) => v,
            None => return Vec::new(),
        };
        let target_image = match Self::extract_str(event, "TargetImage") {
            Some(v) => v,
            None => return Vec::new(),
        };

        let source = Entity::new(source_image, EntityType::Process);
        let target = Entity::new(target_image, EntityType::Process);
        let mut rel = Relation::new(&source.id, &target.id, RelationType::Execute, timestamp);
        if let Some(addr) = Self::extract_str(event, "StartAddress") {
            rel.metadata.insert("start_address".into(), addr.into());
        }
        if let Some(tid) = Self::extract_str(event, "NewThreadId") {
            rel.metadata.insert("new_thread_id".into(), tid.into());
        }
        if let Some(module) = Self::extract_str(event, "StartModule") {
            rel.metadata.insert("start_module".into(), module.into());
        }
        vec![(source, rel, target)]
    }

    /// Event 9: RawAccessRead (Raw Disk Access)
    ///
    /// Produces: Process -[Read]-> File (device)
    fn parse_raw_access_read(event: &Value, timestamp: i64) -> Vec<ParsedTriple> {
        let image = match Self::extract_str(event, "Image") {
            Some(v) => v,
            None => return Vec::new(),
        };
        let device = match Self::extract_str(event, "Device") {
            Some(v) => v,
            None => return Vec::new(),
        };

        let process = Entity::new(image, EntityType::Process);
        let file = Entity::new(device, EntityType::File);
        let rel = Relation::new(&process.id, &file.id, RelationType::Read, timestamp);
        vec![(process, rel, file)]
    }

    /// Event 10: Process Access
    ///
    /// Produces: Process (source) -[Read]-> Process (target)
    fn parse_process_access(event: &Value, timestamp: i64) -> Vec<ParsedTriple> {
        let source_image = match Self::extract_str(event, "SourceImage") {
            Some(v) => v,
            None => return Vec::new(),
        };
        let target_image = match Self::extract_str(event, "TargetImage") {
            Some(v) => v,
            None => return Vec::new(),
        };

        let source = Entity::new(source_image, EntityType::Process);
        let target = Entity::new(target_image, EntityType::Process);
        let mut rel = Relation::new(&source.id, &target.id, RelationType::Read, timestamp);
        if let Some(access) = Self::extract_str(event, "GrantedAccess") {
            rel.metadata
                .insert("granted_access".into(), access.into());
        }
        if let Some(trace) = Self::extract_str(event, "CallTrace") {
            rel.metadata.insert("call_trace".into(), trace.into());
        }

        vec![(source, rel, target)]
    }

    /// Event 11: File Create
    ///
    /// Produces: Process -[Write]-> File
    fn parse_file_create(event: &Value, timestamp: i64) -> Vec<ParsedTriple> {
        let image = match Self::extract_str(event, "Image") {
            Some(v) => v,
            None => return Vec::new(),
        };
        let target = match Self::extract_str(event, "TargetFilename") {
            Some(v) => v,
            None => return Vec::new(),
        };

        let process = Entity::new(image, EntityType::Process);
        let mut file = Entity::new(target, EntityType::File);
        if let Some(hash) = Self::extract_str(event, "Hashes") {
            file.metadata.insert("hashes".into(), hash.into());
        }

        let rel = Relation::new(&process.id, &file.id, RelationType::Write, timestamp);
        vec![(process, rel, file)]
    }

    /// Events 12/13: Registry Object Create/Delete and Registry Value Set
    ///
    /// Produces: Process -[Modify]-> Registry
    fn parse_registry_event(event: &Value, timestamp: i64) -> Vec<ParsedTriple> {
        let image = match Self::extract_str(event, "Image") {
            Some(v) => v,
            None => return Vec::new(),
        };
        let target_object = match Self::extract_str(event, "TargetObject") {
            Some(v) => v,
            None => return Vec::new(),
        };

        let process = Entity::new(image, EntityType::Process);
        let registry = Entity::new(target_object, EntityType::Registry);
        let mut rel = Relation::new(&process.id, &registry.id, RelationType::Modify, timestamp);
        if let Some(event_type) = Self::extract_str(event, "EventType") {
            rel.metadata.insert("event_type".into(), event_type.into());
        }
        if let Some(details) = Self::extract_str(event, "Details") {
            rel.metadata.insert("details".into(), details.into());
        }

        vec![(process, rel, registry)]
    }

    /// Event 15: File Stream Hash (Alternate Data Streams)
    ///
    /// Produces: Process -[Write]-> File
    fn parse_file_stream_hash(event: &Value, timestamp: i64) -> Vec<ParsedTriple> {
        let image = match Self::extract_str(event, "Image") {
            Some(v) => v,
            None => return Vec::new(),
        };
        let target = match Self::extract_str(event, "TargetFilename") {
            Some(v) => v,
            None => return Vec::new(),
        };

        let process = Entity::new(image, EntityType::Process);
        let mut file = Entity::new(target, EntityType::File);
        if let Some(hash) = Self::extract_str(event, "Hash") {
            file.metadata.insert("hash".into(), hash.into());
        }
        let rel = Relation::new(&process.id, &file.id, RelationType::Write, timestamp);
        vec![(process, rel, file)]
    }

    /// Event 17: Pipe Created (Named Pipe)
    ///
    /// Produces: Process -[Write]-> File (pipe)
    fn parse_pipe_created(event: &Value, timestamp: i64) -> Vec<ParsedTriple> {
        let image = match Self::extract_str(event, "Image") {
            Some(v) => v,
            None => return Vec::new(),
        };
        let pipe_name = match Self::extract_str(event, "PipeName") {
            Some(v) => v,
            None => return Vec::new(),
        };

        let process = Entity::new(image, EntityType::Process);
        let file = Entity::new(pipe_name, EntityType::File);
        let rel = Relation::new(&process.id, &file.id, RelationType::Write, timestamp);
        vec![(process, rel, file)]
    }

    /// Event 18: Pipe Connected
    ///
    /// Produces: Process -[Connect]-> File (pipe)
    fn parse_pipe_connected(event: &Value, timestamp: i64) -> Vec<ParsedTriple> {
        let image = match Self::extract_str(event, "Image") {
            Some(v) => v,
            None => return Vec::new(),
        };
        let pipe_name = match Self::extract_str(event, "PipeName") {
            Some(v) => v,
            None => return Vec::new(),
        };

        let process = Entity::new(image, EntityType::Process);
        let file = Entity::new(pipe_name, EntityType::File);
        let rel = Relation::new(&process.id, &file.id, RelationType::Connect, timestamp);
        vec![(process, rel, file)]
    }

    /// Event 22: DNS Query
    ///
    /// Produces: Process -[DNS]-> Domain
    fn parse_dns_query(event: &Value, timestamp: i64) -> Vec<ParsedTriple> {
        let image = match Self::extract_str(event, "Image") {
            Some(v) => v,
            None => return Vec::new(),
        };
        let query_name = match Self::extract_str(event, "QueryName") {
            Some(v) => v,
            None => return Vec::new(),
        };

        let process = Entity::new(image, EntityType::Process);
        let mut domain = Entity::new(query_name, EntityType::Domain);
        if let Some(result) = Self::extract_str(event, "QueryResults") {
            domain
                .metadata
                .insert("query_results".into(), result.into());
        }
        if let Some(qtype) = Self::extract_str(event, "QueryType") {
            domain.metadata.insert("query_type".into(), qtype.into());
        }

        let rel = Relation::new(&process.id, &domain.id, RelationType::DNS, timestamp);
        vec![(process, rel, domain)]
    }

    /// Event 23: File Delete
    ///
    /// Produces: Process -[Delete]-> File
    fn parse_file_delete(event: &Value, timestamp: i64) -> Vec<ParsedTriple> {
        let image = match Self::extract_str(event, "Image") {
            Some(v) => v,
            None => return Vec::new(),
        };
        let target = match Self::extract_str(event, "TargetFilename") {
            Some(v) => v,
            None => return Vec::new(),
        };

        let process = Entity::new(image, EntityType::Process);
        let mut file = Entity::new(target, EntityType::File);
        if let Some(hashes) = Self::extract_str(event, "Hashes") {
            file.metadata.insert("hashes".into(), hashes.into());
        }
        if let Some(is_exec) = Self::extract_str(event, "IsExecutable") {
            file.metadata
                .insert("is_executable".into(), is_exec.into());
        }

        let rel = Relation::new(&process.id, &file.id, RelationType::Delete, timestamp);
        vec![(process, rel, file)]
    }

    // ══════════════════════════════════════════════════════════════
    // Windows Security Event Handlers
    // ══════════════════════════════════════════════════════════════

    /// Events 4624/4625: Logon Success / Logon Failure
    ///
    /// Produces: User -[Auth]-> Host
    fn parse_security_logon(event: &Value, event_id: u64, timestamp: i64) -> Vec<ParsedTriple> {
        let user_name = match Self::extract_str(event, "TargetUserName") {
            Some(v) => v,
            None => return Vec::new(),
        };

        let domain = Self::extract_str(event, "TargetDomainName");
        let user_id = match domain {
            Some(d) if !d.eq_ignore_ascii_case("-") => format!("{}\\{}", d, user_name),
            _ => user_name.to_string(),
        };

        let host_name = Self::extract_str(event, "Computer")
            .or_else(|| Self::extract_str(event, "Hostname"))
            .unwrap_or("unknown-host");

        let user = Entity::new(&user_id, EntityType::User);
        let host = Entity::new(host_name, EntityType::Host);
        let mut rel = Relation::new(&user.id, &host.id, RelationType::Auth, timestamp);
        if let Some(logon_type) = Self::extract_str(event, "LogonType")
            .or_else(|| event.get("LogonType").and_then(|v| v.as_u64()).map(|_| ""))
        {
            // LogonType can be string or int
            let lt = Self::extract_str(event, "LogonType")
                .map(|s| s.to_string())
                .unwrap_or_else(|| {
                    event
                        .get("LogonType")
                        .and_then(|v| v.as_u64())
                        .map(|n| n.to_string())
                        .unwrap_or_default()
                });
            if !lt.is_empty() {
                rel.metadata.insert("logon_type".into(), lt);
            }
            let _ = logon_type; // used above
        }
        if let Some(ip) = Self::extract_str(event, "IpAddress") {
            if ip != "-" {
                rel.metadata.insert("ip_address".into(), ip.into());
            }
        }
        if event_id == 4625 {
            rel.metadata.insert("success".into(), "false".into());
        }
        vec![(user, rel, host)]
    }

    /// Event 4688: Security Process Create
    ///
    /// Produces:
    /// - User -[Execute]-> Process (child)
    /// - Process (parent) -[Spawn]-> Process (child)
    fn parse_security_process_create(event: &Value, timestamp: i64) -> Vec<ParsedTriple> {
        let new_process = match Self::extract_str(event, "NewProcessName") {
            Some(v) => v,
            None => return Vec::new(),
        };

        let mut triples = Vec::new();

        let mut child = Entity::new(new_process, EntityType::Process);
        if let Some(cmdline) = Self::extract_str(event, "CommandLine") {
            child.metadata.insert("cmdline".into(), cmdline.into());
        }
        if let Some(computer) = Self::extract_str(event, "Computer")
            .or_else(|| Self::extract_str(event, "Hostname"))
        {
            child.metadata.insert("computer".into(), computer.into());
        }

        // Triple 1: User -[Execute]-> Process
        if let Some(user_name) = Self::extract_str(event, "SubjectUserName") {
            let domain = Self::extract_str(event, "SubjectDomainName");
            let user_id = match domain {
                Some(d) if !d.eq_ignore_ascii_case("-") => format!("{}\\{}", d, user_name),
                _ => user_name.to_string(),
            };
            let user = Entity::new(&user_id, EntityType::User);
            let rel = Relation::new(&user.id, &child.id, RelationType::Execute, timestamp);
            triples.push((user, rel, child.clone()));
        }

        // Triple 2: Parent -[Spawn]-> Child
        if let Some(parent_name) = Self::extract_str(event, "ParentProcessName") {
            let parent = Entity::new(parent_name, EntityType::Process);
            let rel = Relation::new(&parent.id, &child.id, RelationType::Spawn, timestamp);
            triples.push((parent, rel, child));
        }

        triples
    }

    /// Event 4689: Security Process Terminated
    ///
    /// Produces: Process -[Delete]-> Host
    fn parse_security_process_terminated(event: &Value, timestamp: i64) -> Vec<ParsedTriple> {
        let process_name = match Self::extract_str(event, "ProcessName") {
            Some(v) => v,
            None => return Vec::new(),
        };

        let host_name = Self::extract_str(event, "Computer")
            .or_else(|| Self::extract_str(event, "Hostname"))
            .unwrap_or("unknown-host");

        let process = Entity::new(process_name, EntityType::Process);
        let host = Entity::new(host_name, EntityType::Host);
        let rel = Relation::new(&process.id, &host.id, RelationType::Delete, timestamp);
        vec![(process, rel, host)]
    }

    /// Event 4663: Object Access (File / Registry)
    ///
    /// Produces: Process -[Read]-> File or Process -[Read]-> Registry
    fn parse_security_object_access(event: &Value, timestamp: i64) -> Vec<ParsedTriple> {
        let process_name = match Self::extract_str(event, "ProcessName") {
            Some(v) => v,
            None => return Vec::new(),
        };
        let object_name = match Self::extract_str(event, "ObjectName") {
            Some(v) => v,
            None => return Vec::new(),
        };

        let process = Entity::new(process_name, EntityType::Process);
        let object_type = Self::extract_str(event, "ObjectType");
        let target = if object_type == Some("Key") {
            Entity::new(object_name, EntityType::Registry)
        } else {
            Entity::new(object_name, EntityType::File)
        };
        let rel = Relation::new(&process.id, &target.id, RelationType::Read, timestamp);
        vec![(process, rel, target)]
    }

    /// Event 5145: Network Share Access
    ///
    /// Produces: User -[Read]-> File (share path)
    fn parse_security_network_share(event: &Value, timestamp: i64) -> Vec<ParsedTriple> {
        let user_name = match Self::extract_str(event, "SubjectUserName") {
            Some(v) => v,
            None => return Vec::new(),
        };

        let share_name = Self::extract_str(event, "ShareName").unwrap_or("");
        let relative_target = Self::extract_str(event, "RelativeTargetName").unwrap_or("");
        let path = if !share_name.is_empty() && !relative_target.is_empty() {
            format!("{}\\{}", share_name, relative_target)
        } else if !share_name.is_empty() {
            share_name.to_string()
        } else {
            return Vec::new();
        };

        let domain = Self::extract_str(event, "SubjectDomainName");
        let user_id = match domain {
            Some(d) if !d.eq_ignore_ascii_case("-") => format!("{}\\{}", d, user_name),
            _ => user_name.to_string(),
        };

        let user = Entity::new(&user_id, EntityType::User);
        let mut file = Entity::new(&path, EntityType::File);
        if let Some(ip) = Self::extract_str(event, "IpAddress") {
            file.metadata.insert("ip_address".into(), ip.into());
        }
        let rel = Relation::new(&user.id, &file.id, RelationType::Read, timestamp);
        vec![(user, rel, file)]
    }

    /// Event 5156: WFP (Windows Filtering Platform) Connection
    ///
    /// Produces: Process -[Connect]-> IP
    fn parse_security_wfp_connection(event: &Value, timestamp: i64) -> Vec<ParsedTriple> {
        let application = match Self::extract_str(event, "Application") {
            Some(v) => v,
            None => return Vec::new(),
        };
        let dest_addr = match Self::extract_str(event, "DestAddress") {
            Some(v) => v,
            None => return Vec::new(),
        };

        let process = Entity::new(application, EntityType::Process);
        let mut ip = Entity::new(dest_addr, EntityType::IP);
        if let Some(dp) = Self::extract_str(event, "DestPort") {
            ip.metadata.insert("dest_port".into(), dp.into());
        }
        if let Some(sp) = Self::extract_str(event, "SourcePort") {
            ip.metadata.insert("source_port".into(), sp.into());
        }
        if let Some(proto) = Self::extract_str(event, "Protocol") {
            ip.metadata.insert("protocol".into(), proto.into());
        }

        let mut rel = Relation::new(&process.id, &ip.id, RelationType::Connect, timestamp);
        if let Some(src) = Self::extract_str(event, "SourceAddress") {
            rel.metadata.insert("source_address".into(), src.into());
        }
        vec![(process, rel, ip)]
    }

    // ══════════════════════════════════════════════════════════════
    // PowerShell Event Handlers
    // ══════════════════════════════════════════════════════════════

    /// Event 4104: PowerShell Script Block Logging
    ///
    /// Produces: Host -[Execute]-> Process("powershell.exe")
    fn parse_powershell_script_block(event: &Value, timestamp: i64) -> Vec<ParsedTriple> {
        let host_name = Self::extract_str(event, "Computer")
            .or_else(|| Self::extract_str(event, "Hostname"))
            .unwrap_or("unknown-host");

        let host = Entity::new(host_name, EntityType::Host);
        let mut process = Entity::new("powershell.exe", EntityType::Process);

        if let Some(script_text) = Self::extract_str(event, "ScriptBlockText") {
            let preview: String = script_text.chars().take(200).collect();
            process
                .metadata
                .insert("script_preview".into(), preview);
        }
        if let Some(sbid) = Self::extract_str(event, "ScriptBlockId") {
            process
                .metadata
                .insert("script_block_id".into(), sbid.into());
        }

        let rel = Relation::new(&host.id, &process.id, RelationType::Execute, timestamp);
        vec![(host, rel, process)]
    }
}

impl LogParser for SysmonJsonParser {
    fn parse(&self, data: &str) -> Vec<ParsedTriple> {
        let trimmed = data.trim();

        // Try JSON array first (simd-json for speed, fallback to serde_json)
        if trimmed.starts_with('[') {
            let mut buf = trimmed.as_bytes().to_vec();
            if let Ok(events) = simd_json::serde::from_slice::<Vec<Value>>(&mut buf) {
                return events
                    .par_iter()
                    .flat_map(|event| Self::parse_event(event))
                    .collect();
            }
        }

        // Fall back to NDJSON (one JSON object per line).
        // Prefer simd_json for speed; fall back to serde_json when simd_json fails (e.g. EVTX-converted lines).
        let lines: Vec<&str> = trimmed.lines().filter(|l| !l.trim().is_empty()).collect();
        lines
            .par_iter()
            .filter_map(|line| {
                let mut buf = line.as_bytes().to_vec();
                simd_json::serde::from_slice::<Value>(&mut buf)
                    .ok()
                    .or_else(|| serde_json::from_str(line).ok())
            })
            .flat_map(|event| Self::parse_event(&event))
            .collect()
    }
}
