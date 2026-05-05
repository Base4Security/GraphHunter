use chrono::NaiveDateTime;
use serde::Deserialize;
use serde_json::Value;

use crate::entity::Entity;
use crate::parser::{LogParser, ParsedTriple};
use crate::relation::Relation;
use crate::types::{EntityType, RelationType};

/// Typed Sysmon event row used by the direct-typed fast path
/// (`SysmonJsonParser::try_parse_typed_with_scratch`). Every field is `Option`
/// + `borrow`ed from the input scratch buffer for zero-copy
/// deserialization through `simd_json::serde::from_slice`. The
/// fields cover the union of what every implemented EventID needs
/// — fields not relevant to the active EventID stay `None` and
/// add no per-event cost.
#[derive(Deserialize)]
struct SysmonEventTyped<'a> {
    #[serde(rename = "EventID", default)]
    event_id: Option<u64>,
    #[serde(rename = "UtcTime", default, borrow)]
    utc_time: Option<&'a str>,
    #[serde(rename = "EventTime", default, borrow)]
    event_time: Option<&'a str>,
    #[serde(rename = "@timestamp", default, borrow)]
    timestamp_at: Option<&'a str>,
    // Event 1, 7, 11 — process anchor.
    #[serde(rename = "Image", default, borrow)]
    image: Option<&'a str>,
    // Event 1.
    #[serde(rename = "User", default, borrow)]
    user: Option<&'a str>,
    #[serde(rename = "Computer", default, borrow)]
    computer: Option<&'a str>,
    #[serde(rename = "ProcessId", default)]
    process_id: Option<u64>,
    #[serde(rename = "ParentImage", default, borrow)]
    parent_image: Option<&'a str>,
    #[serde(rename = "ParentProcessId", default)]
    parent_process_id: Option<u64>,
    #[serde(rename = "CommandLine", default, borrow)]
    command_line: Option<&'a str>,
    // Event 3 — network connection.
    #[serde(rename = "Hostname", default, borrow)]
    hostname: Option<&'a str>,
    #[serde(rename = "SourceHostname", default, borrow)]
    source_hostname: Option<&'a str>,
    #[serde(rename = "SourceIp", default, borrow)]
    source_ip: Option<&'a str>,
    #[serde(rename = "SourcePort", default, borrow)]
    source_port: Option<&'a str>,
    #[serde(rename = "DestinationIp", default, borrow)]
    destination_ip: Option<&'a str>,
    #[serde(rename = "DestinationPort", default, borrow)]
    destination_port: Option<&'a str>,
    #[serde(rename = "DestinationHostname", default, borrow)]
    destination_hostname: Option<&'a str>,
    #[serde(rename = "Protocol", default, borrow)]
    protocol: Option<&'a str>,
    // Event 7 — image load.
    #[serde(rename = "ImageLoaded", default, borrow)]
    image_loaded: Option<&'a str>,
    #[serde(rename = "Signed", default, borrow)]
    signed: Option<&'a str>,
    #[serde(rename = "SignatureStatus", default, borrow)]
    signature_status: Option<&'a str>,
    #[serde(rename = "Hashes", default, borrow)]
    hashes: Option<&'a str>,
    // Event 11 — file create.
    #[serde(rename = "TargetFilename", default, borrow)]
    target_filename: Option<&'a str>,
    // Event 8 — CreateRemoteThread.
    #[serde(rename = "SourceImage", default, borrow)]
    source_image: Option<&'a str>,
    #[serde(rename = "TargetImage", default, borrow)]
    target_image: Option<&'a str>,
    #[serde(rename = "StartAddress", default, borrow)]
    start_address: Option<&'a str>,
    #[serde(rename = "NewThreadId", default, borrow)]
    new_thread_id: Option<&'a str>,
    #[serde(rename = "StartModule", default, borrow)]
    start_module: Option<&'a str>,
    // Events 12 / 13 — Registry.
    #[serde(rename = "TargetObject", default, borrow)]
    target_object: Option<&'a str>,
    #[serde(rename = "EventType", default, borrow)]
    event_type_str: Option<&'a str>,
    #[serde(rename = "Details", default, borrow)]
    details: Option<&'a str>,
    // Event 15 — File Stream Hash (single Hash, not Hashes).
    #[serde(rename = "Hash", default, borrow)]
    hash_single: Option<&'a str>,
    // Windows Security 4624 / 4625 — logon.
    #[serde(rename = "TargetUserName", default, borrow)]
    target_user_name: Option<&'a str>,
    #[serde(rename = "TargetDomainName", default, borrow)]
    target_domain_name: Option<&'a str>,
    #[serde(rename = "LogonType", default)]
    logon_type: Option<LogonTypeField<'a>>,
    #[serde(rename = "IpAddress", default, borrow)]
    ip_address: Option<&'a str>,
    // Windows Security 4688 — security process create. Distinct from
    // Sysmon's Image / User: Windows Security uses NewProcessName /
    // SubjectUserName / SubjectDomainName / ParentProcessName.
    #[serde(rename = "NewProcessName", default, borrow)]
    new_process_name: Option<&'a str>,
    #[serde(rename = "SubjectUserName", default, borrow)]
    subject_user_name: Option<&'a str>,
    #[serde(rename = "SubjectDomainName", default, borrow)]
    subject_domain_name: Option<&'a str>,
    #[serde(rename = "ParentProcessName", default, borrow)]
    parent_process_name: Option<&'a str>,
    // Windows Security 4689 / 4663.
    #[serde(rename = "ProcessName", default, borrow)]
    process_name: Option<&'a str>,
    #[serde(rename = "ObjectName", default, borrow)]
    object_name: Option<&'a str>,
    #[serde(rename = "ObjectType", default, borrow)]
    object_type: Option<&'a str>,
    // Windows Security 5145 — network share.
    #[serde(rename = "ShareName", default, borrow)]
    share_name: Option<&'a str>,
    #[serde(rename = "RelativeTargetName", default, borrow)]
    relative_target_name: Option<&'a str>,
    // Windows Security 5156 — WFP connection.
    #[serde(rename = "Application", default, borrow)]
    application: Option<&'a str>,
    #[serde(rename = "DestAddress", default, borrow)]
    dest_address: Option<&'a str>,
    #[serde(rename = "DestPort", default, borrow)]
    dest_port: Option<&'a str>,
    #[serde(rename = "SourceAddress", default, borrow)]
    source_address: Option<&'a str>,
    // PowerShell 4104 — script block.
    #[serde(rename = "ScriptBlockText", default, borrow)]
    script_block_text: Option<&'a str>,
    #[serde(rename = "ScriptBlockId", default, borrow)]
    script_block_id: Option<&'a str>,
}

/// LogonType in Windows Security 4624/4625 can be either an integer
/// (the canonical EVTX format, `2` = Interactive, `3` = Network, …)
/// or a string (some Sentinel exports stringify it as `"3"`). Untagged
/// serde enum lets simd-json accept either without a Value detour.
#[derive(Deserialize)]
#[serde(untagged)]
enum LogonTypeField<'a> {
    Int(i64),
    Str(&'a str),
}

impl LogonTypeField<'_> {
    fn as_string(&self) -> String {
        match self {
            LogonTypeField::Int(n) => n.to_string(),
            LogonTypeField::Str(s) => (*s).to_string(),
        }
    }
}

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
            source
                .metadata
                .insert("source_port".into(), src_port.into());
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
            rel.metadata.insert("granted_access".into(), access.into());
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
            file.metadata.insert("is_executable".into(), is_exec.into());
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
        if let Some(computer) =
            Self::extract_str(event, "Computer").or_else(|| Self::extract_str(event, "Hostname"))
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
            process.metadata.insert("script_preview".into(), preview);
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

impl SysmonJsonParser {
    /// Direct-typed parser for the highest-volume Sysmon EventIDs
    /// (1, 3, 7, 11). Returns `Some(triples)` on a successful typed
    /// parse; `None` falls back to the legacy `Value`-based path
    /// (other EventIDs). Saves the HashMap construction + per-field
    /// probe cost that `parse_event(Value)` pays.
    ///
    /// Field semantics mirror the legacy `parse_*` per EventID:
    /// the typed handlers produce identical triples to the Value
    /// handlers on the same input. Adding more variants is a
    /// mechanical extension of `SysmonEventTyped` + a new arm
    /// here.
    ///
    /// `scratch` is a caller-supplied Vec<u8> reused across every
    /// line a rayon worker handles — saves one heap allocation per
    /// line vs the prior `to_vec()` per line.
    /// Parse-only fast path: deserializes the line into the typed
    /// event struct and returns whether the parse succeeded.
    /// Measures pure parse cost (simd-json + serde reflection)
    /// without paying any `Entity` / `Relation` / `HashMap`
    /// construction. Used by `bench_ingest_parse_only` to
    /// distinguish parser cost from downstream-allocation cost.
    ///
    /// Production callers should NOT use this — it discards the
    /// parsed event. It exists to anchor the upper bound on
    /// throughput: any production ingest path that retains
    /// triples will be bounded above by this number.
    pub fn parse_only_sysmon(line: &str, scratch: &mut Vec<u8>) -> bool {
        scratch.clear();
        scratch.extend_from_slice(line.as_bytes());
        match simd_json::serde::from_slice::<SysmonEventTyped<'_>>(scratch) {
            Ok(ev) => ev.event_id.is_some(),
            Err(_) => false,
        }
    }

    /// Mirrors `try_parse_typed_with_scratch` but emits
    /// `RawIngestEvent`s for the EventIDs that have a raw-path
    /// implementation. For unmigrated IDs returns `None` so the
    /// caller can fall back to the legacy path + lift.
    fn try_parse_typed_raw_with_scratch(
        line: &str,
        scratch: &mut Vec<u8>,
    ) -> Option<Vec<crate::parser::RawIngestEvent>> {
        scratch.clear();
        scratch.extend_from_slice(line.as_bytes());
        let event: SysmonEventTyped<'_> = simd_json::serde::from_slice(scratch).ok()?;
        let event_id = event.event_id?;
        let timestamp = event
            .utc_time
            .or(event.event_time)
            .or(event.timestamp_at)
            .and_then(Self::parse_timestamp)
            .unwrap_or(0);
        match event_id {
            1 => Self::typed_process_create_raw(&event, timestamp),
            3 => Self::typed_network_connection_raw(&event, timestamp),
            5 => Self::typed_process_terminated_raw(&event, timestamp),
            7 => Self::typed_image_load_raw(&event, timestamp),
            8 => Self::typed_create_remote_thread_raw(&event, timestamp),
            11 => Self::typed_file_create_raw(&event, timestamp),
            12 | 13 => Self::typed_registry_event_raw(&event, timestamp),
            15 => Self::typed_file_stream_hash_raw(&event, timestamp),
            23 => Self::typed_file_delete_raw(&event, timestamp),
            4624 | 4625 => Self::typed_security_logon_raw(&event, event_id, timestamp),
            4688 => Self::typed_security_process_create_raw(&event, timestamp),
            4689 => Self::typed_security_process_terminated_raw(&event, timestamp),
            4663 => Self::typed_security_object_access_raw(&event, timestamp),
            5145 => Self::typed_security_network_share_raw(&event, timestamp),
            5156 => Self::typed_security_wfp_connection_raw(&event, timestamp),
            4104 => Self::typed_powershell_script_block_raw(&event, timestamp),
            _ => None,
        }
    }

    fn try_parse_typed_with_scratch(
        line: &str,
        scratch: &mut Vec<u8>,
    ) -> Option<Vec<ParsedTriple>> {
        scratch.clear();
        scratch.extend_from_slice(line.as_bytes());
        let event: SysmonEventTyped<'_> = simd_json::serde::from_slice(scratch).ok()?;
        let event_id = event.event_id?;
        let timestamp = event
            .utc_time
            .or(event.event_time)
            .or(event.timestamp_at)
            .and_then(Self::parse_timestamp)
            .unwrap_or(0);
        match event_id {
            1 => Self::typed_process_create(&event, timestamp),
            3 => Self::typed_network_connection(&event, timestamp),
            5 => Self::typed_process_terminated(&event, timestamp),
            7 => Self::typed_image_load(&event, timestamp),
            8 => Self::typed_create_remote_thread(&event, timestamp),
            11 => Self::typed_file_create(&event, timestamp),
            12 | 13 => Self::typed_registry_event(&event, timestamp),
            15 => Self::typed_file_stream_hash(&event, timestamp),
            23 => Self::typed_file_delete(&event, timestamp),
            // Windows Security.
            4624 | 4625 => Self::typed_security_logon(&event, event_id, timestamp),
            4688 => Self::typed_security_process_create(&event, timestamp),
            4689 => Self::typed_security_process_terminated(&event, timestamp),
            4663 => Self::typed_security_object_access(&event, timestamp),
            5145 => Self::typed_security_network_share(&event, timestamp),
            5156 => Self::typed_security_wfp_connection(&event, timestamp),
            // PowerShell.
            4104 => Self::typed_powershell_script_block(&event, timestamp),
            _ => None,
        }
    }

    /// Raw-event variant of `typed_process_create`. Skips the
    /// `Entity`/`Relation` struct + nested HashMap allocations the
    /// legacy path pays per-event. Critically, when both the user
    /// and parent triples are emitted, the child-process metadata
    /// is populated only on the first event — the writer's
    /// `merge_metadata` already deduplicates by entity id, so the
    /// second event can carry an empty `dst_metadata` and skip the
    /// HashMap deep-clone the legacy `child.clone()` performed.
    #[inline]
    fn typed_process_create_raw(
        event: &SysmonEventTyped<'_>,
        timestamp: i64,
    ) -> Option<Vec<crate::parser::RawIngestEvent>> {
        use crate::parser::RawIngestEvent;
        use std::collections::HashMap;

        let image = event.image?;
        let mut events = Vec::with_capacity(2);

        let mut child_metadata: HashMap<String, String> = HashMap::new();
        if let Some(pid) = event.process_id {
            child_metadata.insert("pid".into(), pid.to_string());
        }
        if let Some(cmd) = event.command_line {
            child_metadata.insert("cmdline".into(), cmd.into());
        }
        if let Some(comp) = event.computer {
            child_metadata.insert("computer".into(), comp.into());
        }

        let mut child_meta_consumed = false;
        if let Some(user_name) = event.user {
            let dst_meta = std::mem::take(&mut child_metadata);
            child_meta_consumed = true;
            events.push(RawIngestEvent {
                src_id: user_name.into(),
                src_type: EntityType::User,
                src_metadata: HashMap::new(),
                dst_id: image.into(),
                dst_type: EntityType::Process,
                dst_metadata: dst_meta,
                rel_type: RelationType::Execute,
                rel_metadata: HashMap::new(),
                timestamp,
            });
        }
        if let Some(parent_image) = event.parent_image {
            let mut parent_meta: HashMap<String, String> = HashMap::new();
            if let Some(ppid) = event.parent_process_id {
                parent_meta.insert("pid".into(), ppid.to_string());
            }
            let dst_meta = if child_meta_consumed {
                HashMap::new()
            } else {
                std::mem::take(&mut child_metadata)
            };
            events.push(RawIngestEvent {
                src_id: parent_image.into(),
                src_type: EntityType::Process,
                src_metadata: parent_meta,
                dst_id: image.into(),
                dst_type: EntityType::Process,
                dst_metadata: dst_meta,
                rel_type: RelationType::Spawn,
                rel_metadata: HashMap::new(),
                timestamp,
            });
        }
        Some(events)
    }

    #[inline]
    fn typed_process_create(
        event: &SysmonEventTyped<'_>,
        timestamp: i64,
    ) -> Option<Vec<ParsedTriple>> {
        let image = event.image?;
        let mut triples = Vec::with_capacity(2);
        let mut child = Entity::new(image, EntityType::Process);
        if let Some(pid) = event.process_id {
            child.metadata.insert("pid".into(), pid.to_string());
        }
        if let Some(cmd) = event.command_line {
            child.metadata.insert("cmdline".into(), cmd.into());
        }
        if let Some(comp) = event.computer {
            child.metadata.insert("computer".into(), comp.into());
        }
        if let Some(user_name) = event.user {
            let user_entity = Entity::new(user_name, EntityType::User);
            let rel =
                Relation::new(&user_entity.id, &child.id, RelationType::Execute, timestamp);
            triples.push((user_entity, rel, child.clone()));
        }
        if let Some(parent_image) = event.parent_image {
            let mut parent = Entity::new(parent_image, EntityType::Process);
            if let Some(ppid) = event.parent_process_id {
                parent.metadata.insert("pid".into(), ppid.to_string());
            }
            let rel = Relation::new(&parent.id, &child.id, RelationType::Spawn, timestamp);
            triples.push((parent, rel, child));
        }
        Some(triples)
    }

    /// Raw-event variants for the long-tail Sysmon EventIDs. Each
    /// mirrors its `typed_*` legacy counterpart but emits
    /// `RawIngestEvent`s without the Entity/Relation struct
    /// allocations. Where a handler emits multiple triples sharing a
    /// dst entity, the metadata is moved into the first event and
    /// later emissions carry empty `dst_metadata` — the writer's
    /// `merge_metadata` already dedupes by entity id.

    #[inline]
    fn typed_network_connection_raw(
        event: &SysmonEventTyped<'_>,
        timestamp: i64,
    ) -> Option<Vec<crate::parser::RawIngestEvent>> {
        use crate::parser::RawIngestEvent;
        use std::collections::HashMap;
        let dest_ip = event.destination_ip?;
        let source_name = event
            .computer
            .or(event.hostname)
            .or(event.source_hostname)
            .unwrap_or("unknown-host");

        let mut source_meta: HashMap<String, String> = HashMap::new();
        if let Some(s) = event.source_ip {
            source_meta.insert("source_ip".into(), s.into());
        }
        if let Some(s) = event.source_port {
            source_meta.insert("source_port".into(), s.into());
        }
        let mut dest_meta: HashMap<String, String> = HashMap::new();
        if let Some(s) = event.destination_port {
            dest_meta.insert("dest_port".into(), s.into());
        }
        if let Some(s) = event.destination_hostname {
            dest_meta.insert("hostname".into(), s.into());
        }
        if let Some(s) = event.protocol {
            dest_meta.insert("protocol".into(), s.into());
        }

        let mut rel_meta: HashMap<String, String> = HashMap::new();
        if let Some(image) = event.image {
            rel_meta.insert("image".into(), image.into());
        }

        let mut events = Vec::with_capacity(2);
        events.push(RawIngestEvent {
            src_id: source_name.into(),
            src_type: EntityType::Host,
            src_metadata: source_meta,
            dst_id: dest_ip.into(),
            dst_type: EntityType::IP,
            dst_metadata: std::mem::take(&mut dest_meta),
            rel_type: RelationType::Connect,
            rel_metadata: rel_meta,
            timestamp,
        });
        if let Some(image) = event.image {
            events.push(RawIngestEvent {
                src_id: image.into(),
                src_type: EntityType::Process,
                src_metadata: HashMap::new(),
                dst_id: dest_ip.into(),
                dst_type: EntityType::IP,
                dst_metadata: HashMap::new(),
                rel_type: RelationType::Connect,
                rel_metadata: HashMap::new(),
                timestamp,
            });
        }
        Some(events)
    }

    #[inline]
    fn typed_image_load_raw(
        event: &SysmonEventTyped<'_>,
        timestamp: i64,
    ) -> Option<Vec<crate::parser::RawIngestEvent>> {
        use crate::parser::RawIngestEvent;
        use std::collections::HashMap;
        let image = event.image?;
        let image_loaded = event.image_loaded?;
        let mut file_meta: HashMap<String, String> = HashMap::new();
        if let Some(s) = event.signed {
            file_meta.insert("signed".into(), s.into());
        }
        if let Some(s) = event.signature_status {
            file_meta.insert("signature_status".into(), s.into());
        }
        if let Some(s) = event.hashes {
            file_meta.insert("hashes".into(), s.into());
        }
        Some(vec![RawIngestEvent {
            src_id: image.into(),
            src_type: EntityType::Process,
            src_metadata: HashMap::new(),
            dst_id: image_loaded.into(),
            dst_type: EntityType::File,
            dst_metadata: file_meta,
            rel_type: RelationType::Read,
            rel_metadata: HashMap::new(),
            timestamp,
        }])
    }

    #[inline]
    fn typed_file_create_raw(
        event: &SysmonEventTyped<'_>,
        timestamp: i64,
    ) -> Option<Vec<crate::parser::RawIngestEvent>> {
        use crate::parser::RawIngestEvent;
        use std::collections::HashMap;
        let image = event.image?;
        let target = event.target_filename?;
        let mut file_meta: HashMap<String, String> = HashMap::new();
        if let Some(s) = event.hashes {
            file_meta.insert("hashes".into(), s.into());
        }
        Some(vec![RawIngestEvent {
            src_id: image.into(),
            src_type: EntityType::Process,
            src_metadata: HashMap::new(),
            dst_id: target.into(),
            dst_type: EntityType::File,
            dst_metadata: file_meta,
            rel_type: RelationType::Write,
            rel_metadata: HashMap::new(),
            timestamp,
        }])
    }

    #[inline]
    fn typed_process_terminated_raw(
        event: &SysmonEventTyped<'_>,
        timestamp: i64,
    ) -> Option<Vec<crate::parser::RawIngestEvent>> {
        use crate::parser::RawIngestEvent;
        use std::collections::HashMap;
        let image = event.image?;
        let host_name = event.computer.or(event.hostname).unwrap_or("unknown-host");
        let mut process_meta: HashMap<String, String> = HashMap::new();
        if let Some(pid) = event.process_id {
            process_meta.insert("pid".into(), pid.to_string());
        }
        Some(vec![RawIngestEvent {
            src_id: image.into(),
            src_type: EntityType::Process,
            src_metadata: process_meta,
            dst_id: host_name.into(),
            dst_type: EntityType::Host,
            dst_metadata: HashMap::new(),
            rel_type: RelationType::Delete,
            rel_metadata: HashMap::new(),
            timestamp,
        }])
    }

    #[inline]
    fn typed_create_remote_thread_raw(
        event: &SysmonEventTyped<'_>,
        timestamp: i64,
    ) -> Option<Vec<crate::parser::RawIngestEvent>> {
        use crate::parser::RawIngestEvent;
        use std::collections::HashMap;
        let source_image = event.source_image?;
        let target_image = event.target_image?;
        let mut rel_meta: HashMap<String, String> = HashMap::new();
        if let Some(s) = event.start_address {
            rel_meta.insert("start_address".into(), s.into());
        }
        if let Some(s) = event.new_thread_id {
            rel_meta.insert("new_thread_id".into(), s.into());
        }
        if let Some(s) = event.start_module {
            rel_meta.insert("start_module".into(), s.into());
        }
        Some(vec![RawIngestEvent {
            src_id: source_image.into(),
            src_type: EntityType::Process,
            src_metadata: HashMap::new(),
            dst_id: target_image.into(),
            dst_type: EntityType::Process,
            dst_metadata: HashMap::new(),
            rel_type: RelationType::Execute,
            rel_metadata: rel_meta,
            timestamp,
        }])
    }

    #[inline]
    fn typed_registry_event_raw(
        event: &SysmonEventTyped<'_>,
        timestamp: i64,
    ) -> Option<Vec<crate::parser::RawIngestEvent>> {
        use crate::parser::RawIngestEvent;
        use std::collections::HashMap;
        let image = event.image?;
        let target_object = event.target_object?;
        let mut rel_meta: HashMap<String, String> = HashMap::new();
        if let Some(s) = event.event_type_str {
            rel_meta.insert("event_type".into(), s.into());
        }
        if let Some(s) = event.details {
            rel_meta.insert("details".into(), s.into());
        }
        Some(vec![RawIngestEvent {
            src_id: image.into(),
            src_type: EntityType::Process,
            src_metadata: HashMap::new(),
            dst_id: target_object.into(),
            dst_type: EntityType::Registry,
            dst_metadata: HashMap::new(),
            rel_type: RelationType::Modify,
            rel_metadata: rel_meta,
            timestamp,
        }])
    }

    #[inline]
    fn typed_file_stream_hash_raw(
        event: &SysmonEventTyped<'_>,
        timestamp: i64,
    ) -> Option<Vec<crate::parser::RawIngestEvent>> {
        use crate::parser::RawIngestEvent;
        use std::collections::HashMap;
        let image = event.image?;
        let target = event.target_filename?;
        let mut file_meta: HashMap<String, String> = HashMap::new();
        if let Some(s) = event.hash_single {
            file_meta.insert("hash".into(), s.into());
        }
        Some(vec![RawIngestEvent {
            src_id: image.into(),
            src_type: EntityType::Process,
            src_metadata: HashMap::new(),
            dst_id: target.into(),
            dst_type: EntityType::File,
            dst_metadata: file_meta,
            rel_type: RelationType::Write,
            rel_metadata: HashMap::new(),
            timestamp,
        }])
    }

    #[inline]
    fn typed_file_delete_raw(
        event: &SysmonEventTyped<'_>,
        timestamp: i64,
    ) -> Option<Vec<crate::parser::RawIngestEvent>> {
        use crate::parser::RawIngestEvent;
        use std::collections::HashMap;
        let image = event.image?;
        let target = event.target_filename?;
        let mut file_meta: HashMap<String, String> = HashMap::new();
        if let Some(s) = event.hashes {
            file_meta.insert("hashes".into(), s.into());
        }
        Some(vec![RawIngestEvent {
            src_id: image.into(),
            src_type: EntityType::Process,
            src_metadata: HashMap::new(),
            dst_id: target.into(),
            dst_type: EntityType::File,
            dst_metadata: file_meta,
            rel_type: RelationType::Delete,
            rel_metadata: HashMap::new(),
            timestamp,
        }])
    }

    #[inline]
    fn typed_network_connection(
        event: &SysmonEventTyped<'_>,
        timestamp: i64,
    ) -> Option<Vec<ParsedTriple>> {
        let dest_ip = event.destination_ip?;
        let source_name = event
            .computer
            .or(event.hostname)
            .or(event.source_hostname)
            .unwrap_or("unknown-host");
        let mut source = Entity::new(source_name, EntityType::Host);
        if let Some(s) = event.source_ip {
            source.metadata.insert("source_ip".into(), s.into());
        }
        if let Some(s) = event.source_port {
            source.metadata.insert("source_port".into(), s.into());
        }
        let mut dest = Entity::new(dest_ip, EntityType::IP);
        if let Some(s) = event.destination_port {
            dest.metadata.insert("dest_port".into(), s.into());
        }
        if let Some(s) = event.destination_hostname {
            dest.metadata.insert("hostname".into(), s.into());
        }
        if let Some(s) = event.protocol {
            dest.metadata.insert("protocol".into(), s.into());
        }
        let mut rel = Relation::new(&source.id, &dest.id, RelationType::Connect, timestamp);
        if let Some(image) = event.image {
            rel.metadata.insert("image".into(), image.into());
        }
        let mut triples = vec![(source, rel, dest.clone())];
        if let Some(image) = event.image {
            let process = Entity::new(image, EntityType::Process);
            let rel2 = Relation::new(&process.id, &dest.id, RelationType::Connect, timestamp);
            triples.push((process, rel2, dest));
        }
        Some(triples)
    }

    #[inline]
    fn typed_image_load(
        event: &SysmonEventTyped<'_>,
        timestamp: i64,
    ) -> Option<Vec<ParsedTriple>> {
        let image = event.image?;
        let image_loaded = event.image_loaded?;
        let process = Entity::new(image, EntityType::Process);
        let mut file = Entity::new(image_loaded, EntityType::File);
        if let Some(s) = event.signed {
            file.metadata.insert("signed".into(), s.into());
        }
        if let Some(s) = event.signature_status {
            file.metadata.insert("signature_status".into(), s.into());
        }
        if let Some(s) = event.hashes {
            file.metadata.insert("hashes".into(), s.into());
        }
        let rel = Relation::new(&process.id, &file.id, RelationType::Read, timestamp);
        Some(vec![(process, rel, file)])
    }

    #[inline]
    fn typed_file_create(
        event: &SysmonEventTyped<'_>,
        timestamp: i64,
    ) -> Option<Vec<ParsedTriple>> {
        let image = event.image?;
        let target = event.target_filename?;
        let process = Entity::new(image, EntityType::Process);
        let mut file = Entity::new(target, EntityType::File);
        if let Some(s) = event.hashes {
            file.metadata.insert("hashes".into(), s.into());
        }
        let rel = Relation::new(&process.id, &file.id, RelationType::Write, timestamp);
        Some(vec![(process, rel, file)])
    }

    #[inline]
    fn typed_process_terminated(
        event: &SysmonEventTyped<'_>,
        timestamp: i64,
    ) -> Option<Vec<ParsedTriple>> {
        let image = event.image?;
        let host_name = event
            .computer
            .or(event.hostname)
            .unwrap_or("unknown-host");
        let mut process = Entity::new(image, EntityType::Process);
        if let Some(pid) = event.process_id {
            process.metadata.insert("pid".into(), pid.to_string());
        }
        let host = Entity::new(host_name, EntityType::Host);
        let rel = Relation::new(&process.id, &host.id, RelationType::Delete, timestamp);
        Some(vec![(process, rel, host)])
    }

    #[inline]
    fn typed_create_remote_thread(
        event: &SysmonEventTyped<'_>,
        timestamp: i64,
    ) -> Option<Vec<ParsedTriple>> {
        let source_image = event.source_image?;
        let target_image = event.target_image?;
        let source = Entity::new(source_image, EntityType::Process);
        let target = Entity::new(target_image, EntityType::Process);
        let mut rel = Relation::new(&source.id, &target.id, RelationType::Execute, timestamp);
        if let Some(s) = event.start_address {
            rel.metadata.insert("start_address".into(), s.into());
        }
        if let Some(s) = event.new_thread_id {
            rel.metadata.insert("new_thread_id".into(), s.into());
        }
        if let Some(s) = event.start_module {
            rel.metadata.insert("start_module".into(), s.into());
        }
        Some(vec![(source, rel, target)])
    }

    #[inline]
    fn typed_registry_event(
        event: &SysmonEventTyped<'_>,
        timestamp: i64,
    ) -> Option<Vec<ParsedTriple>> {
        let image = event.image?;
        let target_object = event.target_object?;
        let process = Entity::new(image, EntityType::Process);
        let registry = Entity::new(target_object, EntityType::Registry);
        let mut rel = Relation::new(&process.id, &registry.id, RelationType::Modify, timestamp);
        if let Some(s) = event.event_type_str {
            rel.metadata.insert("event_type".into(), s.into());
        }
        if let Some(s) = event.details {
            rel.metadata.insert("details".into(), s.into());
        }
        Some(vec![(process, rel, registry)])
    }

    #[inline]
    fn typed_file_stream_hash(
        event: &SysmonEventTyped<'_>,
        timestamp: i64,
    ) -> Option<Vec<ParsedTriple>> {
        let image = event.image?;
        let target = event.target_filename?;
        let process = Entity::new(image, EntityType::Process);
        let mut file = Entity::new(target, EntityType::File);
        if let Some(s) = event.hash_single {
            file.metadata.insert("hash".into(), s.into());
        }
        let rel = Relation::new(&process.id, &file.id, RelationType::Write, timestamp);
        Some(vec![(process, rel, file)])
    }

    #[inline]
    fn typed_file_delete(
        event: &SysmonEventTyped<'_>,
        timestamp: i64,
    ) -> Option<Vec<ParsedTriple>> {
        let image = event.image?;
        let target = event.target_filename?;
        let process = Entity::new(image, EntityType::Process);
        let mut file = Entity::new(target, EntityType::File);
        if let Some(s) = event.hashes {
            file.metadata.insert("hashes".into(), s.into());
        }
        let rel = Relation::new(&process.id, &file.id, RelationType::Delete, timestamp);
        Some(vec![(process, rel, file)])
    }

    /// Helper: build `DOMAIN\user` from an optional domain + user.
    /// Empty / `-` domain falls back to bare username (matches the
    /// legacy `parse_security_*` semantics).
    #[inline]
    fn build_user_id(user: &str, domain: Option<&str>) -> String {
        match domain {
            Some(d) if !d.is_empty() && !d.eq_ignore_ascii_case("-") => {
                format!("{}\\{}", d, user)
            }
            _ => user.to_string(),
        }
    }

    /// Raw-event variants for Windows Security + PowerShell EventIDs.
    /// Same shape as the Sysmon long-tail raw migrations: skip
    /// `Entity`/`Relation` struct allocs, build metadata HashMaps
    /// only on the side that actually owns metadata, and apply the
    /// dst-metadata-skip-on-second-emission trick when a handler
    /// emits multiple triples that share a dst (4688 child process).

    #[inline]
    fn typed_security_logon_raw(
        event: &SysmonEventTyped<'_>,
        event_id: u64,
        timestamp: i64,
    ) -> Option<Vec<crate::parser::RawIngestEvent>> {
        use crate::parser::RawIngestEvent;
        use std::collections::HashMap;
        let user_name = event.target_user_name?;
        let user_id = Self::build_user_id(user_name, event.target_domain_name);
        let host_name = event.computer.or(event.hostname).unwrap_or("unknown-host");
        let mut rel_meta: HashMap<String, String> = HashMap::new();
        if let Some(lt) = &event.logon_type {
            let s = lt.as_string();
            if !s.is_empty() {
                rel_meta.insert("logon_type".into(), s);
            }
        }
        if let Some(ip) = event.ip_address {
            if ip != "-" {
                rel_meta.insert("ip_address".into(), ip.into());
            }
        }
        if event_id == 4625 {
            rel_meta.insert("success".into(), "false".into());
        }
        Some(vec![RawIngestEvent {
            src_id: user_id,
            src_type: EntityType::User,
            src_metadata: HashMap::new(),
            dst_id: host_name.into(),
            dst_type: EntityType::Host,
            dst_metadata: HashMap::new(),
            rel_type: RelationType::Auth,
            rel_metadata: rel_meta,
            timestamp,
        }])
    }

    #[inline]
    fn typed_security_process_create_raw(
        event: &SysmonEventTyped<'_>,
        timestamp: i64,
    ) -> Option<Vec<crate::parser::RawIngestEvent>> {
        use crate::parser::RawIngestEvent;
        use std::collections::HashMap;
        let new_process = event.new_process_name?;

        let mut child_metadata: HashMap<String, String> = HashMap::new();
        if let Some(cmd) = event.command_line {
            child_metadata.insert("cmdline".into(), cmd.into());
        }
        if let Some(comp) = event.computer.or(event.hostname) {
            child_metadata.insert("computer".into(), comp.into());
        }

        let mut events = Vec::with_capacity(2);
        let mut child_meta_consumed = false;
        if let Some(user_name) = event.subject_user_name {
            let user_id = Self::build_user_id(user_name, event.subject_domain_name);
            let dst_meta = std::mem::take(&mut child_metadata);
            child_meta_consumed = true;
            events.push(RawIngestEvent {
                src_id: user_id,
                src_type: EntityType::User,
                src_metadata: HashMap::new(),
                dst_id: new_process.into(),
                dst_type: EntityType::Process,
                dst_metadata: dst_meta,
                rel_type: RelationType::Execute,
                rel_metadata: HashMap::new(),
                timestamp,
            });
        }
        if let Some(parent_name) = event.parent_process_name {
            let dst_meta = if child_meta_consumed {
                HashMap::new()
            } else {
                std::mem::take(&mut child_metadata)
            };
            events.push(RawIngestEvent {
                src_id: parent_name.into(),
                src_type: EntityType::Process,
                src_metadata: HashMap::new(),
                dst_id: new_process.into(),
                dst_type: EntityType::Process,
                dst_metadata: dst_meta,
                rel_type: RelationType::Spawn,
                rel_metadata: HashMap::new(),
                timestamp,
            });
        }
        Some(events)
    }

    #[inline]
    fn typed_security_process_terminated_raw(
        event: &SysmonEventTyped<'_>,
        timestamp: i64,
    ) -> Option<Vec<crate::parser::RawIngestEvent>> {
        use crate::parser::RawIngestEvent;
        use std::collections::HashMap;
        let process_name = event.process_name?;
        let host_name = event.computer.or(event.hostname).unwrap_or("unknown-host");
        Some(vec![RawIngestEvent {
            src_id: process_name.into(),
            src_type: EntityType::Process,
            src_metadata: HashMap::new(),
            dst_id: host_name.into(),
            dst_type: EntityType::Host,
            dst_metadata: HashMap::new(),
            rel_type: RelationType::Delete,
            rel_metadata: HashMap::new(),
            timestamp,
        }])
    }

    #[inline]
    fn typed_security_object_access_raw(
        event: &SysmonEventTyped<'_>,
        timestamp: i64,
    ) -> Option<Vec<crate::parser::RawIngestEvent>> {
        use crate::parser::RawIngestEvent;
        use std::collections::HashMap;
        let process_name = event.process_name?;
        let object_name = event.object_name?;
        let target_type = if event.object_type == Some("Key") {
            EntityType::Registry
        } else {
            EntityType::File
        };
        Some(vec![RawIngestEvent {
            src_id: process_name.into(),
            src_type: EntityType::Process,
            src_metadata: HashMap::new(),
            dst_id: object_name.into(),
            dst_type: target_type,
            dst_metadata: HashMap::new(),
            rel_type: RelationType::Read,
            rel_metadata: HashMap::new(),
            timestamp,
        }])
    }

    #[inline]
    fn typed_security_network_share_raw(
        event: &SysmonEventTyped<'_>,
        timestamp: i64,
    ) -> Option<Vec<crate::parser::RawIngestEvent>> {
        use crate::parser::RawIngestEvent;
        use std::collections::HashMap;
        let user_name = event.subject_user_name?;
        let share_name = event.share_name.unwrap_or("");
        let relative_target = event.relative_target_name.unwrap_or("");
        let path = if !share_name.is_empty() && !relative_target.is_empty() {
            format!("{}\\{}", share_name, relative_target)
        } else if !share_name.is_empty() {
            share_name.to_string()
        } else {
            return None;
        };
        let user_id = Self::build_user_id(user_name, event.subject_domain_name);
        let mut file_meta: HashMap<String, String> = HashMap::new();
        if let Some(ip) = event.ip_address {
            file_meta.insert("ip_address".into(), ip.into());
        }
        Some(vec![RawIngestEvent {
            src_id: user_id,
            src_type: EntityType::User,
            src_metadata: HashMap::new(),
            dst_id: path,
            dst_type: EntityType::File,
            dst_metadata: file_meta,
            rel_type: RelationType::Read,
            rel_metadata: HashMap::new(),
            timestamp,
        }])
    }

    #[inline]
    fn typed_security_wfp_connection_raw(
        event: &SysmonEventTyped<'_>,
        timestamp: i64,
    ) -> Option<Vec<crate::parser::RawIngestEvent>> {
        use crate::parser::RawIngestEvent;
        use std::collections::HashMap;
        let application = event.application?;
        let dest_addr = event.dest_address?;
        let mut ip_meta: HashMap<String, String> = HashMap::new();
        if let Some(s) = event.dest_port {
            ip_meta.insert("dest_port".into(), s.into());
        }
        if let Some(s) = event.source_port {
            ip_meta.insert("source_port".into(), s.into());
        }
        if let Some(s) = event.protocol {
            ip_meta.insert("protocol".into(), s.into());
        }
        let mut rel_meta: HashMap<String, String> = HashMap::new();
        if let Some(s) = event.source_address {
            rel_meta.insert("source_address".into(), s.into());
        }
        Some(vec![RawIngestEvent {
            src_id: application.into(),
            src_type: EntityType::Process,
            src_metadata: HashMap::new(),
            dst_id: dest_addr.into(),
            dst_type: EntityType::IP,
            dst_metadata: ip_meta,
            rel_type: RelationType::Connect,
            rel_metadata: rel_meta,
            timestamp,
        }])
    }

    #[inline]
    fn typed_powershell_script_block_raw(
        event: &SysmonEventTyped<'_>,
        timestamp: i64,
    ) -> Option<Vec<crate::parser::RawIngestEvent>> {
        use crate::parser::RawIngestEvent;
        use std::collections::HashMap;
        let host_name = event.computer.or(event.hostname).unwrap_or("unknown-host");
        let mut process_meta: HashMap<String, String> = HashMap::new();
        if let Some(script_text) = event.script_block_text {
            let preview: String = script_text.chars().take(200).collect();
            process_meta.insert("script_preview".into(), preview);
        }
        if let Some(sbid) = event.script_block_id {
            process_meta.insert("script_block_id".into(), sbid.into());
        }
        Some(vec![RawIngestEvent {
            src_id: host_name.into(),
            src_type: EntityType::Host,
            src_metadata: HashMap::new(),
            dst_id: "powershell.exe".into(),
            dst_type: EntityType::Process,
            dst_metadata: process_meta,
            rel_type: RelationType::Execute,
            rel_metadata: HashMap::new(),
            timestamp,
        }])
    }

    #[inline]
    fn typed_security_logon(
        event: &SysmonEventTyped<'_>,
        event_id: u64,
        timestamp: i64,
    ) -> Option<Vec<ParsedTriple>> {
        let user_name = event.target_user_name?;
        let user_id = Self::build_user_id(user_name, event.target_domain_name);
        let host_name = event
            .computer
            .or(event.hostname)
            .unwrap_or("unknown-host");
        let user = Entity::new(&user_id, EntityType::User);
        let host = Entity::new(host_name, EntityType::Host);
        let mut rel = Relation::new(&user.id, &host.id, RelationType::Auth, timestamp);
        if let Some(lt) = &event.logon_type {
            let s = lt.as_string();
            if !s.is_empty() {
                rel.metadata.insert("logon_type".into(), s);
            }
        }
        if let Some(ip) = event.ip_address {
            if ip != "-" {
                rel.metadata.insert("ip_address".into(), ip.into());
            }
        }
        if event_id == 4625 {
            rel.metadata.insert("success".into(), "false".into());
        }
        Some(vec![(user, rel, host)])
    }

    #[inline]
    fn typed_security_process_create(
        event: &SysmonEventTyped<'_>,
        timestamp: i64,
    ) -> Option<Vec<ParsedTriple>> {
        let new_process = event.new_process_name?;
        let mut triples = Vec::with_capacity(2);
        let mut child = Entity::new(new_process, EntityType::Process);
        if let Some(cmd) = event.command_line {
            child.metadata.insert("cmdline".into(), cmd.into());
        }
        if let Some(comp) = event.computer.or(event.hostname) {
            child.metadata.insert("computer".into(), comp.into());
        }
        if let Some(user_name) = event.subject_user_name {
            let user_id = Self::build_user_id(user_name, event.subject_domain_name);
            let user = Entity::new(&user_id, EntityType::User);
            let rel = Relation::new(&user.id, &child.id, RelationType::Execute, timestamp);
            triples.push((user, rel, child.clone()));
        }
        if let Some(parent_name) = event.parent_process_name {
            let parent = Entity::new(parent_name, EntityType::Process);
            let rel = Relation::new(&parent.id, &child.id, RelationType::Spawn, timestamp);
            triples.push((parent, rel, child));
        }
        Some(triples)
    }

    #[inline]
    fn typed_security_process_terminated(
        event: &SysmonEventTyped<'_>,
        timestamp: i64,
    ) -> Option<Vec<ParsedTriple>> {
        let process_name = event.process_name?;
        let host_name = event
            .computer
            .or(event.hostname)
            .unwrap_or("unknown-host");
        let process = Entity::new(process_name, EntityType::Process);
        let host = Entity::new(host_name, EntityType::Host);
        let rel = Relation::new(&process.id, &host.id, RelationType::Delete, timestamp);
        Some(vec![(process, rel, host)])
    }

    #[inline]
    fn typed_security_object_access(
        event: &SysmonEventTyped<'_>,
        timestamp: i64,
    ) -> Option<Vec<ParsedTriple>> {
        let process_name = event.process_name?;
        let object_name = event.object_name?;
        let process = Entity::new(process_name, EntityType::Process);
        let target = if event.object_type == Some("Key") {
            Entity::new(object_name, EntityType::Registry)
        } else {
            Entity::new(object_name, EntityType::File)
        };
        let rel = Relation::new(&process.id, &target.id, RelationType::Read, timestamp);
        Some(vec![(process, rel, target)])
    }

    #[inline]
    fn typed_security_network_share(
        event: &SysmonEventTyped<'_>,
        timestamp: i64,
    ) -> Option<Vec<ParsedTriple>> {
        let user_name = event.subject_user_name?;
        let share_name = event.share_name.unwrap_or("");
        let relative_target = event.relative_target_name.unwrap_or("");
        let path = if !share_name.is_empty() && !relative_target.is_empty() {
            format!("{}\\{}", share_name, relative_target)
        } else if !share_name.is_empty() {
            share_name.to_string()
        } else {
            return None;
        };
        let user_id = Self::build_user_id(user_name, event.subject_domain_name);
        let user = Entity::new(&user_id, EntityType::User);
        let mut file = Entity::new(&path, EntityType::File);
        if let Some(ip) = event.ip_address {
            file.metadata.insert("ip_address".into(), ip.into());
        }
        let rel = Relation::new(&user.id, &file.id, RelationType::Read, timestamp);
        Some(vec![(user, rel, file)])
    }

    #[inline]
    fn typed_security_wfp_connection(
        event: &SysmonEventTyped<'_>,
        timestamp: i64,
    ) -> Option<Vec<ParsedTriple>> {
        let application = event.application?;
        let dest_addr = event.dest_address?;
        let process = Entity::new(application, EntityType::Process);
        let mut ip = Entity::new(dest_addr, EntityType::IP);
        if let Some(s) = event.dest_port {
            ip.metadata.insert("dest_port".into(), s.into());
        }
        if let Some(s) = event.source_port {
            ip.metadata.insert("source_port".into(), s.into());
        }
        if let Some(s) = event.protocol {
            ip.metadata.insert("protocol".into(), s.into());
        }
        let mut rel = Relation::new(&process.id, &ip.id, RelationType::Connect, timestamp);
        if let Some(s) = event.source_address {
            rel.metadata.insert("source_address".into(), s.into());
        }
        Some(vec![(process, rel, ip)])
    }

    #[inline]
    fn typed_powershell_script_block(
        event: &SysmonEventTyped<'_>,
        timestamp: i64,
    ) -> Option<Vec<ParsedTriple>> {
        let host_name = event
            .computer
            .or(event.hostname)
            .unwrap_or("unknown-host");
        let host = Entity::new(host_name, EntityType::Host);
        let mut process = Entity::new("powershell.exe", EntityType::Process);
        if let Some(script_text) = event.script_block_text {
            let preview: String = script_text.chars().take(200).collect();
            process.metadata.insert("script_preview".into(), preview);
        }
        if let Some(sbid) = event.script_block_id {
            process.metadata.insert("script_block_id".into(), sbid.into());
        }
        let rel = Relation::new(&host.id, &process.id, RelationType::Execute, timestamp);
        Some(vec![(host, rel, process)])
    }

    /// Decodes the input into a `Vec<Value>` using the same JSON-array +
    /// NDJSON fallback logic `parse` uses, so stats and triples see the
    /// exact same row stream.
    ///
    /// Hot-path notes:
    /// - simd-json mutates its input buffer in place (string offsets
    ///   are rewritten), so each line needs an owned `Vec<u8>` for the
    ///   parser to scribble on. We can't share one scratch across lines
    ///   because that would clobber the resulting `Value`s.
    /// - Rayon-parallelize the per-line decode: line iteration is
    ///   sequential but simd-json + serde reflection per line is the
    ///   expensive part, and each line is independent. `par_bridge` on
    ///   `lines()` gives rayon work without forcing a vector-collect
    ///   in the middle.
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
                simd_json::serde::from_slice::<Value>(&mut buf)
                    .ok()
                    .or_else(|| serde_json::from_str(line).ok())
            })
            .collect()
    }
}

impl LogParser for SysmonJsonParser {
    fn parse(&self, data: &str) -> Vec<ParsedTriple> {
        use rayon::prelude::*;
        let trimmed = data.trim();

        // JSON-array path: a single big parse, then parallelize the
        // typed conversion. The Vec<Value> materialization is
        // unavoidable here because simd-json's array-decode is one
        // call.
        if trimmed.starts_with('[') {
            let mut buf = trimmed.as_bytes().to_vec();
            if let Ok(events) = simd_json::serde::from_slice::<Vec<Value>>(&mut buf) {
                return events
                    .par_iter()
                    .flat_map(|event| Self::parse_event(event))
                    .collect();
            }
        }

        // NDJSON fast path: fuse line-parse and event-parse into a
        // single rayon pipeline. Each worker tries the typed path
        // first; on miss falls through to the legacy `Value` path
        // which handles every EventID. `map_init` gives each worker
        // a single `Vec<u8>` scratch buffer that survives across
        // every line that worker handles — saves one heap
        // allocation per line vs the prior `to_vec()` per line.
        trimmed
            .par_lines()
            .filter(|l| !l.trim().is_empty())
            .map_init(
                || Vec::<u8>::with_capacity(2048),
                |scratch, line| {
                    if let Some(triples) =
                        Self::try_parse_typed_with_scratch(line, scratch)
                    {
                        return triples;
                    }
                    scratch.clear();
                    scratch.extend_from_slice(line.as_bytes());
                    let event = simd_json::serde::from_slice::<Value>(scratch)
                        .ok()
                        .or_else(|| serde_json::from_str(line).ok());
                    event.map(|e| Self::parse_event(&e)).unwrap_or_default()
                },
            )
            .flat_map_iter(|v| v.into_iter())
            .collect()
    }

    fn parse_with_stats(&self, data: &str) -> (Vec<ParsedTriple>, crate::parser::ParseStats) {
        let events = Self::collect_events(data);
        crate::generic::parse_events_with_stats(&events, |ev| Self::parse_event(ev))
    }

    /// Raw-event override: NDJSON-only fast path that emits
    /// `RawIngestEvent`s for the migrated EventIDs (currently only
    /// EventID 1). Lines that miss the raw path fall through to the
    /// legacy `try_parse_typed_with_scratch` and are lifted into
    /// `RawIngestEvent` via `from_parsed_triple`.
    fn parse_raw(&self, data: &str) -> Vec<crate::parser::RawIngestEvent> {
        use rayon::prelude::*;
        let trimmed = data.trim();

        // JSON-array path: rare for ingest; just delegate via the
        // default lift-from-parse path.
        if trimmed.starts_with('[') {
            return self
                .parse(data)
                .into_iter()
                .map(crate::parser::RawIngestEvent::from_parsed_triple)
                .collect();
        }

        trimmed
            .par_lines()
            .filter(|l| !l.trim().is_empty())
            .map_init(
                || Vec::<u8>::with_capacity(2048),
                |scratch, line| {
                    if let Some(events) = Self::try_parse_typed_raw_with_scratch(line, scratch) {
                        return events;
                    }
                    if let Some(triples) = Self::try_parse_typed_with_scratch(line, scratch) {
                        return triples
                            .into_iter()
                            .map(crate::parser::RawIngestEvent::from_parsed_triple)
                            .collect();
                    }
                    scratch.clear();
                    scratch.extend_from_slice(line.as_bytes());
                    let event = simd_json::serde::from_slice::<Value>(scratch)
                        .ok()
                        .or_else(|| serde_json::from_str(line).ok());
                    event
                        .map(|e| {
                            Self::parse_event(&e)
                                .into_iter()
                                .map(crate::parser::RawIngestEvent::from_parsed_triple)
                                .collect()
                        })
                        .unwrap_or_default()
                },
            )
            .flat_map_iter(|v: Vec<crate::parser::RawIngestEvent>| v.into_iter())
            .collect()
    }

    /// Native raw-event-with-stats override. Uses the typed scratch
    /// fast-path (same as `parse_raw`) and accumulates only the
    /// minimal stats subset that doesn't require materializing a
    /// `serde_json::Value` per event:
    /// `rows_seen`, `rows_with_triples`, `rows_skipped`. The
    /// `per_field_occurrence`, `skip_reasons`, `skipped_samples`,
    /// and `drift` fields are left empty/None — callers that need
    /// those should call `parse_with_stats` instead.
    ///
    /// JSON-array inputs delegate to the legacy `parse_with_stats`
    /// + lift path to keep full stat fidelity (those inputs are
    /// rare for ingest and going through the stats path is fine).
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

        // Per-line: (events, produced_at_least_one_triple). Reduce
        // counts after the collect; events are flattened into the
        // returned Vec.
        let per_line: Vec<(Vec<crate::parser::RawIngestEvent>, bool)> = trimmed
            .par_lines()
            .filter(|l| !l.trim().is_empty())
            .map_init(
                || Vec::<u8>::with_capacity(2048),
                |scratch, line| {
                    if let Some(events) = Self::try_parse_typed_raw_with_scratch(line, scratch) {
                        let produced = !events.is_empty();
                        return (events, produced);
                    }
                    if let Some(triples) = Self::try_parse_typed_with_scratch(line, scratch) {
                        let produced = !triples.is_empty();
                        let events: Vec<_> = triples
                            .into_iter()
                            .map(crate::parser::RawIngestEvent::from_parsed_triple)
                            .collect();
                        return (events, produced);
                    }
                    scratch.clear();
                    scratch.extend_from_slice(line.as_bytes());
                    let parsed = simd_json::serde::from_slice::<Value>(scratch)
                        .ok()
                        .or_else(|| serde_json::from_str(line).ok());
                    let events: Vec<crate::parser::RawIngestEvent> = parsed
                        .map(|e| {
                            Self::parse_event(&e)
                                .into_iter()
                                .map(crate::parser::RawIngestEvent::from_parsed_triple)
                                .collect()
                        })
                        .unwrap_or_default();
                    let produced = !events.is_empty();
                    (events, produced)
                },
            )
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
        // per_field_occurrence, skip_reasons, skipped_samples, drift
        // intentionally left empty — see trait docstring.
        (all_events, stats)
    }
}
