use rayon::prelude::*;
use serde_json::Value;

use crate::entity::Entity;
use crate::parser::{LogParser, ParsedTriple};
use crate::relation::Relation;
use crate::types::{EntityType, RelationType};

/// Universal field-normalizing JSON parser.
///
/// Maps arbitrary JSON log fields to canonical names via case-insensitive
/// heuristics, then infers entity relationships from normalized fields.
/// Works with any JSON log schema — Sysmon, Sentinel, firewall, proxy, etc.
pub struct GenericParser;

/// Canonical field names after normalization.
pub struct NormalizedEvent {
    pub timestamp: i64,
    pub source_user: Option<String>,
    #[allow(dead_code)]
    pub target_user: Option<String>,
    pub source_ip: Option<String>,
    pub target_ip: Option<String>,
    pub source_host: Option<String>,
    pub source_process: Option<String>,
    pub parent_process: Option<String>,
    pub command_line: Option<String>,
    pub target_file: Option<String>,
    pub target_domain: Option<String>,
    pub target_url: Option<String>,
    pub target_registry: Option<String>,
    pub protocol: Option<String>,
    pub source_port: Option<String>,
    pub target_port: Option<String>,
}

impl GenericParser {
    /// Maps a field name (case-insensitive) to a canonical name.
    pub fn canonical_field(name: &str) -> Option<&'static str> {
        match name.to_lowercase().as_str() {
            // Timestamp
            "timestamp" | "utctime" | "timegenerated" | "eventtime" | "time"
            | "date" | "datetime" | "@timestamp" | "event_time" | "log_time" => {
                Some("timestamp")
            }

            // Source user
            "user" | "username" | "src_user" | "source_user" | "account_name"
            | "subjectusername" | "accountname" | "userprincipalname"
            | "initiatingprocessaccountname" | "actor" | "caller" => {
                Some("source_user")
            }

            // Target user
            "target_user" | "targetusername" | "dst_user" | "dest_user"
            | "targetaccountname" => Some("target_user"),

            // Source IP
            "sourceip" | "src_ip" | "source_ip" | "srcip" | "ipaddress"
            | "clientip" | "client_ip" | "callerip" | "caller_ip" | "src_addr"
            | "sourceaddress" => Some("source_ip"),

            // Target IP
            "destinationip" | "dst_ip" | "dest_ip" | "target_ip" | "dstip"
            | "remoteip" | "remote_ip" | "dst_addr" | "destinationaddress"
            | "server_ip" => Some("target_ip"),

            // Source host
            "computer" | "hostname" | "devicename" | "source_host" | "src_host"
            | "host" | "machine" | "workstation" | "device_name" | "agent_hostname" => {
                Some("source_host")
            }

            // Source process
            "image" | "process_name" | "newprocessname" | "filename"
            | "source_process" | "process" | "exe" | "executable"
            | "initiatingprocessfilename" => Some("source_process"),

            // Parent process
            "parentimage" | "parent_process" | "parentprocessname"
            | "initiatingprocessparentfilename" | "parent_exe" | "ppid_name" => {
                Some("parent_process")
            }

            // Command line
            "commandline" | "command_line" | "cmdline" | "processcommandline"
            | "cmd" | "command" | "initiatingprocesscommandline" => Some("command_line"),

            // Target file
            "targetfilename" | "objectname" | "file_path" | "filepath"
            | "folderpath" | "target_file" | "dest_file" | "file" | "path" => {
                Some("target_file")
            }

            // Target domain
            "queryname" | "domain" | "dns_query" | "target_domain" | "dest_domain"
            | "query" | "dnsquery" | "requested_domain" => Some("target_domain"),

            // Target URL
            "url" | "target_url" | "remoteurl" | "request_url" | "uri"
            | "dest_url" | "http_url" => Some("target_url"),

            // Target registry
            "registry_path" | "registry_key" | "targetobject" | "target_registry"
            | "registrykey" | "registryvaluename" => Some("target_registry"),

            // Protocol
            "protocol" | "proto" | "transport" | "network_protocol" => Some("protocol"),

            // Source port
            "sourceport" | "src_port" | "source_port" | "sport" | "localport"
            | "local_port" => Some("source_port"),

            // Target port
            "destinationport" | "dst_port" | "dest_port" | "target_port" | "dport"
            | "remoteport" | "remote_port" | "server_port" => Some("target_port"),

            // CEF extension keys
            "src" => Some("source_ip"),
            "dst" => Some("target_ip"),
            "suser" | "suid" => Some("source_user"),
            "duser" | "duid" => Some("target_user"),
            "dhost" | "shost" | "dvchost" => Some("source_host"),
            "fname" => Some("target_file"),
            "sproc" => Some("source_process"),
            "dproc" => Some("parent_process"),
            "request" | "requesturl" => Some("target_url"),
            "spt" => Some("source_port"),
            "dpt" => Some("target_port"),
            "rt" | "devicecustomdate1" => Some("timestamp"),

            _ => None,
        }
    }

    /// Maps a canonical field name to the suggested entity type for preview/UI.
    /// Returns "Skip" for metadata-only fields (timestamp, command_line, ports, protocol).
    pub fn canonical_to_entity_type(canonical: &str) -> &'static str {
        match canonical {
            "timestamp" | "command_line" | "protocol" | "source_port" | "target_port" => "Skip",
            "source_user" | "target_user" => "User",
            "source_ip" | "target_ip" => "IP",
            "source_host" => "Host",
            "source_process" | "parent_process" => "Process",
            "target_file" => "File",
            "target_domain" => "Domain",
            "target_url" => "URL",
            "target_registry" => "Registry",
            _ => "Skip",
        }
    }

    /// Returns proposed field -> entity_type mapping for a list of raw field names (e.g. from JSON keys or CSV headers).
    /// Used by preview step for generic/csv ingestion.
    pub fn proposed_field_mapping(field_names: &[String]) -> Vec<(String, String)> {
        field_names
            .iter()
            .map(|name| {
                let canonical = Self::canonical_field(name).unwrap_or("_unknown");
                let entity_type = if canonical == "_unknown" {
                    "Skip"
                } else {
                    Self::canonical_to_entity_type(canonical)
                };
                (name.clone(), entity_type.to_string())
            })
            .collect()
    }

    /// Parses various timestamp formats into Unix epoch seconds.
    fn parse_timestamp(ts: &str) -> Option<i64> {
        let trimmed = ts.trim();
        if trimmed.is_empty() {
            return None;
        }

        // ISO 8601 with Z
        if let Some(pos) = trimmed.find('Z') {
            let before_z = &trimmed[..pos];
            let base = before_z.split('.').next().unwrap_or(before_z);
            if let Ok(dt) = chrono::NaiveDateTime::parse_from_str(base, "%Y-%m-%dT%H:%M:%S") {
                return Some(dt.and_utc().timestamp());
            }
        }

        // ISO 8601 with offset
        if let Ok(dt) = chrono::DateTime::parse_from_rfc3339(trimmed) {
            return Some(dt.timestamp());
        }

        // Try fractional seconds variant
        if trimmed.contains('T') {
            let base = trimmed.split('.').next().unwrap_or(trimmed);
            let base = base.split('+').next().unwrap_or(base);
            let base = base.split('Z').next().unwrap_or(base);
            if let Ok(dt) = chrono::NaiveDateTime::parse_from_str(base, "%Y-%m-%dT%H:%M:%S") {
                return Some(dt.and_utc().timestamp());
            }
        }

        // Sysmon format: "2024-01-15 14:30:00.123"
        let base = trimmed.split('.').next().unwrap_or(trimmed);
        if let Ok(dt) = chrono::NaiveDateTime::parse_from_str(base, "%Y-%m-%d %H:%M:%S") {
            return Some(dt.and_utc().timestamp());
        }

        // Unix epoch (numeric)
        if let Ok(epoch) = trimmed.parse::<i64>() {
            return Some(epoch);
        }

        None
    }

    /// Normalizes a JSON event object into canonical fields.
    pub fn normalize(event: &Value) -> NormalizedEvent {
        let obj = match event.as_object() {
            Some(o) => o,
            None => {
                return NormalizedEvent {
                    timestamp: 0,
                    source_user: None,
                    target_user: None,
                    source_ip: None,
                    target_ip: None,
                    source_host: None,
                    source_process: None,
                    parent_process: None,
                    command_line: None,
                    target_file: None,
                    target_domain: None,
                    target_url: None,
                    target_registry: None,
                    protocol: None,
                    source_port: None,
                    target_port: None,
                };
            }
        };

        let mut timestamp: i64 = 0;
        let mut source_user: Option<String> = None;
        let mut target_user: Option<String> = None;
        let mut source_ip: Option<String> = None;
        let mut target_ip: Option<String> = None;
        let mut source_host: Option<String> = None;
        let mut source_process: Option<String> = None;
        let mut parent_process: Option<String> = None;
        let mut command_line: Option<String> = None;
        let mut target_file: Option<String> = None;
        let mut target_domain: Option<String> = None;
        let mut target_url: Option<String> = None;
        let mut target_registry: Option<String> = None;
        let mut protocol: Option<String> = None;
        let mut source_port: Option<String> = None;
        let mut target_port: Option<String> = None;

        for (key, value) in obj {
            let val_str = match value.as_str() {
                Some(s) if !s.is_empty() => s.to_string(),
                _ => match value {
                    Value::Number(n) => n.to_string(),
                    _ => continue,
                },
            };

            if let Some(canonical) = Self::canonical_field(key) {
                match canonical {
                    "timestamp" => {
                        timestamp = Self::parse_timestamp(&val_str).unwrap_or(0);
                    }
                    "source_user" if source_user.is_none() => {
                        source_user = Some(val_str);
                    }
                    "target_user" if target_user.is_none() => {
                        target_user = Some(val_str);
                    }
                    "source_ip" if source_ip.is_none() => {
                        source_ip = Some(val_str);
                    }
                    "target_ip" if target_ip.is_none() => {
                        target_ip = Some(val_str);
                    }
                    "source_host" if source_host.is_none() => {
                        source_host = Some(val_str);
                    }
                    "source_process" if source_process.is_none() => {
                        source_process = Some(val_str);
                    }
                    "parent_process" if parent_process.is_none() => {
                        parent_process = Some(val_str);
                    }
                    "command_line" if command_line.is_none() => {
                        command_line = Some(val_str);
                    }
                    "target_file" if target_file.is_none() => {
                        target_file = Some(val_str);
                    }
                    "target_domain" if target_domain.is_none() => {
                        target_domain = Some(val_str);
                    }
                    "target_url" if target_url.is_none() => {
                        target_url = Some(val_str);
                    }
                    "target_registry" if target_registry.is_none() => {
                        target_registry = Some(val_str);
                    }
                    "protocol" if protocol.is_none() => {
                        protocol = Some(val_str);
                    }
                    "source_port" if source_port.is_none() => {
                        source_port = Some(val_str);
                    }
                    "target_port" if target_port.is_none() => {
                        target_port = Some(val_str);
                    }
                    _ => {}
                }
            }
        }

        NormalizedEvent {
            timestamp,
            source_user,
            target_user,
            source_ip,
            target_ip,
            source_host,
            source_process,
            parent_process,
            command_line,
            target_file,
            target_domain,
            target_url,
            target_registry,
            protocol,
            source_port,
            target_port,
        }
    }

    /// Generates triples from a single normalized event using relationship inference rules.
    pub fn parse_event(event: &Value) -> Vec<ParsedTriple> {
        let n = Self::normalize(event);
        let mut triples = Vec::new();

        // Rule: parent_process + source_process → Process -[Spawn]-> Process
        if let (Some(parent), Some(child)) = (&n.parent_process, &n.source_process) {
            let src = Entity::new(parent, EntityType::Process);
            let dst = {
                let mut e = Entity::new(child, EntityType::Process);
                if let Some(ref cmd) = n.command_line {
                    e = e.with_metadata("cmdline", cmd);
                }
                e
            };
            let rel = Relation::new(parent, child, RelationType::Spawn, n.timestamp);
            triples.push((src, rel, dst));
        }

        // Rule: source_user + source_process → User -[Execute]-> Process
        if let (Some(user), Some(proc)) = (&n.source_user, &n.source_process) {
            let src = Entity::new(user, EntityType::User);
            let dst = {
                let mut e = Entity::new(proc, EntityType::Process);
                if let Some(ref cmd) = n.command_line {
                    e = e.with_metadata("cmdline", cmd);
                }
                e
            };
            let rel = Relation::new(user, proc, RelationType::Execute, n.timestamp);
            triples.push((src, rel, dst));
        }

        // Rule: source_host + target_ip → Host -[Connect]-> IP
        if let (Some(host), Some(ip)) = (&n.source_host, &n.target_ip) {
            let src = Entity::new(host, EntityType::Host);
            let mut dst = Entity::new(ip, EntityType::IP);
            if let Some(ref port) = n.target_port {
                dst = dst.with_metadata("dest_port", port);
            }
            let mut rel = Relation::new(host, ip, RelationType::Connect, n.timestamp);
            if let Some(ref proto) = n.protocol {
                rel = rel.with_metadata("protocol", proto);
            }
            triples.push((src, rel, dst));
        }

        // Rule: source_ip + target_ip → IP -[Connect]-> IP
        if let (Some(sip), Some(dip)) = (&n.source_ip, &n.target_ip) {
            // Only if we didn't already emit a host→ip connect
            if n.source_host.is_none() {
                let mut src = Entity::new(sip, EntityType::IP);
                if let Some(ref port) = n.source_port {
                    src = src.with_metadata("source_port", port);
                }
                let mut dst = Entity::new(dip, EntityType::IP);
                if let Some(ref port) = n.target_port {
                    dst = dst.with_metadata("dest_port", port);
                }
                let mut rel = Relation::new(sip, dip, RelationType::Connect, n.timestamp);
                if let Some(ref proto) = n.protocol {
                    rel = rel.with_metadata("protocol", proto);
                }
                triples.push((src, rel, dst));
            }
        }

        // Rule: source_user + source_host → User -[Auth]-> Host
        if let (Some(user), Some(host)) = (&n.source_user, &n.source_host) {
            // Only if we don't have a process (otherwise user→execute→process is more specific)
            if n.source_process.is_none() {
                let src = Entity::new(user, EntityType::User);
                let dst = Entity::new(host, EntityType::Host);
                let rel = Relation::new(user, host, RelationType::Auth, n.timestamp);
                triples.push((src, rel, dst));
            }
        }

        // Rule: target_user + source_host → User -[Auth]-> Host (e.g. EVTX 4624 TargetUserName + Computer)
        if let (Some(user), Some(host)) = (&n.target_user, &n.source_host) {
            if n.source_process.is_none() && n.source_user.is_none() {
                let src = Entity::new(user, EntityType::User);
                let dst = Entity::new(host, EntityType::Host);
                let rel = Relation::new(user, host, RelationType::Auth, n.timestamp);
                triples.push((src, rel, dst));
            }
        }

        // Rule: source_process + target_file → Process -[Write]-> File
        if let (Some(proc), Some(file)) = (&n.source_process, &n.target_file) {
            let src = Entity::new(proc, EntityType::Process);
            let dst = Entity::new(file, EntityType::File);
            let rel = Relation::new(proc, file, RelationType::Write, n.timestamp);
            triples.push((src, rel, dst));
        }

        // Rule: source_process + target_domain → Process -[DNS]-> Domain
        if let (Some(proc), Some(domain)) = (&n.source_process, &n.target_domain) {
            let src = Entity::new(proc, EntityType::Process);
            let dst = Entity::new(domain, EntityType::Domain);
            let rel = Relation::new(proc, domain, RelationType::DNS, n.timestamp);
            triples.push((src, rel, dst));
        }

        // Rule: source_process + target_url → Process -[Connect]-> URL
        if let (Some(proc), Some(url)) = (&n.source_process, &n.target_url) {
            let src = Entity::new(proc, EntityType::Process);
            let dst = Entity::new(url, EntityType::URL);
            let rel = Relation::new(proc, url, RelationType::Connect, n.timestamp);
            triples.push((src, rel, dst));
        }

        // Rule: source_process + target_registry → Process -[Modify]-> Registry
        if let (Some(proc), Some(reg)) = (&n.source_process, &n.target_registry) {
            let src = Entity::new(proc, EntityType::Process);
            let dst = Entity::new(reg, EntityType::Registry);
            let rel = Relation::new(proc, reg, RelationType::Modify, n.timestamp);
            triples.push((src, rel, dst));
        }

        // Rule: source_user + target_ip (no process) → User -[Auth]-> IP
        if let (Some(user), Some(ip)) = (&n.source_user, &n.target_ip) {
            if n.source_process.is_none() && n.source_host.is_none() {
                let src = Entity::new(user, EntityType::User);
                let dst = Entity::new(ip, EntityType::IP);
                let rel = Relation::new(user, ip, RelationType::Auth, n.timestamp);
                triples.push((src, rel, dst));
            }
        }

        // Fallback: ensure every event with at least one entity field produces a triple (e.g. EVTX with any EventID).
        if triples.is_empty() {
            if let Some(host) = &n.source_host {
                let h = Entity::new(host, EntityType::Host);
                let rel = Relation::new(host, host, RelationType::Connect, n.timestamp);
                triples.push((h.clone(), rel, h));
            } else if let Some(proc) = &n.source_process {
                let p = Entity::new(proc, EntityType::Process);
                let rel = Relation::new(proc, proc, RelationType::Execute, n.timestamp);
                triples.push((p.clone(), rel, p));
            } else if let Some(user) = &n.source_user {
                let u = Entity::new(user, EntityType::User);
                let rel = Relation::new(user, user, RelationType::Auth, n.timestamp);
                triples.push((u.clone(), rel, u));
            }
        }

        triples
    }

    /// Parses a CEF-formatted line into a JSON Value.
    /// Format: `CEF:Version|Vendor|Product|Version|SignatureID|Name|Severity|Extensions`
    pub fn try_parse_cef(line: &str) -> Option<Value> {
        let s = line.strip_prefix("CEF:")?;
        let parts: Vec<&str> = s.splitn(8, '|').collect();
        if parts.len() < 8 {
            return None;
        }

        let mut map = serde_json::Map::new();
        map.insert("cef_version".to_string(), Value::String(parts[0].to_string()));
        map.insert("device_vendor".to_string(), Value::String(parts[1].to_string()));
        map.insert("device_product".to_string(), Value::String(parts[2].to_string()));
        map.insert("device_version".to_string(), Value::String(parts[3].to_string()));
        map.insert("signature_id".to_string(), Value::String(parts[4].to_string()));
        map.insert("name".to_string(), Value::String(parts[5].to_string()));
        map.insert("severity".to_string(), Value::String(parts[6].to_string()));

        // Parse extensions: key=value pairs separated by spaces
        // Values can contain spaces if the next token doesn't contain '='
        let ext = parts[7];
        let tokens: Vec<&str> = ext.split_whitespace().collect();
        let mut i = 0;
        while i < tokens.len() {
            if let Some(eq_pos) = tokens[i].find('=') {
                let key = &tokens[i][..eq_pos];
                let mut val = tokens[i][eq_pos + 1..].to_string();
                // Absorb subsequent tokens that don't contain '=' (multi-word values)
                let mut j = i + 1;
                while j < tokens.len() && !tokens[j].contains('=') {
                    val.push(' ');
                    val.push_str(tokens[j]);
                    j += 1;
                }
                map.insert(key.to_string(), Value::String(val));
                i = j;
            } else {
                i += 1;
            }
        }

        Some(Value::Object(map))
    }

    /// Parses a LEEF-formatted line into a JSON Value.
    /// Format: `LEEF:Version|Vendor|Product|Version|EventID|Extensions`
    /// Extensions are tab-separated key=value pairs (LEEF 1.0) or custom-delimited (LEEF 2.0).
    pub fn try_parse_leef(line: &str) -> Option<Value> {
        let s = line.strip_prefix("LEEF:")?;
        let parts: Vec<&str> = s.splitn(6, '|').collect();
        if parts.len() < 6 {
            return None;
        }

        let mut map = serde_json::Map::new();
        map.insert("leef_version".to_string(), Value::String(parts[0].to_string()));
        map.insert("device_vendor".to_string(), Value::String(parts[1].to_string()));
        map.insert("device_product".to_string(), Value::String(parts[2].to_string()));
        map.insert("device_version".to_string(), Value::String(parts[3].to_string()));
        map.insert("event_id".to_string(), Value::String(parts[4].to_string()));

        // Parse extensions: tab-separated key=value
        let ext = parts[5];
        let delimiter = '\t';
        for pair in ext.split(delimiter) {
            let pair = pair.trim();
            if let Some(eq_pos) = pair.find('=') {
                let key = &pair[..eq_pos];
                let val = &pair[eq_pos + 1..];
                if !key.is_empty() {
                    map.insert(key.to_string(), Value::String(val.to_string()));
                }
            }
        }

        Some(Value::Object(map))
    }

    /// Flattens ECS-style nested JSON (e.g., `source.ip`, `destination.ip`)
    /// into flat canonical fields for normalization.
    pub fn flatten_nested_json(event: &Value) -> Value {
        let obj = match event.as_object() {
            Some(o) => o,
            None => return event.clone(),
        };

        let mut flat = serde_json::Map::new();

        fn flatten_recursive(prefix: &str, value: &Value, out: &mut serde_json::Map<String, Value>) {
            match value {
                Value::Object(map) => {
                    for (k, v) in map {
                        let new_key = if prefix.is_empty() {
                            k.clone()
                        } else {
                            format!("{}.{}", prefix, k)
                        };
                        flatten_recursive(&new_key, v, out);
                    }
                }
                _ => {
                    out.insert(prefix.to_string(), value.clone());
                }
            }
        }

        flatten_recursive("", &Value::Object(obj.clone()), &mut flat);

        // Apply ECS canonical mappings
        let ecs_mappings: &[(&str, &str)] = &[
            ("source.ip", "source_ip"),
            ("source.address", "source_ip"),
            ("destination.ip", "target_ip"),
            ("destination.address", "target_ip"),
            ("user.name", "source_user"),
            ("user.target.name", "target_user"),
            ("process.name", "source_process"),
            ("process.executable", "source_process"),
            ("process.parent.name", "parent_process"),
            ("process.parent.executable", "parent_process"),
            ("process.command_line", "command_line"),
            ("file.path", "target_file"),
            ("dns.question.name", "target_domain"),
            ("url.original", "target_url"),
            ("registry.path", "target_registry"),
            ("host.name", "source_host"),
            ("host.hostname", "source_host"),
            ("source.port", "source_port"),
            ("destination.port", "target_port"),
            ("network.protocol", "protocol"),
            ("@timestamp", "timestamp"),
            ("event.created", "timestamp"),
        ];

        for &(ecs_key, canonical) in ecs_mappings {
            if flat.contains_key(ecs_key) && !flat.contains_key(canonical) {
                if let Some(val) = flat.get(ecs_key).cloned() {
                    flat.insert(canonical.to_string(), val);
                }
            }
        }

        Value::Object(flat)
    }

    /// Parses JSON events from a string — supports JSON array, NDJSON, CEF, and LEEF.
    pub fn parse_events(data: &str) -> Vec<Value> {
        let trimmed = data.trim();
        if trimmed.is_empty() {
            return Vec::new();
        }

        // Try JSON array first (simd-json for speed)
        if trimmed.starts_with('[') {
            let mut buf = trimmed.as_bytes().to_vec();
            if let Ok(Value::Array(arr)) = simd_json::serde::from_slice::<Value>(&mut buf) {
                return arr.into_iter().map(|e| Self::flatten_nested_json(&e)).collect();
            }
        }

        // Try NDJSON first, then fall back to CEF/LEEF line-by-line
        let mut events = Vec::new();
        let mut json_count = 0usize;
        let mut structured_count = 0usize;

        for line in trimmed.lines() {
            let l = line.trim();
            if l.is_empty() {
                continue;
            }

            let mut buf = l.as_bytes().to_vec();
            if let Ok(val) = simd_json::serde::from_slice::<Value>(&mut buf) {
                events.push(Self::flatten_nested_json(&val));
                json_count += 1;
            } else if let Some(val) = Self::try_parse_cef(l) {
                events.push(val);
                structured_count += 1;
            } else if let Some(val) = Self::try_parse_leef(l) {
                events.push(val);
                structured_count += 1;
            }
            // Lines that don't match any format are silently skipped
        }

        // If we got nothing from line-by-line and it looked like JSON, try array parse
        if events.is_empty() && json_count == 0 && structured_count == 0 {
            let mut buf = trimmed.as_bytes().to_vec();
            if let Ok(Value::Array(arr)) = simd_json::serde::from_slice::<Value>(&mut buf) {
                return arr.into_iter().map(|e| Self::flatten_nested_json(&e)).collect();
            }
        }

        events
    }

    /// Parses up to `limit` events from a string (for preview performance on large files).
    /// Supports JSON array, NDJSON, CEF, and LEEF.
    pub fn parse_events_limited(data: &str, limit: usize) -> Vec<Value> {
        let trimmed = data.trim();
        if trimmed.is_empty() {
            return Vec::new();
        }

        // Try JSON array first (simd-json for speed)
        if trimmed.starts_with('[') {
            let mut buf = trimmed.as_bytes().to_vec();
            if let Ok(Value::Array(arr)) = simd_json::serde::from_slice::<Value>(&mut buf) {
                return arr.into_iter().take(limit).map(|e| Self::flatten_nested_json(&e)).collect();
            }
        }

        // Fallback to NDJSON / CEF / LEEF line-by-line
        let mut events = Vec::new();
        for line in trimmed.lines() {
            if events.len() >= limit {
                break;
            }
            let l = line.trim();
            if l.is_empty() {
                continue;
            }
            let mut buf = l.as_bytes().to_vec();
            let parsed = simd_json::serde::from_slice::<Value>(&mut buf)
                .ok()
                .or_else(|| serde_json::from_str(l).ok());
            if let Some(val) = parsed {
                events.push(Self::flatten_nested_json(&val));
            } else if let Some(val) = Self::try_parse_cef(l) {
                events.push(val);
            } else if let Some(val) = Self::try_parse_leef(l) {
                events.push(val);
            }
        }
        events
    }
}

impl LogParser for GenericParser {
    fn parse(&self, data: &str) -> Vec<ParsedTriple> {
        let events = Self::parse_events(data);
        if events.is_empty() {
            return Vec::new();
        }

        events
            .par_iter()
            .flat_map(|event| Self::parse_event(event))
            .collect()
    }
}
