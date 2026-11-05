use rayon::prelude::*;
use serde_json::Value;

use crate::entity::Entity;
use crate::parser::{LogParser, ParsedTriple};
use crate::relation::Relation;
use crate::types::{EntityType, RelationType};

/// Locale-keyed month-name table (localized token → English 3-letter form).
/// Handles common 3- and 4-letter abbreviations used across European audit
/// exports. Tokens are matched case-insensitively.
fn month_pairs_for(locale: &str) -> &'static [(&'static str, &'static str)] {
    // English tokens are accepted as a no-op fallback so mixed-locale logs
    // still parse when a user passes e.g. `locale="es"` on an English file.
    const EN: &[(&str, &str)] = &[
        ("jan", "Jan"),
        ("feb", "Feb"),
        ("mar", "Mar"),
        ("apr", "Apr"),
        ("may", "May"),
        ("jun", "Jun"),
        ("jul", "Jul"),
        ("aug", "Aug"),
        ("sep", "Sep"),
        ("sept", "Sep"),
        ("oct", "Oct"),
        ("nov", "Nov"),
        ("dec", "Dec"),
    ];
    const ES: &[(&str, &str)] = &[
        ("ene", "Jan"),
        ("feb", "Feb"),
        ("mar", "Mar"),
        ("abr", "Apr"),
        ("may", "May"),
        ("jun", "Jun"),
        ("jul", "Jul"),
        ("ago", "Aug"),
        ("sep", "Sep"),
        ("sept", "Sep"),
        ("oct", "Oct"),
        ("nov", "Nov"),
        ("dic", "Dec"),
    ];
    const PT: &[(&str, &str)] = &[
        ("jan", "Jan"),
        ("fev", "Feb"),
        ("mar", "Mar"),
        ("abr", "Apr"),
        ("mai", "May"),
        ("jun", "Jun"),
        ("jul", "Jul"),
        ("ago", "Aug"),
        ("set", "Sep"),
        ("out", "Oct"),
        ("nov", "Nov"),
        ("dez", "Dec"),
    ];
    const FR: &[(&str, &str)] = &[
        ("janv", "Jan"),
        ("jan", "Jan"),
        ("févr", "Feb"),
        ("fevr", "Feb"),
        ("fev", "Feb"),
        ("mars", "Mar"),
        ("mar", "Mar"),
        ("avr", "Apr"),
        ("mai", "May"),
        ("juin", "Jun"),
        ("jun", "Jun"),
        ("juil", "Jul"),
        ("jul", "Jul"),
        ("août", "Aug"),
        ("aout", "Aug"),
        ("sept", "Sep"),
        ("sep", "Sep"),
        ("oct", "Oct"),
        ("nov", "Nov"),
        ("déc", "Dec"),
        ("dec", "Dec"),
    ];
    const DE: &[(&str, &str)] = &[
        ("jan", "Jan"),
        ("feb", "Feb"),
        ("mär", "Mar"),
        ("maer", "Mar"),
        ("mar", "Mar"),
        ("apr", "Apr"),
        ("mai", "May"),
        ("jun", "Jun"),
        ("jul", "Jul"),
        ("aug", "Aug"),
        ("sep", "Sep"),
        ("sept", "Sep"),
        ("okt", "Oct"),
        ("oct", "Oct"),
        ("nov", "Nov"),
        ("dez", "Dec"),
        ("dec", "Dec"),
    ];
    const IT: &[(&str, &str)] = &[
        ("gen", "Jan"),
        ("feb", "Feb"),
        ("mar", "Mar"),
        ("apr", "Apr"),
        ("mag", "May"),
        ("giu", "Jun"),
        ("lug", "Jul"),
        ("ago", "Aug"),
        ("set", "Sep"),
        ("ott", "Oct"),
        ("nov", "Nov"),
        ("dic", "Dec"),
    ];
    match locale {
        "es" => ES,
        "pt" => PT,
        "fr" => FR,
        "de" => DE,
        "it" => IT,
        _ => EN,
    }
}

/// Rewrites localized 3/4-letter month tokens in `s` to their English
/// equivalents so `chrono` format parsers can handle them. Only whole-word
/// token matches are rewritten to avoid touching other content.
fn translate_month_name(s: &str, locale: &str) -> String {
    let pairs = month_pairs_for(locale);
    let mut out = String::with_capacity(s.len());
    let mut rest = s;
    while !rest.is_empty() {
        // Find the next alphabetic token (Unicode-aware so `août`/`mär`/`déc`
        // stay as single tokens rather than split on the accented char).
        let start = match rest.find(|c: char| c.is_alphabetic()) {
            Some(i) => i,
            None => {
                out.push_str(rest);
                break;
            }
        };
        out.push_str(&rest[..start]);
        let tail = &rest[start..];
        let end = tail
            .find(|c: char| !c.is_alphabetic())
            .unwrap_or(tail.len());
        let token = &tail[..end];
        let lower = token.to_lowercase();
        // Prefer longer aliases first so "sept" wins over "sep" when both exist.
        let replaced = {
            let mut found: Option<&str> = None;
            let mut best_len = 0usize;
            for (src, en) in pairs {
                if *src == lower.as_str() && src.len() > best_len {
                    found = Some(*en);
                    best_len = src.len();
                }
            }
            found
        };
        match replaced {
            Some(en) => out.push_str(en),
            None => out.push_str(token),
        }
        rest = &tail[end..];
    }
    out
}

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
    /// Correlation identifier that threads several events into one logical
    /// session (`sessionId`, `correlation_id`, `request_id`, `job_id`).
    /// Carries the raw value; [`GenericParser::session_entity_id`] adds the
    /// namespace prefix before it becomes a node.
    pub session: Option<String>,
}

impl GenericParser {
    /// Maps a field name (case-insensitive) to a canonical name.
    ///
    /// Portal exports (e.g. the M365 Defender machine-timeline CSV) emit
    /// Title Case headers with spaces ("Remote IP") for the same columns
    /// the API exports as "RemoteIP". Rather than duplicating every alias
    /// per separator style, the lookup retries with separators collapsed
    /// ("remote ip" → "remoteip") and with spaces as underscores
    /// ("event time" → "event_time").
    pub fn canonical_field(name: &str) -> Option<&'static str> {
        let lower = name.to_lowercase();
        if let Some(c) = Self::canonical_field_exact(&lower) {
            return Some(c);
        }
        if lower.contains(' ') || lower.contains('-') {
            let collapsed: String = lower.chars().filter(|c| *c != ' ' && *c != '-').collect();
            if let Some(c) = Self::canonical_field_exact(&collapsed) {
                return Some(c);
            }
            let underscored = lower.replace([' ', '-'], "_");
            return Self::canonical_field_exact(&underscored);
        }
        None
    }

    fn canonical_field_exact(name: &str) -> Option<&'static str> {
        match name {
            // Timestamp
            "timestamp" | "utctime" | "timegenerated" | "eventtime" | "time" | "date"
            | "datetime" | "@timestamp" | "event_time" | "log_time" => Some("timestamp"),

            // Source user
            "user"
            | "username"
            | "src_user"
            | "source_user"
            | "account_name"
            | "subjectusername"
            | "accountname"
            | "userprincipalname"
            | "initiatingprocessaccountname"
            | "actor"
            | "caller"
            | "membername"
            | "samaccountname"
            | "logonid"
            | "connecteduser"
            | "runasuser"
            | "modifyinguser"
            | "usercontext"
            | "event_by"
            | "eventby"
            | "performed_by"
            | "performedby"
            | "done_by"
            | "doneby"
            | "operator" => Some("source_user"),

            // Target user
            "target_user" | "targetusername" | "dst_user" | "dest_user" | "targetaccountname"
            | "targetusersid" | "targetsid" => Some("target_user"),

            // Source IP
            "sourceip" | "src_ip" | "source_ip" | "srcip" | "ipaddress" | "ip_address" | "ip"
            | "client_ip_address" | "clientip" | "client_ip" | "callerip" | "caller_ip"
            | "src_addr" | "sourceaddress" | "clientaddress" | "sourceipaddress" | "localip"
            | "local_ip" => Some("source_ip"),

            // Target IP (also used for client connecting IPs in RDP/TerminalServices)
            "destinationip" | "dst_ip" | "dest_ip" | "target_ip" | "dstip" | "destip" | "remoteip"
            | "remote_ip" | "dst_addr" | "destinationaddress" | "server_ip" | "remoteaddress"
            | "targetaddress" | "address" | "clientaddressv4" | "clientaddressv6"
            | "remoteaddresses" => Some("target_ip"),

            // Source host
            "computer" | "hostname" | "devicename" | "source_host" | "src_host" | "host"
            | "machine" | "workstation" | "device_name" | "agent_hostname" | "clientmachine"
            | "machinename" | "workstationname" | "servername" | "sourceworkstation"
            | "computername" => Some("source_host"),

            // Target host (map to target_ip for graph connectivity)
            "destination"
            | "destinationmachine"
            | "targetserver"
            | "targetcomputer"
            | "remotehost"
            | "remotemachine"
            | "remotecomputername"
            | "destinationhostname" => Some("target_ip"),

            // Source process
            "image"
            | "process_name"
            | "newprocessname"
            | "filename"
            | "source_process"
            | "process"
            | "exe"
            | "executable"
            | "initiatingprocessfilename"
            | "hostapplication"
            | "processpath"
            | "processname"
            | "servicename"
            | "providerpath"
            | "providername"
            | "component"
            | "taskname"
            | "apppoollid"
            | "applicationpath"
            | "modifyingapplication"
            | "actionname" => Some("source_process"),

            // Parent process
            "parentimage"
            | "parent_process"
            | "parentprocessname"
            | "initiatingprocessparentfilename"
            | "parent_exe"
            | "ppid_name"
            | "callerprocessname"
            | "parentprocesspath" => Some("parent_process"),

            // Command line
            "commandline"
            | "command_line"
            | "cmdline"
            | "processcommandline"
            | "cmd"
            | "command"
            | "initiatingprocesscommandline"
            | "scriptblocktext"
            | "payload"
            | "param1"
            | "operation"
            | "contextinfo" => Some("command_line"),

            // Target file
            "targetfilename" | "objectname" | "file_path" | "filepath" | "folderpath"
            | "target_file" | "dest_file" | "file" | "path" | "sharename"
            | "relativetargetname" | "accesslist" => Some("target_file"),

            // Target domain
            "queryname" | "domain" | "dns_query" | "target_domain" | "dest_domain" | "query"
            | "dnsquery" | "requested_domain" | "namespacename" | "namespace" => {
                Some("target_domain")
            }

            // Target URL
            "url" | "target_url" | "remoteurl" | "request_url" | "uri" | "dest_url"
            | "http_url" | "resourceuri" => Some("target_url"),

            // Target registry
            "registry_path" | "registry_key" | "targetobject" | "target_registry"
            | "registrykey" | "registryvaluename" => Some("target_registry"),

            // Protocol
            "protocol" | "proto" | "transport" | "network_protocol" | "layername" => {
                Some("protocol")
            }

            // Source port
            "sourceport" | "src_port" | "source_port" | "sport" | "localport" | "local_port" => {
                Some("source_port")
            }

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

            // Action / event semantics — metadata that hints at the
            // relation type but does not itself produce an entity.
            "action" | "event_type" | "eventtype" | "event_action" | "eventaction" | "activity"
            | "activity_type" | "actiontype" => Some("action"),

            // Outcome / result — skipped by default but reserved for
            // future enrichment (e.g. failed-auth cluster detection).
            "status" | "outcome" | "result" | "event_outcome" | "eventoutcome" | "success" => {
                Some("outcome")
            }

            // Generic resource / target object (RBAC / SaaS audit).
            "target" | "target_object" | "targetobject_name" | "resource" | "resource_name"
            | "object" | "object_name" => Some("target_resource"),

            // File hashes — malware / integrity tracking.
            "md5" | "sha1" | "sha256" | "hash" | "file_hash" | "filehash" | "sha_256" | "sha-1"
            | "sha-256" => Some("target_hash"),

            // Geolocation — mostly enrichment metadata.
            "country" | "country_code" | "city" | "region" | "asn" | "geo_location"
            | "geolocation" | "location" => Some("location"),

            // Email — promoted to source_user when the heuristic is
            // sure the column is an email (value regex will confirm).
            "email" | "email_address" | "mail" | "sender" | "recipient" | "from" | "to" => {
                Some("source_user")
            }

            // Correlation identifiers — useful for session threading.
            "session_id" | "sessionid" | "correlation_id" | "correlationid" | "request_id"
            | "requestid" | "transaction_id" | "transactionid" | "trace_id" | "traceid"
            | "job_id" | "jobid" => Some("session"),

            // Severity / log level — metadata only.
            "severity" | "level" | "priority" | "importance" => Some("severity"),

            // Free-text description.
            "message" | "description" | "detail" | "details" | "reason" | "event_description" => {
                Some("message")
            }

            // Multilingual aliases — Spanish (es).
            "usuario" | "usuario_origen" | "cuenta" | "actor_usuario" => Some("source_user"),
            "usuario_destino" | "usuario_objetivo" => Some("target_user"),
            "direccion" | "dirección" | "direccion_ip" | "dirección_ip" | "ip_origen" => {
                Some("source_ip")
            }
            "direccion_destino" | "dirección_destino" | "ip_destino" => Some("target_ip"),
            "equipo" | "maquina" | "máquina" | "ordenador" | "computador" | "computadora" => {
                Some("source_host")
            }
            "archivo" | "fichero" | "ruta" => Some("target_file"),
            "dominio" => Some("target_domain"),
            "accion" | "acción" | "evento" | "tipo_evento" => Some("action"),
            "fecha" | "fecha_hora" | "marca_temporal" | "hora" => Some("timestamp"),
            "proceso" | "aplicacion" | "aplicación" => Some("source_process"),
            "resultado" | "estado" => Some("outcome"),
            "mensaje" | "descripcion" | "descripción" | "motivo" => Some("message"),

            // Multilingual aliases — Portuguese (pt).
            "usuário" | "usuario_origem" => Some("source_user"),
            "usuário_destino" | "usuario_destino_pt" => Some("target_user"),
            "endereco" | "endereço" | "endereco_ip" | "endereço_ip" => Some("source_ip"),
            "maquina_pt" | "máquina_pt" => Some("source_host"),
            "arquivo" => Some("target_file"),
            "domínio" => Some("target_domain"),
            "açao" | "ação" => Some("action"),
            "data" | "data_hora" => Some("timestamp"),
            "processo" => Some("source_process"),

            // Multilingual aliases — French (fr).
            "utilisateur" | "utilisateur_source" | "compte" => Some("source_user"),
            "utilisateur_cible" | "utilisateur_destination" => Some("target_user"),
            "adresse" | "adresse_ip" | "adresse_source" => Some("source_ip"),
            "adresse_destination" | "adresse_cible" => Some("target_ip"),
            "machine_source" | "ordinateur" | "poste" => Some("source_host"),
            "fichier" | "chemin" => Some("target_file"),
            "domaine" => Some("target_domain"),
            "url_fr" => Some("target_url"),
            "action_fr" | "evenement" | "événement" | "type_evenement" | "type_événement" => {
                Some("action")
            }
            "date_fr" | "horodatage" | "date_heure" => Some("timestamp"),
            "processus" => Some("source_process"),
            "message_fr" | "description_fr" | "motif" => Some("message"),

            _ => None,
        }
    }

    /// Maps a canonical field name to the suggested entity type for preview/UI.
    /// Returns "Skip" for metadata-only fields (timestamp, command_line, ports, protocol).
    pub fn canonical_to_entity_type(canonical: &str) -> &'static str {
        match canonical {
            "timestamp" | "command_line" | "protocol" | "source_port" | "target_port"
            | "action" | "outcome" | "severity" | "message" => "Skip",
            "source_user" | "target_user" => "User",
            "source_ip" | "target_ip" => "IP",
            "source_host" => "Host",
            "source_process" | "parent_process" => "Process",
            "target_file" => "File",
            "target_domain" => "Domain",
            "target_url" => "URL",
            "target_registry" => "Registry",
            // These map to EntityType::Other(String) — the SIMD bridge
            // resolves them via OtherTypeMap, so no changes to libgraphmatch
            // slots are needed.
            "target_resource" => "Resource",
            "target_hash" => "Hash",
            "session" => "Session",
            "location" => "Location",
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
    ///
    /// Accepts (in order): ISO 8601 (`Z`, offset, fractional), Sysmon
    /// `YYYY-MM-DD HH:MM:SS`, European comma-decimal fractional
    /// (`YYYY-MM-DD HH:MM:SS,mmm`), W3C without seconds
    /// (`YYYY-MM-DD HH:MM`), Apache CLF (`19/Apr/2026:09:29:00 +0000`
    /// with or without brackets), RFC 3164 syslog (`Apr 19 09:29:00`
    /// — assumes current year), localized "Mmm D, YYYY, H:MM[:SS]
    /// AM/PM" (Zoho/Google), and Unix epoch (seconds / ms / μs / ns
    /// discriminated by magnitude).
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

        // Sysmon format: "2024-01-15 14:30:00.123" (splits on first `.`).
        // Also accepts European comma-decimal fractionals: "14:30:00,123".
        {
            let base_dot = trimmed.split('.').next().unwrap_or(trimmed);
            let base = base_dot.split(',').next().unwrap_or(base_dot);
            if let Ok(dt) = chrono::NaiveDateTime::parse_from_str(base, "%Y-%m-%d %H:%M:%S") {
                return Some(dt.and_utc().timestamp());
            }
        }

        // W3C without seconds: "2026-04-19 09:29"
        if let Ok(dt) = chrono::NaiveDateTime::parse_from_str(trimmed, "%Y-%m-%d %H:%M") {
            return Some(dt.and_utc().timestamp());
        }

        // Apache CLF: "19/Apr/2026:09:29:00 +0000" (also accepts bracketed).
        if let Some(ts) = Self::parse_apache_clf(trimmed) {
            return Some(ts);
        }

        // RFC 3164 syslog: "Apr 19 09:29:00" (no year → assume current year).
        if let Some(ts) = Self::parse_rfc3164(trimmed) {
            return Some(ts);
        }

        // Localized "Mmm D, YYYY, H:MM[:SS] AM/PM" — Zoho/Google audit exports.
        // Accepts Spanish and English 3-letter month abbreviations.
        if let Some(ts) = Self::parse_localized_month_day(trimmed) {
            return Some(ts);
        }

        // Unix epoch (numeric): discriminate scale by magnitude.
        //   10 digits → seconds (10^9   ≈ year 2001  .. 10^10  ≈ year 2286)
        //   13 digits → milliseconds  (10^12 .. 10^13)
        //   16 digits → microseconds  (10^15 .. 10^16)
        //   19 digits → nanoseconds   (10^18 .. 10^19)
        // Below 10^12 we treat as seconds even for small values (legacy
        // "1713628140" style), preserving prior behavior.
        if let Ok(epoch) = trimmed.parse::<i64>() {
            let abs = epoch.unsigned_abs();
            let scaled = if abs >= 10u64.pow(18) {
                // ns → s
                epoch / 1_000_000_000
            } else if abs >= 10u64.pow(15) {
                // μs → s
                epoch / 1_000_000
            } else if abs >= 10u64.pow(12) {
                // ms → s
                epoch / 1_000
            } else {
                epoch
            };
            return Some(scaled);
        }

        None
    }

    /// Parses Apache Common Log Format timestamps. Strips any surrounding
    /// brackets and handles the `DD/Mon/YYYY:HH:MM:SS ±HHMM` shape.
    fn parse_apache_clf(s: &str) -> Option<i64> {
        let stripped = s.trim_start_matches('[').trim_end_matches(']');
        // Chrono's %z doesn't accept a missing offset — require one.
        if let Ok(dt) = chrono::DateTime::parse_from_str(stripped, "%d/%b/%Y:%H:%M:%S %z") {
            return Some(dt.timestamp());
        }
        // Fall back to no-offset variant (assume UTC).
        if let Ok(dt) = chrono::NaiveDateTime::parse_from_str(stripped, "%d/%b/%Y:%H:%M:%S") {
            return Some(dt.and_utc().timestamp());
        }
        None
    }

    /// Parses RFC 3164 syslog timestamps ("Mmm D HH:MM:SS", e.g. "Apr 19
    /// 09:29:00" or "Apr  1 04:07:00" with the double space for single-digit
    /// days). Year is not in the format; current UTC year is assumed.
    fn parse_rfc3164(s: &str) -> Option<i64> {
        // Must start with 3-letter month. Collapse double-space so chrono's %e
        // (space-padded day) can cope; chrono accepts %e but format crates
        // vary, so we normalize first.
        let collapsed = {
            let mut out = String::with_capacity(s.len());
            let mut prev_space = false;
            for c in s.chars() {
                if c == ' ' {
                    if !prev_space {
                        out.push(' ');
                    }
                    prev_space = true;
                } else {
                    out.push(c);
                    prev_space = false;
                }
            }
            out
        };
        let year = chrono::Utc::now().format("%Y").to_string();
        let with_year = format!("{} {}", year, collapsed);
        if let Ok(dt) = chrono::NaiveDateTime::parse_from_str(&with_year, "%Y %b %d %H:%M:%S") {
            return Some(dt.and_utc().timestamp());
        }
        None
    }

    /// Parses a timestamp string using an explicit chrono format, optionally
    /// pre-translating localized month tokens to English (currently `"es"`).
    ///
    /// Accepts formats with or without a time component. Examples:
    ///   ("abr 19, 2026, 9:29 AM", "%b %d, %Y, %I:%M %p", Some("es"))
    ///   ("2026-04-19 09:29:00",   "%Y-%m-%d %H:%M:%S",   None)
    ///   ("19/04/2026",            "%d/%m/%Y",            None)
    pub fn parse_timestamp_with_hint(
        value: &str,
        format: &str,
        locale: Option<&str>,
    ) -> Option<i64> {
        let value = value.trim();
        if value.is_empty() || format.is_empty() {
            return None;
        }

        let translated = match locale.map(|l| l.to_lowercase()) {
            Some(ref l) if matches!(l.as_str(), "es" | "pt" | "fr" | "de" | "it" | "en") => {
                translate_month_name(value, l.as_str())
            }
            _ => value.to_string(),
        };

        if let Ok(dt) = chrono::NaiveDateTime::parse_from_str(&translated, format) {
            return Some(dt.and_utc().timestamp());
        }
        if let Ok(d) = chrono::NaiveDate::parse_from_str(&translated, format) {
            return d.and_hms_opt(0, 0, 0).map(|dt| dt.and_utc().timestamp());
        }
        None
    }

    /// Parses formats like "abr 19, 2026, 9:29 AM" or "Apr 19, 2026, 09:29:30 PM".
    /// Returns None if the shape doesn't match.
    fn parse_localized_month_day(s: &str) -> Option<i64> {
        let parts: Vec<&str> = s.splitn(3, ", ").collect();
        if parts.len() != 3 {
            return None;
        }

        let date_parts: Vec<&str> = parts[0].split_whitespace().collect();
        if date_parts.len() != 2 {
            return None;
        }
        let month: u32 = match date_parts[0].trim_end_matches('.').to_lowercase().as_str() {
            "ene" | "jan" => 1,
            "feb" => 2,
            "mar" => 3,
            "abr" | "apr" => 4,
            "may" => 5,
            "jun" => 6,
            "jul" => 7,
            "ago" | "aug" => 8,
            "sep" | "sept" => 9,
            "oct" => 10,
            "nov" => 11,
            "dic" | "dec" => 12,
            _ => return None,
        };
        let day: u32 = date_parts[1].parse().ok()?;
        let year: i32 = parts[1].parse().ok()?;

        let time_parts: Vec<&str> = parts[2].split_whitespace().collect();
        let (hm_str, ampm) = match time_parts.len() {
            1 => (time_parts[0], None),
            2 => (time_parts[0], Some(time_parts[1].to_uppercase())),
            _ => return None,
        };
        let hm: Vec<&str> = hm_str.split(':').collect();
        if hm.len() < 2 || hm.len() > 3 {
            return None;
        }
        let mut hour: u32 = hm[0].parse().ok()?;
        let minute: u32 = hm[1].parse().ok()?;
        let second: u32 = if hm.len() == 3 {
            hm[2].parse().ok()?
        } else {
            0
        };

        match ampm.as_deref() {
            Some("PM") if hour < 12 => hour += 12,
            Some("AM") if hour == 12 => hour = 0,
            Some("AM") | Some("PM") | None => {}
            _ => return None,
        }

        let dt =
            chrono::NaiveDate::from_ymd_opt(year, month, day)?.and_hms_opt(hour, minute, second)?;
        Some(dt.and_utc().timestamp())
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
                    session: None,
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
        let mut session: Option<String> = None;
        let mut action_value: Option<String> = None;
        let mut bare_file_name: Option<String> = None;

        for (key, value) in obj {
            let val_str = match value.as_str() {
                Some(s) if !s.is_empty() => s.to_string(),
                _ => match value {
                    Value::Number(n) => n.to_string(),
                    _ => continue,
                },
            };

            if let Some(canonical) = Self::canonical_field(key) {
                // A bare "FileName"/"File Name" column is ambiguous: it names
                // the acted-on process image for process/network events but
                // the file itself for file events (MDE timeline exports use
                // one column for both). Stash it and resolve after the loop,
                // once the action label is known.
                let stripped: String = key
                    .to_lowercase()
                    .chars()
                    .filter(|c| !matches!(c, ' ' | '_' | '-'))
                    .collect();
                if stripped == "filename" {
                    if bare_file_name.is_none() {
                        bare_file_name = Some(val_str);
                    }
                    continue;
                }
                match canonical {
                    "action" if action_value.is_none() => {
                        action_value = Some(val_str);
                    }
                    "timestamp" => {
                        timestamp = Self::parse_timestamp(&val_str).unwrap_or(0);
                    }
                    // Windows account/domain names (and email addresses in
                    // practice) are case-insensitive: lowercase at extraction
                    // so "LOMANEGRA\\JPerez" and "lomanegra\\jperez" resolve
                    // to ONE User entity. Same rule as source_host below.
                    "source_user" if source_user.is_none() => {
                        source_user = Some(val_str.to_lowercase());
                    }
                    "target_user" if target_user.is_none() => {
                        target_user = Some(val_str.to_lowercase());
                    }
                    "source_ip" if source_ip.is_none() => {
                        source_ip = Some(val_str);
                    }
                    "target_ip" if target_ip.is_none() => {
                        target_ip = Some(val_str);
                    }
                    // Hostnames are case-insensitive (DNS/NetBIOS): lowercase
                    // at extraction so "arlmldcc…" (Computer Name) and
                    // "ARLMLDCC…" (Remote Computer Name) resolve to ONE Host
                    // entity instead of one per casing.
                    "source_host" if source_host.is_none() => {
                        source_host = Some(val_str.to_lowercase());
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
                    // Domains are case-insensitive like hostnames.
                    "target_domain" if target_domain.is_none() => {
                        target_domain = Some(val_str.to_lowercase());
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
                    "session" if session.is_none() => {
                        session = Some(val_str);
                    }
                    _ => {}
                }
            }
        }

        // Resolve the stashed bare file name. For file actions
        // ("FileCreated", "FileModified", "file_downloaded"…) it is the file
        // itself — joined onto the folder path when one was captured so the
        // entity carries the full path. For everything else it keeps its
        // historical meaning: the acted-on process image, overriding
        // initiating-process columns (the MDE ProcessCreated child must beat
        // its parent for the Execute/Spawn edges to point at the new process).
        if let Some(fname) = bare_file_name {
            let is_file_action = action_value
                .as_deref()
                .map(|a| a.to_lowercase().contains("file"))
                .unwrap_or(false);
            if is_file_action {
                target_file = Some(match target_file.take() {
                    Some(folder)
                        if !folder
                            .to_ascii_lowercase()
                            .ends_with(&fname.to_ascii_lowercase()) =>
                    {
                        let sep = if folder.contains('/') && !folder.contains('\\') {
                            '/'
                        } else {
                            '\\'
                        };
                        format!("{}{}{}", folder.trim_end_matches(['\\', '/']), sep, fname)
                    }
                    Some(full_path) => full_path,
                    None => fname,
                });
            } else {
                source_process = Some(fname);
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
            session,
        }
    }

    /// Scans `event` for any field whose canonical form is `"action"` and,
    /// if found, maps its string value to a [`RelationType`] via
    /// [`crate::field_preview::infer_relation_from_action`]. Returns `None`
    /// when no action field is present or the action text is unrecognized —
    /// callers then fall back to the static entity→relation default.
    fn find_action_relation(event: &Value) -> Option<RelationType> {
        let obj = event.as_object()?;
        for (k, v) in obj {
            if Self::canonical_field(k) == Some("action") {
                if let Some(s) = v.as_str() {
                    if let Some(rt) = crate::field_preview::infer_relation_from_action(s) {
                        return Some(rt);
                    }
                }
            }
        }
        None
    }

    /// Namespaced node id for a session correlation value, or `None` when
    /// the value cannot be a useful node.
    ///
    /// The prefix is not decoration. In the Keycloak export that motivated
    /// this feature, `userId` and `sessionId` are both UUIDs minted by the
    /// same generator — a bare value would let a session silently collide
    /// with a user and fuse two unrelated nodes into one.
    ///
    /// Rejections mirror the node-promotion guards used for user-mapped
    /// fields: over-long free text and timestamp-shaped values are unique
    /// per row and would mint one dead node per event. Purely numeric ids
    /// are *kept* here, unlike in that path — `request_id` and `job_id` are
    /// normally numeric, and dropping them would silently lose exactly the
    /// correlation this feature exists to capture.
    pub fn session_entity_id(raw: &str) -> Option<String> {
        let v = raw.trim();
        if v.is_empty()
            || v.len() > crate::field_preview::MAX_NODE_VALUE_LEN
            || crate::field_preview::value_looks_like_timestamp(v)
        {
            return None;
        }
        Some(format!("session:{v}"))
    }

    /// Generates triples from a single normalized event using relationship inference rules.
    pub fn parse_event(event: &Value) -> Vec<ParsedTriple> {
        let n = Self::normalize(event);
        let mut triples = Vec::new();

        // Action-aware rel_type: when the event carries a canonical `action`
        // field and it maps unambiguously to a RelationType, use that to
        // override the default rel_type on anchor→target rules below.
        // Structural relations (Spawn from parent→child process, Execute
        // from user→process pairing) intentionally ignore this because the
        // semantic is fixed by the field structure, not by the action label.
        let action_rel = Self::find_action_relation(event);

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
            let rt = action_rel.clone().unwrap_or(RelationType::Connect);
            let mut rel = Relation::new(host, ip, rt, n.timestamp);
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
                let rt = action_rel.clone().unwrap_or(RelationType::Connect);
                let mut rel = Relation::new(sip, dip, rt, n.timestamp);
                if let Some(ref proto) = n.protocol {
                    rel = rel.with_metadata("protocol", proto);
                }
                triples.push((src, rel, dst));
            }
        }

        // Rule: source_host + source_process → Host -[Execute]-> Process
        // Captures EVTX events where a process/service/task runs on a host (TaskScheduler, OpenSSH, Firewall, etc.)
        if let (Some(host), Some(proc)) = (&n.source_host, &n.source_process) {
            if n.source_user.is_none() {
                let src = Entity::new(host, EntityType::Host);
                let dst = {
                    let mut e = Entity::new(proc, EntityType::Process);
                    if let Some(ref cmd) = n.command_line {
                        e = e.with_metadata("cmdline", cmd);
                    }
                    e
                };
                let rel = Relation::new(host, proc, RelationType::Execute, n.timestamp);
                triples.push((src, rel, dst));
            }
        }

        // Rule: source_user + source_host → User -[Auth]-> Host
        if let (Some(user), Some(host)) = (&n.source_user, &n.source_host) {
            // Only if we don't have a process (otherwise user→execute→process is more specific)
            if n.source_process.is_none() {
                let src = Entity::new(user, EntityType::User);
                let dst = Entity::new(host, EntityType::Host);
                let rt = action_rel.clone().unwrap_or(RelationType::Auth);
                let rel = Relation::new(user, host, rt, n.timestamp);
                triples.push((src, rel, dst));
            }
        }

        // Rule: source_user + source_process + source_host → User -[Execute]-> Process (+ Process -[Execute]-> Host)
        // When all three are present, link user to process and process to host
        if let (Some(user), Some(proc), Some(host)) =
            (&n.source_user, &n.source_process, &n.source_host)
        {
            let src = Entity::new(proc, EntityType::Process);
            let dst = Entity::new(host, EntityType::Host);
            let rel = Relation::new(proc, host, RelationType::Execute, n.timestamp);
            triples.push((src, rel, dst));
            // user→execute→process already emitted above
            let _ = (user, host); // suppress unused warnings; triples already cover the chain
        }

        // Rule: target_user + source_host → User -[Auth]-> Host (e.g. EVTX 4624 TargetUserName + Computer)
        if let (Some(user), Some(host)) = (&n.target_user, &n.source_host) {
            if n.source_process.is_none() && n.source_user.is_none() {
                let src = Entity::new(user, EntityType::User);
                let dst = Entity::new(host, EntityType::Host);
                let rt = action_rel.clone().unwrap_or(RelationType::Auth);
                let rel = Relation::new(user, host, rt, n.timestamp);
                triples.push((src, rel, dst));
            }
        }

        // Rule: source_process + target_file → Process -[Write]-> File
        if let (Some(proc), Some(file)) = (&n.source_process, &n.target_file) {
            let src = Entity::new(proc, EntityType::Process);
            let dst = Entity::new(file, EntityType::File);
            let rt = action_rel.clone().unwrap_or(RelationType::Write);
            let rel = Relation::new(proc, file, rt, n.timestamp);
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
            let rt = action_rel.clone().unwrap_or(RelationType::Connect);
            let rel = Relation::new(proc, url, rt, n.timestamp);
            triples.push((src, rel, dst));
        }

        // Rule: source_process + target_registry → Process -[Modify]-> Registry
        if let (Some(proc), Some(reg)) = (&n.source_process, &n.target_registry) {
            let src = Entity::new(proc, EntityType::Process);
            let dst = Entity::new(reg, EntityType::Registry);
            let rt = action_rel.clone().unwrap_or(RelationType::Modify);
            let rel = Relation::new(proc, reg, rt, n.timestamp);
            triples.push((src, rel, dst));
        }

        // Rule: source_user + target_ip (no process) → User -[Auth]-> IP
        if let (Some(user), Some(ip)) = (&n.source_user, &n.target_ip) {
            if n.source_process.is_none() && n.source_host.is_none() {
                let src = Entity::new(user, EntityType::User);
                let dst = Entity::new(ip, EntityType::IP);
                let rt = action_rel.clone().unwrap_or(RelationType::Auth);
                let rel = Relation::new(user, ip, rt, n.timestamp);
                triples.push((src, rel, dst));
            }
        }

        // Rule: source_user + source_ip (no target_ip, no process, no host) → User -[Auth]-> IP.
        // Covers audit/activity logs where the single IP_ADDRESS field is the
        // actor's originating endpoint (Zoho, SaaS audit exports, M365 UAL, etc.).
        if let (Some(user), Some(ip)) = (&n.source_user, &n.source_ip) {
            if n.target_ip.is_none() && n.source_process.is_none() && n.source_host.is_none() {
                let src = Entity::new(user, EntityType::User);
                let dst = Entity::new(ip, EntityType::IP);
                let rt = action_rel.clone().unwrap_or(RelationType::Auth);
                let rel = Relation::new(user, ip, rt, n.timestamp);
                triples.push((src, rel, dst));
            }
        }

        // Rule: correlation id → Session hub node.
        //
        // A session is what threads many events into one logical visit, and
        // it is the artefact hunting actually reasons about: "the same
        // session seen from two addresses" is evidence, while "two events
        // from two addresses" is not. Before this rule the id sat in the
        // source data and never reached the graph, so that question had to
        // be answered with a script over the raw file.
        //
        // Topology is a star with the session at the centre:
        //
        //     User -[Uses]-> Session -[From]-> IP
        //
        // which makes the continuity question one pattern with the session
        // as the grouping node, rather than a join the analyst does by hand.
        if let Some(session_id) = n.session.as_deref().and_then(Self::session_entity_id) {
            let sess = || Entity::new(&session_id, session_entity_type());

            // Prefer the acting user; fall back to the target for logs that
            // only name the account being acted on.
            if let Some(user) = n.source_user.as_ref().or(n.target_user.as_ref()) {
                let src = Entity::new(user, EntityType::User);
                let rel = Relation::new(
                    user,
                    &session_id,
                    RelationType::Other("Uses".into()),
                    n.timestamp,
                );
                triples.push((src, rel, sess()));
            }

            // Only `source_ip`: it is the endpoint the session was observed
            // from. `target_ip` is where the actor went, which is a
            // different fact and would read as a false origin.
            if let Some(ip) = &n.source_ip {
                let rel = Relation::new(
                    &session_id,
                    ip,
                    RelationType::Other("From".into()),
                    n.timestamp,
                );
                triples.push((sess(), rel, Entity::new(ip, EntityType::IP)));
            } else if let Some(host) = &n.source_host {
                let rel = Relation::new(
                    &session_id,
                    host,
                    RelationType::Other("From".into()),
                    n.timestamp,
                );
                triples.push((sess(), rel, Entity::new(host, EntityType::Host)));
            }
        }

        // Fallback: ensure every event with at least one entity field produces a triple (e.g. EVTX with any EventID).
        // Covers both source-side and target-side singleton fields. Target-side
        // singletons are common in DNS / proxy / DLP exports where the actor
        // is anonymised and only `target_*` survives — without this branch
        // those rows produce zero triples and land as "skipped".
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
            } else if let Some(user) = &n.target_user {
                let u = Entity::new(user, EntityType::User);
                let rel = Relation::new(user, user, RelationType::Auth, n.timestamp);
                triples.push((u.clone(), rel, u));
            } else if let Some(ip) = &n.source_ip {
                // B1.5 piece 2. The chain below already gave `target_ip`
                // a singleton self-loop, but `source_ip` had none, so an
                // event whose only entity was the address it came FROM
                // produced nothing at all and left no trace in the graph
                // — while the mirror-image event, naming only where it
                // went, became a node. Nothing principled distinguished
                // the two; it was an omission.
                //
                // It cost real evidence: in the field-case corpus 642 events
                // carry an IP and no user (their `ipAddress` canonicalizes
                // to `source_ip`), and 399 of those are the
                // `realm_disabled` rejections from the incident's
                // containment window. They were invisible to every graph
                // query and had to be recovered from the raw CSV.
                //
                // The metadata-role stamping in `ConfigurableParser` runs
                // over every triple an event produced, this one included,
                // so the edge keeps the event's own attributes: the
                // containment window becomes reachable as
                // `IP -[Connect {error="realm_disabled"}]-> IP`.
                let i = Entity::new(ip, EntityType::IP);
                let rel = Relation::new(ip, ip, RelationType::Connect, n.timestamp);
                triples.push((i.clone(), rel, i));
            } else if let Some(ip) = &n.target_ip {
                let i = Entity::new(ip, EntityType::IP);
                let rel = Relation::new(ip, ip, RelationType::Connect, n.timestamp);
                triples.push((i.clone(), rel, i));
            } else if let Some(domain) = &n.target_domain {
                let d = Entity::new(domain, EntityType::Domain);
                let rel = Relation::new(domain, domain, RelationType::DNS, n.timestamp);
                triples.push((d.clone(), rel, d));
            } else if let Some(file) = &n.target_file {
                let f = Entity::new(file, EntityType::File);
                let rel = Relation::new(file, file, RelationType::Write, n.timestamp);
                triples.push((f.clone(), rel, f));
            } else if let Some(url) = &n.target_url {
                let u = Entity::new(url, EntityType::URL);
                let rel = Relation::new(url, url, RelationType::Connect, n.timestamp);
                triples.push((u.clone(), rel, u));
            } else if let Some(reg) = &n.target_registry {
                let r = Entity::new(reg, EntityType::Registry);
                let rel = Relation::new(reg, reg, RelationType::Modify, n.timestamp);
                triples.push((r.clone(), rel, r));
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
        map.insert(
            "cef_version".to_string(),
            Value::String(parts[0].to_string()),
        );
        map.insert(
            "device_vendor".to_string(),
            Value::String(parts[1].to_string()),
        );
        map.insert(
            "device_product".to_string(),
            Value::String(parts[2].to_string()),
        );
        map.insert(
            "device_version".to_string(),
            Value::String(parts[3].to_string()),
        );
        map.insert(
            "signature_id".to_string(),
            Value::String(parts[4].to_string()),
        );
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
        map.insert(
            "leef_version".to_string(),
            Value::String(parts[0].to_string()),
        );
        map.insert(
            "device_vendor".to_string(),
            Value::String(parts[1].to_string()),
        );
        map.insert(
            "device_product".to_string(),
            Value::String(parts[2].to_string()),
        );
        map.insert(
            "device_version".to_string(),
            Value::String(parts[3].to_string()),
        );
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

        fn flatten_recursive(
            prefix: &str,
            value: &Value,
            out: &mut serde_json::Map<String, Value>,
        ) {
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
                return arr
                    .into_iter()
                    .map(|e| Self::flatten_nested_json(&e))
                    .collect();
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
                return arr
                    .into_iter()
                    .map(|e| Self::flatten_nested_json(&e))
                    .collect();
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
                return arr
                    .into_iter()
                    .take(limit)
                    .map(|e| Self::flatten_nested_json(&e))
                    .collect();
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

    fn parse_with_stats(&self, data: &str) -> (Vec<ParsedTriple>, crate::parser::ParseStats) {
        let events = Self::parse_events(data);
        parse_events_with_stats(&events, |event| Self::parse_event(event))
    }

    /// Native raw-event override for the generic/config path (Fase C-2
    /// Task 3, field_survival). Only the parsed `Value` — not the original
    /// raw `&str` — is in scope at emit time here (the raw row is discarded
    /// per-line inside `parse_events`), so each produced event carries the
    /// canonical (sorted-key) serialization of its pre-mapping `Value`
    /// instead of the literal source bytes. That still reconstructs every
    /// field the field-config mapping later drops. See
    /// `crate::parser::canonical_value_string`.
    fn parse_raw(&self, data: &str) -> Vec<crate::parser::RawIngestEvent> {
        let events = Self::parse_events(data);
        if events.is_empty() {
            return Vec::new();
        }

        events
            .par_iter()
            .flat_map(|event| {
                let triples = Self::parse_event(event);
                if triples.is_empty() {
                    return Vec::new();
                }
                let raw_line = crate::parser::canonical_value_string(event);
                triples
                    .into_iter()
                    .map(|t| {
                        let mut e = crate::parser::RawIngestEvent::from_parsed_triple(t);
                        e.raw_line = Some(raw_line.clone());
                        e
                    })
                    .collect::<Vec<_>>()
            })
            .collect()
    }

    /// Raw-event-with-stats variant of [`parse_raw`]. Single pass: the
    /// per-event triples computed for the aggregate counters (rows_seen,
    /// per_field_occurrence, drift, skip_reasons, ...) are reused to build
    /// the `RawIngestEvent`s, instead of re-running `parse_event` on every
    /// row a second time as this used to do.
    fn parse_raw_with_stats(
        &self,
        data: &str,
    ) -> (Vec<crate::parser::RawIngestEvent>, crate::parser::ParseStats) {
        let events = Self::parse_events(data);
        let (each, stats) = parse_events_each_with_stats(&events, |event| Self::parse_event(event));
        (raw_events_from_each(&events, each), stats)
    }

    /// Generic Result variant (RH-P1-012).
    ///
    /// Reuses `parse_events` + per-event triple extraction, but events that
    /// produce zero triples are surfaced as `Err(ParseError::MalformedRow)`
    /// instead of being silently counted as "skipped". The reason string
    /// reuses `classify_skip_reason` so the DLQ explanation matches what
    /// `parse_with_stats` already reports via `skip_reasons`.
    fn try_parse(&self, data: &str) -> Vec<Result<ParsedTriple, crate::parser::ParseError>> {
        let events = Self::parse_events(data);
        let mut out: Vec<Result<ParsedTriple, crate::parser::ParseError>> = Vec::new();
        for (lineno, event) in events.iter().enumerate() {
            let triples = Self::parse_event(event);
            if triples.is_empty() {
                let reason = classify_skip_reason(event);
                out.push(Err(crate::parser::ParseError::MalformedRow {
                    line: lineno,
                    reason: reason.to_string(),
                }));
            } else {
                for t in triples {
                    out.push(Ok(t));
                }
            }
        }
        out
    }
}

/// Runs `per_event` on each event, aggregates the produced triples, and
/// returns [`ParseStats`] describing how many rows yielded at least one
/// triple plus per-field occurrence counts sampled from the event stream.
///
/// Kept at module level so `ConfigurableParser` can share the same counter
/// logic without duplicating bookkeeping.
pub fn parse_events_with_stats<F>(
    events: &[Value],
    per_event: F,
) -> (Vec<ParsedTriple>, crate::parser::ParseStats)
where
    F: Fn(&Value) -> Vec<ParsedTriple> + Sync,
{
    let (each, stats) = parse_events_each_with_stats(events, per_event);
    (each.into_iter().flatten().collect(), stats)
}

/// Like [`parse_events_with_stats`] but returns the triples still grouped
/// per input event (index-aligned with `events`). Callers that need the
/// event↔triples association — e.g. `parse_raw_with_stats` attaching each
/// event's canonical `raw_line` — use this instead of re-running the
/// per-event parse a second time.
pub fn parse_events_each_with_stats<F>(
    events: &[Value],
    per_event: F,
) -> (Vec<Vec<ParsedTriple>>, crate::parser::ParseStats)
where
    F: Fn(&Value) -> Vec<ParsedTriple> + Sync,
{
    use rayon::prelude::*;
    use std::collections::HashMap;

    let mut stats = crate::parser::ParseStats::default();
    stats.rows_seen = events.len();
    if events.is_empty() {
        return (Vec::new(), stats);
    }

    // The per-event parse (canonical matching, entity building) dominates
    // wall time, so it fans out over rayon. Aggregation below stays
    // sequential and index-ordered: skipped_samples keep the first 20
    // skipped rows in input order and drift observation stays
    // deterministic, exactly as the pre-parallel implementation behaved.
    let mut each: Vec<Vec<ParsedTriple>> = events.par_iter().map(|e| per_event(e)).collect();

    // Session ceiling. Applied here, before the skip accounting below, so
    // an event whose only output was a session edge is correctly counted
    // as skipped once that edge is refused — otherwise the report would
    // claim rows produced triples that never reached the graph.
    let distinct_sessions: std::collections::HashSet<&str> = each
        .iter()
        .flatten()
        .filter(|(src, _, _)| is_session_entity(src))
        .map(|(src, _, _)| src.id.as_str())
        .chain(
            each.iter()
                .flatten()
                .filter(|(_, _, dst)| is_session_entity(dst))
                .map(|(_, _, dst)| dst.id.as_str()),
        )
        .collect();
    stats.sessions_seen = distinct_sessions.len();
    if stats.sessions_seen > max_session_entities() {
        stats.sessions_dropped = stats.sessions_seen;
        for group in each.iter_mut() {
            group.retain(|(src, _, dst)| !is_session_entity(src) && !is_session_entity(dst));
        }
    }
    let each = each;

    let mut per_field: HashMap<String, usize> = HashMap::new();
    let mut skip_reasons: HashMap<String, usize> = HashMap::new();
    let mut drift = crate::drift::DriftCollector::new();
    // Reservoir-sampled skipped rows. Deterministic (positional) so tests
    // are stable and the UI sees the first 20 skipped rows in input order.
    const SKIP_SAMPLE_CAP: usize = 20;
    let mut skipped_samples: Vec<(String, String)> = Vec::with_capacity(SKIP_SAMPLE_CAP);

    for (event, triples) in events.iter().zip(each.iter()) {
        if let Some(obj) = event.as_object() {
            for (k, v) in obj {
                let has_value = match v {
                    Value::String(s) => !s.is_empty(),
                    Value::Null => false,
                    _ => true,
                };
                if has_value {
                    *per_field.entry(k.clone()).or_insert(0) += 1;
                }
            }
        }
        drift.observe_event(event);
        if triples.is_empty() {
            stats.rows_skipped += 1;
            let reason = classify_skip_reason(event);
            *skip_reasons.entry(reason.to_string()).or_insert(0) += 1;
            if skipped_samples.len() < SKIP_SAMPLE_CAP {
                let raw =
                    serde_json::to_string(event).unwrap_or_else(|_| "<unserializable>".to_string());
                skipped_samples.push((raw, reason.to_string()));
            }
        } else {
            stats.rows_with_triples += 1;
        }
    }

    stats.per_field_occurrence = per_field;
    stats.skip_reasons = skip_reasons;
    stats.skipped_samples = skipped_samples;
    stats.drift = Some(drift.into_snapshot());
    (each, stats)
}

/// Lifts per-event triple groups (from [`parse_events_each_with_stats`])
/// into `RawIngestEvent`s, serializing each event's canonical `raw_line`
/// exactly once. Shared by the `parse_raw_with_stats` impls that used to
/// re-run the whole per-event parse just to rebuild this association.
pub fn raw_events_from_each(
    events: &[Value],
    each: Vec<Vec<ParsedTriple>>,
) -> Vec<crate::parser::RawIngestEvent> {
    use rayon::prelude::*;
    events
        .par_iter()
        .zip(each.into_par_iter())
        .flat_map(|(event, triples)| {
            if triples.is_empty() {
                return Vec::new();
            }
            let raw_line = crate::parser::canonical_value_string(event);
            triples
                .into_iter()
                .map(|t| {
                    let mut e = crate::parser::RawIngestEvent::from_parsed_triple(t);
                    e.raw_line = Some(raw_line.clone());
                    e
                })
                .collect::<Vec<_>>()
        })
        .collect()
}

/// Type name carried by session hub nodes. Kept in one place because the
/// parser mints them, the ingest ceiling counts them and the DSL matches
/// them by `Display` string — three call sites that must not drift.
pub const SESSION_TYPE_NAME: &str = "Session";

/// The entity type of a session hub node. `Other` rather than a new enum
/// variant: `EntityType` is serialized into session files and crosses the
/// FFI boundary by tag, and `Other` already round-trips through the
/// `OtherTypeMap` without touching either layout.
pub fn session_entity_type() -> EntityType {
    EntityType::Other(SESSION_TYPE_NAME.to_string())
}

/// True when this entity is a session hub node.
pub fn is_session_entity(e: &Entity) -> bool {
    matches!(&e.entity_type, EntityType::Other(t) if t == SESSION_TYPE_NAME)
}

/// Ceiling on how many distinct session nodes one parse batch may create.
///
/// Sessions are numerous by nature — roughly one per handful of events —
/// so a *proportional* rule is the wrong instrument: sessions legitimately
/// dominate the node count (in the corpus that motivated this feature,
/// 60.145 sessions against 26.183 other entities, i.e. 70% of the graph),
/// and a percentage ceiling would reject exactly the case the feature
/// exists for. What actually needs bounding is memory, so the ceiling is
/// absolute. At ~200 B per `Entity` plus its id, this default caps session
/// nodes at roughly 100 MB.
///
/// Overridable with `GRAPHHUNTER_MAX_SESSION_ENTITIES` — an escape hatch,
/// not a required setting: sessions are on by default with no
/// configuration.
///
/// **Scope caveat:** the ceiling is per parse batch. A streaming ingest
/// that feeds many batches can exceed it in aggregate; bounding the whole
/// graph needs the count at insert time, which this does not do.
pub const MAX_SESSION_ENTITIES: usize = 500_000;

pub(crate) fn max_session_entities() -> usize {
    std::env::var("GRAPHHUNTER_MAX_SESSION_ENTITIES")
        .ok()
        .and_then(|v| v.trim().parse::<usize>().ok())
        .filter(|v| *v > 0)
        .unwrap_or(MAX_SESSION_ENTITIES)
}

/// Canonical fields that can become one end of a relation. A row needs at
/// least two of these filled in to produce a triple at all, which is what
/// [`classify_skip_reason`] uses to tell a data property apart from a
/// parser failure.
const ENDPOINT_FIELDS: &[&str] = &[
    "source_user",
    "target_user",
    "source_ip",
    "target_ip",
    "source_host",
    "source_process",
    "parent_process",
    "target_file",
];

/// Post-hoc classification of why a row produced no triples. Cheap heuristic
/// so the UI can drill down into skip counts without asking the parser to
/// emit a reason per-row. Order matters: empty > no_canonical > no_anchor >
/// single_endpoint > other.
///
/// The `single_endpoint` bucket exists because the previous catch-all
/// conflated two situations that call for opposite responses: a row the
/// parser failed on (fix the parser) and a row that structurally *cannot*
/// yield a relation because only one entity is named (fix nothing — the
/// event is simply one-sided). Both landed in `no_triple_emitted`, so an
/// analyst reading the skip report could not tell which they had.
///
/// This is not hypothetical. In the field-case Keycloak corpus, 642 events
/// carry an IP and no user, and 399 of them are the `realm_disabled`
/// rejections from the incident's containment window — the single most
/// important event of the investigation, silently pooled with parser
/// noise. See `docs/superpowers/plans/2026-08-13-hoja-de-ruta-auditada.md`
/// item B1.5.
pub(crate) fn classify_skip_reason(event: &Value) -> &'static str {
    let obj = match event.as_object() {
        Some(o) if !o.is_empty() => o,
        _ => return "empty_row",
    };
    // Any non-empty cell?
    let any_value = obj.iter().any(|(_, v)| has_value(v));
    if !any_value {
        return "empty_row";
    }
    // Count canonical-field hits (excluding the ones we know are metadata-only).
    let mut has_canonical = false;
    let mut has_anchor_source = false;
    // Distinct *canonical* endpoints carrying a value. Distinct matters:
    // several raw headers can collapse onto the same canonical (e.g. both
    // `destinationHostname` and `dst_ip` map to `target_ip`), and that is
    // one endpoint, not two.
    let mut endpoints: std::collections::HashSet<&'static str> = std::collections::HashSet::new();
    for (key, val) in obj {
        if let Some(c) = GenericParser::canonical_field(key) {
            has_canonical = true;
            if matches!(
                c,
                "source_user"
                    | "target_user"
                    | "source_ip"
                    | "target_ip"
                    | "source_host"
                    | "source_process"
                    | "parent_process"
            ) {
                has_anchor_source = true;
            }
            // A present-but-empty column is not an endpoint. This is the
            // whole point: the one-sided rows carry the *key* for the
            // missing side, just no value in it.
            if ENDPOINT_FIELDS.contains(&c) && has_value(val) {
                endpoints.insert(c);
            }
        }
    }
    if !has_canonical {
        return "no_canonical_fields";
    }
    if !has_anchor_source {
        return "no_anchor";
    }
    if endpoints.len() == 1 {
        return "single_endpoint";
    }
    "no_triple_emitted"
}

/// Whether a JSON cell holds anything usable. Empty strings and nulls are
/// both "absent" — CSV ingest produces the former, JSON the latter, and
/// the distinction is meaningless to the caller.
fn has_value(v: &Value) -> bool {
    match v {
        Value::String(s) => !s.trim().is_empty(),
        Value::Null => false,
        _ => true,
    }
}

#[cfg(test)]
mod session_entity_tests {
    use super::*;
    use serde_json::json;

    fn edge(triples: &[ParsedTriple], rel: &str) -> Option<(String, String)> {
        triples
            .iter()
            .find(|(_, r, _)| r.rel_type.to_string() == rel)
            .map(|(s, _, d)| (s.id.clone(), d.id.clone()))
    }

    /// The shape the hunt needs: one pattern from user through session to
    /// address, instead of a join done by hand over the raw file.
    #[test]
    fn builds_the_user_session_ip_star() {
        let event = json!({
            "timestamp": "2026-07-24T19:42:51Z",
            "username": "usuario.tres@example.com",
            "sessionId": "bbbb0001-1111-2222-3333-444455556666",
            "ipAddress": "203.0.113.21"
        });
        let triples = GenericParser::parse_event(&event);
        assert_eq!(
            edge(&triples, "Uses"),
            Some((
                "usuario.tres@example.com".into(),
                "session:bbbb0001-1111-2222-3333-444455556666".into()
            ))
        );
        assert_eq!(
            edge(&triples, "From"),
            Some((
                "session:bbbb0001-1111-2222-3333-444455556666".into(),
                "203.0.113.21".into()
            ))
        );
    }

    /// The prefix is load-bearing: Keycloak mints `userId` and `sessionId`
    /// from the same UUID generator, so a bare value would fuse a session
    /// node into an unrelated user node.
    #[test]
    fn session_ids_are_namespaced_against_collisions() {
        let shared = "29ab57e4-3105-4eda-9ce5-18dcc0010c22";
        assert_eq!(
            GenericParser::session_entity_id(shared),
            Some(format!("session:{shared}"))
        );
        assert_ne!(
            GenericParser::session_entity_id(shared).unwrap(),
            shared,
            "a bare id would collide with the User node of the same UUID"
        );
    }

    /// Numeric correlation ids are the norm for `request_id` / `job_id`.
    /// The node-promotion path drops all-digit values; doing that here
    /// would silently lose the correlation this feature is for.
    #[test]
    fn numeric_correlation_ids_survive() {
        assert_eq!(
            GenericParser::session_entity_id("8814072"),
            Some("session:8814072".into())
        );
    }

    /// Values that are unique per row and mean nothing as a node stay off
    /// the graph, matching the guards the user-mapping path applies.
    #[test]
    fn junk_session_values_are_refused() {
        assert_eq!(GenericParser::session_entity_id(""), None);
        assert_eq!(GenericParser::session_entity_id("   "), None);
        assert_eq!(GenericParser::session_entity_id("2026-06-18T15:56:13"), None);
        assert_eq!(GenericParser::session_entity_id(&"x".repeat(300)), None);
    }

    /// No session field must mean no session node — this rule cannot
    /// invent a hub for sources that do not correlate their events.
    #[test]
    fn sources_without_a_session_field_are_untouched() {
        let event = json!({
            "timestamp": "2026-07-24T19:42:51Z",
            "username": "alice",
            "ipAddress": "10.0.0.1"
        });
        let triples = GenericParser::parse_event(&event);
        assert!(
            !triples.iter().any(|(s, _, d)| is_session_entity(s) || is_session_entity(d)),
            "no session field, no session node"
        );
        assert!(!triples.is_empty(), "the User->IP edge must still be there");
    }

    /// `target_ip` is where the actor went, not where the session came
    /// from. Using it as the origin would read as a false provenance.
    #[test]
    fn only_the_source_address_becomes_the_session_origin() {
        let event = json!({
            "timestamp": "2026-07-24T19:42:51Z",
            "sessionId": "abc-123",
            "src_ip": "10.0.0.1",
            "dst_ip": "8.8.8.8"
        });
        let triples = GenericParser::parse_event(&event);
        assert_eq!(
            edge(&triples, "From"),
            Some(("session:abc-123".into(), "10.0.0.1".into()))
        );
    }

    /// The ceiling must refuse the nodes AND say so. A silent drop would
    /// surface later as an empty session query with no explanation.
    #[test]
    fn the_ceiling_drops_sessions_and_reports_it() {
        // SAFETY: restored before the test returns.
        unsafe { std::env::set_var("GRAPHHUNTER_MAX_SESSION_ENTITIES", "2") };
        let json = r#"[
            {"timestamp":"2026-07-24T19:42:51Z","username":"a","sessionId":"s1","ipAddress":"10.0.0.1"},
            {"timestamp":"2026-07-24T19:42:52Z","username":"b","sessionId":"s2","ipAddress":"10.0.0.2"},
            {"timestamp":"2026-07-24T19:42:53Z","username":"c","sessionId":"s3","ipAddress":"10.0.0.3"}
        ]"#;
        let (triples, stats) = GenericParser.parse_with_stats(json);
        unsafe { std::env::remove_var("GRAPHHUNTER_MAX_SESSION_ENTITIES") };

        assert_eq!(stats.sessions_seen, 3);
        assert_eq!(stats.sessions_dropped, 3, "over the ceiling, none survive");
        assert!(
            !triples.iter().any(|(s, _, d)| is_session_entity(s) || is_session_entity(d)),
            "no session node may reach the graph once the ceiling trips"
        );
        // The User->IP edges are unaffected: the ceiling bounds sessions,
        // not the rest of the ingest.
        assert_eq!(triples.len(), 3);
        assert_eq!(stats.rows_skipped, 0);
    }

    /// Under the ceiling, sessions are on with no configuration at all.
    #[test]
    fn under_the_ceiling_sessions_are_on_by_default() {
        let json = r#"[
            {"timestamp":"2026-07-24T19:42:51Z","username":"a","sessionId":"s1","ipAddress":"10.0.0.1"}
        ]"#;
        let (triples, stats) = GenericParser.parse_with_stats(json);
        assert_eq!(stats.sessions_seen, 1);
        assert_eq!(stats.sessions_dropped, 0);
        assert!(triples.iter().any(|(s, _, _)| is_session_entity(s)));
    }
}

#[cfg(test)]
mod skip_reason_tests {
    use super::*;
    use serde_json::json;

    /// The field-case shape: an IP, no user. Nothing is wrong with the parser
    /// — a relation needs two ends and this event names one.
    #[test]
    fn one_sided_row_is_single_endpoint_not_a_parser_failure() {
        let event = json!({
            "time": "1784921286240",
            "type": "REGISTER_ERROR",
            "userId": "",
            "ipAddress": "203.0.113.164",
            "error": "realm_disabled"
        });
        assert_eq!(classify_skip_reason(&event), "single_endpoint");
    }

    /// A column that exists but is empty must not count as an end. The
    /// one-sided rows carry the key for the missing side precisely
    /// because the export has a fixed header.
    #[test]
    fn a_present_but_empty_column_is_not_an_endpoint() {
        let filled = json!({"src_ip": "10.0.0.1", "username": "alice"});
        let empty = json!({"src_ip": "10.0.0.1", "username": "   "});
        assert_eq!(classify_skip_reason(&filled), "no_triple_emitted");
        assert_eq!(classify_skip_reason(&empty), "single_endpoint");
    }

    /// Two ends present and still no triple: that is the parser's problem,
    /// and it must stay in its own bucket so the new one keeps meaning
    /// something.
    #[test]
    fn two_endpoints_and_no_triple_stays_a_parser_failure() {
        let event = json!({"src_ip": "10.0.0.1", "dst_ip": "8.8.8.8"});
        assert_eq!(classify_skip_reason(&event), "no_triple_emitted");
    }

    /// Several raw headers can collapse onto one canonical endpoint.
    /// Counting keys instead of canonicals would call this two ends and
    /// silently reclassify a one-sided row as a parser bug.
    #[test]
    fn distinct_canonicals_are_counted_not_distinct_headers() {
        // `destinationHostname` and `dst_ip` both canonicalize to target_ip.
        let event = json!({
            "destinationHostname": "web01",
            "dst_ip": "8.8.8.8"
        });
        assert_eq!(classify_skip_reason(&event), "single_endpoint");
    }

    /// The earlier buckets must keep winning — this change adds a rung to
    /// the ladder, it does not reorder it.
    #[test]
    fn earlier_classifications_still_take_precedence() {
        assert_eq!(classify_skip_reason(&json!({})), "empty_row");
        assert_eq!(
            classify_skip_reason(&json!({"src_ip": "", "username": ""})),
            "empty_row"
        );
        assert_eq!(
            classify_skip_reason(&json!({"colour": "blue", "size": "L"})),
            "no_canonical_fields"
        );
        // Canonical fields, but none that can anchor a relation.
        assert_eq!(
            classify_skip_reason(&json!({"timestamp": "2024-01-15T14:30:00Z"})),
            "no_anchor"
        );
    }

    /// B1.5 piece 2 changed this outcome deliberately: a one-sided source
    /// address now produces a singleton self-loop instead of nothing, so
    /// these rows are no longer skipped at all. The counter was measuring
    /// a loss; the loss is fixed at the source.
    #[test]
    fn one_sided_source_addresses_now_reach_the_graph() {
        let json = r#"[
            {"timestamp":"2024-01-15T14:30:00Z","ipAddress":"203.0.113.164","error":"realm_disabled"},
            {"timestamp":"2024-01-15T14:31:00Z","ipAddress":"203.0.113.165","error":"realm_disabled"}
        ]"#;
        let (triples, stats) = GenericParser.parse_with_stats(json);
        assert_eq!(stats.rows_seen, 2);
        assert_eq!(
            stats.rows_skipped, 0,
            "a lone source address is now a node, not a dropped row: {:?}",
            stats.skip_reasons
        );
        assert_eq!(triples.len(), 2);
        assert!(
            triples.iter().all(|(s, _, d)| s.id == d.id),
            "singleton events are represented as self-loops, matching how \
             target-side singletons were already handled"
        );
        assert_eq!(triples[0].0.entity_type, EntityType::IP);
    }

    /// The classification outlives the specific gap it was found through:
    /// a row whose only endpoint has no singleton fallback is still
    /// reported as one-sided rather than as a parser failure.
    #[test]
    fn single_endpoint_still_reaches_the_ingest_report() {
        // `parentImage` alone: an anchor-capable endpoint with no
        // singleton rule of its own.
        let json = r#"[
            {"timestamp":"2024-01-15T14:30:00Z","parentImage":"C:/Windows/explorer.exe"},
            {"timestamp":"2024-01-15T14:31:00Z","parentImage":"C:/Windows/svchost.exe"}
        ]"#;
        let (_, stats) = GenericParser.parse_with_stats(json);
        assert_eq!(stats.rows_seen, 2);
        assert_eq!(
            stats.skip_reasons.get("single_endpoint"),
            Some(&2),
            "one-sided rows must still be told apart from parser failures, got {:?}",
            stats.skip_reasons
        );
    }
}

/// Fase C-2 Task 3: `raw_line` capture on the generic/config parse path.
/// Only a parsed `Value` is in scope at emit time (the raw `&str` is
/// discarded per-line inside `parse_events`), so the captured `raw_line` is
/// the canonical (sorted-key) serialization of that pre-mapping `Value`
/// rather than the literal source bytes.
#[cfg(test)]
mod raw_line_tests {
    use super::*;

    #[test]
    fn generic_parse_attaches_canonical_raw_line() {
        let json = r#"[{
            "timestamp": "2024-01-15T14:30:00Z",
            "src_ip": "10.0.0.1",
            "dst_ip": "8.8.8.8",
            "dst_port": "53",
            "protocol": "UDP"
        }]"#;

        let (events, _stats) = GenericParser.parse_raw_with_stats(json);

        assert!(!events.is_empty());
        // Every produced event carries the canonical serialization of its
        // source Value.
        assert!(events.iter().all(|e| e.raw_line.is_some()));
        // The raw_line contains a field from the original row.
        let raw = events[0].raw_line.as_ref().unwrap();
        assert!(raw.contains("src_ip"));
        assert!(raw.contains("8.8.8.8"));

        // `parse_raw` (used on the streaming ingest path) attaches the same
        // canonical raw_line.
        let raw_only = GenericParser.parse_raw(json);
        assert!(!raw_only.is_empty());
        assert!(raw_only.iter().all(|e| e.raw_line.is_some()));
    }

    #[test]
    fn generic_parse_raw_line_is_stable_across_key_order() {
        // Two Values with the same fields in different key order must
        // produce the same canonical raw_line — otherwise a re-parse of
        // semantically identical JSON would look like drift in the journal.
        let a = r#"[{"src_ip": "10.0.0.1", "dst_ip": "8.8.8.8", "dst_port": "53", "protocol": "UDP"}]"#;
        let b = r#"[{"protocol": "UDP", "dst_port": "53", "dst_ip": "8.8.8.8", "src_ip": "10.0.0.1"}]"#;

        let events_a = GenericParser.parse_raw(a);
        let events_b = GenericParser.parse_raw(b);

        assert_eq!(events_a.len(), 1);
        assert_eq!(events_b.len(), 1);
        assert_eq!(events_a[0].raw_line, events_b[0].raw_line);
    }
}
