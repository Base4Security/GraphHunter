//! Log format registry: name → parser + detector + preview fields.
//!
//! Moved from `app/src-tauri/src/format_registry.rs`. Adding a new
//! format is still a single append to [`FORMAT_REGISTRY`]
//! (open/closed). The registry plus its three public entry points
//! (`find_descriptor`, `resolve_format`, `make_parser_for_format`) are
//! used by the ingest pipeline and by `cmd_run_kql`.

use graph_hunter_core::{
    CsvParser, FieldInfo, FieldRole, GenericParser, LogParser, SentinelJsonParser,
    SysmonJsonParser, preview_fields_from_events, preview_generic_from_keys, preview_sentinel,
    preview_sysmon,
};
use graph_hunter_parsers::{
    CdmParser, CognitoParser, EtwNodlinkParser, FortiAnalyzerXmlParser, FortiGateParser, HaproxyParser,
    IisW3cParser, looks_like_etw_nodlink,
    looks_like_cdm, looks_like_cognito, looks_like_fortigate, looks_like_haproxy,
    looks_like_iis_w3c,
};
use serde_json::Value;

use crate::util::{extract_csv_headers, extract_json_keys};

pub struct FormatDescriptor {
    pub name: &'static str,
    pub aliases: &'static [&'static str],
    pub detect: fn(content: &str) -> bool,
    pub make_parser: fn() -> Box<dyn LogParser + Send + Sync>,
    pub preview: fn(content: &str) -> Vec<(String, String)>,
}

fn detect_sysmon(contents: &str) -> bool {
    let trimmed = contents.trim();
    (trimmed.starts_with('[') || trimmed.starts_with('{'))
        && (contents.contains("EventID") || contents.contains("event_id"))
        && (contents.contains("UtcTime")
            || contents.contains("Sysmon")
            || contents.contains("Security-Auditing")
            || contents.contains("event_data"))
}

fn detect_sentinel(contents: &str) -> bool {
    let trimmed = contents.trim();
    (trimmed.starts_with('[') || trimmed.starts_with('{'))
        && contents.contains("\"Type\"")
        && (contents.contains("SecurityEvent")
            || contents.contains("SigninLogs")
            || contents.contains("DeviceProcessEvents")
            || contents.contains("DeviceNetworkEvents")
            || contents.contains("DeviceFileEvents")
            || contents.contains("CommonSecurityLog"))
}

fn detect_cognito(contents: &str) -> bool {
    looks_like_cognito(contents)
}

fn detect_iis(contents: &str) -> bool {
    let trimmed = contents.trim();
    !trimmed.starts_with('[') && !trimmed.starts_with('{') && looks_like_iis_w3c(trimmed)
}

/// Detects HAProxy HTTP-log lines. The native parser splits the
/// space-delimited prefix and the quoted request line, routing source
/// IPs to requested domains and URLs — work the generic CSV fallback
/// can't do (it would treat the whole line as one unstructured column).
fn detect_haproxy(contents: &str) -> bool {
    looks_like_haproxy(contents)
}

/// Detects DARPA TC CDM (E3) provenance JSON. The native parser does the
/// two-pass UUID resolution — catalogue entities, then wire events to
/// them — that the generic JSON path cannot: a CDM event references its
/// endpoints by UUID defined in other records, so a per-record parse
/// would emit orphan nodes with no edges.
fn detect_cdm(contents: &str) -> bool {
    looks_like_cdm(contents)
}

/// Detects FortiGate firewall KV log lines (and FortiGate CSV exports
/// whose header carries both `srcip` and `dstip`). The native parser
/// avoids the generic-CSV heuristic bugs (port→IP, dotted-signature→
/// Domain, dropped/close→Delete, no-edge-metadata) so FortiGate data
/// must be routed away from `generic`/`csv` before they swallow it.
/// Detects NODLINK ETW JSONL (`hw20` / `win10`): every leading line is a
/// JSON object carrying `EventName` and `MSec`. Like CDM it must be probed
/// before `generic`, which would otherwise treat each event as a bag of
/// fields and lose the causal direction and process generations.
fn detect_etw_nodlink(contents: &str) -> bool {
    looks_like_etw_nodlink(contents)
}

fn detect_fortigate(contents: &str) -> bool {
    looks_like_fortigate(contents)
}

fn detect_generic_json(contents: &str) -> bool {
    let trimmed = contents.trim();
    trimmed.starts_with('[') || trimmed.starts_with('{')
}

/// Detects a FortiAnalyzer XML report. Requires both a valid XML
/// declaration *and* the FortiAnalyzer root element name so unrelated
/// XML files don't false-match.
fn detect_fortianalyzer(contents: &str) -> bool {
    let trimmed = contents.trim_start();
    trimmed.starts_with("<?xml") && contents.contains("<FortiAnalyzer_Report")
}

fn preview_iis(_contents: &str) -> Vec<(String, String)> {
    vec![
        ("c-ip".into(), "IP (Client)".into()),
        ("s-ip".into(), "Host (Server)".into()),
        ("cs-uri-stem".into(), "URL".into()),
        ("cs-username".into(), "User".into()),
        ("cs-method".into(), "metadata".into()),
        ("sc-status".into(), "metadata".into()),
        ("cs(User-Agent)".into(), "metadata".into()),
        ("time-taken".into(), "metadata".into()),
    ]
}

fn preview_cognito(_contents: &str) -> Vec<(String, String)> {
    vec![
        ("userName".into(), "User".into()),
        ("ipAddress".into(), "IP".into()),
        ("clientId / cognito-pool".into(), "Service".into()),
        ("riskDecision".into(), "metadata".into()),
        ("city".into(), "metadata".into()),
        ("country".into(), "metadata".into()),
        ("deviceName".into(), "metadata".into()),
        ("email".into(), "metadata".into()),
    ]
}

fn preview_fortigate(_contents: &str) -> Vec<(String, String)> {
    vec![
        ("srcip".into(), "IP".into()),
        ("dstip".into(), "IP".into()),
        ("attack".into(), "Other:Signature".into()),
        ("action".into(), "metadata".into()),
        ("severity".into(), "metadata".into()),
        ("service".into(), "metadata".into()),
        ("dstport".into(), "metadata".into()),
        ("policyid".into(), "metadata".into()),
        ("policyname".into(), "metadata".into()),
        ("sentbyte".into(), "metadata".into()),
        ("rcvdbyte".into(), "metadata".into()),
        ("devname".into(), "metadata".into()),
    ]
}

fn preview_haproxy(_contents: &str) -> Vec<(String, String)> {
    vec![
        ("client_ip".into(), "IP (Client)".into()),
        ("url_host".into(), "Domain (Requested)".into()),
        ("url_path".into(), "URL".into()),
        ("backend_server".into(), "Host (Backend)".into()),
        ("method".into(), "metadata".into()),
        ("status".into(), "metadata".into()),
        ("backend".into(), "metadata".into()),
    ]
}

fn preview_cdm(_contents: &str) -> Vec<(String, String)> {
    vec![
        ("subject".into(), "Process (actor)".into()),
        ("predicateObject".into(), "File / IP / Process (acted-on)".into()),
        ("type".into(), "relation (EVENT_* → Execute/Read/Write/Connect/Auth)".into()),
        ("event_type".into(), "metadata".into()),
        ("ts_nanos".into(), "metadata (full nanosecond timestamp)".into()),
    ]
}

fn preview_etw_nodlink(_contents: &str) -> Vec<(String, String)> {
    vec![
        ("PID|PName|generation".into(), "Process (identity survives PID reuse)".into()),
        ("FileName".into(), "File (read/load → process; process → write)".into()),
        ("daddr".into(), "IP (send: process → ip; recv: ip → process)".into()),
        ("EventName".into(), "relation (Start→Spawn, Read, Write, Load, Send/Recv→Connect)".into()),
        ("event_type".into(), "metadata (start/read/write/load/send/recv)".into()),
        ("ts_us".into(), "metadata (microseconds from trace start)".into()),
        ("is_warn".into(), "process metadata (red-team label)".into()),
    ]
}

fn preview_fortianalyzer(_contents: &str) -> Vec<(String, String)> {
    vec![
        ("User_Name".into(), "IP (Top User by Traffic)".into()),
        ("Col (Top Website)".into(), "Domain".into()),
        ("Host_Name".into(), "Host (Compromised Host)".into()),
        ("Threat".into(), "Other:Threat".into()),
        ("Application".into(), "Other:Application".into()),
        (
            "Category".into(),
            "Other:ThreatCategory / AppCategory".into(),
        ),
        ("Bytes".into(), "metadata".into()),
        ("Percent_of_Total".into(), "metadata".into()),
    ]
}

/// Ordered registry. Checked top-to-bottom for "auto" detection.
/// Sysmon must come before generic (both JSON); CSV is the fallback.
static FORMAT_REGISTRY: &[FormatDescriptor] = &[
    FormatDescriptor {
        name: "sysmon",
        aliases: &[],
        detect: detect_sysmon,
        make_parser: || Box::new(SysmonJsonParser),
        preview: |_| preview_sysmon().into_iter().collect(),
    },
    FormatDescriptor {
        name: "sentinel",
        aliases: &[],
        detect: detect_sentinel,
        make_parser: || Box::new(SentinelJsonParser),
        preview: |_| preview_sentinel().into_iter().collect(),
    },
    FormatDescriptor {
        name: "cognito",
        aliases: &[],
        detect: detect_cognito,
        make_parser: || Box::new(CognitoParser),
        preview: preview_cognito,
    },
    FormatDescriptor {
        name: "fortigate",
        aliases: &["fgt", "fortios"],
        detect: detect_fortigate,
        make_parser: || Box::new(FortiGateParser::new()),
        preview: preview_fortigate,
    },
    FormatDescriptor {
        name: "iis",
        aliases: &["iis_w3c", "w3c"],
        detect: detect_iis,
        make_parser: || Box::new(IisW3cParser),
        preview: preview_iis,
    },
    FormatDescriptor {
        name: "haproxy",
        aliases: &["hap", "haproxy_http"],
        detect: detect_haproxy,
        make_parser: || Box::new(HaproxyParser),
        preview: preview_haproxy,
    },
    // CDM is JSON, so it must be probed before `generic`/`csv` swallow it
    // — its detector keys on the cdm18 schema prefix, which generic JSON
    // never carries.
    FormatDescriptor {
        name: "etw",
        aliases: &["nodlink", "etw_nodlink", "hw20", "win10"],
        detect: detect_etw_nodlink,
        make_parser: || Box::new(EtwNodlinkParser),
        preview: preview_etw_nodlink,
    },
    FormatDescriptor {
        name: "cdm",
        aliases: &["darpa", "tc", "cdm18"],
        detect: detect_cdm,
        make_parser: || Box::new(CdmParser),
        preview: preview_cdm,
    },
    FormatDescriptor {
        name: "fortianalyzer",
        aliases: &["faz", "forti", "xml"],
        detect: detect_fortianalyzer,
        make_parser: || Box::new(FortiAnalyzerXmlParser::new()),
        preview: preview_fortianalyzer,
    },
    FormatDescriptor {
        name: "generic",
        aliases: &[],
        detect: detect_generic_json,
        make_parser: || Box::new(GenericParser),
        preview: |contents| {
            let keys = extract_json_keys(contents);
            preview_generic_from_keys(&keys).into_iter().collect()
        },
    },
    FormatDescriptor {
        name: "csv",
        aliases: &[],
        detect: |_| true,
        make_parser: || Box::new(CsvParser),
        preview: |contents| {
            let keys = extract_csv_headers(contents);
            preview_generic_from_keys(&keys).into_iter().collect()
        },
    },
];

/// Find a [`FormatDescriptor`] by canonical name or alias.
pub fn find_descriptor(name: &str) -> Option<&'static FormatDescriptor> {
    let lower = name.to_lowercase();
    FORMAT_REGISTRY
        .iter()
        .find(|d| d.name == lower || d.aliases.iter().any(|a| *a == lower))
}

/// Resolve `"auto"` or an alias to the canonical format name.
pub fn resolve_format(contents: &str, format_param: &str) -> String {
    resolve_format_with_ext(contents, format_param, None)
}

/// Same as [`resolve_format`] but consults the file extension (case-
/// insensitive, leading dot optional) first when `format_param == "auto"`.
/// A `.csv`/`.tsv` extension beats content heuristics because a CSV whose
/// first data line happens to start with `{` would otherwise be misdetected
/// as JSON.
pub fn resolve_format_with_ext(
    contents: &str,
    format_param: &str,
    extension: Option<&str>,
) -> String {
    let f = format_param.to_lowercase();
    if f != "auto" {
        if let Some(desc) = find_descriptor(&f) {
            return desc.name.to_string();
        }
        return f;
    }
    if let Some(ext) = extension {
        let ext_norm = ext.trim_start_matches('.').to_lowercase();
        let ext_hint: Option<&str> = match ext_norm.as_str() {
            "csv" | "tsv" => Some("csv"),
            "json" | "ndjson" | "jsonl" => None, // fall through to content detection
            "xml" => Some("fortianalyzer"),
            "log" => None,
            _ => None,
        };
        if let Some(name) = ext_hint {
            if let Some(desc) = find_descriptor(name) {
                return desc.name.to_string();
            }
        }
    }
    for desc in FORMAT_REGISTRY.iter() {
        if (desc.detect)(contents) {
            return desc.name.to_string();
        }
    }
    "csv".to_string()
}

/// Build a parser for the given format name. Errors when unknown.
pub fn make_parser_for_format(
    format_name: &str,
) -> Result<Box<dyn LogParser + Send + Sync>, String> {
    find_descriptor(format_name)
        .map(|desc| (desc.make_parser)())
        .ok_or_else(|| {
            format!(
                "Unsupported format: '{}'. Use 'auto', 'evtx', 'sysmon', 'sentinel', 'cognito', 'generic', 'csv', 'iis', 'haproxy', 'cdm', 'etw', 'fortianalyzer', or 'fortigate'.",
                format_name
            )
        })
}

/// Preview fields for a given format + content sample.
pub fn preview_for_format(format_name: &str, contents: &str) -> Vec<(String, String)> {
    find_descriptor(format_name)
        .map(|desc| (desc.preview)(contents))
        .unwrap_or_default()
}

const RICH_PREVIEW_SAMPLE_SIZE: usize = 200;

/// Richer preview: sample up to `RICH_PREVIEW_SAMPLE_SIZE` rows and return
/// per-field occurrence counts + up to 5 sample values. For formats where
/// sampling isn't supported (IIS W3C, FortiAnalyzer XML), falls back to the
/// header-only preview with empty sample arrays so callers get a uniform
/// payload.
pub fn rich_preview_for_format(format_name: &str, contents: &str) -> Vec<FieldInfo> {
    let events: Vec<Value> = match format_name {
        "csv" => CsvParser::sample_events(contents, RICH_PREVIEW_SAMPLE_SIZE),
        "sysmon" | "sentinel" | "cognito" | "generic" => {
            GenericParser::parse_events_limited(contents, RICH_PREVIEW_SAMPLE_SIZE)
        }
        _ => Vec::new(),
    };
    if !events.is_empty() {
        return preview_fields_from_events(&events);
    }
    // Fallback: header-only preview lifted into FieldInfo shape.
    preview_for_format(format_name, contents)
        .into_iter()
        .map(|(field_name, suggested)| FieldInfo {
            raw_name: field_name,
            canonical_target: None,
            occurrence_count: 0,
            sample_values: Vec::new(),
            current_role: if suggested == "Skip" {
                FieldRole::Metadata
            } else {
                FieldRole::Node
            },
            suggested_entity_type: if suggested == "Skip" {
                None
            } else {
                Some(suggested)
            },
            suggestion_source: None,
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    const HAPROXY_SAMPLE: &str = " 186.19.87.186:36696 [10/Jun/2026:00:00:27.428] https~ cluster_pps_wss/wss_pps_i10 0/0/0/1/1 200 659 - - --NI 619/611/1/0/0 0/0 \"OPTIONS https://www1.hospitalitaliano.org.ar/wssPortal/api/log/INICIO HTTP/2.0\"\n";

    /// Regression guard for the ingest OOM fix: a HAProxy log must resolve
    /// to the `haproxy` format under auto-detection. The streaming ingest
    /// path keys its line-based (memory-bounded) routing off this name —
    /// if auto-detect ever stops returning `haproxy`, the file silently
    /// falls back to `csv`, lands on the whole-file branch, and a multi-GB
    /// log aborts the process. See `is_line_based` in `operations/ingestion.rs`.
    #[test]
    fn haproxy_auto_detects_to_haproxy() {
        assert_eq!(resolve_format(HAPROXY_SAMPLE, "auto"), "haproxy");
    }

    /// Apache combined access logs share the `[date] "METHOD ... HTTP/x"`
    /// shape but must NOT be mistaken for HAProxy (different field layout).
    #[test]
    fn apache_combined_does_not_detect_as_haproxy() {
        let apache =
            "127.0.0.1 - frank [10/Oct/2000:13:55:36 -0700] \"GET /a HTTP/1.0\" 200 2326\n";
        assert_ne!(resolve_format(apache, "auto"), "haproxy");
    }

    /// CDM provenance JSON must auto-detect to `cdm`, not `generic`/`csv`.
    /// Routing it to the generic JSON parser would emit orphan entity
    /// nodes with no edges, because CDM events reference their endpoints
    /// by UUID defined in other records — the whole reason for the native
    /// two-pass parser.
    #[test]
    fn etw_nodlink_auto_detects_to_etw_not_generic() {
        let etw = "{\"MSec\": \"81.7\", \"PID\": \"88\", \"PName\": \"\", \"EventName\": \"TcpIp/Recv\", \"daddr\": \"1.2.3.4\"}
{\"MSec\": \"82.0\", \"PID\": \"4\", \"PName\": \"svchost\", \"EventName\": \"FileIO/Read\", \"FileName\": \"C:\\x\"}
";
        assert_eq!(resolve_format(etw, "auto"), "etw");
        assert_eq!(resolve_format(etw, "nodlink"), "etw");
    }

    #[test]
    fn cdm_auto_detects_to_cdm() {
        let cdm = "{\"datum\":{\"com.bbn.tc.schema.avro.cdm18.Event\":{\"uuid\":\"e\",\"type\":\"EVENT_EXECUTE\",\"timestampNanos\":1}}}\n";
        assert_eq!(resolve_format(cdm, "auto"), "cdm");
    }

    /// Keycloak user-events export: double-encoded CSV (each data row is a
    /// single quoted field wrapping the real row; `details` JSON inside with
    /// quadruple-quote escaping). Must resolve to `csv`, and the rich
    /// preview — which feeds `auto_field_config_for` on one-shot ingest —
    /// must surface the real columns plus the flattened `details` keys so
    /// User/IP mappings get proposed instead of one garbage `time` blob.
    const KEYCLOAK_SAMPLE: &str = concat!(
        "time,type,realmId,clientId,userId,sessionId,ipAddress,error,details\n",
        r#""1785553172951,LOGIN,realm1,cliente-externo,u-123,sess-1,181.9.227.140,,""{""""auth_method"""":""""openid-connect"""",""""username"""":""""ana@example.com""""}""""#,
        "\n",
    );

    #[test]
    fn keycloak_double_encoded_csv_resolves_to_csv() {
        assert_eq!(resolve_format(KEYCLOAK_SAMPLE, "auto"), "csv");
    }

    #[test]
    fn keycloak_double_encoded_csv_rich_preview_sees_real_fields() {
        let fields = rich_preview_for_format("csv", KEYCLOAK_SAMPLE);
        let names: Vec<&str> = fields.iter().map(|f| f.raw_name.as_str()).collect();
        assert!(names.contains(&"ipAddress"), "missing ipAddress: {names:?}");
        assert!(names.contains(&"username"), "missing username: {names:?}");
        assert!(names.contains(&"auth_method"), "missing auth_method: {names:?}");
        assert!(
            !names.contains(&"details"),
            "raw details blob should be expanded away: {names:?}"
        );
    }
}
