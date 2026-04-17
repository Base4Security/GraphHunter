//! Log format registry: name → parser + detector + preview fields.
//!
//! Moved from `app/src-tauri/src/format_registry.rs`. Adding a new
//! format is still a single append to [`FORMAT_REGISTRY`]
//! (open/closed). The registry plus its three public entry points
//! (`find_descriptor`, `resolve_format`, `make_parser_for_format`) are
//! used by the ingest pipeline and by `cmd_run_kql`.

use graph_hunter_core::{
    looks_like_cognito, looks_like_iis_w3c, preview_generic_from_keys, preview_sentinel,
    preview_sysmon, CognitoParser, CsvParser, FortiAnalyzerXmlParser, GenericParser, IisW3cParser,
    LogParser, SentinelJsonParser, SysmonJsonParser,
};

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
        name: "iis",
        aliases: &["iis_w3c", "w3c"],
        detect: detect_iis,
        make_parser: || Box::new(IisW3cParser),
        preview: preview_iis,
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
    let f = format_param.to_lowercase();
    if f != "auto" {
        if let Some(desc) = find_descriptor(&f) {
            return desc.name.to_string();
        }
        return f;
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
                "Unsupported format: '{}'. Use 'auto', 'evtx', 'sysmon', 'sentinel', 'cognito', 'generic', 'csv', 'iis', or 'fortianalyzer'.",
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
