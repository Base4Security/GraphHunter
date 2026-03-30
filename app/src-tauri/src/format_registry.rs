use graph_hunter_core::{
    CognitoParser, CsvParser, GenericParser, IisW3cParser, LogParser, SentinelJsonParser,
    SysmonJsonParser, looks_like_cognito, looks_like_iis_w3c,
    preview_generic_from_keys, preview_sentinel, preview_sysmon,
};

use crate::helpers::{extract_csv_headers, extract_json_keys};

/// Describes a log format that GraphHunter can ingest.
/// Adding a new format = adding one entry to FORMAT_REGISTRY (Open/Closed Principle).
pub struct FormatDescriptor {
    /// Canonical name: "sysmon", "sentinel", "csv", etc.
    pub name: &'static str,
    /// Aliases the UI may pass (e.g., "iis_w3c", "w3c" map to "iis").
    pub aliases: &'static [&'static str],
    /// Returns true if a content sample matches this format (for "auto" detection).
    /// Checked top-to-bottom; first match wins.
    pub detect: fn(content: &str) -> bool,
    /// Constructs the parser for this format.
    pub make_parser: fn() -> Box<dyn LogParser + Send + Sync>,
    /// Returns preview fields for the ingestion UI.
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

fn preview_iis(_contents: &str) -> Vec<(String, String)> {
    vec![
        ("c-ip".to_string(), "IP (Client)".to_string()),
        ("s-ip".to_string(), "Host (Server)".to_string()),
        ("cs-uri-stem".to_string(), "URL".to_string()),
        ("cs-username".to_string(), "User".to_string()),
        ("cs-method".to_string(), "metadata".to_string()),
        ("sc-status".to_string(), "metadata".to_string()),
        ("cs(User-Agent)".to_string(), "metadata".to_string()),
        ("time-taken".to_string(), "metadata".to_string()),
    ]
}

fn preview_cognito(_contents: &str) -> Vec<(String, String)> {
    vec![
        ("userName".to_string(), "User".to_string()),
        ("ipAddress".to_string(), "IP".to_string()),
        ("clientId / cognito-pool".to_string(), "Service".to_string()),
        ("riskDecision".to_string(), "metadata".to_string()),
        ("city".to_string(), "metadata".to_string()),
        ("country".to_string(), "metadata".to_string()),
        ("deviceName".to_string(), "metadata".to_string()),
        ("email".to_string(), "metadata".to_string()),
    ]
}

/// Ordered registry. Checked top-to-bottom for "auto" detection.
/// Sysmon must come before generic (both are JSON); CSV is the final fallback.
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
        detect: |_| true, // fallback: always matches
        make_parser: || Box::new(CsvParser),
        preview: |contents| {
            let keys = extract_csv_headers(contents);
            preview_generic_from_keys(&keys).into_iter().collect()
        },
    },
];

/// Finds a FormatDescriptor by canonical name or alias.
pub fn find_descriptor(name: &str) -> Option<&'static FormatDescriptor> {
    let lower = name.to_lowercase();
    FORMAT_REGISTRY.iter().find(|d| {
        d.name == lower || d.aliases.iter().any(|a| *a == lower)
    })
}

/// Resolves "auto" format from file contents. Returns the canonical format name.
pub fn resolve_format(contents: &str, format_param: &str) -> String {
    let f = format_param.to_lowercase();
    if f != "auto" {
        // Resolve aliases to canonical name
        if let Some(desc) = find_descriptor(&f) {
            return desc.name.to_string();
        }
        return f;
    }
    // Auto-detect: check each descriptor in priority order
    for desc in FORMAT_REGISTRY.iter() {
        if (desc.detect)(contents) {
            return desc.name.to_string();
        }
    }
    "csv".to_string() // unreachable since csv detect always returns true
}

/// Creates a parser for the given format name. Returns error for unknown formats.
pub fn make_parser_for_format(format_name: &str) -> Result<Box<dyn LogParser + Send + Sync>, String> {
    find_descriptor(format_name)
        .map(|desc| (desc.make_parser)())
        .ok_or_else(|| format!(
            "Unsupported format: '{}'. Use 'auto', 'evtx', 'sysmon', 'sentinel', 'cognito', 'generic', 'csv', or 'iis'.",
            format_name
        ))
}

/// Returns preview fields for a given format and content sample.
pub fn preview_for_format(format_name: &str, contents: &str) -> Vec<(String, String)> {
    find_descriptor(format_name)
        .map(|desc| (desc.preview)(contents))
        .unwrap_or_default()
}
