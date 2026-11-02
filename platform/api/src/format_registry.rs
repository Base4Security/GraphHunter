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
    Auth0CsvParser, BindPspParser, CdmParser, CerteroParser, CognitoParser, EtwNodlinkParser,
    FortiAnalyzerXmlParser, FortiGateParser, FortiWebParser, HaproxyParser, IisW3cParser,
    looks_like_auth0, looks_like_bind_psp, looks_like_cdm, looks_like_certero, looks_like_cognito,
    looks_like_etw_nodlink, looks_like_fortigate, looks_like_fortiweb, looks_like_haproxy,
    looks_like_iis_w3c,
};
use serde_json::Value;

use crate::record_scan::StreamMode;
use crate::util::{extract_csv_headers, extract_json_keys};

pub struct FormatDescriptor {
    pub name: &'static str,
    pub aliases: &'static [&'static str],
    /// True for delimited-text formats — the ones that may legitimately
    /// arrive named `.csv`/`.tsv`. [`resolve_format_with_ext`] probes
    /// only these when the extension says the file is tabular, so a
    /// specific tabular format can claim the file while the JSON
    /// detectors still cannot steal it (see that function's docs).
    pub tabular: bool,
    /// How the streaming ingest path may cut this format into batches.
    ///
    /// Takes the peek buffer because two formats are genuinely bimodal:
    /// Sysmon, Sentinel, Cognito and `generic` all ship either as one
    /// JSON array (unsplittable) or as JSONL (one record per line).
    ///
    /// This replaced a hard-coded `is_line_based` allowlist in
    /// `operations/ingestion.rs` that had silently fallen behind the
    /// registry: `csv` was missing from it, so every CSV over the
    /// whole-file limit was rejected as "not line-delimited" by an error
    /// message that recommended converting to CSV. Declaring the mode
    /// next to the parser keeps the two from drifting apart again.
    pub stream: fn(peek: &str) -> StreamMode,
    /// True when the first record is a column header that every streamed
    /// batch must carry.
    ///
    /// Without this, batch 2..N of a headed format parses its first data
    /// row as the header: no error is raised, the columns simply map to
    /// the wrong names and the ingest lands as near-zero triples. That is
    /// the same silent-mapping failure the IIS `#Fields:` re-injection
    /// already guards against, generalised to first-line headers.
    pub headed: bool,
    pub detect: fn(content: &str) -> bool,
    pub make_parser: fn() -> Box<dyn LogParser + Send + Sync>,
    pub preview: fn(content: &str) -> Vec<(String, String)>,
}

/// JSON that may arrive as an array (whole-file) or as JSONL (per line).
fn stream_json(peek: &str) -> StreamMode {
    if peek.trim_start().starts_with('[') {
        StreamMode::WholeFile
    } else {
        StreamMode::Lines
    }
}

/// One record per newline, always.
fn stream_lines(_: &str) -> StreamMode {
    StreamMode::Lines
}

/// Newline-delimited, but a newline inside a double-quoted value does not
/// end the record.
fn stream_quoted(_: &str) -> StreamMode {
    StreamMode::Quoted
}

/// Must be parsed in a single call (XML documents, cross-record state).
fn stream_whole(_: &str) -> StreamMode {
    StreamMode::WholeFile
}

/// How the resolved `format_name` may be streamed given a peek at the
/// file. Unknown names fall back to [`StreamMode::WholeFile`], the
/// conservative choice: a format we cannot reason about keeps the
/// size guard rather than being cut at guessed boundaries.
pub fn stream_mode_for(format_name: &str, peek: &str) -> StreamMode {
    find_descriptor(format_name)
        .map(|d| (d.stream)(peek))
        .unwrap_or(StreamMode::WholeFile)
}

/// True when `format_name` carries a first-line column header that every
/// streamed batch must repeat.
pub fn format_is_headed(format_name: &str) -> bool {
    find_descriptor(format_name)
        .map(|d| d.headed)
        .unwrap_or(false)
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

/// Detects BIND PSP connector NDJSON. Like CDM and ETW it is JSON and so
/// must be probed before `generic`, which would otherwise see only the
/// three-key log envelope (`labels`/`line`/`timestamp`) and never reach
/// the CVUs, CUITs and amounts embedded in the `line` string.
fn detect_bind_psp(contents: &str) -> bool {
    looks_like_bind_psp(contents)
}

/// Detects a CERTERO personal/labour dossier TSV. The generic CSV path
/// parses the rows but maps none of the Spanish headers (`CUIL`,
/// `NOMBRE`, `DOMICILIO` are all `_unknown` -> `Skip`), so the file would
/// ingest as zero entities and zero relations without ever raising a
/// parse error.
fn detect_certero(contents: &str) -> bool {
    looks_like_certero(contents)
}

/// Detects FortiWeb WAF logs (`alog` attack / `elog` event exports).
///
/// FortiWeb is comma-separated and names its endpoints `src`/`dst`, so
/// `looks_like_fortigate` — which keys on `srcip=`/`dstip=` — never matched
/// and these files fell all the way through to the `csv` fallback. The
/// generic CSV path then saw one unnamed column per line and produced an
/// almost-empty graph without raising anything.
fn detect_fortiweb(contents: &str) -> bool {
    looks_like_fortiweb(contents)
}

/// Detects an Auth0 tenant-log export flattened by Elastic into a wide
/// ECS CSV. Must be probed before `csv`, whose name-based heuristics map
/// almost none of the `json.data.*` columns and would mint a duplicate
/// node for every `.keyword` sibling.
fn detect_auth0(contents: &str) -> bool {
    looks_like_auth0(contents)
}

fn preview_fortiweb(_contents: &str) -> Vec<(String, String)> {
    vec![
        ("src".into(), "IP (attacker)".into()),
        ("dst".into(), "IP (backend)".into()),
        ("signature_id".into(), "Other:Signature (Triggered)".into()),
        ("http_url".into(), "URL (Request)".into()),
        ("http_host".into(), "Domain (Targets)".into()),
        ("policy".into(), "Other:Policy (MatchedPolicy)".into()),
        ("action".into(), "metadata".into()),
        ("severity_level".into(), "metadata".into()),
        ("main_type / sub_type".into(), "metadata".into()),
        ("owasp_top10".into(), "signature metadata".into()),
        ("srccountry".into(), "metadata".into()),
        ("msg".into(), "metadata (may span lines)".into()),
    ]
}

fn preview_auth0(_contents: &str) -> Vec<(String, String)> {
    vec![
        (
            "json.data.details.response.body.user_metadata.cuit".into(),
            "Person (bare CUIT — merges with certero + bind-psp)".into(),
        ),
        (
            "json.data.user_id".into(),
            "Other:Auth0User (TieneCuentaAuth0)".into(),
        ),
        ("json.data.ip".into(), "IP (Auth)".into()),
        (
            "json.data.details.response.body.email".into(),
            "Other:Email (UsaEmail)".into(),
        ),
        (
            "json.data.type".into(),
            "metadata (Auth0 code; s* = success, f* = failure)".into(),
        ),
        ("json.data.client_name".into(), "metadata".into()),
        ("json.data.security_context.ja3".into(), "metadata".into()),
        ("json.data.user_agent".into(), "metadata".into()),
        (
            "json.data.location_info.country_name".into(),
            "metadata".into(),
        ),
    ]
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
        (
            "predicateObject".into(),
            "File / IP / Process (acted-on)".into(),
        ),
        (
            "type".into(),
            "relation (EVENT_* → Execute/Read/Write/Connect/Auth)".into(),
        ),
        ("event_type".into(), "metadata".into()),
        (
            "ts_nanos".into(),
            "metadata (full nanosecond timestamp)".into(),
        ),
    ]
}

fn preview_etw_nodlink(_contents: &str) -> Vec<(String, String)> {
    vec![
        (
            "PID|PName|generation".into(),
            "Process (identity survives PID reuse)".into(),
        ),
        (
            "FileName".into(),
            "File (read/load → process; process → write)".into(),
        ),
        (
            "daddr".into(),
            "IP (send: process → ip; recv: ip → process)".into(),
        ),
        (
            "EventName".into(),
            "relation (Start→Spawn, Read, Write, Load, Send/Recv→Connect)".into(),
        ),
        (
            "event_type".into(),
            "metadata (start/read/write/load/send/recv)".into(),
        ),
        (
            "ts_us".into(),
            "metadata (microseconds from trace start)".into(),
        ),
        ("is_warn".into(), "process metadata (red-team label)".into()),
    ]
}

fn preview_bind_psp(_contents: &str) -> Vec<(String, String)> {
    vec![
        (
            "cuentaId / cvu_origen".into(),
            "Account (wallet side)".into(),
        ),
        (
            "cvuCbuContraparte".into(),
            "Account (counterparty, 22-digit CVU/CBU)".into(),
        ),
        (
            "cuitContraparte / cuitCuil".into(),
            "Person (bare CUIT — merges with certero)".into(),
        ),
        (
            "evento".into(),
            "relation direction (ENTRANTE -> in, SALIENTE/PAGO_QR -> out)".into(),
        ),
        ("importe".into(), "metadata (settled amount, 2dp)".into()),
        (
            "coelsaId".into(),
            "metadata (pairs an attempt with its settlement)".into(),
        ),
        ("bancoContraparte / bancoNombre".into(), "Bank".into()),
        ("aliasContraparte / alias".into(), "Alias".into()),
        ("domicilio".into(), "Domicilio (merges with certero)".into()),
        (
            "http_status".into(),
            "metadata (409 ARDID rejections, 404 CUIT probes)".into(),
        ),
    ]
}

fn preview_certero(_contents: &str) -> Vec<(String, String)> {
    vec![
        (
            "CUIL".into(),
            "Person (bare 11 digits — merges with bind-psp)".into(),
        ),
        ("DOMICILIO".into(), "Domicilio + Localidad".into()),
        (
            "SITUACION LABORAL".into(),
            "Empleador / RegimenFiscal (or metadata)".into(),
        ),
        ("NOMBRE".into(), "metadata".into()),
        ("FECHA DE NACIMIENTO".into(), "metadata".into()),
        ("(columna sin nombre)".into(), "Actividad (AFIP)".into()),
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
        tabular: false,
        stream: stream_json,
        headed: false,
        detect: detect_sysmon,
        make_parser: || Box::new(SysmonJsonParser),
        preview: |_| preview_sysmon().into_iter().collect(),
    },
    FormatDescriptor {
        name: "sentinel",
        aliases: &[],
        tabular: false,
        stream: stream_json,
        headed: false,
        detect: detect_sentinel,
        make_parser: || Box::new(SentinelJsonParser),
        preview: |_| preview_sentinel().into_iter().collect(),
    },
    FormatDescriptor {
        name: "cognito",
        aliases: &[],
        tabular: false,
        stream: stream_json,
        headed: false,
        detect: detect_cognito,
        make_parser: || Box::new(CognitoParser),
        preview: preview_cognito,
    },
    FormatDescriptor {
        name: "fortigate",
        aliases: &["fgt", "fortios"],
        tabular: true,
        stream: stream_lines,
        headed: false,
        detect: detect_fortigate,
        make_parser: || Box::new(FortiGateParser::new()),
        preview: preview_fortigate,
    },
    // FortiWeb is comma-separated KV and arrives named `.csv`, so it is
    // tabular; it must sit ahead of `csv`, which matches everything.
    // Quoted stream mode because a captured multi-line attack payload
    // lives inside `msg="..."` and must not be cut at its newlines.
    FormatDescriptor {
        name: "fortiweb",
        aliases: &["fwb", "fweb", "waf"],
        tabular: true,
        stream: stream_quoted,
        headed: false,
        detect: detect_fortiweb,
        make_parser: || Box::new(FortiWebParser::new()),
        preview: preview_fortiweb,
    },
    FormatDescriptor {
        name: "iis",
        aliases: &["iis_w3c", "w3c"],
        tabular: true,
        stream: stream_lines,
        headed: false,
        detect: detect_iis,
        make_parser: || Box::new(IisW3cParser),
        preview: preview_iis,
    },
    FormatDescriptor {
        name: "haproxy",
        aliases: &["hap", "haproxy_http"],
        tabular: false,
        stream: stream_lines,
        headed: false,
        detect: detect_haproxy,
        make_parser: || Box::new(HaproxyParser),
        preview: preview_haproxy,
    },
    // CDM is JSON, so it must be probed before `generic`/`csv` swallow it
    // — its detector keys on the cdm18 schema prefix, which generic JSON
    // never carries.
    // BIND PSP connector logs are NDJSON, so like CDM/ETW they must be
    // probed before `generic` swallows them.
    FormatDescriptor {
        name: "bind_psp",
        aliases: &["bindpsp", "bind", "psp"],
        tabular: false,
        stream: stream_lines,
        headed: false,
        detect: detect_bind_psp,
        make_parser: || Box::new(BindPspParser),
        preview: preview_bind_psp,
    },
    FormatDescriptor {
        name: "etw",
        aliases: &["nodlink", "etw_nodlink", "hw20", "win10"],
        tabular: false,
        stream: stream_lines,
        headed: false,
        detect: detect_etw_nodlink,
        make_parser: || Box::new(EtwNodlinkParser),
        preview: preview_etw_nodlink,
    },
    FormatDescriptor {
        name: "cdm",
        aliases: &["darpa", "tc", "cdm18"],
        tabular: false,
        stream: stream_lines,
        headed: false,
        detect: detect_cdm,
        make_parser: || Box::new(CdmParser),
        preview: preview_cdm,
    },
    FormatDescriptor {
        name: "fortianalyzer",
        aliases: &["faz", "forti", "xml"],
        tabular: false,
        stream: stream_whole,
        headed: false,
        detect: detect_fortianalyzer,
        make_parser: || Box::new(FortiAnalyzerXmlParser::new()),
        preview: preview_fortianalyzer,
    },
    // Headed: 221 columns mapped by position, so every streamed batch
    // must repeat the header or the mapping silently shifts.
    FormatDescriptor {
        name: "auth0",
        aliases: &["auth0_csv", "auth0_elastic"],
        tabular: true,
        stream: stream_quoted,
        headed: true,
        detect: detect_auth0,
        make_parser: || Box::new(Auth0CsvParser::new()),
        preview: preview_auth0,
    },
    // Tabular, so it is also reachable when a `.tsv` extension routes
    // detection through the tabular-only probe.
    FormatDescriptor {
        name: "certero",
        aliases: &["dossier", "datos_personales"],
        tabular: true,
        stream: stream_quoted,
        headed: true,
        detect: detect_certero,
        make_parser: || Box::new(CerteroParser),
        preview: preview_certero,
    },
    FormatDescriptor {
        name: "generic",
        aliases: &[],
        tabular: false,
        stream: stream_json,
        headed: false,
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
        tabular: true,
        stream: stream_quoted,
        headed: true,
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
///
/// A `.csv`/`.tsv` extension beats the *JSON* content heuristics, because
/// a CSV whose first data line happens to start with `{` would otherwise
/// be misdetected as JSON. It must **not** beat the other delimited-text
/// detectors, though: doing so returned `csv` for every `.tsv` before the
/// registry was consulted at all, so a specific tabular format could
/// never claim its own file no matter where it sat in the registry.
///
/// So a tabular extension narrows the probe to
/// [`FormatDescriptor::tabular`] entries rather than short-circuiting it.
/// `csv` is itself tabular and its detector matches everything, so the
/// old behaviour is the floor: the worst case is still `csv`.
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
        match ext_norm.as_str() {
            "csv" | "tsv" => {
                for desc in FORMAT_REGISTRY.iter().filter(|d| d.tabular) {
                    if (desc.detect)(contents) {
                        return desc.name.to_string();
                    }
                }
                return "csv".to_string();
            }
            // Fall through to full content detection.
            "json" | "ndjson" | "jsonl" | "log" => {}
            "xml" => {
                if let Some(desc) = find_descriptor("fortianalyzer") {
                    return desc.name.to_string();
                }
            }
            _ => {}
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
                "Unsupported format: '{}'. Use 'auto', 'evtx', 'sysmon', 'sentinel', 'cognito', 'generic', 'csv', 'iis', 'haproxy', 'cdm', 'etw', 'bind_psp', 'certero', 'fortianalyzer', 'fortigate', 'fortiweb', or 'auth0'.",
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

    // ── Streamability: the whole-file size guard ────────────────────
    //
    // These pin the fix for "File 'x.csv' (1067 MB) is too large for the
    // whole-file ingest path ... isn't line-delimited so it can't be
    // streamed" — a message that in the same breath recommended CSV.

    /// The regression itself. `csv` was missing from the old hard-coded
    /// `is_line_based` allowlist, so every CSV above the limit was
    /// rejected outright.
    #[test]
    fn csv_is_streamable() {
        assert!(
            stream_mode_for(
                "csv",
                "a,b,c
1,2,3
"
            )
            .is_streamable()
        );
        assert_eq!(
            stream_mode_for(
                "csv", "a,b
"
            ),
            StreamMode::Quoted
        );
    }

    /// Every tabular format is headed and quote-aware, or a big file of
    /// it either cannot stream or streams with shifted columns.
    #[test]
    fn tabular_formats_stream_quoted() {
        for name in ["csv", "auth0", "certero"] {
            assert_eq!(
                stream_mode_for(name, ""),
                StreamMode::Quoted,
                "{name} must be quote-aware to stream safely"
            );
            assert!(format_is_headed(name), "{name} must repeat its header");
        }
    }

    /// FortiWeb has no header row (KV per record), so re-injecting one
    /// would corrupt every batch.
    #[test]
    fn fortiweb_streams_quoted_but_unheaded() {
        assert_eq!(stream_mode_for("fortiweb", ""), StreamMode::Quoted);
        assert!(!format_is_headed("fortiweb"));
    }

    /// Bimodal JSON: an array cannot be split, JSONL can.
    #[test]
    fn json_array_keeps_the_size_guard_but_jsonl_streams() {
        assert_eq!(
            stream_mode_for("generic", "[{\"a\":1}]"),
            StreamMode::WholeFile
        );
        assert_eq!(
            stream_mode_for(
                "generic",
                "{\"a\":1}
"
            ),
            StreamMode::Lines
        );
        assert_eq!(stream_mode_for("sysmon", "  [ {"), StreamMode::WholeFile);
    }

    /// An unknown name must keep the guard rather than be cut at guessed
    /// boundaries.
    #[test]
    fn unknown_format_is_not_streamable() {
        assert_eq!(stream_mode_for("no-such-format", ""), StreamMode::WholeFile);
    }

    /// Every registered format must declare a stream mode that its parser
    /// can actually survive; this catches a new format added without
    /// thinking about the ingest path.
    #[test]
    fn every_format_declares_a_stream_mode() {
        for d in FORMAT_REGISTRY.iter() {
            let mode = (d.stream)("");
            // A headed format must be able to stream, otherwise the
            // header machinery is dead code hiding a size-guard reject.
            if d.headed {
                assert!(
                    mode.is_streamable(),
                    "{} is headed but not streamable",
                    d.name
                );
            }
        }
    }

    /// Equivalence guard for the change that put CSV on the streaming
    /// path. Every CSV under the old size limit used to be parsed whole;
    /// now it is cut into batches with the header re-injected into each.
    /// Those two must produce the same triples, or the fix silently
    /// changes the result of every CSV ingest in the product.
    ///
    /// Mirrors the ingest loop: batch at a record boundary, prepend the
    /// stored header to every batch after the first.
    #[test]
    fn batched_csv_parse_matches_whole_file_parse() {
        use crate::record_scan::RecordScanner;
        use graph_hunter_core::LogParser;

        let csv = "src_ip,dst_ip,user
                   10.0.0.1,10.0.0.2,ana
                   10.0.0.3,10.0.0.4,\"bob, jr\"
                   10.0.0.5,10.0.0.6,carla
                   10.0.0.7,10.0.0.8,dan
                   10.0.0.9,10.0.0.10,eve
";

        let parser = make_parser_for_format("csv").expect("csv parser");
        let whole = parser.parse(csv);
        assert!(!whole.is_empty(), "fixture produced no triples");

        let mode = stream_mode_for("csv", csv);
        let raw = csv.as_bytes();
        let mut hs = RecordScanner::new(mode);
        let header = hs
            .next_record_end(raw, 0)
            .map(|e| String::from_utf8_lossy(&raw[..e]).trim_end().to_string())
            .expect("header");

        // Two data rows per batch exercises several boundaries.
        let mut scanner = RecordScanner::new(mode);
        let mut batched = Vec::new();
        let mut at = 0usize;
        let mut batch_start = 0usize;
        let mut in_batch = 0usize;
        while let Some(pos) = scanner.next_record_end(raw, at) {
            at = pos + 1;
            in_batch += 1;
            if in_batch >= 2 {
                let body = String::from_utf8_lossy(&raw[batch_start..pos + 1]);
                let chunk = if batch_start > 0 {
                    format!(
                        "{header}
{body}"
                    )
                } else {
                    body.into_owned()
                };
                batched.extend(parser.parse(&chunk));
                batch_start = pos + 1;
                in_batch = 0;
            }
        }
        if batch_start < raw.len() {
            let body = String::from_utf8_lossy(&raw[batch_start..]);
            let chunk = format!(
                "{header}
{body}"
            );
            batched.extend(parser.parse(&chunk));
        }

        let key = |ts: &[(
            graph_hunter_core::entity::Entity,
            graph_hunter_core::relation::Relation,
            graph_hunter_core::entity::Entity,
        )]| {
            let mut v: Vec<String> = ts
                .iter()
                .map(|(s, r, d)| format!("{}|{}|{}", s.id, r.rel_type, d.id))
                .collect();
            v.sort();
            v
        };
        assert_eq!(
            key(&batched),
            key(&whole),
            "batched CSV parse diverged from the whole-file parse"
        );
    }

    // ── Detection of the OnlineBanking corpus ───────────────────────

    const FORTIWEB_ALOG: &str = "v015xxxxdate=2026-08-01,time=22:34:07,log_id=20000008,msg_id=000000000001,device_id=FWBVMSTM00000001,eventtime=1785634447670281764,vd=\"root\",type=attack,main_type=\"Signature Detection\",severity_level=Low,action=Alert,policy=\"SP_EJEMPLO\",src=198.51.100.5,dst=10.0.9.10,http_url=\"/api/auth0/register\",http_host=\"24app.example.com.ar\",signature_id=\"080080001\"
";

    const FORTIGATE_VPN: &str = "date=2026-08-24 time=23:59:57 eventtime=1787626798373509651 tz=\"-0300\" logid=\"0101039426\" type=\"event\" subtype=\"vpn\" level=\"alert\" vd=\"root\" logdesc=\"SSL VPN login fail\" action=\"ssl-login-fail\" tunneltype=\"ssl-web\" remip=203.0.113.193 user=\"accounts\" group=\"N/A\"
";

    const AUTH0_CSV: &str = "@timestamp,_id,data_stream.dataset,json.data.type,json.data.ip,json.data.user_id,json.data.client_name,json.data.details.response.body.user_metadata.cuit,json.data.user_name,json.data.connection,json.data.user_agent,json.data.security_context.ja3,tags
\"Sep 3, 2026 @ 10:01:06.343\",abc,auth0.logs,fp,203.0.113.40,auth0|67ffe529,app-mobile,-,usuario_ejemplo,tenant-ejemplo,Android,f79b,-
";

    /// A FortiWeb export named `.csv` must reach its own parser, not the
    /// generic CSV fallback that produced an almost-empty graph.
    #[test]
    fn fortiweb_auto_detects_to_fortiweb() {
        assert_eq!(resolve_format(FORTIWEB_ALOG, "auto"), "fortiweb");
        assert_eq!(
            resolve_format_with_ext(FORTIWEB_ALOG, "auto", Some("csv")),
            "fortiweb"
        );
    }

    /// The SSL-VPN log carries no `srcip`/`dstip`, which is exactly why
    /// the old detector missed it and a 670 MB file hit the size guard.
    #[test]
    fn fortigate_vpn_auto_detects_to_fortigate() {
        assert_eq!(resolve_format(FORTIGATE_VPN, "auto"), "fortigate");
        assert!(stream_mode_for("fortigate", FORTIGATE_VPN).is_streamable());
    }

    #[test]
    fn auth0_export_auto_detects_to_auth0() {
        assert_eq!(resolve_format(AUTH0_CSV, "auto"), "auth0");
        assert_eq!(
            resolve_format_with_ext(AUTH0_CSV, "auto", Some("csv")),
            "auth0"
        );
    }

    /// The three must not steal each other's files — they share the
    /// Fortinet `date=`/`time=` opening and all arrive named `.csv`.
    #[test]
    fn the_three_new_formats_do_not_collide() {
        assert_ne!(resolve_format(FORTIWEB_ALOG, "auto"), "fortigate");
        assert_ne!(resolve_format(FORTIGATE_VPN, "auto"), "fortiweb");
        assert_ne!(resolve_format(AUTH0_CSV, "auto"), "csv");
        // And none of them swallows an ordinary CSV.
        assert_eq!(
            resolve_format(
                "name,age
ana,3
",
                "auto"
            ),
            "csv"
        );
    }

    /// End of the reported bug: none of the four large files in the
    /// corpus may land on the whole-file branch.
    #[test]
    fn no_corpus_file_hits_the_whole_file_guard() {
        for (label, sample) in [
            ("fortiweb alog", FORTIWEB_ALOG),
            ("fortigate vpn", FORTIGATE_VPN),
            ("auth0 csv", AUTH0_CSV),
        ] {
            let fmt = resolve_format(sample, "auto");
            assert!(
                stream_mode_for(&fmt, sample).is_streamable(),
                "{label} resolved to '{fmt}', which still hits the size guard"
            );
        }
    }

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

    const BIND_PSP_SAMPLE: &str = concat!(
        r#"{"labels":{},"line":"2026-09-03 00:00:00,097 [http-nio-8080-exec-44] INFO  [sId:C7F6] c.p.b.p.c.c.c.BindPspFeignLogger - REQUEST: [GET] [https://api.bindpagos.com.ar/walletentidad-cuenta/v1/api/v1.201/SaldoActualByIdCuenta/1000005] [] - time_elapsed: [132 ms] - RESPONSE: [200] [{\"saldo\":29060.00}]","timestamp":"2026-09-03T00:00:00.101251562Z"}"#,
        "
",
        r#"{"labels":{},"line":"2026-09-03 00:00:00,101 [http-nio-8080-exec-44] INFO  [sId:C7F6] c.p.b.p.c.c.s.i.BindPspServiceImpl - ***** Success --> getBalance","timestamp":"2026-09-03T00:00:00.101728533Z"}"#,
        "
",
        r#"{"labels":{},"line":"2026-09-03 00:00:00,105 [http-nio-8080-exec-11] INFO  [sId:DBC5] c.p.b.p.c.c.s.i.BindPspServiceImpl - ***** getAccount","timestamp":"2026-09-03T00:00:00.106181911Z"}"#,
        "
",
    );

    const CERTERO_SAMPLE: &str = concat!(
        "CUIL	NOMBRE	DOMICILIO	SITUACION LABORAL	FECHA DE NACIMIENTO	
",
        "20000000021	PERSONA EJEMPLO SIETE	CALLE UNO 885, LOCALIDAD UNO, BUENOS AIRES	Sin registro	2001-01-01	
",
    );

    /// BIND PSP connector logs are NDJSON; `generic` would swallow them
    /// and see only the three-key envelope, losing every CVU, CUIT and
    /// amount embedded in the `line` string.
    #[test]
    fn bind_psp_auto_detects_to_bind_psp_not_generic() {
        assert_eq!(resolve_format(BIND_PSP_SAMPLE, "auto"), "bind_psp");
        assert_eq!(resolve_format(BIND_PSP_SAMPLE, "psp"), "bind_psp");
        assert_eq!(
            resolve_format_with_ext(BIND_PSP_SAMPLE, "auto", Some(".jsonl")),
            "bind_psp"
        );
    }

    /// A generic shipper's `{"line":…,"timestamp":…}` envelope must not be
    /// captured — only the connector's own logs.
    #[test]
    fn unrelated_ndjson_envelopes_are_not_bind_psp() {
        let other = concat!(
            r#"{"line":"nginx: GET /","timestamp":"2026-09-03T00:00:00Z"}"#,
            "
",
            r#"{"line":"nginx: GET /x","timestamp":"2026-09-03T00:00:01Z"}"#,
            "
",
        );
        assert_ne!(resolve_format(other, "auto"), "bind_psp");
    }

    /// Regression guard for the `.tsv` short-circuit: `resolve_format_with_ext`
    /// used to return `csv` for any `.csv`/`.tsv` file *before* consulting
    /// the registry, so no specific tabular format could ever claim its own
    /// file. A CERTERO dossier routed to `csv` ingests as zero entities and
    /// zero relations, silently — every Spanish header maps to `_unknown`.
    #[test]
    fn certero_tsv_wins_over_the_csv_extension_hint() {
        assert_eq!(resolve_format(CERTERO_SAMPLE, "auto"), "certero");
        assert_eq!(
            resolve_format_with_ext(CERTERO_SAMPLE, "auto", Some(".tsv")),
            "certero"
        );
        assert_eq!(
            resolve_format_with_ext(CERTERO_SAMPLE, "auto", Some("csv")),
            "certero"
        );
    }

    /// The narrowed probe must keep the behaviour it was protecting: a
    /// CSV whose first data line starts with `{` stays `csv` and is not
    /// stolen by a JSON detector.
    #[test]
    fn a_csv_starting_with_a_brace_is_still_csv() {
        let csv = "col_a,col_b
{not json},2
";
        assert_eq!(resolve_format_with_ext(csv, "auto", Some(".csv")), "csv");
        assert_eq!(resolve_format_with_ext(csv, "auto", Some(".tsv")), "csv");
        // …and an ordinary CSV with no special shape, too.
        assert_eq!(
            resolve_format_with_ext(
                "a,b
1,2
",
                "auto",
                Some(".csv")
            ),
            "csv"
        );
    }

    /// A plain `.tsv` that is not a dossier still falls back to `csv`.
    #[test]
    fn unrelated_tsv_still_resolves_to_csv() {
        let tsv = "alpha	beta
1	2
";
        assert_eq!(resolve_format_with_ext(tsv, "auto", Some(".tsv")), "csv");
    }

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
        assert!(
            names.contains(&"auth_method"),
            "missing auth_method: {names:?}"
        );
        assert!(
            !names.contains(&"details"),
            "raw details blob should be expanded away: {names:?}"
        );
    }
}
