//! Ingest-engine introspection.
//!
//! Read-only Tauri command exposing which ingest-stack components are
//! active in the running daemon. The frontend calls it once at mount
//! and renders a toolbar badge so the user perceives that the new
//! RawIngestEvent path + deterministic VRL compiler + (optional) LLM
//! compiler are on without having to flip env vars manually.
//!
//! Status is queried once at startup. The flags it reflects are
//! default-on at daemon startup, matching the perf-flag pattern in
//! `perf.rs`.

use serde::Serialize;

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct IngestEngineStatus {
    /// `RawIngestEvent` path is active for the streaming pipeline,
    /// EnrichmentEngine, EVTX file ingest, and the Sentinel one-shot
    /// load_data path. Default-on after PRs #26-#31. Always `true`
    /// today — the field exists so future feature gates can flip it.
    pub raw_event_active: bool,
    /// Names of parsers that override `parse_raw` natively (and so
    /// capture the per-event allocation savings). Parsers not in
    /// this list still flow correctly via the default lift-from-parse
    /// impl, just without the parser-side win.
    pub parsers_with_native_raw: Vec<String>,
    /// Deterministic VRL compiler available — the `field_config_to_vrl`
    /// transformation that powers FieldConfig-driven ingest. Always
    /// `true`; the field exists for symmetry with the LLM compiler.
    pub vrl_compiler_active: bool,
    /// Local LLM model present on disk and loadable by the
    /// CandleBackend. `true` iff `GRAPHHUNTER_LOCAL_MODEL_PATH` env
    /// var is set; the actual model load is deferred to first use.
    /// Used to gate "LLM" in the badge label.
    pub llm_compiler_available: bool,
    /// Human-readable summary the UI shows in a tooltip.
    pub summary: String,
}

#[tauri::command]
pub fn cmd_get_ingest_engine_status() -> IngestEngineStatus {
    let raw_event_active = true;
    // SysmonJsonParser overrides parse_raw natively for all 16 typed
    // EventIDs (Sysmon 1, 3, 5, 7, 8, 11, 12/13, 15, 23 + WinSec
    // 4624/4625, 4688, 4689, 4663, 5145, 5156 + PowerShell 4104).
    // SentinelJsonParser, GenericParser, CsvParser flow through the
    // default lift-from-parse impl today.
    let parsers_with_native_raw = vec!["Sysmon".to_string()];
    let vrl_compiler_active = true;
    let llm_compiler_available = std::env::var("GRAPHHUNTER_LOCAL_MODEL_PATH")
        .ok()
        .map(|p| !p.is_empty())
        .unwrap_or(false);

    let mut active = vec!["RawIngestEvent path", "VRL compiler"];
    if llm_compiler_available {
        active.push("LLM compiler (model loaded on first use)");
    }
    let summary = format!(
        "Ingest v2 active: {}. Native parsers: {}.",
        active.join(", "),
        parsers_with_native_raw.join(", ")
    );

    IngestEngineStatus {
        raw_event_active,
        parsers_with_native_raw,
        vrl_compiler_active,
        llm_compiler_available,
        summary,
    }
}
