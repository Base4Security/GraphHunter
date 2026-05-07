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
    /// CandleBackend. `true` when [`graph_hunter_local_llm::resolve_model_path`]
    /// finds a checkpoint — either via the
    /// `GRAPHHUNTER_LOCAL_MODEL_PATH` override, the bundled
    /// `resources/models/` location next to the binary, or the
    /// `target/models/` dev-tree fallback. The actual model load is
    /// deferred to first use. Used to gate "LLM" in the badge label.
    pub llm_compiler_available: bool,
    /// Path the resolver settled on, surfaced for diagnostics. `None`
    /// when no checkpoint was found.
    pub llm_compiler_model_path: Option<String>,
    /// LLM-as-compiler hot-path dispatcher enabled (default-on via
    /// `GRAPHHUNTER_LLM_INGEST=1`). When `false`, ambiguous datasets
    /// stay on the heuristic path even if the model is loadable.
    pub llm_compiler_dispatcher_enabled: bool,
    /// Human-readable summary the UI shows in a tooltip.
    pub summary: String,
}

/// Mirrors the parser-status `flag()` helper in `perf.rs` so the
/// dispatcher toggle reads the same `1`/`true`/`yes`/`on` set.
fn flag(key: &str) -> bool {
    std::env::var(key)
        .map(|v| matches!(v.as_str(), "1" | "true" | "yes" | "on"))
        .unwrap_or(false)
}

#[tauri::command]
pub fn cmd_get_ingest_engine_status() -> IngestEngineStatus {
    let raw_event_active = true;
    // SysmonJsonParser: 16 typed EventIDs (Sysmon 1, 3, 5, 7, 8, 11,
    // 12/13, 15, 23 + WinSec 4624/4625, 4688, 4689, 4663, 5145, 5156
    // + PowerShell 4104).
    // SentinelJsonParser: 8 cloud Sentinel tables (SecurityEvent
    // 4624/4625/4688/4663, SigninLogs, DeviceProcessEvents,
    // DeviceNetworkEvents, DeviceFileEvents, CommonSecurityLog).
    // GenericParser, CsvParser flow through the default lift-from-parse
    // impl today.
    let parsers_with_native_raw = vec!["Sysmon".to_string(), "Sentinel".to_string()];
    let vrl_compiler_active = true;

    // Plug-and-play resolver: bundled model next to the binary →
    // `target/models/` dev-tree → `GRAPHHUNTER_LOCAL_MODEL_PATH`
    // override. The badge flips to "Ingest: v2 + LLM" the moment the
    // GGUF is on disk, with no env var to set.
    let resolved_model_path = graph_hunter_api::local_llm::resolve_model_path();
    let llm_compiler_available = resolved_model_path
        .as_ref()
        .map(|p| p.is_file())
        .unwrap_or(false);
    let llm_compiler_model_path = resolved_model_path
        .as_ref()
        .and_then(|p| p.to_str().map(|s| s.to_string()));
    let llm_compiler_dispatcher_enabled = flag("GRAPHHUNTER_LLM_INGEST");

    let mut active = vec![
        "RawIngestEvent path",
        "parse_raw_with_stats (native typed-fast-path)",
        "VRL compiler",
    ];
    if llm_compiler_available && llm_compiler_dispatcher_enabled {
        active.push("LLM-as-compiler dispatcher (auto-fallback on ambiguous datasets)");
    } else if llm_compiler_available {
        active.push("LLM compiler available (dispatcher off — set GRAPHHUNTER_LLM_INGEST=1)");
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
        llm_compiler_model_path,
        llm_compiler_dispatcher_enabled,
        summary,
    }
}

/// On-demand AI rescue for ambiguous datasets. The user clicks "Probar
/// mapeo IA" on a 0-triple `DatasetCard` → this fires → `negotiate_field_config`
/// runs Phi-3 → emits either `ingest-llm-proposal` (banner appears) or
/// `ingest-llm-diagnostic` (status-log entry).
///
/// Why this exists instead of the old silent dispatcher: Phi-3 inference
/// on CPU dev profile takes 9 minutes per call. As a hot-path silent
/// step it blocks every ingest. As an explicit click on an
/// already-failed dataset it's an opt-in rescue — paid once, on
/// demand, and only when the heuristic clearly didn't help.
///
/// `async` + `spawn_blocking`: the dispatcher's `infer` call blocks the
/// thread for the duration of model load + decode. Without
/// `spawn_blocking` the Tauri main thread stalls and WebView2 shows
/// "program not responding".
#[tauri::command]
pub async fn cmd_request_llm_proposal(
    app: tauri::AppHandle,
    api: tauri::State<'_, std::sync::Arc<graph_hunter_api::GraphHunterApi>>,
    dataset_id: String,
) -> Result<(), String> {
    use graph_hunter_api::dto::dataset::ListDatasetsRequest;
    use graph_hunter_api::dto::ingestion::{IngestLlmDiagnostic, IngestLlmProposal};
    use graph_hunter_api::events::events::{INGEST_LLM_DIAGNOSTIC, INGEST_LLM_PROPOSAL};
    use graph_hunter_api::format_registry::resolve_format;
    use graph_hunter_api::local_llm::default_backend;
    use graph_hunter_api::operations::negotiation::{
        NegotiationOutcome, negotiate_field_config,
    };
    use std::io::Read;
    use tauri::Emitter;

    // Look up the dataset's path. Datasets without a path (Sentinel
    // streams, e.g.) can't be re-read for inference; surface a clear
    // error rather than silently no-op.
    let datasets = api
        .list_datasets(ListDatasetsRequest::default())
        .map_err(|e| format!("list_datasets: {e}"))?;
    let target = datasets
        .into_iter()
        .find(|d| d.id == dataset_id)
        .ok_or_else(|| format!("dataset {dataset_id} not found in current session"))?;
    let path = target
        .path
        .ok_or_else(|| format!("dataset `{}` has no source path on disk", target.name))?;

    // Read enough of the file for `resolve_format` + `auto_field_config_for`
    // to produce a heuristic baseline. 16 KB is plenty — the dispatcher
    // re-truncates internally to ~1500 chars before sending to the LLM.
    let mut peek = String::with_capacity(16 * 1024);
    {
        let mut file = std::fs::File::open(&path).map_err(|e| format!("open {path}: {e}"))?;
        let mut buf = [0u8; 16 * 1024];
        let n = file.read(&mut buf).map_err(|e| format!("read {path}: {e}"))?;
        peek.push_str(&String::from_utf8_lossy(&buf[..n]));
    }
    let format = resolve_format(&peek, "auto");

    let dataset_id_clone = dataset_id.clone();
    let path_clone = path.clone();
    let format_clone = format.clone();
    let app_clone = app.clone();

    // Off-thread so WebView2 keeps painting during the ~10-30 s call.
    tokio::task::spawn_blocking(move || {
        let backend = default_backend();
        let backend_id_str = backend.backend_id().to_string();
        let outcome = negotiate_field_config(&format_clone, &peek, backend.as_ref());

        let emit_diag = |outcome: &str, reason: String, backend_id: Option<String>| {
            let payload = IngestLlmDiagnostic {
                job_id: format!("on-demand-{dataset_id_clone}"),
                dataset_id: dataset_id_clone.clone(),
                outcome: outcome.to_string(),
                reason,
                backend_id,
            };
            let _ = app_clone.emit(INGEST_LLM_DIAGNOSTIC, &payload);
        };

        match outcome {
            NegotiationOutcome::HeuristicOk { config, confidence } => {
                let reason = format!(
                    "heuristic confident on `{}` ({} mappings, confidence {:.2}); LLM not consulted",
                    format_clone,
                    config.mappings.len(),
                    confidence,
                );
                tracing::info!(target: "graph_hunter_api::ingest", "{}", reason);
                emit_diag("heuristic_ok", reason, None);
            }
            NegotiationOutcome::LlmProposal {
                heuristic,
                refined,
                diff,
                confidence,
                backend_id,
            } => {
                let teaser = format!(
                    "LLM proposal: +{} added, ~{} changed, -{} removed (confidence {:.2})",
                    diff.added.len(),
                    diff.changed.len(),
                    diff.removed.len(),
                    confidence,
                );
                tracing::info!(target: "graph_hunter_api::ingest", backend = %backend_id, "{}", teaser);
                emit_diag("llm_proposal", teaser, Some(backend_id.clone()));
                let payload = IngestLlmProposal {
                    job_id: format!("on-demand-{dataset_id_clone}"),
                    dataset_id: dataset_id_clone.clone(),
                    source_path: path_clone.clone(),
                    format: format_clone.clone(),
                    heuristic: serde_json::to_value(&heuristic).unwrap_or_default(),
                    refined: serde_json::to_value(&refined).unwrap_or_default(),
                    diff: serde_json::to_value(&diff).unwrap_or_default(),
                    confidence,
                    backend_id,
                };
                let _ = app_clone.emit(INGEST_LLM_PROPOSAL, &payload);
            }
            NegotiationOutcome::LlmUnavailable { reason, .. } => {
                let summary = format!("LLM not used ({reason})");
                tracing::info!(target: "graph_hunter_api::ingest", "{}", summary);
                emit_diag("llm_unavailable", summary, Some(backend_id_str));
            }
        }
        Ok::<(), String>(())
    })
    .await
    .map_err(|e| format!("spawn_blocking join failed: {e}"))?
}

/// Debug-only: fire a synthetic `ingest-llm-proposal` event so the
/// confirm-banner UX can be exercised without waiting on a real Phi-3
/// inference (which takes ~9 minutes per call on CPU in dev mode —
/// unusable for iterating on the banner). The payload mimics what the
/// dispatcher would emit for an IIS log: a heuristic that produced
/// zero recognized Nodes vs an LLM proposal that recognized client IP
/// + HTTP user-agent + URL stem as Nodes.
///
/// Invoke from the IngestPanel debug button or from devtools console:
///   `await window.__TAURI__.core.invoke('cmd_debug_emit_synthetic_llm_proposal')`
#[tauri::command]
pub fn cmd_debug_emit_synthetic_llm_proposal(app: tauri::AppHandle) -> Result<(), String> {
    use tauri::Emitter;
    let payload = serde_json::json!({
        "job_id": "debug-synthetic",
        "dataset_id": "debug-synthetic-dataset",
        "source_path": "C:\\Users\\lsotomayor\\GraphHunter\\demo_data\\ambiguous_iis_for_llm.log",
        "format": "iis",
        "heuristic": {
            "mappings": [
                { "raw_name": "date", "role": "Metadata", "entity_type": null },
                { "raw_name": "time", "role": "Metadata", "entity_type": null },
                { "raw_name": "c-ip", "role": "Metadata", "entity_type": null },
                { "raw_name": "cs-method", "role": "Metadata", "entity_type": null },
                { "raw_name": "cs-uri-stem", "role": "Metadata", "entity_type": null },
                { "raw_name": "cs-username", "role": "Metadata", "entity_type": null }
            ]
        },
        "refined": {
            "mappings": [
                { "raw_name": "date", "role": "Metadata", "entity_type": null },
                { "raw_name": "time", "role": "Metadata", "entity_type": null },
                { "raw_name": "c-ip", "role": "Node", "entity_type": "IP" },
                { "raw_name": "cs-method", "role": "Metadata", "entity_type": null },
                { "raw_name": "cs-uri-stem", "role": "Node", "entity_type": "URL" },
                { "raw_name": "cs-username", "role": "Node", "entity_type": "User" },
                { "raw_name": "cs(User-Agent)", "role": "Node", "entity_type": "UserAgent" }
            ]
        },
        "diff": {
            "added": [
                { "raw_name": "cs(User-Agent)", "role": "Node", "entity_type": "UserAgent" }
            ],
            "removed": [],
            "changed": [
                {
                    "raw_name": "c-ip",
                    "heuristic": { "raw_name": "c-ip", "role": "Metadata", "entity_type": null },
                    "refined":   { "raw_name": "c-ip", "role": "Node",     "entity_type": "IP" }
                },
                {
                    "raw_name": "cs-uri-stem",
                    "heuristic": { "raw_name": "cs-uri-stem", "role": "Metadata", "entity_type": null },
                    "refined":   { "raw_name": "cs-uri-stem", "role": "Node",     "entity_type": "URL" }
                },
                {
                    "raw_name": "cs-username",
                    "heuristic": { "raw_name": "cs-username", "role": "Metadata", "entity_type": null },
                    "refined":   { "raw_name": "cs-username", "role": "Node",     "entity_type": "User" }
                }
            ],
            "unchanged_count": 3
        },
        "confidence": 0.78,
        "backend_id": "debug-synthetic"
    });
    app.emit("ingest-llm-proposal", &payload)
        .map_err(|e| format!("emit failed: {e}"))?;
    Ok(())
}
