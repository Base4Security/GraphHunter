use std::io::BufReader;
use std::sync::Arc;

use graph_hunter_core::{
    ConfigurableParser, FieldConfig, GenericParser, LogParser,
    extract_fields_header,
};
use tauri::{Emitter, State};
use uuid::Uuid;

use crate::evtx::{
    evtx_ingest_streaming, evtx_preview_sample, evtx_to_sysmon_ndjson,
    file_looks_like_evtx, path_is_evtx,
};
use crate::format_registry::{make_parser_for_format, preview_for_format, resolve_format};
use crate::scoring::{run_full_scoring, run_scoring_adaptive};
use crate::state::{AppState, DatasetInfo};
use crate::types::{
    DetectedField, IngestComplete, IngestError, IngestJobStarted,
    LoadResult, PreviewIngestResult,
};

/// Preview ingestion: detect format and proposed field -> entity type mapping (no ingest).
#[tauri::command]
pub fn cmd_preview_ingest(path: String, format: String) -> Result<PreviewIngestResult, String> {
    let use_evtx = format.to_lowercase() == "evtx"
        || path_is_evtx(&path)
        || (format.to_lowercase() == "auto" && file_looks_like_evtx(&path));
    let (contents, resolved) = if use_evtx {
        let contents = evtx_preview_sample(&path, 1000)?;
        (contents, "sysmon".to_string())
    } else {
        // For large files, only read a preview sample (first 64KB) for format detection
        let file_size = std::fs::metadata(&path).map(|m| m.len()).unwrap_or(0);
        let contents = if file_size > 10 * 1024 * 1024 {
            // Large file: read only first 64KB for preview
            let mut file = std::fs::File::open(&path)
                .map_err(|e| format!("Failed to open file '{}': {}", path, e))?;
            let mut buf = vec![0u8; 64 * 1024];
            let n = std::io::Read::read(&mut file, &mut buf)
                .map_err(|e| format!("Failed to read file '{}': {}", path, e))?;
            String::from_utf8_lossy(&buf[..n]).to_string()
        } else {
            std::fs::read_to_string(&path)
                .map_err(|e| format!("Failed to read file '{}': {}", path, e))?
        };
        let resolved = resolve_format(&contents, &format);
        (contents, resolved)
    };

    let detected_fields: Vec<DetectedField> = preview_for_format(&resolved, &contents)
        .into_iter()
        .map(|(field_name, suggested_entity_type)| DetectedField {
            field_name,
            suggested_entity_type,
        })
        .collect();

    Ok(PreviewIngestResult {
        format: resolved,
        detected_fields,
    })
}

/// Reads a file from disk and ingests its log events into the current session's graph.
/// Tags all new entities/relations with a new dataset id for the datasets lateral menu.
/// Auto-computes scores after loading.
#[tauri::command]
pub fn cmd_load_data(
    state: State<Arc<AppState>>,
    path: String,
    format: String,
) -> Result<LoadResult, String> {
    let use_evtx = format.to_lowercase() == "evtx"
        || path_is_evtx(&path)
        || (format.to_lowercase() == "auto" && file_looks_like_evtx(&path));
    let (contents, format_for_parser) = if use_evtx {
        let contents = evtx_to_sysmon_ndjson(&path)?;
        (contents, "generic".to_string()) // Use generic parser so any EVTX event produces entities (Host, User, etc.)
    } else {
        let contents = std::fs::read_to_string(&path)
            .map_err(|e| format!("Failed to read file '{}': {}", path, e))?;
        (contents, format)
    };

    let session_id = state
        .current_session_id
        .read()
        .map_err(|e| format!("Lock poisoned: {}", e))?
        .clone()
        .ok_or("No current session")?;

    let session = {
        let sessions = state
            .sessions
            .read()
            .map_err(|e| format!("Lock poisoned: {}", e))?;
        Arc::clone(sessions.get(&session_id).ok_or("Session not found")?)
    };

    let dataset_id = Uuid::new_v4().to_string();
    let name = std::path::Path::new(&path)
        .file_name()
        .and_then(|p| p.to_str())
        .unwrap_or("ingest")
        .to_string();
    let created_at = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|e| e.to_string())?
        .as_secs() as i64;

    {
        let mut datasets = session
            .datasets
            .write()
            .map_err(|e| format!("Lock poisoned: {}", e))?;
        datasets.push(DatasetInfo {
            id: dataset_id.clone(),
            name: name.clone(),
            path: Some(path.clone()),
            created_at,
            entity_count: 0,
            relation_count: 0,
        });
    }

    let (new_entities, new_relations) = {
        let mut graph = session
            .graph
            .write()
            .map_err(|e| format!("Lock poisoned: {}", e))?;
        let resolved_format = resolve_format(&contents, &format_for_parser);
        let parser = make_parser_for_format(&resolved_format)?;
        let triples = parser.parse(&contents);
        let result = graph.insert_triples(triples, Some(dataset_id.as_str()));
        run_full_scoring(&mut graph);
        result
    };

    {
        let mut datasets = session
            .datasets
            .write()
            .map_err(|e| format!("Lock poisoned: {}", e))?;
        if let Some(last) = datasets.last_mut() {
            last.entity_count = new_entities;
            last.relation_count = new_relations;
        }
    }

    let (total_entities, total_relations) = {
        let graph = session
            .graph
            .read()
            .map_err(|e| format!("Lock poisoned: {}", e))?;
        (graph.entity_count(), graph.relation_count())
    };

    Ok(LoadResult {
        new_entities,
        new_relations,
        total_entities,
        total_relations,
    })
}

/// SIEM ingest (Sentinel or Elastic): fetch via API then ingest into current session.
/// Runs the API call in a blocking task to avoid blocking the UI.
#[tauri::command]
pub async fn cmd_ingest_siem(
    state: State<'_, Arc<AppState>>,
    params: serde_json::Value,
) -> Result<LoadResult, String> {
    let source = params
        .get("source")
        .and_then(|v| v.as_str())
        .ok_or("missing param: source (sentinel | elastic)")?;

    let data = match source {
        "sentinel" => {
            let workspace_id = params
                .get("workspace_id")
                .and_then(|v| v.as_str())
                .ok_or("missing param: workspace_id")?
                .to_string();
            let query = params
                .get("query")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            let auth = match (
                params.get("azure_tenant_id").and_then(|v| v.as_str()),
                params.get("azure_client_id").and_then(|v| v.as_str()),
                params.get("azure_client_secret").and_then(|v| v.as_str()),
            ) {
                (Some(t), Some(c), Some(s)) => Some(graph_hunter_cli::siem::SentinelAuth {
                    tenant_id: t.to_string(),
                    client_id: c.to_string(),
                    client_secret: s.to_string(),
                }),
                _ => None,
            };
            let res = tauri::async_runtime::spawn_blocking(move || {
                graph_hunter_cli::siem::run_sentinel_query(&workspace_id, &query, auth)
            })
            .await
            .map_err(|e| format!("task join error: {}", e))??;
            res.data
        }
        "elastic" => {
            let url = params
                .get("url")
                .and_then(|v| v.as_str())
                .ok_or("missing param: url")?
                .to_string();
            let index = params
                .get("index")
                .and_then(|v| v.as_str())
                .unwrap_or("_all")
                .to_string();
            let query = params
                .get("query")
                .and_then(|v| v.as_str())
                .unwrap_or("{}")
                .to_string();
            let size = params.get("size").and_then(|v| v.as_u64()).map(|n| n as u32);
            let auth = match (
                params.get("elastic_api_key").and_then(|v| v.as_str()),
                params.get("elastic_user").and_then(|v| v.as_str()),
                params.get("elastic_password").and_then(|v| v.as_str()),
            ) {
                (Some(k), _, _) if !k.is_empty() => Some(graph_hunter_cli::siem::ElasticAuth {
                    api_key: Some(k.to_string()),
                    user: None,
                    password: None,
                }),
                (_, Some(u), p) if !u.is_empty() => Some(graph_hunter_cli::siem::ElasticAuth {
                    api_key: None,
                    user: Some(u.to_string()),
                    password: p.map(|s| s.to_string()),
                }),
                _ => None,
            };
            let res = tauri::async_runtime::spawn_blocking(move || {
                graph_hunter_cli::siem::run_elastic_query(&url, &index, &query, size, None, auth)
            })
            .await
            .map_err(|e| format!("task join error: {}", e))??;
            res.data
        }
        _ => return Err(format!("unsupported source: '{}'. Use 'sentinel' or 'elastic'.", source)),
    };

    let session_id = state
        .current_session_id
        .read()
        .map_err(|e| format!("Lock poisoned: {}", e))?
        .clone()
        .ok_or("No current session")?;

    let session = {
        let sessions = state
            .sessions
            .read()
            .map_err(|e| format!("Lock poisoned: {}", e))?;
        Arc::clone(sessions.get(&session_id).ok_or("Session not found")?)
    };

    let dataset_id = Uuid::new_v4().to_string();
    let name = match source {
        "sentinel" => "Sentinel ingest",
        _ => "Elasticsearch ingest",
    }
    .to_string();
    let created_at = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|e| e.to_string())?
        .as_secs() as i64;

    {
        let mut datasets = session
            .datasets
            .write()
            .map_err(|e| format!("Lock poisoned: {}", e))?;
        datasets.push(DatasetInfo {
            id: dataset_id.clone(),
            name: name.clone(),
            path: None,
            created_at,
            entity_count: 0,
            relation_count: 0,
        });
    }

    let (new_entities, new_relations) = {
        let mut graph = session
            .graph
            .write()
            .map_err(|e| format!("Lock poisoned: {}", e))?;
        let parser = make_parser_for_format("sentinel")?;
        let triples = parser.parse(&data);
        let (e, r) = graph.insert_triples(triples, Some(dataset_id.as_str()));
        run_full_scoring(&mut graph);
        (e, r)
    };

    {
        let mut datasets = session
            .datasets
            .write()
            .map_err(|e| format!("Lock poisoned: {}", e))?;
        if let Some(last) = datasets.last_mut() {
            last.entity_count = new_entities;
            last.relation_count = new_relations;
        }
    }

    let (total_entities, total_relations) = {
        let graph = session
            .graph
            .read()
            .map_err(|e| format!("Lock poisoned: {}", e))?;
        (graph.entity_count(), graph.relation_count())
    };

    Ok(LoadResult {
        new_entities,
        new_relations,
        total_entities,
        total_relations,
    })
}

/// Starts file ingestion in the background and returns immediately.
/// Progress is emitted via "ingest-progress" events.
/// Completion is emitted via "ingest-complete" or "ingest-error" events.
#[tauri::command]
pub async fn cmd_load_data_streaming(
    state: State<'_, Arc<AppState>>,
    app: tauri::AppHandle,
    path: String,
    format: String,
    config: Option<FieldConfig>,
    date_from: Option<String>,
    date_to: Option<String>,
) -> Result<IngestJobStarted, String> {
    let job_id = Uuid::new_v4().to_string();

    let session_id = state
        .current_session_id
        .read()
        .map_err(|e| format!("Lock poisoned: {}", e))?
        .clone()
        .ok_or("No current session")?;

    // Clone the Arc<SessionState> under a brief read lock, then release
    let session = {
        let sessions = state
            .sessions
            .read()
            .map_err(|e| format!("Lock poisoned: {}", e))?;
        Arc::clone(sessions.get(&session_id).ok_or("Session not found")?)
    };

    let dataset_id = Uuid::new_v4().to_string();
    let file_name = std::path::Path::new(&path)
        .file_name()
        .and_then(|p| p.to_str())
        .unwrap_or("ingest")
        .to_string();
    let created_at = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|e| e.to_string())?
        .as_secs() as i64;

    // Create dataset entry under brief lock
    {
        let mut datasets = session
            .datasets
            .write()
            .map_err(|e| format!("Lock poisoned: {}", e))?;
        datasets.push(DatasetInfo {
            id: dataset_id.clone(),
            name: file_name.clone(),
            path: Some(path.clone()),
            created_at,
            entity_count: 0,
            relation_count: 0,
        });
    }

    // Validate format before spawning (fail fast for bad format)
    let pre_check = format.to_lowercase();
    if !["auto", "evtx", "sysmon", "sentinel", "cognito", "generic", "csv", "iis", "iis_w3c", "w3c"].contains(&pre_check.as_str()) {
        return Err(format!(
            "Unsupported format: '{}'. Use 'auto', 'evtx', 'sysmon', 'sentinel', 'cognito', 'generic', 'csv', or 'iis'.",
            format
        ));
    }

    let result_to_return = IngestJobStarted {
        job_id: job_id.clone(),
        dataset_id: dataset_id.clone(),
    };

    // Spawn the heavy work in a background thread
    let bg_job_id = job_id.clone();
    let bg_dataset_id = dataset_id.clone();
    let bg_path = path.clone();
    let bg_format = format.clone();
    let bg_app = app.clone();
    let bg_session = Arc::clone(&session);
    let bg_config = config.clone();
    let bg_date_from = date_from.clone();
    let bg_date_to = date_to.clone();

    tauri::async_runtime::spawn_blocking(move || {
        let panic_app = bg_app.clone();
        let panic_job_id = bg_job_id.clone();
        let panic_dataset_id = bg_dataset_id.clone();

        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(move || {
        const BATCH_LINES: usize = 50_000;
        const BUF_CAPACITY: usize = 8 * 1024 * 1024; // 8 MB
        const MAX_INGEST_LINES: usize = usize::MAX;

        // Date range filter: for line-based formats (IIS, CSV), lines starting with
        // a date outside [date_from, date_to] are skipped before parsing.
        // Dates are compared as byte strings (e.g. "2026-01-15") which works because
        // ISO date format sorts lexicographically.
        let date_from_bytes: Option<Vec<u8>> = bg_date_from.as_ref().map(|s| s.as_bytes().to_vec());
        let date_to_bytes: Option<Vec<u8>> = bg_date_to.as_ref().map(|s| s.as_bytes().to_vec());
        tracing::info!("INGEST: date_from={:?}, date_to={:?}", bg_date_from, bg_date_to);

        // 1. Open file and check for EVTX (binary) before any UTF-8 read
        let use_evtx = path_is_evtx(&bg_path)
            || bg_format.to_lowercase() == "evtx"
            || (bg_format.to_lowercase() == "auto" && file_looks_like_evtx(&bg_path));

        if use_evtx {
            // EVTX streaming path: parse records in batches of 50K directly from the EVTX file
            // without ever holding the full converted NDJSON string in memory.
            let parser: Box<dyn LogParser + Send> = if let Some(cfg) = &bg_config {
                Box::new(ConfigurableParser::new(cfg.clone()))
            } else {
                Box::new(GenericParser)
            };

            let result = evtx_ingest_streaming(
                &bg_path,
                parser.as_ref(),
                &bg_session,
                &bg_dataset_id,
                &bg_app,
                &bg_job_id,
            );

            match result {
                Ok((total_new_entities, total_new_relations)) => {
                    // Scoring phase
                    let _ = bg_app.emit("ingest-progress", serde_json::json!({
                        "phase": "scoring",
                        "bytes_read": 0u64,
                        "bytes_total": 0u64,
                        "entities": total_new_entities,
                        "relations": total_new_relations,
                    }));

                    if let Ok(mut graph) = bg_session.graph.write() {
                        graph.compute_composite_score(1.0, 1.0, 1.0);
                        graph.finalize_anomaly_scorer();
                    }

                    {
                        let mut datasets = match bg_session.datasets.write() {
                            Ok(d) => d,
                            Err(_) => return,
                        };
                        if let Some(last) = datasets.last_mut() {
                            last.entity_count = total_new_entities;
                            last.relation_count = total_new_relations;
                        }
                    }

                    let (total_entities, total_relations) = {
                        let graph = match bg_session.graph.read() {
                            Ok(g) => g,
                            Err(_) => return,
                        };
                        (graph.entity_count(), graph.relation_count())
                    };

                    let _ = bg_app.emit("ingest-complete", IngestComplete {
                        job_id: bg_job_id,
                        dataset_id: bg_dataset_id,
                        result: LoadResult {
                            new_entities: total_new_entities,
                            new_relations: total_new_relations,
                            total_entities,
                            total_relations,
                        },
                    });
                }
                Err(e) => {
                    let _ = bg_app.emit("ingest-error", IngestError {
                        job_id: bg_job_id,
                        dataset_id: bg_dataset_id,
                        error: e,
                    });
                }
            }
            return;
        }

        // 2. Open file (or reopen) and get size for progress reporting
        let file = match std::fs::File::open(&bg_path) {
            Ok(f) => f,
            Err(e) => {
                let _ = bg_app.emit("ingest-error", IngestError {
                    job_id: bg_job_id,
                    dataset_id: bg_dataset_id,
                    error: format!("Failed to open file '{}': {}", bg_path, e),
                });
                return;
            }
        };
        let bytes_total = file.metadata().map(|m| m.len()).unwrap_or(0);

        // 3. Read first 8KB for format detection
        let mut reader = BufReader::with_capacity(BUF_CAPACITY, file);
        let peek_buf = {
            let mut peek_bytes = [0u8; 8192];
            let n = std::io::Read::read(&mut reader, &mut peek_bytes).unwrap_or(0);
            String::from_utf8_lossy(&peek_bytes[..n]).to_string()
        };
        let resolved = resolve_format(&peek_buf, &bg_format);

        // Determine if the file is line-based (NDJSON, IIS, CSV) vs JSON array (starts with '[')
        let trimmed_peek = peek_buf.trim_start();
        let is_line_based = trimmed_peek.starts_with('{') || matches!(resolved.as_str(), "iis" | "iis_w3c" | "w3c")
            || (resolved == "cognito" && !trimmed_peek.starts_with('['));

        // For IIS W3C files, extract the #Fields: header from the peek buffer
        // so we can prepend it to each batch (batches may not contain the header).
        let iis_fields_header = if matches!(resolved.as_str(), "iis" | "iis_w3c" | "w3c") {
            extract_fields_header(&peek_buf)
        } else {
            None
        };

        // Helper: select parser as trait object
        let parser = make_parser_for_format(&resolved);
        let parser: Box<dyn LogParser + Send + Sync> = match parser {
            Ok(p) => p,
            Err(e) => {
                let _ = bg_app.emit("ingest-error", IngestError {
                    job_id: bg_job_id,
                    dataset_id: bg_dataset_id,
                    error: e,
                });
                return;
            }
        };

        // Pre-allocate graph capacity based on file size heuristics (capped to avoid OOM)
        {
            let estimated_entities = ((bytes_total / 400) as usize).min(2_000_000);
            let estimated_relations = ((bytes_total / 200) as usize).min(4_000_000);
            if let Ok(mut graph) = bg_session.graph.write() {
                graph.reserve(estimated_entities, estimated_relations);
            }
        }

        tracing::info!("INGEST: format={}, is_line_based={}, file_size={}", resolved, is_line_based, bytes_total);
        let ingest_result: Result<(usize, usize), String> = (|| -> Result<(usize, usize), String> {
            if is_line_based {
                // ── Line-based streaming path (NDJSON / IIS / CSV): mmap + line-batch parsing ──
                let _ = bg_app.emit("ingest-progress", serde_json::json!({
                    "phase": "reading",
                    "bytes_read": 0u64,
                    "bytes_total": bytes_total,
                    "entities": 0,
                    "relations": 0,
                }));

                let file2 = std::fs::File::open(&bg_path)
                    .map_err(|e| format!("Failed to re-open file '{}': {}", bg_path, e))?;
                let mmap = unsafe { memmap2::Mmap::map(&file2) }
                    .map_err(|e| {
                        tracing::error!("INGEST: Failed to mmap: {}", e);
                        format!("Failed to mmap file '{}': {}", bg_path, e)
                    })?;
                tracing::info!("INGEST: mmap OK, {} bytes", mmap.len());

                // Work directly on bytes — never convert the full mmap to String.
                // Only convert each batch (max ~25MB) via lossy UTF-8.
                let raw = &mmap[..];

                let mut total_new_entities = 0usize;
                let mut total_new_relations = 0usize;
                let mut lines_in_batch = 0usize;
                let mut batch_start = 0usize;
                let mut stopped_early = false;

                // For IIS: track the last-seen #Fields: header so we can
                // prepend it to batches that don't contain one.
                let mut last_fields_header: Option<String> = iis_fields_header.clone();

                // SIMD-accelerated newline scanning via memchr (~20x faster than byte-by-byte)
                let mut total_lines = 0usize;
                let mut search_offset = 0usize;
                while let Some(rel_pos) = memchr::memchr(b'\n', &raw[search_offset..]) {
                    let pos = search_offset + rel_pos;
                    search_offset = pos + 1;

                    total_lines += 1;
                    if total_lines > MAX_INGEST_LINES {
                        tracing::warn!("INGEST: reached max ingest limit of {} lines, stopping", MAX_INGEST_LINES);
                        stopped_early = true;
                        break;
                    }

                    // Date range filter: skip lines outside [date_from, date_to].
                    // IIS/CSV lines start with "YYYY-MM-DD" (10 bytes). Comment lines start with '#'.
                    if date_from_bytes.is_some() || date_to_bytes.is_some() {
                        let line_start = if pos > 0 && batch_start < pos {
                            raw[batch_start..pos].iter().rposition(|&b| b == b'\n')
                                .map(|p| batch_start + p + 1)
                                .unwrap_or(batch_start)
                        } else { batch_start };
                        // Only check data lines (not comments/headers)
                        let first_byte = raw.get(line_start).copied().unwrap_or(b'#');
                        if first_byte.is_ascii_digit() && pos >= line_start + 10 {
                            let line_date = &raw[line_start..line_start + 10];
                            if let Some(ref from) = date_from_bytes {
                                if line_date < from.as_slice() { continue; }
                            }
                            if let Some(ref to) = date_to_bytes {
                                if line_date > to.as_slice() { continue; }
                            }
                        }
                    }

                    // Track #Fields: headers for IIS mid-file rotation
                    if last_fields_header.is_some() || iis_fields_header.is_some() {
                        let line_start = if pos > 0 {
                            let search_from = batch_start.max(pos.saturating_sub(512));
                            memchr::memrchr(b'\n', &raw[search_from..pos])
                                .map(|p| search_from + p + 1)
                                .unwrap_or(batch_start)
                        } else { 0 };
                        if pos > line_start + 8 && &raw[line_start..line_start.min(raw.len()).max(line_start + 8)] == b"#Fields:" {
                            let line_bytes = &raw[line_start..pos];
                            let line_str = String::from_utf8_lossy(line_bytes);
                            last_fields_header = Some(line_str.trim().to_string());
                        }
                    }

                    lines_in_batch += 1;

                    if lines_in_batch >= BATCH_LINES {
                        let batch_bytes = &raw[batch_start..pos + 1];
                        let batch_str = String::from_utf8_lossy(batch_bytes);

                        // For IIS: prepend #Fields: header if batch doesn't contain one
                        let parse_input: String = if let Some(ref hdr) = last_fields_header {
                            if memchr::memmem::find(batch_bytes, b"#Fields:").is_none() {
                                format!("{}\n{}", hdr, batch_str)
                            } else {
                                batch_str.into_owned()
                            }
                        } else {
                            batch_str.into_owned()
                        };

                        // Parallel parsing: split the batch into N sub-chunks,
                        // parse each on a rayon thread, then flatten results.
                        let sub_chunks: Vec<&str> = {
                            let num_chunks = rayon::current_num_threads().max(1);
                            let lines: Vec<&str> = parse_input.lines().collect();
                            let chunk_size = (lines.len() / num_chunks).max(1);
                            lines.chunks(chunk_size)
                                .map(|chunk| {
                                    let first = chunk[0].as_ptr() as usize - parse_input.as_ptr() as usize;
                                    let last = chunk.last().unwrap();
                                    let end = last.as_ptr() as usize + last.len() - parse_input.as_ptr() as usize;
                                    &parse_input[first..end]
                                })
                                .collect()
                        };

                        let triples: Vec<_> = if sub_chunks.len() > 1 {
                            use rayon::prelude::*;
                            sub_chunks.par_iter()
                                .flat_map_iter(|chunk| parser.parse(chunk))
                                .collect()
                        } else {
                            parser.parse(&parse_input)
                        };

                        let (ne, nr) = {
                            let mut graph = bg_session
                                .graph
                                .write()
                                .map_err(|e| format!("Lock poisoned: {}", e))?;
                            graph.insert_triples(triples, Some(&bg_dataset_id))
                        };
                        total_new_entities += ne;
                        total_new_relations += nr;

                        let bytes_read = (pos + 1) as u64;
                        let _ = bg_app.emit("ingest-progress", serde_json::json!({
                            "phase": "parsing",
                            "bytes_read": bytes_read,
                            "bytes_total": bytes_total,
                            "entities": total_new_entities,
                            "relations": total_new_relations,
                        }));

                        // Last-resort OOM guard: edges spill to disk via SpillableEdgeStore,
                        // but entities/interner/metadata stay in RAM. Stop only if critically low.
                        if total_new_relations % (BATCH_LINES * 20) < BATCH_LINES {
                            #[cfg(target_os = "windows")]
                            {
                                use std::mem::MaybeUninit;
                                #[repr(C)]
                                struct MEMORYSTATUSEX {
                                    dw_length: u32,
                                    dw_memory_load: u32,
                                    ull_total_phys: u64,
                                    ull_avail_phys: u64,
                                    ull_total_page_file: u64,
                                    ull_avail_page_file: u64,
                                    ull_total_virtual: u64,
                                    ull_avail_virtual: u64,
                                    ull_avail_extended_virtual: u64,
                                }
                                extern "system" {
                                    fn GlobalMemoryStatusEx(lp_buffer: *mut MEMORYSTATUSEX) -> i32;
                                }
                                let mut mem_info = MaybeUninit::<MEMORYSTATUSEX>::zeroed();
                                unsafe {
                                    let p = mem_info.as_mut_ptr();
                                    (*p).dw_length = std::mem::size_of::<MEMORYSTATUSEX>() as u32;
                                    if GlobalMemoryStatusEx(p) != 0 {
                                        let avail_mb = (*p).ull_avail_phys / (1024 * 1024);
                                        if avail_mb < 256 {
                                            tracing::warn!("INGEST: Critically low memory ({} MB free), stopping to prevent crash", avail_mb);
                                            stopped_early = true;
                                            break;
                                        }
                                    }
                                }
                            }
                        }

                        batch_start = pos + 1;
                        lines_in_batch = 0;
                    }
                }

                // Final batch (remaining lines after last newline)
                // Skip if we stopped early due to memory pressure — the remaining
                // data could be gigabytes and would OOM.
                if !stopped_early && batch_start < raw.len() {
                    let batch_bytes = &raw[batch_start..];
                    let batch_str = String::from_utf8_lossy(batch_bytes);
                    if !batch_str.trim().is_empty() {
                        let triples = if let Some(ref hdr) = last_fields_header {
                            if !batch_str.contains("#Fields:") {
                                let with_header = format!("{}\n{}", hdr, batch_str);
                                parser.parse(&with_header)
                            } else {
                                parser.parse(&batch_str)
                            }
                        } else {
                            parser.parse(&batch_str)
                        };
                        let (ne, nr) = {
                            let mut graph = bg_session
                                .graph
                                .write()
                                .map_err(|e| format!("Lock poisoned: {}", e))?;
                            graph.insert_triples(triples, Some(&bg_dataset_id))
                        };
                        total_new_entities += ne;
                        total_new_relations += nr;
                    }
                }

                Ok((total_new_entities, total_new_relations))
            } else {
                // ── JSON array / small file: memory-mapped parse + insert ──
                let file = std::fs::File::open(&bg_path)
                    .map_err(|e| format!("Failed to open file '{}': {}", bg_path, e))?;
                let mmap = unsafe { memmap2::Mmap::map(&file) }
                    .map_err(|e| format!("Failed to mmap file '{}': {}", bg_path, e))?;
                let contents = std::str::from_utf8(&mmap)
                    .map_err(|e| format!("File is not valid UTF-8: {}", e))?;

                let _ = bg_app.emit("ingest-progress", serde_json::json!({
                    "phase": "parsing",
                    "bytes_read": bytes_total,
                    "bytes_total": bytes_total,
                    "entities": 0,
                    "relations": 0,
                }));

                tracing::info!("INGEST: parsing {} bytes as {}", contents.len(), resolved);
                let triples = parser.parse(contents);
                tracing::info!("INGEST: parsed {} triples", triples.len());

                let mut graph = bg_session
                    .graph
                    .write()
                    .map_err(|e| format!("Lock poisoned: {}", e))?;

                let result = graph.insert_triples(triples, Some(&bg_dataset_id));
                tracing::info!("INGEST: inserted {:?}", result);
                Ok(result)
            }
        })();

        match ingest_result {
            Ok((new_entities, new_relations)) => {
                // Run adaptive scoring (emits scoring phase)
                let _ = bg_app.emit("ingest-progress", serde_json::json!({
                    "phase": "scoring",
                    "bytes_read": bytes_total,
                    "bytes_total": bytes_total,
                    "entities": new_entities,
                    "relations": new_relations,
                }));

                {
                    let mut graph = match bg_session.graph.write() {
                        Ok(g) => g,
                        Err(e) => {
                            let _ = bg_app.emit("ingest-error", IngestError {
                                job_id: bg_job_id,
                                dataset_id: bg_dataset_id,
                                error: format!("Lock poisoned during scoring: {}", e),
                            });
                            return;
                        }
                    };
                    run_scoring_adaptive(&mut graph);
                }

                // Update dataset counts
                if let Ok(mut datasets) = bg_session.datasets.write() {
                    if let Some(ds) = datasets.iter_mut().find(|d| d.id == bg_dataset_id) {
                        ds.entity_count = new_entities;
                        ds.relation_count = new_relations;
                    }
                }

                // Get totals
                let (total_entities, total_relations) = bg_session
                    .graph
                    .read()
                    .map(|g| (g.entity_count(), g.relation_count()))
                    .unwrap_or((0, 0));

                let _ = bg_app.emit("ingest-complete", IngestComplete {
                    job_id: bg_job_id,
                    dataset_id: bg_dataset_id,
                    result: LoadResult {
                        new_entities,
                        new_relations,
                        total_entities,
                        total_relations,
                    },
                });
            }
            Err(e) => {
                let _ = bg_app.emit("ingest-error", IngestError {
                    job_id: bg_job_id,
                    dataset_id: bg_dataset_id,
                    error: e,
                });
            }
        }
        })); // end catch_unwind

        if let Err(panic_info) = result {
            let msg = if let Some(s) = panic_info.downcast_ref::<&str>() {
                s.to_string()
            } else if let Some(s) = panic_info.downcast_ref::<String>() {
                s.clone()
            } else {
                "Unknown panic during ingestion".to_string()
            };
            let _ = panic_app.emit("ingest-error", IngestError {
                job_id: panic_job_id,
                dataset_id: panic_dataset_id,
                error: format!("Internal error: {}", msg),
            });
        }
    });

    Ok(result_to_return)
}
