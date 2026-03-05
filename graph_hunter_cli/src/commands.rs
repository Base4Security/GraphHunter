use std::collections::HashMap;
use std::fs;
use std::io::{self, Write};

use graph_hunter_core::{
    CsvParser, GenericParser, GraphHunter, SentinelJsonParser, SysmonJsonParser,
};
use serde_json::json;
use uuid::Uuid;

use crate::protocol::Response;

/// Per-session state: mirrors Tauri's SessionState but without RwLock (single-threaded CLI).
#[allow(dead_code)]
struct Session {
    id: String,
    name: String,
    graph: GraphHunter,
}

/// Handles all incoming commands, dispatching to the right session/graph.
pub struct CommandHandler {
    sessions: HashMap<String, Session>,
}

impl CommandHandler {
    pub fn new() -> Self {
        Self {
            sessions: HashMap::new(),
        }
    }

    /// Dispatches a parsed request to the appropriate handler.
    /// Writes one or more JSON response lines to stdout.
    pub fn dispatch(&mut self, id: &str, cmd: &str, params: &serde_json::Value) {
        match cmd {
            "create_session" => self.create_session(id, params),
            "ingest" => self.ingest(id, params),
            "ingest_query" => self.ingest_query(id, params),
            "get_stats" => self.get_stats(id, params),
            _ => emit(&Response::error(id, format!("unknown command: {}", cmd))),
        }
    }

    fn create_session(&mut self, id: &str, params: &serde_json::Value) {
        let name = params
            .get("name")
            .and_then(|v| v.as_str())
            .unwrap_or("default")
            .to_string();

        let session_id = Uuid::new_v4().to_string();
        self.sessions.insert(
            session_id.clone(),
            Session {
                id: session_id.clone(),
                name: name.clone(),
                graph: GraphHunter::new(),
            },
        );

        emit(&Response::result(
            id,
            json!({ "session_id": session_id, "name": name }),
        ));
    }

    fn ingest(&mut self, id: &str, params: &serde_json::Value) {
        let session_id = match params.get("session_id").and_then(|v| v.as_str()) {
            Some(s) => s,
            None => {
                emit(&Response::error(id, "missing param: session_id"));
                return;
            }
        };
        let file_path = match params.get("file_path").and_then(|v| v.as_str()) {
            Some(s) => s,
            None => {
                emit(&Response::error(id, "missing param: file_path"));
                return;
            }
        };
        let format_param = params
            .get("format")
            .and_then(|v| v.as_str())
            .unwrap_or("auto");

        let session = match self.sessions.get_mut(session_id) {
            Some(s) => s,
            None => {
                emit(&Response::error(
                    id,
                    format!("session not found: {}", session_id),
                ));
                return;
            }
        };

        // Read file from disk
        let contents = match fs::read_to_string(file_path) {
            Ok(c) => c,
            Err(e) => {
                emit(&Response::error(
                    id,
                    format!("failed to read file '{}': {}", file_path, e),
                ));
                return;
            }
        };

        let resolved = resolve_format(&contents, format_param);
        let dataset_id = Some(Uuid::new_v4().to_string());
        let chunk_size = 500;
        let req_id = id.to_string();

        let (new_entities, new_relations) = match resolved.as_str() {
            "sysmon" => session.graph.ingest_logs_chunked(
                &contents,
                &SysmonJsonParser,
                dataset_id,
                chunk_size,
                |processed, total, entities, relations| {
                    emit(&Response::progress(
                        &req_id,
                        json!({
                            "processed": processed,
                            "total": total,
                            "entities": entities,
                            "relations": relations,
                        }),
                    ));
                },
            ),
            "sentinel" => session.graph.ingest_logs_chunked(
                &contents,
                &SentinelJsonParser,
                dataset_id,
                chunk_size,
                |processed, total, entities, relations| {
                    emit(&Response::progress(
                        &req_id,
                        json!({
                            "processed": processed,
                            "total": total,
                            "entities": entities,
                            "relations": relations,
                        }),
                    ));
                },
            ),
            "generic" => session.graph.ingest_logs_chunked(
                &contents,
                &GenericParser,
                dataset_id,
                chunk_size,
                |processed, total, entities, relations| {
                    emit(&Response::progress(
                        &req_id,
                        json!({
                            "processed": processed,
                            "total": total,
                            "entities": entities,
                            "relations": relations,
                        }),
                    ));
                },
            ),
            "csv" => session.graph.ingest_logs_chunked(
                &contents,
                &CsvParser,
                dataset_id,
                chunk_size,
                |processed, total, entities, relations| {
                    emit(&Response::progress(
                        &req_id,
                        json!({
                            "processed": processed,
                            "total": total,
                            "entities": entities,
                            "relations": relations,
                        }),
                    ));
                },
            ),
            other => {
                emit(&Response::error(
                    id,
                    format!(
                        "unsupported format: '{}'. Use 'auto', 'sysmon', 'sentinel', 'generic', or 'csv'.",
                        other
                    ),
                ));
                return;
            }
        };

        // Run scoring pipeline (mirrors Tauri's run_full_scoring)
        run_full_scoring(&mut session.graph);

        emit(&Response::result(
            id,
            json!({
                "new_entities": new_entities,
                "new_relations": new_relations,
                "total_entities": session.graph.entity_count(),
                "total_relations": session.graph.relation_count(),
            }),
        ));
    }

    fn ingest_query(&mut self, id: &str, params: &serde_json::Value) {
        let session_id = match params.get("session_id").and_then(|v| v.as_str()) {
            Some(s) => s,
            None => {
                emit(&Response::error(id, "missing param: session_id"));
                return;
            }
        };
        let source = match params.get("source").and_then(|v| v.as_str()) {
            Some(s) => s,
            None => {
                emit(&Response::error(id, "missing param: source (sentinel | elastic)"));
                return;
            }
        };

        let session = match self.sessions.get_mut(session_id) {
            Some(s) => s,
            None => {
                emit(&Response::error(
                    id,
                    format!("session not found: {}", session_id),
                ));
                return;
            }
        };

        let (data, _format, next_state): (String, &str, Option<serde_json::Value>) = match source {
            "sentinel" => {
                let workspace_id = match params.get("workspace_id").and_then(|v| v.as_str()) {
                    Some(w) => w,
                    None => {
                        emit(&Response::error(id, "missing param: workspace_id"));
                        return;
                    }
                };
                let query = params
                    .get("query")
                    .and_then(|v| v.as_str())
                    .unwrap_or("");
                let auth = match (
                    params.get("azure_tenant_id").and_then(|v| v.as_str()),
                    params.get("azure_client_id").and_then(|v| v.as_str()),
                    params.get("azure_client_secret").and_then(|v| v.as_str()),
                ) {
                    (Some(t), Some(c), Some(s)) => Some(crate::siem::SentinelAuth {
                        tenant_id: t.to_string(),
                        client_id: c.to_string(),
                        client_secret: s.to_string(),
                    }),
                    _ => None,
                };
                match crate::siem::run_sentinel_query(workspace_id, query, auth) {
                    Ok(res) => {
                        let next = res
                            .next_query_start
                            .map(|s| serde_json::json!({ "next_query_start": s }));
                        (res.data, "sentinel", next)
                    }
                    Err(e) => {
                        emit(&Response::error(id, e));
                        return;
                    }
                }
            }
            "elastic" => {
                let url = match params.get("url").and_then(|v| v.as_str()) {
                    Some(u) => u,
                    None => {
                        emit(&Response::error(id, "missing param: url"));
                        return;
                    }
                };
                let index = params
                    .get("index")
                    .and_then(|v| v.as_str())
                    .unwrap_or("_all");
                let query = params
                    .get("query")
                    .and_then(|v| v.as_str())
                    .unwrap_or("{}");
                let size = params.get("size").and_then(|v| v.as_u64()).map(|n| n as u32);
                let search_after = params.get("search_after").and_then(|v| v.as_array());
                let search_after_ref: Option<&[serde_json::Value]> = search_after
                    .as_ref()
                    .map(|a| a.as_slice());
                let auth = match (
                    params.get("elastic_api_key").and_then(|v| v.as_str()),
                    params.get("elastic_user").and_then(|v| v.as_str()),
                    params.get("elastic_password").and_then(|v| v.as_str()),
                ) {
                    (Some(k), _, _) if !k.is_empty() => Some(crate::siem::ElasticAuth {
                        api_key: Some(k.to_string()),
                        user: None,
                        password: None,
                    }),
                    (_, Some(u), p) if !u.is_empty() => Some(crate::siem::ElasticAuth {
                        api_key: None,
                        user: Some(u.to_string()),
                        password: p.map(|s| s.to_string()),
                    }),
                    _ => None,
                };
                match crate::siem::run_elastic_query(
                    url,
                    index,
                    query,
                    size,
                    search_after_ref,
                    auth,
                ) {
                    Ok(res) => {
                        let next = res.next_search_after.map(|v| {
                            serde_json::json!({ "next_search_after": v })
                        });
                        (res.data, "sentinel", next)
                    }
                    Err(e) => {
                        emit(&Response::error(id, e));
                        return;
                    }
                }
            }
            _ => {
                emit(&Response::error(
                    id,
                    format!("unsupported source: '{}'. Use 'sentinel' or 'elastic'.", source),
                ));
                return;
            }
        };

        let dataset_id = Some(Uuid::new_v4().to_string());
        let chunk_size = 500;
        let req_id = id.to_string();

        let (new_entities, new_relations) = session.graph.ingest_logs_chunked(
            &data,
            &SentinelJsonParser,
            dataset_id,
            chunk_size,
            |processed, total, entities, relations| {
                emit(&Response::progress(
                    &req_id,
                    json!({
                        "processed": processed,
                        "total": total,
                        "entities": entities,
                        "relations": relations,
                    }),
                ));
            },
        );

        run_full_scoring(&mut session.graph);

        let mut result = json!({
            "new_entities": new_entities,
            "new_relations": new_relations,
            "total_entities": session.graph.entity_count(),
            "total_relations": session.graph.relation_count(),
        });
        if let Some(ref state) = next_state {
            result.as_object_mut().unwrap().insert("pagination".to_string(), state.clone());
        }
        emit(&Response::result(id, result));
    }

    fn get_stats(&self, id: &str, params: &serde_json::Value) {
        let session_id = match params.get("session_id").and_then(|v| v.as_str()) {
            Some(s) => s,
            None => {
                emit(&Response::error(id, "missing param: session_id"));
                return;
            }
        };

        let session = match self.sessions.get(session_id) {
            Some(s) => s,
            None => {
                emit(&Response::error(
                    id,
                    format!("session not found: {}", session_id),
                ));
                return;
            }
        };

        emit(&Response::result(
            id,
            json!({
                "entity_count": session.graph.entity_count(),
                "relation_count": session.graph.relation_count(),
                "entity_types": session.graph.entity_type_counts(),
            }),
        ));
    }
}

/// Runs the full scoring pipeline (mirrors Tauri's run_full_scoring).
fn run_full_scoring(graph: &mut GraphHunter) {
    graph.compute_scores();
    graph.compute_temporal_pagerank(None, None, None, None, None);
    graph.compute_betweenness(None);
    graph.compute_composite_score(1.0, 1.0, 1.0);
}

/// Resolves "auto" format from file contents (mirrors Tauri's resolve_format).
fn resolve_format(contents: &str, format_param: &str) -> String {
    let f = format_param.to_lowercase();
    if f != "auto" {
        return f;
    }
    let trimmed = contents.trim();
    if trimmed.starts_with('[') || trimmed.starts_with('{') {
        if contents.contains("EventID") && contents.contains("UtcTime") {
            return "sysmon".to_string();
        }
        if contents.contains("\"Type\"")
            && (contents.contains("SecurityEvent")
                || contents.contains("SigninLogs")
                || contents.contains("DeviceProcessEvents")
                || contents.contains("DeviceNetworkEvents")
                || contents.contains("DeviceFileEvents")
                || contents.contains("CommonSecurityLog"))
        {
            return "sentinel".to_string();
        }
        return "generic".to_string();
    }
    "csv".to_string()
}

/// Writes a single JSON line to stdout (the protocol transport).
fn emit(response: &Response) {
    let line = serde_json::to_string(response).expect("failed to serialize response");
    let stdout = io::stdout();
    let mut handle = stdout.lock();
    let _ = writeln!(handle, "{}", line);
    let _ = handle.flush();
}
