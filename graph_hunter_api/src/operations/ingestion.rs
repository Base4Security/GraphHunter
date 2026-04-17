//! Ingestion commands: preview + load_data + ingest_siem +
//! load_data_with_config.
//!
//! The streaming variant (`load_data_streaming`) stays in Tauri for
//! now — it's a ~600-line background-task handler with multi-phase
//! progress emission, date filtering, and memory-pressure checks. It
//! can be migrated in a focused session; the event emission is
//! already compatible with the canonical [`EventEmitter`].

use std::sync::Arc;

use graph_hunter_core::{ConfigurableParser, GenericParser, LogParser};
use uuid::Uuid;

use crate::dto::ingestion::{
    DetectedField, IngestSiemRequest, LoadDataRequest, LoadDataWithConfigRequest, LoadResult,
    PreviewIngestRequest, PreviewIngestResult,
};
use crate::evtx::{evtx_preview_sample, evtx_to_sysmon_ndjson, file_looks_like_evtx, path_is_evtx};
use crate::format_registry::{make_parser_for_format, preview_for_format, resolve_format};
use crate::scoring::run_full_scoring;
use crate::state::DatasetInfo;
use crate::util::now_secs;
use crate::{ApiError, ApiResult, GraphHunterApi};

const LARGE_FILE_THRESHOLD: u64 = 10 * 1024 * 1024;
const PREVIEW_READ_SIZE: usize = 64 * 1024;
const EVTX_PREVIEW_SAMPLE_SIZE: usize = 1000;

impl GraphHunterApi {
    /// Detect a file's format + propose a field → entity type mapping.
    /// Stateless — reads from disk, doesn't touch any session.
    pub fn preview_ingest(&self, req: PreviewIngestRequest) -> ApiResult<PreviewIngestResult> {
        let use_evtx = req.format.to_lowercase() == "evtx"
            || path_is_evtx(&req.path)
            || (req.format.to_lowercase() == "auto" && file_looks_like_evtx(&req.path));
        let (contents, resolved) = if use_evtx {
            let contents = evtx_preview_sample(&req.path, EVTX_PREVIEW_SAMPLE_SIZE)
                .map_err(ApiError::Io)?;
            (contents, "sysmon".to_string())
        } else {
            let file_size = std::fs::metadata(&req.path).map(|m| m.len()).unwrap_or(0);
            let contents = if file_size > LARGE_FILE_THRESHOLD {
                let mut file = std::fs::File::open(&req.path)
                    .map_err(|e| ApiError::Io(format!("open '{}': {e}", req.path)))?;
                let mut buf = vec![0u8; PREVIEW_READ_SIZE];
                let n = std::io::Read::read(&mut file, &mut buf)
                    .map_err(|e| ApiError::Io(format!("read: {e}")))?;
                String::from_utf8_lossy(&buf[..n]).to_string()
            } else {
                std::fs::read_to_string(&req.path)
                    .map_err(|e| ApiError::Io(format!("read '{}': {e}", req.path)))?
            };
            let resolved = resolve_format(&contents, &req.format);
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

    /// Read a file from disk, parse it, insert triples into the
    /// resolved session's graph, and run full scoring. Synchronous;
    /// callers in async contexts should `spawn_blocking`.
    pub fn load_data(&self, req: LoadDataRequest) -> ApiResult<LoadResult> {
        let use_evtx = req.format.to_lowercase() == "evtx"
            || path_is_evtx(&req.path)
            || (req.format.to_lowercase() == "auto" && file_looks_like_evtx(&req.path));
        let (contents, format_for_parser) = if use_evtx {
            let contents = evtx_to_sysmon_ndjson(&req.path).map_err(ApiError::Io)?;
            (contents, "generic".to_string())
        } else {
            let contents = std::fs::read_to_string(&req.path)
                .map_err(|e| ApiError::Io(format!("read '{}': {e}", req.path)))?;
            (contents, req.format)
        };

        let session = self.resolve_session(req.session.as_ref())?;

        let dataset_id = Uuid::new_v4().to_string();
        let name = std::path::Path::new(&req.path)
            .file_name()
            .and_then(|p| p.to_str())
            .unwrap_or("ingest")
            .to_string();

        {
            let mut datasets = session
                .datasets
                .write()
                .map_err(|e| ApiError::Internal(format!("datasets lock poisoned: {e}")))?;
            datasets.push(DatasetInfo {
                id: dataset_id.clone(),
                name,
                path: Some(req.path.clone()),
                created_at: now_secs(),
                entity_count: 0,
                relation_count: 0,
            });
        }

        let (new_entities, new_relations) = {
            let mut graph = session
                .graph
                .write()
                .map_err(|e| ApiError::Internal(format!("graph lock poisoned: {e}")))?;
            let resolved_format = resolve_format(&contents, &format_for_parser);
            let parser = make_parser_for_format(&resolved_format)
                .map_err(ApiError::InvalidInput)?;
            let triples = parser.parse(&contents);
            let result = graph
                .insert_triples(triples, Some(dataset_id.as_str()))
                .map_err(|e| ApiError::Internal(e.to_string()))?;
            run_full_scoring(&mut graph);
            result
        };

        {
            let mut datasets = session
                .datasets
                .write()
                .map_err(|e| ApiError::Internal(format!("datasets lock poisoned: {e}")))?;
            if let Some(last) = datasets.last_mut() {
                last.entity_count = new_entities;
                last.relation_count = new_relations;
            }
        }

        let (total_entities, total_relations) = {
            let graph = session
                .graph
                .read()
                .map_err(|e| ApiError::Internal(format!("graph lock poisoned: {e}")))?;
            (graph.entity_count(), graph.relation_count())
        };

        Ok(LoadResult {
            new_entities,
            new_relations,
            total_entities,
            total_relations,
        })
    }

    /// SIEM ingest (Sentinel or Elastic): fetch via CLI helper then
    /// ingest into the resolved session's graph. Async because the
    /// network fetch runs in a `spawn_blocking` task.
    pub async fn ingest_siem(&self, req: IngestSiemRequest) -> ApiResult<LoadResult> {
        let source = req
            .params
            .get("source")
            .and_then(|v| v.as_str())
            .ok_or_else(|| {
                ApiError::InvalidInput(
                    "missing param: source (sentinel | elastic)".into(),
                )
            })?;

        let data = match source {
            "sentinel" => {
                let workspace_id = req
                    .params
                    .get("workspace_id")
                    .and_then(|v| v.as_str())
                    .ok_or_else(|| {
                        ApiError::InvalidInput("missing param: workspace_id".into())
                    })?
                    .to_string();
                let query = req
                    .params
                    .get("query")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string();
                let auth = match (
                    req.params.get("azure_tenant_id").and_then(|v| v.as_str()),
                    req.params.get("azure_client_id").and_then(|v| v.as_str()),
                    req.params
                        .get("azure_client_secret")
                        .and_then(|v| v.as_str()),
                ) {
                    (Some(t), Some(c), Some(s)) => Some(graph_hunter_cli::siem::SentinelAuth {
                        tenant_id: t.to_string(),
                        client_id: c.to_string(),
                        client_secret: s.to_string(),
                    }),
                    _ => None,
                };
                let res = tokio::task::spawn_blocking(move || {
                    graph_hunter_cli::siem::run_sentinel_query(&workspace_id, &query, auth)
                })
                .await
                .map_err(|e| ApiError::Internal(format!("task join error: {e}")))?
                .map_err(|e| ApiError::Upstream {
                    service: "sentinel".into(),
                    message: e,
                })?;
                res.data
            }
            "elastic" => {
                let url = req
                    .params
                    .get("url")
                    .and_then(|v| v.as_str())
                    .ok_or_else(|| ApiError::InvalidInput("missing param: url".into()))?
                    .to_string();
                let index = req
                    .params
                    .get("index")
                    .and_then(|v| v.as_str())
                    .unwrap_or("_all")
                    .to_string();
                let query = req
                    .params
                    .get("query")
                    .and_then(|v| v.as_str())
                    .unwrap_or("{}")
                    .to_string();
                let size = req.params.get("size").and_then(|v| v.as_u64()).map(|n| n as u32);
                let auth = match (
                    req.params.get("elastic_api_key").and_then(|v| v.as_str()),
                    req.params.get("elastic_user").and_then(|v| v.as_str()),
                    req.params.get("elastic_password").and_then(|v| v.as_str()),
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
                let res = tokio::task::spawn_blocking(move || {
                    graph_hunter_cli::siem::run_elastic_query(
                        &url, &index, &query, size, None, auth,
                    )
                })
                .await
                .map_err(|e| ApiError::Internal(format!("task join error: {e}")))?
                .map_err(|e| ApiError::Upstream {
                    service: "elastic".into(),
                    message: e.to_string(),
                })?;
                res.data
            }
            other => {
                return Err(ApiError::InvalidInput(format!(
                    "unsupported source: '{other}'. Use 'sentinel' or 'elastic'."
                )))
            }
        };

        let session = self.resolve_session(req.session.as_ref())?;

        let dataset_id = Uuid::new_v4().to_string();
        let name = match source {
            "sentinel" => "Sentinel ingest",
            _ => "Elasticsearch ingest",
        }
        .to_string();

        {
            let mut datasets = session
                .datasets
                .write()
                .map_err(|e| ApiError::Internal(format!("datasets lock poisoned: {e}")))?;
            datasets.push(DatasetInfo {
                id: dataset_id.clone(),
                name,
                path: None,
                created_at: now_secs(),
                entity_count: 0,
                relation_count: 0,
            });
        }

        let (new_entities, new_relations) = {
            let mut graph = session
                .graph
                .write()
                .map_err(|e| ApiError::Internal(format!("graph lock poisoned: {e}")))?;
            let parser = make_parser_for_format("sentinel").map_err(ApiError::InvalidInput)?;
            let triples = parser.parse(&data);
            let (e, r) = graph
                .insert_triples(triples, Some(dataset_id.as_str()))
                .map_err(|e| ApiError::Internal(e.to_string()))?;
            run_full_scoring(&mut graph);
            (e, r)
        };

        {
            let mut datasets = session
                .datasets
                .write()
                .map_err(|e| ApiError::Internal(format!("datasets lock poisoned: {e}")))?;
            if let Some(last) = datasets.last_mut() {
                last.entity_count = new_entities;
                last.relation_count = new_relations;
            }
        }

        let (total_entities, total_relations) = {
            let graph = session
                .graph
                .read()
                .map_err(|e| ApiError::Internal(format!("graph lock poisoned: {e}")))?;
            (graph.entity_count(), graph.relation_count())
        };

        Ok(LoadResult {
            new_entities,
            new_relations,
            total_entities,
            total_relations,
        })
    }

    /// Load data with an explicit [`FieldConfig`] (user-supplied field
    /// mapping). Replaces `cmd_load_data_with_config` from the Tauri
    /// `graph_ops` module. Synchronous — spawn_blocking at the
    /// caller.
    pub fn load_data_with_config(&self, req: LoadDataWithConfigRequest) -> ApiResult<LoadResult> {
        // Same EVTX-detection path as load_data.
        let use_evtx = path_is_evtx(&req.path) || file_looks_like_evtx(&req.path);
        let contents = if use_evtx {
            evtx_to_sysmon_ndjson(&req.path).map_err(ApiError::Io)?
        } else {
            std::fs::read_to_string(&req.path)
                .map_err(|e| ApiError::Io(format!("read '{}': {e}", req.path)))?
        };

        let session = self.resolve_session(req.session.as_ref())?;

        let dataset_id = Uuid::new_v4().to_string();
        let name = std::path::Path::new(&req.path)
            .file_name()
            .and_then(|p| p.to_str())
            .unwrap_or("ingest")
            .to_string();
        {
            let mut datasets = session
                .datasets
                .write()
                .map_err(|e| ApiError::Internal(format!("datasets lock poisoned: {e}")))?;
            datasets.push(DatasetInfo {
                id: dataset_id.clone(),
                name,
                path: Some(req.path.clone()),
                created_at: now_secs(),
                entity_count: 0,
                relation_count: 0,
            });
        }

        let (new_entities, new_relations) = {
            let mut graph = session
                .graph
                .write()
                .map_err(|e| ApiError::Internal(format!("graph lock poisoned: {e}")))?;
            let (ne, nr) = if use_evtx {
                graph
                    .ingest_logs(&contents, &GenericParser, None)
                    .map_err(|e| ApiError::Internal(e.to_string()))?
            } else {
                let parser = ConfigurableParser::new(req.config);
                graph
                    .ingest_logs(&contents, &parser, None)
                    .map_err(|e| ApiError::Internal(e.to_string()))?
            };
            run_full_scoring(&mut graph);
            (ne, nr)
        };

        {
            let mut datasets = session
                .datasets
                .write()
                .map_err(|e| ApiError::Internal(format!("datasets lock poisoned: {e}")))?;
            if let Some(last) = datasets.last_mut() {
                last.entity_count = new_entities;
                last.relation_count = new_relations;
            }
        }

        let total_entities = {
            let graph = session
                .graph
                .read()
                .map_err(|e| ApiError::Internal(format!("graph lock poisoned: {e}")))?;
            graph.entity_count()
        };
        let total_relations = {
            let graph = session
                .graph
                .read()
                .map_err(|e| ApiError::Internal(format!("graph lock poisoned: {e}")))?;
            graph.relation_count()
        };

        Ok(LoadResult {
            new_entities,
            new_relations,
            total_entities,
            total_relations,
        })
    }
}

// Keep LogParser in scope so `parser.parse(...)` resolves. Used only to
// satisfy the trait call — not called directly here.
#[allow(dead_code)]
fn _ensure_logparser_imported() {
    let _: Option<&dyn LogParser> = None;
}

// Keep Arc reachable for clippy when the signatures need it.
#[allow(dead_code)]
fn _ensure_arc_imported() -> Option<Arc<u8>> {
    None
}
