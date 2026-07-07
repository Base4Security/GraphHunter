//! Sentinel real-time connector commands: connect, disconnect, status,
//! env probe, and ad-hoc KQL. The polling loop itself lives in
//! `crate::sentinel_connector`; these operations manage its lifecycle.

use std::sync::Arc;
use std::time::Duration;

use graph_hunter_core::sentinel::{build_hydration_kql, sentinel_entity_targets};
use graph_hunter_core::types::EntityType;
use graph_hunter_siem::{
    HttpSentinelTransport, QueryStats, SentinelAuth, SentinelPollingConfig, SentinelTokenCache,
    SentinelTransport, normalize_response, run_sentinel_query,
};
use uuid::Uuid;

use crate::dto::sentinel::{
    BuildRecord, ConnectorStatusResponse, EnrichmentApplied, GraphBuildRequest, GraphBuildResult,
    GraphProposal, GraphProposePayload, GraphProposeRequest, GraphProposeResult, HuntingTemplateId,
    KqlResult,
    NodeEnrichRequest, ProposalEdge, ProposalNode, RunHuntingTemplateRequest, RunKqlRequest,
    SchemaDiscoverRequest, SchemaDiscoverResult, SchemaField, SchemaTable, SeedFromIocRequest,
    SeedResult, SelectedField, SentinelConnectRequest, SentinelConnectedEvent, SentinelEnvStatus,
    TimeWindow,
};
use crate::util::{parse_entity_type, parse_relation_type};
use crate::events::events as event_names;
use crate::format_registry::make_parser_for_format;
use crate::scoring::{run_full_scoring, run_scoring_adaptive, run_scoring_incremental};
use crate::sentinel_connector::{
    ConnectorStatus, SentinelConnectorHandle, default_tables, polling_loop,
};
use crate::state::{DatasetInfo, SessionHandle};
use crate::util::now_secs;
use crate::{ApiError, ApiResult, GraphHunterApi};

// LogParser is pulled in transitively via `make_parser_for_format`,
// no direct import needed here.

/// Narrows a node hydration to a subset of its mapped Sentinel tables
/// and caps the rows pulled per table. `None` fields mean "no
/// restriction" — a fully-`None` filter behaves exactly like the
/// unfiltered hydration.
#[derive(Debug, Clone, Default)]
pub struct HydrationFilter {
    /// Restrict to these tables (case-insensitive match against the
    /// type's mapped tables). `None` = all mapped tables.
    pub tables: Option<Vec<String>>,
    /// Cap rows per table (`| take N`). `None` = 5000 (the built-in default).
    pub max_rows: Option<u32>,
}

fn env_or(explicit: &str, env_key: &str) -> ApiResult<String> {
    if !explicit.is_empty() {
        return Ok(explicit.to_string());
    }
    std::env::var(env_key).map_err(|_| {
        ApiError::InvalidInput(format!(
            "Missing '{env_key}': not provided and {env_key} not set in .env"
        ))
    })
}

fn resolve_poll_interval(explicit: u64) -> u64 {
    if explicit > 0 {
        return explicit;
    }
    std::env::var("SENTINEL_POLL_INTERVAL_SECS")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(30)
}

fn resolve_batch_size(explicit: u32) -> u32 {
    if explicit > 0 {
        return explicit;
    }
    std::env::var("SENTINEL_BATCH_SIZE")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(10000)
}

/// Read the four `AZURE_*` env vars; returns `(workspace_id, auth)` when
/// all are present, else `None`. Shared by seed + enrich.
fn resolve_azure_creds() -> Option<(String, SentinelAuth)> {
    let ws = std::env::var("AZURE_WORKSPACE_ID").ok()?;
    let tenant = std::env::var("AZURE_TENANT_ID").ok()?;
    let client = std::env::var("AZURE_CLIENT_ID").ok()?;
    let secret = std::env::var("AZURE_CLIENT_SECRET").ok()?;
    Some((
        ws,
        SentinelAuth { tenant_id: tenant, client_id: client, client_secret: secret },
    ))
}

fn resolve_tables(explicit: &[String]) -> Vec<String> {
    if !explicit.is_empty() {
        return explicit.to_vec();
    }
    std::env::var("SENTINEL_TABLES")
        .ok()
        .map(|s| {
            s.split(',')
                .map(|t| t.trim().to_string())
                .filter(|t| !t.is_empty())
                .collect()
        })
        .unwrap_or_else(default_tables)
}

impl GraphHunterApi {
    /// Start the real-time Sentinel polling connector. Returns
    /// immediately with the connector metadata; the polling loop
    /// spawns as a background task and emits progress events through
    /// the canonical [`crate::EventEmitter`].
    pub async fn sentinel_connect(
        &self,
        req: SentinelConnectRequest,
        explicit_session: Option<SessionHandle>,
    ) -> ApiResult<SentinelConnectedEvent> {
        // Reject if a connector is already running.
        {
            let handle = self.sentinel_connector_handle();
            let guard = handle
                .read()
                .map_err(|e| ApiError::Internal(format!("sentinel lock poisoned: {e}")))?;
            if guard.is_some() {
                return Err(ApiError::InvalidState(
                    "Sentinel connector is already running. Disconnect first.".into(),
                ));
            }
        }

        let session = self.resolve_session(explicit_session.as_ref())?;
        let session_id = session.id.clone();

        let connector_id = Uuid::new_v4().to_string();
        let dataset_id = format!("sentinel-live-{}", &connector_id[..8]);

        // Add a dataset entry so the UI shows "Sentinel Live (xxxx)".
        {
            let mut datasets = session
                .datasets
                .write()
                .map_err(|e| ApiError::Internal(format!("datasets lock poisoned: {e}")))?;
            datasets.push(DatasetInfo {
                id: dataset_id.clone(),
                name: format!("Sentinel Live ({})", &connector_id[..8]),
                path: None,
                created_at: now_secs(),
                entity_count: 0,
                relation_count: 0,
                field_config: None,
                ingest_stats: None,
            });
        }

        // Resolve creds + config: explicit params override .env fallbacks.
        let workspace_id = env_or(&req.workspace_id, "AZURE_WORKSPACE_ID")?;
        let tenant_id = env_or(&req.azure_tenant_id, "AZURE_TENANT_ID")?;
        let client_id = env_or(&req.azure_client_id, "AZURE_CLIENT_ID")?;
        let client_secret = env_or(&req.azure_client_secret, "AZURE_CLIENT_SECRET")?;
        let poll_interval = resolve_poll_interval(req.poll_interval_secs).max(5);
        let tables = resolve_tables(&req.tables);
        let batch_size = resolve_batch_size(req.batch_size).max(100);

        let config = SentinelPollingConfig {
            workspace_id,
            auth: SentinelAuth {
                tenant_id,
                client_id,
                client_secret,
            },
            poll_interval_secs: poll_interval,
            tables,
            batch_size,
            initial_time_window_filter: req.time_window.as_ref().map(TimeWindow::kql_filter),
        };

        let transport = Arc::new(HttpSentinelTransport::new());
        let token_cache = Arc::new(SentinelTokenCache::new());
        let cancel = tokio_util::sync::CancellationToken::new();
        let (status_tx, status_rx) = tokio::sync::watch::channel(ConnectorStatus::Paused);
        let (pause_tx, pause_rx) = tokio::sync::watch::channel(true);

        let event = SentinelConnectedEvent {
            connector_id: connector_id.clone(),
            tables: config.tables.clone(),
            poll_interval_secs: config.poll_interval_secs,
            paused: true,
        };

        let task_cancel = cancel.clone();
        let emitter = self.emitter_arc();
        let session_for_task = session.clone();
        let task_handle = tokio::spawn(polling_loop(
            config,
            transport,
            token_cache,
            session_for_task,
            session_id,
            emitter.clone(),
            task_cancel,
            status_tx,
            dataset_id,
            pause_rx,
        ));

        // Register the handle.
        {
            let handle_slot = self.sentinel_connector_handle();
            let mut guard = handle_slot
                .write()
                .map_err(|e| ApiError::Internal(format!("sentinel lock poisoned: {e}")))?;
            *guard = Some(SentinelConnectorHandle {
                connector_id: connector_id.clone(),
                cancel_token: cancel,
                task_handle,
                status_rx,
                pause_tx,
            });
        }

        // Connected PAUSED: no live ingest yet, so the session is Ready
        // (huntable over any seeded data). `sentinel_resume` flips it to
        // LiveTail when polling actually starts; `sentinel_pause` restores
        // Ready. (Reconciliation: the pause-by-default model from main now
        // drives the phase, using set_phase restored from the audit branch.)
        session.set_phase(crate::state::SessionPhase::Ready);

        // Announce on the canonical event channel.
        self.emitter_arc().emit(
            "sentinel-connected",
            serde_json::to_value(&event).unwrap_or(serde_json::Value::Null),
        );
        Ok(event)
    }

    /// Disconnect the active connector. Cancels the polling task with
    /// a 10s grace period, then runs full adaptive scoring over the
    /// accumulated graph so the "end of run" analytics are correct.
    pub async fn sentinel_disconnect(&self) -> ApiResult<()> {
        let handle = {
            let handle_slot = self.sentinel_connector_handle();
            let mut guard = handle_slot
                .write()
                .map_err(|e| ApiError::Internal(format!("sentinel lock poisoned: {e}")))?;
            guard.take()
        }
        .ok_or_else(|| ApiError::InvalidState("No Sentinel connector is running.".into()))?;

        handle.cancel_token.cancel();
        let _ = tokio::time::timeout(Duration::from_secs(10), handle.task_handle).await;

        // Final scoring pass, then restore Ready: live ingest has stopped and
        // the graph is scored/stable, so the session is huntable again. The
        // connector left it in LiveTail; without this it would never leave it.
        if let Some(session) = self.sessions().current_session() {
            if let Ok(mut graph) = session.graph.write() {
                let _ = run_scoring_adaptive(&mut graph);
            }
            session.set_phase(crate::state::SessionPhase::Ready);
        }
        // Emit status so the UI updates promptly.
        self.emitter_arc().emit(
            event_names::SENTINEL_STATUS,
            serde_json::json!({"disconnected": true}),
        );
        Ok(())
    }

    /// Return the current connector status (or disconnected when no
    /// handle exists).
    pub fn sentinel_status(&self) -> ApiResult<ConnectorStatusResponse> {
        let handle_slot = self.sentinel_connector_handle();
        let guard = handle_slot
            .read()
            .map_err(|e| ApiError::Internal(format!("sentinel lock poisoned: {e}")))?;
        Ok(match guard.as_ref() {
            Some(h) => ConnectorStatusResponse {
                connected: true,
                connector_id: Some(h.connector_id.clone()),
                status: Some(h.status_rx.borrow().clone()),
            },
            None => ConnectorStatusResponse {
                connected: false,
                connector_id: None,
                status: None,
            },
        })
    }

    /// Check which Sentinel-related env vars are configured. Returns
    /// actual values for non-secret fields and a masked hint for the
    /// client secret so the UI form can auto-populate.
    pub fn sentinel_check_env(&self) -> SentinelEnvStatus {
        let secret = std::env::var("AZURE_CLIENT_SECRET").ok();
        SentinelEnvStatus {
            azure_client_id: std::env::var("AZURE_CLIENT_ID").ok(),
            azure_client_secret_set: secret.is_some(),
            azure_client_secret_masked: secret.map(|s| {
                if s.len() > 6 {
                    format!("{}...{}", &s[..3], &s[s.len() - 3..])
                } else {
                    "***".into()
                }
            }),
            azure_tenant_id: std::env::var("AZURE_TENANT_ID").ok(),
            azure_subscription_id: std::env::var("AZURE_SUBSCRIPTION_ID").ok(),
            azure_resource_group: std::env::var("AZURE_RESOURCE_GROUP").ok(),
            azure_workspace_id: std::env::var("AZURE_WORKSPACE_ID").ok(),
            azure_workspace_name: std::env::var("AZURE_WORKSPACE_NAME").ok(),
        }
    }

    /// Run an ad-hoc KQL query against Log Analytics, ingest the
    /// resulting triples into the current session's graph, and return
    /// the executed KQL so the analyst can replicate it in the Azure
    /// portal.
    pub async fn run_kql(&self, req: RunKqlRequest) -> ApiResult<KqlResult> {
        let raw_kql = req.kql.trim().to_string();
        if raw_kql.is_empty() {
            return Err(ApiError::InvalidInput("KQL query cannot be empty".into()));
        }
        // Phase L soft sugar: if the analyst's query lacks a
        // `TimeGenerated` filter and the form supplied a window, splice
        // one in between the table reference and the rest of the query.
        // If the user wrote their own filter we leave it untouched —
        // explicit always wins over inferred.
        let kql = apply_time_window_sugar(&raw_kql, req.time_window.as_ref());

        // §4.7 fallback gate. Reading entity-class rows out via raw KQL bypasses
        // the graph. On the inspect path, refuse such a query unless the analyst
        // explicitly acknowledges the fallback — and hand back a ready-to-run
        // graph_propose payload so the graph path is the easy next step.
        // Inspect is exactly `ingest == Some(false)` (the rows-only branch
        // below); `None`/`Some(true)` ingest and are never gated.
        let is_inspect = req.ingest == Some(false);
        let propose_payload = extract_propose_payload(&kql);
        let acknowledged = req.acknowledge_fallback == Some(true);
        if is_inspect && propose_payload.is_some() && !acknowledged {
            return Ok(KqlResult {
                new_entities: 0,
                new_relations: 0,
                total_entities: 0,
                total_relations: 0,
                kql_executed: kql,
                row_count: 0,
                took_ms: 0,
                take_limit: None,
                truncated: false,
                rows: None,
                graph_advisory: Some(
                    "Not executed: this raw KQL projects IPs/identities, which GraphHunter \
                     materializes as a graph rather than reading out row-by-row. Call \
                     graph_propose with the suggested fields (then graph_build), or re-run with \
                     acknowledge_fallback=true to run the raw query as a one-off."
                        .to_string(),
                ),
                graph_propose: propose_payload,
                fallback_gated: true,
            });
        }
        if is_inspect && propose_payload.is_some() && acknowledged {
            tracing::warn!(
                target: "graphhunter::fallback",
                "sentinel_query raw-KQL fallback executed (acknowledged): {}",
                kql.lines().next().unwrap_or("").trim()
            );
        }

        let workspace_id = env_or(&req.workspace_id, "AZURE_WORKSPACE_ID")?;
        let tenant_id = env_or(&req.azure_tenant_id, "AZURE_TENANT_ID")?;
        let client_id = env_or(&req.azure_client_id, "AZURE_CLIENT_ID")?;
        let client_secret = env_or(&req.azure_client_secret, "AZURE_CLIENT_SECRET")?;

        let auth = SentinelAuth {
            tenant_id,
            client_id,
            client_secret,
        };
        let kql_clone = kql.clone();
        let ws_clone = workspace_id.clone();
        let started = std::time::Instant::now();
        let res = tokio::task::spawn_blocking(move || {
            run_sentinel_query(&ws_clone, &kql_clone, Some(auth))
        })
        .await
        .map_err(|e| ApiError::Internal(format!("task join error: {e}")))?
        .map_err(|e| ApiError::Upstream {
            service: "sentinel-kql".into(),
            message: e,
        })?;
        let took_ms = started.elapsed().as_millis() as u64;

        let row_count = res.data.matches('{').count();
        let take_limit = extract_take_limit(&kql);
        let truncated = take_limit.is_some_and(|cap| row_count >= cap as usize);

        // Inspect mode: return rows without touching the graph. Default
        // (ingest absent or true) falls through to the ingest path below.
        if req.ingest == Some(false) {
            let cap = req.max_rows.unwrap_or(200) as usize;
            let (rows, total) = cap_kql_rows(&res.data, cap);
            // Use the accurate parsed `total` (not the `{`-heuristic
            // `row_count`) for the LLM-facing truncated flag: true when the
            // KQL `take` saturated OR the display cap dropped rows.
            let take_saturated = take_limit.is_some_and(|t| total >= t as usize);
            let inspect_truncated = take_saturated || total > cap;
            self.emitter_arc().emit(
                "kql-executed",
                serde_json::json!({
                    "kql": kql,
                    "source": "adhoc",
                    "target": "inspect",
                    "row_count": total,
                    "entities_created": 0,
                    "relations_created": 0,
                }),
            );
            let graph_advisory = kql_graph_advisory(&kql);
            return Ok(KqlResult {
                new_entities: 0,
                new_relations: 0,
                total_entities: 0,
                total_relations: 0,
                kql_executed: kql,
                row_count: total,
                took_ms,
                take_limit,
                truncated: inspect_truncated,
                rows: Some(rows),
                graph_advisory,
                // Acknowledged-fallback inspect still surfaces the graph path.
                graph_propose: propose_payload,
                fallback_gated: false,
            });
        }

        let session = self.sessions().current_session().ok_or_else(|| {
            ApiError::InvalidState("No current session. Create or load a session first.".into())
        })?;

        // Register a dataset for audit. A supplied `dataset` name is a
        // stable layer (enables snapshot replace); otherwise a random id
        // (one-off append, legacy behavior).
        let dataset_id = match &req.dataset {
            Some(name) => name.clone(),
            None => Uuid::new_v4().to_string(),
        };
        {
            let mut datasets = session
                .datasets
                .write()
                .map_err(|e| ApiError::Internal(format!("datasets lock poisoned: {e}")))?;
            // Snapshot replace: drop any prior audit entry for this named
            // layer so refreshing a layer doesn't accumulate duplicates.
            if req.dataset.is_some() {
                datasets.retain(|d| d.id != dataset_id);
            }
            datasets.push(DatasetInfo {
                id: dataset_id.clone(),
                name: format!("KQL: {}", if kql.len() > 40 { &kql[..40] } else { &kql }),
                path: None,
                created_at: now_secs(),
                entity_count: 0,
                relation_count: 0,
                field_config: None,
                ingest_stats: None,
            });
        }

        // Parse + ingest + score.
        let (new_entities, new_relations) = {
            let mut graph = session
                .graph
                .write()
                .map_err(|e| ApiError::Internal(format!("graph lock poisoned: {e}")))?;
            // Snapshot replace: refresh a named layer instead of appending.
            if req.dataset.is_some() {
                graph
                    .remove_entities_and_relations_by_dataset(&dataset_id)
                    .map_err(|e| ApiError::Internal(e.to_string()))?;
            }
            let parser = make_parser_for_format("sentinel").map_err(ApiError::InvalidInput)?;
            let triples = parser.parse(&res.data);
            let (e, r) = graph
                .insert_triples(triples, Some(dataset_id.as_str()))
                .map_err(|e| ApiError::Internal(e.to_string()))?;
            run_full_scoring(&mut graph);
            (e, r)
        };

        // Patch dataset counts.
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

        // Emit audit event.
        self.emitter_arc().emit(
            "kql-executed",
            serde_json::json!({
                "kql": kql,
                "source": "adhoc",
                "target": "custom",
                "row_count": row_count,
                "entities_created": new_entities,
                "relations_created": new_relations,
            }),
        );

        Ok(KqlResult {
            new_entities,
            new_relations,
            total_entities,
            total_relations,
            kql_executed: kql,
            row_count,
            took_ms,
            take_limit,
            truncated,
            rows: None,
            // No advisory/gate on the ingest path — the data is already in the
            // graph, which is exactly the behavior the gate steers toward.
            graph_advisory: None,
            graph_propose: None,
            fallback_gated: false,
        })
    }

    /// Discover the active Sentinel tables and classify each table's fields
    /// for graph construction. Two-stage: (1) the `Usage` table gives the
    /// active tables + billable ingestion in the window (cheap, no `union *`);
    /// (2) for the most-ingested tables, a small `take N` sample feeds the
    /// shared field classifier, annotated with `graph_affinity` + `enrichable`.
    ///
    /// Read-only — never touches the session graph. The intended Phase 1
    /// "what's in this workspace, what's worth building?" call.
    pub async fn discover_schema(
        &self,
        req: SchemaDiscoverRequest,
    ) -> ApiResult<SchemaDiscoverResult> {
        let workspace_id = env_or(&req.workspace_id, "AZURE_WORKSPACE_ID")?;
        let tenant_id = env_or(&req.azure_tenant_id, "AZURE_TENANT_ID")?;
        let client_id = env_or(&req.azure_client_id, "AZURE_CLIENT_ID")?;
        let client_secret = env_or(&req.azure_client_secret, "AZURE_CLIENT_SECRET")?;
        let auth = SentinelAuth { tenant_id, client_id, client_secret };

        let time_filter = req
            .time_window
            .as_ref()
            .map(|w| w.kql_filter())
            .unwrap_or_else(|| "where TimeGenerated > ago(24h)".to_string());
        let min_mb = req.min_ingestion_mb.unwrap_or(0.0);
        let max_tables = req.max_tables.unwrap_or(25) as usize;
        let sample_rows = req.sample_rows.unwrap_or(200).clamp(1, 1000);

        let started = std::time::Instant::now();
        let mut cost = CostAccumulator::default();

        // Stage 1: active tables + ingestion volume from the Usage table.
        let usage_kql = format!(
            "Usage | {time_filter} | summarize IngestionMB = sum(Quantity), \
             LastIngested = max(TimeGenerated) by DataType | where IngestionMB >= {min_mb} \
             | order by IngestionMB desc"
        );
        let (usage_rows, usage_stats) = run_kql_rows(&workspace_id, usage_kql, auth.clone()).await?;
        cost.add(&usage_stats);

        // Apply the (case-insensitive) table filter.
        let mut discovered: Vec<(String, Option<f64>, Option<String>)> = usage_rows
            .iter()
            .filter_map(|row| {
                let name = row.get("DataType").and_then(|v| v.as_str())?.to_string();
                if !req.table_filter.is_empty()
                    && !req.table_filter.iter().any(|t| t.eq_ignore_ascii_case(&name))
                {
                    return None;
                }
                let mb = row.get("IngestionMB").and_then(|v| v.as_f64());
                let last = row
                    .get("LastIngested")
                    .and_then(|v| v.as_str())
                    .map(str::to_string);
                Some((name, mb, last))
            })
            .collect();

        let total_tables = discovered.len();
        let note = (total_tables > max_tables).then(|| {
            format!(
                "Introspected the top {max_tables} of {total_tables} tables by ingestion. \
                 Raise max_tables or pass table_filter to inspect the rest."
            )
        });
        discovered.truncate(max_tables);

        // Stage 2: sample + classify each selected table.
        let mut tables = Vec::with_capacity(discovered.len());
        for (name, ingestion_24h_mb, last_ingested) in discovered {
            let sample_kql = format!("{name} | {time_filter} | take {sample_rows}");
            // A single table's sample failing (e.g. a deprecated column) must
            // not abort the whole discovery — degrade to an empty field list.
            let (rows, sample_stats) = run_kql_rows(&workspace_id, sample_kql, auth.clone())
                .await
                .unwrap_or_default();
            cost.add(&sample_stats);
            tables.push(SchemaTable {
                name,
                ingestion_24h_mb,
                last_ingested,
                fields: classify_table_fields(&rows),
            });
        }

        let cost = cost.finish(started.elapsed().as_millis() as u64);
        Ok(SchemaDiscoverResult { tables, total_tables, note, cost })
    }

    /// Phase 2 / MAPPING (§4.2): from analyst-selected `{table, field}` pairs,
    /// emit candidate graph schemas — nodes, edges, and the exact
    /// `materialization_kql` `graph_build` will run. Proposals are persisted in
    /// the session (keyed by `proposal_id`) so `graph_build` can retrieve one by
    /// id. `estimated_entities/relations` are a best-effort probe: when Azure
    /// creds resolve, one cheap `summarize` per table; otherwise omitted.
    /// Proposal generation itself is offline (no SIEM round-trip required).
    pub async fn graph_propose(&self, req: GraphProposeRequest) -> ApiResult<GraphProposeResult> {
        if req.selected_fields.is_empty() {
            return Err(ApiError::InvalidInput(
                "selected_fields is empty — pick fields from schema_discover first".into(),
            ));
        }
        let time_filter = req
            .time_window
            .as_ref()
            .map(|w| w.kql_filter())
            .unwrap_or_else(|| "where TimeGenerated > ago(24h)".to_string());
        let max_proposals = req.max_proposals.unwrap_or(3).max(1) as usize;

        let mut proposals =
            build_proposals(&req.selected_fields, req.hypothesis_context.as_deref(), &time_filter);
        proposals.truncate(max_proposals);

        // Best-effort estimate probe: one `summarize` per proposal when creds
        // resolve. Failures degrade to `None` estimates — never abort propose.
        let mut cost = CostAccumulator::default();
        let started = std::time::Instant::now();
        let creds = explicit_or_env_creds(
            &req.workspace_id,
            &req.azure_tenant_id,
            &req.azure_client_id,
            &req.azure_client_secret,
        );
        if let Some((ws, auth)) = creds {
            for p in &mut proposals {
                if let Some(probe_kql) = estimate_probe_kql(p) {
                    if let Ok((rows, stats)) =
                        run_kql_rows(&ws, probe_kql, auth.clone()).await
                    {
                        cost.add(&stats);
                        if let Some(row) = rows.first() {
                            p.estimated_relations =
                                row.get("Rows").and_then(|v| v.as_u64());
                            p.estimated_entities =
                                row.get("Entities").and_then(|v| v.as_u64());
                        }
                    }
                }
            }
        }
        let cost = cost.finish(started.elapsed().as_millis() as u64);

        // Persist for graph_build. Auto-create a session if none is current so
        // the discover→propose→build cycle works from a cold start.
        if !proposals.is_empty() {
            if self.sessions().current_session().is_none() {
                self.create_session(crate::dto::session::CreateSessionRequest {
                    name: Some("Graph Propose".into()),
                })?;
            }
            if let Some(session) = self.sessions().current_session() {
                let mut store = session
                    .proposals
                    .write()
                    .map_err(|e| ApiError::Internal(format!("proposals lock poisoned: {e}")))?;
                for p in &proposals {
                    store.insert(p.proposal_id.clone(), p.clone());
                }
            }
        }

        Ok(GraphProposeResult { proposals, cost })
    }

    /// Phase 3 / MATERIALIZATION (§4.3): run an approved proposal's
    /// `materialization_kql` against Sentinel, map rows to entities/relations
    /// per the proposal schema, load them into the session graph, and apply
    /// enrichment ONCE (geoip+asn for IP nodes; threat_intel is a stub).
    /// `merge_mode=replace` refreshes this proposal's prior build (snapshot);
    /// `append` (default) adds a fresh layer. Records `last_build` for §5 status.
    pub async fn graph_build(&self, req: GraphBuildRequest) -> ApiResult<GraphBuildResult> {
        let started = std::time::Instant::now();

        let session = self.sessions().current_session().ok_or_else(|| {
            ApiError::InvalidState("No current session. Run graph_propose first.".into())
        })?;
        let proposal = {
            let store = session
                .proposals
                .read()
                .map_err(|e| ApiError::Internal(format!("proposals lock poisoned: {e}")))?;
            store.get(&req.proposal_id).cloned().ok_or_else(|| {
                ApiError::InvalidInput(format!(
                    "unknown proposal_id '{}' — run graph_propose first",
                    req.proposal_id
                ))
            })?
        };

        let workspace_id = env_or(&req.workspace_id, "AZURE_WORKSPACE_ID")?;
        let tenant_id = env_or(&req.azure_tenant_id, "AZURE_TENANT_ID")?;
        let client_id = env_or(&req.azure_client_id, "AZURE_CLIENT_ID")?;
        let client_secret = env_or(&req.azure_client_secret, "AZURE_CLIENT_SECRET")?;
        let auth = SentinelAuth { tenant_id, client_id, client_secret };

        // The stored KQL already filters TimeGenerated; soft-sugar is a no-op
        // unless that filter is somehow absent (explicit always wins).
        let kql = apply_time_window_sugar(&proposal.materialization_kql, req.time_window.as_ref());

        let mut cost = CostAccumulator::default();
        let (rows, stats) = run_kql_rows(&workspace_id, kql, auth.clone()).await?;
        cost.add(&stats);

        let mapped = map_rows_to_graph(&proposal, &rows);

        let merge_mode = req.merge_mode.as_deref().unwrap_or("append").to_ascii_lowercase();
        let replace = merge_mode == "replace";
        let build_id = format!("build-{}", &Uuid::new_v4().to_string()[..8]);
        let dataset_id = if replace {
            format!("graph-build:{}", proposal.proposal_id)
        } else {
            format!("graph-build:{build_id}")
        };

        // Register the dataset for audit (snapshot-replace drops the prior one).
        {
            let mut datasets = session
                .datasets
                .write()
                .map_err(|e| ApiError::Internal(format!("datasets lock poisoned: {e}")))?;
            if replace {
                datasets.retain(|d| d.id != dataset_id);
            }
            datasets.push(DatasetInfo {
                id: dataset_id.clone(),
                name: format!("Graph Build: {}", proposal.proposal_id),
                path: None,
                created_at: now_secs(),
                entity_count: 0,
                relation_count: 0,
                field_config: None,
                ingest_stats: None,
            });
        }

        let (entities_created, relations_created) = {
            let mut graph = session
                .graph
                .write()
                .map_err(|e| ApiError::Internal(format!("graph lock poisoned: {e}")))?;
            if replace {
                graph
                    .remove_entities_and_relations_by_dataset(&dataset_id)
                    .map_err(|e| ApiError::Internal(e.to_string()))?;
            }
            // Lone nodes (edge-less proposals) are inserted directly.
            let mut standalone_count = 0usize;
            for mut e in mapped.standalone {
                e.dataset_id = Some(dataset_id.as_str().into());
                if graph.add_entity(e).is_ok() {
                    standalone_count += 1;
                }
            }
            let (ec, rc) = graph
                .insert_triples(mapped.triples, Some(dataset_id.as_str()))
                .map_err(|e| ApiError::Internal(e.to_string()))?;
            run_scoring_adaptive(&mut graph);
            (ec + standalone_count, rc)
        };

        // Patch dataset counts.
        {
            let mut datasets = session
                .datasets
                .write()
                .map_err(|e| ApiError::Internal(format!("datasets lock poisoned: {e}")))?;
            if let Some(d) = datasets.iter_mut().find(|d| d.id == dataset_id) {
                d.entity_count = entities_created;
                d.relation_count = relations_created;
            }
        }

        // Enrichment ONCE, at build (design principle §2): resolve geoip+asn for
        // the IP nodes and store on entity metadata. threat_intel is a stub.
        let want = |name: &str| {
            req.enrich
                .as_ref()
                .map_or(true, |e| e.iter().any(|x| x.eq_ignore_ascii_case(name)))
        };
        let mut enrichment_applied = EnrichmentApplied::default();
        if want("geoip") || want("asn") {
            for ip in &mapped.ip_values {
                if let Ok(res) = self
                    .enrich_ip(crate::dto::geoip::EnrichIpRequest { session: None, ip: ip.clone() })
                    .await
                {
                    if res.country_code.is_some() || res.city.is_some() {
                        enrichment_applied.geoip += 1;
                    }
                    if res.asn.is_some() {
                        enrichment_applied.asn += 1;
                    }
                }
            }
        }

        let (total_entities, total_relations) = {
            let graph = session
                .graph
                .read()
                .map_err(|e| ApiError::Internal(format!("graph lock poisoned: {e}")))?;
            (graph.entity_count(), graph.relation_count())
        };
        let (graph_state, _) =
            crate::dto::geoip::GraphState::classify(total_entities, total_relations);

        // Record last_build for §5 status.
        let at = now_secs();
        if let Ok(mut slot) = session.last_build.write() {
            *slot = Some(BuildRecord {
                build_id: build_id.clone(),
                proposal_id: proposal.proposal_id.clone(),
                at,
                entities_created,
                relations_created,
                merge_mode: merge_mode.clone(),
            });
        }

        let duration_ms = started.elapsed().as_millis() as u64;
        let cost = cost.finish(duration_ms);
        Ok(GraphBuildResult {
            build_id,
            proposal_id: proposal.proposal_id,
            entities_created,
            relations_created,
            enrichment_applied,
            duration_ms,
            graph_state,
            cost,
        })
    }

    /// Phase M: run a pre-built hunting KQL template against Sentinel.
    /// The KQL is rendered from `template` + the analyst's chosen
    /// `time_window`, then dispatched through the same `run_kql` path
    /// so result handling (ingest + scoring + dataset row + emit)
    /// stays in one place.
    pub async fn run_hunting_template(
        &self,
        req: RunHuntingTemplateRequest,
    ) -> ApiResult<KqlResult> {
        let template = req
            .template
            .ok_or_else(|| ApiError::InvalidInput("template is required".into()))?;
        let window = req
            .time_window
            .clone()
            .unwrap_or(TimeWindow::Preset {
                lookback: crate::dto::sentinel::LookbackPreset::H24,
            });
        let kql = render_hunting_template(template, &window);
        // Setting `time_window: None` here so `run_kql`'s soft-sugar
        // step doesn't double-prepend a filter onto the rendered
        // template (which already contains the analyst's window).
        self.run_kql(RunKqlRequest {
            kql,
            workspace_id: req.workspace_id,
            azure_tenant_id: req.azure_tenant_id,
            azure_client_id: req.azure_client_id,
            azure_client_secret: req.azure_client_secret,
            time_window: None,
            ingest: None,
            max_rows: None,
            dataset: None,
            acknowledge_fallback: None,
        })
        .await
    }

    /// Hydrate a single node from Sentinel: for each (table, columns)
    /// where its type can appear, run an entity-scoped KQL, parse, and
    /// ingest into the current session graph. Generic over transport for
    /// mockability; the live-expand path builds the real HTTP transport.
    ///
    /// Delegates to [`Self::hydrate_node_filtered_with`] with no filter,
    /// preserving the exact prior behavior.
    #[allow(clippy::too_many_arguments)]
    pub async fn hydrate_node_with<T: SentinelTransport>(
        &self,
        transport: &T,
        token_cache: &SentinelTokenCache,
        value: &str,
        entity_type: &EntityType,
        time_filter: &str,
        workspace_id: &str,
        auth: &SentinelAuth,
        dataset_tag: &str,
    ) -> ApiResult<graph_hunter_core::analytics::HydrationOutcome> {
        self.hydrate_node_filtered_with(
            transport, token_cache, value, entity_type, time_filter, workspace_id, auth,
            dataset_tag, None,
        )
        .await
    }

    /// Node hydration with an optional [`HydrationFilter`] that narrows
    /// the tables queried and caps rows per table. `filter = None` is
    /// identical to the unfiltered path.
    #[allow(clippy::too_many_arguments)]
    pub async fn hydrate_node_filtered_with<T: SentinelTransport>(
        &self,
        transport: &T,
        token_cache: &SentinelTokenCache,
        value: &str,
        entity_type: &EntityType,
        time_filter: &str,
        workspace_id: &str,
        auth: &SentinelAuth,
        dataset_tag: &str,
        filter: Option<&HydrationFilter>,
    ) -> ApiResult<graph_hunter_core::analytics::HydrationOutcome> {
        use graph_hunter_core::analytics::HydrationOutcome;

        let all_targets = sentinel_entity_targets(entity_type);
        if all_targets.is_empty() {
            return Ok(HydrationOutcome {
                skipped: true,
                reason: Some(format!("no Sentinel column mapping for type {entity_type}")),
                new_entities: 0,
                new_relations: 0,
                tables_hit: 0,
                tables_attempted: 0,
            });
        }

        // Apply the table filter (case-insensitive). Requested tables that
        // aren't mapped for this type are simply not queried (no error).
        let requested: Option<Vec<String>> = filter.and_then(|f| f.tables.clone());
        let targets: Vec<(&'static str, &'static [&'static str])> = all_targets
            .iter()
            .copied()
            .filter(|(table, _)| match &requested {
                Some(list) => list.iter().any(|t| t.eq_ignore_ascii_case(table)),
                None => true,
            })
            .collect();

        // When a non-empty `tables` filter excludes all mapped tables for this
        // type, return early so callers can distinguish "skipped by filter"
        // from "queried but found nothing".
        if targets.is_empty() {
            return Ok(HydrationOutcome {
                skipped: true,
                reason: Some(format!(
                    "none of the requested tables are mapped for type {entity_type}"
                )),
                new_entities: 0,
                new_relations: 0,
                tables_hit: 0,
                tables_attempted: 0,
            });
        }

        const HYDRATION_TAKE: u32 = 5000;
        let take: u32 = filter.and_then(|f| f.max_rows).unwrap_or(HYDRATION_TAKE);

        let token = token_cache
            .get_or_refresh(transport, auth)
            .await
            .map_err(|e| ApiError::Upstream {
                service: "sentinel-auth".into(),
                message: e,
            })?;

        let parser = make_parser_for_format("sentinel").map_err(ApiError::InvalidInput)?;
        let session = self
            .sessions()
            .current_session()
            .ok_or_else(|| ApiError::InvalidState("No current session.".into()))?;

        let mut tables_hit = 0usize;
        let mut new_e = 0usize;
        let mut new_r = 0usize;
        let tables_attempted = targets.len();

        for (table, columns) in &targets {
            let kql = build_hydration_kql(table, columns, value, time_filter, take);
            match transport.execute_query(workspace_id, &kql, &token).await {
                Ok(raw) => match normalize_response(&raw) {
                    // `normalize_response` serializes rows as a JSON array, so the
                    // empty case is exactly "[]" (never ""). Skip those; the
                    // `triples.is_empty()` guard below covers rows-that-don't-parse.
                    Ok(result) if result.data != "[]" => {
                        let triples = parser.parse(&result.data);
                        if !triples.is_empty() {
                            match session.graph.write() {
                                Ok(mut graph) => match graph.insert_triples(triples, Some(dataset_tag)) {
                                    Ok((e, r)) => {
                                        new_e += e;
                                        new_r += r;
                                        tables_hit += 1;
                                    }
                                    Err(e) => tracing::warn!("hydration insert {table}: {e}"),
                                },
                                Err(e) => tracing::warn!("hydration graph lock poisoned {table}: {e}"),
                            }
                        }
                    }
                    Ok(_) => {}
                    Err(e) => tracing::warn!("hydration normalize {table}: {e}"),
                },
                Err(e) => tracing::warn!("hydration query {table}: {e}"),
            }
        }

        if new_e > 0 || new_r > 0 {
            if let Ok(mut graph) = session.graph.write() {
                run_scoring_incremental(&mut graph);
            }
        }

        Ok(HydrationOutcome {
            skipped: false,
            reason: None,
            new_entities: new_e,
            new_relations: new_r,
            tables_hit,
            tables_attempted,
        })
    }

    /// Build a SeedResult from a (possibly skipped) hydration outcome:
    /// expands the seeded node's neighborhood and ranks its top anomalies.
    fn build_seed_result(
        &self,
        value: &str,
        hydration: graph_hunter_core::analytics::HydrationOutcome,
    ) -> ApiResult<SeedResult> {
        let neighborhood = self.seeded_neighborhood(value)?;
        let top_anomalies = Self::rank_top_anomalies(&neighborhood, 5);
        Ok(SeedResult { hydration, neighborhood, top_anomalies })
    }

    /// Generic seed engine (mockable). Assumes the entity type is valid
    /// and a session is current. Hydrates the IoC, expands its node, and
    /// ranks the neighborhood by anomaly score.
    #[allow(clippy::too_many_arguments)]
    pub async fn seed_from_ioc_with<T: SentinelTransport>(
        &self,
        transport: &T,
        token_cache: &SentinelTokenCache,
        value: &str,
        entity_type: &EntityType,
        time_filter: &str,
        workspace_id: &str,
        auth: &SentinelAuth,
    ) -> ApiResult<SeedResult> {
        let hydration = self
            .hydrate_node_with(
                transport,
                token_cache,
                value,
                entity_type,
                time_filter,
                workspace_id,
                auth,
                "Sentinel Seed",
            )
            .await?;
        self.build_seed_result(value, hydration)
    }

    /// Public cold-start entry: validate type → ensure session →
    /// resolve creds (skip if absent) → hydrate+expand+rank.
    pub async fn seed_from_ioc(&self, req: SeedFromIocRequest) -> ApiResult<SeedResult> {
        use graph_hunter_core::analytics::HydrationOutcome;

        let ty = parse_entity_type(&req.entity_type)
            .filter(|t| !sentinel_entity_targets(t).is_empty())
            .ok_or_else(|| {
                ApiError::InvalidInput(format!(
                    "entity_type must be one of IP, User, Host, Process, File (got '{}')",
                    req.entity_type
                ))
            })?;

        if self.sessions().current_session().is_none() {
            self.create_session(crate::dto::session::CreateSessionRequest {
                name: Some(format!("Sentinel Seed: {}", req.value)),
            })?;
        }

        let time_filter = req
            .time_window
            .as_ref()
            .map(|w| w.kql_filter())
            .unwrap_or_else(|| "where TimeGenerated > ago(24h)".to_string());

        let result = match resolve_azure_creds() {
            Some((ws, auth)) => {
                let transport = HttpSentinelTransport::new();
                let cache = SentinelTokenCache::new();
                self.seed_from_ioc_with(&transport, &cache, &req.value, &ty, &time_filter, &ws, &auth)
                    .await
            }
            None => self.build_seed_result(&req.value, HydrationOutcome {
                skipped: true,
                reason: Some("Azure credentials not configured (set AZURE_* or connect Sentinel)".into()),
                new_entities: 0,
                new_relations: 0,
                tables_hit: 0,
                tables_attempted: 0,
            }),
        };

        // Record the pivot intent regardless of hydration outcome: even the
        // creds-skipped branch returns Ok, and the user expressed intent to
        // pivot on this entity. The MCP graph://recent-pivots resource uses
        // this to surface "unexpanded pivot, consider node_expand" nudges.
        if result.is_ok() {
            crate::operations::graph_meta::RECENT_PIVOTS.push(
                crate::dto::v1::graph_meta::RecentPivot {
                    entity: req.value.clone(),
                    kind: ty.to_string(),
                    added_at: chrono::Utc::now().to_rfc3339(),
                    expanded: false,
                    degree: 0,
                },
            );
        }
        result
    }

    /// Enrich an existing node by pulling a chosen slice of its Sentinel
    /// events into the current session graph. Returns the
    /// `HydrationOutcome` describing what was added.
    pub async fn node_enrich(
        &self,
        req: NodeEnrichRequest,
    ) -> ApiResult<graph_hunter_core::analytics::HydrationOutcome> {
        use graph_hunter_core::analytics::HydrationOutcome;

        let session = self.sessions().current_session().ok_or_else(|| {
            ApiError::InvalidState("No current session. Seed or load a session first.".into())
        })?;

        // Resolve the node's entity type from the graph.
        let entity_type = {
            let graph = session
                .graph
                .read()
                .map_err(|e| ApiError::Internal(format!("graph lock poisoned: {e}")))?;
            graph
                .get_entity(&req.node_id)
                .map(|e| e.entity_type.clone())
                .ok_or_else(|| {
                    ApiError::InvalidInput(format!(
                        "node '{}' not found in the current session graph",
                        req.node_id
                    ))
                })?
        };

        if sentinel_entity_targets(&entity_type).is_empty() {
            return Ok(HydrationOutcome {
                skipped: true,
                reason: Some(format!(
                    "node type {entity_type} has no Sentinel table mapping; nothing to enrich"
                )),
                new_entities: 0,
                new_relations: 0,
                tables_hit: 0,
                tables_attempted: 0,
            });
        }

        let time_filter = req
            .time_window
            .as_ref()
            .map(|w| w.kql_filter())
            .unwrap_or_else(|| "where TimeGenerated > ago(24h)".to_string());

        // On-demand enrichment is intentionally bounded to 1000 rows/table
        // by default (seed/full hydration default is 5000).
        let filter = HydrationFilter {
            tables: req.tables,
            max_rows: req.max_rows.or(Some(1000)),
        };

        // Snapshot replace: a named layer is refreshed (remove then insert);
        // omitted -> the default append tag (legacy behavior).
        let dataset_tag = req.dataset.as_deref().unwrap_or("Sentinel Enrich (node)");
        {
            if req.dataset.is_some() {
                let mut graph = session
                    .graph
                    .write()
                    .map_err(|e| ApiError::Internal(format!("graph lock poisoned: {e}")))?;
                graph
                    .remove_entities_and_relations_by_dataset(dataset_tag)
                    .map_err(|e| ApiError::Internal(e.to_string()))?;
            }
        } // write guard dropped here, before any .await

        match resolve_azure_creds() {
            Some((ws, auth)) => {
                let transport = HttpSentinelTransport::new();
                let cache = SentinelTokenCache::new();
                self.hydrate_node_filtered_with(
                    &transport,
                    &cache,
                    &req.node_id,
                    &entity_type,
                    &time_filter,
                    &ws,
                    &auth,
                    dataset_tag,
                    Some(&filter),
                )
                .await
            }
            None => Ok(HydrationOutcome {
                skipped: true,
                reason: Some(
                    "Azure credentials not configured (set AZURE_* or connect Sentinel)".into(),
                ),
                new_entities: 0,
                new_relations: 0,
                tables_hit: 0,
                tables_attempted: 0,
            }),
        }
    }

    /// Build the neighborhood of the seeded node, or an empty centered
    /// neighborhood if the node was not created (empty/failed hydration).
    fn seeded_neighborhood(
        &self,
        value: &str,
    ) -> ApiResult<graph_hunter_core::analytics::Neighborhood> {
        let exists = {
            let session = self
                .sessions()
                .current_session()
                .ok_or_else(|| ApiError::InvalidState("no session".into()))?;
            let g = session
                .graph
                .read()
                .map_err(|e| ApiError::Internal(format!("graph lock poisoned: {e}")))?;
            g.get_entity(value).is_some()
        };
        if exists {
            self.expand_node(crate::dto::graph_ops::ExpandNodeRequest {
                session: None,
                node_id: value.to_string(),
                max_hops: Some(1),
                max_nodes: Some(50),
                filter: None,
                live: false,
                time_window: None,
            })
        } else {
            Ok(graph_hunter_core::analytics::Neighborhood {
                center: value.to_string(),
                nodes: vec![],
                edges: vec![],
                truncated: false,
                auto_grouped: false,
                auto_group_reason: None,
                hydration: None,
            })
        }
    }

    fn rank_top_anomalies(
        hood: &graph_hunter_core::analytics::Neighborhood,
        n: usize,
    ) -> Vec<graph_hunter_core::analytics::NeighborNode> {
        let mut nodes = hood.nodes.clone();
        nodes.sort_by(|a, b| {
            b.score
                .partial_cmp(&a.score)
                .unwrap_or(std::cmp::Ordering::Equal)
        });
        nodes.truncate(n);
        nodes
    }

    /// Resume (start) the paused polling loop. No-op if already running.
    /// Errors if no connector is registered.
    pub fn sentinel_resume(&self) -> ApiResult<()> {
        {
            let handle_slot = self.sentinel_connector_handle();
            let guard = handle_slot
                .read()
                .map_err(|e| ApiError::Internal(format!("sentinel lock poisoned: {e}")))?;
            let h = guard.as_ref().ok_or_else(|| {
                ApiError::InvalidState("No Sentinel connector is running. Connect first.".into())
            })?;
            let _ = h.pause_tx.send(false);
        }
        // Live ingest is starting: mark the session LiveTail so hunts are
        // not 409-blocked while polling.
        if let Some(session) = self.sessions().current_session() {
            session.set_phase(crate::state::SessionPhase::LiveTail);
        }
        self.emitter_arc().emit(
            event_names::SENTINEL_STATUS,
            serde_json::json!({"resumed": true}),
        );
        Ok(())
    }

    /// Pause the polling loop (stop querying; keep the connector). No-op
    /// if already paused. Errors if no connector is registered.
    pub fn sentinel_pause(&self) -> ApiResult<()> {
        {
            let handle_slot = self.sentinel_connector_handle();
            let guard = handle_slot
                .read()
                .map_err(|e| ApiError::Internal(format!("sentinel lock poisoned: {e}")))?;
            let h = guard.as_ref().ok_or_else(|| {
                ApiError::InvalidState("No Sentinel connector is running. Connect first.".into())
            })?;
            let _ = h.pause_tx.send(true);
        }
        // Polling stopped: no live ingest, so the session is huntable again.
        if let Some(session) = self.sessions().current_session() {
            session.set_phase(crate::state::SessionPhase::Ready);
        }
        self.emitter_arc().emit(
            event_names::SENTINEL_STATUS,
            serde_json::json!({"paused": true}),
        );
        Ok(())
    }
}

/// Parse a normalized KQL response (a JSON array of row objects) and
/// return at most `max_rows` rows together with the pre-truncation total.
/// Non-array or malformed input yields `(vec![], 0)` rather than erroring
/// — inspect mode is best-effort.
fn cap_kql_rows(data: &str, max_rows: usize) -> (Vec<serde_json::Value>, usize) {
    match serde_json::from_str::<Vec<serde_json::Value>>(data) {
        Ok(mut rows) => {
            let total = rows.len();
            rows.truncate(max_rows);
            (rows, total)
        }
        Err(_) => (Vec::new(), 0),
    }
}

/// Phase L: prepend `where TimeGenerated > ...` to the analyst's
/// KQL when (a) the form supplied a time window AND (b) the query
/// doesn't already have a `TimeGenerated` filter. Idempotent — calling
/// it twice with the same window leaves the second call's output
/// unchanged.
fn apply_time_window_sugar(kql: &str, window: Option<&TimeWindow>) -> String {
    let Some(window) = window else {
        return kql.to_string();
    };
    if kql.contains("TimeGenerated") {
        return kql.to_string();
    }
    // Splice the filter as a fresh stage right after the table
    // reference. KQL pipelines are `Table | step | step | ...`, so
    // inserting `| where TimeGenerated ...` after the first segment
    // keeps the rest of the user's pipeline intact.
    let trimmed = kql.trim();
    if let Some((head, tail)) = trimmed.split_once('|') {
        format!("{} | {} | {}", head.trim_end(), window.kql_filter(), tail.trim_start())
    } else {
        format!("{} | {}", trimmed, window.kql_filter())
    }
}

/// Phase N: pull the `take N` clause out of the rendered KQL so the
/// frontend can warn when row count saturates the cap. Conservative
/// regex — matches `take 1234` (case-sensitive, KQL convention) and
/// returns the largest such value, since some templates have multiple
/// `take` stages and the last one is the actual ceiling.
fn extract_take_limit(kql: &str) -> Option<u32> {
    let mut last: Option<u32> = None;
    let mut iter = kql.char_indices().peekable();
    while let Some((i, _)) = iter.next() {
        let rest = &kql[i..];
        let stripped = rest.trim_start();
        if let Some(after_take) = stripped.strip_prefix("take ") {
            let n: String = after_take
                .chars()
                .take_while(|c| c.is_ascii_digit())
                .collect();
            if let Ok(n) = n.parse::<u32>() {
                last = Some(n);
            }
        }
    }
    last
}

/// Run one KQL query against Log Analytics and return the rows as parsed JSON
/// objects plus the query cost. `run_sentinel_query` already normalizes the
/// response to a JSON array of row objects (the same shape `cap_kql_rows`
/// consumes), so a non-array / malformed body degrades to an empty vec rather
/// than erroring.
async fn run_kql_rows(
    workspace_id: &str,
    kql: String,
    auth: SentinelAuth,
) -> ApiResult<(Vec<serde_json::Value>, Option<QueryStats>)> {
    let ws = workspace_id.to_string();
    let res = tokio::task::spawn_blocking(move || run_sentinel_query(&ws, &kql, Some(auth)))
        .await
        .map_err(|e| ApiError::Internal(format!("task join error: {e}")))?
        .map_err(|e| ApiError::Upstream { service: "sentinel-kql".into(), message: e })?;
    let rows = serde_json::from_str::<Vec<serde_json::Value>>(&res.data).unwrap_or_default();
    Ok((rows, res.stats))
}

/// Accumulates Sentinel query cost across the multiple round-trips a single
/// tool call makes (e.g. discovery's usage probe + per-table samples).
#[derive(Default)]
struct CostAccumulator {
    bytes_scanned: u64,
    server_duration_ms: u64,
    /// True once any query reported a `statistics` object — distinguishes
    /// "no cost" from "cost not reported".
    saw_stats: bool,
}

impl CostAccumulator {
    fn add(&mut self, stats: &Option<QueryStats>) {
        if let Some(s) = stats {
            self.saw_stats = true;
            if let Some(b) = s.bytes_scanned {
                self.bytes_scanned += b;
            }
            if let Some(d) = s.server_duration_ms {
                self.server_duration_ms += d;
            }
        }
    }

    /// Finalize into the serializable DTO. `wall_ms` is the locally-measured
    /// total round-trip time. Returns `None` only when no stats were seen AND
    /// no wall time elapsed (degenerate / no queries ran).
    fn finish(self, wall_ms: u64) -> Option<crate::dto::sentinel::QueryCost> {
        if !self.saw_stats && wall_ms == 0 {
            return None;
        }
        Some(crate::dto::sentinel::QueryCost {
            bytes_scanned: self.saw_stats.then_some(self.bytes_scanned),
            server_duration_ms: self.saw_stats.then_some(self.server_duration_ms),
            wall_ms,
        })
    }
}

/// Node-affinity entity classes — fields resolving to one of these become
/// graph nodes; everything else is an attribute. Mirrors the seedable/graph
/// entity types the SentinelJsonParser produces.
fn is_node_class(class: &str) -> bool {
    matches!(
        class,
        "IP" | "User" | "Host" | "Process" | "File" | "Domain" | "URL" | "Registry" | "Service"
    )
}

/// Enrichments that *apply to* a given node class (design doc §4.1). IP nodes
/// advertise geoip+asn+threat_intel. Note this is the applicability hint shown
/// in discovery — at build time geoip/asn are real while threat_intel is an
/// honest stub (no feed wired yet), reflected in graph_build's
/// `enrichment_applied` and the `capabilities` flag.
fn enrichable_for(class: &str) -> Vec<String> {
    match class {
        "IP" => vec!["geoip".to_string(), "asn".to_string(), "threat_intel".to_string()],
        _ => Vec::new(),
    }
}

/// Classify the fields of one sampled table for graph construction. Reuses the
/// ingest preview classifier for role/canonical/sample-value detection, then
/// layers on graph_affinity + enrichable + a sample-based cardinality estimate.
fn classify_table_fields(rows: &[serde_json::Value]) -> Vec<SchemaField> {
    use graph_hunter_core::field_preview::{preview_fields_from_events_with_classifier, FieldRole};
    use graph_hunter_core::generic::GenericParser;

    if rows.is_empty() {
        return Vec::new();
    }

    // Independent pass over the rows for full distinct counts + coarse JSON
    // type (the preview only keeps 5 sample values, too few for cardinality).
    let mut stats: std::collections::HashMap<String, (usize, std::collections::HashSet<String>, &'static str)> =
        std::collections::HashMap::new();
    for row in rows {
        if let Some(obj) = row.as_object() {
            for (key, value) in obj {
                let (val_str, ty) = match value {
                    serde_json::Value::String(s) if !s.is_empty() => (s.clone(), "string"),
                    serde_json::Value::Number(n) => (n.to_string(), "number"),
                    serde_json::Value::Bool(b) => (b.to_string(), "bool"),
                    _ => continue,
                };
                let entry = stats.entry(key.clone()).or_insert((0, std::collections::HashSet::new(), ty));
                entry.0 += 1;
                entry.1.insert(val_str);
            }
        }
    }

    let infos = preview_fields_from_events_with_classifier(rows, None);
    infos
        .into_iter()
        .map(|fi| {
            // Prefer the canonical mapping for the node class (UserPrincipalName
            // -> User); fall back to the name/value suggestion.
            let class = fi
                .canonical_target
                .as_deref()
                .map(GenericParser::canonical_to_entity_type)
                .filter(|s| *s != "Skip")
                .map(str::to_string)
                .or_else(|| fi.suggested_entity_type.clone());

            let is_node = matches!(fi.current_role, FieldRole::Node)
                && class.as_deref().map(is_node_class).unwrap_or(false);

            let (graph_affinity, node_class, enrichable) = if is_node {
                let c = class.unwrap();
                let enrich = enrichable_for(&c);
                ("node".to_string(), Some(c), enrich)
            } else {
                ("attribute".to_string(), None, Vec::new())
            };

            let (ty, cardinality) = match stats.get(&fi.raw_name) {
                Some((occ, distinct, ty)) => (ty.to_string(), cardinality_label(distinct.len(), *occ)),
                None => ("string".to_string(), "low".to_string()),
            };

            SchemaField {
                name: fi.raw_name,
                r#type: ty,
                cardinality,
                graph_affinity,
                node_class,
                enrichable,
                sample_values: fi.sample_values,
            }
        })
        .collect()
}

/// Sample-based cardinality label. Mirrors the categorical-label heuristic in
/// `field_preview`: ≤4 distinct values or a distinct/total ratio ≤ 0.25 reads
/// as a low-cardinality attribute (status/severity/result), otherwise high.
fn cardinality_label(distinct: usize, occurrences: usize) -> String {
    let ratio = distinct as f64 / occurrences.max(1) as f64;
    if distinct <= 4 || ratio <= 0.25 {
        "low".to_string()
    } else {
        "high".to_string()
    }
}

// ── graph_propose helpers (§4.2) — pure, unit-testable ─────────────────

/// Resolve Azure creds from explicit request fields, falling back to env per
/// field. Returns `None` (not an error) when any of the four is missing — used
/// by best-effort paths like the graph_propose estimate probe.
fn explicit_or_env_creds(
    ws: &str,
    tenant: &str,
    client: &str,
    secret: &str,
) -> Option<(String, SentinelAuth)> {
    let pick = |explicit: &str, key: &str| -> Option<String> {
        if !explicit.is_empty() {
            Some(explicit.to_string())
        } else {
            std::env::var(key).ok()
        }
    };
    Some((
        pick(ws, "AZURE_WORKSPACE_ID")?,
        SentinelAuth {
            tenant_id: pick(tenant, "AZURE_TENANT_ID")?,
            client_id: pick(client, "AZURE_CLIENT_ID")?,
            client_secret: pick(secret, "AZURE_CLIENT_SECRET")?,
        },
    ))
}

/// Classify a selected field by NAME only (no sample values) into a node class:
/// the canonical alias table first (precise), then a curated name map. `None`
/// means the field should be an edge attribute, not a node.
fn classify_field_name(field: &str) -> Option<String> {
    use graph_hunter_core::generic::GenericParser;
    // Nested dynamic paths (RequestParameters.foo) classify on the leaf.
    let leaf = field.rsplit('.').next().unwrap_or(field);
    if let Some(canon) = GenericParser::canonical_field(leaf) {
        let c = GenericParser::canonical_to_entity_type(canon);
        if c != "Skip" && is_node_class(c) {
            return Some(c.to_string());
        }
    }
    name_to_class(&leaf.to_ascii_lowercase()).map(str::to_string)
}

/// Curated, precise name→class map for graph_propose (name-only, no sample
/// values). Distinct multi-char tokens deliberately avoid the substring traps
/// of the ingest-time heuristic — e.g. "ResultDescription" contains "ip" but is
/// not an IP. Used only after the canonical alias table misses.
fn name_to_class(leaf_lower: &str) -> Option<&'static str> {
    const RULES: &[(&str, &str)] = &[
        // IP
        ("ipaddress", "IP"), ("ipaddr", "IP"), ("remoteip", "IP"), ("sourceip", "IP"),
        ("destinationip", "IP"), ("clientip", "IP"), ("callerip", "IP"), ("publicip", "IP"),
        ("privateip", "IP"),
        // User / identity
        ("userprincipalname", "User"), ("useridentityarn", "User"), ("useridentity", "User"),
        ("username", "User"), ("samaccountname", "User"), ("accountname", "User"),
        ("subjectusername", "User"), ("targetusername", "User"), ("principalid", "User"),
        // Host
        ("hostname", "Host"), ("devicename", "Host"), ("machinename", "Host"),
        ("workstation", "Host"), ("computer", "Host"),
        // Process / file
        ("newprocessname", "Process"), ("parentprocessname", "Process"),
        ("initiatingprocessfilename", "Process"), ("processname", "Process"),
        ("filename", "File"), ("filepath", "File"),
        // Domain / URL
        ("fqdn", "Domain"), ("dnsname", "Domain"), ("domainname", "Domain"),
    ];
    for (needle, class) in RULES {
        if leaf_lower.contains(needle) {
            return Some(class);
        }
    }
    match leaf_lower {
        "ip" => Some("IP"),
        "url" | "uri" => Some("URL"),
        "domain" => Some("Domain"),
        "host" => Some("Host"),
        _ => None,
    }
}

/// Sanitize a field (possibly a `Root.path`) into a valid KQL identifier used
/// as the projected column alias and the suffix of a node `source`.
fn sanitize_alias(field: &str) -> String {
    field
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() { c } else { '_' })
        .collect()
}

/// KQL `project` term for a selected field. Guards missing columns with
/// `columnifexists` (the prior `UserIdentitySessionContext` semantic error) and
/// extracts nested dynamic paths via `parse_json` (AWSCloudTrail
/// RequestParameters / AdditionalEventData). All values coerced to string so
/// node ids are stable.
fn project_expr_for_field(field: &str) -> String {
    let alias = sanitize_alias(field);
    if let Some((root, path)) = field.split_once('.') {
        format!("{alias} = tostring(parse_json(columnifexists(\"{root}\", \"\")).{path})")
    } else {
        format!("{alias} = tostring(columnifexists(\"{field}\", \"\"))")
    }
}

/// Engine `RelationType` name for an edge into `to_class`, so `graph_build` can
/// parse it back. Mirrors the engine's entity→relation defaults.
fn rel_name_for(to_class: &str) -> &'static str {
    match to_class {
        "User" => "Auth",
        "Process" => "Execute",
        "File" => "Write",
        "Domain" => "DNS",
        "Registry" => "Modify",
        _ => "Connect", // IP, Host, URL, Service, …
    }
}

fn slugify(s: &str) -> String {
    s.chars()
        .map(|c| if c.is_ascii_alphanumeric() { c.to_ascii_lowercase() } else { '-' })
        .collect::<String>()
        .split('-')
        .filter(|p| !p.is_empty())
        .collect::<Vec<_>>()
        .join("-")
}

/// Pick the anchor node (the `from` side of every edge) by class priority,
/// falling back to the first node.
fn pick_anchor(nodes: &[(String, String)]) -> usize {
    const PRIORITY: &[&str] = &["User", "Host", "IP", "Process", "Domain", "URL", "File"];
    for want in PRIORITY {
        if let Some(i) = nodes.iter().position(|(_, c)| c == want) {
            return i;
        }
    }
    0
}

/// Ensure proposal ids are unique (append an index on collision).
fn dedupe_ids(proposals: &mut [GraphProposal]) {
    let mut seen: std::collections::HashMap<String, usize> = std::collections::HashMap::new();
    for p in proposals.iter_mut() {
        let n = *seen.get(&p.proposal_id).unwrap_or(&0);
        if n > 0 {
            let base = p.proposal_id.clone();
            p.proposal_id = format!("{base}-{n}");
            *seen.entry(base).or_insert(0) += 1;
        } else {
            *seen.entry(p.proposal_id.clone()).or_insert(0) += 1;
        }
    }
}

/// Best-effort estimate query for a proposal: wraps its `materialization_kql`
/// (which already carries the time filter) and summarizes row + distinct-anchor
/// counts. Counts distinct values of the anchor node's projected column.
fn estimate_probe_kql(p: &GraphProposal) -> Option<String> {
    let anchor_alias = p
        .edges
        .first()
        .map(|e| e.from.as_str())
        .and_then(|fc| p.nodes.iter().find(|n| n.class == fc))
        .or_else(|| p.nodes.first())?
        .source
        .rsplit('.')
        .next()?
        .to_string();
    Some(format!(
        "{}\n| summarize Rows = count(), Entities = dcount({anchor_alias})",
        p.materialization_kql
    ))
}

/// Build candidate graph schemas from selected fields — one proposal per table
/// that has ≥1 node field. Pure (no I/O) so KQL generation is unit-testable;
/// the op layers on the optional estimate probe and session persistence.
fn build_proposals(
    selected: &[SelectedField],
    hypothesis_context: Option<&str>,
    time_filter: &str,
) -> Vec<GraphProposal> {
    // Group fields by table, preserving first-seen table order.
    let mut order: Vec<String> = Vec::new();
    let mut by_table: std::collections::HashMap<String, Vec<String>> =
        std::collections::HashMap::new();
    for sf in selected {
        if !by_table.contains_key(&sf.table) {
            order.push(sf.table.clone());
        }
        by_table.entry(sf.table.clone()).or_default().push(sf.field.clone());
    }

    let mut proposals = Vec::new();
    for table in order {
        let fields = &by_table[&table];
        let mut node_fields: Vec<(String, String)> = Vec::new(); // (field, class)
        let mut attr_fields: Vec<String> = Vec::new();
        for f in fields {
            match classify_field_name(f) {
                Some(class) => node_fields.push((f.clone(), class)),
                None => attr_fields.push(f.clone()),
            }
        }
        if node_fields.is_empty() {
            continue;
        }

        let anchor_idx = pick_anchor(&node_fields);
        let anchor_class = node_fields[anchor_idx].1.clone();

        let nodes: Vec<ProposalNode> = node_fields
            .iter()
            .map(|(f, class)| ProposalNode {
                class: class.clone(),
                source: format!("{table}.{}", sanitize_alias(f)),
                enrich: enrichable_for(class),
            })
            .collect();

        let mut edge_attrs = vec!["TimeGenerated".to_string()];
        edge_attrs.extend(attr_fields.iter().map(|f| sanitize_alias(f)));
        let edges: Vec<ProposalEdge> = node_fields
            .iter()
            .enumerate()
            .filter(|(i, _)| *i != anchor_idx)
            .map(|(_, (_, to_class))| ProposalEdge {
                r#type: rel_name_for(to_class).to_string(),
                from: anchor_class.clone(),
                to: to_class.clone(),
                attributes: edge_attrs.clone(),
            })
            .collect();

        let mut proj: Vec<String> =
            node_fields.iter().map(|(f, _)| project_expr_for_field(f)).collect();
        proj.extend(attr_fields.iter().map(|f| project_expr_for_field(f)));
        proj.push("TimeGenerated".to_string());
        let materialization_kql =
            format!("{table}\n| {time_filter}\n| project {}", proj.join(", "));

        let classes: Vec<String> =
            node_fields.iter().map(|(_, c)| c.clone()).collect();
        let proposal_id =
            format!("{}-{}", slugify(&table), classes.join("-").to_ascii_lowercase());
        let description = match hypothesis_context {
            Some(ctx) if !ctx.trim().is_empty() => {
                format!("{} graph from {} ({})", classes.join("→"), table, ctx.trim())
            }
            _ => format!("{} graph from {}", classes.join("→"), table),
        };

        proposals.push(GraphProposal {
            proposal_id,
            description,
            nodes,
            edges,
            estimated_entities: None,
            estimated_relations: None,
            materialization_kql,
        });
    }
    dedupe_ids(&mut proposals);
    proposals
}

// ── graph_build schema-driven row→graph mapper (§4.3) ──────────────────

/// Output of mapping materialized rows onto a proposal's schema.
struct MappedGraph {
    triples: Vec<graph_hunter_core::parser::ParsedTriple>,
    /// Lone entities for edge-less proposals (no triple would carry them).
    standalone: Vec<graph_hunter_core::entity::Entity>,
    /// Distinct IP node values, for build-time enrichment.
    ip_values: std::collections::HashSet<String>,
}

/// Coerce a JSON cell to a non-empty string id.
fn cell_string(v: Option<&serde_json::Value>) -> Option<String> {
    match v? {
        serde_json::Value::String(s) if !s.is_empty() => Some(s.clone()),
        serde_json::Value::Number(n) => Some(n.to_string()),
        serde_json::Value::Bool(b) => Some(b.to_string()),
        _ => None,
    }
}

/// Parse a Log Analytics `TimeGenerated` (RFC3339) to epoch seconds; 0 on miss.
fn parse_ts(s: &str) -> i64 {
    chrono::DateTime::parse_from_rfc3339(s)
        .map(|dt| dt.timestamp())
        .unwrap_or(0)
}

/// Map materialized rows onto the proposal's nodes/edges. Each row yields one
/// entity per node (by projected column) and one relation per edge whose
/// endpoints are both present; edge `attributes` columns become edge metadata.
/// Pure — no graph access — so it's unit-testable without a session.
fn map_rows_to_graph(p: &GraphProposal, rows: &[serde_json::Value]) -> MappedGraph {
    use graph_hunter_core::entity::Entity;
    use graph_hunter_core::relation::Relation;
    use graph_hunter_core::{EntityType, RelationType};

    let node_alias = |src: &str| src.rsplit('.').next().unwrap_or(src).to_string();
    let class_et = |class: &str| {
        parse_entity_type(class).unwrap_or_else(|| EntityType::Other(class.to_string()))
    };

    let mut triples = Vec::new();
    let mut standalone = Vec::new();
    let mut ip_values = std::collections::HashSet::new();

    for row in rows {
        let obj = match row.as_object() {
            Some(o) => o,
            None => continue,
        };
        // Resolve each node class to this row's value (first node of a class wins).
        let mut class_val: std::collections::HashMap<&str, String> = std::collections::HashMap::new();
        for n in &p.nodes {
            if let Some(v) = cell_string(obj.get(&node_alias(&n.source))) {
                if n.class == "IP" {
                    ip_values.insert(v.clone());
                }
                if p.edges.is_empty() {
                    standalone.push(Entity::new(&v, class_et(&n.class)));
                }
                class_val.entry(n.class.as_str()).or_insert(v);
            }
        }
        if p.edges.is_empty() {
            continue;
        }
        let ts = obj
            .get("TimeGenerated")
            .and_then(|v| v.as_str())
            .map(parse_ts)
            .unwrap_or(0);
        for e in &p.edges {
            let (from, to) = match (class_val.get(e.from.as_str()), class_val.get(e.to.as_str())) {
                (Some(f), Some(t)) => (f.clone(), t.clone()),
                _ => continue,
            };
            let rel_type =
                parse_relation_type(&e.r#type).unwrap_or_else(|| RelationType::Other(e.r#type.clone()));
            let mut rel = Relation::new(from.clone(), to.clone(), rel_type, ts);
            for attr in &e.attributes {
                if attr == "TimeGenerated" {
                    continue;
                }
                if let Some(v) = cell_string(obj.get(attr)) {
                    rel = rel.with_metadata(attr.clone(), v);
                }
            }
            triples.push((
                Entity::new(&from, class_et(&e.from)),
                rel,
                Entity::new(&to, class_et(&e.to)),
            ));
        }
    }
    MappedGraph { triples, standalone, ip_values }
}

/// Graph-first nudge for inspect-mode KQL: return an advisory when the query
/// references identity/IP-like columns that GraphHunter could materialize as
/// graph entities. Case-insensitive substring scan over a small set of the
/// canonical identifier columns the `SentinelJsonParser` turns into nodes
/// (IP / user / host / account). Returns `None` for graph-irrelevant queries
/// (pure aggregates, lookups over non-entity columns) so the nudge stays
/// signal, not noise.
/// Entity-class column tokens (lowercased needle → canonical column name) that
/// map to node-affinity entity types. Shared by the graph-advisory nudge and
/// the §4.7 fallback gate's `graph_propose` payload so the two never drift.
const ENTITY_COLUMNS: &[(&str, &str)] = &[
    ("ipaddress", "IPAddress"),
    ("remoteip", "RemoteIP"),
    ("sourceip", "SourceIP"),
    ("destinationip", "DestinationIP"),
    ("userprincipalname", "UserPrincipalName"),
    ("accountname", "AccountName"),
    ("targetusername", "TargetUserName"),
    ("computer", "Computer"),
    ("devicename", "DeviceName"),
];

fn kql_graph_advisory(kql: &str) -> Option<String> {
    let lower = kql.to_ascii_lowercase();
    if ENTITY_COLUMNS.iter().any(|(needle, _)| lower.contains(needle)) {
        Some(
            "This query touches IPs/identities that GraphHunter can materialize as graph \
             entities. For recurring pivots, prefer sentinel_seed (cold-start from an IoC) or \
             sentinel_schema (discover which tables/fields are worth building) over repeated raw \
             KQL — the graph persists what the query cannot."
                .to_string(),
        )
    } else {
        None
    }
}

/// §4.7: build a ready-to-run `graph_propose` payload from a raw KQL query's
/// entity-class columns. `None` when the query is graph-irrelevant (then the
/// fallback gate does not fire). The table is the first identifier in the query.
fn extract_propose_payload(kql: &str) -> Option<GraphProposePayload> {
    let lower = kql.to_ascii_lowercase();
    let mut selected_fields: Vec<SelectedField> = ENTITY_COLUMNS
        .iter()
        .filter(|(needle, _)| lower.contains(needle))
        .map(|(_, name)| SelectedField { table: String::new(), field: (*name).to_string() })
        .collect();
    if selected_fields.is_empty() {
        return None;
    }
    let table = kql
        .trim_start()
        .split(|c: char| c == '|' || c == '\n' || c.is_whitespace())
        .find(|t| !t.is_empty())
        .unwrap_or("")
        .to_string();
    for f in &mut selected_fields {
        f.table = table.clone();
    }
    Some(GraphProposePayload { next_tool: "graph_propose".to_string(), table, selected_fields })
}

/// Phase M (revised): ingest-scope templates — pull RAW events in a
/// thematic category so the analyst can hunt over them inside
/// GraphHunter (DSL, temporal heatmap, graph traversal, scoring).
///
/// Critical design decision: these queries deliberately do NOT
/// aggregate. The original drafts used `summarize` — that pre-hunts
/// in KQL and returns rows that have already lost the per-event
/// detail GraphHunter's graph engine needs. The user's mental model
/// is "bring logs to GH, hunt in GH (not in Azure)", so each template
/// scopes the table + filters by event type and projects the columns
/// the SentinelJsonParser uses to build entities/relations, then
/// `take`s a bounded number of raw rows.
fn render_hunting_template(template: HuntingTemplateId, window: &TimeWindow) -> String {
    let time_filter = window.kql_filter();
    match template {
        // Authentication failures: raw 4625 events. Each row becomes
        // an Account → IP / Account → Computer relation in GH; the
        // analyst then hunts brute-force / credential-stuffing
        // structurally with the DSL.
        HuntingTemplateId::FailedLogonBurst => format!(
            "SecurityEvent\n\
             | {time_filter}\n\
             | where EventID == 4625\n\
             | project TimeGenerated, Computer, Account, TargetUserName,\n\
                       IpAddress, LogonType, FailureReason, WorkstationName\n\
             | order by TimeGenerated desc\n\
             | take 1000"
        ),
        // Successful interactive / remote logons: raw 4624 events
        // (LogonType 2 = interactive, 3 = network, 7 = unlock,
        // 10 = RemoteInteractive). Lateral-movement hunts in GH look
        // for one Account touching ≥N Computers via the resulting
        // edges.
        HuntingTemplateId::LateralMovement => format!(
            "SecurityEvent\n\
             | {time_filter}\n\
             | where EventID == 4624 and LogonType in (2, 3, 7, 10)\n\
             | project TimeGenerated, Computer, Account, TargetUserName,\n\
                       IpAddress, LogonType, AuthenticationPackageName, WorkstationName\n\
             | order by TimeGenerated desc\n\
             | take 1000"
        ),
        // PowerShell process executions, scoped to suspicious-CLI
        // patterns. The `where` keeps the volume manageable while
        // staying raw (no aggregation): every row is one process
        // launch, GH builds (User, Computer, ParentProcess, Process)
        // edges per row.
        HuntingTemplateId::EncodedPowerShell => format!(
            "DeviceProcessEvents\n\
             | {time_filter}\n\
             | where FileName endswith \"powershell.exe\" or FileName endswith \"pwsh.exe\"\n\
             | where ProcessCommandLine has_any (\"-EncodedCommand\", \"-enc \", \"FromBase64String\", \"-nop\", \"-w hidden\")\n\
             | project TimeGenerated, DeviceName, AccountName, AccountDomain,\n\
                       ProcessCommandLine, InitiatingProcessFileName,\n\
                       InitiatingProcessAccountName, FileName\n\
             | order by TimeGenerated desc\n\
             | take 1000"
        ),
        // DNS queries scoped to risk-list TLDs. Raw rows so GH builds
        // (ClientIP, Domain) edges per query — the analyst then hunts
        // for fan-out patterns or co-occurrence with other categories.
        HuntingTemplateId::SuspiciousDns => format!(
            "DnsEvents\n\
             | {time_filter}\n\
             | where QueryType in (\"A\", \"AAAA\")\n\
             | extend Tld = tolower(extract(@\"\\.([a-z]+)$\", 1, Name))\n\
             | where Tld in~ (\"ru\", \"cn\", \"tk\", \"top\", \"xyz\", \"icu\", \"click\", \"info\")\n\
             | project TimeGenerated, ClientIP, Computer, Name, QueryType, Tld\n\
             | order by TimeGenerated desc\n\
             | take 1000"
        ),
    }
}

/// Render a hunting template's KQL without dispatching it. Lets the
/// frontend "ver KQL" toggle show the analyst exactly what's about to
/// run.
pub fn preview_hunting_template(template: HuntingTemplateId, window: &TimeWindow) -> String {
    render_hunting_template(template, window)
}

#[cfg(test)]
mod cap_kql_rows_tests {
    use super::*;

    #[test]
    fn cap_kql_rows_parses_and_truncates() {
        let data = r#"[{"a":1},{"a":2},{"a":3}]"#;
        let (rows, total) = cap_kql_rows(data, 2);
        assert_eq!(rows.len(), 2, "must truncate to max_rows");
        assert_eq!(total, 3, "total reflects pre-truncation length");
        assert_eq!(rows[0]["a"], serde_json::json!(1));
    }

    #[test]
    fn cap_kql_rows_handles_non_array() {
        // Malformed / non-array data yields an empty vec + zero total, never panics.
        assert_eq!(cap_kql_rows("not json", 10), (vec![], 0));
        assert_eq!(cap_kql_rows("{}", 10), (vec![], 0));
    }

    #[test]
    fn cap_kql_rows_zero_cap_returns_empty_with_total() {
        let (rows, total) = cap_kql_rows(r#"[{"a":1},{"a":2}]"#, 0);
        assert!(rows.is_empty());
        assert_eq!(total, 2);
    }

    #[test]
    fn cap_kql_rows_empty_array() {
        let (rows, total) = cap_kql_rows("[]", 10);
        assert!(rows.is_empty());
        assert_eq!(total, 0);
    }
}

#[cfg(test)]
mod resume_pause_tests {
    use super::*;

    #[tokio::test]
    async fn resume_without_connector_errors() {
        let api = GraphHunterApi::new_noop();
        let err = api.sentinel_resume().unwrap_err();
        match err { ApiError::InvalidState(_) => {}, o => panic!("expected InvalidState, got {o:?}") }
    }

    #[tokio::test]
    async fn pause_without_connector_errors() {
        let api = GraphHunterApi::new_noop();
        let err = api.sentinel_pause().unwrap_err();
        match err { ApiError::InvalidState(_) => {}, o => panic!("expected InvalidState, got {o:?}") }
    }
}

#[cfg(test)]
mod sugar_tests {

    use super::*;
    use crate::dto::sentinel::LookbackPreset;

    #[test]
    fn time_window_sugar_prepends_when_no_filter() {
        let out = apply_time_window_sugar(
            "SecurityEvent | take 50",
            Some(&TimeWindow::Preset { lookback: LookbackPreset::H1 }),
        );
        assert_eq!(out, "SecurityEvent | where TimeGenerated > ago(1h) | take 50");
    }

    #[test]
    fn time_window_sugar_leaves_user_filter_alone() {
        let original = "SecurityEvent | where TimeGenerated > ago(7d) | take 50";
        let out = apply_time_window_sugar(
            original,
            Some(&TimeWindow::Preset { lookback: LookbackPreset::H1 }),
        );
        assert_eq!(out, original);
    }

    #[test]
    fn time_window_sugar_noops_when_no_window() {
        let original = "SecurityEvent | take 50";
        let out = apply_time_window_sugar(original, None);
        assert_eq!(out, original);
    }

    #[test]
    fn take_limit_picks_last_take() {
        // Multiple `take` stages — last wins, like KQL semantics.
        let kql = "SigninLogs | take 1000 | summarize by Account | take 200";
        assert_eq!(extract_take_limit(kql), Some(200));
    }

    #[test]
    fn take_limit_none_when_no_take() {
        let kql = "SigninLogs | summarize by Account";
        assert_eq!(extract_take_limit(kql), None);
    }

    #[test]
    fn graph_advisory_set_for_identity_ip_query() {
        let kql = "SigninLogs | project IPAddress, UserPrincipalName | take 50";
        assert!(super::kql_graph_advisory(kql).is_some());
    }

    #[test]
    fn graph_advisory_none_for_non_entity_query() {
        // Pure aggregate over a non-entity column — no node-affinity tokens.
        let kql = "Usage | summarize total = sum(Quantity) by DataType";
        assert!(super::kql_graph_advisory(kql).is_none());
    }
}

#[cfg(test)]
mod fallback_gate_tests {
    use super::*;

    #[test]
    fn propose_payload_extracts_table_and_entity_fields() {
        let p = extract_propose_payload(
            "SigninLogs | where ResultType == 0 | project IPAddress, UserPrincipalName, ResultType",
        )
        .expect("payload for entity query");
        assert_eq!(p.next_tool, "graph_propose");
        assert_eq!(p.table, "SigninLogs");
        let fields: Vec<&str> = p.selected_fields.iter().map(|f| f.field.as_str()).collect();
        assert!(fields.contains(&"IPAddress"));
        assert!(fields.contains(&"UserPrincipalName"));
        assert!(p.selected_fields.iter().all(|f| f.table == "SigninLogs"));
    }

    #[test]
    fn non_entity_query_has_no_payload() {
        assert!(extract_propose_payload("Usage | summarize sum(Quantity) by DataType").is_none());
    }

    #[tokio::test]
    async fn inspect_entity_query_is_gated_without_ack() {
        let api = GraphHunterApi::new_noop();
        let res = api
            .run_kql(RunKqlRequest {
                kql: "SigninLogs | project IPAddress, UserPrincipalName".into(),
                ingest: Some(false),
                ..Default::default()
            })
            .await
            .expect("gated path returns Ok without executing");
        assert!(res.fallback_gated, "entity-class inspect query must be gated");
        assert!(res.rows.is_none(), "gated query is not executed");
        let gp = res.graph_propose.expect("ready-to-run propose payload");
        assert_eq!(gp.table, "SigninLogs");
        assert!(!gp.selected_fields.is_empty());
    }

    #[tokio::test]
    async fn ack_lets_entity_query_through_the_gate() {
        // With acknowledge_fallback the gate does not fire; the call then
        // proceeds to credential resolution (which fails here with no AZURE_*),
        // proving it was NOT short-circuited as gated.
        for k in ["AZURE_WORKSPACE_ID", "AZURE_TENANT_ID", "AZURE_CLIENT_ID", "AZURE_CLIENT_SECRET"] {
            // SAFETY: see other AZURE_* tests in this file — no concurrent reader.
            unsafe { std::env::remove_var(k) };
        }
        let api = GraphHunterApi::new_noop();
        let err = api
            .run_kql(RunKqlRequest {
                kql: "SigninLogs | project IPAddress".into(),
                ingest: Some(false),
                acknowledge_fallback: Some(true),
                ..Default::default()
            })
            .await
            .expect_err("no creds → proceeds past gate, then errors resolving AZURE_*");
        assert!(matches!(err, ApiError::InvalidInput(_)));
    }
}

#[cfg(test)]
mod schema_discover_tests {
    use super::*;

    fn signin_rows() -> Vec<serde_json::Value> {
        // 6 rows: IPAddress + UserPrincipalName are high-cardinality identifiers;
        // ResultType is a low-cardinality categorical attribute.
        (0..6)
            .map(|i| {
                serde_json::json!({
                    "TimeGenerated": "2026-06-01T10:00:00Z",
                    "UserPrincipalName": format!("user{i}@corp.com"),
                    "IPAddress": format!("203.0.113.{i}"),
                    "ResultType": "0",
                })
            })
            .collect()
    }

    #[test]
    fn classify_marks_ip_as_node_with_enrichment() {
        let fields = classify_table_fields(&signin_rows());
        let ip = fields.iter().find(|f| f.name == "IPAddress").expect("IPAddress field");
        assert_eq!(ip.graph_affinity, "node");
        assert_eq!(ip.node_class.as_deref(), Some("IP"));
        assert_eq!(
            ip.enrichable,
            vec!["geoip".to_string(), "asn".to_string(), "threat_intel".to_string()]
        );
        assert_eq!(ip.cardinality, "high");
    }

    #[test]
    fn classify_marks_identity_as_node_no_enrichment() {
        let fields = classify_table_fields(&signin_rows());
        let upn = fields
            .iter()
            .find(|f| f.name == "UserPrincipalName")
            .expect("UPN field");
        assert_eq!(upn.graph_affinity, "node");
        assert_eq!(upn.node_class.as_deref(), Some("User"));
        assert!(upn.enrichable.is_empty(), "User has no enrichment today");
    }

    #[test]
    fn classify_marks_categorical_as_attribute() {
        let fields = classify_table_fields(&signin_rows());
        let rt = fields.iter().find(|f| f.name == "ResultType").expect("ResultType field");
        assert_eq!(rt.graph_affinity, "attribute");
        assert_eq!(rt.cardinality, "low");
        assert!(rt.node_class.is_none());
    }

    #[test]
    fn classify_empty_rows_is_empty() {
        assert!(classify_table_fields(&[]).is_empty());
    }
}

#[cfg(test)]
mod graph_propose_tests {
    use super::*;

    fn sf(table: &str, field: &str) -> SelectedField {
        SelectedField { table: table.into(), field: field.into() }
    }

    #[test]
    fn proposes_identity_ip_graph_from_signinlogs() {
        let selected = vec![
            sf("SigninLogs", "UserPrincipalName"),
            sf("SigninLogs", "IPAddress"),
            sf("SigninLogs", "ResultType"),
        ];
        let props = build_proposals(&selected, Some("auth pivot"), "where TimeGenerated > ago(24h)");
        assert_eq!(props.len(), 1);
        let p = &props[0];
        // UserPrincipalName + IPAddress are nodes; ResultType is an attribute.
        assert_eq!(p.nodes.len(), 2, "two node fields");
        assert!(p.nodes.iter().any(|n| n.class == "User"));
        let ip = p.nodes.iter().find(|n| n.class == "IP").expect("IP node");
        assert_eq!(ip.source, "SigninLogs.IPAddress");
        assert_eq!(ip.enrich, vec!["geoip", "asn", "threat_intel"]);
        // Anchor is User (priority), one edge User -> IP, rel type Connect.
        assert_eq!(p.edges.len(), 1);
        assert_eq!(p.edges[0].from, "User");
        assert_eq!(p.edges[0].to, "IP");
        assert_eq!(p.edges[0].r#type, "Connect");
        // ResultType rides the edge as an attribute, alongside TimeGenerated.
        assert!(p.edges[0].attributes.contains(&"TimeGenerated".to_string()));
        assert!(p.edges[0].attributes.contains(&"ResultType".to_string()));
    }

    #[test]
    fn materialization_kql_guards_columns_and_projects_time() {
        let selected = vec![sf("SigninLogs", "UserPrincipalName"), sf("SigninLogs", "IPAddress")];
        let p = &build_proposals(&selected, None, "where TimeGenerated > ago(7d)")[0];
        let kql = &p.materialization_kql;
        assert!(kql.starts_with("SigninLogs\n| where TimeGenerated > ago(7d)\n| project "));
        // columnifexists guard on each projected source column.
        assert!(kql.contains("UserPrincipalName = tostring(columnifexists(\"UserPrincipalName\", \"\"))"));
        assert!(kql.contains("IPAddress = tostring(columnifexists(\"IPAddress\", \"\"))"));
        assert!(kql.trim_end().ends_with("TimeGenerated"));
    }

    #[test]
    fn nested_aws_field_uses_parse_json() {
        // AWSCloudTrail dynamic column path → parse_json with a guarded root.
        let selected = vec![
            sf("AWSCloudTrail", "UserIdentityArn"),
            sf("AWSCloudTrail", "RequestParameters.instanceType"),
        ];
        let p = &build_proposals(&selected, None, "where TimeGenerated > ago(24h)")[0];
        let kql = &p.materialization_kql;
        assert!(
            kql.contains(
                "RequestParameters_instanceType = tostring(parse_json(columnifexists(\"RequestParameters\", \"\")).instanceType)"
            ),
            "nested field must parse_json the guarded root: {kql}"
        );
    }

    #[test]
    fn table_with_no_node_fields_is_skipped() {
        // ResultType / ResultDescription are categorical attributes, no nodes.
        let selected = vec![sf("SigninLogs", "ResultType"), sf("SigninLogs", "ResultDescription")];
        assert!(build_proposals(&selected, None, "where TimeGenerated > ago(24h)").is_empty());
    }

    #[test]
    fn one_proposal_per_table_with_unique_ids() {
        let selected = vec![
            sf("SigninLogs", "UserPrincipalName"),
            sf("SigninLogs", "IPAddress"),
            sf("DeviceNetworkEvents", "DeviceName"),
            sf("DeviceNetworkEvents", "RemoteIP"),
        ];
        let props = build_proposals(&selected, None, "where TimeGenerated > ago(24h)");
        assert_eq!(props.len(), 2);
        let ids: std::collections::HashSet<_> = props.iter().map(|p| &p.proposal_id).collect();
        assert_eq!(ids.len(), 2, "proposal ids unique");
    }

    #[test]
    fn estimate_probe_wraps_materialization() {
        let selected = vec![sf("SigninLogs", "UserPrincipalName"), sf("SigninLogs", "IPAddress")];
        let p = &build_proposals(&selected, None, "where TimeGenerated > ago(24h)")[0];
        let probe = estimate_probe_kql(p).expect("probe");
        assert!(probe.contains("summarize Rows = count(), Entities = dcount(UserPrincipalName)"));
        assert!(probe.starts_with("SigninLogs\n"));
    }
}

#[cfg(test)]
mod graph_build_mapper_tests {
    use super::*;

    fn signin_proposal() -> GraphProposal {
        let selected = vec![
            SelectedField { table: "SigninLogs".into(), field: "UserPrincipalName".into() },
            SelectedField { table: "SigninLogs".into(), field: "IPAddress".into() },
            SelectedField { table: "SigninLogs".into(), field: "ResultType".into() },
        ];
        build_proposals(&selected, None, "where TimeGenerated > ago(24h)")
            .into_iter()
            .next()
            .unwrap()
    }

    #[test]
    fn maps_rows_to_entities_relations_and_edge_metadata() {
        let p = signin_proposal();
        let rows = vec![
            serde_json::json!({
                "UserPrincipalName": "alice@corp.com",
                "IPAddress": "203.0.113.7",
                "ResultType": "0",
                "TimeGenerated": "2026-06-01T10:00:00Z",
            }),
            serde_json::json!({
                "UserPrincipalName": "bob@corp.com",
                "IPAddress": "203.0.113.8",
                "ResultType": "50126",
                "TimeGenerated": "2026-06-01T11:00:00Z",
            }),
        ];
        let mapped = map_rows_to_graph(&p, &rows);
        assert_eq!(mapped.triples.len(), 2, "one User->IP edge per row");
        // IP values collected for enrichment.
        assert!(mapped.ip_values.contains("203.0.113.7"));
        assert!(mapped.ip_values.contains("203.0.113.8"));
        // First triple: User -> IP with ResultType + a parsed timestamp.
        let (src, rel, dst) = &mapped.triples[0];
        assert_eq!(src.id, "alice@corp.com");
        assert_eq!(dst.id, "203.0.113.7");
        assert_eq!(rel.metadata.get("ResultType").map(String::as_str), Some("0"));
        assert!(rel.timestamp > 0, "TimeGenerated parsed to epoch");
        // edge-bearing proposals produce no standalone entities.
        assert!(mapped.standalone.is_empty());
    }

    #[test]
    fn rows_missing_an_endpoint_are_skipped() {
        let p = signin_proposal();
        let rows = vec![serde_json::json!({
            "UserPrincipalName": "alice@corp.com",
            // IPAddress missing → no User->IP edge for this row.
            "TimeGenerated": "2026-06-01T10:00:00Z",
        })];
        let mapped = map_rows_to_graph(&p, &rows);
        assert!(mapped.triples.is_empty());
    }

    #[test]
    fn edgeless_single_node_proposal_yields_standalone_entities() {
        let selected = vec![SelectedField { table: "SigninLogs".into(), field: "IPAddress".into() }];
        let p = build_proposals(&selected, None, "where TimeGenerated > ago(24h)")
            .into_iter()
            .next()
            .unwrap();
        assert!(p.edges.is_empty(), "single node → no edges");
        let rows = vec![serde_json::json!({"IPAddress": "203.0.113.7"})];
        let mapped = map_rows_to_graph(&p, &rows);
        assert_eq!(mapped.standalone.len(), 1);
        assert_eq!(mapped.standalone[0].id, "203.0.113.7");
        assert!(mapped.triples.is_empty());
    }
}

#[cfg(test)]
mod hydrate_tests {
    use super::*;
    use crate::dto::session::CreateSessionRequest;
    use graph_hunter_siem::{SentinelTransport, TokenResponse};
    use std::sync::Mutex;

    struct MockTransport {
        queries: Mutex<Vec<String>>,
        response: serde_json::Value,
    }

    impl SentinelTransport for MockTransport {
        async fn acquire_token(
            &self,
            _t: &str,
            _c: &str,
            _s: &str,
        ) -> Result<TokenResponse, String> {
            Ok(TokenResponse {
                access_token: "tok".into(),
                expires_in: 3600,
            })
        }

        async fn execute_query(
            &self,
            _ws: &str,
            query: &str,
            _b: &str,
        ) -> Result<serde_json::Value, String> {
            self.queries.lock().unwrap().push(query.to_string());
            Ok(self.response.clone())
        }
    }

    fn one_signin_row() -> serde_json::Value {
        serde_json::json!({
            "tables": [{
                "name": "PrimaryResult",
                "columns": [
                    {"name": "TimeGenerated"}, {"name": "Type"},
                    {"name": "UserPrincipalName"}, {"name": "IPAddress"}, {"name": "ResultType"}
                ],
                "rows": [[
                    "2026-06-01T10:00:00Z", "SigninLogs",
                    "alice@corp.com", "10.0.0.9", "0"
                ]]
            }]
        })
    }

    #[tokio::test]
    async fn hydrate_ip_issues_three_table_queries_and_ingests() {
        let api = GraphHunterApi::new_noop();
        api.create_session(CreateSessionRequest {
            name: Some("hydrate-test".into()),
        })
        .expect("create_session");
        let transport = MockTransport {
            queries: Mutex::new(vec![]),
            response: one_signin_row(),
        };
        let cache = graph_hunter_siem::SentinelTokenCache::new();

        let outcome = api
            .hydrate_node_with(
                &transport,
                &cache,
                "10.0.0.9",
                &graph_hunter_core::types::EntityType::IP,
                "where TimeGenerated > ago(24h)",
                "ws-1",
                &SentinelAuth {
                    tenant_id: "t".into(),
                    client_id: "c".into(),
                    client_secret: "s".into(),
                },
                "Sentinel Hydration (live)",
            )
            .await
            .expect("hydrate");

        // IP maps to 3 tables (SigninLogs, DeviceNetworkEvents, CommonSecurityLog) -> 3 queries.
        assert_eq!(transport.queries.lock().unwrap().len(), 3);
        assert_eq!(outcome.tables_attempted, 3);
        assert!(!outcome.skipped);
        // The mock returns a SigninLogs row for every query; at least one table ingested.
        assert!(outcome.tables_hit >= 1, "expected ≥1 table ingested, got {}", outcome.tables_hit);
        assert!(
            outcome.new_relations >= 1,
            "expected ingested relations, got {}",
            outcome.new_relations
        );
    }

    #[tokio::test]
    async fn hydrate_filter_restricts_tables_and_caps_rows() {
        let api = GraphHunterApi::new_noop();
        api.create_session(CreateSessionRequest {
            name: Some("enrich-test".into()),
        })
        .expect("create_session");
        let transport = MockTransport {
            queries: Mutex::new(vec![]),
            response: one_signin_row(),
        };
        let cache = graph_hunter_siem::SentinelTokenCache::new();

        let filter = HydrationFilter {
            tables: Some(vec!["SigninLogs".to_string()]),
            max_rows: Some(100),
        };
        let outcome = api
            .hydrate_node_filtered_with(
                &transport,
                &cache,
                "10.0.0.9",
                &graph_hunter_core::types::EntityType::IP,
                "where TimeGenerated > ago(24h)",
                "ws-1",
                &SentinelAuth {
                    tenant_id: "t".into(),
                    client_id: "c".into(),
                    client_secret: "s".into(),
                },
                "Sentinel Enrich",
                Some(&filter),
            )
            .await
            .expect("hydrate filtered");

        let queries = transport.queries.lock().unwrap();
        // IP maps to 3 tables; the filter narrows to SigninLogs only -> 1 query.
        assert_eq!(queries.len(), 1, "filter must restrict to one table");
        assert!(queries[0].contains("SigninLogs"), "query: {}", queries[0]);
        assert!(queries[0].contains("take 100"), "max_rows must cap take: {}", queries[0]);
        assert_eq!(outcome.tables_attempted, 1);
    }

    #[tokio::test]
    async fn hydrate_filter_unknown_table_is_skipped() {
        let api = GraphHunterApi::new_noop();
        api.create_session(CreateSessionRequest {
            name: Some("enrich-unknown".into()),
        })
        .expect("create_session");
        let transport = MockTransport {
            queries: Mutex::new(vec![]),
            response: one_signin_row(),
        };
        let cache = graph_hunter_siem::SentinelTokenCache::new();

        let filter = HydrationFilter {
            tables: Some(vec!["NoSuchTable".to_string()]),
            max_rows: None,
        };
        let outcome = api
            .hydrate_node_filtered_with(
                &transport,
                &cache,
                "10.0.0.9",
                &graph_hunter_core::types::EntityType::IP,
                "where TimeGenerated > ago(24h)",
                "ws-1",
                &SentinelAuth {
                    tenant_id: "t".into(),
                    client_id: "c".into(),
                    client_secret: "s".into(),
                },
                "Sentinel Enrich",
                Some(&filter),
            )
            .await
            .expect("hydrate filtered");

        assert!(outcome.skipped, "unknown-table filter must be skipped");
        assert_eq!(outcome.tables_attempted, 0);
        assert_eq!(transport.queries.lock().unwrap().len(), 0, "no queries issued");
    }

    #[tokio::test]
    async fn hydrate_unmapped_type_is_skipped() {
        let api = GraphHunterApi::new_noop();
        api.create_session(CreateSessionRequest {
            name: Some("hydrate-test2".into()),
        })
        .expect("create_session");
        let transport = MockTransport {
            queries: Mutex::new(vec![]),
            response: serde_json::json!({"tables": []}),
        };
        let cache = graph_hunter_siem::SentinelTokenCache::new();
        let outcome = api
            .hydrate_node_with(
                &transport,
                &cache,
                "evil.com",
                &graph_hunter_core::types::EntityType::Domain,
                "where TimeGenerated > ago(24h)",
                "ws-1",
                &SentinelAuth {
                    tenant_id: "t".into(),
                    client_id: "c".into(),
                    client_secret: "s".into(),
                },
                "Sentinel Hydration (live)",
            )
            .await
            .expect("hydrate");
        assert!(outcome.skipped);
        assert_eq!(
            transport.queries.lock().unwrap().len(),
            0,
            "unmapped type must not query"
        );
    }
}

#[cfg(test)]
mod seed_tests {
    use super::*;
    use crate::dto::session::CreateSessionRequest;
    use crate::dto::v1::sentinel::SeedFromIocRequest;

    struct MockTransport {
        response: serde_json::Value,
    }

    impl SentinelTransport for MockTransport {
        async fn acquire_token(
            &self,
            _t: &str,
            _c: &str,
            _s: &str,
        ) -> Result<graph_hunter_siem::TokenResponse, String> {
            Ok(graph_hunter_siem::TokenResponse {
                access_token: "tok".into(),
                expires_in: 3600,
            })
        }

        async fn execute_query(
            &self,
            _ws: &str,
            _q: &str,
            _b: &str,
        ) -> Result<serde_json::Value, String> {
            Ok(self.response.clone())
        }
    }

    fn one_signin_row() -> serde_json::Value {
        serde_json::json!({
            "tables": [{
                "name": "PrimaryResult",
                "columns": [
                    {"name": "TimeGenerated"}, {"name": "Type"},
                    {"name": "UserPrincipalName"}, {"name": "IPAddress"}, {"name": "ResultType"}
                ],
                "rows": [["2026-06-02T10:00:00Z", "SigninLogs", "alice@corp.com", "10.0.0.9", "0"]]
            }]
        })
    }

    #[tokio::test]
    async fn seed_ip_populates_neighborhood_and_ranks_anomalies() {
        let api = GraphHunterApi::new_noop();
        api.create_session(CreateSessionRequest {
            name: Some("seed-test".into()),
        })
        .expect("session");
        let transport = MockTransport {
            response: one_signin_row(),
        };
        let cache = graph_hunter_siem::SentinelTokenCache::new();
        let auth = SentinelAuth {
            tenant_id: "t".into(),
            client_id: "c".into(),
            client_secret: "s".into(),
        };

        let result = api
            .seed_from_ioc_with(
                &transport,
                &cache,
                "10.0.0.9",
                &graph_hunter_core::types::EntityType::IP,
                "where TimeGenerated > ago(24h)",
                "ws-1",
                &auth,
            )
            .await
            .expect("seed");

        assert!(!result.hydration.skipped);
        assert!(result.hydration.new_relations >= 1);
        assert_eq!(result.neighborhood.center, "10.0.0.9");
        assert!(!result.neighborhood.nodes.is_empty());
        assert!(result.top_anomalies.len() <= 5);
        for w in result.top_anomalies.windows(2) {
            assert!(
                w[0].score >= w[1].score,
                "top_anomalies must be score-descending"
            );
        }
    }

    #[tokio::test]
    async fn seed_without_session_auto_creates_one() {
        for k in [
            "AZURE_WORKSPACE_ID",
            "AZURE_TENANT_ID",
            "AZURE_CLIENT_ID",
            "AZURE_CLIENT_SECRET",
        ] {
            // SAFETY: no TEST in this binary reads AZURE_* from the process
            // environment — the production readers (run_kql, sentinel_connect,
            // sentinel_check_env) are never exercised by a test, and
            // hydrate_tests/seed_tests pass credentials as literals. So
            // stripping these vars races with no concurrent observer. If a
            // future test calls an env-reading production path, serialize it
            // (e.g. add the serial_test dep + #[serial]) or pass creds via
            // request fields.
            unsafe { std::env::remove_var(k); }
        }
        let api = GraphHunterApi::new_noop();
        let result = api
            .seed_from_ioc(SeedFromIocRequest {
                session: None,
                entity_type: "IP".into(),
                value: "10.0.0.9".into(),
                time_window: None,
            })
            .await
            .expect("seed");
        assert!(result.hydration.skipped, "no creds → skipped");
        let session = api
            .sessions()
            .current_session()
            .expect("auto-created session");
        assert!(session.name.contains("Sentinel Seed"));
    }

    #[tokio::test]
    async fn seed_rejects_unseedable_type() {
        let api = GraphHunterApi::new_noop();
        let err = api
            .seed_from_ioc(SeedFromIocRequest {
                session: None,
                entity_type: "Domain".into(),
                value: "evil.com".into(),
                time_window: None,
            })
            .await
            .unwrap_err();
        match err {
            ApiError::InvalidInput(_) => {}
            other => panic!("expected InvalidInput, got {other:?}"),
        }
    }
}

#[cfg(test)]
mod node_enrich_tests {
    use super::*;
    use crate::dto::session::CreateSessionRequest;
    use crate::dto::v1::sentinel::NodeEnrichRequest;

    #[tokio::test]
    async fn node_enrich_errors_when_node_absent() {
        let api = GraphHunterApi::new_noop();
        api.create_session(CreateSessionRequest {
            name: Some("enrich-absent".into()),
        })
        .unwrap();
        let err = api
            .node_enrich(NodeEnrichRequest {
                session: None,
                node_id: "does-not-exist".into(),
                tables: None,
                time_window: None,
                max_rows: None,
                dataset: None,
            })
            .await
            .unwrap_err();
        assert!(matches!(err, ApiError::InvalidInput(_)));
        assert!(err.to_string().contains("does-not-exist"), "error should name the missing node: {err}");
    }

    #[tokio::test]
    async fn node_enrich_errors_without_session() {
        let api = GraphHunterApi::new_noop();
        let err = api
            .node_enrich(NodeEnrichRequest {
                session: None,
                node_id: "10.0.0.9".into(),
                tables: None,
                time_window: None,
                max_rows: None,
                dataset: None,
            })
            .await
            .unwrap_err();
        assert!(matches!(err, ApiError::InvalidState(_)));
    }
}
