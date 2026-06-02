//! Sentinel real-time connector commands: connect, disconnect, status,
//! env probe, and ad-hoc KQL. The polling loop itself lives in
//! `crate::sentinel_connector`; these operations manage its lifecycle.

use std::sync::Arc;
use std::time::Duration;

use graph_hunter_core::sentinel::{build_hydration_kql, sentinel_entity_targets};
use graph_hunter_core::types::EntityType;
use graph_hunter_siem::{
    HttpSentinelTransport, SentinelAuth, SentinelPollingConfig, SentinelTokenCache,
    SentinelTransport, normalize_response, run_sentinel_query,
};
use uuid::Uuid;

use crate::dto::sentinel::{
    ConnectorStatusResponse, HuntingTemplateId, KqlResult, RunHuntingTemplateRequest,
    RunKqlRequest, SentinelConnectRequest, SentinelConnectedEvent, SentinelEnvStatus, TimeWindow,
};
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
        let (status_tx, status_rx) = tokio::sync::watch::channel(ConnectorStatus::Connecting);

        let event = SentinelConnectedEvent {
            connector_id: connector_id.clone(),
            tables: config.tables.clone(),
            poll_interval_secs: config.poll_interval_secs,
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
            });
        }

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

        // Final scoring pass.
        if let Some(session) = self.sessions().current_session() {
            if let Ok(mut graph) = session.graph.write() {
                let _ = run_scoring_adaptive(&mut graph);
            }
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

        let session = self.sessions().current_session().ok_or_else(|| {
            ApiError::InvalidState("No current session. Create or load a session first.".into())
        })?;

        // Register a dataset for audit.
        let dataset_id = Uuid::new_v4().to_string();
        {
            let mut datasets = session
                .datasets
                .write()
                .map_err(|e| ApiError::Internal(format!("datasets lock poisoned: {e}")))?;
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
        })
        .await
    }

    /// Hydrate a single node from Sentinel: for each (table, columns)
    /// where its type can appear, run an entity-scoped KQL, parse, and
    /// ingest into the current session graph. Generic over transport for
    /// mockability; the live-expand path builds the real HTTP transport.
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
    ) -> ApiResult<graph_hunter_core::analytics::HydrationOutcome> {
        use graph_hunter_core::analytics::HydrationOutcome;

        let targets = sentinel_entity_targets(entity_type);
        if targets.is_empty() {
            return Ok(HydrationOutcome {
                skipped: true,
                reason: Some(format!("no Sentinel column mapping for type {entity_type}")),
                new_entities: 0,
                new_relations: 0,
                tables_hit: 0,
                tables_attempted: 0,
            });
        }

        let token = token_cache
            .get_or_refresh(transport, auth)
            .await
            .map_err(|e| ApiError::Upstream {
                service: "sentinel-auth".into(),
                message: e,
            })?;

        const HYDRATION_TAKE: u32 = 5000;
        const HYDRATION_DATASET: &str = "Sentinel Hydration (live)";

        let parser = make_parser_for_format("sentinel").map_err(ApiError::InvalidInput)?;
        let session = self.sessions().current_session().ok_or_else(|| {
            ApiError::InvalidState("No current session.".into())
        })?;

        let mut tables_hit = 0usize;
        let mut new_e = 0usize;
        let mut new_r = 0usize;
        let tables_attempted = targets.len();

        for (table, columns) in targets {
            let kql = build_hydration_kql(table, columns, value, time_filter, HYDRATION_TAKE);
            match transport.execute_query(workspace_id, &kql, &token).await {
                Ok(raw) => match normalize_response(&raw) {
                    Ok(result) if !result.data.is_empty() && result.data != "[]" => {
                        let triples = parser.parse(&result.data);
                        if !triples.is_empty() {
                            match session.graph.write() {
                                Ok(mut graph) => {
                                    match graph.insert_triples(triples, Some(HYDRATION_DATASET)) {
                                        Ok((e, r)) => {
                                            new_e += e;
                                            new_r += r;
                                            tables_hit += 1;
                                        }
                                        Err(e) => {
                                            tracing::warn!("hydration insert {table}: {e}");
                                        }
                                    }
                                }
                                Err(e) => {
                                    tracing::warn!(
                                        "hydration graph lock poisoned {table}: {e}"
                                    );
                                }
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
            )
            .await
            .expect("hydrate");

        // IP maps to 3 tables (SigninLogs, DeviceNetworkEvents, CommonSecurityLog) -> 3 queries.
        assert_eq!(transport.queries.lock().unwrap().len(), 3);
        assert_eq!(outcome.tables_attempted, 3);
        assert!(!outcome.skipped);
        // The mock returns a SigninLogs row for every query; at least one table ingested.
        assert!(
            outcome.new_relations >= 1,
            "expected ingested relations, got {}",
            outcome.new_relations
        );
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
