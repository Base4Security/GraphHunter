//! AI command operations: 9 methods covering config, conversation,
//! LLM calls, and the agentic tool-calling loop.
//!
//! The per-session conversation fix (from the feedback's fractura #X)
//! lives here: every method that touches history resolves a session
//! first and reads/writes `session.ai_conversation`. The global
//! `ai_conversation` slot in `ApiState` is preserved as a
//! backward-compat vestige but is no longer written.

use graph_hunter_core::{GraphHunter, parse_dsl};

use crate::ai::{self, AiAnalysisResponse, AiConfig, ConversationMessage, ProviderConfig};
use crate::dto::ai::{
    AiChatRequest, AiConversationScope, AnalyzeGraphConversationRequest, AnalyzeGraphRequest,
    ProposeHypothesisRequest, SetAiKeyRequest, SetAiProviderRequest,
};
use crate::dto::dsl::ParseDslResponse;
use crate::util::{now_secs, parse_entity_type};
use crate::{ApiError, ApiResult, GraphHunterApi};

const MAX_HISTORY_BEFORE_SUMMARIZE: usize = 10;
const RECENT_MESSAGES_KEPT: usize = 4;

impl GraphHunterApi {
    // ── Config (global, no session) ─────────────────────────────────────

    /// Probe the AI provider configuration. Reads `ApiState.ai_config`
    /// if set; otherwise falls back to env vars so analysts can see
    /// whether `.env` is wired up.
    pub fn ai_check_config(&self) -> AiConfig {
        let cfg = self.inner.ai_config.read().ok().and_then(|g| g.clone());
        ai::check_config(cfg.as_ref())
    }

    /// Set the API key (legacy one-arg command — defaults to OpenAI).
    /// Empty key clears the config.
    pub fn ai_set_key(&self, req: SetAiKeyRequest) -> ApiResult<()> {
        let mut guard = self
            .inner
            .ai_config
            .write()
            .map_err(|e| ApiError::Internal(format!("ai_config poisoned: {e}")))?;
        if req.key.trim().is_empty() {
            *guard = None;
        } else {
            *guard = Some(ProviderConfig {
                provider: ai::AiProvider::OpenAI,
                api_key: req.key.trim().to_string(),
                model: None,
                base_url: None,
            });
        }
        Ok(())
    }

    /// Set the full AI provider configuration (provider + key +
    /// optional model/base_url). `"auto"` or `""` detects from the
    /// key format. Returns the detected provider name.
    pub fn ai_set_provider(&self, req: SetAiProviderRequest) -> ApiResult<String> {
        let mut guard = self
            .inner
            .ai_config
            .write()
            .map_err(|e| ApiError::Internal(format!("ai_config poisoned: {e}")))?;
        if req.api_key.trim().is_empty() {
            *guard = None;
            return Ok("none".to_string());
        }
        let ai_provider = match req.provider.to_lowercase().as_str() {
            "auto" | "" => ai::detect_provider(&req.api_key).ok_or_else(|| {
                ApiError::InvalidInput(
                    "Could not detect provider from API key format. Please select a provider manually.".into(),
                )
            })?,
            "openai" => ai::AiProvider::OpenAI,
            "anthropic" => ai::AiProvider::Anthropic,
            "google" => ai::AiProvider::Google,
            other => {
                return Err(ApiError::InvalidInput(format!(
                    "Unknown provider: '{other}'. Use 'openai', 'anthropic', or 'google'."
                )))
            }
        };
        let provider_name = ai_provider.to_string();
        *guard = Some(ProviderConfig {
            provider: ai_provider,
            api_key: req.api_key.trim().to_string(),
            model: req.model,
            base_url: req.base_url,
        });
        Ok(provider_name)
    }

    // ── Conversation (per-session) ──────────────────────────────────────

    /// Clear the resolved session's AI conversation history. Errors
    /// when no session is selected — the per-session refactor fixed
    /// the old bug where clear() hit a global slot.
    pub fn ai_clear_conversation(&self, req: AiConversationScope) -> ApiResult<()> {
        let session = self.resolve_session(req.session.as_ref())?;
        let mut conv = session
            .ai_conversation
            .write()
            .map_err(|e| ApiError::Internal(format!("ai_conversation poisoned: {e}")))?;
        conv.clear();
        Ok(())
    }

    /// Return the resolved session's conversation messages.
    pub fn ai_get_conversation(
        &self,
        req: AiConversationScope,
    ) -> ApiResult<Vec<ConversationMessage>> {
        let session = self.resolve_session(req.session.as_ref())?;
        let conv = session
            .ai_conversation
            .read()
            .map_err(|e| ApiError::Internal(format!("ai_conversation poisoned: {e}")))?;
        Ok(conv.messages.clone())
    }

    // ── LLM calls ───────────────────────────────────────────────────────

    /// Propose a hypothesis from a natural-language situation.
    /// Stateless (no history).
    pub async fn ai_propose_hypothesis(
        &self,
        req: ProposeHypothesisRequest,
    ) -> ApiResult<ParseDslResponse> {
        let cfg = self.read_ai_config();
        let result = ai::propose_hypothesis(&req.situation, cfg.as_ref())
            .await
            .map_err(ApiError::Upstream_ai)?;
        let steps = result.hypothesis.steps.len();
        Ok(ParseDslResponse {
            hypothesis: result.hypothesis,
            formatted: result.formatted,
            steps,
        })
    }

    /// One-shot subgraph analysis (no history).
    pub async fn ai_analyze_graph(
        &self,
        req: AnalyzeGraphRequest,
    ) -> ApiResult<AiAnalysisResponse> {
        let cfg = self.read_ai_config();
        ai::analyze_graph(
            &req.nodes_json,
            &req.edges_json,
            req.selected_node_id,
            req.question_override,
            cfg.as_ref(),
        )
        .await
        .map_err(ApiError::Upstream_ai)
    }

    /// Chat-style subgraph analysis with per-session conversation
    /// history + auto-summarization after 10 turns.
    pub async fn ai_analyze_graph_conversation(
        &self,
        req: AnalyzeGraphConversationRequest,
    ) -> ApiResult<AiAnalysisResponse> {
        let cfg = self.read_ai_config();
        let session = self.resolve_session(req.session.as_ref())?;

        // Snapshot history outside the await (Send across awaits).
        let conversation = {
            let conv = session
                .ai_conversation
                .read()
                .map_err(|e| ApiError::Internal(format!("ai_conversation poisoned: {e}")))?;
            conv.clone()
        };

        let user_message = req.user_message.clone();
        let (raw_response, parsed) = ai::analyze_graph_conversation(
            &req.nodes_json,
            &req.edges_json,
            req.selected_node_id.as_deref(),
            &user_message,
            &conversation,
            cfg.as_ref(),
        )
        .await
        .map_err(ApiError::Upstream_ai)?;

        // Append the turn to the session's history + auto-summarize.
        {
            let mut conv = session
                .ai_conversation
                .write()
                .map_err(|e| ApiError::Internal(format!("ai_conversation poisoned: {e}")))?;
            let now = now_secs();
            conv.messages.push(ConversationMessage {
                role: "user".to_string(),
                content: user_message,
                timestamp: now,
            });
            conv.messages.push(ConversationMessage {
                role: "assistant".to_string(),
                content: raw_response,
                timestamp: now,
            });
            summarize_if_needed(&mut conv);
        }

        Ok(parsed)
    }

    /// Agentic AI chat: the LLM can invoke graph-query tools in a
    /// loop (max 5 iterations) before producing a final answer.
    ///
    /// Tools have access to the session's graph via a brief write
    /// lock per call. The tool set is the one agreed in
    /// `build_agentic_system_prompt`: search_entities, get_node_details,
    /// expand_node, run_hunt, get_graph_stats.
    pub async fn ai_chat(&self, req: AiChatRequest) -> ApiResult<AiAnalysisResponse> {
        let cfg = self.read_ai_config().ok_or_else(|| {
            ApiError::InvalidInput("No AI provider configured. Set API key in AI Settings.".into())
        })?;
        let resolved_cfg = ai::resolve_config(Some(&cfg)).map_err(ApiError::Upstream_ai)?;
        let session = self.resolve_session(req.session.as_ref())?;

        // Build graph stats under a brief read lock, release before the
        // first LLM await.
        let graph_stats = {
            let graph = session
                .graph
                .read()
                .map_err(|e| ApiError::Internal(format!("graph lock poisoned: {e}")))?;
            build_graph_stats_for_prompt(&graph)
        };
        let system_prompt = ai::build_agentic_system_prompt(&graph_stats);

        // Snapshot history.
        let conversation = {
            let conv = session
                .ai_conversation
                .read()
                .map_err(|e| ApiError::Internal(format!("ai_conversation poisoned: {e}")))?;
            conv.clone()
        };

        let mut working_history = ai::build_messages_with_history(&conversation, &req.user_message);
        let mut final_response = String::new();
        const MAX_ITERATIONS: usize = 5;

        for iteration in 0..MAX_ITERATIONS {
            // LLM call — no locks held across the await.
            let raw = ai::call_llm_with_history(
                &resolved_cfg,
                &system_prompt,
                &working_history,
                Some(16384),
            )
            .await
            .map_err(ApiError::Upstream_ai)?;

            let tool_calls = ai::parse_tool_calls(&raw);
            if tool_calls.is_empty() {
                final_response = raw;
                break;
            }

            // Execute tools under brief write locks.
            let mut tool_results: Vec<ai::ToolResult> = Vec::new();
            for tc in &tool_calls {
                let mut graph = session
                    .graph
                    .write()
                    .map_err(|e| ApiError::Internal(format!("graph lock poisoned: {e}")))?;
                tool_results.push(execute_ai_tool(tc, &mut graph, session.phase()));
            }

            let now = now_secs();
            working_history.push(ConversationMessage {
                role: "assistant".to_string(),
                content: raw,
                timestamp: now,
            });
            let tool_results_text = tool_results
                .iter()
                .map(|r| {
                    if r.success {
                        format!("Tool `{}` result:\n{}", r.tool, r.data)
                    } else {
                        format!("Tool `{}` error: {}", r.tool, r.data)
                    }
                })
                .collect::<Vec<_>>()
                .join("\n\n");
            working_history.push(ConversationMessage {
                role: "user".to_string(),
                content: format!("[Tool Results]\n{tool_results_text}"),
                timestamp: now,
            });

            if iteration == MAX_ITERATIONS - 1 {
                // Force one final call without expecting tools.
                let final_raw = ai::call_llm_with_history(
                    &resolved_cfg,
                    &system_prompt,
                    &working_history,
                    Some(16384),
                )
                .await
                .map_err(ApiError::Upstream_ai)?;
                final_response = final_raw;
            }
        }

        let parsed = ai::parse_ai_response(&final_response);

        // Persist only the user message + final assistant text to the
        // session's history (not the intermediate tool-exchange turns).
        {
            let mut conv = session
                .ai_conversation
                .write()
                .map_err(|e| ApiError::Internal(format!("ai_conversation poisoned: {e}")))?;
            let now = now_secs();
            conv.messages.push(ConversationMessage {
                role: "user".to_string(),
                content: req.user_message,
                timestamp: now,
            });
            conv.messages.push(ConversationMessage {
                role: "assistant".to_string(),
                content: parsed.text.clone(),
                timestamp: now,
            });
            summarize_if_needed(&mut conv);
        }

        Ok(parsed)
    }

    /// Read the (optional) AI config, snapshotting out of the lock.
    fn read_ai_config(&self) -> Option<ProviderConfig> {
        self.inner.ai_config.read().ok().and_then(|g| g.clone())
    }
}

/// Auto-summarize the conversation once it grows past 10 messages.
/// Drain all but the last 4 into a `context_summary` so the LLM can
/// still see gist but the token budget stays bounded.
fn summarize_if_needed(conv: &mut ai::AiConversation) {
    if conv.messages.len() > MAX_HISTORY_BEFORE_SUMMARIZE {
        let drain_end = conv.messages.len() - RECENT_MESSAGES_KEPT;
        let old: Vec<ConversationMessage> = conv.messages.drain(..drain_end).collect();
        let summary_parts: Vec<String> = old
            .iter()
            .map(|m| {
                let content = if m.content.len() > 200 {
                    format!("{}...", &m.content[..200])
                } else {
                    m.content.clone()
                };
                format!("[{}]: {}", m.role, content)
            })
            .collect();
        conv.context_summary = Some(summary_parts.join("\n"));
    }
}

/// Short graph stats for the agentic system prompt. Keeps the prompt
/// under a few hundred bytes even on huge graphs.
pub(crate) fn build_graph_stats_for_prompt(graph: &GraphHunter) -> String {
    let summary = graph.get_graph_summary();
    let mut parts = vec![format!(
        "{} entities, {} relations",
        summary.entity_count, summary.relation_count
    )];
    if !summary.type_distribution.is_empty() {
        let types: Vec<String> = summary
            .type_distribution
            .iter()
            .map(|t| format!("{}: {}", t.entity_type, t.count))
            .collect();
        parts.push(format!("Types: {}", types.join(", ")));
    }
    if let Some((min, max)) = summary.time_range {
        parts.push(format!("Time range: {min} to {max}"));
    }
    if !summary.top_anomalies.is_empty() {
        let top: Vec<String> = summary
            .top_anomalies
            .iter()
            .take(5)
            .map(|a| format!("{} ({}, score={:.2})", a.id, a.entity_type, a.score))
            .collect();
        parts.push(format!("Top anomalies: {}", top.join("; ")));
    }
    parts.join("\n")
}

/// Execute a single tool call against the graph. Truncates large
/// result payloads to 8 KB so the LLM context doesn't explode on
/// `expand_node` against a hub.
///
/// `phase` is the session's current lifecycle phase; `run_hunt` is
/// gated to `Ready`/`LiveTail` — identical to the HTTP `run_hunt`
/// entrypoint — so the AI agent cannot bypass the phase fence.
fn execute_ai_tool(
    tool_call: &ai::ToolCall,
    graph: &mut GraphHunter,
    phase: crate::state::SessionPhase,
) -> ai::ToolResult {
    let result: Result<String, String> = match tool_call.tool.as_str() {
        "search_entities" => {
            let query = tool_call
                .params
                .get("query")
                .and_then(|v| v.as_str())
                .unwrap_or("");
            let type_filter = tool_call
                .params
                .get("entity_type")
                .and_then(|v| v.as_str())
                .and_then(parse_entity_type);
            let limit = tool_call
                .params
                .get("limit")
                .and_then(|v| v.as_u64())
                .unwrap_or(20) as usize;
            let results = graph.search_entities(query, type_filter.as_ref(), limit);
            serde_json::to_string(&results).map_err(|e| e.to_string())
        }
        "get_node_details" => {
            let node_id = tool_call
                .params
                .get("node_id")
                .and_then(|v| v.as_str())
                .unwrap_or("");
            match graph.get_node_details(node_id) {
                Some(details) => serde_json::to_string(&details).map_err(|e| e.to_string()),
                None => Err(format!("Entity not found: {node_id}")),
            }
        }
        "expand_node" => {
            let node_id = tool_call
                .params
                .get("node_id")
                .and_then(|v| v.as_str())
                .unwrap_or("");
            let max_hops = tool_call
                .params
                .get("max_hops")
                .and_then(|v| v.as_u64())
                .unwrap_or(2) as usize;
            let max_nodes = tool_call
                .params
                .get("max_nodes")
                .and_then(|v| v.as_u64())
                .unwrap_or(50) as usize;
            match graph.get_neighborhood(node_id, max_hops, max_nodes, None) {
                Some(hood) => serde_json::to_string(&hood).map_err(|e| e.to_string()),
                None => Err(format!("Entity not found: {node_id}")),
            }
        }
        "run_hunt" => {
            // Gate: reject hunts while the session is Loading or Finalizing,
            // mirroring `ensure_huntable_phase` used by every HTTP hunt path.
            if let Err(e) = crate::operations::hunt::ensure_huntable_phase(phase) {
                return ai::ToolResult {
                    tool: tool_call.tool.clone(),
                    success: false,
                    data: e.to_string(),
                };
            }
            let dsl = tool_call
                .params
                .get("hypothesis_dsl")
                .and_then(|v| v.as_str())
                .unwrap_or("");
            match parse_dsl(dsl, Some("AI")) {
                Ok(parsed) => {
                    match graph.search_temporal_pattern(&parsed.hypothesis, None, Some(100)) {
                        Ok((paths, truncated)) => {
                            let summary = serde_json::json!({
                                "path_count": paths.len(),
                                "truncated": truncated,
                                "paths": paths.iter().take(20).collect::<Vec<_>>(),
                            });
                            Ok(summary.to_string())
                        }
                        Err(e) => Err(format!("Hunt failed: {e}")),
                    }
                }
                Err(e) => Err(format!("Invalid DSL: {e}")),
            }
        }
        "get_graph_stats" => {
            let summary = graph.get_graph_summary();
            serde_json::to_string(&summary).map_err(|e| e.to_string())
        }
        other => Err(format!("Unknown tool: {other}")),
    };

    match result {
        Ok(mut data) => {
            if data.len() > 8000 {
                data.truncate(8000);
                data.push_str("...(truncated)");
            }
            ai::ToolResult {
                tool: tool_call.tool.clone(),
                success: true,
                data,
            }
        }
        Err(e) => ai::ToolResult {
            tool: tool_call.tool.clone(),
            success: false,
            data: e,
        },
    }
}

// Tiny extension on `ApiError` so `map_err(ApiError::Upstream_ai)`
// reads cleanly — the existing `Upstream` variant needs two fields,
// which is verbose when the service is always "ai-provider".
impl ApiError {
    #[allow(non_snake_case)]
    fn Upstream_ai(message: String) -> ApiError {
        ApiError::Upstream {
            service: "ai".into(),
            message,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state::SessionPhase;
    use graph_hunter_core::GraphHunter;
    use serde_json::json;

    fn run_hunt_tool_call(dsl: &str) -> ai::ToolCall {
        ai::ToolCall {
            tool: "run_hunt".to_string(),
            params: json!({ "hypothesis_dsl": dsl }),
        }
    }

    /// Gate: the AI `run_hunt` tool must be rejected when the session is
    /// in `Finalizing` phase. The result must be an error whose message
    /// indicates the session is not huntable.
    #[test]
    fn ai_run_hunt_rejected_while_finalizing() {
        let mut graph = GraphHunter::new();
        let tc = run_hunt_tool_call("User -[Auth]-> Host");
        let result = execute_ai_tool(&tc, &mut graph, SessionPhase::Finalizing);
        assert!(
            !result.success,
            "run_hunt should fail in Finalizing phase but returned success"
        );
        let msg = result.data.to_lowercase();
        assert!(
            msg.contains("finaliz") || msg.contains("loading"),
            "error message should mention finalizing/loading, got: {}",
            result.data
        );
    }

    /// Sanity: the AI `run_hunt` tool succeeds (no error from the gate)
    /// when the session is in `Ready` phase. The empty graph yields 0
    /// paths but does not error.
    #[test]
    fn ai_run_hunt_allowed_while_ready() {
        let mut graph = GraphHunter::new();
        let tc = run_hunt_tool_call("User -[Auth]-> Host");
        let result = execute_ai_tool(&tc, &mut graph, SessionPhase::Ready);
        // On an empty graph the hunt succeeds with 0 paths.
        assert!(
            result.success,
            "run_hunt should succeed in Ready phase, got: {}",
            result.data
        );
    }
}
