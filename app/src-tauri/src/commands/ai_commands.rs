use std::sync::Arc;

use graph_hunter_core::{GraphHunter, parse_dsl};
use tauri::State;

use crate::ai;
use crate::helpers::{parse_entity_type, with_current_graph, with_current_graph_mut};
use crate::state::AppState;
use crate::types::DslResult;

/// Get the AI config from AppState (set by user) or None for env fallback.
pub(crate) fn get_ai_config(state: &AppState) -> Option<ai::ProviderConfig> {
    state.ai_config.read().ok().and_then(|g| g.clone())
}

/// Check AI configuration: is API key set, which provider/model/base_url.
#[tauri::command]
pub fn cmd_ai_check_config(state: State<Arc<AppState>>) -> ai::AiConfig {
    let cfg = get_ai_config(state.as_ref());
    ai::check_config(cfg.as_ref())
}

/// Set the AI API key in AppState (legacy, for backward compat — defaults to OpenAI).
#[tauri::command]
pub fn cmd_ai_set_key(state: State<Arc<AppState>>, key: String) -> Result<(), String> {
    let mut guard = state.ai_config.write().map_err(|e| format!("Lock poisoned: {}", e))?;
    if key.trim().is_empty() {
        *guard = None;
    } else {
        *guard = Some(ai::ProviderConfig {
            provider: ai::AiProvider::OpenAI,
            api_key: key.trim().to_string(),
            model: None,
            base_url: None,
        });
    }
    Ok(())
}

/// Set the AI provider configuration (provider, api_key, model, base_url).
/// Pass provider="auto" or "" to auto-detect from API key format.
/// Returns the detected provider name.
#[tauri::command]
pub fn cmd_ai_set_provider(
    state: State<Arc<AppState>>,
    provider: String,
    api_key: String,
    model: Option<String>,
    base_url: Option<String>,
) -> Result<String, String> {
    let mut guard = state.ai_config.write().map_err(|e| format!("Lock poisoned: {}", e))?;
    if api_key.trim().is_empty() {
        *guard = None;
        return Ok("none".to_string());
    }
    let ai_provider = match provider.to_lowercase().as_str() {
        "auto" | "" => {
            ai::detect_provider(&api_key)
                .ok_or_else(|| "Could not detect provider from API key format. Please select a provider manually.".to_string())?
        }
        "openai" => ai::AiProvider::OpenAI,
        "anthropic" => ai::AiProvider::Anthropic,
        "google" => ai::AiProvider::Google,
        other => return Err(format!("Unknown provider: '{}'. Use 'openai', 'anthropic', or 'google'.", other)),
    };
    let provider_name = ai_provider.to_string();
    *guard = Some(ai::ProviderConfig {
        provider: ai_provider,
        api_key: api_key.trim().to_string(),
        model,
        base_url,
    });
    Ok(provider_name)
}

/// Propose a hypothesis from a natural-language situation.
#[tauri::command]
pub async fn cmd_ai_propose_hypothesis(state: State<'_, Arc<AppState>>, situation: String) -> Result<DslResult, String> {
    let cfg = get_ai_config(state.as_ref());
    let result = ai::propose_hypothesis(&situation, cfg.as_ref()).await?;
    Ok(DslResult {
        hypothesis: result.hypothesis,
        formatted: result.formatted,
    })
}

/// Analyze the current subgraph (one-shot, no history). Returns structured response.
#[tauri::command]
pub async fn cmd_ai_analyze_graph(
    state: State<'_, Arc<AppState>>,
    nodes_json: String,
    edges_json: String,
    selected_node_id: Option<String>,
    question_override: Option<String>,
) -> Result<ai::AiAnalysisResponse, String> {
    let cfg = get_ai_config(state.as_ref());
    ai::analyze_graph(
        &nodes_json,
        &edges_json,
        selected_node_id,
        question_override,
        cfg.as_ref(),
    )
    .await
}

/// Analyze subgraph with conversation history (chat-style). Maintains context.
#[tauri::command]
pub async fn cmd_ai_analyze_graph_conversation(
    state: State<'_, Arc<AppState>>,
    nodes_json: String,
    edges_json: String,
    selected_node_id: Option<String>,
    user_message: String,
) -> Result<ai::AiAnalysisResponse, String> {
    let cfg = get_ai_config(state.as_ref());

    let conversation = state.ai_conversation.read()
        .map_err(|e| format!("Lock poisoned: {}", e))?
        .clone();

    let (raw_response, parsed) = ai::analyze_graph_conversation(
        &nodes_json,
        &edges_json,
        selected_node_id.as_deref(),
        &user_message,
        &conversation,
        cfg.as_ref(),
    )
    .await?;

    // Update conversation history
    {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as i64;

        let mut conv = state.ai_conversation.write()
            .map_err(|e| format!("Lock poisoned: {}", e))?;

        conv.messages.push(ai::ConversationMessage {
            role: "user".to_string(),
            content: user_message,
            timestamp: now,
        });
        conv.messages.push(ai::ConversationMessage {
            role: "assistant".to_string(),
            content: raw_response,
            timestamp: now,
        });

        // Auto-summarize when conversation gets long (>10 messages)
        if conv.messages.len() > 10 {
            let drain_end = conv.messages.len() - 4;
            let old_messages: Vec<ai::ConversationMessage> =
                conv.messages.drain(..drain_end).collect();
            let summary_parts: Vec<String> = old_messages.iter()
                .map(|m| format!("[{}]: {}", m.role,
                    if m.content.len() > 200 { format!("{}...", &m.content[..200]) } else { m.content.clone() }
                ))
                .collect();
            conv.context_summary = Some(summary_parts.join("\n"));
        }
    }

    Ok(parsed)
}

/// Execute a single AI tool call against the graph.
pub(crate) fn execute_ai_tool(tool_call: &ai::ToolCall, graph: &mut GraphHunter) -> ai::ToolResult {
    let result: Result<String, String> = match tool_call.tool.as_str() {
        "search_entities" => {
            let query = tool_call.params.get("query")
                .and_then(|v| v.as_str())
                .unwrap_or("");
            let type_filter = tool_call.params.get("entity_type")
                .and_then(|v| v.as_str())
                .and_then(parse_entity_type);
            let limit = tool_call.params.get("limit")
                .and_then(|v| v.as_u64())
                .unwrap_or(20) as usize;
            let results = graph.search_entities(query, type_filter.as_ref(), limit);
            serde_json::to_string(&results).map_err(|e| e.to_string())
        }
        "get_node_details" => {
            let node_id = tool_call.params.get("node_id")
                .and_then(|v| v.as_str())
                .unwrap_or("");
            match graph.get_node_details(node_id) {
                Some(details) => serde_json::to_string(&details).map_err(|e| e.to_string()),
                None => Err(format!("Entity not found: {}", node_id)),
            }
        }
        "expand_node" => {
            let node_id = tool_call.params.get("node_id")
                .and_then(|v| v.as_str())
                .unwrap_or("");
            let max_hops = tool_call.params.get("max_hops")
                .and_then(|v| v.as_u64())
                .unwrap_or(2) as usize;
            let max_nodes = tool_call.params.get("max_nodes")
                .and_then(|v| v.as_u64())
                .unwrap_or(50) as usize;
            match graph.get_neighborhood(node_id, max_hops, max_nodes, None) {
                Some(hood) => serde_json::to_string(&hood).map_err(|e| e.to_string()),
                None => Err(format!("Entity not found: {}", node_id)),
            }
        }
        "run_hunt" => {
            let dsl = tool_call.params.get("hypothesis_dsl")
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
                        Err(e) => Err(format!("Hunt failed: {}", e)),
                    }
                }
                Err(e) => Err(format!("Invalid DSL: {}", e)),
            }
        }
        "get_graph_stats" => {
            let summary = graph.get_graph_summary();
            serde_json::to_string(&summary).map_err(|e| e.to_string())
        }
        other => Err(format!("Unknown tool: {}", other)),
    };

    match result {
        Ok(mut data) => {
            // Truncate large results to prevent context overflow
            if data.len() > 8000 {
                data.truncate(8000);
                data.push_str("...(truncated)");
            }
            ai::ToolResult { tool: tool_call.tool.clone(), success: true, data }
        }
        Err(e) => ai::ToolResult { tool: tool_call.tool.clone(), success: false, data: e },
    }
}

/// Build a short graph stats string for the agentic system prompt.
pub(crate) fn build_graph_stats_for_prompt(graph: &GraphHunter) -> String {
    let summary = graph.get_graph_summary();
    let mut parts = vec![
        format!("{} entities, {} relations", summary.entity_count, summary.relation_count),
    ];
    if !summary.type_distribution.is_empty() {
        let types: Vec<String> = summary.type_distribution.iter()
            .map(|t| format!("{}: {}", t.entity_type, t.count))
            .collect();
        parts.push(format!("Types: {}", types.join(", ")));
    }
    if let Some((min, max)) = summary.time_range {
        parts.push(format!("Time range: {} to {}", min, max));
    }
    if !summary.top_anomalies.is_empty() {
        let top: Vec<String> = summary.top_anomalies.iter().take(5)
            .map(|a| format!("{} ({}, score={:.2})", a.id, a.entity_type, a.score))
            .collect();
        parts.push(format!("Top anomalies: {}", top.join("; ")));
    }
    parts.join("\n")
}

/// Agentic AI chat: LLM can call tools in a loop to query the graph.
#[tauri::command]
pub async fn cmd_ai_chat(
    state: State<'_, Arc<AppState>>,
    user_message: String,
) -> Result<ai::AiAnalysisResponse, String> {
    let cfg = get_ai_config(state.as_ref())
        .ok_or_else(|| "No AI provider configured. Set API key in AI Settings.".to_string())?;
    let resolved_cfg = ai::resolve_config(Some(&cfg))?;

    // Build graph stats (read lock, release immediately)
    let graph_stats = with_current_graph(state.as_ref(), |graph| {
        Ok(build_graph_stats_for_prompt(graph))
    })?;

    let system_prompt = ai::build_agentic_system_prompt(&graph_stats);

    // Load conversation history
    let conversation = state.ai_conversation.read()
        .map_err(|e| format!("Lock poisoned: {}", e))?
        .clone();

    let mut working_history = ai::build_messages_with_history(&conversation, &user_message);

    let mut final_response = String::new();
    const MAX_ITERATIONS: usize = 5;

    for _iteration in 0..MAX_ITERATIONS {
        // Call LLM (no locks held during this call)
        let raw = ai::call_llm_with_history(
            &resolved_cfg,
            &system_prompt,
            &working_history,
            Some(16384),
        ).await?;

        // Parse tool calls
        let tool_calls = ai::parse_tool_calls(&raw);

        if tool_calls.is_empty() {
            // No tools → this is the final answer
            final_response = raw;
            break;
        }

        // Execute tools (brief write lock per tool)
        let mut tool_results: Vec<ai::ToolResult> = Vec::new();
        for tc in &tool_calls {
            let result = with_current_graph_mut(state.as_ref(), |graph| {
                Ok(execute_ai_tool(tc, graph))
            })?;
            tool_results.push(result);
        }

        // Append assistant response + tool results to working history
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as i64;

        working_history.push(ai::ConversationMessage {
            role: "assistant".to_string(),
            content: raw,
            timestamp: now,
        });

        let tool_results_text = tool_results.iter()
            .map(|r| {
                if r.success {
                    format!("Tool `{}` result:\n{}", r.tool, r.data)
                } else {
                    format!("Tool `{}` error: {}", r.tool, r.data)
                }
            })
            .collect::<Vec<_>>()
            .join("\n\n");

        working_history.push(ai::ConversationMessage {
            role: "user".to_string(),
            content: format!("[Tool Results]\n{}", tool_results_text),
            timestamp: now,
        });

        // If this is the last iteration, set the raw as final response
        if _iteration == MAX_ITERATIONS - 1 {
            // Force one more call without expecting tools
            let final_raw = ai::call_llm_with_history(
                &resolved_cfg,
                &system_prompt,
                &working_history,
                Some(16384),
            ).await?;
            final_response = final_raw;
        }
    }

    // Parse the final response for suggestions
    let parsed = ai::parse_ai_response(&final_response);

    // Save only user message + final response to persistent conversation history
    {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as i64;

        let mut conv = state.ai_conversation.write()
            .map_err(|e| format!("Lock poisoned: {}", e))?;

        conv.messages.push(ai::ConversationMessage {
            role: "user".to_string(),
            content: user_message,
            timestamp: now,
        });
        conv.messages.push(ai::ConversationMessage {
            role: "assistant".to_string(),
            content: parsed.text.clone(),
            timestamp: now,
        });

        // Auto-summarize when conversation gets long
        if conv.messages.len() > 10 {
            let drain_end = conv.messages.len() - 4;
            let old_messages: Vec<ai::ConversationMessage> =
                conv.messages.drain(..drain_end).collect();
            let summary_parts: Vec<String> = old_messages.iter()
                .map(|m| format!("[{}]: {}", m.role,
                    if m.content.len() > 200 { format!("{}...", &m.content[..200]) } else { m.content.clone() }
                ))
                .collect();
            conv.context_summary = Some(summary_parts.join("\n"));
        }
    }

    Ok(parsed)
}

/// Clear the AI conversation history.
#[tauri::command]
pub fn cmd_ai_clear_conversation(state: State<Arc<AppState>>) -> Result<(), String> {
    let mut conv = state.ai_conversation.write()
        .map_err(|e| format!("Lock poisoned: {}", e))?;
    conv.clear();
    Ok(())
}

/// Get the current AI conversation messages (for frontend display).
#[tauri::command]
pub fn cmd_ai_get_conversation(state: State<Arc<AppState>>) -> Result<Vec<ai::ConversationMessage>, String> {
    let conv = state.ai_conversation.read()
        .map_err(|e| format!("Lock poisoned: {}", e))?;
    Ok(conv.messages.clone())
}
