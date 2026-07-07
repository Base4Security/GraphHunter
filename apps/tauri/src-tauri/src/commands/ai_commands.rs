//! AI commands — all 9 delegate to the canonical API.
//!
//! The per-session conversation fix from the feedback lives in the
//! API: `Session` now owns `ai_conversation`, so switching sessions
//! yields clean history. Commands that touch conversation state thus
//! require a current session (`ApiError::NoCurrentSession` when
//! missing).

use std::sync::Arc;

use tauri::State;

use graph_hunter_api::ai;
use graph_hunter_api::dto::ai::{
    AiChatRequest, AiConversationScope, AnalyzeGraphConversationRequest, AnalyzeGraphRequest,
    ProposeHypothesisRequest, SetAiKeyRequest, SetAiProviderRequest,
};
use graph_hunter_api::GraphHunterApi;

use crate::error::CommandError;
use crate::types::DslResult;

#[tauri::command]
pub fn cmd_ai_check_config(api: State<Arc<GraphHunterApi>>) -> ai::AiConfig {
    api.ai_check_config()
}

#[tauri::command]
pub fn cmd_ai_set_key(
    api: State<Arc<GraphHunterApi>>,
    key: String,
) -> Result<(), CommandError> {
    api.ai_set_key(SetAiKeyRequest { key })
        .map_err(CommandError::from)
}

#[tauri::command]
pub fn cmd_ai_set_provider(
    api: State<Arc<GraphHunterApi>>,
    provider: String,
    api_key: String,
    model: Option<String>,
    base_url: Option<String>,
) -> Result<String, CommandError> {
    api.ai_set_provider(SetAiProviderRequest {
        provider,
        api_key,
        model,
        base_url,
    })
    .map_err(CommandError::from)
}

/// Propose a hypothesis from a natural-language situation.
#[tauri::command]
pub async fn cmd_ai_propose_hypothesis(
    api: State<'_, Arc<GraphHunterApi>>,
    situation: String,
) -> Result<DslResult, CommandError> {
    let resp = api
        .ai_propose_hypothesis(ProposeHypothesisRequest { situation })
        .await
        .map_err(CommandError::from)?;
    Ok(DslResult {
        hypothesis: resp.hypothesis,
        formatted: resp.formatted,
    })
}

/// One-shot subgraph analysis (no history).
#[tauri::command]
pub async fn cmd_ai_analyze_graph(
    api: State<'_, Arc<GraphHunterApi>>,
    nodes_json: String,
    edges_json: String,
    selected_node_id: Option<String>,
    question_override: Option<String>,
) -> Result<ai::AiAnalysisResponse, CommandError> {
    api.ai_analyze_graph(AnalyzeGraphRequest {
        nodes_json,
        edges_json,
        selected_node_id,
        question_override,
    })
    .await
    .map_err(CommandError::from)
}

/// Chat-style analysis with per-session conversation history.
#[tauri::command]
pub async fn cmd_ai_analyze_graph_conversation(
    api: State<'_, Arc<GraphHunterApi>>,
    nodes_json: String,
    edges_json: String,
    selected_node_id: Option<String>,
    user_message: String,
) -> Result<ai::AiAnalysisResponse, CommandError> {
    api.ai_analyze_graph_conversation(AnalyzeGraphConversationRequest {
        session: None,
        nodes_json,
        edges_json,
        selected_node_id,
        user_message,
    })
    .await
    .map_err(CommandError::from)
}

/// Agentic AI chat with tool-calling loop.
#[tauri::command]
pub async fn cmd_ai_chat(
    api: State<'_, Arc<GraphHunterApi>>,
    user_message: String,
) -> Result<ai::AiAnalysisResponse, CommandError> {
    api.ai_chat(AiChatRequest {
        session: None,
        user_message,
    })
    .await
    .map_err(CommandError::from)
}

/// Clear the current session's AI conversation history.
#[tauri::command]
pub fn cmd_ai_clear_conversation(api: State<Arc<GraphHunterApi>>) -> Result<(), CommandError> {
    api.ai_clear_conversation(AiConversationScope::default())
        .map_err(CommandError::from)
}

/// Current session's conversation messages (for frontend display).
#[tauri::command]
pub fn cmd_ai_get_conversation(
    api: State<Arc<GraphHunterApi>>,
) -> Result<Vec<ai::ConversationMessage>, CommandError> {
    api.ai_get_conversation(AiConversationScope::default())
        .map_err(CommandError::from)
}
