//! DTOs for the 9 AI commands.
//!
//! `ai_config` is global (set once per process via UI or env var
//! fallback). `ai_conversation` is per-session — the bug documented
//! in the feedback ("switching sessions reused history") is fixed by
//! moving the conversation slot into [`crate::state::Session`].

use crate::state::SessionHandle;
use serde::{Deserialize, Serialize};

// ── Config (global) ────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SetAiKeyRequest {
    pub key: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SetAiProviderRequest {
    /// `"openai"` | `"anthropic"` | `"google"` | `"auto"` | `""`.
    pub provider: String,
    pub api_key: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub model: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub base_url: Option<String>,
}

// ── Conversation (per-session) ─────────────────────────────────────────

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct AiConversationScope {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session: Option<SessionHandle>,
}

// ── LLM calls ──────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProposeHypothesisRequest {
    pub situation: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnalyzeGraphRequest {
    pub nodes_json: String,
    pub edges_json: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub selected_node_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub question_override: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnalyzeGraphConversationRequest {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session: Option<SessionHandle>,
    pub nodes_json: String,
    pub edges_json: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub selected_node_id: Option<String>,
    pub user_message: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AiChatRequest {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session: Option<SessionHandle>,
    pub user_message: String,
}

// Re-exports so transports can use the core types by their canonical
// api-crate path.
pub use crate::ai::{AiAnalysisResponse, AiConfig as AiConfigStatus};
#[allow(unused_imports)]
pub use crate::ai::{
    AiProvider as ReexportedAiProvider, ConversationMessage as ReexportedMessage,
    ProviderConfig as ReexportedProviderConfig,
};
