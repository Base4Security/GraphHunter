//! LLM integration for AI hypothesis proposal and graph analysis.
//! Supports multiple providers: OpenAI, Anthropic, Google.

use graph_hunter_core::{parse_dsl, DslParseResult};
use serde::{Deserialize, Serialize};
use serde_json::Value;

// ── Tool call types (agentic loop) ──

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolCall {
    pub tool: String,
    pub params: Value,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolResult {
    pub tool: String,
    pub success: bool,
    pub data: String,
}

/// Parse tool calls from LLM response. Extracts `{"tool":..., "params":...}` from fenced JSON blocks.
pub fn parse_tool_calls(response: &str) -> Vec<ToolCall> {
    let mut calls = Vec::new();
    let mut search_from = 0;
    while let Some(start) = response[search_from..].find("```json") {
        let abs_start = search_from + start + 7;
        if let Some(end) = response[abs_start..].find("```") {
            let block = response[abs_start..abs_start + end].trim();
            if let Ok(val) = serde_json::from_str::<Value>(block) {
                if val.get("tool").is_some() {
                    if let Ok(tc) = serde_json::from_value::<ToolCall>(val) {
                        calls.push(tc);
                    }
                }
            }
            search_from = abs_start + end + 3;
        } else {
            break;
        }
    }
    calls
}

/// Auto-detect AI provider from API key format.
pub fn detect_provider(api_key: &str) -> Option<AiProvider> {
    let key = api_key.trim();
    if key.starts_with("sk-ant-") {
        Some(AiProvider::Anthropic)
    } else if key.starts_with("sk-") {
        Some(AiProvider::OpenAI)
    } else if key.starts_with("AI") {
        Some(AiProvider::Google)
    } else {
        None
    }
}

// ── Provider types ──

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum AiProvider {
    OpenAI,
    Anthropic,
    Google,
}

impl std::fmt::Display for AiProvider {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AiProvider::OpenAI => write!(f, "OpenAI"),
            AiProvider::Anthropic => write!(f, "Anthropic"),
            AiProvider::Google => write!(f, "Google"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProviderConfig {
    pub provider: AiProvider,
    pub api_key: String,
    pub model: Option<String>,
    pub base_url: Option<String>,
}

impl ProviderConfig {
    fn effective_model(&self) -> String {
        if let Some(ref m) = self.model {
            if !m.is_empty() {
                return m.clone();
            }
        }
        match self.provider {
            AiProvider::OpenAI => {
                std::env::var("OPENAI_MODEL").unwrap_or_else(|_| "gpt-4o".to_string())
            }
            AiProvider::Anthropic => "claude-sonnet-4-20250514".to_string(),
            AiProvider::Google => "gemini-2.0-flash".to_string(),
        }
    }

    fn effective_base_url(&self) -> String {
        if let Some(ref u) = self.base_url {
            if !u.is_empty() {
                return u.clone();
            }
        }
        match self.provider {
            AiProvider::OpenAI => {
                std::env::var("OPENAI_API_BASE")
                    .unwrap_or_else(|_| "https://api.openai.com/v1".to_string())
            }
            AiProvider::Anthropic => "https://api.anthropic.com".to_string(),
            AiProvider::Google => "https://generativelanguage.googleapis.com".to_string(),
        }
    }
}

/// AI configuration info returned to the frontend.
#[derive(Serialize)]
pub struct AiConfig {
    pub api_key_set: bool,
    pub provider: Option<AiProvider>,
    pub model: String,
    pub base_url: String,
}

// ── Conversation types ──

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConversationMessage {
    pub role: String,     // "user" | "assistant" | "system"
    pub content: String,
    pub timestamp: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AiSuggestion {
    pub action: String,    // "expand_node" | "run_hypothesis"
    pub target_id: String,
    pub label: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AiAnalysisResponse {
    pub text: String,
    pub suggestions: Vec<AiSuggestion>,
}

#[derive(Clone)]
pub struct AiConversation {
    pub messages: Vec<ConversationMessage>,
    pub context_summary: Option<String>,
}

impl AiConversation {
    pub fn new() -> Self {
        Self {
            messages: Vec::new(),
            context_summary: None,
        }
    }

    pub fn clear(&mut self) {
        self.messages.clear();
        self.context_summary = None;
    }
}

// ── OpenAI types ──

#[derive(Debug, Serialize, Deserialize)]
struct OpenAiMessage {
    role: String,
    content: String,
}

#[derive(Debug, Deserialize)]
struct OpenAiChoice {
    message: OpenAiMessage,
}

#[derive(Debug, Serialize)]
struct OpenAiRequest {
    model: String,
    messages: Vec<OpenAiMessage>,
    #[serde(skip_serializing_if = "Option::is_none")]
    max_tokens: Option<u32>,
}

#[derive(Debug, Deserialize)]
struct OpenAiResponse {
    choices: Option<Vec<OpenAiChoice>>,
    error: Option<ApiError>,
}

// ── Anthropic types ──

#[derive(Debug, Serialize)]
struct AnthropicRequest {
    model: String,
    max_tokens: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    system: Option<String>,
    messages: Vec<AnthropicMessage>,
}

#[derive(Debug, Serialize, Deserialize)]
struct AnthropicMessage {
    role: String,
    content: String,
}

#[derive(Debug, Deserialize)]
struct AnthropicResponse {
    content: Option<Vec<AnthropicContent>>,
    error: Option<AnthropicError>,
}

#[derive(Debug, Deserialize)]
struct AnthropicContent {
    text: Option<String>,
}

#[derive(Debug, Deserialize)]
struct AnthropicError {
    message: String,
}

// ── Google types ──

#[derive(Debug, Serialize)]
struct GoogleRequest {
    #[serde(skip_serializing_if = "Option::is_none")]
    system_instruction: Option<GoogleSystemInstruction>,
    contents: Vec<GoogleContent>,
    #[serde(skip_serializing_if = "Option::is_none")]
    generation_config: Option<GoogleGenerationConfig>,
}

#[derive(Debug, Serialize)]
struct GoogleSystemInstruction {
    parts: Vec<GooglePart>,
}

#[derive(Debug, Serialize)]
struct GoogleContent {
    role: String,
    parts: Vec<GooglePart>,
}

#[derive(Debug, Serialize)]
struct GooglePart {
    text: String,
}

#[derive(Debug, Serialize)]
struct GoogleGenerationConfig {
    #[serde(skip_serializing_if = "Option::is_none")]
    max_output_tokens: Option<u32>,
}

#[derive(Debug, Deserialize)]
struct GoogleResponse {
    candidates: Option<Vec<GoogleCandidate>>,
    error: Option<GoogleError>,
}

#[derive(Debug, Deserialize)]
struct GoogleCandidate {
    content: Option<GoogleCandidateContent>,
}

#[derive(Debug, Deserialize)]
struct GoogleCandidateContent {
    parts: Option<Vec<GoogleResponsePart>>,
}

#[derive(Debug, Deserialize)]
struct GoogleResponsePart {
    text: Option<String>,
}

#[derive(Debug, Deserialize)]
struct GoogleError {
    message: String,
}

// ── Shared ──

#[derive(Debug, Deserialize)]
struct ApiError {
    message: String,
}

// ── Provider resolution ──

/// Try to build a ProviderConfig from env vars alone (no explicit config).
fn config_from_env() -> Option<ProviderConfig> {
    // Try OpenAI first, then Anthropic, then Google
    if let Ok(key) = std::env::var("OPENAI_API_KEY") {
        if !key.is_empty() {
            return Some(ProviderConfig {
                provider: AiProvider::OpenAI,
                api_key: key,
                model: std::env::var("OPENAI_MODEL").ok(),
                base_url: std::env::var("OPENAI_API_BASE").ok(),
            });
        }
    }
    if let Ok(key) = std::env::var("ANTHROPIC_API_KEY") {
        if !key.is_empty() {
            return Some(ProviderConfig {
                provider: AiProvider::Anthropic,
                api_key: key,
                model: None,
                base_url: None,
            });
        }
    }
    if let Ok(key) = std::env::var("GOOGLE_AI_KEY") {
        if !key.is_empty() {
            return Some(ProviderConfig {
                provider: AiProvider::Google,
                api_key: key,
                model: None,
                base_url: None,
            });
        }
    }
    None
}

/// Resolve effective config: explicit config first, then env fallback.
pub fn resolve_config(explicit: Option<&ProviderConfig>) -> Result<ProviderConfig, String> {
    if let Some(cfg) = explicit {
        if !cfg.api_key.is_empty() {
            return Ok(cfg.clone());
        }
    }
    config_from_env().ok_or_else(|| {
        "No AI provider configured. Set API key in settings or via environment variables (OPENAI_API_KEY, ANTHROPIC_API_KEY, or GOOGLE_AI_KEY).".to_string()
    })
}

/// Check if an AI provider is available (from explicit config or env).
pub fn check_config(explicit: Option<&ProviderConfig>) -> AiConfig {
    match resolve_config(explicit) {
        Ok(cfg) => AiConfig {
            api_key_set: true,
            provider: Some(cfg.provider.clone()),
            model: cfg.effective_model(),
            base_url: cfg.effective_base_url(),
        },
        Err(_) => AiConfig {
            api_key_set: false,
            provider: None,
            model: String::new(),
            base_url: String::new(),
        },
    }
}

// ── Provider-specific call functions ──

async fn call_openai(
    config: &ProviderConfig,
    messages: Vec<OpenAiMessage>,
    max_tokens: Option<u32>,
) -> Result<String, String> {
    let base_url = config.effective_base_url();
    let model = config.effective_model();
    let url = format!("{}/chat/completions", base_url.trim_end_matches('/'));

    let request = OpenAiRequest {
        model,
        messages,
        max_tokens: max_tokens.or(Some(4096)),
    };

    let client = reqwest::Client::new();
    let res = client
        .post(&url)
        .header("Authorization", format!("Bearer {}", config.api_key))
        .header("Content-Type", "application/json")
        .json(&request)
        .send()
        .await
        .map_err(|e| format!("Request failed: {}", e))?;

    let status = res.status();
    let body: OpenAiResponse = res
        .json()
        .await
        .map_err(|e| format!("Invalid response: {}", e))?;

    if let Some(err) = body.error {
        return Err(format!("API error: {}", err.message));
    }
    if !status.is_success() {
        return Err(format!("API returned status {}", status));
    }

    body.choices
        .and_then(|c| c.into_iter().next())
        .map(|c| c.message.content.trim().to_string())
        .ok_or_else(|| "No completion in response".to_string())
}

async fn call_anthropic(
    config: &ProviderConfig,
    system: Option<&str>,
    messages: Vec<AnthropicMessage>,
    max_tokens: Option<u32>,
) -> Result<String, String> {
    let base_url = config.effective_base_url();
    let model = config.effective_model();
    let url = format!("{}/v1/messages", base_url.trim_end_matches('/'));

    let request = AnthropicRequest {
        model,
        max_tokens: max_tokens.unwrap_or(4096),
        system: system.map(|s| s.to_string()),
        messages,
    };

    let client = reqwest::Client::new();
    let res = client
        .post(&url)
        .header("x-api-key", &config.api_key)
        .header("anthropic-version", "2023-06-01")
        .header("Content-Type", "application/json")
        .json(&request)
        .send()
        .await
        .map_err(|e| format!("Request failed: {}", e))?;

    let status = res.status();
    let body: AnthropicResponse = res
        .json()
        .await
        .map_err(|e| format!("Invalid response: {}", e))?;

    if let Some(err) = body.error {
        return Err(format!("API error: {}", err.message));
    }
    if !status.is_success() {
        return Err(format!("API returned status {}", status));
    }

    body.content
        .and_then(|c| c.into_iter().next())
        .and_then(|c| c.text)
        .map(|t| t.trim().to_string())
        .ok_or_else(|| "No content in response".to_string())
}

async fn call_google(
    config: &ProviderConfig,
    system: Option<&str>,
    messages: Vec<GoogleContent>,
    max_tokens: Option<u32>,
) -> Result<String, String> {
    let base_url = config.effective_base_url();
    let model = config.effective_model();
    let url = format!(
        "{}/v1beta/models/{}:generateContent?key={}",
        base_url.trim_end_matches('/'),
        model,
        config.api_key
    );

    let request = GoogleRequest {
        system_instruction: system.map(|s| GoogleSystemInstruction {
            parts: vec![GooglePart { text: s.to_string() }],
        }),
        contents: messages,
        generation_config: max_tokens.map(|t| GoogleGenerationConfig {
            max_output_tokens: Some(t),
        }),
    };

    let client = reqwest::Client::new();
    let res = client
        .post(&url)
        .header("Content-Type", "application/json")
        .json(&request)
        .send()
        .await
        .map_err(|e| format!("Request failed: {}", e))?;

    let status = res.status();
    let body: GoogleResponse = res
        .json()
        .await
        .map_err(|e| format!("Invalid response: {}", e))?;

    if let Some(err) = body.error {
        return Err(format!("API error: {}", err.message));
    }
    if !status.is_success() {
        return Err(format!("API returned status {}", status));
    }

    body.candidates
        .and_then(|c| c.into_iter().next())
        .and_then(|c| c.content)
        .and_then(|c| c.parts)
        .and_then(|p| p.into_iter().next())
        .and_then(|p| p.text)
        .map(|t| t.trim().to_string())
        .ok_or_else(|| "No content in response".to_string())
}

// ── Unified LLM call dispatch ──

/// Call the configured LLM provider with system + user message.
pub async fn call_llm_provider(
    config: &ProviderConfig,
    system: &str,
    user: &str,
    max_tokens: Option<u32>,
) -> Result<String, String> {
    match config.provider {
        AiProvider::OpenAI => {
            let messages = vec![
                OpenAiMessage { role: "system".to_string(), content: system.to_string() },
                OpenAiMessage { role: "user".to_string(), content: user.to_string() },
            ];
            call_openai(config, messages, max_tokens).await
        }
        AiProvider::Anthropic => {
            let messages = vec![
                AnthropicMessage { role: "user".to_string(), content: user.to_string() },
            ];
            call_anthropic(config, Some(system), messages, max_tokens).await
        }
        AiProvider::Google => {
            let messages = vec![
                GoogleContent {
                    role: "user".to_string(),
                    parts: vec![GooglePart { text: user.to_string() }],
                },
            ];
            call_google(config, Some(system), messages, max_tokens).await
        }
    }
}

/// Call the configured LLM with full conversation history (for chat-style interactions).
pub async fn call_llm_with_history(
    config: &ProviderConfig,
    system: &str,
    history: &[ConversationMessage],
    max_tokens: Option<u32>,
) -> Result<String, String> {
    match config.provider {
        AiProvider::OpenAI => {
            let mut messages = vec![
                OpenAiMessage { role: "system".to_string(), content: system.to_string() },
            ];
            for msg in history {
                messages.push(OpenAiMessage {
                    role: msg.role.clone(),
                    content: msg.content.clone(),
                });
            }
            call_openai(config, messages, max_tokens).await
        }
        AiProvider::Anthropic => {
            let messages: Vec<AnthropicMessage> = history
                .iter()
                .map(|m| AnthropicMessage {
                    role: m.role.clone(),
                    content: m.content.clone(),
                })
                .collect();
            call_anthropic(config, Some(system), messages, max_tokens).await
        }
        AiProvider::Google => {
            let messages: Vec<GoogleContent> = history
                .iter()
                .map(|m| GoogleContent {
                    role: if m.role == "assistant" { "model".to_string() } else { m.role.clone() },
                    parts: vec![GooglePart { text: m.content.clone() }],
                })
                .collect();
            call_google(config, Some(system), messages, max_tokens).await
        }
    }
}

// ── Subgraph context compression ──

/// Compress subgraph context for AI prompts. If small enough, serialize fully;
/// otherwise generate a statistical summary.
pub fn compress_subgraph_context(
    nodes_json: &str,
    edges_json: &str,
    selected_node_id: Option<&str>,
) -> String {
    // Rough token estimate: 1 token ~ 4 chars
    let estimated_tokens = (nodes_json.len() + edges_json.len()) / 4;

    if estimated_tokens < 2000 {
        // Small enough to include fully
        let mut ctx = format!("Nodes:\n{}\n\nEdges:\n{}", nodes_json, edges_json);
        if let Some(id) = selected_node_id {
            ctx.push_str(&format!("\n\nSelected/focused node: {}", id));
        }
        return ctx;
    }

    // Large subgraph: generate summary
    let mut summary = String::new();

    // Parse nodes for stats
    if let Ok(nodes) = serde_json::from_str::<Vec<serde_json::Value>>(nodes_json) {
        let total_nodes = nodes.len();
        let mut type_counts: std::collections::HashMap<String, usize> = std::collections::HashMap::new();
        let mut top_scores: Vec<(String, f64)> = Vec::new();

        for node in &nodes {
            if let Some(et) = node.get("entity_type").and_then(|v| v.as_str()) {
                *type_counts.entry(et.to_string()).or_insert(0) += 1;
            }
            if let (Some(id), Some(score)) = (
                node.get("id").and_then(|v| v.as_str()),
                node.get("score").and_then(|v| v.as_f64()),
            ) {
                top_scores.push((id.to_string(), score));
            }
        }
        top_scores.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal));
        top_scores.truncate(10);

        summary.push_str(&format!("Subgraph summary: {} nodes\n", total_nodes));
        summary.push_str("Node types: ");
        let type_strs: Vec<String> = type_counts.iter().map(|(t, c)| format!("{}:{}", t, c)).collect();
        summary.push_str(&type_strs.join(", "));
        summary.push('\n');

        if !top_scores.is_empty() {
            summary.push_str("Top scoring nodes:\n");
            for (id, score) in &top_scores {
                let display = if id.len() > 40 { &id[..40] } else { id };
                summary.push_str(&format!("  {} (score: {:.2})\n", display, score));
            }
        }
    }

    // Parse edges for stats
    if let Ok(edges) = serde_json::from_str::<Vec<serde_json::Value>>(edges_json) {
        let total_edges = edges.len();
        let mut rel_counts: std::collections::HashMap<String, usize> = std::collections::HashMap::new();
        let mut min_ts: Option<i64> = None;
        let mut max_ts: Option<i64> = None;

        for edge in &edges {
            if let Some(rt) = edge.get("rel_type").and_then(|v| v.as_str()) {
                *rel_counts.entry(rt.to_string()).or_insert(0) += 1;
            }
            if let Some(ts) = edge.get("timestamp").and_then(|v| v.as_i64()) {
                min_ts = Some(min_ts.map_or(ts, |m: i64| m.min(ts)));
                max_ts = Some(max_ts.map_or(ts, |m: i64| m.max(ts)));
            }
        }

        summary.push_str(&format!("Edges: {}\n", total_edges));
        summary.push_str("Edge types: ");
        let rel_strs: Vec<String> = rel_counts.iter().map(|(t, c)| format!("{}:{}", t, c)).collect();
        summary.push_str(&rel_strs.join(", "));
        summary.push('\n');

        if let (Some(min), Some(max)) = (min_ts, max_ts) {
            summary.push_str(&format!("Time range: {} to {}\n", min, max));
        }
    }

    if let Some(id) = selected_node_id {
        summary.push_str(&format!("\nSelected/focused node: {}", id));
    }

    summary
}

// ── Response parsing ──

/// Parse AI response to extract text and structured suggestions.
pub fn parse_ai_response(raw: &str) -> AiAnalysisResponse {
    let mut text = raw.to_string();
    let mut suggestions: Vec<AiSuggestion> = Vec::new();

    // Try to find a ```json block at the end of the response
    if let Some(json_start) = raw.rfind("```json") {
        let after = &raw[json_start + 7..];
        let json_end = after.find("```").unwrap_or(after.len());
        let json_block = after[..json_end].trim();

        if let Ok(parsed) = serde_json::from_str::<serde_json::Value>(json_block) {
            if let Some(arr) = parsed.get("suggestions").and_then(|v| v.as_array()) {
                for item in arr {
                    if let (Some(action), Some(target_id), Some(label)) = (
                        item.get("action").and_then(|v| v.as_str()),
                        item.get("target_id").and_then(|v| v.as_str()),
                        item.get("label").and_then(|v| v.as_str()),
                    ) {
                        suggestions.push(AiSuggestion {
                            action: action.to_string(),
                            target_id: target_id.to_string(),
                            label: label.to_string(),
                        });
                    }
                }
            }
            // Remove the JSON block from the display text
            text = raw[..json_start].trim().to_string();
        }
    }

    AiAnalysisResponse { text, suggestions }
}

// ── Conversation history management ──

/// Build messages for LLM call with sliding window history.
/// Keeps recent messages within ~3000 token budget.
pub fn build_messages_with_history(
    conversation: &AiConversation,
    new_user_message: &str,
) -> Vec<ConversationMessage> {
    const MAX_HISTORY_CHARS: usize = 12_000; // ~3000 tokens

    let mut result: Vec<ConversationMessage> = Vec::new();
    let mut chars_used = 0usize;

    // Include context_summary if we have one and there are old messages
    if let Some(ref summary) = conversation.context_summary {
        result.push(ConversationMessage {
            role: "system".to_string(),
            content: format!("Previous conversation summary: {}", summary),
            timestamp: 0,
        });
    }

    // Walk backward through history to fit within budget
    let mut included_msgs: Vec<&ConversationMessage> = Vec::new();
    for msg in conversation.messages.iter().rev() {
        let msg_chars = msg.content.len();
        if chars_used + msg_chars > MAX_HISTORY_CHARS {
            break;
        }
        chars_used += msg_chars;
        included_msgs.push(msg);
    }
    included_msgs.reverse();

    for msg in included_msgs {
        result.push(msg.clone());
    }

    // Add the new user message
    result.push(ConversationMessage {
        role: "user".to_string(),
        content: new_user_message.to_string(),
        timestamp: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as i64,
    });

    result
}

// ── Prompt builders ──

/// Build system + user prompt for proposing a hypothesis from a situation description.
fn build_hypothesis_prompt(situation: &str) -> (String, String) {
    let system = r#"You are a threat hunting expert. Your task is to propose a single hypothesis chain in GraphHunter DSL format.

DSL format: a sequence of entity types linked by relation types, like:
  EntityType -[RelationType]-> EntityType -[RelationType]-> EntityType ...

Entity types (use exactly these): IP, Host, User, Process, File, Domain, Registry, URL, Service. You may use * for "any".
Relation types (use exactly these): Auth, Connect, Execute, Read, Write, DNS, Modify, Spawn, Delete. You may use * for "any".

Examples:
- IP -[Connect]-> Host -[Auth]-> User -[Execute]-> Process
- User -[Execute]-> Process -[Spawn]-> Process
- Host -[Connect]-> Domain -[DNS]-> *

IMPORTANT: Respond with ONLY the hypothesis chain on a single line using the exact DSL syntax shown above. No explanation, no markdown, no code blocks. Use ASCII characters only (hyphen-bracket-arrow: -[Type]->)."#.to_string();

    let user = format!(
        "Propose a single hypothesis chain (one line of DSL) for this scenario: {}",
        situation
    );

    (system, user)
}

/// Build system prompt for analyzing a subgraph with conversation support.
fn build_analyze_system_prompt() -> String {
    r#"You are a security analyst. You are given a subgraph (nodes and edges) from a telemetry graph. Nodes are entities (IP, Host, User, Process, File, etc.); edges are relations (Connect, Execute, Auth, etc.) with timestamps.

Answer concisely:
1. Does anything in this subgraph look malicious or suspicious? Why?
2. Which node(s) should we expand next (check neighbors) to look for malicious or suspicious activity?

Use markdown for readability. Be specific about node IDs or types when suggesting what to explore next.

At the end of your analysis, include a JSON block with actionable suggestions in this exact format:
```json
{"suggestions": [{"action": "expand_node", "target_id": "exact-node-id", "label": "Expand this node to see connections"}]}
```
Valid actions: "expand_node" (explore a node's neighbors), "run_hypothesis" (run a DSL pattern like "User -[Execute]-> Process -[Spawn]-> Process").
Only include suggestions you are confident about. The JSON block must be the last thing in your response."#.to_string()
}

/// Build the user message for graph analysis.
fn build_analyze_user_message(
    context: &str,
    question_override: Option<&str>,
) -> String {
    let mut user = context.to_string();
    if let Some(q) = question_override {
        user.push_str(&format!("\n\nAdditional question: {}", q));
    } else {
        user.push_str("\n\nAnalyze this subgraph and answer the questions above.");
    }
    user
}

/// Extract and clean a DSL line from LLM text output.
fn extract_dsl_line(text: &str) -> Option<String> {
    let text = text.trim();
    let inner = if let Some(start) = text.find("```") {
        let after = &text[start + 3..];
        let end = after.find("```").unwrap_or(after.len());
        after[..end].trim()
    } else {
        text
    };

    for line in inner.lines() {
        let cleaned = line
            .trim()
            .replace('\u{2192}', "->")
            .replace('\u{2013}', "-")
            .replace('\u{2014}', "-")
            .replace('\u{200B}', "")
            .replace("\\_", "_");
        if cleaned.is_empty() {
            continue;
        }
        if parse_dsl(&cleaned, Some("AI")).is_ok() {
            return Some(cleaned);
        }
    }

    let cleaned = inner
        .replace('\u{2192}', "->")
        .replace('\u{2013}', "-")
        .replace('\u{2014}', "-")
        .replace('\u{200B}', "")
        .replace("\\_", "_");
    let single = cleaned.lines().next().unwrap_or("").trim();
    if !single.is_empty() && parse_dsl(single, Some("AI")).is_ok() {
        return Some(single.to_string());
    }

    None
}

// ── Agentic system prompt ──

/// Build the system prompt for the agentic AI chat with tool descriptions.
pub fn build_agentic_system_prompt(graph_stats: &str) -> String {
    format!(
r#"You are a security analyst with access to a threat-hunting knowledge graph. You can query the graph using tools to investigate threats, find suspicious patterns, and answer questions.

## Current Graph
{graph_stats}

## Available Tools

Call tools by emitting a fenced JSON block with "tool" and "params" keys. You may call multiple tools in one response. After receiving tool results, analyze them and either call more tools or give your final answer.

### search_entities
Search for entities by substring match.
```json
{{"tool": "search_entities", "params": {{"query": "string", "entity_type": "IP|Host|User|Process|File|Domain|Registry|URL|Service", "limit": 20}}}}
```
- `query` (required): substring to search for
- `entity_type` (optional): filter by type
- `limit` (optional, default 20): max results

### get_node_details
Get details about a specific node: score, degree, neighbors.
```json
{{"tool": "get_node_details", "params": {{"node_id": "exact-node-id"}}}}
```

### expand_node
BFS neighborhood expansion from a node.
```json
{{"tool": "expand_node", "params": {{"node_id": "exact-node-id", "max_hops": 2, "max_nodes": 50}}}}
```
- `max_hops` (optional, default 2): BFS depth
- `max_nodes` (optional, default 50): max nodes to return

### run_hunt
Execute a hunt hypothesis in DSL format.
```json
{{"tool": "run_hunt", "params": {{"hypothesis_dsl": "User -[Execute]-> Process -[Spawn]-> Process"}}}}
```

### get_graph_stats
Get global graph statistics (type distribution, top anomalies, time range).
```json
{{"tool": "get_graph_stats", "params": {{}}}}
```

## Instructions
1. When the user asks a question, use tools to gather data from the graph before answering.
2. Be specific: use exact node IDs from tool results.
3. For your final answer, write plain text (markdown OK). Do NOT wrap your final answer in a tool call block.
4. At the end of your final answer, include an actionable suggestions block:
```json
{{"suggestions": [{{"action": "expand_node|run_hypothesis|search_entities", "target_id": "node-id-or-dsl", "label": "Short description"}}]}}
```
5. Only include suggestions you are confident about. The suggestions block must be the last thing in your final answer."#,
        graph_stats = graph_stats
    )
}

// ── Public API ──

/// Propose a hypothesis from a natural-language situation.
pub async fn propose_hypothesis(
    situation: &str,
    config: Option<&ProviderConfig>,
) -> Result<DslParseResult, String> {
    let cfg = resolve_config(config)?;
    let (system, user) = build_hypothesis_prompt(situation);
    let response = call_llm_provider(&cfg, &system, &user, Some(512)).await?;
    let dsl_line = extract_dsl_line(&response)
        .ok_or_else(|| format!("Could not extract hypothesis from model response: {}", response))?;
    parse_dsl(dsl_line.trim(), Some("AI Hypothesis")).map_err(|e| e.to_string())
}

/// Analyze a subgraph (one-shot, no conversation history).
pub async fn analyze_graph(
    nodes_json: &str,
    edges_json: &str,
    selected_node_id: Option<String>,
    question_override: Option<String>,
    config: Option<&ProviderConfig>,
) -> Result<AiAnalysisResponse, String> {
    let cfg = resolve_config(config)?;
    let system = build_analyze_system_prompt();
    let context = compress_subgraph_context(
        nodes_json,
        edges_json,
        selected_node_id.as_deref(),
    );
    let user = build_analyze_user_message(&context, question_override.as_deref());
    let raw = call_llm_provider(&cfg, &system, &user, Some(4096)).await?;
    Ok(parse_ai_response(&raw))
}

/// Analyze a subgraph with conversation history (chat-style).
pub async fn analyze_graph_conversation(
    nodes_json: &str,
    edges_json: &str,
    selected_node_id: Option<&str>,
    user_message: &str,
    conversation: &AiConversation,
    config: Option<&ProviderConfig>,
) -> Result<(String, AiAnalysisResponse), String> {
    let cfg = resolve_config(config)?;
    let system = build_analyze_system_prompt();
    let context = compress_subgraph_context(nodes_json, edges_json, selected_node_id);

    // Build full user message with context
    let full_user_msg = if conversation.messages.is_empty() {
        // First message: include full context
        format!("{}\n\n{}", context, user_message)
    } else {
        // Follow-up: just the user's question (context was in earlier messages)
        user_message.to_string()
    };

    let history_messages = build_messages_with_history(conversation, &full_user_msg);
    let raw = call_llm_with_history(&cfg, &system, &history_messages, Some(4096)).await?;
    let parsed = parse_ai_response(&raw);
    Ok((raw, parsed))
}

