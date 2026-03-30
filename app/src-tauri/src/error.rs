use serde::Serialize;

/// Typed error enum for all Tauri commands, replacing stringly-typed `Result<T, String>`.
///
/// Serializes as `{ "kind": "VariantName", "message": "..." }` so the frontend can
/// programmatically match on `kind` while still displaying the human-readable `message`.
#[derive(Debug, Serialize)]
#[serde(tag = "kind", content = "message")]
pub enum CommandError {
    SessionNotFound(String),
    GraphLocked(String),
    IoError(String),
    ParseError(String),
    SentinelError(String),
    AiError(String),
    InvalidInput(String),
    Internal(String),
}

impl std::fmt::Display for CommandError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let msg = match self {
            CommandError::SessionNotFound(m)
            | CommandError::GraphLocked(m)
            | CommandError::IoError(m)
            | CommandError::ParseError(m)
            | CommandError::SentinelError(m)
            | CommandError::AiError(m)
            | CommandError::InvalidInput(m)
            | CommandError::Internal(m) => m,
        };
        write!(f, "{}", msg)
    }
}

impl std::error::Error for CommandError {}

/// Allow `?` on `String` errors (e.g. from `ai.rs` helpers) to convert into `CommandError::Internal`.
impl From<String> for CommandError {
    fn from(s: String) -> Self {
        CommandError::Internal(s)
    }
}

impl From<std::io::Error> for CommandError {
    fn from(e: std::io::Error) -> Self {
        CommandError::IoError(e.to_string())
    }
}

impl From<serde_json::Error> for CommandError {
    fn from(e: serde_json::Error) -> Self {
        CommandError::ParseError(e.to_string())
    }
}
