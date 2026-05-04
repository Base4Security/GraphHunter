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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn serializes_with_kind_tag() {
        let err = CommandError::SessionNotFound("sess-123".to_string());
        let json = serde_json::to_value(&err).unwrap();
        assert_eq!(json["kind"], "SessionNotFound");
        assert_eq!(json["message"], "sess-123");
    }

    #[test]
    fn from_string_maps_to_internal() {
        let err: CommandError = "something broke".to_string().into();
        let json = serde_json::to_value(&err).unwrap();
        assert_eq!(json["kind"], "Internal");
        assert_eq!(json["message"], "something broke");
    }

    #[test]
    fn from_io_error() {
        let io_err = std::io::Error::new(std::io::ErrorKind::NotFound, "file gone");
        let err: CommandError = io_err.into();
        let json = serde_json::to_value(&err).unwrap();
        assert_eq!(json["kind"], "IoError");
        assert!(json["message"].as_str().unwrap().contains("file gone"));
    }

    #[test]
    fn display_shows_message() {
        let err = CommandError::GraphLocked("busy".to_string());
        assert_eq!(format!("{}", err), "busy");
    }
}
