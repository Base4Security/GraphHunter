//! Unified error type for the canonical API.
//!
//! Every operation returns [`ApiResult<T>`]. Transports map [`ApiError`]
//! to their native shape:
//! - Tauri: serializes to JSON via `serde` (frontend gets the variant tag).
//! - HTTP: maps to status codes via the `status_code()` helper.
//! - MCP: surfaces as a tool error with the `Display` message.
//!
//! New variants should be added when a genuinely new failure mode appears.
//! Resist the temptation to add `Other(String)` — a well-typed error surface
//! is part of the point of this refactor.

use serde::{Deserialize, Serialize};
use thiserror::Error;

pub type ApiResult<T> = Result<T, ApiError>;

#[derive(Debug, Error, Serialize, Deserialize, Clone)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ApiError {
    /// Requested a session that does not exist in the store.
    #[error("session not found: {0}")]
    SessionNotFound(String),

    /// Operation requires a "current" session but none is set.
    #[error("no current session selected")]
    NoCurrentSession,

    /// A referenced entity / node / tag / note was not found.
    #[error("not found: {0}")]
    NotFound(String),

    /// Input failed validation (malformed DSL, missing required field, ...).
    #[error("invalid input: {0}")]
    InvalidInput(String),

    /// A precondition on the graph is not met (e.g., "edges not finalized").
    #[error("invalid state: {0}")]
    InvalidState(String),

    /// Operation conflicts with current session lifecycle (e.g., hunt while finalizing).
    #[error("conflict: {0}")]
    Conflict(String),

    /// An external service (Sentinel, AI provider, ticketing) returned an
    /// error. Preserves the upstream message verbatim.
    #[error("upstream error ({service}): {message}")]
    Upstream { service: String, message: String },

    /// I/O failure while reading or writing session files / caches.
    #[error("i/o error: {0}")]
    Io(String),

    /// Request body exceeded a documented per-endpoint cap (e.g.
    /// `/graph/overlap` rejects > 500 entities). Maps to HTTP 413.
    #[error("payload too large: {0}")]
    PayloadTooLarge(String),

    /// Unexpected internal failure. Should map to 500 at HTTP. Log with
    /// tracing BEFORE returning so the payload alone is enough context for
    /// the caller.
    #[error("internal: {0}")]
    Internal(String),
}

impl ApiError {
    /// HTTP status code an HTTP transport should return for this variant.
    /// Keep in sync with the MCP surface if/when MCP gains status codes.
    pub fn status_code(&self) -> u16 {
        match self {
            ApiError::SessionNotFound(_) | ApiError::NotFound(_) => 404,
            ApiError::NoCurrentSession | ApiError::InvalidInput(_) | ApiError::InvalidState(_) => {
                400
            }
            ApiError::Conflict(_) => 409,
            ApiError::PayloadTooLarge(_) => 413,
            ApiError::Upstream { .. } => 502,
            ApiError::Io(_) | ApiError::Internal(_) => 500,
        }
    }
}

impl From<std::io::Error> for ApiError {
    fn from(e: std::io::Error) -> Self {
        ApiError::Io(e.to_string())
    }
}

impl From<serde_json::Error> for ApiError {
    fn from(e: serde_json::Error) -> Self {
        ApiError::InvalidInput(format!("json: {e}"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn status_code_mapping() {
        assert_eq!(ApiError::NotFound("x".into()).status_code(), 404);
        assert_eq!(ApiError::SessionNotFound("x".into()).status_code(), 404);
        assert_eq!(ApiError::NoCurrentSession.status_code(), 400);
        assert_eq!(ApiError::InvalidInput("x".into()).status_code(), 400);
        assert_eq!(
            ApiError::Upstream {
                service: "s".into(),
                message: "m".into()
            }
            .status_code(),
            502
        );
        assert_eq!(ApiError::Internal("x".into()).status_code(), 500);
        assert_eq!(ApiError::Conflict("x".into()).status_code(), 409);
        assert_eq!(ApiError::PayloadTooLarge("x".into()).status_code(), 413);
    }

    #[test]
    fn roundtrips_through_serde() {
        let e = ApiError::Upstream {
            service: "sentinel".into(),
            message: "429 throttled".into(),
        };
        let s = serde_json::to_string(&e).unwrap();
        let back: ApiError = serde_json::from_str(&s).unwrap();
        assert_eq!(format!("{e}"), format!("{back}"));
    }
}
