//! DTOs for session lifecycle operations.

use crate::state::SessionHandle;
use serde::{Deserialize, Serialize};

/// Wire shape returned for every session lookup (create, list, load,
/// get_current). Matches the legacy Tauri `types::SessionInfo`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionInfo {
    pub id: String,
    pub name: String,
    pub created_at: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct CreateSessionRequest {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoadSessionRequest {
    pub session_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct SaveSessionRequest {
    /// When `None`, saves the current session.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session_id: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeleteSessionRequest {
    pub session_id: String,
}

/// Explicit handle alias for transports that prefer the typed wrapper.
pub type SessionInfoByHandle = (SessionHandle, SessionInfo);
