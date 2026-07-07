//! Canonical request / response DTOs.
//!
//! Each operation exposed by [`crate::GraphHunterApi`] has a `*Request`
//! and (when return is structured) a `*Response` type here. Both derive
//! `Serialize + Deserialize` so all three transports consume them
//! directly — no per-transport shape mapping.
//!
//! # Versioning (F4.1)
//!
//! Types live under [`v1`]; `pub use v1::*` keeps the legacy paths
//! (`dto::hunt::HuntRequest`, etc.) working so no caller needs to
//! update. Breaking changes go to [`v2`] as a parallel namespace and
//! callers opt in per endpoint.

pub mod v1;
pub mod v2;

pub use v1::*;

use crate::state::SessionHandle;
use serde::{Deserialize, Serialize};

/// Every request that operates on a session includes this. `None` means
/// "use the current session"; an explicit handle overrides.
///
/// Using a bare field (not wrapped in `#[serde(flatten)]`) keeps the JSON
/// shape explicit and greppable — `"session": "<uuid>"` everywhere it
/// matters.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct SessionScope {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session: Option<SessionHandle>,
}

impl SessionScope {
    pub fn current() -> Self {
        Self { session: None }
    }

    pub fn explicit(h: SessionHandle) -> Self {
        Self { session: Some(h) }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn current_serializes_as_empty_object() {
        let s = serde_json::to_value(&SessionScope::current()).unwrap();
        assert_eq!(s, serde_json::json!({}));
    }

    #[test]
    fn explicit_serializes_with_session_field() {
        let h = SessionHandle::new();
        let v = serde_json::to_value(&SessionScope::explicit(h)).unwrap();
        assert!(v.get("session").is_some());
    }

    #[test]
    fn deserializes_from_missing_field() {
        let v: SessionScope = serde_json::from_str("{}").unwrap();
        assert!(v.session.is_none());
    }
}
