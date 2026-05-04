//! DSL + catalog operations.
//!
//! These three operations are stateless (no session access). They're the
//! smallest coherent slice of the API, migrated first as a POC of the
//! end-to-end canonical-API pattern.

use crate::dto::dsl::{
    GetCatalogDiagnosticsResponse, GetCatalogResponse, GetCatalogWithStatusRequest,
    GetCatalogWithStatusResponse, LoadCatalogHypothesisRequest, ParseDslRequest, ParseDslResponse,
};
use crate::{ApiError, ApiResult, GraphHunterApi};
use graph_hunter_core::{
    check_catalog_compatibility, format_hypothesis, get_catalog, get_catalog_snapshot, parse_dsl,
};

impl GraphHunterApi {
    /// Parse an arrow-chain DSL string into a [`graph_hunter_core::Hypothesis`].
    ///
    /// Returns [`ApiError::InvalidInput`] when the string is empty or
    /// malformed. Transports map that to whatever their error surface is
    /// (Tauri: `Result::Err` JSON, HTTP: 400, MCP: tool error).
    pub fn parse_dsl(&self, req: ParseDslRequest) -> ApiResult<ParseDslResponse> {
        let parsed = parse_dsl(&req.input, req.name.as_deref())
            .map_err(|e| ApiError::InvalidInput(e.to_string()))?;
        let steps = parsed.hypothesis.steps.len();
        Ok(ParseDslResponse {
            hypothesis: parsed.hypothesis,
            formatted: parsed.formatted,
            steps,
        })
    }

    /// Return the full built-in ATT&CK hypothesis catalog.
    ///
    /// Today the catalog is a compile-time `const` array in
    /// `graph_hunter_core::catalog`. P2-C migrates it to runtime-loaded
    /// YAML files; this method's signature does not change — it keeps
    /// returning `Vec<CatalogEntry>`, only the source of truth shifts.
    pub fn get_catalog(&self) -> GetCatalogResponse {
        get_catalog().to_vec()
    }

    /// Return the catalog with per-entry compatibility computed against
    /// the resolved session's graph schema. Incompatible entries carry
    /// the lists of `missing_entity_types` / `missing_rel_types` so the
    /// UI can gray them out and explain why.
    ///
    /// Resolves the session via [`SessionStore::resolve`](crate::SessionStore::resolve):
    /// explicit handle wins, else falls back to current. Returns
    /// [`ApiError::NoCurrentSession`] when neither is set and
    /// [`ApiError::SessionNotFound`] when an explicit handle points at a
    /// session that doesn't exist.
    pub fn get_catalog_with_status(
        &self,
        req: GetCatalogWithStatusRequest,
    ) -> ApiResult<GetCatalogWithStatusResponse> {
        let store = self.sessions();
        let session = match req.session.as_ref() {
            Some(h) => store
                .get(h.as_str())
                .ok_or_else(|| ApiError::SessionNotFound(h.as_str().to_string()))?,
            None => store.current_session().ok_or(ApiError::NoCurrentSession)?,
        };
        let graph = session
            .graph
            .read()
            .map_err(|e| ApiError::Internal(format!("graph lock poisoned: {e}")))?;
        let schema = graph.get_relation_schema();
        Ok(get_catalog()
            .iter()
            .map(|e| check_catalog_compatibility(e, &schema))
            .collect())
    }

    /// Return any diagnostics collected by the catalog loader at startup.
    ///
    /// The list is empty when every built-in YAML and every user-supplied
    /// file under `$GRAPHHUNTER_CATALOG_DIR` (or `~/.graphhunter/catalog`)
    /// parsed and validated cleanly. When non-empty, each entry carries
    /// the offending file path (when known), the entry id (when the
    /// loader got far enough to know it), and a human-readable message.
    ///
    /// Built-in YAMLs are embedded at compile time so they don't fail
    /// to load under normal circumstances — a non-empty diagnostics
    /// list almost always points at user-authored files.
    pub fn get_catalog_diagnostics(&self) -> GetCatalogDiagnosticsResponse {
        get_catalog_snapshot().load_errors.clone()
    }

    /// Look up a catalog entry by id and parse its DSL pattern into a
    /// [`Hypothesis`], applying the entry's `k_simplicity` override.
    ///
    /// Returns [`ApiError::NotFound`] when the id doesn't match any
    /// catalog entry, [`ApiError::InvalidInput`] when the stored pattern
    /// fails to parse (shouldn't happen for built-ins — guarded to catch
    /// misauthored user-supplied catalogs once P2-C ships).
    pub fn load_catalog_hypothesis(
        &self,
        req: LoadCatalogHypothesisRequest,
    ) -> ApiResult<ParseDslResponse> {
        let catalog = get_catalog();
        let entry = catalog
            .iter()
            .find(|e| e.id == req.catalog_id)
            .ok_or_else(|| ApiError::NotFound(format!("catalog entry: {}", req.catalog_id)))?;
        let parsed = parse_dsl(&entry.dsl_pattern, Some(&entry.name)).map_err(|e| {
            ApiError::InvalidInput(format!(
                "catalog entry {} has malformed pattern: {e}",
                entry.id
            ))
        })?;
        let mut hypothesis = parsed.hypothesis;
        hypothesis.k_simplicity = entry.k_simplicity;
        let formatted = format_hypothesis(&hypothesis);
        let steps = hypothesis.steps.len();
        Ok(ParseDslResponse {
            hypothesis,
            formatted,
            steps,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_dsl_happy_path() {
        let api = GraphHunterApi::new_noop();
        let resp = api
            .parse_dsl(ParseDslRequest {
                input: "User -[Auth]-> Host -[Execute]-> Process".to_string(),
                name: Some("test".to_string()),
            })
            .expect("parse should succeed");
        assert_eq!(resp.steps, 2);
        assert!(!resp.formatted.is_empty());
        assert_eq!(resp.hypothesis.steps.len(), 2);
    }

    #[test]
    fn parse_dsl_empty_input_is_invalid() {
        let api = GraphHunterApi::new_noop();
        let err = api
            .parse_dsl(ParseDslRequest {
                input: "   ".to_string(),
                name: None,
            })
            .unwrap_err();
        assert!(matches!(err, ApiError::InvalidInput(_)));
        assert_eq!(err.status_code(), 400);
    }

    #[test]
    fn get_catalog_is_nonempty() {
        let api = GraphHunterApi::new_noop();
        let cat = api.get_catalog();
        assert!(
            cat.len() >= 29,
            "expected at least 29 built-in patterns, got {}",
            cat.len()
        );
        assert!(cat.iter().any(|e| e.id == "cat-001"));
    }

    #[test]
    fn load_catalog_hypothesis_resolves_known_id() {
        let api = GraphHunterApi::new_noop();
        let resp = api
            .load_catalog_hypothesis(LoadCatalogHypothesisRequest {
                catalog_id: "cat-001".to_string(),
            })
            .expect("cat-001 should load");
        assert!(!resp.formatted.is_empty());
        assert!(resp.steps >= 1);
    }

    #[test]
    fn load_catalog_hypothesis_unknown_id_is_not_found() {
        let api = GraphHunterApi::new_noop();
        let err = api
            .load_catalog_hypothesis(LoadCatalogHypothesisRequest {
                catalog_id: "cat-does-not-exist".to_string(),
            })
            .unwrap_err();
        assert!(matches!(err, ApiError::NotFound(_)));
        assert_eq!(err.status_code(), 404);
    }

    #[test]
    fn catalog_with_status_no_current_session_errors() {
        let api = GraphHunterApi::new_noop();
        let err = api
            .get_catalog_with_status(GetCatalogWithStatusRequest::default())
            .unwrap_err();
        assert!(matches!(err, ApiError::NoCurrentSession));
        assert_eq!(err.status_code(), 400);
    }

    #[test]
    fn catalog_with_status_unknown_handle_errors() {
        use crate::state::SessionHandle;
        let api = GraphHunterApi::new_noop();
        let err = api
            .get_catalog_with_status(GetCatalogWithStatusRequest {
                session: Some(SessionHandle::from_string("ghost")),
            })
            .unwrap_err();
        assert!(matches!(err, ApiError::SessionNotFound(_)));
        assert_eq!(err.status_code(), 404);
    }

    #[test]
    fn catalog_with_status_empty_graph_marks_all_incompatible() {
        use crate::state::Session;
        use graph_hunter_core::GraphHunter;
        use std::sync::Arc;

        let api = GraphHunterApi::new_noop();
        let session = Arc::new(Session::new("s1", "test", GraphHunter::new(), 0));
        api.sessions().insert(session);
        api.sessions().set_current(Some("s1".to_string()));

        let entries = api
            .get_catalog_with_status(GetCatalogWithStatusRequest::default())
            .expect("should succeed with current session");
        // Empty graph has no schema → every entry is incompatible.
        assert!(!entries.is_empty());
        assert!(
            entries.iter().all(|e| !e.compatible),
            "expected every catalog entry to be flagged incompatible against an empty graph"
        );
    }
}
