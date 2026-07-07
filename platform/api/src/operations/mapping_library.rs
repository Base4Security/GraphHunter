//! Explicit publish/consume against the M5 mapping library.
//!
//! The review-queue's `agentic_review_approve` already auto-publishes
//! drafts as a side effect. This surface is the analyst-driven one:
//!
//! - `publish_mapping(draft_id)` lets a human force-publish *any* draft
//!   in the review queue (even Rejected/Pending) — useful when sharing
//!   experimental mappings across sessions or pre-promoting drafts that
//!   haven't yet cleared the gate. Stamped with `PublishSource::Manual`
//!   so audit can distinguish auto-publication from analyst override.
//!
//! - `fetch_shared_mappings(filter)` returns compact summaries of every
//!   published entry, optionally filtered by fingerprint/category.
//!   Surface for the cross-session catalog UI in M7.
//!
//! Both ops require the mapping library to be configured at API
//! construction (Tauri bootstrap opens it at
//! `<data>/GraphHunter/mapping_library/`). When the slot is empty,
//! these surface a clear `InvalidState` instead of pretending success —
//! the analyst-facing contract is stricter than the review-queue's
//! "best-effort silently log" path.

use graph_hunter_core::mapping_library::{PublishSource, PublishedMapping, fingerprint};

use crate::dto::mapping_library::{
    FetchSharedMappingsRequest, FetchSharedMappingsResponse, PublishMappingRequest,
    PublishMappingResponse, SharedMappingSummary,
};
use crate::util::now_secs;
use crate::{ApiError, ApiResult, GraphHunterApi};

impl GraphHunterApi {
    /// Force-publish a review-queue draft to the shared mapping
    /// library. Mirrors what `agentic_review_approve` does as a side
    /// effect, but allows arbitrary draft promotion (independent of
    /// status) and stamps `PublishSource::Manual` so audit can
    /// distinguish the two paths.
    pub fn publish_mapping(&self, req: PublishMappingRequest) -> ApiResult<PublishMappingResponse> {
        let session = self.resolve_session(req.session.as_ref())?;
        let store = self.mapping_library().ok_or_else(|| {
            ApiError::InvalidState(
                "mapping library not configured (no <data>/mapping_library path opened)".into(),
            )
        })?;

        let draft = {
            let q = session
                .agentic_review
                .read()
                .map_err(|e| ApiError::Internal(format!("agentic_review lock poisoned: {e}")))?;
            q.get(&req.draft_id)
                .ok_or_else(|| ApiError::NotFound(format!("draft {}", req.draft_id)))?
        };

        let cfg = draft.field_config.clone().ok_or_else(|| {
            ApiError::InvalidState(format!(
                "draft {} has no field_config — cannot fingerprint for publication",
                req.draft_id
            ))
        })?;

        let published_at = now_secs();
        let fp = fingerprint(&cfg);
        let entry = PublishedMapping {
            mapping_id: String::new(),
            fingerprint: fp.clone(),
            field_config: cfg,
            vrl_source: draft.vrl_source.clone(),
            mapping_hash: draft.mapping_hash.clone(),
            ocsf_category: req.ocsf_category,
            source: PublishSource::Manual,
            origin_draft_id: Some(draft.draft_id.clone()),
            published_at,
        };
        let mapping_id = store
            .publish(entry)
            .map_err(|e| ApiError::Internal(format!("mapping_library publish failed: {e}")))?;

        Ok(PublishMappingResponse {
            mapping_id,
            fingerprint: fp,
            published_at,
        })
    }

    /// List published mappings as compact summaries, optionally
    /// filtered by fingerprint and/or `ocsf_category`. Returns total
    /// pre-limit so the caller can render pagination context. Newest
    /// first when `limit` is set; otherwise insertion order.
    pub fn fetch_shared_mappings(
        &self,
        req: FetchSharedMappingsRequest,
    ) -> ApiResult<FetchSharedMappingsResponse> {
        let store = self.mapping_library().ok_or_else(|| {
            ApiError::InvalidState(
                "mapping library not configured (no <data>/mapping_library path opened)".into(),
            )
        })?;

        let all = store
            .list()
            .map_err(|e| ApiError::Internal(format!("mapping_library list failed: {e}")))?;

        let mut filtered: Vec<PublishedMapping> = all
            .into_iter()
            .filter(|m| {
                req.fingerprint
                    .as_deref()
                    .map_or(true, |fp| m.fingerprint == fp)
            })
            .filter(|m| {
                req.ocsf_category
                    .as_deref()
                    .map_or(true, |cat| m.ocsf_category.as_deref() == Some(cat))
            })
            .collect();

        let total = filtered.len();
        if let Some(limit) = req.limit {
            filtered.sort_by_key(|m| std::cmp::Reverse(m.published_at));
            filtered.truncate(limit);
        }

        let mappings = filtered
            .into_iter()
            .map(|m| SharedMappingSummary {
                mapping_id: m.mapping_id,
                fingerprint: m.fingerprint,
                mapping_hash: m.mapping_hash,
                ocsf_category: m.ocsf_category,
                source: source_tag(m.source).to_string(),
                published_at: m.published_at,
                field_count: m.field_config.mappings.len(),
                has_vrl: m.vrl_source.is_some(),
            })
            .collect();

        Ok(FetchSharedMappingsResponse { mappings, total })
    }
}

fn source_tag(s: PublishSource) -> &'static str {
    match s {
        PublishSource::IngestNegotiator => "ingest_negotiator",
        PublishSource::ParserGenerator => "parser_generator",
        PublishSource::Manual => "manual",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dto::agentic::IngestNegotiateRequest;
    use crate::dto::session::CreateSessionRequest;
    use graph_hunter_core::mapping_library::MappingLibraryStore;
    use std::sync::Arc;

    fn api_with_library() -> (GraphHunterApi, tempfile::TempDir) {
        let dir = tempfile::tempdir().unwrap();
        let store = Arc::new(MappingLibraryStore::open(dir.path()).unwrap());
        let api = GraphHunterApi::new_noop();
        {
            let handle = api.mapping_library_handle();
            *handle.lock().unwrap() = Some(store);
        }
        api.create_session(CreateSessionRequest {
            name: Some("publish-test".into()),
        })
        .unwrap();
        (api, dir)
    }

    fn negotiate_draft(api: &GraphHunterApi) -> String {
        let csv = "User,Image\nalice,cmd.exe\n";
        api.ingest_negotiate(IngestNegotiateRequest {
            session: None,
            dataset_id: None,
            raw_sample: csv.into(),
            hint_format: Some("csv".into()),
            max_rounds: None,
        })
        .unwrap()
        .draft_id
    }

    #[test]
    fn publish_mapping_round_trips_to_library() {
        let (api, _dir) = api_with_library();
        let draft_id = negotiate_draft(&api);

        let resp = api
            .publish_mapping(PublishMappingRequest {
                session: None,
                draft_id: draft_id.clone(),
                ocsf_category: Some("authentication".into()),
            })
            .expect("publish_mapping");
        assert!(resp.mapping_id.starts_with("ml-fp-"));
        assert!(resp.fingerprint.starts_with("fp-"));

        let listed = api
            .fetch_shared_mappings(FetchSharedMappingsRequest::default())
            .unwrap();
        assert_eq!(listed.total, 1);
        assert_eq!(listed.mappings[0].mapping_id, resp.mapping_id);
        assert_eq!(listed.mappings[0].source, "manual");
        assert_eq!(
            listed.mappings[0].ocsf_category.as_deref(),
            Some("authentication")
        );
        assert_eq!(listed.mappings[0].fingerprint, resp.fingerprint);
    }

    #[test]
    fn publish_mapping_errors_when_library_unconfigured() {
        let api = GraphHunterApi::new_noop();
        api.create_session(CreateSessionRequest {
            name: Some("no-lib".into()),
        })
        .unwrap();
        let err = api
            .publish_mapping(PublishMappingRequest {
                session: None,
                draft_id: "nope".into(),
                ocsf_category: None,
            })
            .expect_err("library missing");
        assert!(matches!(err, ApiError::InvalidState(_)), "got: {err}");
    }

    #[test]
    fn publish_mapping_errors_for_unknown_draft() {
        let (api, _dir) = api_with_library();
        let err = api
            .publish_mapping(PublishMappingRequest {
                session: None,
                draft_id: "draft-does-not-exist".into(),
                ocsf_category: None,
            })
            .expect_err("unknown draft");
        assert!(matches!(err, ApiError::NotFound(_)), "got: {err}");
    }

    #[test]
    fn fetch_shared_mappings_filters_by_fingerprint_and_category() {
        let (api, _dir) = api_with_library();
        let id1 = negotiate_draft(&api);
        let id2 = negotiate_draft(&api);
        api.publish_mapping(PublishMappingRequest {
            session: None,
            draft_id: id1,
            ocsf_category: Some("authentication".into()),
        })
        .unwrap();
        api.publish_mapping(PublishMappingRequest {
            session: None,
            draft_id: id2,
            ocsf_category: Some("process_activity".into()),
        })
        .unwrap();

        let auth = api
            .fetch_shared_mappings(FetchSharedMappingsRequest {
                fingerprint: None,
                ocsf_category: Some("authentication".into()),
                limit: None,
            })
            .unwrap();
        assert_eq!(auth.total, 1);
        assert_eq!(
            auth.mappings[0].ocsf_category.as_deref(),
            Some("authentication")
        );

        let by_fp = api
            .fetch_shared_mappings(FetchSharedMappingsRequest {
                fingerprint: Some(auth.mappings[0].fingerprint.clone()),
                ocsf_category: None,
                limit: None,
            })
            .unwrap();
        // Both drafts shared the same FieldConfig (same CSV header), so
        // both publications land on the same fingerprint.
        assert_eq!(by_fp.total, 2);
    }

    #[test]
    fn fetch_shared_mappings_limit_returns_newest_first() {
        let (api, _dir) = api_with_library();
        for _ in 0..3 {
            let draft = negotiate_draft(&api);
            api.publish_mapping(PublishMappingRequest {
                session: None,
                draft_id: draft,
                ocsf_category: None,
            })
            .unwrap();
        }
        let resp = api
            .fetch_shared_mappings(FetchSharedMappingsRequest {
                fingerprint: None,
                ocsf_category: None,
                limit: Some(2),
            })
            .unwrap();
        assert_eq!(resp.total, 3);
        assert_eq!(resp.mappings.len(), 2);
        assert!(resp.mappings[0].published_at >= resp.mappings[1].published_at);
    }
}
