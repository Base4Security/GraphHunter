//! Review-queue operations: `list`, `approve`, `reject`.
//!
//! Approval policy:
//! - **IngestNegotiator drafts** carry a `field_config`. Approving
//!   one promotes that FieldConfig onto the *most recent* dataset in
//!   the session (in absence of a dataset link on the draft itself).
//!   The promoted dataset id is returned so the caller can confirm
//!   the binding.
//! - **ParserGenerator drafts** carry `vrl_source` + `mapping_hash`.
//!   Their VRL flows into provenance the next time the caller exports
//!   OCSF for any dataset whose FieldConfig hashes to the same value;
//!   nothing else moves on approval. We still flip `Pending →
//!   Approved` so audit shows the human gate fired.
//! - **CanonicalMapper drafts** are not produced today (M4.c only
//!   uses canonical_map synchronously). The branch exists for
//!   forward compat.
//!
//! Rejecting any draft requires a non-empty reason.

use crate::dto::agentic::{
    DraftSource, DraftStatus, ListDraftsRequest, ListDraftsResponse, ResolveDraftRequest,
    ResolveDraftResponse,
};
use crate::util::now_secs;
use crate::{ApiError, ApiResult, GraphHunterApi};

impl GraphHunterApi {
    /// List drafts in the review queue. Defaults to pending only.
    pub fn agentic_review_list(&self, req: ListDraftsRequest) -> ApiResult<ListDraftsResponse> {
        let session = self.resolve_session(req.session.as_ref())?;
        let q = session
            .agentic_review
            .read()
            .map_err(|e| ApiError::Internal(format!("agentic_review lock poisoned: {e}")))?;
        Ok(ListDraftsResponse {
            drafts: q.list(req.include_resolved),
        })
    }

    /// Approve one draft. Promotes the draft's payload to active
    /// state per the policy in the module docstring. Returns the
    /// updated draft + the dataset id that received the promotion
    /// (when applicable).
    pub fn agentic_review_approve(
        &self,
        req: ResolveDraftRequest,
    ) -> ApiResult<ResolveDraftResponse> {
        let session = self.resolve_session(req.session.as_ref())?;

        // Lookup before mutating the queue: we need the payload.
        let existing = {
            let q = session
                .agentic_review
                .read()
                .map_err(|e| ApiError::Internal(format!("agentic_review lock poisoned: {e}")))?;
            q.get(&req.draft_id)
                .ok_or_else(|| ApiError::NotFound(format!("draft {}", req.draft_id)))?
        };
        if !matches!(existing.status, DraftStatus::Pending) {
            return Err(ApiError::InvalidState(format!(
                "draft {} is not pending (current: {:?})",
                req.draft_id, existing.status
            )));
        }

        // Promote per source.
        let promoted_dataset_id = match existing.source {
            DraftSource::IngestNegotiator => {
                if let Some(cfg) = existing.field_config.clone() {
                    Some(promote_field_config_to_latest_dataset(&session, cfg)?)
                } else {
                    None
                }
            }
            DraftSource::ParserGenerator | DraftSource::CanonicalMapper => None,
        };

        // Publish to the mapping library so future ingests can reuse
        // the approved artefact. No-op when the library is unconfigured
        // (tests, headless). Never bubbles up — a library failure must
        // not block the human approval.
        self.publish_approved_draft(&existing);

        // Flip status.
        let updated = {
            let mut q = session
                .agentic_review
                .write()
                .map_err(|e| ApiError::Internal(format!("agentic_review lock poisoned: {e}")))?;
            q.set_status(&req.draft_id, DraftStatus::Approved { at: now_secs() })
                .ok_or_else(|| ApiError::NotFound(format!("draft {}", req.draft_id)))?
        };

        Ok(ResolveDraftResponse {
            draft: updated,
            promoted_dataset_id,
        })
    }

    /// Reject one draft. Persists the reason on the draft so the
    /// audit trail shows why it was discarded. Reason is required.
    pub fn agentic_review_reject(
        &self,
        req: ResolveDraftRequest,
    ) -> ApiResult<ResolveDraftResponse> {
        let reason = req
            .reason
            .as_deref()
            .map(str::trim)
            .filter(|r| !r.is_empty())
            .ok_or_else(|| ApiError::InvalidInput("reject requires `reason`".into()))?
            .to_string();

        let session = self.resolve_session(req.session.as_ref())?;
        let existing = {
            let q = session
                .agentic_review
                .read()
                .map_err(|e| ApiError::Internal(format!("agentic_review lock poisoned: {e}")))?;
            q.get(&req.draft_id)
                .ok_or_else(|| ApiError::NotFound(format!("draft {}", req.draft_id)))?
        };
        if !matches!(existing.status, DraftStatus::Pending) {
            return Err(ApiError::InvalidState(format!(
                "draft {} is not pending (current: {:?})",
                req.draft_id, existing.status
            )));
        }

        let updated = {
            let mut q = session
                .agentic_review
                .write()
                .map_err(|e| ApiError::Internal(format!("agentic_review lock poisoned: {e}")))?;
            q.set_status(
                &req.draft_id,
                DraftStatus::Rejected {
                    at: now_secs(),
                    reason,
                },
            )
            .ok_or_else(|| ApiError::NotFound(format!("draft {}", req.draft_id)))?
        };

        Ok(ResolveDraftResponse {
            draft: updated,
            promoted_dataset_id: None,
        })
    }
}

impl GraphHunterApi {
    /// Publish an approved draft to the mapping library. Silently
    /// skips when the library is unconfigured or the draft carries
    /// no field_config (can't fingerprint without one). Errors are
    /// logged and swallowed — approval must not fail because of
    /// publication bookkeeping.
    pub(crate) fn publish_approved_draft(&self, draft: &crate::dto::agentic::MappingDraft) {
        use graph_hunter_core::mapping_library::{PublishSource, PublishedMapping};

        let Some(store) = self.mapping_library() else {
            return;
        };
        let Some(cfg) = draft.field_config.clone() else {
            return;
        };
        let source = match draft.source {
            DraftSource::IngestNegotiator => PublishSource::IngestNegotiator,
            DraftSource::ParserGenerator => PublishSource::ParserGenerator,
            // CanonicalMapper drafts don't exist today (see module
            // docstring). If they ever do, bucket them alongside the
            // ingest-negotiator flow — they carry the same payload
            // shape (FieldConfig + rationale).
            DraftSource::CanonicalMapper => PublishSource::IngestNegotiator,
        };
        let entry = PublishedMapping {
            mapping_id: String::new(),
            fingerprint: String::new(),
            field_config: cfg,
            vrl_source: draft.vrl_source.clone(),
            mapping_hash: draft.mapping_hash.clone(),
            ocsf_category: None,
            source,
            origin_draft_id: Some(draft.draft_id.clone()),
            published_at: now_secs(),
        };
        if let Err(e) = store.publish(entry) {
            tracing::warn!(
                "mapping_library publish failed for draft {}: {}",
                draft.draft_id,
                e
            );
        }
    }
}

fn promote_field_config_to_latest_dataset(
    session: &std::sync::Arc<crate::state::Session>,
    cfg: graph_hunter_core::field_preview::FieldConfig,
) -> ApiResult<String> {
    let mut datasets = session
        .datasets
        .write()
        .map_err(|e| ApiError::Internal(format!("datasets lock poisoned: {e}")))?;
    let target = datasets.last_mut().ok_or_else(|| {
        ApiError::InvalidState(
            "no dataset to promote FieldConfig onto (ingest something first)".into(),
        )
    })?;
    let id = target.id.clone();
    target.field_config = Some(cfg);
    Ok(id)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dto::agentic::IngestNegotiateRequest;
    use crate::dto::session::CreateSessionRequest;
    use crate::state::DatasetInfo;

    fn make_api_with_dataset() -> GraphHunterApi {
        let api = GraphHunterApi::new_noop();
        api.create_session(CreateSessionRequest {
            name: Some("review-test".into()),
        })
        .expect("create_session");
        let session = api.sessions().current_session().unwrap();
        let mut datasets = session.datasets.write().unwrap();
        datasets.push(DatasetInfo {
            id: "ds-1".into(),
            name: "ds-1".into(),
            path: None,
            created_at: 0,
            entity_count: 0,
            relation_count: 0,
            field_config: None,
            ingest_stats: None,
        });
        drop(datasets);
        api
    }

    fn negotiate(api: &GraphHunterApi) -> String {
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
    fn approve_promotes_field_config_to_latest_dataset() {
        let api = make_api_with_dataset();
        let id = negotiate(&api);
        let resp = api
            .agentic_review_approve(ResolveDraftRequest {
                session: None,
                draft_id: id.clone(),
                reason: None,
            })
            .expect("approve");
        assert_eq!(resp.promoted_dataset_id.as_deref(), Some("ds-1"));
        assert!(matches!(resp.draft.status, DraftStatus::Approved { .. }));

        let session = api.sessions().current_session().unwrap();
        let datasets = session.datasets.read().unwrap();
        assert!(
            datasets[0].field_config.is_some(),
            "approval should have stamped the FieldConfig onto ds-1"
        );
    }

    #[test]
    fn reject_requires_reason() {
        let api = make_api_with_dataset();
        let id = negotiate(&api);
        let err = api
            .agentic_review_reject(ResolveDraftRequest {
                session: None,
                draft_id: id,
                reason: None,
            })
            .expect_err("reject without reason");
        assert!(matches!(err, ApiError::InvalidInput(_)), "got: {err}");
    }

    #[test]
    fn cannot_approve_already_resolved_draft() {
        let api = make_api_with_dataset();
        let id = negotiate(&api);
        api.agentic_review_approve(ResolveDraftRequest {
            session: None,
            draft_id: id.clone(),
            reason: None,
        })
        .unwrap();
        let err = api
            .agentic_review_approve(ResolveDraftRequest {
                session: None,
                draft_id: id,
                reason: None,
            })
            .expect_err("double approve");
        assert!(matches!(err, ApiError::InvalidState(_)), "got: {err}");
    }

    #[test]
    fn list_excludes_resolved_by_default() {
        let api = make_api_with_dataset();
        let id1 = negotiate(&api);
        let _id2 = negotiate(&api);
        api.agentic_review_approve(ResolveDraftRequest {
            session: None,
            draft_id: id1,
            reason: None,
        })
        .unwrap();
        let pending = api
            .agentic_review_list(ListDraftsRequest {
                session: None,
                include_resolved: false,
            })
            .unwrap();
        assert_eq!(pending.drafts.len(), 1);
        let all = api
            .agentic_review_list(ListDraftsRequest {
                session: None,
                include_resolved: true,
            })
            .unwrap();
        assert_eq!(all.drafts.len(), 2);
    }
}
