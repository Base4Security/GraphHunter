//! Per-session review queue for agentic drafts.
//!
//! Lives behind `Arc<RwLock<_>>` so the agentic operations (which
//! borrow the session through the API façade) can both write new
//! drafts and read the queue from MCP without contending with
//! ingestion.
//!
//! In-memory only for M4. Persistence to the session file is the
//! M5/M7 mapping-library work — until then a process restart clears
//! the queue, which is acceptable: drafts are cheap to regenerate by
//! re-running `ingest_negotiator`.

use crate::dto::agentic::{DraftStatus, MappingDraft};

#[derive(Default)]
pub struct MappingReviewQueue {
    drafts: Vec<MappingDraft>,
}

impl MappingReviewQueue {
    pub fn new() -> Self {
        Self::default()
    }

    /// Append a fresh draft. Caller-allocated `draft_id` so the
    /// returning agentic op can hand it back to the user immediately
    /// without an extra read-back from the queue.
    pub fn push(&mut self, draft: MappingDraft) {
        self.drafts.push(draft);
    }

    pub fn list(&self, include_resolved: bool) -> Vec<MappingDraft> {
        self.drafts
            .iter()
            .filter(|d| include_resolved || matches!(d.status, DraftStatus::Pending))
            .cloned()
            .collect()
    }

    pub fn get(&self, draft_id: &str) -> Option<MappingDraft> {
        self.drafts.iter().find(|d| d.draft_id == draft_id).cloned()
    }

    /// Mutate one draft's status. Returns `Some(updated)` if found, or
    /// `None` to let the caller surface a 404-style error.
    pub fn set_status(&mut self, draft_id: &str, new_status: DraftStatus) -> Option<MappingDraft> {
        let d = self.drafts.iter_mut().find(|d| d.draft_id == draft_id)?;
        d.status = new_status;
        Some(d.clone())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dto::agentic::DraftSource;

    fn pending_draft(id: &str) -> MappingDraft {
        MappingDraft {
            draft_id: id.into(),
            source: DraftSource::IngestNegotiator,
            created_at: 0,
            status: DraftStatus::Pending,
            field_config: None,
            vrl_source: None,
            mapping_hash: None,
            rationale: "test".into(),
            backend_id: "mock".into(),
        }
    }

    #[test]
    fn list_filters_resolved_by_default() {
        let mut q = MappingReviewQueue::new();
        q.push(pending_draft("a"));
        q.push(pending_draft("b"));
        q.set_status("b", DraftStatus::Approved { at: 1 });
        let pending = q.list(false);
        assert_eq!(pending.len(), 1);
        assert_eq!(pending[0].draft_id, "a");
        let all = q.list(true);
        assert_eq!(all.len(), 2);
    }

    #[test]
    fn set_status_unknown_id_returns_none() {
        let mut q = MappingReviewQueue::new();
        assert!(
            q.set_status(
                "missing",
                DraftStatus::Rejected {
                    at: 0,
                    reason: "x".into()
                }
            )
            .is_none()
        );
    }
}
