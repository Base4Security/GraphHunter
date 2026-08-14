//! Analytics over session hub nodes.
//!
//! One question lives here today: which sessions carried more than one
//! account. It is a function rather than a catalog pattern because the
//! DSL's `HAVING` groups by the first node of a path, and session edges
//! run `User -[Uses]-> Session` — expressible as "one account, N
//! sessions", not as "one session, N accounts". Flipping the edge would
//! make it a pattern at the cost of the two-hop pivot in `cat-032`, and
//! measured against real telemetry the flip buys a single row, so the
//! model stays put and the question gets a dedicated walk.

use crate::dto::session_analytics::{
    SharedSession, SharedSessionsRequest, SharedSessionsResponse, DEFAULT_SHARED_SESSION_LIMIT,
};
use crate::{ApiResult, GraphHunterApi};

impl GraphHunterApi {
    /// Sessions observed under more than one account.
    ///
    /// A stolen token or a shared cookie shows up here and nearly nowhere
    /// else. Read-only.
    pub fn get_shared_sessions(
        &self,
        req: SharedSessionsRequest,
    ) -> ApiResult<SharedSessionsResponse> {
        let limit = req.limit.unwrap_or(DEFAULT_SHARED_SESSION_LIMIT).max(1);

        self.with_graph_read(req.session.as_ref(), |graph| {
            let examined = graph
                .entity_ids_for_type(&graph_hunter_core::generic::session_entity_type())
                .map(|v| v.len())
                .unwrap_or(0);

            // An empty answer has two very different causes and the
            // caller cannot tell them apart from the list alone: either
            // no session carried two accounts, or the graph holds no
            // sessions to begin with (the source had no correlation id,
            // or the ingest ceiling refused them). Say which.
            if examined == 0 {
                return Ok(SharedSessionsResponse {
                    sessions: Vec::new(),
                    sessions_examined: 0,
                    truncated: false,
                    note: Some(
                        "This graph has no session entities, so nothing was examined. Either the \
                         ingested source carries no correlation id (sessionId, correlation_id, \
                         request_id, job_id), or the ingest session ceiling refused them — check \
                         `sessions_dropped` in the ingest report."
                            .to_string(),
                    ),
                });
            }

            let mut found = graph.sessions_with_multiple_accounts();
            let truncated = found.len() > limit;
            found.truncate(limit);

            Ok(SharedSessionsResponse {
                sessions: found
                    .into_iter()
                    .map(|s| SharedSession {
                        session_id: s.session_id,
                        accounts: s.accounts,
                        addresses: s.addresses,
                        first_seen: s.first_seen,
                        last_seen: s.last_seen,
                        duration_seconds: s.duration_seconds,
                        event_count: s.event_count,
                    })
                    .collect(),
                sessions_examined: examined,
                truncated,
                note: None,
            })
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A graph with no sessions must not read as "checked, found
    /// nothing". The distinction is the whole point of `note`.
    #[test]
    fn empty_graph_says_why_it_is_empty() {
        let api = GraphHunterApi::new_noop();
        api.create_session(Default::default()).expect("session");
        let res = api
            .get_shared_sessions(SharedSessionsRequest::default())
            .expect("call");
        assert!(res.sessions.is_empty());
        assert_eq!(res.sessions_examined, 0);
        assert!(!res.truncated);
        let note = res.note.expect("an empty graph must explain itself");
        assert!(
            note.contains("no session entities"),
            "note should name the cause: {note}"
        );
    }
}
