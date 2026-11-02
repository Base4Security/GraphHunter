//! Temporal summary for session hub nodes.
//!
//! A session is the one entity in the graph that inherently *has a
//! duration*: it opens, it is used, it ends. The distinction the AD-CAP
//! investigation turned on — a sustained 87-minute session with 26 token
//! renewals versus a 1,3-minute credential check — is a property of that
//! span, and before this pass it had to be reconstructed by hand from
//! event timestamps.
//!
//! **Why the span lives on the node and not on the edges.** The obvious
//! shape is an edge with `[start, end]`, but [`crate::relation::
//! CompactRelation`] is pinned at 32 bytes by a test, with a single byte
//! of padding left. A second timestamp would push it to 40 — a 25% rise
//! on the largest structure in the system, roughly 1,6 GB on a 200M-edge
//! graph, paid by every edge to serve the few that have a duration.
//! [`crate::entity::Entity`] already carries free-form metadata, and a
//! session is exactly the thing whose duration is being described, so the
//! span belongs there. Edges stay points in time, which is what they are.

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

use crate::generic::session_entity_type;
use crate::graph::GraphHunter;
use crate::types::EntityType;

/// Metadata keys written onto each session node.
pub const K_FIRST_SEEN: &str = "session_first_seen";
pub const K_LAST_SEEN: &str = "session_last_seen";
pub const K_DURATION: &str = "session_duration_seconds";
pub const K_EVENTS: &str = "session_event_count";

/// What one session's edges add up to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SessionSpan {
    pub first_seen: i64,
    pub last_seen: i64,
    pub event_count: usize,
}

impl SessionSpan {
    pub fn duration_seconds(&self) -> i64 {
        self.last_seen - self.first_seen
    }
}

/// One session that more than one account was seen on.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SharedSession {
    /// Node id, including the `session:` namespace prefix.
    pub session_id: String,
    /// Accounts observed on this session, sorted for stable output.
    pub accounts: Vec<String>,
    /// Addresses the session was opened from, sorted.
    pub addresses: Vec<String>,
    pub first_seen: i64,
    pub last_seen: i64,
    pub duration_seconds: i64,
    pub event_count: usize,
}

impl GraphHunter {
    /// Folds each session node's edge timestamps into a span and writes it
    /// onto the node's metadata. Idempotent: re-running overwrites with the
    /// same answer, so it is safe to call after every ingest.
    ///
    /// Returns how many session nodes were summarized. Zero is the normal
    /// answer for sources that carry no correlation id, and is not an
    /// error.
    pub fn summarize_sessions(&mut self) -> usize {
        let ids = match self.entity_ids_for_type(&session_entity_type()) {
            Some(ids) if !ids.is_empty() => ids,
            _ => return 0,
        };

        // Two phases: the fold borrows the graph immutably to read
        // adjacency, the write borrows it mutably. Collecting the spans
        // first keeps both borrows short and non-overlapping.
        let mut spans: HashMap<String, SessionSpan> = HashMap::with_capacity(ids.len());
        for id in &ids {
            if let Some(span) = self.session_span(id) {
                spans.insert(id.clone(), span);
            }
        }

        let mut written = 0usize;
        for (id, span) in spans {
            if let Some(e) = self.get_entity_mut(&id) {
                e.metadata
                    .insert(K_FIRST_SEEN.to_string(), span.first_seen.to_string());
                e.metadata
                    .insert(K_LAST_SEEN.to_string(), span.last_seen.to_string());
                e.metadata
                    .insert(K_DURATION.to_string(), span.duration_seconds().to_string());
                e.metadata
                    .insert(K_EVENTS.to_string(), span.event_count.to_string());
                written += 1;
            }
        }
        written
    }

    /// Sessions that more than one account was seen on.
    ///
    /// A stolen token or a shared cookie shows up here and almost nowhere
    /// else: one session id, two identities. On the corpus this was built
    /// for, exactly **one** of 60.145 sessions matched, and it joined the
    /// two accounts the incident had already confirmed as taken over —
    /// evidence of a single operator that no time-correlation argument had
    /// produced.
    ///
    /// **Why this is a function and not a catalog pattern.** The DSL's
    /// `HAVING` groups by the first node of a path, and the session edges
    /// run `User -[Uses]-> Session`, so a pattern can group by account but
    /// not by session. Flipping the edge to `Session -[By]-> User` would
    /// make it expressible and cost the two-hop pivot in `cat-032`;
    /// measured against real data the flip buys a single row, so the model
    /// stays as it is and the rare-but-valuable question gets a dedicated
    /// walk instead. Reverse traversal is something the graph supports
    /// perfectly well outside the DSL — the limitation was only in the
    /// aggregation grammar.
    ///
    /// Results are sorted by account count descending, then by session id,
    /// so output is stable across runs.
    pub fn sessions_with_multiple_accounts(&self) -> Vec<SharedSession> {
        let ids = match self.entity_ids_for_type(&session_entity_type()) {
            Some(ids) if !ids.is_empty() => ids,
            _ => return Vec::new(),
        };

        let mut out = Vec::new();
        for id in ids {
            let accounts = self.accounts_on_session(&id);
            if accounts.len() < 2 {
                continue;
            }
            let span = self.session_span(&id);
            let mut addresses: Vec<String> = self
                .neighbors_incl_tail_by_id(&id)
                .iter()
                .filter_map(|e| self.id_for_sid(e.dest_sid))
                .filter(|n| {
                    self.get_entity(n)
                        .is_some_and(|e| e.entity_type == EntityType::IP)
                })
                .map(str::to_string)
                .collect();
            addresses.sort();
            addresses.dedup();

            out.push(SharedSession {
                session_id: id,
                accounts,
                addresses,
                first_seen: span.map(|s| s.first_seen).unwrap_or(0),
                last_seen: span.map(|s| s.last_seen).unwrap_or(0),
                duration_seconds: span.map(|s| s.duration_seconds()).unwrap_or(0),
                event_count: span.map(|s| s.event_count).unwrap_or(0),
            });
        }

        out.sort_by(|a, b| {
            b.accounts
                .len()
                .cmp(&a.accounts.len())
                .then_with(|| a.session_id.cmp(&b.session_id))
        });
        out
    }

    /// Accounts on a session, deduplicated and sorted.
    ///
    /// The reverse index lists a predecessor once per edge rather than
    /// once per node, so an account with twenty events on a session
    /// appears twenty times. Deduplicating here is what keeps
    /// `accounts.len() >= 2` meaning "two accounts" rather than "two
    /// events".
    fn accounts_on_session(&self, session_id: &str) -> Vec<String> {
        let mut seen = std::collections::HashSet::new();
        let mut accounts: Vec<String> = self
            .get_reverse_source_sids(session_id)
            .iter()
            .filter(|sid| seen.insert(**sid))
            .filter_map(|sid| self.id_for_sid(*sid))
            .filter(|n| {
                self.get_entity(n)
                    .is_some_and(|e| e.entity_type == EntityType::User)
            })
            .map(str::to_string)
            .collect();
        accounts.sort();
        accounts.dedup();
        accounts
    }

    /// The span of one session, or `None` when it has no edges at all.
    ///
    /// Outgoing edges (`Session -[From]-> IP`) are the common case and are
    /// read directly. A session that named a user but no address has only
    /// the incoming `User -[Uses]-> Session` edge; that fallback walks the
    /// reverse index, which is why it is second — it costs a neighbour
    /// scan per predecessor and is rare in practice.
    pub fn session_span(&self, session_id: &str) -> Option<SessionSpan> {
        let mut first = i64::MAX;
        let mut last = i64::MIN;
        let mut count = 0usize;

        for edge in self.neighbors_incl_tail_by_id(session_id) {
            first = first.min(edge.timestamp);
            last = last.max(edge.timestamp);
            count += 1;
        }

        if count == 0 {
            let target = self.sid_for_id(session_id)?;
            // The reverse index lists a predecessor once per edge, not once
            // per node. Walking it undeduplicated visits each predecessor's
            // whole neighbour list again for every edge it contributed, so
            // a node with k edges into this session gets counted k² times.
            // Same shape as the `events_for_node` defect found during the
            // AD-CAP hunt, caught here by the event count coming back as 4
            // for two edges.
            let mut seen: std::collections::HashSet<_> = std::collections::HashSet::new();
            for &pred_sid in self.get_reverse_source_sids(session_id) {
                if !seen.insert(pred_sid) {
                    continue;
                }
                for edge in self.neighbors_incl_tail(pred_sid) {
                    if edge.dest_sid == target {
                        first = first.min(edge.timestamp);
                        last = last.max(edge.timestamp);
                        count += 1;
                    }
                }
            }
        }

        if count == 0 {
            return None;
        }
        Some(SessionSpan {
            first_seen: first,
            last_seen: last,
            event_count: count,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::entity::Entity;
    use crate::relation::Relation;
    use crate::types::{EntityType, RelationType};

    fn graph_with_session(id: &str, stamps: &[i64]) -> GraphHunter {
        let mut g = GraphHunter::new();
        g.add_entity(Entity::new(id, session_entity_type()))
            .expect("session node");
        for (i, ts) in stamps.iter().enumerate() {
            let ip = format!("10.0.0.{i}");
            g.add_entity(Entity::new(&ip, EntityType::IP)).ok();
            g.add_relation(Relation::new(
                id,
                &ip,
                RelationType::Other("From".into()),
                *ts,
            ))
            .expect("edge");
        }
        g
    }

    /// The distinction the investigation turned on: a sustained session
    /// versus a quick credential check, read off the node instead of
    /// reconstructed from raw events.
    #[test]
    fn a_sustained_session_and_a_quick_one_are_told_apart() {
        let mut sustained = graph_with_session("session:long", &[1_000, 3_000, 6_220]);
        assert_eq!(sustained.summarize_sessions(), 1);
        let e = sustained.get_entity("session:long").expect("node");
        assert_eq!(e.metadata.get(K_DURATION).map(String::as_str), Some("5220"));
        assert_eq!(e.metadata.get(K_EVENTS).map(String::as_str), Some("3"));
        assert_eq!(
            e.metadata.get(K_FIRST_SEEN).map(String::as_str),
            Some("1000")
        );
        assert_eq!(
            e.metadata.get(K_LAST_SEEN).map(String::as_str),
            Some("6220")
        );

        let mut quick = graph_with_session("session:short", &[500, 578]);
        quick.summarize_sessions();
        let e = quick.get_entity("session:short").expect("node");
        assert_eq!(e.metadata.get(K_DURATION).map(String::as_str), Some("78"));
    }

    /// A session observed once has a real zero-length span, which is not
    /// the same as having no span. Reporting it keeps "instant" and
    /// "unknown" distinguishable.
    #[test]
    fn a_single_event_session_has_a_zero_span_not_a_missing_one() {
        let mut g = graph_with_session("session:one", &[42]);
        assert_eq!(g.summarize_sessions(), 1);
        let e = g.get_entity("session:one").expect("node");
        assert_eq!(e.metadata.get(K_DURATION).map(String::as_str), Some("0"));
        assert_eq!(e.metadata.get(K_EVENTS).map(String::as_str), Some("1"));
    }

    /// Sessions that only ever named a user still get a span, via the
    /// reverse index.
    #[test]
    fn a_session_with_only_an_incoming_edge_is_still_summarized() {
        let mut g = GraphHunter::new();
        g.add_entity(Entity::new("session:rev", session_entity_type()))
            .expect("session");
        g.add_entity(Entity::new("alice", EntityType::User))
            .expect("user");
        for ts in [700i64, 900] {
            g.add_relation(Relation::new(
                "alice",
                "session:rev",
                RelationType::Other("Uses".into()),
                ts,
            ))
            .expect("edge");
        }
        assert_eq!(g.summarize_sessions(), 1);
        let e = g.get_entity("session:rev").expect("node");
        assert_eq!(e.metadata.get(K_DURATION).map(String::as_str), Some("200"));
        assert_eq!(e.metadata.get(K_EVENTS).map(String::as_str), Some("2"));
    }

    /// Re-running after another ingest must not accumulate or drift.
    #[test]
    fn summarizing_twice_gives_the_same_answer() {
        let mut g = graph_with_session("session:idem", &[10, 20, 30]);
        assert_eq!(g.summarize_sessions(), 1);
        let first = g.get_entity("session:idem").unwrap().metadata.clone();
        assert_eq!(g.summarize_sessions(), 1);
        let second = g.get_entity("session:idem").unwrap().metadata.clone();
        assert_eq!(first, second);
    }

    /// A graph without sessions is the normal case for most sources and
    /// must cost nothing and report nothing.
    #[test]
    fn a_graph_without_sessions_summarizes_none() {
        let mut g = GraphHunter::new();
        g.add_entity(Entity::new("10.0.0.1", EntityType::IP)).ok();
        assert_eq!(g.summarize_sessions(), 0);
    }

    /// The AD-CAP shape: one session id carrying two victim accounts,
    /// both from the same hosting address. This is the row the real
    /// corpus produced -- one hit out of 60.145 sessions, joining the two
    /// confirmed takeovers.
    #[test]
    fn a_session_shared_by_two_accounts_is_reported() {
        use crate::generic::{GenericParser, session_entity_type};
        use crate::parser::LogParser;

        let log = r#"[
          {"timestamp":"2026-07-23T19:57:48Z","username":"victima.uno@example.com",
           "sessionId":"aaaa0001","ipAddress":"203.0.113.210"},
          {"timestamp":"2026-07-23T20:12:13Z","username":"victima.dos@example.com",
           "sessionId":"aaaa0001","ipAddress":"203.0.113.210"},
          {"timestamp":"2026-07-23T20:15:00Z","username":"innocent@example.com",
           "sessionId":"other-session","ipAddress":"198.51.100.141"}
        ]"#;

        let mut g = GraphHunter::new();
        for (src, rel, dst) in GenericParser.parse(log) {
            g.add_entity(src).ok();
            g.add_entity(dst).ok();
            g.add_relation(rel).ok();
        }
        let _ = session_entity_type();

        let shared = g.sessions_with_multiple_accounts();
        assert_eq!(shared.len(), 1, "only the two-account session qualifies");
        let s = &shared[0];
        assert_eq!(s.session_id, "session:aaaa0001");
        assert_eq!(
            s.accounts,
            vec![
                "victima.dos@example.com".to_string(),
                "victima.uno@example.com".to_string()
            ]
        );
        assert_eq!(s.addresses, vec!["203.0.113.210".to_string()]);
        assert_eq!(s.duration_seconds, 865);
    }

    /// A single account with many events on one session must not read as
    /// many accounts -- the reverse index lists a predecessor once per
    /// edge, and that is exactly how this would go wrong.
    #[test]
    fn many_events_from_one_account_is_not_many_accounts() {
        use crate::generic::session_entity_type;

        let mut g = GraphHunter::new();
        g.add_entity(Entity::new("session:busy", session_entity_type()))
            .expect("session");
        g.add_entity(Entity::new("alice", EntityType::User))
            .expect("user");
        for ts in 0..25i64 {
            g.add_relation(Relation::new(
                "alice",
                "session:busy",
                RelationType::Other("Uses".into()),
                1_000 + ts,
            ))
            .expect("edge");
        }
        assert!(
            g.sessions_with_multiple_accounts().is_empty(),
            "25 events from one account is one account"
        );
    }

    /// The gap the per-batch cap could not close: many small ingests,
    /// each well under the batch ceiling, must still not take the graph
    /// past it in aggregate. This is the streaming case.
    #[test]
    fn the_ceiling_holds_across_separate_ingests() {
        use crate::generic::GenericParser;
        use crate::parser::LogParser;

        // SAFETY: restored before the test returns.
        unsafe { std::env::set_var("GRAPHHUNTER_MAX_SESSION_ENTITIES", "3") };

        let mut g = GraphHunter::new();
        // Five separate ingests of one session each: every batch is far
        // under the cap, so the parser-side guard never fires.
        for i in 0..5 {
            let log = format!(
                r#"[{{"timestamp":"2026-07-24T19:4{i}:51Z","username":"u{i}","sessionId":"s{i}","ipAddress":"10.0.0.{i}"}}]"#
            );
            g.ingest_logs(&log, &GenericParser, None).expect("ingest");
        }
        unsafe { std::env::remove_var("GRAPHHUNTER_MAX_SESSION_ENTITIES") };

        assert_eq!(
            g.session_entity_count(),
            3,
            "the graph-wide ceiling must hold across batches, not per batch"
        );
        assert!(
            g.sessions_refused() > 0,
            "refusals must be counted, not silently dropped"
        );
        // The non-session part of every event still lands: the ceiling
        // bounds sessions, not the ingest.
        assert!(
            g.get_entity("u4").is_some() && g.get_entity("10.0.0.4").is_some(),
            "the fifth event's user and address must still be in the graph"
        );
    }

    /// Under the ceiling nothing is refused and nothing is reported.
    #[test]
    fn an_ingest_under_the_ceiling_refuses_nothing() {
        use crate::generic::GenericParser;
        use crate::parser::LogParser;

        let mut g = GraphHunter::new();
        let log = r#"[{"timestamp":"2026-07-24T19:42:51Z","username":"a","sessionId":"s1","ipAddress":"10.0.0.1"}]"#;
        g.ingest_logs(log, &GenericParser, None).expect("ingest");
        assert_eq!(g.session_entity_count(), 1);
        assert_eq!(g.sessions_refused(), 0);
    }

    /// A graph with no sessions must answer nothing rather than scan.
    #[test]
    fn no_sessions_means_no_shared_sessions() {
        let mut g = GraphHunter::new();
        g.add_entity(Entity::new("10.0.0.1", EntityType::IP)).ok();
        assert!(g.sessions_with_multiple_accounts().is_empty());
    }

    /// End to end, on the shape that motivated the feature: one session
    /// observed from two addresses. Before this, answering it meant a
    /// script over the raw CSV; here it is structure in the graph, which
    /// `Session -[From]-> IP` reaches directly.
    #[test]
    fn one_session_seen_from_two_addresses_is_graph_structure() {
        use crate::generic::{GenericParser, is_session_entity};
        use crate::parser::LogParser;

        let log = r#"[
          {"timestamp":"2026-07-24T14:26:15Z","username":"victim@example.com",
           "sessionId":"e6516095-aaaa","ipAddress":"103.50.33.107"},
          {"timestamp":"2026-07-24T14:26:49Z","username":"victim@example.com",
           "sessionId":"e6516095-aaaa","ipAddress":"38.165.230.130"}
        ]"#;

        let mut g = GraphHunter::new();
        for (src, rel, dst) in GenericParser.parse(log) {
            g.add_entity(src).ok();
            g.add_entity(dst).ok();
            g.add_relation(rel).ok();
        }
        assert_eq!(g.summarize_sessions(), 1);

        let sid = "session:e6516095-aaaa";
        let session = g.get_entity(sid).expect("session node");
        assert!(is_session_entity(session));

        // Two distinct addresses reached from the one session — the
        // cross-provider handoff, as structure rather than as a join.
        let ips: std::collections::HashSet<String> = g
            .neighbors_incl_tail_by_id(sid)
            .iter()
            .filter_map(|e| g.id_for_sid(e.dest_sid).map(str::to_string))
            .collect();
        assert_eq!(
            ips,
            ["103.50.33.107".to_string(), "38.165.230.130".to_string()]
                .into_iter()
                .collect()
        );

        // And the 34-second gap the report quoted, read off the node.
        assert_eq!(
            session.metadata.get(K_DURATION).map(String::as_str),
            Some("34")
        );
    }
}
