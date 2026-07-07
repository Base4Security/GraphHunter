//! Session registry.
//!
//! A [`Session`] owns the per-workspace `GraphHunter` instance plus the
//! analyst's annotations (tags, notes, path pins, datasets). The
//! [`SessionStore`] is the registry: create / look up / remove / switch
//! current. Its internal locks are exposed behind `Arc` handles so the
//! legacy Tauri `AppState` can share the same `HashMap` during P1
//! migration — there is exactly one store, not a dual-write between
//! legacy and canonical.
//!
//! Locking:
//! - Outer map + current ptr use `std::sync::RwLock` (same API as the
//!   existing Tauri helpers — `read().map_err(...)` — so migration of
//!   `with_current_graph` et al. doesn't need to change error handling).
//! - Per-session inner locks (`graph`, `notes`, `tags`, `datasets`,
//!   `path_node_ids`) also use `std::sync::RwLock` for the same reason.

use std::collections::HashMap;
use std::sync::{Arc, RwLock};

use graph_hunter_core::GraphHunter;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::ai::AiConversation;
use crate::state::agentic::MappingReviewQueue;
use crate::state::session_types::{DatasetInfo, EntityTag, LiveTailStats, Note, SessionPhase};

/// Opaque identifier for a loaded session.
///
/// Wraps a `String` (not a `Uuid`) because existing session IDs are
/// validated as `[A-Za-z0-9_-]` and are not always UUIDs in practice
/// (tests and CLI tooling use descriptive IDs). Serializes transparently
/// so over-the-wire the handle is just the plain ID string.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct SessionHandle(String);

impl SessionHandle {
    /// Fresh UUID-v4 handle. Use for new sessions created server-side.
    pub fn new() -> Self {
        Self(Uuid::new_v4().to_string())
    }

    /// Wrap an existing id string (e.g. loaded from disk).
    pub fn from_string(s: impl Into<String>) -> Self {
        Self(s.into())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn into_string(self) -> String {
        self.0
    }
}

impl Default for SessionHandle {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Display for SessionHandle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.fmt(f)
    }
}

impl From<String> for SessionHandle {
    fn from(s: String) -> Self {
        Self(s)
    }
}

impl From<&str> for SessionHandle {
    fn from(s: &str) -> Self {
        Self(s.to_string())
    }
}

/// In-memory session state: one graph per session plus the analyst's
/// workspace annotations.
///
/// Was `app/src-tauri/src/state.rs::SessionState`; Tauri re-exports this
/// type as `SessionState` for backwards compat during P1 migration.
pub struct Session {
    pub id: String,
    pub name: String,
    pub created_at: i64,
    pub graph: RwLock<GraphHunter>,
    /// Node IDs pinned as path nodes (fixed in graph, persisted with session).
    pub path_node_ids: RwLock<Vec<String>>,
    /// Notes (standalone or linked to a node), persisted with session.
    pub notes: RwLock<Vec<Note>>,
    /// Ingested datasets (for lateral menu: list, remove, rename types).
    pub datasets: RwLock<Vec<DatasetInfo>>,
    /// Entity tags — primarily used for IoC marking (`ioc:malicious`,
    /// `benign:confirmed`, etc.). Exported via the canonical `export_iocs`.
    pub tags: RwLock<Vec<EntityTag>>,
    /// AI conversation history. Per-session (fixes the bug from the
    /// feedback: switching sessions used to reuse a global history).
    /// NOT persisted in `SessionFile` — chat transcripts are ephemeral
    /// by design.
    pub ai_conversation: RwLock<AiConversation>,
    /// Pending / resolved drafts produced by the agentic slow lane.
    /// In-memory only for M4; cleared on process restart. Persistence
    /// is part of the M5/M7 mapping-library work.
    pub agentic_review: RwLock<MappingReviewQueue>,
    /// D3 stage 3 — persistent LFTJ cache, keyed on the graph's
    /// mutation_version. Survives across `run_hunt_batch` calls
    /// and is invalidated cheaply by the version comparator. The
    /// forward trie and ts_map are shared by triangle / K4 / K5;
    /// the reverse trie is built lazily on first C6 dispatch and
    /// cached separately. Stored on the Session (not the
    /// `GraphHunter` itself) because the cache is API-layer
    /// concept — `core/graph-engine` doesn't own the run-hunt
    /// concept and shouldn't carry rayon-built indexes that only
    /// matter to batch lifetimes.
    pub lftj_cache: RwLock<Option<LftjSessionCache>>,
    /// D3 stage 5 — Session-level Yannakakis bag cache. Mirror of
    /// `lftj_cache` for the α-acyclic chain dispatch path. Persists
    /// `Bag` materializations across `run_hunt_batch` calls keyed on
    /// the graph's `mutation_version`. FIFO-bounded by total cached
    /// `BagRow` bytes (`MAX_BAG_BYTES`) so a long-lived session
    /// running many α-acyclic templates doesn't OOM — bags can be
    /// large (one row per matching edge, 24 B per row).
    pub yannakakis_cache: RwLock<Option<YannakakisSessionCache>>,
    /// Hybrid ingest lifecycle — gates hunts during load/finalize.
    pub phase: RwLock<SessionPhase>,
    /// Post-finalize tail append counters (Track H).
    pub live_tail_stats: RwLock<LiveTailStats>,
    /// Graph-cycle proposals (§4.2) keyed by `proposal_id`. `graph_propose`
    /// writes them; `graph_build` reads by id. Ephemeral — NOT persisted in
    /// `SessionFile` (a proposal is only meaningful against the live schema
    /// it was derived from), same policy as `ai_conversation`.
    pub proposals: RwLock<std::collections::HashMap<String, crate::dto::sentinel::GraphProposal>>,
    /// Most recent `graph_build` (§4.3), surfaced in §5 status as `last_build`.
    /// Ephemeral — cleared on process restart.
    pub last_build: RwLock<Option<crate::dto::sentinel::BuildRecord>>,
}

/// D3 stage 3+4 — Session-level LFTJ index cache. Built lazily on
/// the first LFTJ-routed batch hypothesis and reused across
/// subsequent batches until the graph mutates. The `version`
/// field captures `GraphHunter::mutation_version()` at build
/// time; on each batch entry the API code compares this to the
/// live counter and invalidates the cache on mismatch.
///
/// Stage 4 generalizations vs. stage 3:
///   * Typed tries — instead of a single forward/reverse pair,
///     the cache holds a map keyed on the homogeneous-shape
///     signature (`Option<(rel_type_tag, vertex_type_tag)>`).
///     `None` is the type-blind trie (used by name-marker-only
///     dispatch); concrete keys are typed tries built via
///     `build_lftj_trie_for`. A single session that fires K4-Auth
///     and C6-Connect templates back-to-back keeps both tries
///     warm without rebuilding either.
///   * Persistent canonical raw-result cache — the LFTJ raw
///     enumerate output (keyed on dispatch plan, type signature,
///     time window) is kept alive across batches too. FIFO
///     eviction at `MAX_CANONICAL_ENTRIES` keeps the memory
///     footprint bounded regardless of how many distinct
///     templates a session fires.
pub struct LftjSessionCache {
    pub version: u64,
    /// Typed-trie map. Key is the homogeneous-shape signature or
    /// `None` for the type-blind trie. Each entry holds the
    /// forward trie + ts_map plus an optional reverse (built
    /// lazily on first C6 dispatch for that key).
    pub typed_tries: HashMap<Option<(u8, u8)>, LftjTypedTrie>,
    /// Persistent canonical raw-result cache. Survives across
    /// batches; bounded at `MAX_CANONICAL_ENTRIES` with FIFO
    /// eviction (oldest insertion order discarded first).
    pub canonical_results: HashMap<LftjCanonicalKey, Arc<Vec<graph_hunter_core::graph::HuntResult>>>,
    /// Insertion-order witness for FIFO eviction. Front = oldest.
    pub canonical_results_order: std::collections::VecDeque<LftjCanonicalKey>,
}

/// Maximum number of distinct LFTJ canonical raw-result entries
/// kept warm across batches. Each entry is a `Vec<HuntResult>`
/// of size up to `max_results` (default 10K paths × ~6 vertices
/// × ~40 B/Arc<str> = ~2.4 MB per entry). At 64 entries this
/// caps the canonical-cache footprint at ~150 MB per session,
/// the right shape for SOC template batteries that fire many
/// distinct templates against a single graph.
pub const MAX_CANONICAL_ENTRIES: usize = 64;

/// Per-(type-signature) typed trie entry. Reverse is C6-only
/// and populated lazily on first C6 dispatch.
pub struct LftjTypedTrie {
    pub forward: Arc<graph_hunter_core::lftj::MaterializedCsrTrie>,
    pub ts_map: Arc<graph_hunter_core::lftj_query::MinTimestampMap>,
    pub reverse: Option<Arc<graph_hunter_core::lftj::MaterializedCsrTrie>>,
}

/// Cache key for the persistent LFTJ canonical raw-result cache.
/// The plan + type signature + time window together canonicalize
/// the enumerate output: two hypotheses agreeing on this tuple
/// produce identical raw paths.
pub type LftjCanonicalKey = (
    graph_hunter_core::planner::DispatchPlan,
    Option<(u8, u8)>,
    i64,
    i64,
);

/// Maximum bytes of `BagRow` payload kept warm in the Yannakakis
/// cache. ~256 MB cap — enough for ~10M cached BagRows (24 B each)
/// across all live (step, window) signatures. A typical SOC
/// template touches 1–5 distinct steps; at this cap we keep ~50
/// templates worth of bags warm before FIFO eviction kicks in.
pub const MAX_BAG_BYTES: usize = 256 * 1024 * 1024;

/// Maximum bytes of prefix-snapshot payload kept warm. Prefix
/// snapshots are smaller per-entry than bags (one entry per
/// surviving partial chain at depth K) but the per-batch
/// `PREFIX_CACHE_CAP` of 50K entries × ~40 B per entry × ~64
/// distinct prefixes can still reach hundreds of MB. Cap at
/// 128 MB — half the bag budget, since the Yannakakis chain
/// enumerator pays bag cost first and prefix cost second.
pub const MAX_PREFIX_BYTES: usize = 128 * 1024 * 1024;

/// D3 stage 5 — Session-level Yannakakis cache. Persists `Bag`
/// materializations and prefix snapshots across `run_hunt_batch`
/// calls. Each cache FIFO-evicts on its own total byte budget
/// (`MAX_BAG_BYTES`, `MAX_PREFIX_BYTES`); bag and prefix entries
/// don't compete for the same budget because their access
/// patterns differ (bag = wide reuse across templates that share
/// a step; prefix = narrow reuse across templates that share an
/// initial chain slice).
pub struct YannakakisSessionCache {
    pub version: u64,
    pub bags: HashMap<String, Arc<graph_hunter_core::yannakakis::Bag>>,
    pub bags_order: std::collections::VecDeque<String>,
    pub bags_bytes: usize,
    pub prefixes: HashMap<
        String,
        Arc<Vec<(Vec<graph_hunter_core::interner::StrId>, i64)>>,
    >,
    pub prefixes_order: std::collections::VecDeque<String>,
    pub prefixes_bytes: usize,
}

impl YannakakisSessionCache {
    /// Fresh empty cache stamped with a graph version.
    pub fn new(version: u64) -> Self {
        Self {
            version,
            bags: HashMap::new(),
            bags_order: std::collections::VecDeque::new(),
            bags_bytes: 0,
            prefixes: HashMap::new(),
            prefixes_order: std::collections::VecDeque::new(),
            prefixes_bytes: 0,
        }
    }

    /// Approximate byte cost of a `Bag` (excludes the `Vec` header
    /// + any spare capacity, since callers shouldn't reserve much).
    fn bag_bytes(bag: &graph_hunter_core::yannakakis::Bag) -> usize {
        bag.rows.len() * std::mem::size_of::<graph_hunter_core::yannakakis::BagRow>()
    }

    /// Approximate byte cost of a prefix snapshot. Each entry is a
    /// `(Vec<StrId>, i64)` pair; the `Vec<StrId>` contents dominate
    /// (one StrId = 4 bytes per visited vertex). Avg depth is
    /// captured from the first entry — prefix snapshots at a fixed
    /// depth all have equal-length inner vecs, so the first row is
    /// representative.
    fn prefix_bytes(
        snapshot: &Vec<(Vec<graph_hunter_core::interner::StrId>, i64)>,
    ) -> usize {
        let depth_bytes = snapshot
            .first()
            .map(|(v, _)| v.len() * std::mem::size_of::<graph_hunter_core::interner::StrId>())
            .unwrap_or(0);
        snapshot.len() * (depth_bytes + std::mem::size_of::<i64>())
    }

    /// Insert a bag, evicting oldest entries until the total byte
    /// budget fits. Returns `true` when the entry was newly inserted;
    /// `false` when the key already existed (the previous value is
    /// overwritten with the new one but the FIFO position is
    /// unchanged).
    pub fn insert(
        &mut self,
        key: String,
        bag: Arc<graph_hunter_core::yannakakis::Bag>,
    ) -> bool {
        let new_bytes = Self::bag_bytes(&bag);
        let is_new = !self.bags.contains_key(&key);
        if is_new {
            // Evict from the front until we fit. Stop if we'd
            // empty the cache and STILL not fit — in that case
            // the bag itself exceeds the budget; insert it anyway
            // (one big bag is better than no bags) but the next
            // insert will evict it.
            while self.bags_bytes + new_bytes > MAX_BAG_BYTES
                && !self.bags_order.is_empty()
            {
                let evict_key = self.bags_order.pop_front().expect("non-empty");
                if let Some(evicted) = self.bags.remove(&evict_key) {
                    self.bags_bytes =
                        self.bags_bytes.saturating_sub(Self::bag_bytes(&evicted));
                }
            }
            self.bags_order.push_back(key.clone());
            self.bags_bytes += new_bytes;
        }
        self.bags.insert(key, bag);
        is_new
    }

    /// Insert a prefix snapshot with the same FIFO + byte-budget
    /// semantics as `insert`. Returns `true` on a new key.
    pub fn insert_prefix(
        &mut self,
        key: String,
        snapshot: Arc<Vec<(Vec<graph_hunter_core::interner::StrId>, i64)>>,
    ) -> bool {
        let new_bytes = Self::prefix_bytes(&snapshot);
        let is_new = !self.prefixes.contains_key(&key);
        if is_new {
            while self.prefixes_bytes + new_bytes > MAX_PREFIX_BYTES
                && !self.prefixes_order.is_empty()
            {
                let evict_key = self.prefixes_order.pop_front().expect("non-empty");
                if let Some(evicted) = self.prefixes.remove(&evict_key) {
                    self.prefixes_bytes = self
                        .prefixes_bytes
                        .saturating_sub(Self::prefix_bytes(&evicted));
                }
            }
            self.prefixes_order.push_back(key.clone());
            self.prefixes_bytes += new_bytes;
        }
        self.prefixes.insert(key, snapshot);
        is_new
    }
}

impl Session {
    pub fn new(
        id: impl Into<String>,
        name: impl Into<String>,
        graph: GraphHunter,
        created_at: i64,
    ) -> Self {
        Self {
            id: id.into(),
            name: name.into(),
            created_at,
            graph: RwLock::new(graph),
            path_node_ids: RwLock::new(Vec::new()),
            notes: RwLock::new(Vec::new()),
            datasets: RwLock::new(Vec::new()),
            tags: RwLock::new(Vec::new()),
            ai_conversation: RwLock::new(AiConversation::new()),
            agentic_review: RwLock::new(MappingReviewQueue::new()),
            lftj_cache: RwLock::new(None),
            yannakakis_cache: RwLock::new(None),
            phase: RwLock::new(SessionPhase::Loading),
            live_tail_stats: RwLock::new(LiveTailStats::default()),
            proposals: RwLock::new(std::collections::HashMap::new()),
            last_build: RwLock::new(None),
        }
    }

    pub fn phase(&self) -> SessionPhase {
        *self
            .phase
            .read()
            .unwrap_or_else(|e| e.into_inner())
    }

    pub fn set_phase(&self, phase: SessionPhase) {
        *self
            .phase
            .write()
            .unwrap_or_else(|e| e.into_inner()) = phase;
    }

    /// Record post-finalize appends: when the streaming graph is finalized
    /// and new relations land while the session is `Ready`, enter
    /// `LiveTail` and bump live-tail stats.
    pub fn note_post_finalize_appends(&self, count: u64, timestamp: i64) {
        if count == 0 {
            return;
        }
        let finalized = self
            .graph
            .read()
            .ok()
            .map(|g| g.streaming_is_finalized())
            .unwrap_or(false);
        if !finalized {
            return;
        }
        match self.phase() {
            SessionPhase::Ready => self.set_phase(SessionPhase::LiveTail),
            SessionPhase::LiveTail => {}
            _ => return,
        }
        self.note_live_tail_relations(count, timestamp);
    }

    /// Increment live-tail counters when post-finalize appends land.
    fn note_live_tail_relations(&self, count: u64, timestamp: i64) {
        if count == 0 || self.phase() != SessionPhase::LiveTail {
            return;
        }
        let mut stats = self
            .live_tail_stats
            .write()
            .unwrap_or_else(|e| e.into_inner());
        stats.tail_edge_count = stats.tail_edge_count.saturating_add(count);
        stats.last_append_at = Some(timestamp);
    }
}

impl LftjSessionCache {
    /// Fresh empty cache stamped with a graph version. Both the
    /// typed-trie map and the canonical-result map start empty;
    /// entries accrete as batches dispatch.
    pub fn new(version: u64) -> Self {
        Self {
            version,
            typed_tries: HashMap::new(),
            canonical_results: HashMap::new(),
            canonical_results_order: std::collections::VecDeque::new(),
        }
    }

    /// Insert a canonical raw-result entry, evicting the oldest if
    /// `MAX_CANONICAL_ENTRIES` would be exceeded. Returns `true`
    /// when the entry was newly inserted; `false` when the key
    /// already existed (the previous value is overwritten with the
    /// new one but the FIFO position is unchanged).
    pub fn insert_canonical(
        &mut self,
        key: LftjCanonicalKey,
        paths: Arc<Vec<graph_hunter_core::graph::HuntResult>>,
    ) -> bool {
        let is_new = !self.canonical_results.contains_key(&key);
        if is_new {
            if self.canonical_results.len() >= MAX_CANONICAL_ENTRIES {
                if let Some(evict_key) = self.canonical_results_order.pop_front() {
                    self.canonical_results.remove(&evict_key);
                }
            }
            self.canonical_results_order.push_back(key);
        }
        self.canonical_results.insert(key, paths);
        is_new
    }
}

/// Registry of loaded sessions.
///
/// Internal state is wrapped in `Arc<RwLock<_>>` so it can be shared with
/// the legacy Tauri `AppState.sessions` / `current_session_id` fields
/// during P1 migration — both refer to the same map and pointer, no
/// dual-write or divergence possible.
#[derive(Clone)]
pub struct SessionStore {
    inner: Arc<RwLock<HashMap<String, Arc<Session>>>>,
    current: Arc<RwLock<Option<String>>>,
}

impl SessionStore {
    pub fn new() -> Self {
        Self {
            inner: Arc::new(RwLock::new(HashMap::new())),
            current: Arc::new(RwLock::new(None)),
        }
    }

    /// Handle to the shared map, for consumers that need to hold the same
    /// locked `HashMap` the store uses internally (e.g. the Tauri
    /// `AppState` re-export path during migration). The lock semantics
    /// are `std::sync::RwLock` (poisoning).
    pub fn map_handle(&self) -> Arc<RwLock<HashMap<String, Arc<Session>>>> {
        self.inner.clone()
    }

    /// Handle to the current-session pointer. Same sharing rationale as
    /// [`Self::map_handle`].
    pub fn current_handle(&self) -> Arc<RwLock<Option<String>>> {
        self.current.clone()
    }

    pub fn insert(&self, session: Arc<Session>) {
        let id = session.id.clone();
        let mut map = self.inner.write().expect("session map write");
        map.insert(id, session);
    }

    pub fn get(&self, id: &str) -> Option<Arc<Session>> {
        self.inner
            .read()
            .expect("session map read")
            .get(id)
            .cloned()
    }

    pub fn remove(&self, id: &str) -> Option<Arc<Session>> {
        self.inner.write().expect("session map write").remove(id)
    }

    pub fn list(&self) -> Vec<Arc<Session>> {
        self.inner
            .read()
            .expect("session map read")
            .values()
            .cloned()
            .collect()
    }

    pub fn len(&self) -> usize {
        self.inner.read().expect("session map read").len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub fn contains(&self, id: &str) -> bool {
        self.inner
            .read()
            .expect("session map read")
            .contains_key(id)
    }

    pub fn current_id(&self) -> Option<String> {
        self.current.read().expect("current read").clone()
    }

    pub fn set_current(&self, id: Option<String>) {
        *self.current.write().expect("current write") = id;
    }

    /// Resolve the current session, if any. Cheap — the `Arc<Session>` is
    /// cloned so callers don't hold the map lock.
    pub fn current_session(&self) -> Option<Arc<Session>> {
        let id = self.current_id()?;
        self.get(&id)
    }

    /// Convenience: resolve either an explicit handle or fall back to
    /// current. Returns `None` when neither resolves to a live session.
    pub fn resolve(&self, handle: Option<&SessionHandle>) -> Option<Arc<Session>> {
        match handle {
            Some(h) => self.get(h.as_str()),
            None => self.current_session(),
        }
    }
}

impl Default for SessionStore {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fresh_session(id: &str) -> Arc<Session> {
        Arc::new(Session::new(id, id, GraphHunter::new(), 0))
    }

    #[test]
    fn handle_roundtrips() {
        let h = SessionHandle::new();
        let s = h.to_string();
        let back = SessionHandle::from_string(s.clone());
        assert_eq!(h, back);
        assert_eq!(back.as_str(), s);
    }

    #[test]
    fn handle_serializes_as_plain_string() {
        let h = SessionHandle::from_string("my-sess-01");
        let j = serde_json::to_string(&h).unwrap();
        assert_eq!(j, "\"my-sess-01\"");
        let back: SessionHandle = serde_json::from_str(&j).unwrap();
        assert_eq!(back, h);
    }

    #[test]
    fn store_starts_empty() {
        let s = SessionStore::new();
        assert!(s.is_empty());
        assert_eq!(s.current_id(), None);
        assert!(s.current_session().is_none());
    }

    #[test]
    fn insert_then_get() {
        let store = SessionStore::new();
        store.insert(fresh_session("s1"));
        assert_eq!(store.len(), 1);
        assert!(store.contains("s1"));
        assert!(store.get("s1").is_some());
        assert!(store.get("s2").is_none());
    }

    #[test]
    fn set_current_and_resolve() {
        let store = SessionStore::new();
        store.insert(fresh_session("s1"));
        store.set_current(Some("s1".to_string()));
        assert!(store.current_session().is_some());

        let h = SessionHandle::from_string("s1");
        assert!(store.resolve(Some(&h)).is_some());
        assert!(store.resolve(None).is_some()); // falls through to current
    }

    #[test]
    fn resolve_missing_returns_none() {
        let store = SessionStore::new();
        let h = SessionHandle::from_string("does-not-exist");
        assert!(store.resolve(Some(&h)).is_none());
        assert!(store.resolve(None).is_none());
    }

    #[test]
    fn map_handle_is_the_same_arc() {
        let store = SessionStore::new();
        let handle_a = store.map_handle();
        let handle_b = store.map_handle();
        // Same Arc underneath — inserting through one is visible via the
        // other, proving the handle-sharing invariant for Tauri AppState.
        handle_a
            .write()
            .unwrap()
            .insert("x".to_string(), fresh_session("x"));
        assert!(handle_b.read().unwrap().contains_key("x"));
    }

    #[test]
    fn post_finalize_append_transitions_ready_to_live_tail() {
        use graph_hunter_core::parser::RawIngestEvent;
        use graph_hunter_core::{EntityType, RelationType};

        fn edge(src: &str, dst: &str, ts: i64) -> RawIngestEvent {
            RawIngestEvent {
                src_id: src.into(),
                src_type: EntityType::User,
                src_metadata: Default::default(),
                dst_id: dst.into(),
                dst_type: EntityType::Host,
                dst_metadata: Default::default(),
                rel_type: RelationType::Auth,
                rel_metadata: Default::default(),
                timestamp: ts,
            }
        }

        let mut g = GraphHunter::new();
        g.insert_raw_events(vec![edge("u1", "h1", 100)], None)
            .unwrap();
        g.sort_edges_by_timestamp().unwrap();
        assert!(g.streaming_is_finalized());

        let session = Session::new("s", "s", g, 0);
        session.set_phase(SessionPhase::Ready);

        let new_relations = {
            let mut g = session.graph.write().unwrap();
            let (_, nr) = g.insert_raw_events(vec![edge("u2", "h2", 200)], None)
                .unwrap();
            nr
        };
        session.note_post_finalize_appends(new_relations as u64, 42);

        assert_eq!(session.phase(), SessionPhase::LiveTail);
        let stats = session.live_tail_stats.read().unwrap();
        assert_eq!(stats.tail_edge_count, 1);
        assert_eq!(stats.last_append_at, Some(42));
    }
}
