use ahash::{HashMap, HashMapExt, HashSet, HashSetExt};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use rayon::prelude::*;

use crate::anomaly::{AnomalyScorer, ScoringWeights};
use crate::entity::Entity;
use crate::errors::GraphError;
use crate::hypothesis::Hypothesis;
use crate::interner::{StrId, StringInterner};
use crate::metadata_store::MetadataStore;
use crate::relation::{CompactRelation, Relation};
use crate::spill::SpillableEdgeStore;
use crate::types::{EntityType, MergePolicy, RelationType, entity_type_matches, relation_type_matches};

/// Result of a successful pattern match: an ordered list of entity IDs
/// representing the attack path through the graph.
pub type HuntResult = Vec<String>;

/// Iterative DFS frame. Module-level so it can appear in the
/// `dfs_match_iterative` signature (callers pass a reusable scratch stack).
struct DfsFrame {
    sid: StrId,
    step_idx: usize,
    edge_hi: usize,
    edge_cursor: usize,
}

/// Stack frame for the anomaly-pruned DFS. Carries the running path-anomaly
/// sum so the admissible heuristic can be evaluated without re-walking the
/// path. Module-level so it can appear in `dfs_match_smart`'s signature.
struct AnomalyFrame {
    sid: StrId,
    step_idx: usize,
    edge_hi: usize,
    edge_cursor: usize,
    path_anomaly_sum: f64,
}

/// Concrete heap type used by the smart top-K search.
///
/// Min-heap on `(score, path)`: the smallest-score entry sits at the root,
/// so when capacity is exceeded we pop the worst path. Wrapping in `Reverse`
/// inverts `BinaryHeap`'s default max-heap into a min-heap.
type SmartHeap = std::collections::BinaryHeap<
    std::cmp::Reverse<(ordered_float::OrderedFloat<f64>, Vec<String>)>,
>;

/// Sentinel tag value used by `entity_type_tags` to mean "no entity lives at
/// this StrId slot" (either it was never inserted or it has been removed).
/// 253 is unused by `EntityType::to_u8()` (which allocates 0..=8, 254 for
/// `Any`, and 255 for `Other(_)`) so it can't collide with a real tag.
const TAG_DEAD: u8 = 253;

/// The core threat hunting graph engine.
///
/// Stores entities in a HashMap keyed by interned StrId for memory efficiency.
/// Relations in a spillable edge store that can overflow to disk for large graphs.
/// All string IDs are interned via `StringInterner` — each unique ID stored once.
///
/// A parallel `entity_type_tags` array gives the DFS inner loop a cache-
/// friendly fast path: reading an entity's type becomes a single indexed
/// load into a `Vec<u8>` instead of a HashMap probe that pulls a full
/// `Entity` (≈120 bytes, mostly cold) into cache just to read ~1 byte.
#[derive(Clone)]
pub struct GraphHunter {
    /// String interner: stores each unique entity ID once.
    pub interner: StringInterner,
    pub entities: HashMap<StrId, Entity>,
    /// SoA hot-path index: `entity_type_tags[sid.index()]` holds the u8
    /// tag of the entity's type, or `TAG_DEAD` when the slot is empty
    /// (never populated, or removed). Kept in lockstep with `entities`.
    ///
    /// For `EntityType::Other(String)` the tag is 255 and the actual name
    /// lives in `other_type_names` — we keep custom names off this hot
    /// array so it stays a dense `Vec<u8>` indexable without indirection.
    pub(crate) entity_type_tags: Vec<u8>,
    /// Side table for `EntityType::Other(_)` names, keyed by the same StrId.
    /// Rarely populated — only matters when users add custom types via the
    /// DSL. Kept off the hot array so the common path stays tight.
    pub(crate) other_type_names: HashMap<StrId, String>,
    pub edge_store: SpillableEdgeStore,
    /// Index: entity type → set of interned entity IDs of that type.
    pub type_index: HashMap<EntityType, HashSet<StrId>>,
    /// Reverse adjacency: dest StrId → vec of source StrIds.
    pub reverse_adj: HashMap<StrId, Vec<StrId>>,
    /// Append-only metadata store for relation metadata.
    pub meta_store: MetadataStore,
    /// Unique dataset IDs. Index 0 = "no dataset".
    pub dataset_tags: Vec<Arc<str>>,
    /// Optional anomaly scorer for path ranking.
    pub anomaly_scorer: Option<AnomalyScorer>,
    /// Whether edges have been sorted by timestamp (avoids re-sorting on every search).
    edges_sorted: bool,
}

/// Checks if a relation type tag matches a pattern, treating Any as wildcard.
#[inline]
fn relation_type_tag_matches(pattern: &RelationType, tag: u8) -> bool {
    *pattern == RelationType::Any || pattern.to_u8() == tag
}

impl GraphHunter {
    /// Creates a new empty graph.
    pub fn new() -> Self {
        Self {
            interner: StringInterner::new(),
            entities: HashMap::new(),
            entity_type_tags: Vec::new(),
            other_type_names: HashMap::new(),
            edge_store: SpillableEdgeStore::with_default_budget(),
            type_index: HashMap::new(),
            reverse_adj: HashMap::new(),
            meta_store: MetadataStore::new(),
            dataset_tags: vec![Arc::from("")],
            anomaly_scorer: None,
            edges_sorted: false,
        }
    }

    /// Pre-allocates capacity for the internal HashMaps to avoid rehashing during bulk insertion.
    pub fn reserve(&mut self, entity_hint: usize, relation_hint: usize) {
        self.interner.reserve(entity_hint);
        self.entities.reserve(entity_hint);
        self.entity_type_tags.reserve(entity_hint);
        self.type_index.reserve(16);
        self.reverse_adj.reserve(entity_hint);
        let _ = relation_hint;
    }

    /// Ensures `entity_type_tags` has a slot at `sid.index()`, padding any
    /// prior gap with `TAG_DEAD`. Called by every entity insertion site.
    #[inline]
    fn ensure_tag_capacity(&mut self, sid: StrId) {
        let needed = sid.index() + 1;
        if self.entity_type_tags.len() < needed {
            self.entity_type_tags.resize(needed, TAG_DEAD);
        }
    }

    /// Records an entity's type in the SoA hot array. Must be called
    /// whenever `self.entities` is mutated so the two stay in sync.
    #[inline]
    fn set_entity_type_tag(&mut self, sid: StrId, et: &EntityType) {
        self.ensure_tag_capacity(sid);
        self.entity_type_tags[sid.index()] = et.to_u8();
        if let EntityType::Other(name) = et {
            self.other_type_names.insert(sid, name.clone());
        } else {
            // Transitioning away from Other(_) — drop the side-table entry.
            self.other_type_names.remove(&sid);
        }
    }

    /// Marks a slot as empty. Used after `entities.remove(..)`.
    #[inline]
    fn mark_entity_dead(&mut self, sid: StrId) {
        if let Some(slot) = self.entity_type_tags.get_mut(sid.index()) {
            *slot = TAG_DEAD;
        }
        self.other_type_names.remove(&sid);
    }

    /// Fast entity-type check against a pattern, reading only the SoA
    /// hot array (and, for `Other(_)`, a small side table). Semantics
    /// match `self.entities.get(&sid).map_or(false, |e| entity_type_matches(pattern, &e.entity_type))`
    /// but avoids the HashMap probe + full `Entity` deref on every DFS step.
    #[inline]
    pub(crate) fn fast_type_matches(&self, pattern: &EntityType, sid: StrId) -> bool {
        let idx = sid.index();
        let tag = match self.entity_type_tags.get(idx) {
            Some(&t) => t,
            None => return false,
        };
        if tag == TAG_DEAD {
            return false;
        }
        if matches!(pattern, EntityType::Any) {
            return true;
        }
        let pat_tag = pattern.to_u8();
        if pat_tag != tag {
            return false;
        }
        // Same tag; only `Other(_)` needs a string comparison to disambiguate.
        if tag == 255 {
            if let EntityType::Other(pat_name) = pattern {
                return self
                    .other_type_names
                    .get(&sid)
                    .map(|n| n == pat_name)
                    .unwrap_or(false);
            }
            return false;
        }
        true
    }

    /// Returns the number of entities (nodes) in the graph.
    pub fn entity_count(&self) -> usize {
        self.entities.len()
    }

    /// Returns the total number of relations (edges) in the graph.
    pub fn relation_count(&self) -> usize {
        self.edge_store.len()
    }

    /// Adds an entity to the graph.
    pub fn add_entity(&mut self, entity: Entity) -> Result<(), GraphError> {
        let sid = self.interner.intern(&entity.id);
        if self.entities.contains_key(&sid) {
            return Err(GraphError::DuplicateEntity(entity.id.clone()));
        }
        self.type_index
            .entry(entity.entity_type.clone())
            .or_default()
            .insert(sid);
        self.set_entity_type_tag(sid, &entity.entity_type);
        self.entities.insert(sid, entity);
        self.reverse_adj.entry(sid).or_default();
        Ok(())
    }

    /// Adds a relation (directed edge) to the graph.
    pub fn add_relation(&mut self, relation: Relation) -> Result<(), GraphError> {
        let src_sid = self.interner.get(&relation.source_id)
            .ok_or_else(|| GraphError::EntityNotFound(relation.source_id.clone()))?;
        let dst_sid = self.interner.get(&relation.dest_id)
            .ok_or_else(|| GraphError::EntityNotFound(relation.dest_id.clone()))?;

        if !self.entities.contains_key(&src_sid) {
            return Err(GraphError::EntityNotFound(relation.source_id.clone()));
        }
        if !self.entities.contains_key(&dst_sid) {
            return Err(GraphError::EntityNotFound(relation.dest_id.clone()));
        }

        if let Some(ref mut scorer) = self.anomaly_scorer {
            scorer.observe_entity(&relation.source_id, relation.timestamp);
            scorer.observe_entity(&relation.dest_id, relation.timestamp);
            scorer.observe_edge(&relation.source_id, &relation.dest_id);
        }

        let meta_offset = self.meta_store.append(&relation.metadata);
        let ds_tag = self.intern_dataset_tag(relation.dataset_id.as_deref());
        let compact = CompactRelation {
            source_sid: src_sid,
            dest_sid: dst_sid,
            rel_type_tag: relation.rel_type.to_u8(),
            timestamp: relation.timestamp,
            metadata_offset: meta_offset,
            dataset_tag: ds_tag,
        };

        self.reverse_adj
            .entry(dst_sid)
            .or_default()
            .push(src_sid);
        self.edge_store.push(compact)?;
        self.edges_sorted = false;
        Ok(())
    }

    /// Gets or creates a dataset tag index.
    fn intern_dataset_tag(&mut self, dataset_id: Option<&str>) -> u16 {
        match dataset_id {
            None => 0,
            Some(id) => {
                if let Some(pos) = self.dataset_tags.iter().position(|t| &**t == id) {
                    pos as u16
                } else {
                    let idx = self.dataset_tags.len() as u16;
                    self.dataset_tags.push(Arc::from(id));
                    idx
                }
            }
        }
    }

    /// Resolves a dataset tag to its string.
    pub fn resolve_dataset_tag(&self, tag: u16) -> Option<Arc<str>> {
        if tag == 0 { None } else { self.dataset_tags.get(tag as usize).cloned() }
    }

    /// Materializes a CompactRelation into a full Relation.
    pub fn materialize_relation(&self, compact: &CompactRelation) -> Relation {
        Relation {
            source_id: self.interner.resolve(compact.source_sid).to_string(),
            dest_id: self.interner.resolve(compact.dest_sid).to_string(),
            rel_type: compact.rel_type(),
            timestamp: compact.timestamp,
            metadata: self.meta_store.get(compact.metadata_offset),
            dataset_id: self.resolve_dataset_tag(compact.dataset_tag),
        }
    }

    /// Retrieves an entity by its ID.
    pub fn get_entity(&self, id: &str) -> Option<&Entity> {
        let sid = self.interner.get(id)?;
        self.entities.get(&sid)
    }

    /// Retrieves all outgoing relations from a given entity (materialized).
    pub fn get_relations(&self, source_id: &str) -> Vec<Relation> {
        self.interner
            .get(source_id)
            .map(|sid| {
                self.edge_store.get_edges(sid)
                    .iter()
                    .map(|c| self.materialize_relation(c))
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Retrieves outgoing relations of a specific type from a given entity (materialized).
    /// NOTE: returns ALL outgoing edges; callers must filter by rel_type themselves.
    pub fn get_relations_by_type(&self, source_id: &str, _rel_type: &RelationType) -> Vec<Relation> {
        self.get_relations(source_id)
    }

    /// Returns compact outgoing edges by string ID (no materialization).
    pub fn get_compact_relations(&self, source_id: &str) -> &[CompactRelation] {
        self.interner
            .get(source_id)
            .map(|sid| self.edge_store.get_edges(sid))
            .unwrap_or(&[])
    }

    /// Returns the StrIds of entities that have edges pointing TO the given entity.
    /// This is the public API for reverse adjacency lookup.
    pub fn get_reverse_source_sids(&self, id: &str) -> &[StrId] {
        self.interner
            .get(id)
            .and_then(|sid| self.reverse_adj.get(&sid))
            .map(|v| v.as_slice())
            .unwrap_or(&[])
    }

    /// Internal: get compact relations by StrId for step matching.
    #[inline]
    pub fn get_relations_by_sid(&self, sid: StrId) -> &[CompactRelation] {
        self.edge_store.get_edges(sid)
    }

    /// Internal: get compact relations by StrId and type.
    /// Returns ALL outgoing edges; callers filter by type in their loops.
    #[inline]
    fn get_relations_by_type_sid(&self, sid: StrId, _rel_type: &RelationType) -> &[CompactRelation] {
        self.get_relations_by_sid(sid)
    }

    /// Returns entity type names that exist in the graph.
    pub fn entity_types_in_graph(&self) -> Vec<String> {
        let mut names: Vec<String> = self
            .type_index
            .keys()
            .map(|t| format!("{}", t))
            .collect();
        names.sort();
        names
    }

    /// Returns (type_name, count) for each entity type present in the graph.
    pub fn entity_type_counts(&self) -> Vec<(String, usize)> {
        let mut v: Vec<(String, usize)> = self
            .type_index
            .iter()
            .map(|(k, set)| (format!("{}", k), set.len()))
            .collect();
        v.sort_by(|a, b| a.0.cmp(&b.0));
        v
    }

    /// Returns all entity IDs of the given type, or None if not in graph.
    pub fn entity_ids_for_type(&self, entity_type: &EntityType) -> Option<Vec<String>> {
        self.type_index
            .get(entity_type)
            .map(|set| set.iter().map(|&sid| self.interner.resolve(sid).to_string()).collect())
    }

    /// Returns entity type names among neighbours of the given node.
    pub fn entity_types_of_neighbours(&self, node_id: &str) -> Vec<String> {
        let mut types_set = HashSet::new();
        let Some(sid) = self.interner.get(node_id) else {
            return Vec::new();
        };
        for compact in self.edge_store.get_edges(sid) {
            if let Some(e) = self.entities.get(&compact.dest_sid) {
                types_set.insert(format!("{}", e.entity_type));
            }
        }
        if let Some(sources) = self.reverse_adj.get(&sid) {
            for &source_sid in sources {
                if let Some(e) = self.entities.get(&source_sid) {
                    types_set.insert(format!("{}", e.entity_type));
                }
            }
        }
        let mut names: Vec<String> = types_set.into_iter().collect();
        names.sort();
        names
    }

    /// Returns compact edges for a hypothesis step: type-filtered via rel_index or all edges.
    #[inline]
    fn get_edges_for_step_sid(&self, sid: StrId, step: &crate::hypothesis::HypothesisStep) -> &[CompactRelation] {
        if step.relation_type != RelationType::Any {
            self.get_relations_by_type_sid(sid, &step.relation_type)
        } else {
            self.get_relations_by_sid(sid)
        }
    }

    /// Returns materialized edges for a hypothesis step using string ID.
    #[inline]
    #[allow(dead_code)]
    fn get_edges_for_step(&self, node_id: &str, step: &crate::hypothesis::HypothesisStep) -> Vec<Relation> {
        if step.relation_type != RelationType::Any {
            self.get_relations_by_type(node_id, &step.relation_type)
        } else {
            self.get_relations(node_id)
        }
    }

    /// Sorts all edge lists by timestamp so binary search can skip temporally invalid edges.
    /// Call once after ingestion completes. Subsequent calls are no-ops.
    /// Now delegates to `edge_store.finalize()` which sorts by (source_sid, timestamp).
    pub fn sort_edges_by_timestamp(&mut self) -> Result<(), GraphError> {
        if self.edges_sorted {
            return Ok(());
        }
        self.edge_store.finalize()?;
        self.edges_sorted = true;
        Ok(())
    }

    /// Ensures edges are sorted. Called internally before searches.
    /// Returns true if edges were already sorted (no mutation needed).
    #[inline]
    fn ensure_sorted(&self) -> bool {
        self.edges_sorted
    }

    /// Searches for paths matching a temporal hypothesis pattern.
    /// For best performance, call `sort_edges_by_timestamp()` after ingestion.
    /// The search still works without sorting but binary-search optimizations are disabled.
    pub fn search_temporal_pattern(
        &self,
        hypothesis: &Hypothesis,
        time_window: Option<(i64, i64)>,
        max_results: Option<usize>,
    ) -> Result<(Vec<HuntResult>, bool), GraphError> {
        hypothesis
            .validate()
            .map_err(GraphError::InvalidHypothesis)?;

        let cap = max_results.unwrap_or(10_000);

        let first_step = &hypothesis.steps[0];
        let start_sids: Vec<StrId> = if first_step.origin_type == EntityType::Any {
            self.entities.keys().copied().collect()
        } else {
            self.type_index
                .get(&first_step.origin_type)
                .map(|ids| ids.iter().copied().collect())
                .unwrap_or_default()
        };

        let k = hypothesis.k_simplicity.max(1);
        let result_count = Arc::new(AtomicUsize::new(0));

        // Pre-size scratch buffers based on hypothesis depth.
        let depth = hypothesis.steps.len();
        let visit_cap = (depth * k).max(8);

        // Per-thread scratch state held in TLS so each rayon worker reuses
        // its `path`/`visit_count`/`stack` across every start it processes.
        // This eliminates the per-start HashMap+Vec allocations that used to
        // dominate non-saturation workloads (~75% fewer allocs measured).
        thread_local! {
            static DFS_SCRATCH: std::cell::RefCell<(
                Vec<StrId>,
                HashMap<StrId, usize>,
                Vec<DfsFrame>,
            )> = std::cell::RefCell::new((
                Vec::new(),
                HashMap::new(),
                Vec::new(),
            ));
        }
        // Helper to size buffers on first use per worker. Subsequent calls
        // are no-ops because Vec/HashMap reserve() only grows on demand.
        let init_buffers = move |s: &mut (Vec<StrId>, HashMap<StrId, usize>, Vec<DfsFrame>)| {
            if s.0.capacity() < depth + 1 {
                s.0.reserve(depth + 1);
            }
            if s.1.capacity() < visit_cap {
                s.1.reserve(visit_cap);
            }
            if s.2.capacity() < depth + 1 {
                s.2.reserve(depth + 1);
            }
        };

        let results: Vec<HuntResult> = if start_sids.len() >= 64 {
            let rc = Arc::clone(&result_count);
            // flat_map_iter is rayon's preferred shape for many small per-item
            // result lists — its parallel collect is more efficient than the
            // explicit fold/reduce we tried before.
            start_sids
                .par_iter()
                .flat_map_iter(|&start_sid| {
                    let mut local_results: Vec<HuntResult> = Vec::new();
                    if rc.load(Ordering::Relaxed) >= cap {
                        return local_results;
                    }
                    DFS_SCRATCH.with(|cell| {
                        let mut s = cell.borrow_mut();
                        init_buffers(&mut s);
                        // Reborrow once into a tuple ref so split-borrow on
                        // the three fields is unambiguous to borrowck.
                        let s_ref: &mut (Vec<StrId>, HashMap<StrId, usize>, Vec<DfsFrame>) =
                            &mut *s;
                        self.dfs_match_iterative(
                            start_sid,
                            &hypothesis.steps,
                            time_window,
                            k,
                            cap,
                            &rc,
                            &mut local_results,
                            &mut s_ref.0,
                            &mut s_ref.1,
                            &mut s_ref.2,
                        );
                    });
                    local_results
                })
                .collect()
        } else {
            // Sequential branch: keep one scratch set on the stack and reuse it.
            let mut path: Vec<StrId> = Vec::with_capacity(depth + 1);
            let mut visit_count: HashMap<StrId, usize> = HashMap::with_capacity(visit_cap);
            let mut stack: Vec<DfsFrame> = Vec::with_capacity(depth + 1);
            let mut results: Vec<HuntResult> = Vec::new();
            for &start_sid in &start_sids {
                if result_count.load(Ordering::Relaxed) >= cap {
                    break;
                }
                self.dfs_match_iterative(
                    start_sid,
                    &hypothesis.steps,
                    time_window,
                    k,
                    cap,
                    &result_count,
                    &mut results,
                    &mut path,
                    &mut visit_count,
                    &mut stack,
                );
            }
            results
        };

        let truncated = result_count.load(Ordering::Relaxed) >= cap;
        Ok((results, truncated))
    }

    /// Anomaly-guided smart search: uses a top-K min-heap to prune low-anomaly
    /// branches during DFS, eliminating the dependency on the cap for performance.
    ///
    /// When the scorer is finalized, this replaces the brute-force cap-based search
    /// with an A*-like admissible heuristic: it assumes future steps could score 1.0
    /// (max anomaly), so it never prunes a path that *could* end up in the top-K.
    ///
    /// Falls back to `search_temporal_pattern` if no scorer is available.
    pub fn search_temporal_pattern_smart(
        &self,
        hypothesis: &Hypothesis,
        time_window: Option<(i64, i64)>,
        top_k: usize,
    ) -> Result<(Vec<HuntResult>, bool), GraphError> {
        // Fallback if no finalized scorer
        let scorer_ready = self
            .anomaly_scorer
            .as_ref()
            .map(|s| s.is_finalized())
            .unwrap_or(false);
        if !scorer_ready {
            return self.search_temporal_pattern(hypothesis, time_window, Some(top_k));
        }

        hypothesis
            .validate()
            .map_err(GraphError::InvalidHypothesis)?;

        let first_step = &hypothesis.steps[0];
        let start_sids: Vec<StrId> = if first_step.origin_type == EntityType::Any {
            self.entities.keys().copied().collect()
        } else {
            self.type_index
                .get(&first_step.origin_type)
                .map(|ids| ids.iter().copied().collect())
                .unwrap_or_default()
        };

        let k = hypothesis.k_simplicity.max(1);
        let total_steps = hypothesis.steps.len();
        let depth = hypothesis.steps.len();
        let visit_cap = (depth * k).max(8);

        use std::cmp::Reverse;
        use std::collections::BinaryHeap;

        // Per-thread state used by both branches: a top-K min-heap plus the
        // three DFS scratch buffers. In the parallel branch each fold chunk
        // owns one of these; in the sequential branch a single one is reused
        // across all starts.
        type SmartChunk = (
            SmartHeap,
            Vec<StrId>,
            HashMap<StrId, usize>,
            Vec<AnomalyFrame>,
        );
        let init_chunk = || -> SmartChunk {
            (
                BinaryHeap::with_capacity(top_k + 1),
                Vec::with_capacity(depth + 1),
                HashMap::with_capacity(visit_cap),
                Vec::with_capacity(depth + 1),
            )
        };

        // Merges two top-K heaps into the larger one, popping the lowest
        // scores until only `top_k` entries remain. Cost is O((|a|+|b|) log K).
        let merge_into_topk = |mut a: SmartHeap, b: SmartHeap, top_k: usize| -> SmartHeap {
            // Drain `b` into `a`, keeping `a` bounded.
            for entry in b {
                a.push(entry);
                if a.len() > top_k {
                    a.pop();
                }
            }
            a
        };

        let final_heap: SmartHeap = if start_sids.len() >= 64 {
            // Parallel branch: each rayon fold chunk maintains its own heap +
            // scratch buffers. The per-chunk threshold is naturally less
            // aggressive than the global one, but the merge step at the end
            // restores the global top-K invariant.
            //
            // `with_min_len(256)` coalesces work into at most ~N/256 chunks
            // so rayon does not thrash its work-stealing queues on workloads
            // where each start does tiny work (typed first step with zero-
            // result DFS). For heavy workloads (Any first step + deep chain)
            // the per-chunk init cost is amortized over hundreds of starts.
            start_sids
                .par_iter()
                .with_min_len(256)
                .fold(
                    init_chunk,
                    |mut chunk, &start_sid| {
                        let (heap, path, visit_count, stack) =
                            (&mut chunk.0, &mut chunk.1, &mut chunk.2, &mut chunk.3);
                        self.dfs_match_smart(
                            start_sid,
                            &hypothesis.steps,
                            time_window,
                            k,
                            top_k,
                            total_steps,
                            heap,
                            path,
                            visit_count,
                            stack,
                        );
                        chunk
                    },
                )
                .map(|chunk| chunk.0)
                .reduce(
                    || BinaryHeap::with_capacity(top_k + 1),
                    |a, b| merge_into_topk(a, b, top_k),
                )
        } else {
            // Sequential branch: one heap, one set of scratch buffers, reused
            // across every start. Pruning sees the full global threshold so
            // it is maximally aggressive — best for small start_sids sets.
            let (mut heap, mut path, mut visit_count, mut stack) = init_chunk();
            for &start_sid in &start_sids {
                self.dfs_match_smart(
                    start_sid,
                    &hypothesis.steps,
                    time_window,
                    k,
                    top_k,
                    total_steps,
                    &mut heap,
                    &mut path,
                    &mut visit_count,
                    &mut stack,
                );
            }
            heap
        };

        // Extract results from the final heap, sorted by score descending.
        let mut scored: Vec<(f64, Vec<String>)> = final_heap
            .into_sorted_vec()
            .into_iter()
            .map(|Reverse((score, path))| (score.into_inner(), path))
            .collect();
        scored.reverse(); // highest score first

        let results: Vec<HuntResult> = scored.into_iter().map(|(_, path)| path).collect();
        Ok((results, false))
    }

    /// Anomaly-pruned DFS that maintains a top-K min-heap of best-scoring paths.
    ///
    /// `heap`, `path`, `visit_count` and `stack` are caller-owned scratch
    /// buffers (cleared on entry) so the function can be invoked many times
    /// per search without per-call allocations. The heap is the *only* buffer
    /// that carries information out of the call — the rest is reset.
    fn dfs_match_smart(
        &self,
        start_sid: StrId,
        steps: &[crate::hypothesis::HypothesisStep],
        time_window: Option<(i64, i64)>,
        k: usize,
        top_k: usize,
        total_steps: usize,
        heap: &mut SmartHeap,
        path: &mut Vec<StrId>,
        visit_count: &mut HashMap<StrId, usize>,
        stack: &mut Vec<AnomalyFrame>,
    ) {
        use ordered_float::OrderedFloat;
        use std::cmp::Reverse;

        let scorer = match self.anomaly_scorer.as_ref() {
            Some(s) => s,
            None => return, // scorer not initialized; skip smart DFS
        };

        // Reset scratch state. Buffers normally drain naturally during
        // backtrack, but a defensive clear keeps the contract explicit.
        path.clear();
        visit_count.clear();
        stack.clear();

        path.push(start_sid);
        visit_count.insert(start_sid, 1);

        let start_str = self.interner.resolve(start_sid);
        let start_node_score = scorer.node_anomaly_estimate(start_str);

        let (lo, hi) = if !steps.is_empty() {
            self.edge_range_sid(start_sid, &steps[0], i64::MIN, time_window)
        } else {
            (0, 0)
        };

        stack.push(AnomalyFrame {
            sid: start_sid,
            step_idx: 0,
            edge_hi: hi,
            edge_cursor: lo,
            path_anomaly_sum: start_node_score,
        });

        while let Some(frame) = stack.last_mut() {
            // Path complete: all steps matched
            if frame.step_idx >= steps.len() {
                // Total nodes in path = total_steps + 1
                let path_len = total_steps + 1;
                let avg_score = frame.path_anomaly_sum / path_len as f64;

                if heap.len() < top_k
                    || avg_score > heap.peek().unwrap().0 .0.into_inner()
                {
                    let path_strings: Vec<String> = path
                        .iter()
                        .map(|&sid| self.interner.resolve(sid).to_string())
                        .collect();
                    heap.push(Reverse((OrderedFloat(avg_score), path_strings)));
                    if heap.len() > top_k {
                        heap.pop(); // remove lowest
                    }
                }

                let node_sid = path.pop().unwrap();
                let c = visit_count.get_mut(&node_sid).unwrap();
                *c -= 1;
                if *c == 0 {
                    visit_count.remove(&node_sid);
                }
                stack.pop();
                continue;
            }

            let step = &steps[frame.step_idx];
            let edges = self.get_edges_for_step_sid(frame.sid, step);

            let mut found = false;
            while frame.edge_cursor < frame.edge_hi {
                let idx = frame.edge_cursor;
                frame.edge_cursor += 1;
                let edge = &edges[idx];

                if !relation_type_tag_matches(&step.relation_type, edge.rel_type_tag) {
                    continue;
                }

                let dest_sid = edge.dest_sid;
                if !self.fast_type_matches(&step.dest_type, dest_sid) {
                    continue;
                }

                let count = visit_count.get(&dest_sid).copied().unwrap_or(0);
                if count >= k {
                    continue;
                }

                // Anomaly-based pruning
                let dest_str = self.interner.resolve(dest_sid);
                let current_str = self.interner.resolve(frame.sid);
                let node_score = scorer.node_anomaly_estimate(dest_str);
                let edge_score = scorer.edge_anomaly_estimate(current_str, dest_str);
                let step_score = (node_score + edge_score) / 2.0;
                let new_sum = frame.path_anomaly_sum + step_score;

                // Admissible heuristic: assume remaining steps score 1.0 (max)
                let remaining_steps = total_steps - (frame.step_idx + 1);
                let path_len = total_steps + 1;
                let optimistic_avg = (new_sum + remaining_steps as f64) / path_len as f64;

                // Prune if even the optimistic estimate can't beat the current threshold
                if heap.len() >= top_k {
                    let threshold = heap.peek().unwrap().0 .0.into_inner();
                    if optimistic_avg < threshold {
                        continue; // PRUNE
                    }
                }

                *visit_count.entry(dest_sid).or_insert(0) += 1;
                path.push(dest_sid);

                let next_step_idx = frame.step_idx + 1;
                let (next_lo, next_hi) = if next_step_idx < steps.len() {
                    self.edge_range_sid(
                        dest_sid,
                        &steps[next_step_idx],
                        edge.timestamp,
                        time_window,
                    )
                } else {
                    (0, 0)
                };

                stack.push(AnomalyFrame {
                    sid: dest_sid,
                    step_idx: next_step_idx,
                    edge_hi: next_hi,
                    edge_cursor: next_lo,
                    path_anomaly_sum: new_sum,
                });
                found = true;
                break;
            }

            if !found {
                let node_sid = path.pop().unwrap();
                let c = visit_count.get_mut(&node_sid).unwrap();
                *c -= 1;
                if *c == 0 {
                    visit_count.remove(&node_sid);
                }
                stack.pop();
            }
        }
    }

    /// Iterative stack-based DFS with backtracking.
    ///
    /// Scratch buffers (`path`, `visit_count`, `stack`) are passed in by the
    /// caller so they can be reused across many start nodes — this avoids
    /// thousands of small allocations per search. The function clears them
    /// on entry to make the contract explicit; the buffers are also left
    /// empty by the natural backtrack at the end of the DFS.
    fn dfs_match_iterative(
        &self,
        start_sid: StrId,
        steps: &[crate::hypothesis::HypothesisStep],
        time_window: Option<(i64, i64)>,
        k: usize,
        cap: usize,
        result_count: &AtomicUsize,
        results: &mut Vec<HuntResult>,
        path: &mut Vec<StrId>,
        visit_count: &mut HashMap<StrId, usize>,
        stack: &mut Vec<DfsFrame>,
    ) {
        // Reset scratch state. The DFS leaves them empty on a normal exit, but
        // an early break on `cap` reached can leave residue — clear defensively.
        path.clear();
        visit_count.clear();
        stack.clear();

        path.push(start_sid);
        visit_count.insert(start_sid, 1);

        let (lo, hi) = if !steps.is_empty() {
            self.edge_range_sid(start_sid, &steps[0], i64::MIN, time_window)
        } else {
            (0, 0)
        };

        stack.push(DfsFrame {
            sid: start_sid,
            step_idx: 0,
            edge_hi: hi,
            edge_cursor: lo,
        });

        while let Some(frame) = stack.last_mut() {
            if result_count.load(Ordering::Relaxed) >= cap {
                break;
            }

            if frame.step_idx >= steps.len() {
                let prev = result_count.fetch_add(1, Ordering::Relaxed);
                if prev < cap {
                    results.push(
                        path.iter()
                            .map(|&sid| self.interner.resolve(sid).to_string())
                            .collect(),
                    );
                }
                let node_sid = path.pop().unwrap();
                let c = visit_count.get_mut(&node_sid).unwrap();
                *c -= 1;
                if *c == 0 { visit_count.remove(&node_sid); }
                stack.pop();
                continue;
            }

            let step = &steps[frame.step_idx];
            let edges = self.get_edges_for_step_sid(frame.sid, step);

            let mut found = false;
            while frame.edge_cursor < frame.edge_hi {
                let idx = frame.edge_cursor;
                frame.edge_cursor += 1;
                let edge = &edges[idx];

                if !relation_type_tag_matches(&step.relation_type, edge.rel_type_tag) {
                    continue;
                }

                let dest_sid = edge.dest_sid;
                if !self.fast_type_matches(&step.dest_type, dest_sid) {
                    continue;
                }

                let count = visit_count.get(&dest_sid).copied().unwrap_or(0);
                if count >= k {
                    continue;
                }

                *visit_count.entry(dest_sid).or_insert(0) += 1;
                path.push(dest_sid);

                let next_step_idx = frame.step_idx + 1;
                let (next_lo, next_hi) = if next_step_idx < steps.len() {
                    self.edge_range_sid(dest_sid, &steps[next_step_idx], edge.timestamp, time_window)
                } else {
                    (0, 0)
                };

                stack.push(DfsFrame {
                    sid: dest_sid,
                    step_idx: next_step_idx,
                    edge_hi: next_hi,
                    edge_cursor: next_lo,
                });
                found = true;
                break;
            }

            if !found {
                let node_sid = path.pop().unwrap();
                let c = visit_count.get_mut(&node_sid).unwrap();
                *c -= 1;
                if *c == 0 { visit_count.remove(&node_sid); }
                stack.pop();
            }
        }
    }

    /// Computes valid edge index range [lo, hi) using binary search on sorted edges (StrId version).
    #[inline]
    fn edge_range_sid(
        &self,
        sid: StrId,
        step: &crate::hypothesis::HypothesisStep,
        last_timestamp: i64,
        time_window: Option<(i64, i64)>,
    ) -> (usize, usize) {
        let edges = self.get_edges_for_step_sid(sid, step);
        if edges.is_empty() {
            return (0, 0);
        }
        let lo_ts = if let Some((tw_start, _)) = time_window {
            last_timestamp.max(tw_start)
        } else {
            last_timestamp
        };
        let lo = edges.partition_point(|e| e.timestamp < lo_ts);
        let hi = if let Some((_, tw_end)) = time_window {
            edges.partition_point(|e| e.timestamp <= tw_end)
        } else {
            edges.len()
        };
        (lo, hi)
    }

    /// Computes valid edge index range [lo, hi) (string version, kept for get_edges_for_step).
    #[inline]
    #[allow(dead_code)]
    fn edge_range(
        &self,
        node_id: &str,
        step: &crate::hypothesis::HypothesisStep,
        last_timestamp: i64,
        time_window: Option<(i64, i64)>,
    ) -> (usize, usize) {
        // This method uses the StrId-based version internally
        let sid = match self.interner.get(node_id) {
            Some(s) => s,
            None => return (0, 0),
        };
        self.edge_range_sid(sid, step, last_timestamp, time_window)
    }

    /// Merges metadata from `incoming` into `existing` according to the merge policy.
    fn merge_metadata(
        existing: &mut std::collections::HashMap<String, String>,
        incoming: &std::collections::HashMap<String, String>,
        policy: &MergePolicy,
    ) {
        for (k, v) in incoming {
            match policy {
                MergePolicy::FirstWriteWins => {
                    existing.entry(k.clone()).or_insert_with(|| v.clone());
                }
                MergePolicy::LastWriteWins => {
                    existing.insert(k.clone(), v.clone());
                }
                MergePolicy::Append => {
                    existing
                        .entry(k.clone())
                        .and_modify(|old| {
                            old.push_str(", ");
                            old.push_str(v);
                        })
                        .or_insert_with(|| v.clone());
                }
            }
        }
    }

    /// Ingests raw log data using the provided parser.
    pub fn ingest_logs<P: crate::parser::LogParser>(
        &mut self,
        logs: &str,
        parser: &P,
        dataset_id: Option<String>,
    ) -> Result<(usize, usize), GraphError> {
        self.ingest_logs_with_policy(logs, parser, dataset_id, &MergePolicy::default())
    }

    /// Ingests raw log data with a specific merge policy.
    pub fn ingest_logs_with_policy<P: crate::parser::LogParser>(
        &mut self,
        logs: &str,
        parser: &P,
        dataset_id: Option<String>,
        merge_policy: &MergePolicy,
    ) -> Result<(usize, usize), GraphError> {
        let triples = parser.parse(logs);
        let mut new_entities = 0usize;
        let mut new_relations = 0usize;
        let ds: Option<Arc<str>> = dataset_id.map(|s| Arc::from(s.as_str()));
        let ds_tag = self.intern_dataset_tag(ds.as_deref());

        for (mut src, rel, mut dst) in triples {
            if let Some(ref id) = ds {
                src.dataset_id = Some(Arc::clone(id));
                dst.dataset_id = Some(Arc::clone(id));
            }

            // Upsert source entity
            let src_sid = self.interner.intern(&src.id);
            if let Some(existing) = self.entities.get_mut(&src_sid) {
                Self::merge_metadata(&mut existing.metadata, &src.metadata, merge_policy);
            } else {
                let et = src.entity_type.clone();
                self.set_entity_type_tag(src_sid, &et);
                self.entities.insert(src_sid, src);
                self.type_index.entry(et).or_default().insert(src_sid);
                self.reverse_adj.entry(src_sid).or_default();
                new_entities += 1;
            }

            // Upsert destination entity
            let dst_sid = self.interner.intern(&dst.id);
            if let Some(existing) = self.entities.get_mut(&dst_sid) {
                Self::merge_metadata(&mut existing.metadata, &dst.metadata, merge_policy);
            } else {
                let et = dst.entity_type.clone();
                self.set_entity_type_tag(dst_sid, &et);
                self.entities.insert(dst_sid, dst);
                self.type_index.entry(et).or_default().insert(dst_sid);
                self.reverse_adj.entry(dst_sid).or_default();
                new_entities += 1;
            }

            // Feed anomaly scorer if enabled
            if let Some(ref mut scorer) = self.anomaly_scorer {
                scorer.observe_entity(&rel.source_id, rel.timestamp);
                scorer.observe_entity(&rel.dest_id, rel.timestamp);
                scorer.observe_edge(&rel.source_id, &rel.dest_id);
            }

            let meta_offset = self.meta_store.append(&rel.metadata);
            let compact = CompactRelation {
                source_sid: src_sid,
                dest_sid: dst_sid,
                rel_type_tag: rel.rel_type.to_u8(),
                timestamp: rel.timestamp,
                metadata_offset: meta_offset,
                dataset_tag: ds_tag,
            };

            // Always insert relation
            self.reverse_adj
                .entry(dst_sid)
                .or_default()
                .push(src_sid);
            self.edge_store.push(compact)?;
            new_relations += 1;
        }

        Ok((new_entities, new_relations))
    }

    /// Removes all entities and relations that belong to the given dataset.
    pub fn remove_entities_and_relations_by_dataset(&mut self, dataset_id: &str) -> Result<(usize, usize), GraphError> {
        let to_remove: Vec<StrId> = self
            .entities
            .iter()
            .filter(|(_, e)| e.dataset_id.as_deref() == Some(dataset_id))
            .map(|(&sid, _)| sid)
            .collect();

        // Find the dataset tag for this dataset_id
        let ds_tag = self.dataset_tags.iter().position(|t| &**t == dataset_id)
            .map(|p| p as u16);

        // Rebuild edge_store keeping only edges that don't match the dataset tag
        let total_before = self.edge_store.len();
        let kept: Vec<CompactRelation> = self.edge_store.iter_all()
            .filter(|c| ds_tag.map_or(true, |tag| c.dataset_tag != tag))
            .copied()
            .collect();
        let relations_removed = total_before - kept.len();

        self.edge_store.clear();
        for c in &kept {
            self.edge_store.push(*c)?;
        }
        self.edge_store.finalize()?;

        // Rebuild reverse_adj
        self.reverse_adj.clear();
        for compact in &kept {
            self.reverse_adj
                .entry(compact.dest_sid)
                .or_default()
                .push(compact.source_sid);
        }
        for v in self.reverse_adj.values_mut() {
            v.sort_unstable();
            v.dedup();
        }

        // Remove entities
        let entities_removed = to_remove.len();
        for sid in &to_remove {
            if let Some(entity) = self.entities.remove(sid) {
                if let Some(set) = self.type_index.get_mut(&entity.entity_type) {
                    set.remove(sid);
                }
            }
            self.mark_entity_dead(*sid);
            self.reverse_adj.remove(sid);
        }

        self.edges_sorted = true; // finalize() sorted them
        Ok((entities_removed, relations_removed))
    }

    /// Renames entity types in a dataset.
    pub fn rename_entity_type_in_dataset(
        &mut self,
        dataset_id: &str,
        from_type: EntityType,
        to_type: EntityType,
    ) -> usize {
        let to_rename: Vec<StrId> = self
            .entities
            .iter()
            .filter(|(_, e)| {
                e.dataset_id.as_deref() == Some(dataset_id) && e.entity_type == from_type
            })
            .map(|(&sid, _)| sid)
            .collect();
        let count = to_rename.len();
        for sid in to_rename {
            if let Some(mut entity) = self.entities.remove(&sid) {
                if let Some(set) = self.type_index.get_mut(&from_type) {
                    set.remove(&sid);
                }
                entity.entity_type = to_type.clone();
                self.type_index
                    .entry(to_type.clone())
                    .or_default()
                    .insert(sid);
                self.set_entity_type_tag(sid, &to_type);
                self.entities.insert(sid, entity);
            }
        }
        count
    }

    /// Returns entity type names in the given dataset.
    pub fn entity_types_in_dataset(&self, dataset_id: &str) -> Vec<String> {
        let mut types: HashSet<String> = HashSet::new();
        for e in self.entities.values() {
            if e.dataset_id.as_deref() == Some(dataset_id) {
                types.insert(e.entity_type.to_string());
            }
        }
        let mut v: Vec<String> = types.into_iter().collect();
        v.sort();
        v
    }

    /// Exports the graph as a snapshot for serialization.
    pub fn to_snapshot(&self) -> (Vec<Entity>, Vec<Relation>) {
        let entities: Vec<Entity> = self.entities.values().cloned().collect();
        let relations: Vec<Relation> = self.edge_store.iter_all()
            .map(|c| self.materialize_relation(c))
            .collect();
        (entities, relations)
    }

    /// Builds a graph from a snapshot.
    pub fn load_snapshot(
        entities: Vec<Entity>,
        relations: Vec<Relation>,
    ) -> Result<Self, GraphError> {
        let mut g = GraphHunter::new();
        for entity in entities {
            g.add_entity(entity)?;
        }
        for relation in relations {
            g.add_relation(relation)?;
        }
        Ok(g)
    }

    /// Naive DFS search (baseline for benchmarks).
    pub fn search_naive_dfs(
        &self,
        hypothesis: &Hypothesis,
    ) -> Result<(Vec<HuntResult>, usize), GraphError> {
        hypothesis
            .validate()
            .map_err(GraphError::InvalidHypothesis)?;

        let mut results: Vec<HuntResult> = Vec::new();
        let mut nodes_visited: usize = 0;

        for (&start_sid, _) in &self.entities {
            let mut visited = HashSet::new();
            visited.insert(start_sid);
            let mut path = vec![self.interner.resolve(start_sid).to_string()];

            self.naive_dfs_recurse(
                start_sid,
                &hypothesis.steps,
                0,
                &mut visited,
                &mut path,
                &mut results,
                &mut nodes_visited,
            );
        }

        Ok((results, nodes_visited))
    }

    /// Naive DFS recursive core.
    fn naive_dfs_recurse(
        &self,
        current_sid: StrId,
        steps: &[crate::hypothesis::HypothesisStep],
        step_idx: usize,
        visited: &mut HashSet<StrId>,
        path: &mut Vec<String>,
        results: &mut Vec<HuntResult>,
        nodes_visited: &mut usize,
    ) {
        *nodes_visited += 1;

        if step_idx >= steps.len() {
            let valid = self.verify_path_matches(path, steps);
            if valid {
                results.push(path.clone());
            }
            return;
        }

        let edges = self.get_relations_by_sid(current_sid);
        for edge in edges {
            let dest_sid = edge.dest_sid;
            if visited.contains(&dest_sid) {
                continue;
            }

            visited.insert(dest_sid);
            path.push(self.interner.resolve(dest_sid).to_string());

            self.naive_dfs_recurse(
                dest_sid,
                steps,
                step_idx + 1,
                visited,
                path,
                results,
                nodes_visited,
            );

            path.pop();
            visited.remove(&dest_sid);
        }
    }

    /// Verifies that a completed path matches the hypothesis types and temporal order.
    fn verify_path_matches(
        &self,
        path: &[String],
        steps: &[crate::hypothesis::HypothesisStep],
    ) -> bool {
        if path.len() != steps.len() + 1 {
            return false;
        }

        let first_sid = match self.interner.get(&path[0]) {
            Some(s) => s,
            None => return false,
        };
        let first = match self.entities.get(&first_sid) {
            Some(e) => e,
            None => return false,
        };
        if !entity_type_matches(&steps[0].origin_type, &first.entity_type) {
            return false;
        }

        let mut last_timestamp = i64::MIN;

        for (i, step) in steps.iter().enumerate() {
            let src_id = &path[i];
            let dst_id = &path[i + 1];

            let edges = self.get_relations(src_id);
            let mut found = false;
            for edge in edges {
                if edge.dest_id == *dst_id {
                    if relation_type_matches(&step.relation_type, &edge.rel_type) {
                        let dst_sid = match self.interner.get(dst_id) {
                            Some(s) => s,
                            None => continue,
                        };
                        let dest = match self.entities.get(&dst_sid) {
                            Some(e) => e,
                            None => continue,
                        };
                        if entity_type_matches(&step.dest_type, &dest.entity_type)
                            && edge.timestamp >= last_timestamp
                        {
                            last_timestamp = edge.timestamp;
                            found = true;
                            break;
                        }
                    }
                }
            }
            if !found {
                return false;
            }
        }

        true
    }

    /// Ingests log data in chunks with progress callback.
    pub fn ingest_logs_chunked<P, F>(
        &mut self,
        logs: &str,
        parser: &P,
        dataset_id: Option<String>,
        chunk_size: usize,
        mut on_progress: F,
    ) -> Result<(usize, usize), GraphError>
    where
        P: crate::parser::LogParser,
        F: FnMut(usize, usize, usize, usize),
    {
        let merge_policy = MergePolicy::default();
        let triples = parser.parse(logs);
        let total = triples.len();
        let mut new_entities = 0usize;
        let mut new_relations = 0usize;
        let ds: Option<Arc<str>> = dataset_id.map(|s| Arc::from(s.as_str()));
        let ds_tag = self.intern_dataset_tag(ds.as_deref());

        for (i, (mut src, rel, mut dst)) in triples.into_iter().enumerate() {
            if let Some(ref id) = ds {
                src.dataset_id = Some(Arc::clone(id));
                dst.dataset_id = Some(Arc::clone(id));
            }

            let src_sid = self.interner.intern(&src.id);
            if let Some(existing) = self.entities.get_mut(&src_sid) {
                Self::merge_metadata(&mut existing.metadata, &src.metadata, &merge_policy);
            } else {
                let et = src.entity_type.clone();
                self.set_entity_type_tag(src_sid, &et);
                self.entities.insert(src_sid, src);
                self.type_index.entry(et).or_default().insert(src_sid);
                self.reverse_adj.entry(src_sid).or_default();
                new_entities += 1;
            }

            let dst_sid = self.interner.intern(&dst.id);
            if let Some(existing) = self.entities.get_mut(&dst_sid) {
                Self::merge_metadata(&mut existing.metadata, &dst.metadata, &merge_policy);
            } else {
                let et = dst.entity_type.clone();
                self.set_entity_type_tag(dst_sid, &et);
                self.entities.insert(dst_sid, dst);
                self.type_index.entry(et).or_default().insert(dst_sid);
                self.reverse_adj.entry(dst_sid).or_default();
                new_entities += 1;
            }

            if let Some(ref mut scorer) = self.anomaly_scorer {
                scorer.observe_entity(&rel.source_id, rel.timestamp);
                scorer.observe_entity(&rel.dest_id, rel.timestamp);
                scorer.observe_edge(&rel.source_id, &rel.dest_id);
            }

            let meta_offset = self.meta_store.append(&rel.metadata);
            let compact = CompactRelation {
                source_sid: src_sid,
                dest_sid: dst_sid,
                rel_type_tag: rel.rel_type.to_u8(),
                timestamp: rel.timestamp,
                metadata_offset: meta_offset,
                dataset_tag: ds_tag,
            };

            self.reverse_adj
                .entry(dst_sid)
                .or_default()
                .push(src_sid);
            self.edge_store.push(compact)?;
            new_relations += 1;

            if (i + 1) % chunk_size == 0 || i + 1 == total {
                on_progress(i + 1, total, new_entities, new_relations);
            }
        }

        Ok((new_entities, new_relations))
    }

    /// Inserts pre-parsed triples directly (streaming ingestion).
    pub fn insert_triples(
        &mut self,
        triples: Vec<crate::parser::ParsedTriple>,
        dataset_id: Option<&str>,
    ) -> Result<(usize, usize), GraphError> {
        let merge_policy = MergePolicy::default();
        let mut new_entities = 0usize;
        let mut new_relations = 0usize;
        let ds: Option<Arc<str>> = dataset_id.map(Arc::from);
        let ds_tag = self.intern_dataset_tag(dataset_id);

        for (mut src, rel, mut dst) in triples {
            if let Some(ref id) = ds {
                src.dataset_id = Some(Arc::clone(id));
                dst.dataset_id = Some(Arc::clone(id));
            }

            let src_sid = self.interner.intern(&src.id);
            if let Some(existing) = self.entities.get_mut(&src_sid) {
                Self::merge_metadata(&mut existing.metadata, &src.metadata, &merge_policy);
            } else {
                let et = src.entity_type.clone();
                self.set_entity_type_tag(src_sid, &et);
                self.entities.insert(src_sid, src);
                self.type_index.entry(et).or_default().insert(src_sid);
                self.reverse_adj.entry(src_sid).or_default();
                new_entities += 1;
            }

            let dst_sid = self.interner.intern(&dst.id);
            if let Some(existing) = self.entities.get_mut(&dst_sid) {
                Self::merge_metadata(&mut existing.metadata, &dst.metadata, &merge_policy);
            } else {
                let et = dst.entity_type.clone();
                self.set_entity_type_tag(dst_sid, &et);
                self.entities.insert(dst_sid, dst);
                self.type_index.entry(et).or_default().insert(dst_sid);
                self.reverse_adj.entry(dst_sid).or_default();
                new_entities += 1;
            }

            if let Some(ref mut scorer) = self.anomaly_scorer {
                scorer.observe_entity(&rel.source_id, rel.timestamp);
                scorer.observe_entity(&rel.dest_id, rel.timestamp);
                scorer.observe_edge(&rel.source_id, &rel.dest_id);
            }

            let meta_offset = self.meta_store.append(&rel.metadata);
            let compact = CompactRelation {
                source_sid: src_sid,
                dest_sid: dst_sid,
                rel_type_tag: rel.rel_type.to_u8(),
                timestamp: rel.timestamp,
                metadata_offset: meta_offset,
                dataset_tag: ds_tag,
            };

            self.reverse_adj
                .entry(dst_sid)
                .or_default()
                .push(src_sid);
            self.edge_store.push(compact)?;
            new_relations += 1;
        }

        Ok((new_entities, new_relations))
    }

    /// Enables anomaly scoring with backfilling from existing data.
    pub fn enable_anomaly_scoring(&mut self, weights: ScoringWeights) {
        let mut scorer = AnomalyScorer::new(weights);
        for compact in self.edge_store.iter_all() {
            let src_str = self.interner.resolve(compact.source_sid);
            let dst_str = self.interner.resolve(compact.dest_sid);
            scorer.observe_entity(src_str, compact.timestamp);
            scorer.observe_entity(dst_str, compact.timestamp);
            scorer.observe_edge(src_str, dst_str);
        }
        scorer.finalize(self);
        self.anomaly_scorer = Some(scorer);
    }

    /// Finalizes the anomaly scorer (call after ingestion completes).
    pub fn finalize_anomaly_scorer(&mut self) {
        if let Some(mut scorer) = self.anomaly_scorer.take() {
            scorer.finalize(self);
            self.anomaly_scorer = Some(scorer);
        }
    }

    /// Compute GNN threat scores for all entities using an NpuScorer.
    ///
    /// Extracts k-hop subgraphs around each entity, runs GNN inference,
    /// and injects the resulting threat scores into the anomaly scorer.
    /// Requires anomaly scoring to be enabled first.
    ///
    /// Returns the number of entities successfully scored.
    pub fn compute_gnn_scores(
        &mut self,
        scorer: &mut crate::npu_scorer::scorer::NpuScorer,
        k_hops: usize,
    ) -> usize {
        // Collect all entity IDs
        let entity_ids: Vec<String> = self
            .entities
            .keys()
            .map(|&sid| self.interner.resolve(sid).to_string())
            .collect();

        // Extract subgraph features and run batch inference
        let features = crate::gnn_bridge::extract_batch_features(self, &entity_ids, k_hops);
        let gnn_scores = scorer.batch_score(&features);
        let scored_count = gnn_scores.len();

        // Inject into anomaly scorer
        if let Some(ref mut anomaly) = self.anomaly_scorer {
            anomaly.set_gnn_scores(gnn_scores);
        }

        scored_count
    }

    /// Returns hourly-bucketed relation counts grouped by relation type.
    pub fn temporal_heatmap(&self) -> Vec<(String, Vec<(i64, usize)>)> {
        use std::collections::BTreeMap;
        let mut by_type: HashMap<String, BTreeMap<i64, usize>> = HashMap::new();

        for compact in self.edge_store.iter_all() {
            let type_name = format!("{}", compact.rel_type());
            let hour = compact.timestamp - (compact.timestamp % 3600);
            *by_type
                .entry(type_name)
                .or_default()
                .entry(hour)
                .or_insert(0) += 1;
        }

        let mut result: Vec<(String, Vec<(i64, usize)>)> = by_type
            .into_iter()
            .map(|(type_name, bins)| {
                let bins_vec: Vec<(i64, usize)> = bins.into_iter().collect();
                (type_name, bins_vec)
            })
            .collect();
        result.sort_by(|a, b| a.0.cmp(&b.0));
        result
    }

    /// Returns timestamp distribution per entity type for sparkline visualization.
    pub fn timeline_data(&self) -> Vec<(String, i64, i64, Vec<(i64, usize)>)> {
        use std::collections::BTreeMap;
        let mut type_data: HashMap<String, BTreeMap<i64, usize>> = HashMap::new();
        let mut type_min: HashMap<String, i64> = HashMap::new();
        let mut type_max: HashMap<String, i64> = HashMap::new();

        for compact in self.edge_store.iter_all() {
            if let Some(src) = self.entities.get(&compact.source_sid) {
                let type_name = format!("{}", src.entity_type);
                let hour = compact.timestamp - (compact.timestamp % 3600);
                *type_data
                    .entry(type_name.clone())
                    .or_default()
                    .entry(hour)
                    .or_insert(0) += 1;
                let min = type_min.entry(type_name.clone()).or_insert(compact.timestamp);
                if compact.timestamp < *min { *min = compact.timestamp; }
                let max = type_max.entry(type_name.clone()).or_insert(compact.timestamp);
                if compact.timestamp > *max { *max = compact.timestamp; }
            }
        }

        let mut result: Vec<(String, i64, i64, Vec<(i64, usize)>)> = type_data
            .into_iter()
            .map(|(type_name, bins)| {
                let min = *type_min.get(&type_name).unwrap_or(&0);
                let max = *type_max.get(&type_name).unwrap_or(&0);
                let bins_vec: Vec<(i64, usize)> = bins.into_iter().collect();
                (type_name, min, max, bins_vec)
            })
            .collect();
        result.sort_by(|a, b| a.0.cmp(&b.0));
        result
    }

    /// Compacts old edges before cutoff into summary edges.
    pub fn compact_before(&mut self, cutoff: i64) -> Result<CompactionStats, GraphError> {
        let mut edges_before = 0usize;
        let mut edges_removed = 0usize;
        let mut groups_compacted = 0usize;

        // Materialize all edges into full Relations for grouping
        let mut groups: HashMap<(String, String, String), Vec<Relation>> = HashMap::new();
        for compact in self.edge_store.iter_all() {
            edges_before += 1;
            let rel = self.materialize_relation(compact);
            let key = (
                rel.source_id.clone(),
                rel.dest_id.clone(),
                format!("{}", rel.rel_type),
            );
            groups.entry(key).or_default().push(rel);
        }

        let mut summary_edges: Vec<Relation> = Vec::new();
        let mut keep_edges: Vec<Relation> = Vec::new();

        for ((_src, _dst, _rt), edges) in &groups {
            let all_old = edges.iter().all(|e| e.timestamp < cutoff);
            if all_old && edges.len() > 1 {
                let earliest = edges.iter().map(|e| e.timestamp).min().unwrap();
                let latest = edges.iter().map(|e| e.timestamp).max().unwrap();
                let count = edges.len();
                edges_removed += count - 1;
                groups_compacted += 1;

                let mut summary = edges[0].clone();
                summary.timestamp = earliest;
                summary.metadata.insert("compacted_count".to_string(), count.to_string());
                summary.metadata.insert("compacted_latest".to_string(), latest.to_string());
                summary_edges.push(summary);
            } else {
                keep_edges.extend(edges.iter().cloned());
            }
        }

        // Rebuild with fresh metadata store and edge store
        self.edge_store.clear();
        self.reverse_adj.clear();
        self.meta_store = MetadataStore::new();

        let all_edges: Vec<Relation> = keep_edges.into_iter().chain(summary_edges).collect();
        for rel in all_edges {
            let src_sid = self.interner.intern(&rel.source_id);
            let dst_sid = self.interner.intern(&rel.dest_id);
            let meta_offset = self.meta_store.append(&rel.metadata);
            let ds_tag = self.intern_dataset_tag(rel.dataset_id.as_deref());
            let compact = CompactRelation {
                source_sid: src_sid,
                dest_sid: dst_sid,
                rel_type_tag: rel.rel_type.to_u8(),
                timestamp: rel.timestamp,
                metadata_offset: meta_offset,
                dataset_tag: ds_tag,
            };
            self.reverse_adj
                .entry(dst_sid)
                .or_default()
                .push(src_sid);
            self.edge_store.push(compact)?;
        }
        self.edge_store.finalize()?;

        for v in self.reverse_adj.values_mut() {
            v.sort_unstable();
            v.dedup();
        }

        for &&sid in self.entities.keys().collect::<Vec<_>>().iter() {
            self.reverse_adj.entry(sid).or_default();
        }

        self.edges_sorted = true; // finalize() sorted them
        Ok(CompactionStats {
            edges_before,
            edges_after: edges_before - edges_removed,
            edges_removed,
            groups_compacted,
        })
    }
}

/// Statistics returned by temporal compaction.
#[derive(serde::Serialize, Clone, Debug)]
pub struct CompactionStats {
    pub edges_before: usize,
    pub edges_after: usize,
    pub edges_removed: usize,
    pub groups_compacted: usize,
}

impl Default for GraphHunter {
    fn default() -> Self {
        Self::new()
    }
}
