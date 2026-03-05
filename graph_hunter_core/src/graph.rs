use ahash::{HashMap, HashMapExt, HashSet, HashSetExt};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use rayon::prelude::*;

use crate::anomaly::{AnomalyScorer, ScoringWeights};
use crate::entity::Entity;
use crate::errors::GraphError;
use crate::hypothesis::Hypothesis;
use crate::interner::{StrId, StringInterner};
use crate::relation::Relation;
use crate::types::{EntityType, MergePolicy, RelationType, entity_type_matches, relation_type_matches};

/// Result of a successful pattern match: an ordered list of entity IDs
/// representing the attack path through the graph.
pub type HuntResult = Vec<String>;

/// The core threat hunting graph engine.
///
/// Stores entities in a HashMap keyed by interned StrId for memory efficiency.
/// Relations in an adjacency list keyed by source entity StrId.
/// All string IDs are interned via `StringInterner` — each unique ID stored once.
#[derive(Clone)]
pub struct GraphHunter {
    /// String interner: stores each unique entity ID once.
    pub interner: StringInterner,
    pub entities: HashMap<StrId, Entity>,
    pub adjacency_list: HashMap<StrId, Vec<Relation>>,
    /// Index: entity type → set of interned entity IDs of that type.
    pub type_index: HashMap<EntityType, HashSet<StrId>>,
    /// Reverse adjacency: dest StrId → vec of source StrIds.
    pub reverse_adj: HashMap<StrId, Vec<StrId>>,
    /// Secondary index: source StrId → (rel_type → relations of that type from that source).
    pub rel_index: HashMap<StrId, HashMap<RelationType, Vec<Relation>>>,
    /// Optional anomaly scorer for path ranking.
    pub anomaly_scorer: Option<AnomalyScorer>,
}

impl GraphHunter {
    /// Creates a new empty graph.
    pub fn new() -> Self {
        Self {
            interner: StringInterner::new(),
            entities: HashMap::new(),
            adjacency_list: HashMap::new(),
            type_index: HashMap::new(),
            reverse_adj: HashMap::new(),
            rel_index: HashMap::new(),
            anomaly_scorer: None,
        }
    }

    /// Pre-allocates capacity for the internal HashMaps to avoid rehashing during bulk insertion.
    pub fn reserve(&mut self, entity_hint: usize, relation_hint: usize) {
        self.interner.reserve(entity_hint);
        self.entities.reserve(entity_hint);
        self.adjacency_list.reserve(entity_hint);
        self.type_index.reserve(16);
        self.reverse_adj.reserve(entity_hint);
        self.rel_index.reserve(entity_hint);
        let _ = relation_hint;
    }

    /// Rebuilds the rel_index from adjacency_list in one pass.
    pub fn rebuild_rel_index(&mut self) {
        self.rel_index.clear();
        for (&source_sid, edges) in &self.adjacency_list {
            for rel in edges {
                self.rel_index
                    .entry(source_sid)
                    .or_default()
                    .entry(rel.rel_type.clone())
                    .or_default()
                    .push(rel.clone());
            }
        }
    }

    /// Returns the number of entities (nodes) in the graph.
    pub fn entity_count(&self) -> usize {
        self.entities.len()
    }

    /// Returns the total number of relations (edges) in the graph.
    pub fn relation_count(&self) -> usize {
        self.adjacency_list.values().map(|edges| edges.len()).sum()
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
        self.entities.insert(sid, entity);
        self.adjacency_list.entry(sid).or_default();
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

        self.reverse_adj
            .entry(dst_sid)
            .or_default()
            .push(src_sid);
        self.rel_index
            .entry(src_sid)
            .or_default()
            .entry(relation.rel_type.clone())
            .or_default()
            .push(relation.clone());
        self.adjacency_list
            .entry(src_sid)
            .or_default()
            .push(relation);
        Ok(())
    }

    /// Retrieves an entity by its ID.
    pub fn get_entity(&self, id: &str) -> Option<&Entity> {
        let sid = self.interner.get(id)?;
        self.entities.get(&sid)
    }

    /// Retrieves all outgoing relations from a given entity.
    pub fn get_relations(&self, source_id: &str) -> &[Relation] {
        self.interner
            .get(source_id)
            .and_then(|sid| self.adjacency_list.get(&sid))
            .map(|v| v.as_slice())
            .unwrap_or(&[])
    }

    /// Retrieves outgoing relations of a specific type from a given entity.
    pub fn get_relations_by_type(&self, source_id: &str, rel_type: &RelationType) -> &[Relation] {
        self.interner
            .get(source_id)
            .and_then(|sid| self.rel_index.get(&sid))
            .and_then(|by_type| by_type.get(rel_type))
            .map(|v| v.as_slice())
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

    /// Internal: get relations by StrId for step matching.
    #[inline]
    fn get_relations_by_sid(&self, sid: StrId) -> &[Relation] {
        self.adjacency_list
            .get(&sid)
            .map(|v| v.as_slice())
            .unwrap_or(&[])
    }

    /// Internal: get relations by StrId and type.
    #[inline]
    fn get_relations_by_type_sid(&self, sid: StrId, rel_type: &RelationType) -> &[Relation] {
        self.rel_index
            .get(&sid)
            .and_then(|by_type| by_type.get(rel_type))
            .map(|v| v.as_slice())
            .unwrap_or(&[])
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
        if let Some(edges) = self.adjacency_list.get(&sid) {
            for rel in edges {
                if let Some(dest_sid) = self.interner.get(&rel.dest_id) {
                    if let Some(e) = self.entities.get(&dest_sid) {
                        types_set.insert(format!("{}", e.entity_type));
                    }
                }
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

    /// Returns edges for a hypothesis step: type-filtered via rel_index or all edges.
    #[inline]
    fn get_edges_for_step_sid(&self, sid: StrId, step: &crate::hypothesis::HypothesisStep) -> &[Relation] {
        if step.relation_type != RelationType::Any {
            self.get_relations_by_type_sid(sid, &step.relation_type)
        } else {
            self.get_relations_by_sid(sid)
        }
    }

    /// Returns edges for a hypothesis step using string ID.
    #[inline]
    #[allow(dead_code)]
    fn get_edges_for_step(&self, node_id: &str, step: &crate::hypothesis::HypothesisStep) -> &[Relation] {
        if step.relation_type != RelationType::Any {
            self.get_relations_by_type(node_id, &step.relation_type)
        } else {
            self.get_relations(node_id)
        }
    }

    /// Sorts all edge lists by timestamp so binary search can skip temporally invalid edges.
    pub fn sort_edges_by_timestamp(&mut self) {
        for edges in self.adjacency_list.values_mut() {
            edges.sort_unstable_by_key(|r| r.timestamp);
        }
        for by_type in self.rel_index.values_mut() {
            for edges in by_type.values_mut() {
                edges.sort_unstable_by_key(|r| r.timestamp);
            }
        }
    }

    /// Searches for paths matching a temporal hypothesis pattern.
    pub fn search_temporal_pattern(
        &mut self,
        hypothesis: &Hypothesis,
        time_window: Option<(i64, i64)>,
        max_results: Option<usize>,
    ) -> Result<(Vec<HuntResult>, bool), GraphError> {
        hypothesis
            .validate()
            .map_err(GraphError::InvalidHypothesis)?;

        self.sort_edges_by_timestamp();

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

        let results: Vec<HuntResult> = if start_sids.len() >= 64 {
            let rc = Arc::clone(&result_count);
            start_sids
                .par_iter()
                .flat_map_iter(|&start_sid| {
                    let mut local_results = Vec::new();
                    if rc.load(Ordering::Relaxed) >= cap {
                        return local_results;
                    }
                    self.dfs_match_iterative(
                        start_sid,
                        &hypothesis.steps,
                        time_window,
                        k,
                        cap,
                        &rc,
                        &mut local_results,
                    );
                    local_results
                })
                .collect()
        } else {
            let mut results = Vec::new();
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
        &mut self,
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

        self.sort_edges_by_timestamp();

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

        // Min-heap of (score, path): keeps the top_k highest-scoring paths.
        // The minimum in the heap acts as the dynamic pruning threshold.
        use ordered_float::OrderedFloat;
        use std::cmp::Reverse;
        use std::collections::BinaryHeap;

        let mut heap: BinaryHeap<Reverse<(OrderedFloat<f64>, Vec<String>)>> =
            BinaryHeap::with_capacity(top_k + 1);

        for &start_sid in &start_sids {
            self.dfs_match_smart(
                start_sid,
                &hypothesis.steps,
                time_window,
                k,
                top_k,
                total_steps,
                &mut heap,
            );
        }

        // Extract results from heap, sorted by score descending
        let mut scored: Vec<(f64, Vec<String>)> = heap
            .into_sorted_vec()
            .into_iter()
            .map(|Reverse((score, path))| (score.into_inner(), path))
            .collect();
        scored.reverse(); // highest score first

        let results: Vec<HuntResult> = scored.into_iter().map(|(_, path)| path).collect();
        Ok((results, false))
    }

    /// Smart DFS with anomaly-based pruning and top-K heap.
    fn dfs_match_smart(
        &self,
        start_sid: StrId,
        steps: &[crate::hypothesis::HypothesisStep],
        time_window: Option<(i64, i64)>,
        k: usize,
        top_k: usize,
        total_steps: usize,
        heap: &mut std::collections::BinaryHeap<
            std::cmp::Reverse<(ordered_float::OrderedFloat<f64>, Vec<String>)>,
        >,
    ) {
        use ordered_float::OrderedFloat;
        use std::cmp::Reverse;

        struct AnomalyFrame {
            sid: StrId,
            step_idx: usize,
            edge_hi: usize,
            edge_cursor: usize,
            path_anomaly_sum: f64,
        }

        let scorer = match self.anomaly_scorer.as_ref() {
            Some(s) => s,
            None => return, // scorer not initialized; skip smart DFS
        };

        let mut path: Vec<StrId> = Vec::with_capacity(steps.len() + 1);
        let mut visit_count: HashMap<StrId, usize> = HashMap::new();

        path.push(start_sid);
        *visit_count.entry(start_sid).or_insert(0) += 1;

        let start_str = self.interner.resolve(start_sid);
        let start_node_score = scorer.node_anomaly_estimate(start_str);

        let (lo, hi) = if !steps.is_empty() {
            self.edge_range_sid(start_sid, &steps[0], i64::MIN, time_window)
        } else {
            (0, 0)
        };

        let mut stack: Vec<AnomalyFrame> = vec![AnomalyFrame {
            sid: start_sid,
            step_idx: 0,
            edge_hi: hi,
            edge_cursor: lo,
            path_anomaly_sum: start_node_score,
        }];

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

                if !relation_type_matches(&step.relation_type, &edge.rel_type) {
                    continue;
                }

                let dest_sid = match self.interner.get(&edge.dest_id) {
                    Some(s) => s,
                    None => continue,
                };
                let dest_entity = match self.entities.get(&dest_sid) {
                    Some(e) if entity_type_matches(&step.dest_type, &e.entity_type) => e,
                    _ => continue,
                };

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

                let _ = dest_entity;
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
    fn dfs_match_iterative(
        &self,
        start_sid: StrId,
        steps: &[crate::hypothesis::HypothesisStep],
        time_window: Option<(i64, i64)>,
        k: usize,
        cap: usize,
        result_count: &AtomicUsize,
        results: &mut Vec<HuntResult>,
    ) {
        struct Frame {
            sid: StrId,
            step_idx: usize,
            edge_hi: usize,
            edge_cursor: usize,
        }

        let mut path: Vec<StrId> = Vec::with_capacity(steps.len() + 1);
        let mut visit_count: HashMap<StrId, usize> = HashMap::new();

        path.push(start_sid);
        *visit_count.entry(start_sid).or_insert(0) += 1;

        let (lo, hi) = if !steps.is_empty() {
            self.edge_range_sid(start_sid, &steps[0], i64::MIN, time_window)
        } else {
            (0, 0)
        };

        let mut stack: Vec<Frame> = vec![Frame {
            sid: start_sid,
            step_idx: 0,
            edge_hi: hi,
            edge_cursor: lo,
        }];

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

                if !relation_type_matches(&step.relation_type, &edge.rel_type) {
                    continue;
                }

                let dest_sid = match self.interner.get(&edge.dest_id) {
                    Some(s) => s,
                    None => continue,
                };
                let dest_entity = match self.entities.get(&dest_sid) {
                    Some(e) if entity_type_matches(&step.dest_type, &e.entity_type) => e,
                    _ => continue,
                };

                let count = visit_count.get(&dest_sid).copied().unwrap_or(0);
                if count >= k {
                    continue;
                }

                let _ = dest_entity;
                *visit_count.entry(dest_sid).or_insert(0) += 1;
                path.push(dest_sid);

                let next_step_idx = frame.step_idx + 1;
                let (next_lo, next_hi) = if next_step_idx < steps.len() {
                    self.edge_range_sid(dest_sid, &steps[next_step_idx], edge.timestamp, time_window)
                } else {
                    (0, 0)
                };

                stack.push(Frame {
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
        let edges = self.get_edges_for_step(node_id, step);
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
    ) -> (usize, usize) {
        self.ingest_logs_with_policy(logs, parser, dataset_id, &MergePolicy::default())
    }

    /// Ingests raw log data with a specific merge policy.
    pub fn ingest_logs_with_policy<P: crate::parser::LogParser>(
        &mut self,
        logs: &str,
        parser: &P,
        dataset_id: Option<String>,
        merge_policy: &MergePolicy,
    ) -> (usize, usize) {
        let triples = parser.parse(logs);
        let mut new_entities = 0usize;
        let mut new_relations = 0usize;
        let ds: Option<Arc<str>> = dataset_id.map(|s| Arc::from(s.as_str()));

        for (mut src, mut rel, mut dst) in triples {
            if let Some(ref id) = ds {
                src.dataset_id = Some(Arc::clone(id));
                rel.dataset_id = Some(Arc::clone(id));
                dst.dataset_id = Some(Arc::clone(id));
            }

            // Upsert source entity
            let src_sid = self.interner.intern(&src.id);
            if let Some(existing) = self.entities.get_mut(&src_sid) {
                Self::merge_metadata(&mut existing.metadata, &src.metadata, merge_policy);
            } else {
                let et = src.entity_type.clone();
                self.entities.insert(src_sid, src);
                self.type_index.entry(et).or_default().insert(src_sid);
                self.adjacency_list.entry(src_sid).or_default();
                self.reverse_adj.entry(src_sid).or_default();
                new_entities += 1;
            }

            // Upsert destination entity
            let dst_sid = self.interner.intern(&dst.id);
            if let Some(existing) = self.entities.get_mut(&dst_sid) {
                Self::merge_metadata(&mut existing.metadata, &dst.metadata, merge_policy);
            } else {
                let et = dst.entity_type.clone();
                self.entities.insert(dst_sid, dst);
                self.type_index.entry(et).or_default().insert(dst_sid);
                self.adjacency_list.entry(dst_sid).or_default();
                self.reverse_adj.entry(dst_sid).or_default();
                new_entities += 1;
            }

            // Feed anomaly scorer if enabled
            if let Some(ref mut scorer) = self.anomaly_scorer {
                scorer.observe_entity(&rel.source_id, rel.timestamp);
                scorer.observe_entity(&rel.dest_id, rel.timestamp);
                scorer.observe_edge(&rel.source_id, &rel.dest_id);
            }

            // Always insert relation (skip rel_index — rebuilt after batch)
            self.reverse_adj
                .entry(dst_sid)
                .or_default()
                .push(src_sid);
            self.adjacency_list
                .entry(src_sid)
                .or_default()
                .push(rel);
            new_relations += 1;
        }

        self.rebuild_rel_index();
        (new_entities, new_relations)
    }

    /// Removes all entities and relations that belong to the given dataset.
    pub fn remove_entities_and_relations_by_dataset(&mut self, dataset_id: &str) -> (usize, usize) {
        let to_remove: Vec<StrId> = self
            .entities
            .iter()
            .filter(|(_, e)| e.dataset_id.as_deref() == Some(dataset_id))
            .map(|(&sid, _)| sid)
            .collect();

        // Remove relations with this dataset_id
        let mut relations_removed = 0usize;
        for edges in self.adjacency_list.values_mut() {
            let before = edges.len();
            edges.retain(|rel| rel.dataset_id.as_deref() != Some(dataset_id));
            relations_removed += before - edges.len();
        }

        // Rebuild reverse_adj and rel_index
        self.reverse_adj.clear();
        self.rel_index.clear();
        for (&source_sid, edges) in &self.adjacency_list {
            for rel in edges {
                if let Some(dst_sid) = self.interner.get(&rel.dest_id) {
                    self.reverse_adj
                        .entry(dst_sid)
                        .or_default()
                        .push(source_sid);
                }
                self.rel_index
                    .entry(source_sid)
                    .or_default()
                    .entry(rel.rel_type.clone())
                    .or_default()
                    .push(rel.clone());
            }
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
            self.adjacency_list.remove(sid);
            self.reverse_adj.remove(sid);
        }

        (entities_removed, relations_removed)
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
        let relations: Vec<Relation> = self
            .adjacency_list
            .values()
            .flat_map(|edges| edges.iter().cloned())
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
            let dest_sid = match self.interner.get(&edge.dest_id) {
                Some(s) => s,
                None => continue,
            };
            if visited.contains(&dest_sid) {
                continue;
            }

            visited.insert(dest_sid);
            path.push(edge.dest_id.clone());

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
    ) -> (usize, usize)
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

        for (i, (mut src, mut rel, mut dst)) in triples.into_iter().enumerate() {
            if let Some(ref id) = ds {
                src.dataset_id = Some(Arc::clone(id));
                rel.dataset_id = Some(Arc::clone(id));
                dst.dataset_id = Some(Arc::clone(id));
            }

            let src_sid = self.interner.intern(&src.id);
            if let Some(existing) = self.entities.get_mut(&src_sid) {
                Self::merge_metadata(&mut existing.metadata, &src.metadata, &merge_policy);
            } else {
                let et = src.entity_type.clone();
                self.entities.insert(src_sid, src);
                self.type_index.entry(et).or_default().insert(src_sid);
                self.adjacency_list.entry(src_sid).or_default();
                self.reverse_adj.entry(src_sid).or_default();
                new_entities += 1;
            }

            let dst_sid = self.interner.intern(&dst.id);
            if let Some(existing) = self.entities.get_mut(&dst_sid) {
                Self::merge_metadata(&mut existing.metadata, &dst.metadata, &merge_policy);
            } else {
                let et = dst.entity_type.clone();
                self.entities.insert(dst_sid, dst);
                self.type_index.entry(et).or_default().insert(dst_sid);
                self.adjacency_list.entry(dst_sid).or_default();
                self.reverse_adj.entry(dst_sid).or_default();
                new_entities += 1;
            }

            if let Some(ref mut scorer) = self.anomaly_scorer {
                scorer.observe_entity(&rel.source_id, rel.timestamp);
                scorer.observe_entity(&rel.dest_id, rel.timestamp);
                scorer.observe_edge(&rel.source_id, &rel.dest_id);
            }

            self.reverse_adj
                .entry(dst_sid)
                .or_default()
                .push(src_sid);
            self.adjacency_list
                .entry(src_sid)
                .or_default()
                .push(rel);
            new_relations += 1;

            if (i + 1) % chunk_size == 0 || i + 1 == total {
                on_progress(i + 1, total, new_entities, new_relations);
            }
        }

        self.rebuild_rel_index();
        (new_entities, new_relations)
    }

    /// Inserts pre-parsed triples directly (streaming ingestion).
    pub fn insert_triples(
        &mut self,
        triples: Vec<crate::parser::ParsedTriple>,
        dataset_id: Option<&str>,
    ) -> (usize, usize) {
        let merge_policy = MergePolicy::default();
        let mut new_entities = 0usize;
        let mut new_relations = 0usize;
        let ds: Option<Arc<str>> = dataset_id.map(Arc::from);

        for (mut src, mut rel, mut dst) in triples {
            if let Some(ref id) = ds {
                src.dataset_id = Some(Arc::clone(id));
                rel.dataset_id = Some(Arc::clone(id));
                dst.dataset_id = Some(Arc::clone(id));
            }

            let src_sid = self.interner.intern(&src.id);
            if let Some(existing) = self.entities.get_mut(&src_sid) {
                Self::merge_metadata(&mut existing.metadata, &src.metadata, &merge_policy);
            } else {
                let et = src.entity_type.clone();
                self.entities.insert(src_sid, src);
                self.type_index.entry(et).or_default().insert(src_sid);
                self.adjacency_list.entry(src_sid).or_default();
                self.reverse_adj.entry(src_sid).or_default();
                new_entities += 1;
            }

            let dst_sid = self.interner.intern(&dst.id);
            if let Some(existing) = self.entities.get_mut(&dst_sid) {
                Self::merge_metadata(&mut existing.metadata, &dst.metadata, &merge_policy);
            } else {
                let et = dst.entity_type.clone();
                self.entities.insert(dst_sid, dst);
                self.type_index.entry(et).or_default().insert(dst_sid);
                self.adjacency_list.entry(dst_sid).or_default();
                self.reverse_adj.entry(dst_sid).or_default();
                new_entities += 1;
            }

            if let Some(ref mut scorer) = self.anomaly_scorer {
                scorer.observe_entity(&rel.source_id, rel.timestamp);
                scorer.observe_entity(&rel.dest_id, rel.timestamp);
                scorer.observe_edge(&rel.source_id, &rel.dest_id);
            }

            self.reverse_adj
                .entry(dst_sid)
                .or_default()
                .push(src_sid);
            self.adjacency_list
                .entry(src_sid)
                .or_default()
                .push(rel);
            new_relations += 1;
        }

        (new_entities, new_relations)
    }

    /// Enables anomaly scoring with backfilling from existing data.
    pub fn enable_anomaly_scoring(&mut self, weights: ScoringWeights) {
        let mut scorer = AnomalyScorer::new(weights);
        for edges in self.adjacency_list.values() {
            for rel in edges {
                scorer.observe_entity(&rel.source_id, rel.timestamp);
                scorer.observe_entity(&rel.dest_id, rel.timestamp);
                scorer.observe_edge(&rel.source_id, &rel.dest_id);
            }
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

        for edges in self.adjacency_list.values() {
            for rel in edges {
                let type_name = format!("{}", rel.rel_type);
                let hour = rel.timestamp - (rel.timestamp % 3600);
                *by_type
                    .entry(type_name)
                    .or_default()
                    .entry(hour)
                    .or_insert(0) += 1;
            }
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

        for edges in self.adjacency_list.values() {
            for rel in edges {
                if let Some(src_sid) = self.interner.get(&rel.source_id) {
                    if let Some(src) = self.entities.get(&src_sid) {
                        let type_name = format!("{}", src.entity_type);
                        let hour = rel.timestamp - (rel.timestamp % 3600);
                        *type_data
                            .entry(type_name.clone())
                            .or_default()
                            .entry(hour)
                            .or_insert(0) += 1;
                        let min = type_min.entry(type_name.clone()).or_insert(rel.timestamp);
                        if rel.timestamp < *min { *min = rel.timestamp; }
                        let max = type_max.entry(type_name.clone()).or_insert(rel.timestamp);
                        if rel.timestamp > *max { *max = rel.timestamp; }
                    }
                }
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
    pub fn compact_before(&mut self, cutoff: i64) -> CompactionStats {
        use crate::relation::Relation;

        let mut edges_before = 0usize;
        let mut edges_removed = 0usize;
        let mut groups_compacted = 0usize;

        let mut groups: HashMap<(String, String, String), Vec<Relation>> = HashMap::new();
        for edges in self.adjacency_list.values() {
            for rel in edges {
                edges_before += 1;
                let key = (
                    rel.source_id.clone(),
                    rel.dest_id.clone(),
                    format!("{}", rel.rel_type),
                );
                groups.entry(key).or_default().push(rel.clone());
            }
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

        // Rebuild
        self.adjacency_list.clear();
        self.rel_index.clear();
        self.reverse_adj.clear();

        let all_edges: Vec<Relation> = keep_edges.into_iter().chain(summary_edges).collect();
        for rel in all_edges {
            let src_sid = self.interner.intern(&rel.source_id);
            let dst_sid = self.interner.intern(&rel.dest_id);
            self.reverse_adj
                .entry(dst_sid)
                .or_default()
                .push(src_sid);
            self.rel_index
                .entry(src_sid)
                .or_default()
                .entry(rel.rel_type.clone())
                .or_default()
                .push(rel.clone());
            self.adjacency_list
                .entry(src_sid)
                .or_default()
                .push(rel);
        }

        for v in self.reverse_adj.values_mut() {
            v.sort_unstable();
            v.dedup();
        }

        for &&sid in self.entities.keys().collect::<Vec<_>>().iter() {
            self.adjacency_list.entry(sid).or_default();
            self.reverse_adj.entry(sid).or_default();
        }

        CompactionStats {
            edges_before,
            edges_after: edges_before - edges_removed,
            edges_removed,
            groups_compacted,
        }
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
