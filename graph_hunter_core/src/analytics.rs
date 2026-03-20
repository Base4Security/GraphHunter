use std::collections::{HashMap, HashSet, VecDeque};

use serde::{Deserialize, Serialize};

use crate::anomaly::ScoreBreakdown;
use crate::graph::GraphHunter;
use crate::interner::StrId;
use crate::types::{EntityType, RelationType};

// ── Serializable structs ──

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct NeighborhoodFilter {
    pub entity_types: Option<Vec<EntityType>>,
    pub relation_types: Option<Vec<RelationType>>,
    pub time_start: Option<i64>,
    pub time_end: Option<i64>,
    pub min_score: Option<f64>,
}

#[derive(Serialize, Clone, Debug)]
pub struct NeighborNode {
    pub id: String,
    pub entity_type: String,
    pub score: f64,
    pub metadata: HashMap<String, String>,
}

#[derive(Serialize, Clone, Debug)]
pub struct NeighborEdge {
    pub source: String,
    pub target: String,
    pub rel_type: String,
    pub timestamp: i64,
    pub metadata: HashMap<String, String>,
}

#[derive(Serialize, Clone, Debug)]
pub struct Neighborhood {
    pub center: String,
    pub nodes: Vec<NeighborNode>,
    pub edges: Vec<NeighborEdge>,
    pub truncated: bool,
}

#[derive(Serialize, Clone, Debug)]
pub struct SearchResult {
    pub id: String,
    pub entity_type: String,
    pub score: f64,
    pub connections: usize,
}

/// Minimal info for one neighbour in the node details panel (clickable list).
#[derive(Serialize, Clone, Debug)]
pub struct NeighborSummary {
    pub id: String,
    pub entity_type: String,
}

#[derive(Serialize, Clone, Debug)]
pub struct NodeDetails {
    pub id: String,
    pub entity_type: String,
    pub score: f64,
    pub degree_score: f64,
    pub betweenness: f64,
    pub pagerank_score: f64,
    pub metadata: HashMap<String, String>,
    pub in_degree: usize,
    pub out_degree: usize,
    pub time_range: Option<(i64, i64)>,
    pub neighbor_types: HashMap<String, usize>,
    /// Neighbour node IDs and types for the lateral panel.
    pub neighbors: Vec<NeighborSummary>,
}

#[derive(Serialize, Clone, Debug)]
pub struct TypeDistribution {
    pub entity_type: String,
    pub count: usize,
}

#[derive(Serialize, Clone, Debug)]
pub struct TopAnomaly {
    pub id: String,
    pub entity_type: String,
    pub score: f64,
}

#[derive(Serialize, Clone, Debug)]
pub struct GraphSummary {
    pub entity_count: usize,
    pub relation_count: usize,
    pub type_distribution: Vec<TypeDistribution>,
    pub time_range: Option<(i64, i64)>,
    pub top_anomalies: Vec<TopAnomaly>,
}

#[derive(Serialize, Clone, Debug)]
pub struct ScoredPath {
    pub path: Vec<String>,
    pub max_score: f64,
    pub total_score: f64,
    pub time_start: i64,
    pub time_end: i64,
    pub chain_summary: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub anomaly_score: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub anomaly_breakdown: Option<ScoreBreakdown>,
}

// ── Implementations on GraphHunter ──

impl GraphHunter {
    /// Searches entities by substring match on ID (case-insensitive).
    pub fn search_entities(
        &self,
        query: &str,
        type_filter: Option<&EntityType>,
        limit: usize,
    ) -> Vec<SearchResult> {
        let query_lower = query.to_lowercase();
        let mut results = Vec::new();

        // If type_filter is specified, use type_index for fast lookup
        let candidate_sids: Vec<StrId> = match type_filter {
            Some(et) => {
                if let Some(ids) = self.type_index.get(et) {
                    ids.iter().copied().collect()
                } else {
                    return results;
                }
            }
            None => self.entities.keys().copied().collect(),
        };

        for sid in candidate_sids {
            if results.len() >= limit {
                break;
            }
            let id_str = self.interner.resolve(sid);
            if id_str.to_lowercase().contains(&query_lower) {
                if let Some(entity) = self.entities.get(&sid) {
                    let out_degree = self.edge_store.get_edges(sid).len();
                    let in_degree = self
                        .reverse_adj
                        .get(&sid)
                        .map(|v| v.len())
                        .unwrap_or(0);
                    results.push(SearchResult {
                        id: entity.id.clone(),
                        entity_type: format!("{}", entity.entity_type),
                        score: entity.score,
                        connections: out_degree + in_degree,
                    });
                }
            }
        }

        results
    }

    /// BFS-based neighborhood expansion from a center node.
    pub fn get_neighborhood(
        &self,
        center: &str,
        max_hops: usize,
        max_nodes: usize,
        filter: Option<&NeighborhoodFilter>,
    ) -> Option<Neighborhood> {
        let center_sid = self.interner.get(center)?;
        if !self.entities.contains_key(&center_sid) {
            return None;
        }

        let mut visited: HashSet<StrId> = HashSet::new();
        let mut queue: VecDeque<(StrId, usize)> = VecDeque::new();
        let mut node_sids: Vec<StrId> = Vec::new();
        let mut edges: Vec<NeighborEdge> = Vec::new();
        let mut truncated = false;
        let max_edges = max_nodes * 10; // cap edges to prevent OOM on dense graphs

        visited.insert(center_sid);
        queue.push_back((center_sid, 0));
        node_sids.push(center_sid);

        while let Some((current_sid, depth)) = queue.pop_front() {
            if depth >= max_hops {
                continue;
            }

            // Outgoing edges
            {
                let compacts = self.edge_store.get_edges(current_sid);
                for compact in compacts {
                    if edges.len() >= max_edges {
                        truncated = true;
                        break;
                    }
                    // Filter using compact fields to avoid materializing every edge
                    let dest_sid = compact.dest_sid;
                    let dest_id_str = self.interner.resolve(dest_sid);

                    if let Some(f) = filter {
                        if let Some(ref rel_types) = f.relation_types {
                            if !rel_types.iter().any(|rt| rt.to_u8() == compact.rel_type_tag) {
                                continue;
                            }
                        }
                        if let Some(start) = f.time_start {
                            if compact.timestamp < start { continue; }
                        }
                        if let Some(end) = f.time_end {
                            if compact.timestamp > end { continue; }
                        }
                        if let Some(ref entity_types) = f.entity_types {
                            if let Some(entity) = self.entities.get(&dest_sid) {
                                if !entity_types.contains(&entity.entity_type) { continue; }
                            }
                        }
                        if let Some(min_score) = f.min_score {
                            if let Some(entity) = self.entities.get(&dest_sid) {
                                if entity.score < min_score { continue; }
                            }
                        }
                    }

                    if !visited.contains(&dest_sid) {
                        if node_sids.len() >= max_nodes {
                            truncated = true;
                            continue;
                        }
                        visited.insert(dest_sid);
                        node_sids.push(dest_sid);
                        queue.push_back((dest_sid, depth + 1));
                    }

                    if visited.contains(&dest_sid) {
                        edges.push(NeighborEdge {
                            source: self.interner.resolve(compact.source_sid).to_string(),
                            target: dest_id_str.to_string(),
                            rel_type: format!("{}", compact.rel_type()),
                            timestamp: compact.timestamp,
                            metadata: self.meta_store.get(compact.metadata_offset),
                        });
                    }
                }
            }

            // Incoming edges (via reverse_adj)
            if edges.len() >= max_edges {
                truncated = true;
            } else if let Some(sources) = self.reverse_adj.get(&current_sid) {
                for &source_sid in sources {
                    if edges.len() >= max_edges {
                        truncated = true;
                        break;
                    }
                    {
                        let compacts = self.edge_store.get_edges(source_sid);
                        for compact in compacts {
                            if edges.len() >= max_edges {
                                truncated = true;
                                break;
                            }
                            if compact.dest_sid != current_sid {
                                continue;
                            }

                            if !visited.contains(&source_sid) {
                                if node_sids.len() >= max_nodes {
                                    truncated = true;
                                    continue;
                                }
                                visited.insert(source_sid);
                                node_sids.push(source_sid);
                                queue.push_back((source_sid, depth + 1));
                            }

                            if visited.contains(&source_sid) {
                                edges.push(NeighborEdge {
                                    source: self.interner.resolve(compact.source_sid).to_string(),
                                    target: self.interner.resolve(compact.dest_sid).to_string(),
                                    rel_type: format!("{}", compact.rel_type()),
                                    timestamp: compact.timestamp,
                                    metadata: self.meta_store.get(compact.metadata_offset),
                                });
                            }
                        }
                    }
                }
            }
        }

        // Deduplicate edges
        let mut seen_edges: HashSet<(String, String, i64)> = HashSet::new();
        edges.retain(|e| seen_edges.insert((e.source.clone(), e.target.clone(), e.timestamp)));

        // Build node list
        let nodes: Vec<NeighborNode> = node_sids
            .iter()
            .filter_map(|&sid| {
                self.entities.get(&sid).map(|e| NeighborNode {
                    id: e.id.clone(),
                    entity_type: format!("{}", e.entity_type),
                    score: e.score,
                    metadata: e.metadata.clone(),
                })
            })
            .collect();

        Some(Neighborhood {
            center: center.to_string(),
            nodes,
            edges,
            truncated,
        })
    }

    /// Checks whether a relation and its neighbor node pass the given filter.
    fn passes_filter(
        &self,
        rel: &crate::relation::Relation,
        neighbor_id: &str,
        filter: Option<&NeighborhoodFilter>,
    ) -> bool {
        let filter = match filter {
            Some(f) => f,
            None => return true,
        };

        if let Some(ref rel_types) = filter.relation_types {
            if !rel_types.contains(&rel.rel_type) {
                return false;
            }
        }

        if let Some(start) = filter.time_start {
            if rel.timestamp < start {
                return false;
            }
        }
        if let Some(end) = filter.time_end {
            if rel.timestamp > end {
                return false;
            }
        }

        if let Some(ref entity_types) = filter.entity_types {
            if let Some(entity) = self.get_entity(neighbor_id) {
                if !entity_types.contains(&entity.entity_type) {
                    return false;
                }
            }
        }

        if let Some(min_score) = filter.min_score {
            if let Some(entity) = self.get_entity(neighbor_id) {
                if entity.score < min_score {
                    return false;
                }
            }
        }

        true
    }

    /// Computes degree centrality scores for all entities.
    pub fn compute_scores(&mut self) {
        if self.entities.is_empty() {
            return;
        }

        let mut degrees: HashMap<StrId, usize> = HashMap::new();
        let mut max_degree: usize = 0;

        for &sid in self.entities.keys() {
            let out_deg = self.edge_store.get_edges(sid).len();
            *degrees.entry(sid).or_default() += out_deg;
        }
        for (&sid, sources) in &self.reverse_adj {
            *degrees.entry(sid).or_default() += sources.len();
        }

        for &deg in degrees.values() {
            if deg > max_degree {
                max_degree = deg;
            }
        }

        if max_degree == 0 {
            return;
        }

        for (&sid, entity) in &mut self.entities {
            let deg = degrees.get(&sid).copied().unwrap_or(0);
            let normalized = (deg as f64 / max_degree as f64) * 100.0;
            entity.score = normalized;
            entity.degree_score = normalized;
        }
    }

    /// Computes betweenness centrality using Brandes' algorithm.
    pub fn compute_betweenness(&mut self, sample_limit: Option<usize>) {
        let n = self.entities.len();
        if n < 2 {
            return;
        }

        let sids: Vec<StrId> = self.entities.keys().copied().collect();
        let sid_to_idx: HashMap<StrId, usize> = sids.iter().enumerate().map(|(i, &sid)| (sid, i)).collect();
        let mut cb = vec![0.0f64; n];

        let limit = sample_limit.unwrap_or(500);
        let sources: Vec<usize> = if n <= limit {
            (0..n).collect()
        } else {
            let step = n as f64 / limit as f64;
            (0..limit).map(|i| (i as f64 * step) as usize).collect()
        };
        let sample_count = sources.len();

        for &s in &sources {
            let mut stack: Vec<usize> = Vec::new();
            let mut predecessors: Vec<Vec<usize>> = vec![Vec::new(); n];
            let mut sigma = vec![0.0f64; n];
            sigma[s] = 1.0;
            let mut dist: Vec<i64> = vec![-1; n];
            dist[s] = 0;
            let mut queue: VecDeque<usize> = VecDeque::new();
            queue.push_back(s);

            while let Some(v) = queue.pop_front() {
                stack.push(v);
                let v_sid = sids[v];

                // Outgoing edges
                for compact in self.edge_store.get_edges(v_sid) {
                    if let Some(&w) = sid_to_idx.get(&compact.dest_sid) {
                        if dist[w] < 0 {
                            dist[w] = dist[v] + 1;
                            queue.push_back(w);
                        }
                        if dist[w] == dist[v] + 1 {
                            sigma[w] += sigma[v];
                            predecessors[w].push(v);
                        }
                    }
                }
                // Incoming edges (treat as undirected)
                if let Some(srcs) = self.reverse_adj.get(&v_sid) {
                    for &src_sid in srcs {
                        if let Some(&w) = sid_to_idx.get(&src_sid) {
                            if dist[w] < 0 {
                                dist[w] = dist[v] + 1;
                                queue.push_back(w);
                            }
                            if dist[w] == dist[v] + 1 {
                                sigma[w] += sigma[v];
                                predecessors[w].push(v);
                            }
                        }
                    }
                }
            }

            let mut delta = vec![0.0f64; n];
            while let Some(w) = stack.pop() {
                for &v in &predecessors[w] {
                    delta[v] += (sigma[v] / sigma[w]) * (1.0 + delta[w]);
                }
                if w != s {
                    cb[w] += delta[w];
                }
            }
        }

        let norm = if n > 2 {
            ((n - 1) * (n - 2)) as f64
        } else {
            1.0
        };
        let scale = if sample_count < n {
            n as f64 / sample_count as f64
        } else {
            1.0
        };

        let mut max_cb = 0.0f64;
        for val in &mut cb {
            *val = (*val / norm) * scale;
            if *val > max_cb {
                max_cb = *val;
            }
        }

        for (i, &sid) in sids.iter().enumerate() {
            if let Some(entity) = self.entities.get_mut(&sid) {
                entity.betweenness = if max_cb > 0.0 {
                    (cb[i] / max_cb) * 100.0
                } else {
                    0.0
                };
            }
        }
    }

    /// Computes temporal PageRank with exponential decay.
    pub fn compute_temporal_pagerank(
        &mut self,
        lambda: Option<f64>,
        damping: Option<f64>,
        max_iter: Option<usize>,
        epsilon: Option<f64>,
        reference_time: Option<i64>,
    ) {
        let n = self.entities.len();
        if n == 0 {
            return;
        }

        let lambda = lambda.unwrap_or(0.001);
        let d = damping.unwrap_or(0.85);
        let max_iter = max_iter.unwrap_or(30);
        let eps = epsilon.unwrap_or(1e-6);

        let t_ref = reference_time.unwrap_or_else(|| {
            let mut max_t = 0i64;
            for compact in self.edge_store.iter_all() {
                if compact.timestamp > max_t {
                    max_t = compact.timestamp;
                }
            }
            max_t
        });

        let sids: Vec<StrId> = self.entities.keys().copied().collect();
        let sid_to_idx: HashMap<StrId, usize> = sids.iter().enumerate().map(|(i, &sid)| (sid, i)).collect();

        let mut w_out = vec![0.0f64; n];
        let mut weighted_edges: Vec<(usize, usize, f64)> = Vec::new();

        for compact in self.edge_store.iter_all() {
            if let (Some(&src_idx), Some(&dst_idx)) = (
                sid_to_idx.get(&compact.source_sid),
                sid_to_idx.get(&compact.dest_sid),
            ) {
                let dt = (t_ref - compact.timestamp).max(0) as f64;
                let w = (-lambda * dt).exp();
                w_out[src_idx] += w;
                weighted_edges.push((src_idx, dst_idx, w));
            }
        }

        let mut pr = vec![1.0 / n as f64; n];
        let base = (1.0 - d) / n as f64;

        for _ in 0..max_iter {
            let mut pr_new = vec![0.0f64; n];

            let mut dangling_sum = 0.0f64;
            for (i, &wo) in w_out.iter().enumerate() {
                if wo == 0.0 {
                    dangling_sum += pr[i];
                }
            }

            for &(src, dst, w) in &weighted_edges {
                if w_out[src] > 0.0 {
                    pr_new[dst] += w * pr[src] / w_out[src];
                }
            }

            let dangling_add = d * dangling_sum / n as f64;
            for val in &mut pr_new {
                *val = base + d * *val + dangling_add;
            }

            let diff: f64 = pr.iter().zip(pr_new.iter()).map(|(a, b)| (a - b).abs()).sum();
            pr = pr_new;
            if diff < eps {
                break;
            }
        }

        let max_pr = pr.iter().cloned().fold(0.0f64, f64::max);
        if max_pr > 0.0 {
            for (i, &sid) in sids.iter().enumerate() {
                if let Some(entity) = self.entities.get_mut(&sid) {
                    entity.pagerank_score = (pr[i] / max_pr) * 100.0;
                }
            }
        }
    }

    /// Composite scoring from weighted combination.
    pub fn compute_composite_score(&mut self, degree_w: f64, pagerank_w: f64, betweenness_w: f64) {
        let n = self.entities.len();
        if n == 0 {
            return;
        }

        let mut raw: Vec<(StrId, f64)> = self
            .entities
            .iter()
            .map(|(&sid, e)| {
                let val = degree_w * e.degree_score
                    + pagerank_w * e.pagerank_score
                    + betweenness_w * e.betweenness;
                (sid, val)
            })
            .collect();

        let max_raw = raw.iter().map(|(_, v)| *v).fold(0.0f64, f64::max);
        if max_raw > 0.0 {
            for (_, v) in &mut raw {
                *v = (*v / max_raw) * 100.0;
            }
        }

        for (sid, val) in raw {
            if let Some(entity) = self.entities.get_mut(&sid) {
                entity.score = val;
            }
        }
    }

    /// Returns detailed information about a specific node.
    pub fn get_node_details(&self, node_id: &str) -> Option<NodeDetails> {
        let sid = self.interner.get(node_id)?;
        let entity = self.entities.get(&sid)?;

        let out_edges = self.edge_store.get_edges(sid);
        let out_degree = out_edges.len();
        let in_degree = self
            .reverse_adj
            .get(&sid)
            .map(|v| v.len())
            .unwrap_or(0);

        // Cap iterations to prevent OOM/hangs on super-connected nodes (e.g. 1.5M edges)
        const MAX_SCAN_EDGES: usize = 50_000;
        const MAX_NEIGHBORS_RETURNED: usize = 200;

        let mut min_ts = i64::MAX;
        let mut max_ts = i64::MIN;
        let mut has_timestamps = false;

        for compact in out_edges.iter().take(MAX_SCAN_EDGES) {
            if compact.timestamp != 0 {
                min_ts = min_ts.min(compact.timestamp);
                max_ts = max_ts.max(compact.timestamp);
                has_timestamps = true;
            }
        }
        // For incoming edges, sample reverse_adj instead of scanning all
        if let Some(sources) = self.reverse_adj.get(&sid) {
            for &source_sid in sources.iter().take(MAX_SCAN_EDGES) {
                for compact in self.edge_store.get_edges(source_sid) {
                    if compact.dest_sid == sid && compact.timestamp != 0 {
                        min_ts = min_ts.min(compact.timestamp);
                        max_ts = max_ts.max(compact.timestamp);
                        has_timestamps = true;
                        break; // one match per source is enough for time range
                    }
                }
            }
        }

        let mut neighbor_types: HashMap<String, usize> = HashMap::new();
        let mut seen: HashSet<StrId> = HashSet::new();
        let mut neighbors: Vec<NeighborSummary> = Vec::new();

        for compact in out_edges {
            if let Some(dest) = self.entities.get(&compact.dest_sid) {
                *neighbor_types
                    .entry(format!("{}", dest.entity_type))
                    .or_default() += 1;
                if seen.insert(compact.dest_sid) && neighbors.len() < MAX_NEIGHBORS_RETURNED {
                    neighbors.push(NeighborSummary {
                        id: dest.id.clone(),
                        entity_type: format!("{}", dest.entity_type),
                    });
                }
            }
        }
        if let Some(sources) = self.reverse_adj.get(&sid) {
            for &source_sid in sources {
                if let Some(src) = self.entities.get(&source_sid) {
                    *neighbor_types
                        .entry(format!("{}", src.entity_type))
                        .or_default() += 1;
                    if seen.insert(source_sid) && neighbors.len() < MAX_NEIGHBORS_RETURNED {
                        neighbors.push(NeighborSummary {
                            id: src.id.clone(),
                            entity_type: format!("{}", src.entity_type),
                        });
                    }
                }
            }
        }

        Some(NodeDetails {
            id: entity.id.clone(),
            entity_type: format!("{}", entity.entity_type),
            score: entity.score,
            degree_score: entity.degree_score,
            betweenness: entity.betweenness,
            pagerank_score: entity.pagerank_score,
            metadata: entity.metadata.clone(),
            in_degree,
            out_degree,
            time_range: if has_timestamps {
                Some((min_ts, max_ts))
            } else {
                None
            },
            neighbor_types,
            neighbors,
        })
    }

    /// Returns a summary of the entire graph.
    pub fn get_graph_summary(&self) -> GraphSummary {
        let mut type_distribution: Vec<TypeDistribution> = self
            .type_index
            .iter()
            .map(|(et, ids)| TypeDistribution {
                entity_type: format!("{}", et),
                count: ids.len(),
            })
            .collect();
        type_distribution.sort_by(|a, b| b.count.cmp(&a.count));

        let mut min_ts = i64::MAX;
        let mut max_ts = i64::MIN;
        let mut has_timestamps = false;

        // Sample edges for time range instead of scanning all millions
        let mut edges_scanned = 0usize;
        for compact in self.edge_store.iter_all() {
            if compact.timestamp != 0 {
                min_ts = min_ts.min(compact.timestamp);
                max_ts = max_ts.max(compact.timestamp);
                has_timestamps = true;
            }
            edges_scanned += 1;
            if edges_scanned >= 100_000 { break; }
        }

        let mut entities_by_score: Vec<_> = self.entities.values().collect();
        entities_by_score.sort_by(|a, b| b.score.partial_cmp(&a.score).unwrap_or(std::cmp::Ordering::Equal));
        let top_anomalies: Vec<TopAnomaly> = entities_by_score
            .into_iter()
            .take(10)
            .filter(|e| e.score > 0.0)
            .map(|e| TopAnomaly {
                id: e.id.clone(),
                entity_type: format!("{}", e.entity_type),
                score: e.score,
            })
            .collect();

        GraphSummary {
            entity_count: self.entity_count(),
            relation_count: self.relation_count(),
            type_distribution,
            time_range: if has_timestamps {
                Some((min_ts, max_ts))
            } else {
                None
            },
            top_anomalies,
        }
    }

    /// Scores, filters, sorts, and paginates hunt result paths.
    pub fn score_and_paginate_paths(
        &self,
        paths: &[Vec<String>],
        page: usize,
        page_size: usize,
        min_score: Option<f64>,
    ) -> (Vec<ScoredPath>, usize) {
        let has_anomaly = self.anomaly_scorer.as_ref().is_some_and(|s| s.is_finalized());

        // Phase 1: lightweight scoring
        let mut lightweight: Vec<(usize, f64, f64, f64)> = paths
            .iter()
            .enumerate()
            .map(|(idx, path)| {
                let mut max_score: f64 = 0.0;
                let mut total_score: f64 = 0.0;
                for node_id in path {
                    if let Some(entity) = self.get_entity(node_id) {
                        let s = entity.score;
                        if s > max_score {
                            max_score = s;
                        }
                        total_score += s;
                    }
                }
                let anomaly = if has_anomaly {
                    self.anomaly_scorer.as_ref().unwrap().score_path(path, self).0
                } else {
                    0.0
                };
                (idx, max_score, total_score, anomaly)
            })
            .collect();

        // Phase 2: filter
        if let Some(threshold) = min_score {
            lightweight.retain(|&(_, ms, _, _)| ms >= threshold);
        }
        let filtered_count = lightweight.len();

        // Phase 3: sort
        lightweight.sort_unstable_by(|a, b| {
            if has_anomaly {
                b.3.partial_cmp(&a.3)
                    .unwrap_or(std::cmp::Ordering::Equal)
                    .then_with(|| {
                        b.1.partial_cmp(&a.1)
                            .unwrap_or(std::cmp::Ordering::Equal)
                    })
                    .then_with(|| {
                        b.2.partial_cmp(&a.2)
                            .unwrap_or(std::cmp::Ordering::Equal)
                    })
            } else {
                b.1.partial_cmp(&a.1)
                    .unwrap_or(std::cmp::Ordering::Equal)
                    .then_with(|| {
                        b.2.partial_cmp(&a.2)
                            .unwrap_or(std::cmp::Ordering::Equal)
                    })
            }
        });

        // Phase 4: build ScoredPath for page
        let start = page * page_size;
        let page_items = if start >= lightweight.len() {
            Vec::new()
        } else {
            let end = (start + page_size).min(lightweight.len());
            lightweight[start..end]
                .iter()
                .map(|&(idx, max_score, total_score, _)| {
                    let path = &paths[idx];
                    let mut time_start = i64::MAX;
                    let mut time_end = i64::MIN;
                    let mut labels: Vec<String> = Vec::new();

                    for node_id in path {
                        if let Some(_entity) = self.get_entity(node_id) {
                            let short = if let Some(pos) = node_id.rfind('\\') {
                                &node_id[pos + 1..]
                            } else if node_id.len() > 20 {
                                &node_id[node_id.len() - 20..]
                            } else {
                                node_id.as_str()
                            };
                            labels.push(short.to_string());
                        }
                    }

                    for i in 0..path.len().saturating_sub(1) {
                        // Use compact relations to avoid materializing full Relation objects
                        let dest_sid = self.interner.get(&path[i + 1]);
                        for compact in self.get_compact_relations(&path[i]) {
                            if Some(compact.dest_sid) == dest_sid && compact.timestamp != 0 {
                                if compact.timestamp < time_start {
                                    time_start = compact.timestamp;
                                }
                                if compact.timestamp > time_end {
                                    time_end = compact.timestamp;
                                }
                            }
                        }
                    }

                    if time_start == i64::MAX { time_start = 0; }
                    if time_end == i64::MIN { time_end = 0; }

                    let (anomaly_score, anomaly_breakdown) = if has_anomaly {
                        let (score, breakdown) = self.anomaly_scorer.as_ref().unwrap().score_path(path, self);
                        (Some(score), Some(breakdown))
                    } else {
                        (None, None)
                    };

                    ScoredPath {
                        path: path.clone(),
                        max_score,
                        total_score,
                        time_start,
                        time_end,
                        chain_summary: labels.join(" -> "),
                        anomaly_score,
                        anomaly_breakdown,
                    }
                })
                .collect()
        };

        (page_items, filtered_count)
    }
}
