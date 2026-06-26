use std::collections::{HashMap, HashSet, VecDeque};

use serde::{Deserialize, Serialize};

use crate::anomaly::ScoreBreakdown;
use crate::config;
use crate::graph::GraphHunter;
use crate::interner::StrId;
use crate::types::{EntityType, RelationType};

/// Combined in_degree + out_degree above which a plain `expand_node` call
/// would produce an unwieldy response (and, at extreme degrees, timeout).
/// Callers above this threshold should either switch to `get_neighborhood_grouped`
/// or, in the command layer, silently auto-fall-back to grouped expansion
/// and flag the response.
pub const AUTO_GROUPED_THRESHOLD: usize = 50;

/// One hop in a path returned by [`GraphHunter::find_paths`]. `edge` is the
/// relation type taken INTO this node; the first hop of a path (the origin)
/// has `edge: None`.
#[derive(Serialize, Clone, Debug)]
pub struct PathHop {
    pub node_id: String,
    pub node_class: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub edge: Option<String>,
}

/// A structurally anomalous entity surfaced by [`GraphHunter::structural_anomalies`].
#[derive(Serialize, Clone, Debug)]
pub struct AnomalyHit {
    pub node_id: String,
    pub node_class: String,
    /// `degree` | `betweenness` | `isolation`.
    pub metric: String,
    /// Raw metric value (the per-entity score the z-score is computed from).
    pub value: f64,
    /// Standard scores above the population (optionally class-scoped) mean.
    pub z_score: f64,
    pub observation: String,
}

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

/// Reports the result of live-source hydration performed before an
/// expansion. Attached to `Neighborhood` when an expand ran with the
/// live flag. `skipped=true` with a `reason` means hydration could not
/// run (non-Sentinel session, missing creds, unmapped entity type).
#[derive(Serialize, Clone, Debug)]
pub struct HydrationOutcome {
    pub skipped: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    pub new_entities: usize,
    pub new_relations: usize,
    pub tables_hit: usize,
    pub tables_attempted: usize,
}

#[derive(Serialize, Clone, Debug)]
pub struct Neighborhood {
    pub center: String,
    pub nodes: Vec<NeighborNode>,
    pub edges: Vec<NeighborEdge>,
    pub truncated: bool,
    /// Set when the command layer auto-routed this expansion through
    /// `get_neighborhood_grouped` because the node's degree exceeded
    /// `AUTO_GROUPED_THRESHOLD`. When true, each edge in `edges` represents
    /// a collapsed group — see the edge metadata keys `edge_count`,
    /// `first_ts`, `last_ts` — and `auto_group_reason` explains why.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub auto_grouped: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub auto_group_reason: Option<String>,
    /// Present when this expansion ran with live hydration (Enfoque A).
    /// See `HydrationOutcome`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hydration: Option<HydrationOutcome>,
}

/// A grouped edge that collapses N edges sharing the same source,
/// rel_type, and target *entity type*. The individual target IDs are
/// preserved in `targets` so the UI can drill in without a second round
/// trip. Grouping by (source, rel_type, target_entity_type) is what lets
/// a node whose 64 targets are all unique strings (action/INFO logs) still
/// collapse into a single summary row — the original (source, target,
/// rel_type) key never grouped when targets were unique.
///
/// `target` is retained for back-compat: when the group covers exactly one
/// target, it holds that target's id; otherwise it's a synthetic label of
/// the form `"{target_entity_type} (×N)"` so legacy clients that display
/// `target` still render something sensible.
#[derive(Serialize, Clone, Debug)]
pub struct GroupedNeighborEdge {
    pub source: String,
    pub target: String,
    pub rel_type: String,
    pub count: usize,
    pub first_ts: i64,
    pub last_ts: i64,
    /// Entity type of every target in this group. Populated when grouping
    /// collapses across multiple unique target ids.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target_entity_type: Option<String>,
    /// Up to 20 sample target ids drawn from the group. Keeps the payload
    /// bounded while still giving the UI concrete ids to show.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub targets: Vec<String>,
}

/// Neighborhood with grouped edges for high-degree nodes.
#[derive(Serialize, Clone, Debug)]
pub struct GroupedNeighborhood {
    pub center: String,
    pub nodes: Vec<NeighborNode>,
    pub edges: Vec<GroupedNeighborEdge>,
    pub truncated: bool,
    pub total_edge_count: usize,
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
    /// True when `in_degree + out_degree > AUTO_GROUPED_THRESHOLD`. Surfaces
    /// to the UI as a hint that plain `expand_node` will return an unwieldy
    /// fanout; `expand_node_grouped` is the better call for this node.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub recommend_grouped_expansion: bool,
    /// Four-dimension anomaly breakdown (entity rarity / edge rarity /
    /// neighborhood concentration / temporal novelty). Populated only when
    /// anomaly scoring is enabled and finalized — `None` otherwise.
    ///
    /// The feedback pointed out that the scoring doc promises this breakdown
    /// but `get_node_details` never returned it. This closes the gap.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub anomaly_breakdown: Option<ScoreBreakdown>,
}

/// Detailed score explanation for a single node. Returned by `explain_score`.
#[derive(Serialize, Clone, Debug)]
pub struct ExplainedScore {
    pub id: String,
    pub entity_type: String,
    pub composite_score: f64,
    pub degree_score: f64,
    pub pagerank_score: f64,
    pub betweenness: f64,
    /// Rarity score [0, 100]: inverted degree. A hot public asset
    /// (logo, CDN edge) sits near 0; a rarely-touched endpoint (one
    /// IP reads it once) sits near 100. The hunt-oriented signal.
    #[serde(default)]
    pub rarity_score: f64,
    /// Four-dimension anomaly breakdown if anomaly scoring is active.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub anomaly_breakdown: Option<ScoreBreakdown>,
    /// Percentile rank (0-100) of `composite_score` against all entities in
    /// the graph. 100 = tied for top; 0 = bottom of the pack.
    pub composite_percentile: f64,
    /// Percentile rank of `degree_score` across all entities.
    pub degree_percentile: f64,
    /// Percentile rank of `rarity_score` across all entities.
    #[serde(default)]
    pub rarity_percentile: f64,
    /// Top-5 peers (by composite score) of the same entity type, so the
    /// analyst can see whether this node is a legitimate outlier or a
    /// member of a cohort that all scored high (the `/usr/bin/grep` case
    /// — "high degree is structural, not anomalous").
    pub peers: Vec<ExplainedPeer>,
    /// Narrative sentence combining the above for quick consumption.
    pub narrative: String,
}

#[derive(Serialize, Clone, Debug)]
pub struct ExplainedPeer {
    pub id: String,
    pub composite_score: f64,
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

/// One row of the relation schema: a distinct (rel_type, source_type, target_type)
/// triple observed in the graph, with its edge count and the union of metadata keys
/// seen on any edge in the group.
#[derive(Serialize, Clone, Debug)]
pub struct RelSchemaEntry {
    pub rel_type: String,
    pub source_type: String,
    pub target_type: String,
    pub edge_count: usize,
    pub metadata_keys: Vec<String>,
}

/// Result of `diff_hunts` — compare the hunt result set at two points in
/// time and return what appeared / disappeared. "Snapshot" here is
/// purely a time-bound on the existing graph; no separate session file
/// is required. Paths are identified by their node sequence.
#[derive(Serialize, Clone, Debug)]
pub struct HuntDiff {
    /// Upper time bound for the baseline hunt (inclusive).
    pub baseline_ts: i64,
    /// Upper time bound for the current hunt (inclusive).
    pub current_ts: i64,
    /// Total deduped path count in the baseline.
    pub baseline_count: usize,
    /// Total deduped path count in the current snapshot.
    pub current_count: usize,
    /// Paths present in `current` but not in `baseline` — the newly-
    /// surfaced activity between the two timestamps.
    pub added: Vec<ScoredPath>,
    /// Paths present in `baseline` but not in `current`. Usually empty
    /// for monotonic append-only ingest; non-empty when an upstream
    /// truncation happened between the two bounds.
    pub removed: Vec<ScoredPath>,
}

/// Why a hunt returned zero paths — returned from `hunt_diagnostic` and
/// attached to the `HuntResults` response so the analyst doesn't have to
/// guess whether the pattern was impossible, direction-inverted, or just
/// temporally filtered out.
#[derive(Serialize, Clone, Debug)]
pub struct HuntDiagnostic {
    /// Index of the step where the DFS would run out of matches.
    pub failed_step_index: usize,
    /// Human-readable reason.
    pub reason: String,
    /// If set, the analyst can almost certainly fix the hunt by copy-pasting this.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub suggestion: Option<String>,
    /// How many candidate starts would have matched the *first* step alone.
    /// Zero here means the hypothesis asks for entity/rel types that the
    /// dataset simply doesn't contain.
    pub first_step_matches: usize,
}

/// Metadata surfaced when hunting during post-finalize live-tail ingest.
#[derive(Serialize, Clone, Debug, Default)]
pub struct LiveTailCoverage {
    pub phase: String,
    pub tail_edge_count: u64,
    pub index_coverage: f64,
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
    /// How many raw paths collapsed into this row when dedup was active.
    /// 1 for DedupMode::None. Matters because 1835 identical paths that
    /// all scored 100 used to drown out the single genuinely interesting
    /// path at page 91 — dedup surfaces the interesting one at page 1
    /// and records the 1835 as a count here.
    pub edge_count: usize,
    /// Dataset IDs that contributed at least one edge to this path. Powers
    /// the provenance badges in the hunt-results UI: an analyst can see
    /// at a glance whether a finding is cross-dataset, and click through
    /// to the source dataset card.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub datasets_used: Vec<String>,
}

/// How `score_and_paginate_paths` collapses identical or related paths.
#[derive(serde::Serialize, serde::Deserialize, Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum DedupMode {
    /// Every raw path shows up as its own row. Old behavior; use only when
    /// you genuinely need to inspect duplicates.
    None,
    /// Group by the full node sequence — 1835 `(root, /usr/bin/grep)` paths
    /// collapse to one row with `edge_count=1835`.
    #[default]
    ByPath,
    /// Group by `(first, last)` only. Useful for long chains where the
    /// intermediate hops differ slightly but the endpoints are what the
    /// analyst actually cares about.
    ByEndpoints,
}

// ── Standalone helpers for explain_score ──

/// Percentile of `x` in the population `xs`. 100 = top, 0 = bottom.
/// Uses "percent of values strictly less than x" + half of ties, which
/// matches the semantics most analysts expect.
fn percentile_of(xs: &[f64], x: f64) -> f64 {
    if xs.is_empty() {
        return 0.0;
    }
    let n = xs.len() as f64;
    let below = xs.iter().filter(|&&v| v < x).count() as f64;
    let equal = xs.iter().filter(|&&v| v == x).count() as f64;
    (100.0 * (below + equal / 2.0) / n).clamp(0.0, 100.0)
}

fn build_narrative(
    composite: f64,
    composite_pct: f64,
    degree_pct: f64,
    rarity_pct: f64,
    rarity: f64,
    pagerank: f64,
    breakdown: Option<&ScoreBreakdown>,
    peer_ids: String,
) -> String {
    let mut parts = Vec::new();
    parts.push(format!(
        "Composite score {:.1} (percentile {:.1} of all entities).",
        composite, composite_pct
    ));
    parts.push(format!(
        "Rarity {:.1} (percentile {:.1}) — higher = touched by fewer edges.",
        rarity, rarity_pct
    ));
    parts.push(format!("Degree centrality percentile {:.1}.", degree_pct));
    if pagerank > 10.0 {
        parts.push(format!(
            "PageRank {:.2} indicates this node is structurally central.",
            pagerank
        ));
    }
    // Call out the "hot asset" case explicitly: very high degree + very
    // low rarity means a node that's heavily accessed but uninteresting
    // for a threat hunt (logos, CDN edges, common DNS servers).
    if degree_pct > 95.0 && rarity_pct < 20.0 {
        parts.push(
            "High degree + low rarity: this node is a hot, widely-used asset — likely infrastructure, not an anomaly.".into(),
        );
    }
    if let Some(b) = breakdown {
        if b.temporal_novelty < 0.1 && composite_pct > 90.0 {
            parts.push(
                "Temporal novelty is near zero — this node was present throughout the window, so the high score is centrality, not anomaly.".into(),
            );
        } else if b.entity_rarity > 0.7 || b.edge_rarity > 0.7 {
            parts.push(format!(
                "High anomaly contribution: entity_rarity={:.2}, edge_rarity={:.2}, temporal_novelty={:.2}.",
                b.entity_rarity, b.edge_rarity, b.temporal_novelty
            ));
        }
    }
    if !peer_ids.is_empty() {
        parts.push(format!("Top peers of the same type: {}.", peer_ids));
    }
    parts.join(" ")
}

// ── channel_behavior projection ──

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChannelSortBy {
    Beacon,
    Resets,
    Volume,
}

#[derive(Debug, Clone)]
pub struct ChannelBehaviorOpts {
    pub top_n: usize,
    pub min_count: Option<usize>,
    pub window_secs: u64,
    pub rel_type: Option<String>,
    pub sort_by: ChannelSortBy,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct ChannelBehavior {
    pub source: String,
    pub target: String,
    pub rel_type: String,
    pub count: usize,
    pub first_ts: i64,
    pub last_ts: i64,
    pub interval_mean_secs: f64,
    /// Coefficient of variation of inter-arrival intervals (population stddev / mean).
    /// 0.0 when count < 3 (not enough data) or when mean == 0 — indistinguishable
    /// from a genuine zero-variance result; pair with `count` to disambiguate.
    pub interval_cv: f64,
    pub beacon_score: f64,
    pub max_resets_in_window: usize,
    pub max_bytes_in_window: u64,
    pub max_count_in_window: usize,
}

// ── heavy_edges projection ──

#[derive(Debug, Clone, serde::Serialize)]
pub struct HeavyEdge {
    pub source: String,
    pub target: String,
    pub rel_type: String,
    pub count: usize,
    pub total_bytes: u64,
    pub total_duration_secs: u64,
    pub reset_pct: f64,
    pub first_ts: i64,
    pub last_ts: i64,
}

#[derive(Debug, Clone)]
pub struct HeavyEdgesOpts {
    pub top_n: usize,
    pub min_count: Option<usize>,
    pub rel_type: Option<String>,
}

// ── Implementations on GraphHunter ──

impl GraphHunter {
    /// Searches entities by substring match on ID (case-insensitive).
    ///
    /// When `query` is empty, acts as a list-mode: returns the top-N entities
    /// (filtered by `type_filter` if given) ordered by score descending. This
    /// lets analysts enumerate a small entity type without inventing a dummy
    /// query like `"."`, which used to be the only workaround.
    pub fn search_entities(
        &self,
        query: &str,
        type_filter: Option<&EntityType>,
        limit: usize,
    ) -> Vec<SearchResult> {
        let query_lower = query.to_lowercase();
        let list_mode = query.is_empty();

        // If type_filter is specified, use type_index for fast lookup
        let candidate_sids: Vec<StrId> = match type_filter {
            Some(et) => {
                if let Some(ids) = self.type_index.get(et) {
                    ids.iter().copied().collect()
                } else {
                    return Vec::new();
                }
            }
            None => self.entities.keys().copied().collect(),
        };

        // Collect matching results without the `limit` cap first; apply
        // the cap after sorting so list-mode returns the *top* N by score,
        // not an arbitrary N by HashMap iteration order.
        let mut results: Vec<SearchResult> = Vec::new();
        for sid in candidate_sids {
            let matches = list_mode || {
                let id_str = self.interner.resolve(sid);
                id_str.to_lowercase().contains(&query_lower)
            };
            if !matches {
                continue;
            }
            if let Some(entity) = self.entities.get(&sid) {
                let out_degree = self.streaming.degree_of(sid);
                let in_degree = self.reverse_adj.get(&sid).map(|v| v.len()).unwrap_or(0);
                results.push(SearchResult {
                    id: entity.id.clone(),
                    entity_type: format!("{}", entity.entity_type),
                    score: entity.score,
                    connections: out_degree + in_degree,
                });
            }
        }

        if list_mode {
            // Sort by score desc, tiebreak on connections desc so the most
            // central nodes surface first in an enumeration.
            results.sort_by(|a, b| {
                b.score
                    .partial_cmp(&a.score)
                    .unwrap_or(std::cmp::Ordering::Equal)
                    .then(b.connections.cmp(&a.connections))
            });
        }
        results.truncate(limit);
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
        let max_edges = max_nodes * config::NEIGHBORHOOD_EDGE_RATIO;

        visited.insert(center_sid);
        queue.push_back((center_sid, 0));
        node_sids.push(center_sid);

        while let Some((current_sid, depth)) = queue.pop_front() {
            if depth >= max_hops {
                continue;
            }

            // Outgoing edges
            if let Some(arc) = self.streaming.neighbors_arc(current_sid) {
                let g = arc.read();
                for edge in g.as_slice() {
                    if edges.len() >= max_edges {
                        truncated = true;
                        break;
                    }
                    let dest_sid = edge.dest_sid;
                    let dest_id_str = self.interner.resolve(dest_sid);

                    if let Some(f) = filter {
                        if let Some(ref rel_types) = f.relation_types {
                            if !rel_types
                                .iter()
                                .any(|rt| rt.to_u8() == edge.rel_type_tag)
                            {
                                continue;
                            }
                        }
                        if let Some(start) = f.time_start {
                            if edge.timestamp < start {
                                continue;
                            }
                        }
                        if let Some(end) = f.time_end {
                            if edge.timestamp > end {
                                continue;
                            }
                        }
                        if let Some(ref entity_types) = f.entity_types {
                            if let Some(entity) = self.entities.get(&dest_sid) {
                                if !entity_types.contains(&entity.entity_type) {
                                    continue;
                                }
                            }
                        }
                        if let Some(min_score) = f.min_score {
                            if let Some(entity) = self.entities.get(&dest_sid) {
                                if entity.score < min_score {
                                    continue;
                                }
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
                        let mut meta = self.meta_store.get(edge.metadata_offset);
                        meta.remove("_rel_type");
                        edges.push(NeighborEdge {
                            source: self.interner.resolve(edge.source_sid).to_string(),
                            target: dest_id_str.to_string(),
                            rel_type: self.resolve_rel_type_name_raw(
                                edge.rel_type_tag,
                                edge.metadata_offset,
                            ),
                            timestamp: edge.timestamp,
                            metadata: meta,
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
                    if let Some(arc) = self.streaming.neighbors_arc(source_sid) {
                        let g = arc.read();
                        for edge in g.as_slice() {
                            if edges.len() >= max_edges {
                                truncated = true;
                                break;
                            }
                            if edge.dest_sid != current_sid {
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
                                let mut meta = self.meta_store.get(edge.metadata_offset);
                                meta.remove("_rel_type");
                                edges.push(NeighborEdge {
                                    source: self.interner.resolve(edge.source_sid).to_string(),
                                    target: self.interner.resolve(edge.dest_sid).to_string(),
                                    rel_type: self.resolve_rel_type_name_raw(
                                        edge.rel_type_tag,
                                        edge.metadata_offset,
                                    ),
                                    timestamp: edge.timestamp,
                                    metadata: meta,
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
            auto_grouped: false,
            auto_group_reason: None,
            hydration: None,
        })
    }

    /// BFS-based neighborhood with grouped edges.
    /// Collapses N edges of the same (source, target, rel_type) into a single
    /// summary edge with count and time range. Useful for high-degree nodes.
    pub fn get_neighborhood_grouped(
        &self,
        center: &str,
        max_hops: usize,
        max_nodes: usize,
        filter: Option<&NeighborhoodFilter>,
    ) -> Option<GroupedNeighborhood> {
        let neighborhood = self.get_neighborhood(center, max_hops, max_nodes, filter)?;

        // Build a target_id → entity_type lookup so we can group by target type.
        let type_of: HashMap<&str, &str> = neighborhood
            .nodes
            .iter()
            .map(|n| (n.id.as_str(), n.entity_type.as_str()))
            .collect();

        // Group edges by (source, rel_type, target_entity_type). This is
        // the key that actually collapses: unique target ids (64 distinct
        // action strings from one INFO source) all share the same type,
        // so they merge into one summary row instead of 64 count=1 rows.
        const SAMPLE_TARGETS_CAP: usize = 20;
        #[derive(Default)]
        struct GroupAgg {
            count: usize,
            first_ts: i64,
            last_ts: i64,
            targets: Vec<String>,
            seen: HashSet<String>,
        }
        let mut groups: HashMap<(String, String, String), GroupAgg> = HashMap::new();
        let total_edge_count = neighborhood.edges.len();

        for edge in &neighborhood.edges {
            let target_type = type_of
                .get(edge.target.as_str())
                .copied()
                .unwrap_or("Unknown")
                .to_string();
            let key = (edge.source.clone(), edge.rel_type.clone(), target_type);
            let entry = groups.entry(key).or_insert_with(|| GroupAgg {
                count: 0,
                first_ts: i64::MAX,
                last_ts: i64::MIN,
                targets: Vec::new(),
                seen: HashSet::new(),
            });
            entry.count += 1;
            if edge.timestamp < entry.first_ts {
                entry.first_ts = edge.timestamp;
            }
            if edge.timestamp > entry.last_ts {
                entry.last_ts = edge.timestamp;
            }
            if entry.seen.insert(edge.target.clone()) && entry.targets.len() < SAMPLE_TARGETS_CAP {
                entry.targets.push(edge.target.clone());
            }
        }

        let grouped_edges: Vec<GroupedNeighborEdge> = groups
            .into_iter()
            .map(|((source, rel_type, target_type), agg)| {
                let distinct_targets = agg.seen.len();
                // Back-compat: `target` holds the single id when the group
                // covers exactly one, else a synthetic "{Type} (×N)" label.
                let target_field = if distinct_targets == 1 {
                    agg.targets.first().cloned().unwrap_or_default()
                } else {
                    format!("{} (×{})", target_type, distinct_targets)
                };
                GroupedNeighborEdge {
                    source,
                    target: target_field,
                    rel_type,
                    count: agg.count,
                    first_ts: if agg.first_ts == i64::MAX {
                        0
                    } else {
                        agg.first_ts
                    },
                    last_ts: if agg.last_ts == i64::MIN {
                        0
                    } else {
                        agg.last_ts
                    },
                    target_entity_type: Some(target_type),
                    targets: agg.targets,
                }
            })
            .collect();

        Some(GroupedNeighborhood {
            center: neighborhood.center,
            nodes: neighborhood.nodes,
            edges: grouped_edges,
            truncated: neighborhood.truncated,
            total_edge_count,
        })
    }

    /// Computes degree centrality **and** entity rarity scores for all
    /// entities in a single pass over `edge_store` + `reverse_adj`.
    ///
    /// `degree_score` is `(deg / max_deg) * 100` — high for hubs.
    /// `rarity_score` is `(1 - ln(deg + 1) / ln(max_deg + 1)) * 100` —
    /// high for rarely-touched nodes. Entities with zero edges get the
    /// maximum rarity (100); the `+1` inside the log avoids `ln(0)`
    /// without biasing the ordering between degree=1 and degree=2.
    pub fn compute_scores(&mut self) {
        if self.entities.is_empty() {
            return;
        }

        let mut degrees: HashMap<StrId, usize> = HashMap::new();
        let mut max_degree: usize = 0;

        for &sid in self.entities.keys() {
            let out_deg = self.streaming.degree_of(sid);
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

        let log_max = ((max_degree + 1) as f64).ln();
        for (&sid, entity) in &mut self.entities {
            let deg = degrees.get(&sid).copied().unwrap_or(0);
            let degree_norm = (deg as f64 / max_degree as f64) * 100.0;
            entity.score = degree_norm;
            entity.degree_score = degree_norm;
            let rarity = if log_max > 0.0 {
                (1.0 - ((deg + 1) as f64).ln() / log_max) * 100.0
            } else {
                0.0
            };
            entity.rarity_score = rarity.clamp(0.0, 100.0);
        }
    }

    /// Computes betweenness centrality using Brandes' algorithm.
    pub fn compute_betweenness(&mut self, sample_limit: Option<usize>) {
        let n = self.entities.len();
        if n < 2 {
            return;
        }

        let sids: Vec<StrId> = self.entities.keys().copied().collect();
        let sid_to_idx: HashMap<StrId, usize> =
            sids.iter().enumerate().map(|(i, &sid)| (sid, i)).collect();
        let mut cb = vec![0.0f64; n];

        let limit = sample_limit.unwrap_or(config::DEFAULT_BETWEENNESS_SAMPLE);
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
                if let Some(arc) = self.streaming.neighbors_arc(v_sid) {
                    let g = arc.read();
                    for edge in g.as_slice() {
                        if let Some(&w) = sid_to_idx.get(&edge.dest_sid) {
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

        let lambda = lambda.unwrap_or(config::DEFAULT_PAGERANK_LAMBDA);
        let d = damping.unwrap_or(config::DEFAULT_PAGERANK_DAMPING);
        let max_iter = max_iter.unwrap_or(config::DEFAULT_PAGERANK_MAX_ITER);
        let eps = epsilon.unwrap_or(config::DEFAULT_PAGERANK_EPSILON);

        let t_ref = reference_time.unwrap_or_else(|| {
            let mut max_t = 0i64;
            self.streaming.for_each_edge(|_src, edge| {
                if edge.timestamp > max_t {
                    max_t = edge.timestamp;
                }
            });
            max_t
        });

        let sids: Vec<StrId> = self.entities.keys().copied().collect();
        let sid_to_idx: HashMap<StrId, usize> =
            sids.iter().enumerate().map(|(i, &sid)| (sid, i)).collect();

        let mut w_out = vec![0.0f64; n];
        let mut weighted_edges: Vec<(usize, usize, f64)> = Vec::new();

        self.streaming.for_each_edge(|src_sid, edge| {
            if let (Some(&src_idx), Some(&dst_idx)) = (
                sid_to_idx.get(&src_sid),
                sid_to_idx.get(&edge.dest_sid),
            ) {
                let dt = (t_ref - edge.timestamp).max(0) as f64;
                let w = (-lambda * dt).exp();
                w_out[src_idx] += w;
                weighted_edges.push((src_idx, dst_idx, w));
            }
        });

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

            let diff: f64 = pr
                .iter()
                .zip(pr_new.iter())
                .map(|(a, b)| (a - b).abs())
                .sum();
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

    /// Composite scoring from weighted combination of degree, pagerank,
    /// betweenness, and rarity. The first three are centrality metrics
    /// (high = hub/bridge); `rarity_weight` is the inverted-degree
    /// signal that threat hunting wants (high = rarely touched). For
    /// pure-hunt workloads call with `(0.0, 0.0, 0.0, 1.0)` to rank by
    /// rarity alone; for balanced "what's interesting" use
    /// [`Self::compute_composite_score_hunt_default`] which blends
    /// rarity-dominant plus small centrality sprinkles.
    pub fn compute_composite_score(
        &mut self,
        degree_w: f64,
        pagerank_w: f64,
        betweenness_w: f64,
        rarity_w: f64,
    ) {
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
                    + betweenness_w * e.betweenness
                    + rarity_w * e.rarity_score;
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

    /// Hunt-oriented default: rarity gets the lion's share of the weight;
    /// centrality metrics contribute a small factor so genuine bridge
    /// nodes don't get buried under the rarity floor. Use this when
    /// ingest-time scoring needs a single sensible call that favours
    /// threat-hunt-relevant ranking over hub-centric centrality.
    pub fn compute_composite_score_hunt_default(&mut self) {
        self.compute_composite_score(0.1, 0.1, 0.1, 1.0);
    }

    /// Returns detailed information about a specific node.
    pub fn get_node_details(&self, node_id: &str) -> Option<NodeDetails> {
        let sid = self.interner.get(node_id)?;
        let entity = self.entities.get(&sid)?;

        // Tail-aware degree: `degree_of` reads BOTH the per-vertex base
        // neighbor list AND the post-finalize tail buffer. The previous
        // `out_edges.len()` path via `neighbors_arc` was base-only and
        // silently dropped every edge appended after the first finalize
        // (e.g. ingest of a second/third dataset in the same session).
        let out_degree = self.streaming.degree_of(sid);
        // `reverse_adj` is updated on every `add_relation` (including
        // post-finalize appends — see graph.rs:463 C3a ordering), so it
        // is already tail-aware by construction.
        let in_degree = self.reverse_adj.get(&sid).map(|v| v.len()).unwrap_or(0);

        let mut min_ts = i64::MAX;
        let mut max_ts = i64::MIN;
        let mut has_timestamps = false;

        let mut neighbor_types: HashMap<String, usize> = HashMap::new();
        let mut seen: HashSet<StrId> = HashSet::new();
        let mut neighbors: Vec<NeighborSummary> = Vec::new();

        // Outgoing pass: chain base + tail under a single lock acquisition.
        //
        // Cap iteration to avoid stalling on extremely high-degree nodes
        // (1M+ edges). The neighbors list is also capped at
        // MAX_NEIGHBORS_RETURNED. neighbor_types counts UNIQUE destination
        // entity_types (gated by `seen`) — previously the count incremented
        // per-edge, so a hub with N edges to a single neighbor reported
        // N for that type (capped at MAX_SCAN_EDGES). The fix collapses
        // to per-unique-neighbor, matching the intended semantics: "how
        // many neighbors of each type does this node have?".
        self.streaming.with_neighbors_and_tail(sid, |base, tail| {
            let mut scanned = 0usize;
            for edge in base.iter().chain(tail.iter()) {
                if scanned >= config::MAX_SCAN_EDGES {
                    break;
                }
                scanned += 1;
                if edge.timestamp != 0 {
                    min_ts = min_ts.min(edge.timestamp);
                    max_ts = max_ts.max(edge.timestamp);
                    has_timestamps = true;
                }
                if let Some(dest) = self.entities.get(&edge.dest_sid) {
                    // Count + push only on the first sighting of this
                    // distinct destination. neighbor_types is a unique-
                    // neighbor-by-type histogram, NOT an edge-count
                    // histogram. (Fan-out info lives in `out_degree`.)
                    if seen.insert(edge.dest_sid) {
                        *neighbor_types
                            .entry(format!("{}", dest.entity_type))
                            .or_default() += 1;
                        if neighbors.len() < config::MAX_NEIGHBORS_RETURNED {
                            neighbors.push(NeighborSummary {
                                id: dest.id.clone(),
                                entity_type: format!("{}", dest.entity_type),
                            });
                        }
                    }
                }
            }
        });

        // Incoming pass: walk reverse_adj (already tail-aware). Same
        // unique-by-source semantics as the outgoing pass. For timestamp
        // discovery we look up the source's outgoing edges via the
        // tail-aware helper and find the first edge that lands on us;
        // any single timestamp suffices to extend the min/max range.
        if let Some(sources) = self.reverse_adj.get(&sid) {
            let mut scanned = 0usize;
            for &source_sid in sources.iter() {
                if scanned >= config::MAX_SCAN_EDGES {
                    break;
                }
                scanned += 1;
                let Some(src_entity) = self.entities.get(&source_sid) else {
                    continue;
                };
                // Unique-by-source: skip if we've already counted this
                // source (e.g. same source sent multiple edges to us).
                if !seen.insert(source_sid) {
                    continue;
                }
                *neighbor_types
                    .entry(format!("{}", src_entity.entity_type))
                    .or_default() += 1;
                if neighbors.len() < config::MAX_NEIGHBORS_RETURNED {
                    neighbors.push(NeighborSummary {
                        id: src_entity.id.clone(),
                        entity_type: format!("{}", src_entity.entity_type),
                    });
                }
                // Sample a timestamp from this source's outgoing edges
                // (base + tail) for the time_range computation.
                self.streaming
                    .with_neighbors_and_tail(source_sid, |base, tail| {
                        for edge in base.iter().chain(tail.iter()) {
                            if edge.dest_sid == sid && edge.timestamp != 0 {
                                min_ts = min_ts.min(edge.timestamp);
                                max_ts = max_ts.max(edge.timestamp);
                                has_timestamps = true;
                                break;
                            }
                        }
                    });
            }
        }

        let anomaly_breakdown = self
            .anomaly_scorer
            .as_ref()
            .filter(|s| s.is_finalized())
            .map(|s| {
                // Scorer averages over path; a single-node path gives back
                // exactly this node's per-dimension contributions.
                s.score_path(std::slice::from_ref(&entity.id), self).1
            });

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
            recommend_grouped_expansion: in_degree + out_degree > AUTO_GROUPED_THRESHOLD,
            anomaly_breakdown,
        })
    }

    /// Detailed explanation for why a node has its score: the four-dimension
    /// breakdown, percentiles against the whole graph, and a peers list so
    /// the analyst can see whether they're looking at an outlier or a
    /// legitimate centrality pillar like `/usr/bin/grep` under MDE agent.
    pub fn explain_score(&self, node_id: &str) -> Option<ExplainedScore> {
        let sid = self.interner.get(node_id)?;
        let entity = self.entities.get(&sid)?.clone();

        // Percentiles
        let all_scores: Vec<f64> = self.entities.values().map(|e| e.score).collect();
        let all_degrees: Vec<f64> = self.entities.values().map(|e| e.degree_score).collect();
        let all_rarities: Vec<f64> = self.entities.values().map(|e| e.rarity_score).collect();
        let composite_percentile = percentile_of(&all_scores, entity.score);
        let degree_percentile = percentile_of(&all_degrees, entity.degree_score);
        let rarity_percentile = percentile_of(&all_rarities, entity.rarity_score);

        // Peers: top 5 of the same type by composite score (excluding self).
        let mut same_type: Vec<(&str, f64)> = self
            .type_index
            .get(&entity.entity_type)
            .map(|ids| {
                ids.iter()
                    .filter(|&&p| p != sid)
                    .filter_map(|&p| self.entities.get(&p).map(|e| (e.id.as_str(), e.score)))
                    .collect()
            })
            .unwrap_or_default();
        same_type.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal));
        let peers: Vec<ExplainedPeer> = same_type
            .into_iter()
            .take(5)
            .map(|(id, score)| ExplainedPeer {
                id: id.to_string(),
                composite_score: score,
            })
            .collect();

        let anomaly_breakdown = self
            .anomaly_scorer
            .as_ref()
            .filter(|s| s.is_finalized())
            .map(|s| s.score_path(std::slice::from_ref(&entity.id), self).1);

        // Narrative: pick the dominant driver (degree vs anomaly vs pagerank)
        // and word it the way the feedback asked — "score 100 because degree
        // percentile 99.8, temporal novelty 0 (common, not rare)".
        let narrative = build_narrative(
            entity.score,
            composite_percentile,
            degree_percentile,
            rarity_percentile,
            entity.rarity_score,
            entity.pagerank_score,
            anomaly_breakdown.as_ref(),
            peers
                .iter()
                .take(3)
                .map(|p| p.id.as_str())
                .collect::<Vec<_>>()
                .join(", "),
        );

        Some(ExplainedScore {
            id: entity.id.clone(),
            entity_type: format!("{}", entity.entity_type),
            composite_score: entity.score,
            degree_score: entity.degree_score,
            pagerank_score: entity.pagerank_score,
            betweenness: entity.betweenness,
            rarity_score: entity.rarity_score,
            anomaly_breakdown,
            composite_percentile,
            degree_percentile,
            rarity_percentile,
            peers,
            narrative,
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
        let scan_limit = config::MAX_SUMMARY_EDGE_SCAN;
        let mut edges_scanned = 0usize;
        // for_each_edge has no early-exit hook; emulate one with a counter
        // and a no-op past the cap. for the typical bench-sized graphs
        // (< MAX_SUMMARY_EDGE_SCAN edges) this iterates everything anyway.
        self.streaming.for_each_edge(|_src, edge| {
            if edges_scanned >= scan_limit {
                return;
            }
            if edge.timestamp != 0 {
                min_ts = min_ts.min(edge.timestamp);
                max_ts = max_ts.max(edge.timestamp);
                has_timestamps = true;
            }
            edges_scanned += 1;
        });

        let mut entities_by_score: Vec<_> = self.entities.values().collect();
        // Tiebreaker cascade: score desc → rarity desc → id asc. Without
        // this a mass-tie (common when 60+ INFO-string nodes all score
        // 99.86) produces arbitrary top_anomalies ordering and hides
        // interesting outliers behind routine duplicates. Rarity wins
        // among ties because the hunt-oriented signal prefers
        // rarely-touched nodes; id alphabetical is the final deterministic
        // tiebreaker so repeated runs return the same list.
        entities_by_score.sort_by(|a, b| {
            b.score
                .partial_cmp(&a.score)
                .unwrap_or(std::cmp::Ordering::Equal)
                .then_with(|| {
                    b.rarity_score
                        .partial_cmp(&a.rarity_score)
                        .unwrap_or(std::cmp::Ordering::Equal)
                })
                .then_with(|| a.id.cmp(&b.id))
        });
        let top_anomalies: Vec<TopAnomaly> = entities_by_score
            .into_iter()
            .take(config::TOP_ANOMALIES_COUNT)
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
    ///
    /// `dedup_mode` controls whether identical or endpoint-identical paths
    /// collapse into a single row with an `edge_count` aggregate. Default
    /// `DedupMode::ByPath` — callers that truly want raw output must opt
    /// into `DedupMode::None` explicitly.
    pub fn score_and_paginate_paths<S: AsRef<str>>(
        &self,
        paths: &[Vec<S>],
        page: usize,
        page_size: usize,
        min_score: Option<f64>,
        dedup_mode: DedupMode,
    ) -> (Vec<ScoredPath>, usize) {
        // The DFS hot path emits `Vec<Arc<str>>` (D0). Analytics still
        // surfaces `ScoredPath` with `Vec<String>` to keep the public DTO
        // stable across FFI / REST / MCP. We materialize `Vec<String>`
        // once here (out of the DFS hot loop) and operate on owned strings
        // for the rest of dedup/score/sort.
        let paths_owned: Vec<Vec<String>> = paths
            .iter()
            .map(|p| p.iter().map(|s| s.as_ref().to_string()).collect())
            .collect();
        let paths: &[Vec<String>] = &paths_owned;

        // Phase 0: dedup. Results are (representative_path, collapsed_count).
        // For ByPath we keep insertion order by walking `paths` once; for
        // ByEndpoints we also keep the first-seen representative so the
        // chain_summary stays interpretable.
        let deduped: Vec<(Vec<String>, usize)> = match dedup_mode {
            DedupMode::None => paths.iter().map(|p| (p.clone(), 1usize)).collect(),
            DedupMode::ByPath => {
                let mut order: Vec<Vec<String>> = Vec::new();
                let mut counts: HashMap<Vec<String>, usize> = HashMap::new();
                for p in paths {
                    match counts.entry(p.clone()) {
                        std::collections::hash_map::Entry::Occupied(mut e) => {
                            *e.get_mut() += 1;
                        }
                        std::collections::hash_map::Entry::Vacant(e) => {
                            e.insert(1);
                            order.push(p.clone());
                        }
                    }
                }
                order
                    .into_iter()
                    .map(|p| {
                        let c = counts[&p];
                        (p, c)
                    })
                    .collect()
            }
            DedupMode::ByEndpoints => {
                let mut order: Vec<(String, String)> = Vec::new();
                let mut seen: HashMap<(String, String), (Vec<String>, usize)> = HashMap::new();
                for p in paths {
                    if p.is_empty() {
                        continue;
                    }
                    let key = (p.first().unwrap().clone(), p.last().unwrap().clone());
                    match seen.entry(key.clone()) {
                        std::collections::hash_map::Entry::Occupied(mut e) => {
                            e.get_mut().1 += 1;
                        }
                        std::collections::hash_map::Entry::Vacant(e) => {
                            e.insert((p.clone(), 1));
                            order.push(key);
                        }
                    }
                }
                order
                    .into_iter()
                    .map(|k| {
                        let (p, c) = seen[&k].clone();
                        (p, c)
                    })
                    .collect()
            }
        };

        // Everything below operates on `deduped`; the old raw-path path is
        // preserved behind DedupMode::None with one-to-one mapping.
        let paths: &[(Vec<String>, usize)] = &deduped;
        let scorer = self.anomaly_scorer.as_ref().filter(|s| s.is_finalized());
        let has_anomaly = scorer.is_some();

        // Phase 1: lightweight scoring
        let mut lightweight: Vec<(usize, f64, f64, f64)> = paths
            .iter()
            .enumerate()
            .map(|(idx, (path, _count))| {
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
                let anomaly = scorer.map(|s| s.score_path(path, self).0).unwrap_or(0.0);
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
                    .then_with(|| b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal))
                    .then_with(|| b.2.partial_cmp(&a.2).unwrap_or(std::cmp::Ordering::Equal))
            } else {
                b.1.partial_cmp(&a.1)
                    .unwrap_or(std::cmp::Ordering::Equal)
                    .then_with(|| b.2.partial_cmp(&a.2).unwrap_or(std::cmp::Ordering::Equal))
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
                    let (path, edge_count) = &paths[idx];
                    let edge_count = *edge_count;
                    let mut time_start = i64::MAX;
                    let mut time_end = i64::MIN;
                    let mut labels: Vec<String> = Vec::new();
                    // Collect all distinct dataset tags that contributed an
                    // edge to this path. Tags get resolved to dataset IDs
                    // after the loop.
                    let mut dataset_tags: std::collections::BTreeSet<u16> =
                        std::collections::BTreeSet::new();

                    for node_id in path {
                        if let Some(_entity) = self.get_entity(node_id) {
                            // Only shorten Windows-style paths — take the
                            // filename after the last backslash. Full IDs
                            // (emails, FQDNs) used to get their FIRST char
                            // silently dropped by a `len - 20..` slice;
                            // the correct behavior is to keep the full ID
                            // and let the UI ellipsize for display.
                            let short = if let Some(pos) = node_id.rfind('\\') {
                                &node_id[pos + 1..]
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
                            if Some(compact.dest_sid) == dest_sid {
                                // Record provenance regardless of whether a
                                // timestamp is present — ingest paths without
                                // time data still carry a dataset tag.
                                if compact.dataset_tag != 0 {
                                    dataset_tags.insert(compact.dataset_tag);
                                }
                                if compact.timestamp != 0 {
                                    if compact.timestamp < time_start {
                                        time_start = compact.timestamp;
                                    }
                                    if compact.timestamp > time_end {
                                        time_end = compact.timestamp;
                                    }
                                }
                            }
                        }
                    }

                    if time_start == i64::MAX {
                        time_start = 0;
                    }
                    if time_end == i64::MIN {
                        time_end = 0;
                    }

                    let (anomaly_score, anomaly_breakdown) = match scorer {
                        Some(s) => {
                            let (score, breakdown) = s.score_path(path, self);
                            (Some(score), Some(breakdown))
                        }
                        None => (None, None),
                    };

                    let datasets_used: Vec<String> = dataset_tags
                        .into_iter()
                        .filter_map(|tag| self.resolve_dataset_tag(tag).map(|s| s.to_string()))
                        .collect();

                    ScoredPath {
                        path: path.clone(),
                        max_score,
                        total_score,
                        time_start,
                        time_end,
                        chain_summary: labels.join(" -> "),
                        anomaly_score,
                        anomaly_breakdown,
                        edge_count,
                        datasets_used,
                    }
                })
                .collect()
        };

        (page_items, filtered_count)
    }

    /// Computes the relation schema: one entry per distinct
    /// (rel_type, source_type, target_type) triple observed in the graph.
    ///
    /// Intended as the first call after `get_graph_summary` when building a
    /// hunt — the DSL requires edge direction to match the underlying data,
    /// and this surfaces that direction explicitly instead of forcing users
    /// to discover it through failed `run_hunt` calls.
    ///
    /// Memoized behind `schema_cache` keyed by `(edge_count, meta_bytes)`;
    /// warm calls are O(1). Cold computation is one O(E) pass over
    /// `edge_store`, per-edge cost dominated by cheap entity type lookup
    /// (full metadata is NOT decoded — only key names via
    /// `MetadataStore::visit_keys`, and each triple stops sampling keys
    /// after `SCHEMA_META_SAMPLE_CAP` edges since the key set is almost
    /// always stable within the first hundred edges per triple). Results
    /// are sorted by edge_count descending.
    pub fn get_relation_schema(&self) -> Vec<RelSchemaEntry> {
        self.get_relation_schema_with_cache_info().0
    }

    /// Same as [`Self::get_relation_schema`] but also reports whether the
    /// result came from the memoized cache. Used by the HTTP/MCP path so
    /// callers can surface the cache-hit signal in response metadata
    /// without re-running the computation for timing.
    pub fn get_relation_schema_with_cache_info(&self) -> (Vec<RelSchemaEntry>, bool) {
        let edge_count = self.streaming_edge_count();
        let meta_bytes = self.meta_store.size_bytes();

        {
            let cache = self.schema_cache.lock().expect("schema_cache poisoned");
            if let Some(entry) = cache.as_ref() {
                if entry.edge_count == edge_count && entry.meta_bytes == meta_bytes {
                    return (entry.schema.clone(), true);
                }
            }
        }

        // Per-triple edge sample cap for metadata key discovery. Threat-hunt
        // edges emitted by the same parser share the same metadata schema;
        // the key set is fixed within the first hundred edges of a triple.
        // Scanning every one of the 7M edges just to re-confirm already-
        // known keys wastes ~25% of schema compute for zero new info.
        const SCHEMA_META_SAMPLE_CAP: usize = 1_000;

        let mut groups: HashMap<(RelationType, EntityType, EntityType), (usize, HashSet<String>)> =
            HashMap::new();

        self.streaming.for_each_edge(|src_sid, edge| {
            let rel = edge.rel_type();
            let src_et = match self.entities.get(&src_sid) {
                Some(e) => e.entity_type.clone(),
                None => return,
            };
            let dst_et = match self.entities.get(&edge.dest_sid) {
                Some(e) => e.entity_type.clone(),
                None => return,
            };

            let slot = groups
                .entry((rel, src_et, dst_et))
                .or_insert_with(|| (0, HashSet::new()));
            slot.0 += 1;
            if edge.metadata_offset != 0 && slot.0 <= SCHEMA_META_SAMPLE_CAP {
                self.meta_store.visit_keys(edge.metadata_offset, |k| {
                    if !slot.1.contains(k) {
                        slot.1.insert(k.to_string());
                    }
                });
            }
        });

        let mut out: Vec<RelSchemaEntry> = groups
            .into_iter()
            .map(|((rel, src, dst), (count, keys))| {
                let mut keys_vec: Vec<String> = keys.into_iter().collect();
                keys_vec.sort();
                RelSchemaEntry {
                    rel_type: format!("{}", rel),
                    source_type: format!("{}", src),
                    target_type: format!("{}", dst),
                    edge_count: count,
                    metadata_keys: keys_vec,
                }
            })
            .collect();

        out.sort_by(|a, b| b.edge_count.cmp(&a.edge_count));

        {
            let mut cache = self.schema_cache.lock().expect("schema_cache poisoned");
            *cache = Some(crate::graph::SchemaCacheEntry {
                edge_count,
                meta_bytes,
                schema: out.clone(),
            });
        }

        (out, false)
    }

    /// Run the same hypothesis at two upper time bounds and return what
    /// appeared / disappeared between them. Uses the existing
    /// `search_temporal_pattern` time_window parameter — no separate
    /// snapshot storage needed. Paths are compared by full node
    /// sequence; duplicates within a bound collapse first via
    /// `DedupMode::ByPath` so only meaningfully-new paths surface in
    /// `added`.
    pub fn diff_hunts(
        &self,
        hypothesis: &crate::Hypothesis,
        baseline_ts: i64,
        current_ts: i64,
    ) -> Result<HuntDiff, crate::errors::GraphError> {
        // Time window (i64::MIN, ts) includes every event up to and including
        // `ts`. Engine code already understands this interval shape.
        let baseline_window = Some((i64::MIN, baseline_ts));
        let current_window = Some((i64::MIN, current_ts));

        let (baseline_raw, _) = self.search_temporal_pattern(hypothesis, baseline_window, None)?;
        let (current_raw, _) = self.search_temporal_pattern(hypothesis, current_window, None)?;

        // Dedup + score each side independently so the ScoredPath
        // metadata (edge_count, time_start, time_end) travels with the
        // diff. Large page_size = give us everything; we filter later.
        let (baseline_scored, _) = self.score_and_paginate_paths(
            &baseline_raw,
            0,
            usize::MAX.min(baseline_raw.len().max(1)),
            None,
            DedupMode::ByPath,
        );
        let (current_scored, _) = self.score_and_paginate_paths(
            &current_raw,
            0,
            usize::MAX.min(current_raw.len().max(1)),
            None,
            DedupMode::ByPath,
        );

        // Index each side by path-sequence key for O(1) lookups.
        use std::collections::HashMap;
        let baseline_keys: HashMap<Vec<String>, &ScoredPath> = baseline_scored
            .iter()
            .map(|sp| (sp.path.clone(), sp))
            .collect();
        let current_keys: HashMap<Vec<String>, &ScoredPath> = current_scored
            .iter()
            .map(|sp| (sp.path.clone(), sp))
            .collect();

        let added: Vec<ScoredPath> = current_scored
            .iter()
            .filter(|sp| !baseline_keys.contains_key(&sp.path))
            .cloned()
            .collect();
        let removed: Vec<ScoredPath> = baseline_scored
            .iter()
            .filter(|sp| !current_keys.contains_key(&sp.path))
            .cloned()
            .collect();

        Ok(HuntDiff {
            baseline_ts,
            current_ts,
            baseline_count: baseline_scored.len(),
            current_count: current_scored.len(),
            added,
            removed,
        })
    }

    /// Given a hypothesis that returned zero paths, explain why.
    ///
    /// Walks the steps and, for each one, counts how many edges of the
    /// required `(source_type, rel_type, target_type)` triple exist at the
    /// schema level. The first step with zero matches is the failure point.
    /// If the same rel_type has edges in the reverse direction, the
    /// suggestion proposes a direction inversion — which covered the
    /// single most common cause of false-negative hunts in the post-hunt
    /// feedback.
    ///
    /// This does **not** run DFS — it's a pure schema consult, O(E) at most
    /// (dominated by `get_relation_schema`), and intended to run only when
    /// the actual hunt returned nothing.
    pub fn hunt_diagnostic(&self, hypothesis: &crate::Hypothesis) -> HuntDiagnostic {
        let steps = &hypothesis.steps;
        if steps.is_empty() {
            return HuntDiagnostic {
                failed_step_index: 0,
                reason: "hypothesis has no steps".into(),
                suggestion: None,
                first_step_matches: 0,
            };
        }

        let schema = self.get_relation_schema();

        // Pre-compute: how many edges match each step's (src_type, rel, dst_type)
        // triple. Wildcards (EntityType::Any, RelationType::Any) are treated as
        // always-matching and count the union across all compatible schema rows.
        let count_matches = |src: &EntityType, rel: &RelationType, dst: &EntityType| -> usize {
            let src_str = format!("{src}");
            let rel_str = format!("{rel}");
            let dst_str = format!("{dst}");
            schema
                .iter()
                .filter(|e| {
                    (src_str == "*" || e.source_type == src_str)
                        && (rel_str == "*" || e.rel_type == rel_str)
                        && (dst_str == "*" || e.target_type == dst_str)
                })
                .map(|e| e.edge_count)
                .sum()
        };

        // Count matches of the first step (the "first_step_matches" field
        // the feedback explicitly asked for).
        let first = &steps[0];
        let first_matches =
            count_matches(&first.origin_type, &first.relation_type, &first.dest_type);

        // Find the first step with zero schema matches.
        for (i, step) in steps.iter().enumerate() {
            let n = count_matches(&step.origin_type, &step.relation_type, &step.dest_type);
            if n > 0 {
                continue;
            }

            // Zero matches for this step. See if the reverse direction has any.
            let reverse = count_matches(&step.dest_type, &step.relation_type, &step.origin_type);
            let reason = format!(
                "no edges of type '{}' from '{}' to '{}' exist in the loaded dataset",
                step.relation_type, step.origin_type, step.dest_type
            );
            let suggestion = if reverse > 0 {
                Some(format!(
                    "Found {} edges going the other way — did you mean '{} -[{}]-> {}' (reversed)?",
                    reverse, step.dest_type, step.relation_type, step.origin_type
                ))
            } else {
                // No reverse either. Check if the rel_type exists at all for either direction.
                let rel_anywhere: usize = schema
                    .iter()
                    .filter(|e| e.rel_type == format!("{}", step.relation_type))
                    .map(|e| e.edge_count)
                    .sum();
                if rel_anywhere == 0 {
                    Some(format!(
                        "Relation type '{}' does not appear anywhere in the dataset — call `get_relation_schema` to list the relation types that actually exist here.",
                        step.relation_type
                    ))
                } else {
                    Some(format!(
                        "Relation '{}' exists but not between ({}, {}). Call `get_relation_schema` and pick a triple that matches the data.",
                        step.relation_type, step.origin_type, step.dest_type
                    ))
                }
            };
            return HuntDiagnostic {
                failed_step_index: i,
                reason,
                suggestion,
                first_step_matches: first_matches,
            };
        }

        // Every step has schema-level (src, rel, dst) matches but DFS still
        // returned zero. Before blaming temporal ordering, check whether any
        // step carries edge predicates that rule out every edge — that is
        // the common failure mode when the pattern assumes enrichment
        // (e.g. `risk_tag="anonymizing"`) that the ingest pipeline never
        // populates.
        for (i, step) in steps.iter().enumerate() {
            if step.edge_predicates.is_empty() {
                continue;
            }
            // Look at the schema row(s) for this step's triple and see if
            // any predicate key is missing from the observed metadata_keys
            // union — a cheap signal that the field was never present.
            let origin_s = format!("{}", step.origin_type);
            let rel_s = format!("{}", step.relation_type);
            let dest_s = format!("{}", step.dest_type);
            let mut observed_keys: std::collections::HashSet<&str> =
                std::collections::HashSet::new();
            let mut edges_total: usize = 0;
            for row in schema.iter().filter(|r| {
                (origin_s == "*" || r.source_type == origin_s)
                    && (rel_s == "*" || r.rel_type == rel_s)
                    && (dest_s == "*" || r.target_type == dest_s)
            }) {
                edges_total += row.edge_count;
                for k in &row.metadata_keys {
                    observed_keys.insert(k.as_str());
                }
            }

            // For each predicate, record the key it reads and whether that
            // key was ever seen on any edge of this (src, rel, dst) group.
            let missing_keys: Vec<&str> = step
                .edge_predicates
                .iter()
                .filter_map(|p| match p {
                    crate::hypothesis::Predicate::Eq { key, .. }
                    | crate::hypothesis::Predicate::Match { key, .. }
                    | crate::hypothesis::Predicate::In { key, .. } => {
                        if observed_keys.contains(key.as_str()) {
                            None
                        } else {
                            Some(key.as_str())
                        }
                    }
                    // Negative predicates (Neq, NotIn) match missing keys by
                    // design, so their absence is not the cause.
                    crate::hypothesis::Predicate::Neq { .. }
                    | crate::hypothesis::Predicate::NotIn { .. } => None,
                })
                .collect();

            if !missing_keys.is_empty() {
                let keys_list = missing_keys
                    .iter()
                    .collect::<Vec<_>>()
                    .iter()
                    .map(|s| format!("`{s}`"))
                    .collect::<Vec<_>>()
                    .join(", ");
                let reason = format!(
                    "step {i} has a metadata predicate on {keys_list} but that field is not populated on any of the {edges_total} observed edges for this triple — the pattern requires upstream enrichment that is not present in this dataset"
                );
                let observed_list = if observed_keys.is_empty() {
                    "none".to_string()
                } else {
                    let mut v: Vec<&str> = observed_keys.iter().copied().collect();
                    v.sort();
                    v.iter()
                        .map(|s| format!("`{s}`"))
                        .collect::<Vec<_>>()
                        .join(", ")
                };
                let suggestion = Some(format!(
                    "Observed metadata keys on this edge group: {observed_list}. Either remove the predicate from the hypothesis, relax it (e.g. use a `~` substring match on a related field), or enable the ingest enrichment that would populate {keys_list}."
                ));
                return HuntDiagnostic {
                    failed_step_index: i,
                    reason,
                    suggestion,
                    first_step_matches: first_matches,
                };
            }

            // Keys exist at the schema level, but the specific values may
            // not. Run a cheap sample scan: walk up to N edges of this
            // triple and record which predicates pass. Zero-pass = the
            // value is absent even though the key is observed.
            const SAMPLE_CAP: usize = 5_000;
            let mut sampled: usize = 0;
            let mut passed: usize = 0;
            self.streaming.for_each_edge(|src_sid, edge| {
                if sampled >= SAMPLE_CAP {
                    return;
                }
                if format!("{}", edge.rel_type()) != rel_s && rel_s != "*" {
                    return;
                }
                let (src_et, dst_et) = match (
                    self.entities.get(&src_sid).map(|e| &e.entity_type),
                    self.entities.get(&edge.dest_sid).map(|e| &e.entity_type),
                ) {
                    (Some(s), Some(d)) => (s, d),
                    _ => return,
                };
                if origin_s != "*" && format!("{src_et}") != origin_s {
                    return;
                }
                if dest_s != "*" && format!("{dst_et}") != dest_s {
                    return;
                }
                sampled += 1;
                let metadata = if edge.metadata_offset != 0 {
                    self.meta_store.get(edge.metadata_offset)
                } else {
                    std::collections::HashMap::new()
                };
                if crate::hypothesis::all_predicates_match(&step.edge_predicates, &metadata) {
                    passed += 1;
                }
            });
            if sampled > 0 && passed == 0 {
                return HuntDiagnostic {
                    failed_step_index: i,
                    reason: format!(
                        "step {i} has metadata predicates that match 0/{sampled} sampled edges of this triple — the keys exist but none carries a value matching the filter"
                    ),
                    suggestion: Some(
                        "Try a wider predicate (e.g. `~` substring instead of `=`) or inspect values via `expand_node_grouped` on a representative source node."
                            .into(),
                    ),
                    first_step_matches: first_matches,
                };
            }
        }

        // Every step has schema-level matches AND predicates are satisfiable
        // — the failure is structural (temporal ordering, k-simplicity, or
        // disconnected edges). Fall back to the generic advice.
        HuntDiagnostic {
            failed_step_index: steps.len().saturating_sub(1),
            reason: "every step matches the schema individually, but no chain satisfies temporal ordering or k-simplicity (paths exist as isolated edges but not connected in the expected order)".into(),
            suggestion: Some(
                "Widen the time window with the `time_window` parameter, or inspect individual hops with `expand_node_grouped` on the expected intermediate nodes."
                    .into(),
            ),
            first_step_matches: first_matches,
        }
    }

    /// Read-only projection: group stored edges by (source, dest, rel_type)
    /// with volume metrics, ranked by count desc (bytes desc tiebreak). Does
    /// not mutate the graph. Recovers custom rel-type names from `_rel_type`.
    pub fn heavy_edges(&self, opts: &HeavyEdgesOpts) -> Vec<HeavyEdge> {
        struct Agg {
            count: usize,
            bytes: u64,
            dur: u64,
            resets: usize,
            first_ts: i64,
            last_ts: i64,
        }
        let mut groups: HashMap<(StrId, StrId, String), Agg> = HashMap::new();
        // NOTE: `meta_store.get` allocates a fresh HashMap per edge. Fine for
        // this on-demand analytical query; if ever called per-tick or at
        // 500k+ edges, add a borrowing `visit_kv(offset, |k,v|)` accessor to
        // MetadataStore (cf. its existing `visit_keys`) to avoid the alloc.
        self.streaming.for_each_edge(|src, e| {
            let md = self.meta_store.get(e.metadata_offset);
            let rt = md.get("_rel_type").cloned()
                .unwrap_or_else(|| format!("{}", crate::types::RelationType::from_u8(e.rel_type_tag)));
            let entry = groups.entry((src, e.dest_sid, rt)).or_insert_with(|| Agg {
                count: 0,
                bytes: 0,
                dur: 0,
                resets: 0,
                first_ts: i64::MAX,
                last_ts: i64::MIN,
            });
            entry.count += 1;
            if let Some(b) = md.get("sentbyte").and_then(|s| s.parse::<u64>().ok()) {
                entry.bytes += b;
            }
            if let Some(d) = md.get("duration").and_then(|s| s.parse::<u64>().ok()) {
                entry.dur += d;
            }
            if matches!(
                md.get("action").map(|s| s.as_str()),
                Some("client-rst") | Some("server-rst")
            ) {
                entry.resets += 1;
            }
            if e.timestamp < entry.first_ts {
                entry.first_ts = e.timestamp;
            }
            if e.timestamp > entry.last_ts {
                entry.last_ts = e.timestamp;
            }
        });
        // `for_each_edge` visits base AND post-finalize tail edges (tail
        // completeness fix), so heavy_edges covers live Sentinel tail data.
        let mut out: Vec<HeavyEdge> = groups
            .into_iter()
            .filter(|((_, _, rt), _)| opts.rel_type.as_ref().map_or(true, |w| w == rt))
            .filter(|(_, a)| opts.min_count.map_or(true, |m| a.count >= m))
            .map(|((s, d, rt), a)| HeavyEdge {
                source: self.interner.resolve(s).to_string(),
                target: self.interner.resolve(d).to_string(),
                rel_type: rt,
                count: a.count,
                total_bytes: a.bytes,
                total_duration_secs: a.dur,
                reset_pct: if a.count > 0 {
                    100.0 * a.resets as f64 / a.count as f64
                } else {
                    0.0
                },
                first_ts: a.first_ts,
                last_ts: a.last_ts,
            })
            .collect();
        out.sort_by(|x, y| y.count.cmp(&x.count).then(y.total_bytes.cmp(&x.total_bytes)));
        out.truncate(opts.top_n);
        out
    }

    /// Read-only per-channel temporal behavior: beaconing (inter-arrival CV),
    /// reset bursts, and volume spikes. Groups by (source, dest, rel_type).
    /// Does not mutate the graph.
    pub fn channel_behavior(&self, opts: &ChannelBehaviorOpts) -> Vec<ChannelBehavior> {
        // NOTE: `meta_store.get` allocates a HashMap per edge — acceptable for an
        // on-demand analytical query (cf. heavy_edges). `for_each_edge` visits
        // base AND post-finalize tail edges, so live finalized graphs are covered.
        let window = opts.window_secs.max(1) as i64;
        let mut groups: HashMap<(StrId, StrId, String), Vec<(i64, u64, bool)>> = HashMap::new();
        self.streaming.for_each_edge(|src, ed| {
            let md = self.meta_store.get(ed.metadata_offset);
            let rt = md.get("_rel_type").cloned()
                .unwrap_or_else(|| format!("{}", crate::types::RelationType::from_u8(ed.rel_type_tag)));
            let bytes = md.get("sentbyte").and_then(|s| s.parse::<u64>().ok()).unwrap_or(0);
            let is_reset = matches!(
                md.get("action").map(|s| s.as_str()),
                Some("client-rst") | Some("server-rst")
            );
            groups.entry((src, ed.dest_sid, rt)).or_default().push((ed.timestamp, bytes, is_reset));
        });

        let mut out: Vec<ChannelBehavior> = Vec::new();
        for ((s, d, rt), mut edges) in groups {
            if let Some(m) = opts.min_count {
                if edges.len() < m {
                    continue;
                }
            }
            if let Some(want) = opts.rel_type.as_ref() {
                if want != &rt {
                    continue;
                }
            }
            edges.sort_by_key(|x| x.0);
            let count = edges.len();
            let first_ts = edges.first().map(|x| x.0).unwrap_or(0);
            let last_ts = edges.last().map(|x| x.0).unwrap_or(0);

            let mut interval_mean_secs = 0.0_f64;
            let mut interval_cv = 0.0_f64;
            let mut beacon_score = 0.0_f64;
            if count >= 2 {
                let intervals: Vec<f64> = edges
                    .windows(2)
                    .map(|w| (w[1].0 - w[0].0) as f64)
                    .collect();
                let mean = intervals.iter().sum::<f64>() / intervals.len() as f64;
                interval_mean_secs = mean;
                if count >= 3 && mean > 0.0 {
                    let var = intervals
                        .iter()
                        .map(|x| (x - mean).powi(2))
                        .sum::<f64>()
                        / intervals.len() as f64;
                    interval_cv = var.sqrt() / mean;
                    beacon_score = 1.0 - interval_cv.min(1.0);
                }
            }

            let mut buckets: HashMap<i64, (usize, u64, usize)> = HashMap::new();
            for (ts, bytes, is_reset) in &edges {
                let b = buckets.entry(ts / window).or_insert((0, 0, 0));
                if *is_reset {
                    b.0 += 1;
                }
                b.1 += *bytes;
                b.2 += 1;
            }
            let max_resets_in_window = buckets.values().map(|b| b.0).max().unwrap_or(0);
            let max_bytes_in_window = buckets.values().map(|b| b.1).max().unwrap_or(0);
            let max_count_in_window = buckets.values().map(|b| b.2).max().unwrap_or(0);

            out.push(ChannelBehavior {
                source: self.interner.resolve(s).to_string(),
                target: self.interner.resolve(d).to_string(),
                rel_type: rt,
                count,
                first_ts,
                last_ts,
                interval_mean_secs,
                interval_cv,
                beacon_score,
                max_resets_in_window,
                max_bytes_in_window,
                max_count_in_window,
            });
        }

        out.sort_by(|x, y| {
            let primary = match opts.sort_by {
                ChannelSortBy::Beacon => y
                    .beacon_score
                    .partial_cmp(&x.beacon_score)
                    .unwrap_or(std::cmp::Ordering::Equal),
                ChannelSortBy::Resets => y.max_resets_in_window.cmp(&x.max_resets_in_window),
                ChannelSortBy::Volume => y.max_bytes_in_window.cmp(&x.max_bytes_in_window),
            };
            primary.then(y.count.cmp(&x.count))
        });
        out.truncate(opts.top_n);
        out
    }

    /// Entity-class (EntityType display) for a node, or "" when unknown.
    fn class_of(&self, sid: StrId) -> String {
        self.entities
            .get(&sid)
            .map(|e| format!("{}", e.entity_type))
            .unwrap_or_default()
    }

    /// Find simple paths from `from_id` following outgoing edges. When `to_id`
    /// is `Some`, returns paths that terminate at it; when `None`, returns every
    /// outbound path up to `max_depth` hops. `rel_filter` restricts which edge
    /// (relation) types may be traversed. Capped at `max_paths` results. Each
    /// path is a node→edge→node→… sequence (the origin hop has `edge: None`).
    ///
    /// This is the traversal `graph_path` (design doc §4.4) exposes — chains
    /// that in KQL would need repeated joins are one precomputed walk here.
    pub fn find_paths(
        &self,
        from_id: &str,
        to_id: Option<&str>,
        max_depth: usize,
        rel_filter: Option<&[RelationType]>,
        max_paths: usize,
    ) -> Vec<Vec<PathHop>> {
        let Some(from_sid) = self.interner.get(from_id) else {
            return Vec::new();
        };
        if !self.entities.contains_key(&from_sid) {
            return Vec::new();
        }
        let to_sid = match to_id {
            Some(t) => match self.interner.get(t) {
                Some(s) if self.entities.contains_key(&s) => Some(s),
                // Target named but absent → no paths.
                _ => return Vec::new(),
            },
            None => None,
        };

        let mut out: Vec<Vec<PathHop>> = Vec::new();
        let mut on_path: HashSet<StrId> = HashSet::new();
        on_path.insert(from_sid);
        let mut path = vec![PathHop {
            node_id: from_id.to_string(),
            node_class: self.class_of(from_sid),
            edge: None,
        }];
        self.dfs_paths(
            from_sid, to_sid, max_depth, rel_filter, &mut path, &mut on_path, &mut out, max_paths,
        );
        out
    }

    #[allow(clippy::too_many_arguments)]
    fn dfs_paths(
        &self,
        current: StrId,
        to_sid: Option<StrId>,
        max_depth: usize,
        rel_filter: Option<&[RelationType]>,
        path: &mut Vec<PathHop>,
        on_path: &mut HashSet<StrId>,
        out: &mut Vec<Vec<PathHop>>,
        max_paths: usize,
    ) {
        if out.len() >= max_paths {
            return;
        }
        let edges_so_far = path.len() - 1;
        if path.len() > 1 {
            match to_sid {
                // Stop at the target — don't traverse through it.
                Some(t) => {
                    if current == t {
                        out.push(path.clone());
                        return;
                    }
                }
                None => out.push(path.clone()),
            }
        }
        if edges_so_far >= max_depth {
            return;
        }

        // Snapshot this node's outgoing edges, then drop the per-node read lock
        // before recursing so we never hold nested per-node locks.
        let children: Vec<(StrId, u8, u64)> = match self.streaming.neighbors_arc(current) {
            Some(arc) => {
                let g = arc.read();
                g.as_slice()
                    .iter()
                    .filter(|e| {
                        rel_filter.is_none_or(|rf| rf.iter().any(|rt| rt.to_u8() == e.rel_type_tag))
                    })
                    .map(|e| (e.dest_sid, e.rel_type_tag, e.metadata_offset))
                    .collect()
            }
            None => Vec::new(),
        };

        for (dest, tag, off) in children {
            if out.len() >= max_paths {
                break;
            }
            if on_path.contains(&dest) {
                continue; // simple paths only
            }
            path.push(PathHop {
                node_id: self.interner.resolve(dest).to_string(),
                node_class: self.class_of(dest),
                edge: Some(self.resolve_rel_type_name_raw(tag, off)),
            });
            on_path.insert(dest);
            self.dfs_paths(dest, to_sid, max_depth, rel_filter, path, on_path, out, max_paths);
            on_path.remove(&dest);
            path.pop();
        }
    }

    /// Structural anomalies (design doc §4.6): entities whose graph metric is
    /// atypical for their population. `metric` is `degree`, `betweenness`,
    /// `isolation`, or `all`. `node_class` scopes both the candidates and the
    /// mean/stddev baseline. Returns the `top_n` by z-score (above-mean only),
    /// each with a human-readable observation. Reuses the per-entity centrality
    /// computed by the scoring pass (`isolation` derives from `rarity_score`,
    /// the inverted-degree signal — high = weakly connected / rare).
    pub fn structural_anomalies(
        &self,
        metric: &str,
        node_class: Option<&str>,
        top_n: usize,
    ) -> Vec<AnomalyHit> {
        // Candidate entities, optionally scoped to one class.
        let candidates: Vec<&crate::entity::Entity> = self
            .entities
            .values()
            .filter(|e| node_class.is_none_or(|c| format!("{}", e.entity_type) == c))
            .collect();
        if candidates.len() < 2 {
            return Vec::new(); // no meaningful distribution
        }

        let metrics: Vec<&str> = match metric {
            "all" => vec!["degree", "betweenness", "isolation"],
            m => vec![m],
        };

        let mut hits: Vec<AnomalyHit> = Vec::new();
        for m in metrics {
            if !matches!(m, "degree" | "betweenness" | "isolation") {
                continue; // unknown metric name — nothing to score
            }
            let value_of = |e: &crate::entity::Entity| -> f64 {
                match m {
                    "betweenness" => e.betweenness,
                    "isolation" => e.rarity_score,
                    _ => e.degree_score, // "degree" + unknown fall back to degree
                }
            };
            let vals: Vec<f64> = candidates.iter().map(|e| value_of(e)).collect();
            let n = vals.len() as f64;
            let mean = vals.iter().sum::<f64>() / n;
            let var = vals.iter().map(|v| (v - mean).powi(2)).sum::<f64>() / n;
            let std = var.sqrt();
            if std < f64::EPSILON {
                continue; // flat distribution — nothing stands out
            }
            for e in &candidates {
                let v = value_of(e);
                let z = (v - mean) / std;
                if z <= 0.0 {
                    continue; // only above-mean values are "anomalous"
                }
                let class = format!("{}", e.entity_type);
                let observation = match m {
                    "betweenness" => format!(
                        "betweenness {v:.1} vs {class} mean {mean:.1} (z {z:.1}) — bridges otherwise-separate clusters"
                    ),
                    "isolation" => format!(
                        "isolation {v:.1} vs {class} mean {mean:.1} (z {z:.1}) — weakly connected / rare for its class"
                    ),
                    _ => format!(
                        "degree {v:.1} vs {class} mean {mean:.1} (z {z:.1}) — unusually high connectivity for its class"
                    ),
                };
                hits.push(AnomalyHit {
                    node_id: e.id.clone(),
                    node_class: class,
                    metric: m.to_string(),
                    value: v,
                    z_score: (z * 10.0).round() / 10.0,
                    observation,
                });
            }
        }
        hits.sort_by(|a, b| b.z_score.partial_cmp(&a.z_score).unwrap_or(std::cmp::Ordering::Equal));
        hits.truncate(top_n);
        hits
    }
}

#[cfg(test)]
mod heavy_edges_tests {
    use super::*;
    use crate::GraphHunter;
    use crate::types::{EntityType, RelationType};
    use crate::entity::Entity;
    use crate::relation::Relation;
    use std::collections::HashMap;

    fn edge(
        s: &str,
        d: &str,
        rt: RelationType,
        ts: i64,
        sentbyte: Option<&str>,
        action: Option<&str>,
    ) -> crate::parser::ParsedTriple {
        let mut md = HashMap::new();
        if let Some(b) = sentbyte {
            md.insert("sentbyte".into(), b.into());
        }
        if let Some(a) = action {
            md.insert("action".into(), a.into());
        }
        let mut rel = Relation::new(s, d, rt, ts);
        rel.metadata = md;
        (Entity::new(s, EntityType::IP), rel, Entity::new(d, EntityType::IP))
    }

    #[test]
    fn heavy_edges_groups_and_ranks() {
        let mut g = GraphHunter::new();
        g.insert_triples(
            vec![
                edge("A", "B", RelationType::Connect, 10, Some("100"), Some("close")),
                edge("A", "B", RelationType::Connect, 20, Some("200"), Some("close")),
                edge("A", "B", RelationType::Connect, 30, Some("300"), Some("close")),
                edge("A", "B", RelationType::Connect, 40, Some("400"), Some("client-rst")),
                edge("A", "C", RelationType::Connect, 50, Some("999"), Some("close")),
            ],
            None,
        )
        .unwrap();
        let out = g.heavy_edges(&HeavyEdgesOpts { top_n: 10, min_count: None, rel_type: None });
        let ab = out
            .iter()
            .find(|e| e.source == "A" && e.target == "B")
            .expect("A->B group");
        assert_eq!(ab.count, 4);
        assert_eq!(ab.total_bytes, 1000);
        assert_eq!(ab.rel_type, "Connect");
        assert!((ab.reset_pct - 25.0).abs() < 1e-9);
        assert_eq!(ab.first_ts, 10);
        assert_eq!(ab.last_ts, 40);
        // count 4 ranks first
        assert_eq!(out[0].source, "A");
        assert_eq!(out[0].target, "B");
        let filtered =
            g.heavy_edges(&HeavyEdgesOpts { top_n: 10, min_count: Some(2), rel_type: None });
        assert!(filtered.iter().all(|e| e.count >= 2));
        assert!(filtered.iter().all(|e| !(e.source == "A" && e.target == "C")));
    }

    #[test]
    fn heavy_edges_custom_rel_type_labeled() {
        let mut g = GraphHunter::new();
        g.insert_triples(
            vec![edge(
                "X",
                "Y",
                RelationType::Other("SNAT".to_string()),
                1,
                None,
                None,
            )],
            None,
        )
        .unwrap();
        let out = g.heavy_edges(&HeavyEdgesOpts {
            top_n: 10,
            min_count: None,
            rel_type: Some("SNAT".to_string()),
        });
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].rel_type, "SNAT");
        assert_eq!(out[0].count, 1);
        assert_eq!(out[0].total_bytes, 0);
    }

    #[test]
    fn neighborhood_recovers_custom_rel_type_and_strips_reserved_key() {
        let mut g = GraphHunter::new();
        g.insert_triples(
            vec![edge(
                "a",
                "b",
                RelationType::Other("SNAT".to_string()),
                1,
                None,
                None,
            )],
            None,
        )
        .unwrap();
        let hood = g
            .get_neighborhood("a", 1, 50, None)
            .expect("neighborhood");
        let e = hood
            .edges
            .iter()
            .find(|e| e.source == "a" && e.target == "b")
            .expect("edge a->b");
        assert_eq!(e.rel_type, "SNAT", "rel_type should be recovered custom name");
        assert!(
            !e.metadata.contains_key("_rel_type"),
            "_rel_type must not leak into public edge metadata"
        );
    }
}

#[cfg(test)]
mod hydration_outcome_tests {
    use super::*;

    #[test]
    fn neighborhood_default_omits_hydration_in_json() {
        let hood = Neighborhood {
            center: "x".into(),
            nodes: vec![],
            edges: vec![],
            truncated: false,
            auto_grouped: false,
            auto_group_reason: None,
            hydration: None,
        };
        let json = serde_json::to_string(&hood).unwrap();
        assert!(!json.contains("hydration"), "None hydration must be skipped: {json}");
    }

    #[test]
    fn hydration_outcome_serializes_counts() {
        let o = HydrationOutcome {
            skipped: false,
            reason: None,
            new_entities: 3,
            new_relations: 7,
            tables_hit: 2,
            tables_attempted: 3,
        };
        let json = serde_json::to_string(&o).unwrap();
        assert!(json.contains("\"new_relations\":7"));
    }
}

#[cfg(test)]
mod channel_behavior_tests {
    use super::*;
    use crate::GraphHunter;
    use crate::types::{EntityType, RelationType};
    use crate::entity::Entity;
    use crate::relation::Relation;
    use std::collections::HashMap;

    fn e(s: &str, d: &str, ts: i64, sentbyte: Option<&str>, action: Option<&str>) -> crate::parser::ParsedTriple {
        let mut md = HashMap::new();
        if let Some(b) = sentbyte {
            md.insert("sentbyte".into(), b.into());
        }
        if let Some(a) = action {
            md.insert("action".into(), a.into());
        }
        let mut rel = Relation::new(s, d, RelationType::Connect, ts);
        rel.metadata = md;
        (Entity::new(s, EntityType::IP), rel, Entity::new(d, EntityType::IP))
    }

    fn opts(sort_by: ChannelSortBy) -> ChannelBehaviorOpts {
        ChannelBehaviorOpts {
            top_n: 10,
            min_count: None,
            window_secs: 60,
            rel_type: None,
            sort_by,
        }
    }

    #[test]
    fn regular_channel_scores_as_beacon() {
        let mut g = GraphHunter::new();
        g.insert_triples(
            vec![
                e("A", "B", 0, Some("10"), None),
                e("A", "B", 60, Some("10"), None),
                e("A", "B", 120, Some("10"), None),
                e("A", "B", 180, Some("10"), None),
            ],
            None,
        )
        .unwrap();
        let out = g.channel_behavior(&opts(ChannelSortBy::Beacon));
        let ab = out
            .iter()
            .find(|c| c.source == "A" && c.target == "B")
            .expect("A->B");
        assert_eq!(ab.count, 4);
        assert!((ab.interval_mean_secs - 60.0).abs() < 1e-6);
        assert!(ab.interval_cv < 1e-6, "cv ~0, got {}", ab.interval_cv);
        assert!(ab.beacon_score > 0.99, "beacon ~1, got {}", ab.beacon_score);
    }

    #[test]
    fn irregular_channel_low_beacon() {
        let mut g = GraphHunter::new();
        g.insert_triples(
            vec![
                e("A", "B", 0, None, None),
                e("A", "B", 5, None, None),
                e("A", "B", 200, None, None),
                e("A", "B", 201, None, None),
            ],
            None,
        )
        .unwrap();
        let ab = g
            .channel_behavior(&opts(ChannelSortBy::Beacon))
            .into_iter()
            .find(|c| c.source == "A")
            .unwrap();
        assert!(ab.interval_cv > 0.5, "high cv, got {}", ab.interval_cv);
        assert!(ab.beacon_score < 0.5, "low beacon, got {}", ab.beacon_score);
    }

    #[test]
    fn too_few_events_no_beacon() {
        let mut g = GraphHunter::new();
        g.insert_triples(
            vec![e("A", "B", 0, None, None), e("A", "B", 60, None, None)],
            None,
        )
        .unwrap();
        let ab = g
            .channel_behavior(&opts(ChannelSortBy::Beacon))
            .into_iter()
            .find(|c| c.source == "A")
            .unwrap();
        assert_eq!(ab.beacon_score, 0.0);
    }

    #[test]
    fn reset_burst_and_volume_window() {
        let mut g = GraphHunter::new();
        g.insert_triples(
            vec![
                e("A", "B", 1, Some("500"), Some("client-rst")),
                e("A", "B", 2, Some("500"), Some("server-rst")),
                e("A", "B", 3, Some("500"), Some("client-rst")),
                e("A", "B", 1000, Some("10"), Some("close")),
            ],
            None,
        )
        .unwrap();
        let ab = g
            .channel_behavior(&opts(ChannelSortBy::Resets))
            .into_iter()
            .find(|c| c.source == "A")
            .unwrap();
        assert_eq!(ab.max_resets_in_window, 3);
        assert_eq!(ab.max_bytes_in_window, 1500);
        assert_eq!(ab.max_count_in_window, 3);
    }

    #[test]
    fn min_count_filters_small_channels() {
        let mut g = GraphHunter::new();
        g.insert_triples(vec![
            e("A","B",0,None,None), e("A","B",60,None,None), e("A","B",120,None,None), // count 3
            e("A","C",0,None,None), // count 1
        ], None).unwrap();
        let out = g.channel_behavior(&ChannelBehaviorOpts {
            top_n: 10, min_count: Some(3), window_secs: 60, rel_type: None, sort_by: ChannelSortBy::Beacon,
        });
        assert!(out.iter().any(|c| c.source=="A" && c.target=="B"));
        assert!(out.iter().all(|c| !(c.source=="A" && c.target=="C")), "A->C (count 1) must be filtered by min_count=3");
    }

    #[test]
    fn rel_type_filter_restricts_channels() {
        let mut g = GraphHunter::new();
        // A->B Connect (built-in) and A->D Other("SNAT")
        let mut snat = Relation::new("A","D",RelationType::Other("SNAT".to_string()),0);
        snat.metadata = HashMap::new();
        g.insert_triples(vec![
            e("A","B",0,None,None), e("A","B",60,None,None),
            (Entity::new("A",EntityType::IP), snat, Entity::new("D",EntityType::IP)),
        ], None).unwrap();
        let out = g.channel_behavior(&ChannelBehaviorOpts {
            top_n: 10, min_count: None, window_secs: 60, rel_type: Some("SNAT".to_string()), sort_by: ChannelSortBy::Beacon,
        });
        assert!(out.iter().all(|c| c.rel_type=="SNAT"), "only SNAT channels");
        assert!(out.iter().any(|c| c.source=="A" && c.target=="D"), "the SNAT channel is present");
    }
}

#[cfg(test)]
mod find_paths_tests {
    use super::*;
    use crate::GraphHunter;
    use crate::entity::Entity;
    use crate::relation::Relation;
    use crate::types::{EntityType, RelationType};

    // Chain: alice -Auth-> IP -Connect-> ROLE -Connect-> ACCT, plus a side edge
    // alice -Connect-> HOST to exercise edge_filter and branching.
    fn chain_graph() -> GraphHunter {
        let mut g = GraphHunter::new();
        g.insert_triples(
            vec![
                (
                    Entity::new("alice", EntityType::User),
                    Relation::new("alice", "1.1.1.1", RelationType::Auth, 1),
                    Entity::new("1.1.1.1", EntityType::IP),
                ),
                (
                    Entity::new("1.1.1.1", EntityType::IP),
                    Relation::new("1.1.1.1", "ROLE", RelationType::Connect, 2),
                    Entity::new("ROLE", EntityType::Other("Role".into())),
                ),
                (
                    Entity::new("ROLE", EntityType::Other("Role".into())),
                    Relation::new("ROLE", "ACCT", RelationType::Connect, 3),
                    Entity::new("ACCT", EntityType::Other("Account".into())),
                ),
                (
                    Entity::new("alice", EntityType::User),
                    Relation::new("alice", "HOST", RelationType::Connect, 4),
                    Entity::new("HOST", EntityType::Host),
                ),
            ],
            None,
        )
        .unwrap();
        g
    }

    #[test]
    fn finds_path_between_two_entities() {
        let g = chain_graph();
        let paths = g.find_paths("alice", Some("ACCT"), 4, None, 50);
        assert_eq!(paths.len(), 1, "one simple path alice→ACCT");
        let p = &paths[0];
        // hops: alice, IP, ROLE, ACCT  → length 3
        assert_eq!(p.len(), 4);
        assert_eq!(p[0].node_id, "alice");
        assert!(p[0].edge.is_none(), "origin hop carries no edge");
        assert_eq!(p[1].edge.as_deref(), Some("Auth"));
        assert_eq!(p[3].node_id, "ACCT");
        assert_eq!(p[3].node_class, "Account");
    }

    #[test]
    fn max_depth_bounds_traversal() {
        let g = chain_graph();
        // ACCT is 3 hops away; depth 2 can't reach it.
        assert!(g.find_paths("alice", Some("ACCT"), 2, None, 50).is_empty());
    }

    #[test]
    fn edge_filter_restricts_traversal() {
        let g = chain_graph();
        // Only Auth edges: alice→IP is the single reachable path.
        let paths = g.find_paths("alice", None, 4, Some(&[RelationType::Auth]), 50);
        assert_eq!(paths.len(), 1);
        assert_eq!(paths[0].last().unwrap().node_id, "1.1.1.1");
    }

    #[test]
    fn all_outbound_paths_when_no_target() {
        let g = chain_graph();
        let paths = g.find_paths("alice", None, 4, None, 50);
        // alice→IP, alice→IP→ROLE, alice→IP→ROLE→ACCT, alice→HOST = 4 paths.
        assert_eq!(paths.len(), 4);
    }

    #[test]
    fn unknown_origin_or_target_yields_no_paths() {
        let g = chain_graph();
        assert!(g.find_paths("nope", Some("ACCT"), 4, None, 50).is_empty());
        assert!(g.find_paths("alice", Some("nope"), 4, None, 50).is_empty());
    }
}

#[cfg(test)]
mod structural_anomaly_tests {
    use super::*;
    use crate::GraphHunter;
    use crate::entity::Entity;
    use crate::relation::Relation;
    use crate::types::{EntityType, RelationType};

    // Star: hub HUB connected to many leaves → HUB has anomalous degree.
    fn star_graph() -> GraphHunter {
        let mut g = GraphHunter::new();
        let mut triples = Vec::new();
        for i in 0..12 {
            triples.push((
                Entity::new("HUB", EntityType::Host),
                Relation::new("HUB", format!("leaf{i}"), RelationType::Connect, i as i64),
                Entity::new(format!("leaf{i}"), EntityType::IP),
            ));
        }
        g.insert_triples(triples, None).unwrap();
        g.compute_scores(); // populate degree_score / rarity_score
        g
    }

    #[test]
    fn degree_anomaly_surfaces_the_hub() {
        let g = star_graph();
        let hits = g.structural_anomalies("degree", None, 10);
        assert!(!hits.is_empty(), "hub should register as a degree anomaly");
        assert_eq!(hits[0].node_id, "HUB");
        assert_eq!(hits[0].metric, "degree");
        assert!(hits[0].z_score > 0.0);
    }

    #[test]
    fn node_class_scopes_candidates() {
        let g = star_graph();
        // Scope to IP leaves only — the hub (Host) is excluded entirely.
        let hits = g.structural_anomalies("degree", Some("IP"), 10);
        assert!(hits.iter().all(|h| h.node_class == "IP"));
        assert!(hits.iter().all(|h| h.node_id != "HUB"));
    }

    #[test]
    fn unknown_metric_or_tiny_graph_is_empty() {
        let g = star_graph();
        assert!(g.structural_anomalies("nonsense", None, 10).is_empty());
        let tiny = GraphHunter::new();
        assert!(tiny.structural_anomalies("all", None, 10).is_empty());
    }
}
