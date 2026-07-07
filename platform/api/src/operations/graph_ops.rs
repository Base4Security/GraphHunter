//! Graph operations. Fase 1 migrates the read-only subset plus a few
//! small mutations (`compute_scores`). Hunt execution, paging, and
//! ingest land in Fase 2 (they touch the HuntCache service).

use std::collections::HashSet;

use graph_hunter_core::{
    FieldInfo, NeighborEdge, NeighborNode, Neighborhood, NodeDetails, SearchResult, preview_fields,
};

use crate::dto::entity::{NodeScopedRequest, SessionOnly};
use crate::dto::graph_ops::{
    AnomalyItem, ChannelBehaviorRequest, ComputeScoresRequest, EventsForNodeRequest,
    EventsPaginatedRequest, ExpandFilter, ExpandNodeRequest, GraphAnomalyRequest,
    GraphAnomalyResult, GraphNeighborsRequest, GraphNeighborsResult, GraphPathRequest,
    GraphPathResult, GraphStats, HeavyEdgesRequest, NeighborItem, NeighborRef, NeighborsCenter,
    PaginatedEvents, PathDto, PathHopDto, PathNode, PreviewFieldsRequest, RuntimeInfo,
    SearchEntitiesRequest, Subgraph, SubgraphEdge, SubgraphNode, SubgraphRequest,
};
use crate::util::{parse_entity_type, parse_relation_type, to_core_filter};
use crate::{ApiError, ApiResult, GraphHunterApi};

impl GraphHunterApi {
    /// Node + relation counts for the resolved session's graph.
    pub fn get_graph_stats(&self, req: SessionOnly) -> ApiResult<GraphStats> {
        self.with_graph_read(req.session.as_ref(), |g| {
            Ok(GraphStats {
                entity_count: g.entity_count(),
                relation_count: g.relation_count(),
            })
        })
    }

    /// Detailed view of a node: core fields, neighbors by type, score
    /// breakdown, etc.
    pub fn get_node_details(&self, req: NodeScopedRequest) -> ApiResult<NodeDetails> {
        self.with_graph_read(req.session.as_ref(), |g| {
            g.get_node_details(&req.node_id)
                .ok_or_else(|| ApiError::NotFound(format!("entity: {}", req.node_id)))
        })
    }

    /// Trigger a full score recomputation over all entities. Write lock;
    /// blocks reads for the duration.
    pub fn compute_scores(&self, req: ComputeScoresRequest) -> ApiResult<()> {
        self.with_graph_write(req.session.as_ref(), |g| {
            g.compute_scores();
            // Populate `entity.score` with the hunt-oriented composite so
            // downstream consumers (`get_graph_summary.top_anomalies`,
            // UI ranking, MCP tool callers) surface rarity-driven picks
            // by default instead of pure degree centrality. PageRank and
            // betweenness stay at 0 unless explicitly computed — the
            // hunt default uses small weights for them so their absence
            // doesn't distort the ranking.
            g.compute_composite_score_hunt_default();
            Ok(())
        })
    }

    // ── Stateless ops ──────────────────────────────────────────────────

    /// Preview field names in a log file by sampling the first N events.
    /// No session required — reads from disk.
    pub fn preview_fields(&self, req: PreviewFieldsRequest) -> ApiResult<Vec<FieldInfo>> {
        let limit = req.sample_size.unwrap_or(500);
        let file = std::fs::File::open(&req.path)
            .map_err(|e| ApiError::Io(format!("open '{}': {e}", req.path)))?;
        let mut reader = std::io::BufReader::new(file);
        let mut buf = vec![0u8; 10 * 1024 * 1024];
        use std::io::Read;
        let n = reader
            .read(&mut buf)
            .map_err(|e| ApiError::Io(format!("read: {e}")))?;
        buf.truncate(n);
        let contents = String::from_utf8_lossy(&buf).to_string();
        Ok(preview_fields(&contents, limit))
    }

    /// Runtime build/hardware capabilities. Stateless — safe to call
    /// before any session exists. Replaces the legacy one-off
    /// `cmd_get_simd_isa` with a generalized payload.
    pub fn runtime_info(&self) -> RuntimeInfo {
        RuntimeInfo {
            simd_isa: graph_hunter_core::simd_rust::isa_label().to_string(),
        }
    }

    // ── Events / subgraph / search / expand ─────────────────────────────

    /// All relations (events) where the given node is source or target,
    /// sorted by timestamp. Caps at 500 rows to keep the frontend
    /// responsive; use [`Self::get_events_paginated`] for deeper browsing.
    pub fn get_events_for_node(&self, req: EventsForNodeRequest) -> ApiResult<Vec<SubgraphEdge>> {
        const MAX_EVENTS: usize = 500;
        self.with_graph_read(req.session.as_ref(), |graph| {
            let mut edges: Vec<SubgraphEdge> = Vec::new();

            for compact in graph.get_compact_relations(&req.node_id) {
                if edges.len() >= MAX_EVENTS {
                    break;
                }
                edges.push(subgraph_edge_from_compact(graph, &compact));
            }

            let target_sid = graph.interner.get(&req.node_id);
            // `reverse_adj` stores one entry per incoming edge, so a single
            // source `S` with `X` incoming edges to `node_id` appears `X`
            // times. Without dedup, the outer loop fires `X` times per
            // unique source, and the inner `break` means we push the
            // same first-match edge `X` times — that's why this endpoint
            // used to return 500 identical events when a node had one
            // heavy source.
            let mut seen_sources: std::collections::HashSet<graph_hunter_core::StrId> =
                std::collections::HashSet::new();
            for &source_sid in graph.get_reverse_source_sids(&req.node_id) {
                if edges.len() >= MAX_EVENTS {
                    break;
                }
                if !seen_sources.insert(source_sid) {
                    continue;
                }
                for compact in graph.get_relations_by_sid(source_sid) {
                    if Some(compact.dest_sid) == target_sid {
                        edges.push(subgraph_edge_from_compact(graph, &compact));
                        break;
                    }
                }
            }
            edges.sort_by_key(|e| e.timestamp);
            Ok(edges)
        })
    }

    /// Paginated variant of [`Self::get_events_for_node`] with optional
    /// `sort_by` key. Default sort is timestamp ascending.
    ///
    /// Collects incident edges as `CompactRelation` (32 bytes, `Copy`),
    /// sorts in place, and only materializes `SubgraphEdge` (which
    /// allocates per-edge `String`s + a metadata `HashMap`) for the
    /// final page slice. The earlier implementation built a
    /// `Vec<SubgraphEdge>` over every incident edge before paginating;
    /// on a URL with 10^5+ incident edges that OOM-crashed the process
    /// while allocating ~10 GB.
    pub fn get_events_paginated(&self, req: EventsPaginatedRequest) -> ApiResult<PaginatedEvents> {
        let page = req.page;
        let page_size = req.page_size.unwrap_or(100);
        let sort_by = req.sort_by.clone();
        self.with_graph_read(req.session.as_ref(), |graph| {
            let mut compacts: Vec<graph_hunter_core::CompactRelation> = Vec::new();

            for compact in graph.get_compact_relations(&req.node_id) {
                compacts.push(compact);
            }
            let target_sid = graph.interner.get(&req.node_id);
            // `reverse_adj` stores one entry per incoming edge (not one
            // per distinct source), so a source `S` with `X` edges to
            // `node_id` appears `X` times. Without this dedup, the
            // inner loop below pushes every matching edge `X` times,
            // inflating `total_count` quadratically.
            let mut seen_sources: HashSet<graph_hunter_core::StrId> = HashSet::new();
            for &source_sid in graph.get_reverse_source_sids(&req.node_id) {
                if !seen_sources.insert(source_sid) {
                    continue;
                }
                for compact in graph.get_relations_by_sid(source_sid) {
                    if Some(compact.dest_sid) == target_sid {
                        compacts.push(compact);
                    }
                }
            }

            // String-keyed sorts resolve SIDs via the interner — that is
            // a `&str` borrow, no allocation.
            match sort_by.as_deref() {
                Some("rel_type") => compacts.sort_by_key(|c| c.rel_type_tag),
                Some("source") => compacts.sort_by(|a, b| {
                    graph
                        .interner
                        .resolve(a.source_sid)
                        .cmp(graph.interner.resolve(b.source_sid))
                }),
                Some("target") => compacts.sort_by(|a, b| {
                    graph
                        .interner
                        .resolve(a.dest_sid)
                        .cmp(graph.interner.resolve(b.dest_sid))
                }),
                _ => compacts.sort_by_key(|c| c.timestamp),
            }

            let total_count = compacts.len();
            let start = (page * page_size).min(total_count);
            let end = (start + page_size).min(total_count);
            let events: Vec<SubgraphEdge> = compacts[start..end]
                .iter()
                .map(|c| subgraph_edge_from_compact(graph, c))
                .collect();
            Ok(PaginatedEvents {
                events,
                total_count,
                page,
                page_size,
            })
        })
    }

    /// Build the complete subgraph (nodes + edges) induced by the given
    /// set of node IDs.
    ///
    /// 2026-05-06 (#13 fix): edges are now paginated. `page_size`
    /// defaults to 5 000 (the legacy implicit cap) and `offset` to 0.
    /// The response carries `total_edges`/`has_more` so callers know
    /// whether to keep walking. Hard ceiling of 50 000 per page to
    /// keep memory bounded — large investigations should chunk
    /// instead of spiking the cap.
    pub fn get_subgraph(&self, req: SubgraphRequest) -> ApiResult<Subgraph> {
        const DEFAULT_PAGE_SIZE: usize = 5_000;
        const MAX_PAGE_SIZE: usize = 50_000;

        let page_size = req
            .page_size
            .unwrap_or(DEFAULT_PAGE_SIZE)
            .min(MAX_PAGE_SIZE)
            .max(1);
        let offset = req.offset.unwrap_or(0);

        self.with_graph_read(req.session.as_ref(), |graph| {
            let id_set: HashSet<&str> = req.node_ids.iter().map(|s| s.as_str()).collect();

            let nodes: Vec<SubgraphNode> = req
                .node_ids
                .iter()
                .filter_map(|id| graph.get_entity(id))
                .map(|e| {
                    SubgraphNode::new(
                        e.id.clone(),
                        format!("{}", e.entity_type),
                        e.score,
                        e.metadata.clone(),
                    )
                })
                .collect();

            // Walk every induced edge once to count the total, but
            // only materialize `SubgraphEdge` for the requested page.
            // This gives the caller honest paging metadata without
            // forcing a second pass.
            let mut total_edges: usize = 0;
            let mut edges: Vec<SubgraphEdge> = Vec::new();
            for source_id in &req.node_ids {
                for compact in graph.get_compact_relations(source_id) {
                    let dest_str = graph.interner.resolve(compact.dest_sid);
                    if !id_set.contains(dest_str) {
                        continue;
                    }
                    let idx = total_edges;
                    total_edges += 1;
                    if idx >= offset && edges.len() < page_size {
                        edges.push(subgraph_edge_from_compact(graph, &compact));
                    }
                }
            }
            let returned_edges = edges.len();
            let has_more = offset + returned_edges < total_edges;
            Ok(Subgraph {
                nodes,
                edges,
                total_edges,
                returned_edges,
                offset,
                page_size,
                has_more,
            })
        })
    }

    /// Substring search over entity IDs with optional type filter. When
    /// `query` is empty a `type_filter` is required — unbounded
    /// enumeration of the whole graph is almost never what a caller
    /// wants and produces poor UX.
    pub fn search_entities(&self, req: SearchEntitiesRequest) -> ApiResult<Vec<SearchResult>> {
        if req.query.is_empty()
            && req
                .type_filter
                .as_deref()
                .map(str::is_empty)
                .unwrap_or(true)
        {
            return Err(ApiError::InvalidInput(
                "query is required when no type_filter is provided (pass type_filter='Host' etc. to list entities of a single type)"
                    .into(),
            ));
        }
        self.with_graph_read(req.session.as_ref(), |graph| {
            let et = req.type_filter.as_deref().and_then(parse_entity_type);
            Ok(graph.search_entities(&req.query, et.as_ref(), req.limit.unwrap_or(50)))
        })
    }

    /// Neighborhood expansion around `node_id`. High-degree nodes auto-
    /// route to grouped mode: if `in_degree + out_degree` exceeds
    /// `AUTO_GROUPED_THRESHOLD`, the neighborhood is built from
    /// `get_neighborhood_grouped` and each edge represents a collapsed
    /// group (see metadata keys `edge_count`, `first_ts`, `last_ts`).
    /// Pinned path nodes from the session are merged into the result so
    /// the analyst's workspace stays visible.
    pub fn expand_node(&self, req: ExpandNodeRequest) -> ApiResult<Neighborhood> {
        let session = self.resolve_session(req.session.as_ref())?;
        let graph = session
            .graph
            .read()
            .map_err(|e| ApiError::Internal(format!("graph lock poisoned: {e}")))?;

        let core_filter = req.filter.as_ref().map(to_core_filter);
        let max_hops = req.max_hops.unwrap_or(1);
        let max_nodes = req.max_nodes.unwrap_or(50);

        let total_degree = match graph.interner.get(&req.node_id) {
            Some(sid) => {
                let out_d = graph.streaming.degree_of(sid);
                let in_d = graph.reverse_adj.get(&sid).map(|v| v.len()).unwrap_or(0);
                out_d + in_d
            }
            None => 0,
        };

        let mut hood = if total_degree > graph_hunter_core::AUTO_GROUPED_THRESHOLD {
            let grouped = graph
                .get_neighborhood_grouped(&req.node_id, max_hops, max_nodes, core_filter.as_ref())
                .ok_or_else(|| ApiError::NotFound(format!("entity: {}", req.node_id)))?;
            let reason = format!(
                "node has {} edges (threshold {}); expand_node auto-routed to grouped mode — each edge represents {} collapsed events (see metadata.edge_count)",
                total_degree,
                graph_hunter_core::AUTO_GROUPED_THRESHOLD,
                grouped.total_edge_count,
            );
            let edges: Vec<NeighborEdge> = grouped
                .edges
                .into_iter()
                .map(|g| {
                    let mut metadata = std::collections::HashMap::new();
                    metadata.insert("edge_count".to_string(), g.count.to_string());
                    metadata.insert("first_ts".to_string(), g.first_ts.to_string());
                    metadata.insert("last_ts".to_string(), g.last_ts.to_string());
                    NeighborEdge {
                        source: g.source,
                        target: g.target,
                        rel_type: g.rel_type,
                        timestamp: g.last_ts,
                        metadata,
                    }
                })
                .collect();
            Neighborhood {
                center: grouped.center,
                nodes: grouped.nodes,
                edges,
                truncated: grouped.truncated,
                auto_grouped: true,
                auto_group_reason: Some(reason),
                hydration: None,
            }
        } else {
            graph
                .get_neighborhood(&req.node_id, max_hops, max_nodes, core_filter.as_ref())
                .ok_or_else(|| ApiError::NotFound(format!("entity: {}", req.node_id)))?
        };

        let path_ids: Vec<String> = session
            .path_node_ids
            .read()
            .map_err(|e| ApiError::Internal(format!("path_node_ids poisoned: {e}")))?
            .clone();
        let mut in_hood: HashSet<String> = hood.nodes.iter().map(|n| n.id.clone()).collect();

        for path_id in path_ids {
            if in_hood.contains(&path_id) {
                continue;
            }
            let Some(entity) = graph.get_entity(&path_id) else {
                continue;
            };
            hood.nodes.push(NeighborNode {
                id: entity.id.clone(),
                entity_type: format!("{}", entity.entity_type),
                score: entity.score,
                metadata: entity.metadata.clone(),
            });
            in_hood.insert(path_id.clone());

            for compact in graph.get_compact_relations(&path_id) {
                let dest_str = graph.interner.resolve(compact.dest_sid);
                if in_hood.contains(dest_str) {
                    let mut meta = graph.meta_store.get(compact.metadata_offset);
                    meta.remove("_rel_type");
                    hood.edges.push(NeighborEdge {
                        source: graph.interner.resolve(compact.source_sid).to_string(),
                        target: dest_str.to_string(),
                        rel_type: graph.resolve_rel_type_name(&compact),
                        timestamp: compact.timestamp,
                        metadata: meta,
                    });
                }
            }
            let target_sid = graph.interner.get(&path_id);
            for &source_sid in graph.get_reverse_source_sids(&path_id) {
                let source_str = graph.interner.resolve(source_sid);
                if !in_hood.contains(source_str) {
                    continue;
                }
                for compact in graph.get_relations_by_sid(source_sid) {
                    if Some(compact.dest_sid) == target_sid {
                        let mut meta = graph.meta_store.get(compact.metadata_offset);
                        meta.remove("_rel_type");
                        hood.edges.push(NeighborEdge {
                            source: graph.interner.resolve(compact.source_sid).to_string(),
                            target: graph.interner.resolve(compact.dest_sid).to_string(),
                            rel_type: graph.resolve_rel_type_name(&compact),
                            timestamp: compact.timestamp,
                            metadata: meta,
                        });
                        break;
                    }
                }
            }
        }

        // No-op if the entity was never seeded; lets the MCP graph://recent-pivots
        // resource flip expanded=true so the nudge stops suggesting node_expand
        // on something the user just explored.
        crate::operations::graph_meta::RECENT_PIVOTS
            .mark_expanded(&req.node_id, hood.nodes.len() as u32);

        Ok(hood)
    }

    /// Force-grouped expansion — always collapses parallel edges, even
    /// for low-degree nodes. Useful when the analyst explicitly wants
    /// the summary view.
    pub fn expand_node_grouped(
        &self,
        req: ExpandNodeRequest,
    ) -> ApiResult<graph_hunter_core::GroupedNeighborhood> {
        self.with_graph_read(req.session.as_ref(), |graph| {
            let core_filter = req.filter.as_ref().map(to_core_filter);
            graph
                .get_neighborhood_grouped(
                    &req.node_id,
                    req.max_hops.unwrap_or(1),
                    req.max_nodes.unwrap_or(50),
                    core_filter.as_ref(),
                )
                .ok_or_else(|| ApiError::NotFound(format!("entity: {}", req.node_id)))
        })
    }

    /// Phase 4 / ANALYSIS (§4.5): immediate neighborhood of an entity. Wraps
    /// `expand_node` and reshapes to the doc contract — the center entity's
    /// attributes plus its directly-connected entities and per-edge metadata.
    /// Pure graph read; no SIEM round-trip (the value over raw KQL pivoting).
    pub fn graph_neighbors(
        &self,
        req: GraphNeighborsRequest,
    ) -> ApiResult<GraphNeighborsResult> {
        let center = req.entity.value.clone();
        let filter = req.edge_filter.clone().map(|rt| ExpandFilter {
            relation_types: Some(rt),
            ..Default::default()
        });
        let hood = self.expand_node(ExpandNodeRequest {
            session: req.session.clone(),
            node_id: center.clone(),
            max_hops: Some(req.degree.unwrap_or(1).max(1)),
            max_nodes: Some(req.max_nodes.unwrap_or(100)),
            filter,
            live: false,
            time_window: None,
        })?;

        // Center entity class + attributes (label from metadata when present).
        let (center_class, attributes, label) =
            self.with_graph_read(req.session.as_ref(), |g| {
                Ok(match g.get_entity(&center) {
                    Some(e) => (
                        format!("{}", e.entity_type),
                        e.metadata.clone(),
                        e.metadata.get("label").cloned(),
                    ),
                    None => (
                        req.entity.class.clone().unwrap_or_default(),
                        std::collections::HashMap::new(),
                        None,
                    ),
                })
            })?;

        // node id → class, for rendering neighbor refs.
        let class_of: std::collections::HashMap<&str, &str> = hood
            .nodes
            .iter()
            .map(|n| (n.id.as_str(), n.entity_type.as_str()))
            .collect();

        let mut neighbors = Vec::new();
        for edge in &hood.edges {
            let other = if edge.source == center {
                &edge.target
            } else if edge.target == center {
                &edge.source
            } else {
                continue; // edge between two neighbors (degree>1) — not incident to center
            };
            neighbors.push(NeighborItem {
                edge: edge.rel_type.clone(),
                node: NeighborRef {
                    class: class_of.get(other.as_str()).copied().unwrap_or("").to_string(),
                    value: other.clone(),
                },
                attributes: edge.metadata.clone(),
            });
        }

        Ok(GraphNeighborsResult {
            entity: NeighborsCenter { class: center_class, value: center, label },
            attributes,
            neighbors,
        })
    }

    /// Phase 4 / ANALYSIS (§4.4): paths between two entities (or all outbound
    /// paths up to `max_depth` when `to_entity` is omitted). Pure graph
    /// traversal — chains that KQL would resolve with repeated joins are one
    /// precomputed walk here. IP nodes carry their geoip enrichment inline.
    pub fn graph_path(&self, req: GraphPathRequest) -> ApiResult<GraphPathResult> {
        let rel_filter: Option<Vec<graph_hunter_core::RelationType>> = req
            .edge_filter
            .as_ref()
            .map(|v| v.iter().filter_map(|s| parse_relation_type(s)).collect());
        // An all-unknown filter would silently match nothing; treat empty as "no filter".
        let rel_filter = rel_filter.filter(|v| !v.is_empty());
        let max_depth = req.max_depth.unwrap_or(4).clamp(1, 8);
        let max_paths = req.max_paths.unwrap_or(50).clamp(1, 500);
        let to_value = req.to_entity.as_ref().map(|e| e.value.clone());

        self.with_graph_read(req.session.as_ref(), |g| {
            let paths = g.find_paths(
                &req.from_entity.value,
                to_value.as_deref(),
                max_depth,
                rel_filter.as_deref(),
                max_paths,
            );
            let paths = paths
                .into_iter()
                .map(|hops| {
                    let length = hops.len().saturating_sub(1);
                    let hops = hops
                        .into_iter()
                        .map(|h| {
                            let geoip = g.get_entity(&h.node_id).and_then(|e| {
                                e.metadata
                                    .get("geo_country")
                                    .or_else(|| e.metadata.get("geo_country_code"))
                                    .cloned()
                            });
                            PathHopDto {
                                edge: h.edge,
                                node: PathNode { class: h.node_class, value: h.node_id, geoip },
                            }
                        })
                        .collect();
                    PathDto { length, hops }
                })
                .collect();
            Ok(GraphPathResult { paths })
        })
    }

    /// Phase 4 / ANALYSIS (§4.6): structural anomalies — entities whose
    /// degree / betweenness / isolation is atypical for their class. Reuses the
    /// per-entity centrality from scoring and reports z-scores. Pure graph read.
    pub fn graph_anomaly(&self, req: GraphAnomalyRequest) -> ApiResult<GraphAnomalyResult> {
        let metric = req.metric.as_deref().unwrap_or("all");
        if !matches!(metric, "degree" | "betweenness" | "isolation" | "all") {
            return Err(ApiError::InvalidInput(format!(
                "metric must be one of degree|betweenness|isolation|all (got '{metric}')"
            )));
        }
        let top_n = req.top_n.unwrap_or(20).clamp(1, 500);
        self.with_graph_read(req.session.as_ref(), |g| {
            let hits = g.structural_anomalies(metric, req.node_class.as_deref(), top_n);
            let anomalies = hits
                .into_iter()
                .map(|h| AnomalyItem {
                    entity: NeighborRef { class: h.node_class, value: h.node_id },
                    metric: h.metric,
                    observation: h.observation,
                    z_score: h.z_score,
                })
                .collect();
            Ok(GraphAnomalyResult { anomalies })
        })
    }

    /// Top-N heaviest (source → target : rel_type) groups ranked by edge
    /// count. Delegates directly to `GraphHunter::heavy_edges`.
    pub fn graph_heavy_edges(
        &self,
        req: HeavyEdgesRequest,
    ) -> ApiResult<Vec<graph_hunter_core::analytics::HeavyEdge>> {
        let opts = graph_hunter_core::analytics::HeavyEdgesOpts {
            top_n: req.top_n.unwrap_or(50),
            min_count: req.min_count,
            rel_type: req.rel_type,
        };
        self.with_graph_read(req.session.as_ref(), |graph| Ok(graph.heavy_edges(&opts)))
    }

    /// Per-channel temporal behavior: beaconing score, reset bursts, and
    /// volume spikes for each (source → target : rel_type). Delegates
    /// directly to `GraphHunter::channel_behavior`.
    pub fn graph_channel_behavior(
        &self,
        req: ChannelBehaviorRequest,
    ) -> ApiResult<Vec<graph_hunter_core::analytics::ChannelBehavior>> {
        use graph_hunter_core::analytics::{ChannelBehaviorOpts, ChannelSortBy};
        let sort_by = match req.sort_by.as_deref() {
            Some("resets") => ChannelSortBy::Resets,
            Some("volume") => ChannelSortBy::Volume,
            _ => ChannelSortBy::Beacon,
        };
        let opts = ChannelBehaviorOpts {
            top_n: req.top_n.unwrap_or(50),
            min_count: req.min_count.or(Some(4)),
            window_secs: req.window_secs.unwrap_or(60),
            rel_type: req.rel_type,
            sort_by,
        };
        self.with_graph_read(req.session.as_ref(), |graph| Ok(graph.channel_behavior(&opts)))
    }

    /// Live-backed expansion (Enfoque A): hydrate the target node from
    /// Sentinel (when possible), then run the synchronous `expand_node`
    /// and attach the hydration outcome. Soft no-op (skipped outcome)
    /// when the session is not Sentinel-capable or the type is unmapped.
    pub async fn expand_node_live(
        &self,
        req: ExpandNodeRequest,
    ) -> ApiResult<graph_hunter_core::analytics::Neighborhood> {
        use graph_hunter_core::analytics::HydrationOutcome;

        if !req.live {
            return self.expand_node(req);
        }

        // Clone the values we need before moving `req` into `expand_node`.
        let node_id = req.node_id.clone();
        let session_handle = req.session.clone();
        let time_filter = req
            .time_window
            .as_ref()
            .map(|w| w.kql_filter())
            .unwrap_or_else(|| "where TimeGenerated > ago(24h)".to_string());

        // Resolve the node's entity type (brief read lock).
        let entity_type = {
            let session = self.resolve_session(session_handle.as_ref())?;
            let graph = session
                .graph
                .read()
                .map_err(|e| ApiError::Internal(format!("graph lock poisoned: {e}")))?;
            graph.get_entity(&node_id).map(|e| e.entity_type.clone())
        };

        let creds = (
            std::env::var("AZURE_WORKSPACE_ID").ok(),
            std::env::var("AZURE_TENANT_ID").ok(),
            std::env::var("AZURE_CLIENT_ID").ok(),
            std::env::var("AZURE_CLIENT_SECRET").ok(),
        );

        let skip = |reason: &str| HydrationOutcome {
            skipped: true,
            reason: Some(reason.to_string()),
            new_entities: 0,
            new_relations: 0,
            tables_hit: 0,
            tables_attempted: 0,
        };

        let outcome = match (entity_type, creds) {
            (None, _) => skip("node not in graph; cannot infer entity type"),
            (
                Some(ty),
                (Some(ws), Some(tenant), Some(client), Some(secret)),
            ) => {
                let transport = graph_hunter_siem::HttpSentinelTransport::new();
                let cache = graph_hunter_siem::SentinelTokenCache::new();
                let auth = graph_hunter_siem::SentinelAuth {
                    tenant_id: tenant,
                    client_id: client,
                    client_secret: secret,
                };
                self.hydrate_node_with(
                    &transport,
                    &cache,
                    &node_id,
                    &ty,
                    &time_filter,
                    &ws,
                    &auth,
                    "Sentinel Hydration (live)",
                )
                .await
                .unwrap_or_else(|e| skip(&format!("hydration error: {e}")))
            }
            (Some(_), _) => skip(
                "Azure credentials not configured (set AZURE_* or connect Sentinel)",
            ),
        };

        let mut hood = self.expand_node(req)?;
        hood.hydration = Some(outcome);
        Ok(hood)
    }
}

/// Build a [`SubgraphEdge`] from a core [`graph_hunter_core::CompactRelation`]
/// owned by `graph`. Small helper to avoid repeating the same 6-field
/// materialization in every read path.
fn subgraph_edge_from_compact(
    graph: &graph_hunter_core::GraphHunter,
    compact: &graph_hunter_core::CompactRelation,
) -> SubgraphEdge {
    let mut metadata = graph.meta_store.get(compact.metadata_offset);
    metadata.remove("_rel_type");
    SubgraphEdge {
        source: graph.interner.resolve(compact.source_sid).to_string(),
        target: graph.interner.resolve(compact.dest_sid).to_string(),
        rel_type: graph.resolve_rel_type_name(compact),
        timestamp: compact.timestamp,
        metadata,
        dataset_id: graph
            .resolve_dataset_tag(compact.dataset_tag)
            .map(|s| s.to_string()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state::Session;
    use graph_hunter_core::GraphHunter;
    use std::sync::Arc;

    #[test]
    fn graph_stats_empty() {
        let api = GraphHunterApi::new_noop();
        let s = Arc::new(Session::new("s1", "t", GraphHunter::new(), 0));
        api.sessions().insert(s);
        api.sessions().set_current(Some("s1".into()));
        let stats = api.get_graph_stats(SessionOnly::default()).unwrap();
        assert_eq!(stats.entity_count, 0);
        assert_eq!(stats.relation_count, 0);
    }

    #[test]
    fn runtime_info_has_isa() {
        let api = GraphHunterApi::new_noop();
        let ri = api.runtime_info();
        // Exact value depends on build; just assert it's non-empty so
        // callers can trust the field is populated.
        assert!(!ri.simd_isa.is_empty());
    }

    #[test]
    fn preview_fields_missing_file_is_io() {
        let api = GraphHunterApi::new_noop();
        let err = api
            .preview_fields(PreviewFieldsRequest {
                path: "Z:/does/not/exist.ndjson".to_string(),
                sample_size: None,
            })
            .unwrap_err();
        assert!(matches!(err, ApiError::Io(_)));
    }
}

#[cfg(test)]
mod expand_live_tests {
    use super::*;
    use crate::dto::session::CreateSessionRequest;
    use crate::dto::v1::graph_ops::ExpandNodeRequest;

    #[tokio::test]
    async fn expand_live_without_creds_soft_skips_and_still_expands() {
        // Ensure no Azure creds in this test process (new_noop does not load .env).
        for k in [
            "AZURE_WORKSPACE_ID",
            "AZURE_TENANT_ID",
            "AZURE_CLIENT_ID",
            "AZURE_CLIENT_SECRET",
        ] {
            // SAFETY: no other test in this binary reads AZURE_* from the
            // process environment (the production readers in sentinel.rs are
            // not exercised by any test; hydrate_tests passes creds as
            // literals), so stripping them races with no concurrent observer.
            // A future test calling sentinel_check_env/connect_sentinel must
            // serialize against this one or pass creds via request fields.
            unsafe { std::env::remove_var(k) };
        }
        let api = GraphHunterApi::new_noop();
        api.create_session(CreateSessionRequest {
            name: Some("expand-live-test".into()),
        })
        .expect("create_session");
        // Seed a single IP node so the wrapper can resolve its entity type.
        {
            let session = api.resolve_session(None).expect("session");
            let mut g = session.graph.write().unwrap();
            g.add_entity(graph_hunter_core::Entity::new(
                "10.0.0.9",
                graph_hunter_core::types::EntityType::IP,
            ))
            .unwrap();
        }

        let hood = api
            .expand_node_live(ExpandNodeRequest {
                session: None,
                node_id: "10.0.0.9".into(),
                max_hops: Some(1),
                max_nodes: Some(50),
                filter: None,
                live: true,
                time_window: None,
            })
            .await
            .expect("expand_node_live ok");

        let h = hood
            .hydration
            .expect("hydration block present on live expand");
        assert!(
            h.skipped,
            "should soft-skip without creds, reason: {:?}",
            h.reason
        );
        assert_eq!(hood.center, "10.0.0.9");
    }

    #[tokio::test]
    async fn expand_non_live_has_no_hydration_block() {
        let api = GraphHunterApi::new_noop();
        api.create_session(CreateSessionRequest {
            name: Some("expand-nolive".into()),
        })
        .expect("create_session");
        {
            let session = api.resolve_session(None).expect("session");
            let mut g = session.graph.write().unwrap();
            g.add_entity(graph_hunter_core::Entity::new(
                "host-1",
                graph_hunter_core::types::EntityType::Host,
            ))
            .unwrap();
        }
        let hood = api
            .expand_node_live(ExpandNodeRequest {
                session: None,
                node_id: "host-1".into(),
                max_hops: Some(1),
                max_nodes: Some(50),
                filter: None,
                live: false,
                time_window: None,
            })
            .await
            .expect("ok");
        assert!(
            hood.hydration.is_none(),
            "non-live expand must not attach hydration"
        );
    }
}

#[cfg(test)]
mod graph_neighbors_tests {
    use super::*;
    use crate::dto::session::CreateSessionRequest;
    use crate::dto::v1::graph_ops::{EntityRef, GraphNeighborsRequest};
    use graph_hunter_core::entity::Entity;
    use graph_hunter_core::relation::Relation;
    use graph_hunter_core::types::{EntityType, RelationType};

    #[test]
    fn neighbors_reshapes_to_doc_contract() {
        let api = GraphHunterApi::new_noop();
        api.create_session(CreateSessionRequest { name: Some("nbr-test".into()) })
            .unwrap();
        {
            let session = api.resolve_session(None).unwrap();
            let mut g = session.graph.write().unwrap();
            let user = Entity::new("alice@corp.com", EntityType::User);
            let ip = Entity::new("203.0.113.7", EntityType::IP);
            let rel = Relation::new("alice@corp.com", "203.0.113.7", RelationType::Auth, 1_700_000_000)
                .with_metadata("ResultType", "0");
            g.insert_triples(vec![(user, rel, ip)], Some("test")).unwrap();
        }

        let res = api
            .graph_neighbors(GraphNeighborsRequest {
                session: None,
                entity: EntityRef { class: Some("User".into()), value: "alice@corp.com".into() },
                degree: Some(1),
                edge_filter: None,
                max_nodes: None,
            })
            .expect("graph_neighbors");

        assert_eq!(res.entity.class, "User");
        assert_eq!(res.entity.value, "alice@corp.com");
        let ip_nbr = res
            .neighbors
            .iter()
            .find(|n| n.node.value == "203.0.113.7")
            .expect("IP neighbor present");
        assert_eq!(ip_nbr.node.class, "IP");
        assert_eq!(ip_nbr.edge, "Auth");
        assert_eq!(ip_nbr.attributes.get("ResultType").map(String::as_str), Some("0"));
    }

    #[test]
    fn edge_filter_restricts_relation_types() {
        let api = GraphHunterApi::new_noop();
        api.create_session(CreateSessionRequest { name: Some("nbr-filter".into()) })
            .unwrap();
        {
            let session = api.resolve_session(None).unwrap();
            let mut g = session.graph.write().unwrap();
            let u = Entity::new("alice@corp.com", EntityType::User);
            let ip = Entity::new("203.0.113.7", EntityType::IP);
            let host = Entity::new("HOST1", EntityType::Host);
            g.insert_triples(
                vec![(
                    u.clone(),
                    Relation::new("alice@corp.com", "203.0.113.7", RelationType::Auth, 1),
                    ip,
                )],
                Some("test"),
            )
            .unwrap();
            g.insert_triples(
                vec![(
                    u,
                    Relation::new("alice@corp.com", "HOST1", RelationType::Connect, 1),
                    host,
                )],
                Some("test"),
            )
            .unwrap();
        }
        let res = api
            .graph_neighbors(GraphNeighborsRequest {
                session: None,
                entity: EntityRef { class: None, value: "alice@corp.com".into() },
                degree: Some(1),
                edge_filter: Some(vec!["Auth".into()]),
                max_nodes: None,
            })
            .expect("graph_neighbors");
        assert!(res.neighbors.iter().all(|n| n.edge == "Auth"), "only Auth edges pass the filter");
        assert!(res.neighbors.iter().any(|n| n.node.value == "203.0.113.7"));
    }
}
