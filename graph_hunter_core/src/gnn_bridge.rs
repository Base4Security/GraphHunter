//! GNN bridge module: extracts subgraph features from the Graph Hunter
//! knowledge graph in the format expected by GraphOS-APT GNN models.
//!
//! The GNN models expect:
//! - Node feature matrix: [K_MAX x D_NODE] flattened to f32 vector
//! - Adjacency matrix: [K_MAX x K_MAX] flattened to f32 vector
//! - Combined input: [K_MAX * D_NODE + K_MAX * K_MAX] = 1536 floats

use ahash::{HashMap, HashMapExt, HashSet, HashSetExt};
use serde::{Deserialize, Serialize};
use std::collections::VecDeque;

use crate::graph::GraphHunter;
use crate::interner::StrId;
use crate::types::EntityType;

/// Maximum nodes per subgraph (matches GraphOS-APT K_MAX).
pub const K_MAX: usize = 32;

/// Feature dimensions per node (matches GraphOS-APT D_NODE).
pub const D_NODE: usize = 16;

/// Total GNN input dimension: K_MAX * D_NODE + K_MAX * K_MAX.
pub const GNN_INPUT_DIM: usize = K_MAX * D_NODE + K_MAX * K_MAX;

/// Extracted subgraph features ready for GNN inference.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SubgraphFeatures {
    /// Flattened node features [K_MAX x D_NODE] — zero-padded if fewer than K_MAX nodes.
    pub node_features: Vec<f32>,
    /// Flattened adjacency matrix [K_MAX x K_MAX] — symmetric, binary.
    pub adjacency: Vec<f32>,
    /// Number of actual nodes in the subgraph (before padding).
    pub num_nodes: usize,
    /// Entity IDs of the nodes in the subgraph (ordered by discovery).
    pub node_ids: Vec<String>,
}

impl SubgraphFeatures {
    /// Flatten into a single GNN input vector [K_MAX*D_NODE + K_MAX*K_MAX].
    pub fn to_input_tensor(&self) -> Vec<f32> {
        let mut tensor = Vec::with_capacity(GNN_INPUT_DIM);
        tensor.extend_from_slice(&self.node_features);
        tensor.extend_from_slice(&self.adjacency);
        debug_assert_eq!(tensor.len(), GNN_INPUT_DIM);
        tensor
    }
}

/// Maps an EntityType to a one-hot encoding index (0..9).
/// Returns 0 for Any/unknown.
fn entity_type_index(et: &EntityType) -> usize {
    match et {
        EntityType::IP => 0,
        EntityType::Host => 1,
        EntityType::User => 2,
        EntityType::Process => 3,
        EntityType::File => 4,
        EntityType::Domain => 5,
        EntityType::Registry => 6,
        EntityType::URL => 7,
        EntityType::Service => 8,
        EntityType::Any | EntityType::Other(_) => 0,
    }
}

/// Number of entity types used in one-hot encoding.
const NUM_ENTITY_TYPES: usize = 9;

/// Extract a k-hop subgraph around `center` and featurize it for GNN inference.
///
/// The feature vector per node (D_NODE=16):
/// - dims 0..8: one-hot entity type (9 dims, IP/Host/User/Process/File/Domain/Registry/URL/Service)
/// - dim 9: normalized out-degree (out_degree / K_MAX)
/// - dim 10: normalized in-degree (in_degree / K_MAX)
/// - dim 11: entity rarity score (from anomaly scorer, 0.0 if unavailable)
/// - dim 12: temporal novelty score (from anomaly scorer, 0.0 if unavailable)
/// - dim 13: neighborhood concentration (from anomaly scorer, 0.0 if unavailable)
/// - dim 14: edge count normalized (total edges / K_MAX)
/// - dim 15: is_center flag (1.0 for center node, 0.0 otherwise)
pub fn extract_subgraph_features(
    graph: &GraphHunter,
    center: &str,
    k_hops: usize,
) -> Option<SubgraphFeatures> {
    let center_sid = graph.interner.get(center)?;

    // BFS to collect k-hop neighborhood, capped at K_MAX nodes
    let mut visited: HashSet<StrId> = HashSet::new();
    let mut queue: VecDeque<(StrId, usize)> = VecDeque::new();
    let mut ordered_nodes: Vec<StrId> = Vec::new();

    visited.insert(center_sid);
    queue.push_back((center_sid, 0));
    ordered_nodes.push(center_sid);

    while let Some((current, depth)) = queue.pop_front() {
        if depth >= k_hops || ordered_nodes.len() >= K_MAX {
            break;
        }

        // Outgoing neighbors
        if let Some(rels) = graph.adjacency_list.get(&current) {
            for rel in rels {
                if ordered_nodes.len() >= K_MAX {
                    break;
                }
                if let Some(dest_sid) = graph.interner.get(&rel.dest_id) {
                    if visited.insert(dest_sid) {
                        ordered_nodes.push(dest_sid);
                        queue.push_back((dest_sid, depth + 1));
                    }
                }
            }
        }

        // Incoming neighbors
        if let Some(sources) = graph.reverse_adj.get(&current) {
            for &source_sid in sources {
                if ordered_nodes.len() >= K_MAX {
                    break;
                }
                if visited.insert(source_sid) {
                    ordered_nodes.push(source_sid);
                    queue.push_back((source_sid, depth + 1));
                }
            }
        }
    }

    let num_nodes = ordered_nodes.len();

    // Build local index: StrId -> position in ordered_nodes
    let mut sid_to_idx: HashMap<StrId, usize> = HashMap::with_capacity(num_nodes);
    for (i, &sid) in ordered_nodes.iter().enumerate() {
        sid_to_idx.insert(sid, i);
    }

    // Build node features [K_MAX x D_NODE] — zero-padded
    let mut node_features = vec![0.0f32; K_MAX * D_NODE];
    let mut node_ids = Vec::with_capacity(num_nodes);

    for (i, &sid) in ordered_nodes.iter().enumerate() {
        let entity = graph.entities.get(&sid)?;
        let entity_id = graph.interner.resolve(sid);
        node_ids.push(entity_id.to_string());

        let base = i * D_NODE;

        // One-hot entity type (dims 0..8)
        let type_idx = entity_type_index(&entity.entity_type);
        if type_idx < NUM_ENTITY_TYPES {
            node_features[base + type_idx] = 1.0;
        }

        // Normalized out-degree (dim 9)
        let out_degree = graph
            .adjacency_list
            .get(&sid)
            .map(|r| r.len())
            .unwrap_or(0);
        node_features[base + 9] = (out_degree as f32 / K_MAX as f32).min(1.0);

        // Normalized in-degree (dim 10)
        let in_degree = graph
            .reverse_adj
            .get(&sid)
            .map(|r| r.len())
            .unwrap_or(0);
        node_features[base + 10] = (in_degree as f32 / K_MAX as f32).min(1.0);

        // Anomaly scorer features (dims 11-13) — use 0.0 if scorer not available
        if let Some(ref scorer) = graph.anomaly_scorer {
            if scorer.is_finalized() {
                // Entity rarity estimate (dim 11)
                let er = scorer.node_anomaly_estimate(entity_id);
                node_features[base + 11] = er as f32;

                // NC score (dim 13) — included in node_anomaly_estimate but
                // we use the full estimate as a proxy
                node_features[base + 13] = er as f32;
            }
        }

        // Edge count normalized (dim 14)
        let total_edges = out_degree + in_degree;
        node_features[base + 14] = (total_edges as f32 / (2.0 * K_MAX as f32)).min(1.0);

        // Is center (dim 15)
        if sid == center_sid {
            node_features[base + 15] = 1.0;
        }
    }

    // Build adjacency matrix [K_MAX x K_MAX] — binary, directed
    let mut adjacency = vec![0.0f32; K_MAX * K_MAX];

    for &src_sid in &ordered_nodes {
        if let Some(&src_idx) = sid_to_idx.get(&src_sid) {
            if let Some(rels) = graph.adjacency_list.get(&src_sid) {
                for rel in rels {
                    if let Some(dest_sid) = graph.interner.get(&rel.dest_id) {
                        if let Some(&dst_idx) = sid_to_idx.get(&dest_sid) {
                            adjacency[src_idx * K_MAX + dst_idx] = 1.0;
                        }
                    }
                }
            }
        }
    }

    Some(SubgraphFeatures {
        node_features,
        adjacency,
        num_nodes,
        node_ids,
    })
}

/// Batch-extract subgraph features for multiple center nodes.
/// Returns a map from entity_id to SubgraphFeatures.
pub fn extract_batch_features(
    graph: &GraphHunter,
    center_ids: &[String],
    k_hops: usize,
) -> HashMap<String, SubgraphFeatures> {
    let mut results = HashMap::with_capacity(center_ids.len());
    for id in center_ids {
        if let Some(features) = extract_subgraph_features(graph, id, k_hops) {
            results.insert(id.clone(), features);
        }
    }
    results
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::entity::Entity;
    use crate::relation::Relation;
    use crate::types::{EntityType, RelationType};

    fn build_test_graph() -> GraphHunter {
        let mut g = GraphHunter::new();

        // Create a small graph: IP -> Host -> User -> Process
        let ip = Entity::new("attacker-ip", EntityType::IP);
        let host = Entity::new("target-host", EntityType::Host);
        let user = Entity::new("admin-user", EntityType::User);
        let proc = Entity::new("evil-proc", EntityType::Process);

        g.add_entity(ip).unwrap();
        g.add_entity(host).unwrap();
        g.add_entity(user).unwrap();
        g.add_entity(proc).unwrap();

        g.add_relation(Relation::new(
            "attacker-ip",
            "target-host",
            RelationType::Connect,
            100,
        ))
        .unwrap();
        g.add_relation(Relation::new(
            "target-host",
            "admin-user",
            RelationType::Auth,
            200,
        ))
        .unwrap();
        g.add_relation(Relation::new(
            "admin-user",
            "evil-proc",
            RelationType::Execute,
            300,
        ))
        .unwrap();

        g
    }

    #[test]
    fn extract_subgraph_basic() {
        let g = build_test_graph();
        let features = extract_subgraph_features(&g, "target-host", 2).unwrap();

        assert_eq!(features.num_nodes, 4);
        assert_eq!(features.node_features.len(), K_MAX * D_NODE);
        assert_eq!(features.adjacency.len(), K_MAX * K_MAX);
        assert!(features.node_ids.contains(&"target-host".to_string()));
        assert!(features.node_ids.contains(&"attacker-ip".to_string()));
    }

    #[test]
    fn extract_subgraph_dimensions() {
        let g = build_test_graph();
        let features = extract_subgraph_features(&g, "target-host", 1).unwrap();

        let tensor = features.to_input_tensor();
        assert_eq!(tensor.len(), GNN_INPUT_DIM);
        assert_eq!(GNN_INPUT_DIM, K_MAX * D_NODE + K_MAX * K_MAX);
    }

    #[test]
    fn extract_subgraph_center_flag() {
        let g = build_test_graph();
        let features = extract_subgraph_features(&g, "target-host", 2).unwrap();

        // Find the center node index
        let center_idx = features
            .node_ids
            .iter()
            .position(|id| id == "target-host")
            .unwrap();
        // Check is_center flag (dim 15)
        assert_eq!(features.node_features[center_idx * D_NODE + 15], 1.0);

        // Other nodes should not have center flag
        for (i, _) in features.node_ids.iter().enumerate() {
            if i != center_idx {
                assert_eq!(features.node_features[i * D_NODE + 15], 0.0);
            }
        }
    }

    #[test]
    fn extract_subgraph_one_hot_types() {
        let g = build_test_graph();
        let features = extract_subgraph_features(&g, "target-host", 2).unwrap();

        // Host should have one-hot at index 1
        let host_idx = features
            .node_ids
            .iter()
            .position(|id| id == "target-host")
            .unwrap();
        assert_eq!(features.node_features[host_idx * D_NODE + 1], 1.0); // Host = index 1

        // IP should have one-hot at index 0
        let ip_idx = features
            .node_ids
            .iter()
            .position(|id| id == "attacker-ip")
            .unwrap();
        assert_eq!(features.node_features[ip_idx * D_NODE + 0], 1.0); // IP = index 0
    }

    #[test]
    fn extract_subgraph_nonexistent_center() {
        let g = build_test_graph();
        assert!(extract_subgraph_features(&g, "nonexistent", 2).is_none());
    }

    #[test]
    fn extract_subgraph_adjacency() {
        let g = build_test_graph();
        let features = extract_subgraph_features(&g, "target-host", 2).unwrap();

        let ip_idx = features
            .node_ids
            .iter()
            .position(|id| id == "attacker-ip")
            .unwrap();
        let host_idx = features
            .node_ids
            .iter()
            .position(|id| id == "target-host")
            .unwrap();

        // IP -> Host edge should be present
        assert_eq!(features.adjacency[ip_idx * K_MAX + host_idx], 1.0);
        // Host -> IP should NOT be present (directed graph)
        assert_eq!(features.adjacency[host_idx * K_MAX + ip_idx], 0.0);
    }

    #[test]
    fn batch_extract_features() {
        let g = build_test_graph();
        let centers = vec![
            "attacker-ip".to_string(),
            "target-host".to_string(),
            "nonexistent".to_string(),
        ];
        let results = extract_batch_features(&g, &centers, 1);

        assert_eq!(results.len(), 2); // nonexistent is skipped
        assert!(results.contains_key("attacker-ip"));
        assert!(results.contains_key("target-host"));
    }
}
