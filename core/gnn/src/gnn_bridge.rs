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

use graph_hunter_core::graph::GraphHunter;
use graph_hunter_core::interner::StrId;
use graph_hunter_core::types::EntityType;

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
        if let Some(arc) = graph.streaming.neighbors_arc(current) {
            let g = arc.read();
            for edge in g.as_slice() {
                if ordered_nodes.len() >= K_MAX {
                    break;
                }
                let dest_sid = edge.dest_sid;
                if visited.insert(dest_sid) {
                    ordered_nodes.push(dest_sid);
                    queue.push_back((dest_sid, depth + 1));
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
        let out_degree = graph.streaming.degree_of(sid);
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
            if let Some(arc) = graph.streaming.neighbors_arc(src_sid) {
                let g = arc.read();
                for edge in g.as_slice() {
                    if let Some(&dst_idx) = sid_to_idx.get(&edge.dest_sid) {
                        adjacency[src_idx * K_MAX + dst_idx] = 1.0;
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

// ══════════════════════════════════════════════════════════════════
// D.1 — GNN v2: cloud-identity feature extension
// ══════════════════════════════════════════════════════════════════
//
// v1 (D_NODE=16) was trained on endpoint corpora (DARPA OpTC). During
// the re-hunt the v1 model scored a confirmed attacker IP at
// gnn_threat=0, proving its feature vector has no signal for cloud
// identity. v2 adds 8 dims covering the Auth/app/geo surface:
//
//   dims 16        : is_cloud_auth (1.0 if node participates in Auth
//                    rel with `app` metadata populated)
//   dims 17..=22   : auth_app_bucket one-hot (6 classes: Browser,
//                    PowerShell, MobileApp, AuthAgent, DeviceCode,
//                    Other)
//   dim 23         : geo_country_hash — stable hash of geo_country /
//                    location metadata bucketed to [0,1], 0 if missing
//
// The v2 extractor produces SubgraphFeaturesV2 and v1 is untouched so
// the existing model stays runnable until v2 graduates.

/// Node feature dim for v2 (v1 had 16).
pub const D_NODE_V2: usize = 24;

/// Total v2 GNN input: same adjacency but wider node features.
pub const GNN_INPUT_DIM_V2: usize = K_MAX * D_NODE_V2 + K_MAX * K_MAX;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SubgraphFeaturesV2 {
    pub node_features: Vec<f32>,
    pub adjacency: Vec<f32>,
    pub num_nodes: usize,
    pub node_ids: Vec<String>,
}

impl SubgraphFeaturesV2 {
    pub fn to_input_tensor(&self) -> Vec<f32> {
        let mut t = Vec::with_capacity(GNN_INPUT_DIM_V2);
        t.extend_from_slice(&self.node_features);
        t.extend_from_slice(&self.adjacency);
        debug_assert_eq!(t.len(), GNN_INPUT_DIM_V2);
        t
    }
}

/// App-family one-hot index used by v2 feature extraction.
/// Bucketing keeps cardinality bounded — any app not in these classes
/// lands in `Other` (index 5).
fn app_bucket_index(app: &str) -> usize {
    let a = app.to_ascii_lowercase();
    if a.contains("browser") || a.contains("chrome") || a.contains("edge") {
        0
    } else if a.contains("powershell") || a.contains("aad powershell") || a.contains("azure cli") {
        1
    } else if a.contains("mobile") || a.contains("ios") || a.contains("android") || a.contains("outlook") {
        2
    } else if a.contains("authenticator") || a.contains("auth agent") || a.contains("sso") {
        3
    } else if a.contains("device code") || a.contains("msol") {
        4
    } else {
        5
    }
}

/// Stable hash of a geo-country / location string into [0.0, 1.0].
/// Collisions are fine — the model only needs a group signal, not
/// identity. Missing metadata returns 0.0.
fn geo_country_hash(meta: &std::collections::HashMap<String, String>) -> f32 {
    let s = meta
        .get("geo_country")
        .or_else(|| meta.get("country"))
        .or_else(|| meta.get("location"))
        .cloned()
        .unwrap_or_default();
    if s.is_empty() {
        return 0.0;
    }
    let mut hash: u32 = 0x811c_9dc5;
    for b in s.bytes() {
        hash ^= b as u32;
        hash = hash.wrapping_mul(0x0100_0193);
    }
    (hash as f32) / (u32::MAX as f32)
}

/// Extract v2 subgraph features with the cloud-identity dims layered on
/// top of v1's 16. Delegates to the v1 extractor for the structural
/// features then patches in the new dims.
pub fn extract_subgraph_features_v2(
    graph: &GraphHunter,
    center: &str,
    k_hops: usize,
) -> Option<SubgraphFeaturesV2> {
    let v1 = extract_subgraph_features(graph, center, k_hops)?;
    let mut node_features = vec![0.0f32; K_MAX * D_NODE_V2];

    // Copy the v1 [K_MAX x D_NODE] block into the first 16 columns of
    // the v2 [K_MAX x D_NODE_V2] matrix. Zero-pad the rest.
    for i in 0..K_MAX {
        let src_off = i * D_NODE;
        let dst_off = i * D_NODE_V2;
        node_features[dst_off..dst_off + D_NODE]
            .copy_from_slice(&v1.node_features[src_off..src_off + D_NODE]);
    }

    // Now layer the 8 new dims per real node.
    for (i, id) in v1.node_ids.iter().enumerate() {
        let entity = match graph.get_entity(id) {
            Some(e) => e,
            None => continue,
        };
        let dst_off = i * D_NODE_V2;

        // Find the `app` metadata value on ANY Auth edge touching this
        // node, if any. First match wins — we only care about the
        // family-of-app signal, not cardinality.
        let mut is_cloud_auth: f32 = 0.0;
        let mut app_bucket: Option<usize> = None;
        if let Some(sid) = graph.interner.get(id) {
            if let Some(arc) = graph.streaming.neighbors_arc(sid) {
                let g = arc.read();
                for edge in g.as_slice() {
                    if edge.rel_type_tag != 0 /* Auth */ {
                        continue;
                    }
                    if edge.metadata_offset == 0 {
                        continue;
                    }
                    let meta = graph.meta_store.get(edge.metadata_offset);
                    if let Some(app) = meta.get("app") {
                        is_cloud_auth = 1.0;
                        app_bucket = Some(app_bucket_index(app));
                        break;
                    }
                }
            }
        }
        node_features[dst_off + 16] = is_cloud_auth;
        if let Some(b) = app_bucket {
            // Six one-hot dims at [17..=22].
            if b < 6 {
                node_features[dst_off + 17 + b] = 1.0;
            }
        }
        node_features[dst_off + 23] = geo_country_hash(&entity.metadata);
    }

    Some(SubgraphFeaturesV2 {
        node_features,
        adjacency: v1.adjacency,
        num_nodes: v1.num_nodes,
        node_ids: v1.node_ids,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use graph_hunter_core::entity::Entity;
    use graph_hunter_core::relation::Relation;
    use graph_hunter_core::types::{EntityType, RelationType};

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
