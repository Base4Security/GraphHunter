//! D.1 — AAD SigninLogs → GNN v2 training corpus.
//!
//! Converts a JSON dump of Azure AD `SigninLogs` into the training
//! format expected by the GNN v2 pipeline: one JSON object per graph
//! entity with its `SubgraphFeaturesV2` tensor plus a label
//! (`benign` / `credential_attack` / `lateral_movement` / ...).
//!
//! This is a thin export adapter — it reuses the existing
//! `SentinelJsonParser` to convert raw SigninLogs into entities +
//! relations, then calls `extract_subgraph_features_v2` on each node
//! the caller marked as interesting.
//!
//! Labels come from either (a) an explicit `labels` map passed by the
//! caller (e.g. the analyst's `tag_entity` output exported as
//! `{node_id: label}`) or (b) an auto-labeling heuristic based on
//! known IoC prefixes (see `auto_label`).

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

use crate::gnn_bridge::{extract_subgraph_features_v2, SubgraphFeaturesV2};
use graph_hunter_core::graph::GraphHunter;

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct TrainingExample {
    pub node_id: String,
    pub entity_type: String,
    pub label: String,
    pub features: SubgraphFeaturesV2,
}

/// Labels accepted by the v2 model. Keep in sync with `train_gnn_v2.py`.
pub const LABELS: &[&str] = &[
    "benign",
    "exfiltration",
    "c2_beacon",
    "lateral_movement",
    "privilege_escalation",
    "credential_attack", // new in v2
];

/// Export a training corpus from the graph. Each node that has an
/// explicit label in `labels` becomes one TrainingExample; unlabeled
/// nodes are skipped unless `auto_label_all_ips = true`, in which case
/// every IP gets a heuristic label.
pub fn export_training_examples(
    graph: &GraphHunter,
    labels: &HashMap<String, String>,
    k_hops: usize,
    auto_label_all_ips: bool,
) -> Vec<TrainingExample> {
    let mut out = Vec::with_capacity(labels.len());
    for (node_id, label) in labels {
        if !LABELS.contains(&label.as_str()) {
            continue;
        }
        let features = match extract_subgraph_features_v2(graph, node_id, k_hops) {
            Some(f) => f,
            None => continue,
        };
        let entity_type = graph
            .get_entity(node_id)
            .map(|e| format!("{}", e.entity_type))
            .unwrap_or_else(|| "Unknown".to_string());
        out.push(TrainingExample {
            node_id: node_id.clone(),
            entity_type,
            label: label.clone(),
            features,
        });
    }

    if auto_label_all_ips {
        use graph_hunter_core::types::EntityType;
        if let Some(ips) = graph.entity_ids_for_type(&EntityType::IP) {
            for ip in ips {
                if labels.contains_key(&ip) {
                    continue;
                }
                let features = match extract_subgraph_features_v2(graph, &ip, k_hops) {
                    Some(f) => f,
                    None => continue,
                };
                out.push(TrainingExample {
                    node_id: ip.clone(),
                    entity_type: "IP".to_string(),
                    label: auto_label(graph, &ip),
                    features,
                });
            }
        }
    }

    out
}

/// Heuristic label for an unlabeled IP — used to bootstrap training
/// data before the analyst has tagged everything. Looks at the node's
/// metadata for hints: `ip_class=Private` → benign; risk_tag → attack.
/// Returns "benign" by default so unlabeled IPs don't poison the model.
fn auto_label(graph: &GraphHunter, ip: &str) -> String {
    let entity = match graph.get_entity(ip) {
        Some(e) => e,
        None => return "benign".into(),
    };
    if entity.metadata.get("ip_class").map(|v| v.as_str()) == Some("Private") {
        return "benign".into();
    }
    if entity.metadata.contains_key("risk_tag") {
        return "credential_attack".into();
    }
    "benign".into()
}

/// Serialize a corpus as newline-delimited JSON (one TrainingExample
/// per line) — the format `train_gnn_v2.py` reads.
pub fn examples_to_ndjson(examples: &[TrainingExample]) -> String {
    let mut out = String::new();
    for ex in examples {
        if let Ok(s) = serde_json::to_string(ex) {
            out.push_str(&s);
            out.push('\n');
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use graph_hunter_core::{Entity, EntityType, Relation, RelationType};

    fn fixture_graph() -> GraphHunter {
        let mut g = GraphHunter::new();
        g.add_entity(Entity::new("alice", EntityType::User)).unwrap();
        g.add_entity(Entity::new("1.2.3.4", EntityType::IP)).unwrap();
        g.add_relation(
            Relation::new("alice", "1.2.3.4", RelationType::Auth, 100)
                .with_metadata("app", "Browser"),
        )
        .unwrap();
        g
    }

    #[test]
    fn exports_labeled_examples_with_v2_tensor() {
        let g = fixture_graph();
        let labels = HashMap::from([("alice".to_string(), "benign".to_string())]);
        let out = export_training_examples(&g, &labels, 1, false);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].label, "benign");
        assert_eq!(out[0].entity_type, "User");
        // v2 tensor shape: K_MAX * D_NODE_V2 floats for node features.
        assert_eq!(
            out[0].features.node_features.len(),
            crate::gnn_bridge::K_MAX * crate::gnn_bridge::D_NODE_V2
        );
    }

    #[test]
    fn rejects_unknown_label() {
        let g = fixture_graph();
        let labels = HashMap::from([("alice".to_string(), "nonsense".to_string())]);
        let out = export_training_examples(&g, &labels, 1, false);
        assert!(out.is_empty());
    }

    #[test]
    fn ndjson_has_one_line_per_example() {
        let g = fixture_graph();
        let labels = HashMap::from([("alice".to_string(), "benign".to_string())]);
        let out = export_training_examples(&g, &labels, 1, false);
        let nd = examples_to_ndjson(&out);
        assert_eq!(nd.lines().count(), 1);
        assert!(nd.contains("\"label\":\"benign\""));
    }
}
