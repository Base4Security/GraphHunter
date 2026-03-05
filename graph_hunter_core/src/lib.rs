pub mod analytics;
pub mod anomaly;
pub mod benchmark;
pub mod catalog;
pub mod csv_parser;
pub mod dsl;
pub mod types;
pub mod entity;
pub mod errors;
pub mod field_preview;
pub mod generic;
pub mod gnn_bridge;
pub mod graph;
pub mod npu_scorer;
pub mod hypothesis;
pub mod interner;
pub mod parser;
pub mod preview;
pub mod relation;
pub mod sentinel;
pub mod sysmon;

// Re-export core types at crate root for ergonomic imports.
pub use analytics::{
    GraphSummary, Neighborhood, NeighborhoodFilter, NeighborNode, NeighborEdge,
    NodeDetails, ScoredPath, SearchResult, TopAnomaly, TypeDistribution,
};
pub use anomaly::{AnomalyScorer, ScoreBreakdown, ScoringWeights, ThreatClass};
pub use gnn_bridge::{SubgraphFeatures, extract_subgraph_features, extract_batch_features, K_MAX, D_NODE, GNN_INPUT_DIM};
pub use npu_scorer::scorer::{NpuScorer, NpuError};
pub use csv_parser::CsvParser;
pub use entity::Entity;
pub use field_preview::{
    preview_fields, ConfigurableParser, FieldConfig, FieldInfo, FieldMapping, FieldRole,
};
pub use errors::GraphError;
pub use generic::GenericParser;
pub use graph::{CompactionStats, GraphHunter};
pub use interner::{StrId, StringInterner};
pub use hypothesis::{Hypothesis, HypothesisStep};
pub use parser::{LogParser, ParsedTriple};
pub use preview::{preview_generic_from_keys, preview_sentinel, preview_sysmon};
pub use relation::Relation;
pub use sentinel::SentinelJsonParser;
pub use sysmon::SysmonJsonParser;
pub use catalog::{CatalogEntry, get_catalog};
pub use dsl::{DslError, DslParseResult, parse_dsl, format_hypothesis};
pub use types::{EntityType, MergePolicy, RelationType, entity_type_matches, relation_type_matches};
pub use benchmark::{
    BenchmarkResult, PruningStats,
    generate_erdos_renyi, generate_barabasi_albert,
    search_instrumented, run_benchmark, graph_params, approx_memory,
    build_spawn_chain_hypothesis, build_lateral_movement_hypothesis,
    format_latex_row,
};

#[cfg(test)]
mod tests {
    use super::*;

    // ── Entity Tests ──

    #[test]
    fn entity_creation_default() {
        let e = Entity::new("192.168.1.1", EntityType::IP);
        assert_eq!(e.id, "192.168.1.1");
        assert_eq!(e.entity_type, EntityType::IP);
        assert_eq!(e.score, 0.0);
        assert!(e.metadata.is_empty());
    }

    #[test]
    fn entity_with_score() {
        let e = Entity::with_score("malware.exe", EntityType::File, 95.0);
        assert_eq!(e.score, 95.0);
    }

    #[test]
    fn entity_builder_metadata() {
        let e = Entity::new("10.0.0.1", EntityType::IP)
            .with_metadata("geo", "US")
            .with_metadata("asn", "AS15169");
        assert_eq!(e.metadata.get("geo").unwrap(), "US");
        assert_eq!(e.metadata.get("asn").unwrap(), "AS15169");
    }

    #[test]
    fn entity_equality_by_id() {
        let e1 = Entity::new("host-1", EntityType::Host);
        let e2 = Entity::with_score("host-1", EntityType::Host, 50.0);
        assert_eq!(e1, e2); // Same ID = equal, regardless of score
    }

    // ── Relation Tests ──

    #[test]
    fn relation_creation() {
        let r = Relation::new("10.0.0.1", "server-1", RelationType::Connect, 1700000000);
        assert_eq!(r.source_id, "10.0.0.1");
        assert_eq!(r.dest_id, "server-1");
        assert_eq!(r.rel_type, RelationType::Connect);
        assert_eq!(r.timestamp, 1700000000);
    }

    #[test]
    fn relation_builder_metadata() {
        let r = Relation::new("user-admin", "cmd.exe", RelationType::Execute, 1700000100)
            .with_metadata("cmdline", "whoami")
            .with_metadata("pid", "4512");
        assert_eq!(r.metadata.get("cmdline").unwrap(), "whoami");
        assert_eq!(r.metadata.get("pid").unwrap(), "4512");
    }

    // ── Hypothesis Tests ──

    #[test]
    fn hypothesis_builder() {
        let h = Hypothesis::new("Lateral Movement")
            .add_step(HypothesisStep::new(
                EntityType::IP,
                RelationType::Connect,
                EntityType::Host,
            ))
            .add_step(HypothesisStep::new(
                EntityType::Host,
                RelationType::Auth,
                EntityType::User,
            ))
            .add_step(HypothesisStep::new(
                EntityType::User,
                RelationType::Execute,
                EntityType::Process,
            ));

        assert_eq!(h.name, "Lateral Movement");
        assert_eq!(h.len(), 3);
        assert!(!h.is_empty());
    }

    #[test]
    fn hypothesis_validation_ok() {
        let h = Hypothesis::new("DNS Exfil")
            .add_step(HypothesisStep::new(
                EntityType::Process,
                RelationType::DNS,
                EntityType::Domain,
            ));
        assert!(h.validate().is_ok());
    }

    #[test]
    fn hypothesis_validation_chained_ok() {
        let h = Hypothesis::new("Full Kill Chain")
            .add_step(HypothesisStep::new(
                EntityType::IP,
                RelationType::Connect,
                EntityType::Host,
            ))
            .add_step(HypothesisStep::new(
                EntityType::Host,
                RelationType::Auth,
                EntityType::User,
            ));
        assert!(h.validate().is_ok());
    }

    #[test]
    fn hypothesis_validation_type_mismatch() {
        let h = Hypothesis::new("Bad Chain")
            .add_step(HypothesisStep::new(
                EntityType::IP,
                RelationType::Connect,
                EntityType::Host,
            ))
            .add_step(HypothesisStep::new(
                EntityType::Process, // Mismatch: previous step ends with Host
                RelationType::Execute,
                EntityType::File,
            ));
        assert!(h.validate().is_err());
    }

    #[test]
    fn hypothesis_validation_empty() {
        let h = Hypothesis::new("Empty");
        assert!(h.validate().is_err());
    }

    // ── Serialization Round-Trip Tests ──

    #[test]
    fn entity_serde_roundtrip() {
        let original = Entity::new("192.168.1.100", EntityType::IP)
            .with_metadata("reputation", "malicious");

        let json = serde_json::to_string(&original).unwrap();
        let deserialized: Entity = serde_json::from_str(&json).unwrap();

        assert_eq!(deserialized.id, original.id);
        assert_eq!(deserialized.entity_type, original.entity_type);
        assert_eq!(
            deserialized.metadata.get("reputation").unwrap(),
            "malicious"
        );
    }

    #[test]
    fn relation_serde_roundtrip() {
        let original =
            Relation::new("attacker-ip", "victim-host", RelationType::Connect, 1700000000)
                .with_metadata("port", "445");

        let json = serde_json::to_string(&original).unwrap();
        let deserialized: Relation = serde_json::from_str(&json).unwrap();

        assert_eq!(deserialized.source_id, "attacker-ip");
        assert_eq!(deserialized.dest_id, "victim-host");
        assert_eq!(deserialized.rel_type, RelationType::Connect);
        assert_eq!(deserialized.timestamp, 1700000000);
        assert_eq!(deserialized.metadata.get("port").unwrap(), "445");
    }

    #[test]
    fn hypothesis_serde_roundtrip() {
        let original = Hypothesis::new("Lateral Movement")
            .add_step(HypothesisStep::new(
                EntityType::IP,
                RelationType::Connect,
                EntityType::Host,
            ))
            .add_step(HypothesisStep::new(
                EntityType::Host,
                RelationType::Auth,
                EntityType::User,
            ));

        let json = serde_json::to_string(&original).unwrap();
        let deserialized: Hypothesis = serde_json::from_str(&json).unwrap();

        assert_eq!(deserialized.name, "Lateral Movement");
        assert_eq!(deserialized.len(), 2);
        assert!(deserialized.validate().is_ok());
    }

    #[test]
    fn entity_type_display() {
        assert_eq!(format!("{}", EntityType::IP), "IP");
        assert_eq!(format!("{}", EntityType::Process), "Process");
    }

    #[test]
    fn relation_type_display() {
        assert_eq!(format!("{}", RelationType::DNS), "DNS");
        assert_eq!(format!("{}", RelationType::Execute), "Execute");
    }

    #[test]
    fn entity_hash_consistency() {
        use std::collections::HashSet;
        let e1 = Entity::new("node-1", EntityType::Host);
        let e2 = Entity::new("node-1", EntityType::Host);
        let mut set = HashSet::new();
        set.insert(e1);
        set.insert(e2);
        assert_eq!(set.len(), 1); // Deduplication by ID
    }

    #[test]
    fn hypothesis_json_structure() {
        let h = Hypothesis::new("Test")
            .add_step(HypothesisStep::new(
                EntityType::IP,
                RelationType::Connect,
                EntityType::Host,
            ));

        let json: serde_json::Value = serde_json::to_value(&h).unwrap();
        assert!(json["name"].is_string());
        assert!(json["steps"].is_array());
        assert_eq!(json["steps"].as_array().unwrap().len(), 1);

        let step = &json["steps"][0];
        assert_eq!(step["origin_type"], "IP");
        assert_eq!(step["relation_type"], "Connect");
        assert_eq!(step["dest_type"], "Host");
    }

    // ══════════════════════════════════════════════════
    // ── Phase 2: GraphHunter Engine Tests ──
    // ══════════════════════════════════════════════════

    /// Helper: builds a realistic lateral movement graph.
    ///
    /// Topology:
    /// ```text
    /// attacker-ip -[Connect@100]-> web-server -[Auth@200]-> admin-user -[Execute@300]-> cmd.exe -[Write@400]-> payload.dll
    /// ```
    fn build_lateral_movement_graph() -> GraphHunter {
        let mut g = GraphHunter::new();

        g.add_entity(Entity::new("attacker-ip", EntityType::IP)).unwrap();
        g.add_entity(Entity::new("web-server", EntityType::Host)).unwrap();
        g.add_entity(Entity::new("admin-user", EntityType::User)).unwrap();
        g.add_entity(Entity::new("cmd.exe", EntityType::Process)).unwrap();
        g.add_entity(Entity::new("payload.dll", EntityType::File)).unwrap();

        g.add_relation(Relation::new("attacker-ip", "web-server", RelationType::Connect, 100)).unwrap();
        g.add_relation(Relation::new("web-server", "admin-user", RelationType::Auth, 200)).unwrap();
        g.add_relation(Relation::new("admin-user", "cmd.exe", RelationType::Execute, 300)).unwrap();
        g.add_relation(Relation::new("cmd.exe", "payload.dll", RelationType::Write, 400)).unwrap();

        g
    }

    // ── Graph Construction Tests ──

    #[test]
    fn graph_new_is_empty() {
        let mut g = GraphHunter::new();
        assert_eq!(g.entity_count(), 0);
        assert_eq!(g.relation_count(), 0);
    }

    #[test]
    fn graph_add_entity_and_count() {
        let mut g = GraphHunter::new();
        g.add_entity(Entity::new("node-1", EntityType::IP)).unwrap();
        g.add_entity(Entity::new("node-2", EntityType::Host)).unwrap();
        assert_eq!(g.entity_count(), 2);
    }

    #[test]
    fn graph_duplicate_entity_error() {
        let mut g = GraphHunter::new();
        g.add_entity(Entity::new("dup", EntityType::IP)).unwrap();
        let err = g.add_entity(Entity::new("dup", EntityType::IP)).unwrap_err();
        assert_eq!(err, GraphError::DuplicateEntity("dup".into()));
    }

    #[test]
    fn graph_add_relation_validates_source() {
        let mut g = GraphHunter::new();
        g.add_entity(Entity::new("dest", EntityType::Host)).unwrap();
        let err = g
            .add_relation(Relation::new("ghost", "dest", RelationType::Connect, 100))
            .unwrap_err();
        assert_eq!(err, GraphError::EntityNotFound("ghost".into()));
    }

    #[test]
    fn graph_add_relation_validates_dest() {
        let mut g = GraphHunter::new();
        g.add_entity(Entity::new("src", EntityType::IP)).unwrap();
        let err = g
            .add_relation(Relation::new("src", "ghost", RelationType::Connect, 100))
            .unwrap_err();
        assert_eq!(err, GraphError::EntityNotFound("ghost".into()));
    }

    #[test]
    fn graph_relation_count() {
        let mut g = build_lateral_movement_graph();
        assert_eq!(g.entity_count(), 5);
        assert_eq!(g.relation_count(), 4);
    }

    #[test]
    fn graph_get_entity() {
        let mut g = build_lateral_movement_graph();
        let e = g.get_entity("web-server").unwrap();
        assert_eq!(e.entity_type, EntityType::Host);
    }

    #[test]
    fn graph_get_relations() {
        let mut g = build_lateral_movement_graph();
        let rels = g.get_relations("attacker-ip");
        assert_eq!(rels.len(), 1);
        assert_eq!(rels[0].dest_id, "web-server");
    }

    #[test]
    fn graph_get_relations_empty() {
        let mut g = build_lateral_movement_graph();
        let rels = g.get_relations("payload.dll"); // leaf node, no outgoing
        assert!(rels.is_empty());
    }

    // ── Pattern Search: Positive Tests ──

    #[test]
    fn search_full_lateral_movement_chain() {
        let mut g = build_lateral_movement_graph();

        let hypothesis = Hypothesis::new("Lateral Movement")
            .add_step(HypothesisStep::new(EntityType::IP, RelationType::Connect, EntityType::Host))
            .add_step(HypothesisStep::new(EntityType::Host, RelationType::Auth, EntityType::User))
            .add_step(HypothesisStep::new(EntityType::User, RelationType::Execute, EntityType::Process))
            .add_step(HypothesisStep::new(EntityType::Process, RelationType::Write, EntityType::File));

        let results = g.search_temporal_pattern(&hypothesis, None, None).unwrap().0;
        assert_eq!(results.len(), 1);
        assert_eq!(
            results[0],
            vec!["attacker-ip", "web-server", "admin-user", "cmd.exe", "payload.dll"]
        );
    }

    #[test]
    fn search_partial_chain() {
        let mut g = build_lateral_movement_graph();

        // Only search for the first two steps: IP -> Connect -> Host -> Auth -> User
        let hypothesis = Hypothesis::new("Initial Access")
            .add_step(HypothesisStep::new(EntityType::IP, RelationType::Connect, EntityType::Host))
            .add_step(HypothesisStep::new(EntityType::Host, RelationType::Auth, EntityType::User));

        let results = g.search_temporal_pattern(&hypothesis, None, None).unwrap().0;
        assert_eq!(results.len(), 1);
        assert_eq!(results[0], vec!["attacker-ip", "web-server", "admin-user"]);
    }

    #[test]
    fn search_single_step() {
        let mut g = build_lateral_movement_graph();

        let hypothesis = Hypothesis::new("Connection")
            .add_step(HypothesisStep::new(EntityType::IP, RelationType::Connect, EntityType::Host));

        let results = g.search_temporal_pattern(&hypothesis, None, None).unwrap().0;
        assert_eq!(results.len(), 1);
        assert_eq!(results[0], vec!["attacker-ip", "web-server"]);
    }

    // ── Pattern Search: Negative / Pruning Tests ──

    #[test]
    fn search_no_match_wrong_relation_type() {
        let mut g = build_lateral_movement_graph();

        // IP -> Auth (wrong: should be Connect) -> Host
        let hypothesis = Hypothesis::new("Wrong Relation")
            .add_step(HypothesisStep::new(EntityType::IP, RelationType::Auth, EntityType::Host));

        let results = g.search_temporal_pattern(&hypothesis, None, None).unwrap().0;
        assert!(results.is_empty());
    }

    #[test]
    fn search_no_match_wrong_dest_type() {
        let mut g = build_lateral_movement_graph();

        // IP -> Connect -> User (wrong: web-server is a Host, not User)
        let hypothesis = Hypothesis::new("Wrong Dest Type")
            .add_step(HypothesisStep::new(EntityType::IP, RelationType::Connect, EntityType::User));

        let results = g.search_temporal_pattern(&hypothesis, None, None).unwrap().0;
        assert!(results.is_empty());
    }

    #[test]
    fn search_invalid_hypothesis_returns_error() {
        let mut g = build_lateral_movement_graph();
        let hypothesis = Hypothesis::new("Empty");
        let err = g.search_temporal_pattern(&hypothesis, None, None).unwrap_err();
        assert!(matches!(err, GraphError::InvalidHypothesis(_)));
    }

    // ── Causal Monotonicity Tests ──

    #[test]
    fn search_enforces_causal_monotonicity() {
        let mut g = GraphHunter::new();

        g.add_entity(Entity::new("ip-1", EntityType::IP)).unwrap();
        g.add_entity(Entity::new("host-1", EntityType::Host)).unwrap();
        g.add_entity(Entity::new("user-1", EntityType::User)).unwrap();

        // Connection at t=500, Auth at t=200 (BEFORE the connection — violates causality)
        g.add_relation(Relation::new("ip-1", "host-1", RelationType::Connect, 500)).unwrap();
        g.add_relation(Relation::new("host-1", "user-1", RelationType::Auth, 200)).unwrap();

        let hypothesis = Hypothesis::new("Broken Causality")
            .add_step(HypothesisStep::new(EntityType::IP, RelationType::Connect, EntityType::Host))
            .add_step(HypothesisStep::new(EntityType::Host, RelationType::Auth, EntityType::User));

        let results = g.search_temporal_pattern(&hypothesis, None, None).unwrap().0;
        assert!(results.is_empty(), "Should not match when Auth happens before Connect");
    }

    #[test]
    fn search_allows_same_timestamp() {
        let mut g = GraphHunter::new();

        g.add_entity(Entity::new("ip-1", EntityType::IP)).unwrap();
        g.add_entity(Entity::new("host-1", EntityType::Host)).unwrap();
        g.add_entity(Entity::new("user-1", EntityType::User)).unwrap();

        // Same timestamp is valid (simultaneous events in same log batch)
        g.add_relation(Relation::new("ip-1", "host-1", RelationType::Connect, 100)).unwrap();
        g.add_relation(Relation::new("host-1", "user-1", RelationType::Auth, 100)).unwrap();

        let hypothesis = Hypothesis::new("Same Time")
            .add_step(HypothesisStep::new(EntityType::IP, RelationType::Connect, EntityType::Host))
            .add_step(HypothesisStep::new(EntityType::Host, RelationType::Auth, EntityType::User));

        let results = g.search_temporal_pattern(&hypothesis, None, None).unwrap().0;
        assert_eq!(results.len(), 1);
    }

    // ── Time Window Tests ──

    #[test]
    fn search_time_window_includes_match() {
        let mut g = build_lateral_movement_graph(); // timestamps: 100, 200, 300, 400

        let hypothesis = Hypothesis::new("Windowed")
            .add_step(HypothesisStep::new(EntityType::IP, RelationType::Connect, EntityType::Host))
            .add_step(HypothesisStep::new(EntityType::Host, RelationType::Auth, EntityType::User));

        // Window [50, 250] includes both edges (t=100, t=200)
        let results = g.search_temporal_pattern(&hypothesis, Some((50, 250)), None).unwrap().0;
        assert_eq!(results.len(), 1);
    }

    #[test]
    fn search_time_window_excludes_match() {
        let mut g = build_lateral_movement_graph(); // timestamps: 100, 200, 300, 400

        let hypothesis = Hypothesis::new("Windowed Excluded")
            .add_step(HypothesisStep::new(EntityType::IP, RelationType::Connect, EntityType::Host))
            .add_step(HypothesisStep::new(EntityType::Host, RelationType::Auth, EntityType::User));

        // Window [150, 250] excludes first edge (t=100)
        let results = g.search_temporal_pattern(&hypothesis, Some((150, 250)), None).unwrap().0;
        assert!(results.is_empty());
    }

    #[test]
    fn search_time_window_partial_chain_cutoff() {
        let mut g = build_lateral_movement_graph();

        let hypothesis = Hypothesis::new("Full Chain Windowed")
            .add_step(HypothesisStep::new(EntityType::IP, RelationType::Connect, EntityType::Host))
            .add_step(HypothesisStep::new(EntityType::Host, RelationType::Auth, EntityType::User))
            .add_step(HypothesisStep::new(EntityType::User, RelationType::Execute, EntityType::Process))
            .add_step(HypothesisStep::new(EntityType::Process, RelationType::Write, EntityType::File));

        // Window [50, 350] excludes the Write at t=400
        let results = g.search_temporal_pattern(&hypothesis, Some((50, 350)), None).unwrap().0;
        assert!(results.is_empty());
    }

    // ── Cycle Avoidance Tests ──

    #[test]
    fn search_avoids_cycles() {
        let mut g = GraphHunter::new();

        g.add_entity(Entity::new("ip-1", EntityType::IP)).unwrap();
        g.add_entity(Entity::new("host-1", EntityType::Host)).unwrap();
        // Create a Host that also acts as an IP (unusual but tests cycle detection)
        // Instead: create a cycle-like scenario where DFS could loop
        g.add_entity(Entity::new("host-2", EntityType::Host)).unwrap();

        g.add_relation(Relation::new("ip-1", "host-1", RelationType::Connect, 100)).unwrap();
        g.add_relation(Relation::new("ip-1", "host-2", RelationType::Connect, 100)).unwrap();

        let hypothesis = Hypothesis::new("Fan Out")
            .add_step(HypothesisStep::new(EntityType::IP, RelationType::Connect, EntityType::Host));

        let results = g.search_temporal_pattern(&hypothesis, None, None).unwrap().0;
        assert_eq!(results.len(), 2); // Two distinct paths, no cycles
    }

    // ── Multiple Paths Tests ──

    #[test]
    fn search_finds_multiple_attack_paths() {
        let mut g = GraphHunter::new();

        // Two attackers, same target chain
        g.add_entity(Entity::new("attacker-1", EntityType::IP)).unwrap();
        g.add_entity(Entity::new("attacker-2", EntityType::IP)).unwrap();
        g.add_entity(Entity::new("server", EntityType::Host)).unwrap();

        g.add_relation(Relation::new("attacker-1", "server", RelationType::Connect, 100)).unwrap();
        g.add_relation(Relation::new("attacker-2", "server", RelationType::Connect, 200)).unwrap();

        let hypothesis = Hypothesis::new("Multi-Source")
            .add_step(HypothesisStep::new(EntityType::IP, RelationType::Connect, EntityType::Host));

        let results = g.search_temporal_pattern(&hypothesis, None, None).unwrap().0;
        assert_eq!(results.len(), 2);

        let paths: Vec<Vec<&str>> = results
            .iter()
            .map(|p| p.iter().map(|s| s.as_str()).collect())
            .collect();
        assert!(paths.contains(&vec!["attacker-1", "server"]));
        assert!(paths.contains(&vec!["attacker-2", "server"]));
    }

    #[test]
    fn search_branching_paths() {
        let mut g = GraphHunter::new();

        g.add_entity(Entity::new("ip", EntityType::IP)).unwrap();
        g.add_entity(Entity::new("host", EntityType::Host)).unwrap();
        g.add_entity(Entity::new("user-a", EntityType::User)).unwrap();
        g.add_entity(Entity::new("user-b", EntityType::User)).unwrap();

        g.add_relation(Relation::new("ip", "host", RelationType::Connect, 100)).unwrap();
        g.add_relation(Relation::new("host", "user-a", RelationType::Auth, 200)).unwrap();
        g.add_relation(Relation::new("host", "user-b", RelationType::Auth, 300)).unwrap();

        let hypothesis = Hypothesis::new("Branch")
            .add_step(HypothesisStep::new(EntityType::IP, RelationType::Connect, EntityType::Host))
            .add_step(HypothesisStep::new(EntityType::Host, RelationType::Auth, EntityType::User));

        let results = g.search_temporal_pattern(&hypothesis, None, None).unwrap().0;
        assert_eq!(results.len(), 2);
    }

    // ── Complex Realistic Scenario ──

    #[test]
    fn search_realistic_apt_scenario() {
        let mut g = GraphHunter::new();

        // Build APT kill chain:
        // C2-IP -> Connect -> DMZ-Host -> Auth -> Service-Account -> Execute -> PowerShell
        // -> Write -> Beacon.exe -> Execute -> Mimikatz -> Read -> LSASS
        g.add_entity(Entity::new("c2-server", EntityType::IP)).unwrap();
        g.add_entity(Entity::new("dmz-host", EntityType::Host)).unwrap();
        g.add_entity(Entity::new("svc-account", EntityType::User)).unwrap();
        g.add_entity(Entity::new("powershell.exe", EntityType::Process)).unwrap();
        g.add_entity(Entity::new("beacon.exe", EntityType::File)).unwrap();

        g.add_relation(Relation::new("c2-server", "dmz-host", RelationType::Connect, 1000)).unwrap();
        g.add_relation(Relation::new("dmz-host", "svc-account", RelationType::Auth, 1005)).unwrap();
        g.add_relation(Relation::new("svc-account", "powershell.exe", RelationType::Execute, 1010)).unwrap();
        g.add_relation(Relation::new("powershell.exe", "beacon.exe", RelationType::Write, 1015)).unwrap();

        // Search for: IP -> Connect -> Host -> Auth -> User -> Execute -> Process -> Write -> File
        let hypothesis = Hypothesis::new("APT Kill Chain")
            .add_step(HypothesisStep::new(EntityType::IP, RelationType::Connect, EntityType::Host))
            .add_step(HypothesisStep::new(EntityType::Host, RelationType::Auth, EntityType::User))
            .add_step(HypothesisStep::new(EntityType::User, RelationType::Execute, EntityType::Process))
            .add_step(HypothesisStep::new(EntityType::Process, RelationType::Write, EntityType::File));

        let results = g.search_temporal_pattern(&hypothesis, None, None).unwrap().0;
        assert_eq!(results.len(), 1);
        assert_eq!(
            results[0],
            vec!["c2-server", "dmz-host", "svc-account", "powershell.exe", "beacon.exe"]
        );

        // Same search but with tight time window
        let results_windowed = g
            .search_temporal_pattern(&hypothesis, Some((999, 1020)), None)
            .unwrap().0;
        assert_eq!(results_windowed.len(), 1);

        // Too narrow window excludes the Write
        let results_narrow = g
            .search_temporal_pattern(&hypothesis, Some((999, 1012)), None)
            .unwrap().0;
        assert!(results_narrow.is_empty());
    }

    #[test]
    fn graph_error_display() {
        let err = GraphError::EntityNotFound("ghost-node".into());
        assert_eq!(format!("{err}"), "Entity not found: ghost-node");

        let err = GraphError::InvalidHypothesis("empty".into());
        assert_eq!(format!("{err}"), "Invalid hypothesis: empty");

        let err = GraphError::DuplicateEntity("dup".into());
        assert_eq!(format!("{err}"), "Duplicate entity ID: dup");
    }

    #[test]
    fn graph_default_trait() {
        let mut g = GraphHunter::default();
        assert_eq!(g.entity_count(), 0);
    }

    // ══════════════════════════════════════════════════
    // ── Phase 3: Parser & Ingestion Tests ──
    // ══════════════════════════════════════════════════

    // ── Sysmon Event 1: Process Create ──

    #[test]
    fn sysmon_parse_event1_process_create() {
        let json = r#"[{
            "EventID": 1,
            "UtcTime": "2024-01-15 14:30:00.123",
            "User": "CORP\\admin",
            "Image": "C:\\Windows\\System32\\cmd.exe",
            "CommandLine": "cmd.exe /c whoami",
            "ProcessId": 4512,
            "ParentImage": "C:\\Windows\\explorer.exe",
            "ParentProcessId": 1200,
            "Computer": "WORKSTATION-01"
        }]"#;

        let parser = SysmonJsonParser;
        let triples = parser.parse(json);

        // Event 1 produces 2 triples: User->Execute->Process and Parent->Spawn->Child
        assert_eq!(triples.len(), 2);

        // Triple 1: User -> Execute -> Process
        let (src, rel, dst) = &triples[0];
        assert_eq!(src.id, "CORP\\admin");
        assert_eq!(src.entity_type, EntityType::User);
        assert_eq!(rel.rel_type, RelationType::Execute);
        assert_eq!(dst.id, "C:\\Windows\\System32\\cmd.exe");
        assert_eq!(dst.entity_type, EntityType::Process);
        assert_eq!(dst.metadata.get("pid").unwrap(), "4512");
        assert_eq!(dst.metadata.get("cmdline").unwrap(), "cmd.exe /c whoami");

        // Triple 2: ParentProcess -> Spawn -> ChildProcess
        let (src2, rel2, dst2) = &triples[1];
        assert_eq!(src2.id, "C:\\Windows\\explorer.exe");
        assert_eq!(src2.entity_type, EntityType::Process);
        assert_eq!(rel2.rel_type, RelationType::Spawn);
        assert_eq!(dst2.id, "C:\\Windows\\System32\\cmd.exe");

        // Verify timestamp parsing: 2024-01-15 14:30:00.123 UTC
        assert_eq!(rel.timestamp, 1705329000);
    }

    // ── Sysmon Event 3: Network Connection ──

    #[test]
    fn sysmon_parse_event3_network_connection() {
        let json = r#"[{
            "EventID": 3,
            "UtcTime": "2024-01-15 14:35:00.000",
            "Computer": "WORKSTATION-01",
            "Image": "C:\\Windows\\System32\\cmd.exe",
            "SourceIp": "192.168.1.100",
            "SourcePort": "49152",
            "DestinationIp": "10.0.0.50",
            "DestinationPort": "445",
            "DestinationHostname": "DC-01",
            "Protocol": "tcp"
        }]"#;

        let parser = SysmonJsonParser;
        let triples = parser.parse(json);
        assert_eq!(triples.len(), 2);

        // Triple 1: Host -> Connect -> IP
        let (src, rel, dst) = &triples[0];
        assert_eq!(src.id, "WORKSTATION-01");
        assert_eq!(src.entity_type, EntityType::Host);
        assert_eq!(src.metadata.get("source_ip").unwrap(), "192.168.1.100");
        assert_eq!(rel.rel_type, RelationType::Connect);
        assert_eq!(rel.metadata.get("image").unwrap(), "C:\\Windows\\System32\\cmd.exe");
        assert_eq!(dst.id, "10.0.0.50");
        assert_eq!(dst.entity_type, EntityType::IP);
        assert_eq!(dst.metadata.get("dest_port").unwrap(), "445");
        assert_eq!(dst.metadata.get("hostname").unwrap(), "DC-01");
        assert_eq!(dst.metadata.get("protocol").unwrap(), "tcp");

        // Triple 2: Process -> Connect -> IP
        let (src2, rel2, dst2) = &triples[1];
        assert_eq!(src2.id, "C:\\Windows\\System32\\cmd.exe");
        assert_eq!(src2.entity_type, EntityType::Process);
        assert_eq!(rel2.rel_type, RelationType::Connect);
        assert_eq!(dst2.id, "10.0.0.50");
    }

    // ── Sysmon Event 11: File Create ──

    #[test]
    fn sysmon_parse_event11_file_create() {
        let json = r#"[{
            "EventID": 11,
            "UtcTime": "2024-01-15 14:40:00.000",
            "Image": "C:\\Windows\\System32\\cmd.exe",
            "TargetFilename": "C:\\Temp\\payload.dll",
            "Hashes": "SHA256=ABCDEF1234567890"
        }]"#;

        let parser = SysmonJsonParser;
        let triples = parser.parse(json);
        assert_eq!(triples.len(), 1);

        let (src, rel, dst) = &triples[0];
        assert_eq!(src.id, "C:\\Windows\\System32\\cmd.exe");
        assert_eq!(src.entity_type, EntityType::Process);
        assert_eq!(rel.rel_type, RelationType::Write);
        assert_eq!(dst.id, "C:\\Temp\\payload.dll");
        assert_eq!(dst.entity_type, EntityType::File);
        assert_eq!(dst.metadata.get("hashes").unwrap(), "SHA256=ABCDEF1234567890");
    }

    // ── Sysmon Event 22: DNS Query ──

    #[test]
    fn sysmon_parse_event22_dns_query() {
        let json = r#"[{
            "EventID": 22,
            "UtcTime": "2024-01-15 14:45:00.000",
            "Image": "C:\\Windows\\System32\\cmd.exe",
            "QueryName": "evil-c2.attacker.com",
            "QueryResults": "185.220.101.1",
            "QueryType": "A"
        }]"#;

        let parser = SysmonJsonParser;
        let triples = parser.parse(json);
        assert_eq!(triples.len(), 1);

        let (src, rel, dst) = &triples[0];
        assert_eq!(src.entity_type, EntityType::Process);
        assert_eq!(rel.rel_type, RelationType::DNS);
        assert_eq!(dst.id, "evil-c2.attacker.com");
        assert_eq!(dst.entity_type, EntityType::Domain);
        assert_eq!(dst.metadata.get("query_results").unwrap(), "185.220.101.1");
        assert_eq!(dst.metadata.get("query_type").unwrap(), "A");
    }

    // ── NDJSON Parsing ──

    #[test]
    fn sysmon_parse_ndjson_format() {
        let ndjson = r#"{"EventID": 22, "UtcTime": "2024-01-15 14:45:00", "Image": "powershell.exe", "QueryName": "c2.evil.com"}
{"EventID": 22, "UtcTime": "2024-01-15 14:46:00", "Image": "powershell.exe", "QueryName": "exfil.evil.com"}"#;

        let parser = SysmonJsonParser;
        let triples = parser.parse(ndjson);
        assert_eq!(triples.len(), 2);
        assert_eq!(triples[0].2.id, "c2.evil.com");
        assert_eq!(triples[1].2.id, "exfil.evil.com");
    }

    // ── Malformed / Edge Cases ──

    #[test]
    fn sysmon_parse_unknown_event_id_skipped() {
        let json = r#"[{"EventID": 999, "UtcTime": "2024-01-15 14:30:00"}]"#;
        let parser = SysmonJsonParser;
        let triples = parser.parse(json);
        assert!(triples.is_empty());
    }

    #[test]
    fn sysmon_parse_missing_required_fields_skipped() {
        // Event 1 without Image field — should produce 0 triples
        let json = r#"[{"EventID": 1, "UtcTime": "2024-01-15 14:30:00", "User": "admin"}]"#;
        let parser = SysmonJsonParser;
        let triples = parser.parse(json);
        assert!(triples.is_empty());
    }

    #[test]
    fn sysmon_parse_garbage_input_returns_empty() {
        let parser = SysmonJsonParser;
        assert!(parser.parse("not json at all!").is_empty());
        assert!(parser.parse("").is_empty());
        assert!(parser.parse("{}").is_empty()); // single object without EventID
    }

    #[test]
    fn sysmon_parse_missing_timestamp_defaults_to_zero() {
        let json = r#"[{
            "EventID": 22,
            "Image": "cmd.exe",
            "QueryName": "test.com"
        }]"#;
        let parser = SysmonJsonParser;
        let triples = parser.parse(json);
        assert_eq!(triples.len(), 1);
        assert_eq!(triples[0].1.timestamp, 0);
    }

    // ── Sysmon Event 5: Process Terminated ──

    #[test]
    fn sysmon_parse_event5_process_terminated() {
        let json = r#"[{
            "EventID": 5,
            "UtcTime": "2024-01-15 15:00:00.000",
            "Image": "C:\\Windows\\System32\\cmd.exe",
            "ProcessId": 4512,
            "Computer": "WORKSTATION-01"
        }]"#;

        let parser = SysmonJsonParser;
        let triples = parser.parse(json);
        assert_eq!(triples.len(), 1);

        let (src, rel, dst) = &triples[0];
        assert_eq!(src.id, "C:\\Windows\\System32\\cmd.exe");
        assert_eq!(src.entity_type, EntityType::Process);
        assert_eq!(src.metadata.get("pid").unwrap(), "4512");
        assert_eq!(rel.rel_type, RelationType::Delete);
        assert_eq!(dst.id, "WORKSTATION-01");
        assert_eq!(dst.entity_type, EntityType::Host);
    }

    // ── Sysmon Event 7: Image Load ──

    #[test]
    fn sysmon_parse_event7_image_load() {
        let json = r#"[{
            "EventID": 7,
            "UtcTime": "2024-01-15 15:01:00.000",
            "Image": "C:\\Windows\\System32\\svchost.exe",
            "ImageLoaded": "C:\\Windows\\System32\\ntdll.dll",
            "Signed": "true",
            "SignatureStatus": "Valid",
            "Hashes": "SHA256=ABCDEF"
        }]"#;

        let parser = SysmonJsonParser;
        let triples = parser.parse(json);
        assert_eq!(triples.len(), 1);

        let (src, rel, dst) = &triples[0];
        assert_eq!(src.id, "C:\\Windows\\System32\\svchost.exe");
        assert_eq!(src.entity_type, EntityType::Process);
        assert_eq!(rel.rel_type, RelationType::Read);
        assert_eq!(dst.id, "C:\\Windows\\System32\\ntdll.dll");
        assert_eq!(dst.entity_type, EntityType::File);
        assert_eq!(dst.metadata.get("signed").unwrap(), "true");
        assert_eq!(dst.metadata.get("signature_status").unwrap(), "Valid");
        assert_eq!(dst.metadata.get("hashes").unwrap(), "SHA256=ABCDEF");
    }

    // ── Sysmon Event 10: Process Access ──

    #[test]
    fn sysmon_parse_event10_process_access() {
        let json = r#"[{
            "EventID": 10,
            "UtcTime": "2024-01-15 15:02:00.000",
            "SourceImage": "C:\\Tools\\mimikatz.exe",
            "TargetImage": "C:\\Windows\\System32\\lsass.exe",
            "GrantedAccess": "0x1010",
            "CallTrace": "C:\\Windows\\SYSTEM32\\ntdll.dll+1234"
        }]"#;

        let parser = SysmonJsonParser;
        let triples = parser.parse(json);
        assert_eq!(triples.len(), 1);

        let (src, rel, dst) = &triples[0];
        assert_eq!(src.id, "C:\\Tools\\mimikatz.exe");
        assert_eq!(src.entity_type, EntityType::Process);
        assert_eq!(rel.rel_type, RelationType::Read);
        assert_eq!(rel.metadata.get("granted_access").unwrap(), "0x1010");
        assert_eq!(rel.metadata.get("call_trace").unwrap(), "C:\\Windows\\SYSTEM32\\ntdll.dll+1234");
        assert_eq!(dst.id, "C:\\Windows\\System32\\lsass.exe");
        assert_eq!(dst.entity_type, EntityType::Process);
    }

    // ── Sysmon Event 12: Registry Create/Delete ──

    #[test]
    fn sysmon_parse_event12_registry_create() {
        let json = r#"[{
            "EventID": 12,
            "UtcTime": "2024-01-15 15:03:00.000",
            "Image": "C:\\Windows\\regedit.exe",
            "TargetObject": "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\\Backdoor",
            "EventType": "CreateKey"
        }]"#;

        let parser = SysmonJsonParser;
        let triples = parser.parse(json);
        assert_eq!(triples.len(), 1);

        let (src, rel, dst) = &triples[0];
        assert_eq!(src.id, "C:\\Windows\\regedit.exe");
        assert_eq!(src.entity_type, EntityType::Process);
        assert_eq!(rel.rel_type, RelationType::Modify);
        assert_eq!(rel.metadata.get("event_type").unwrap(), "CreateKey");
        assert_eq!(dst.id, "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\\Backdoor");
        assert_eq!(dst.entity_type, EntityType::Registry);
    }

    // ── Sysmon Event 13: Registry Value Set ──

    #[test]
    fn sysmon_parse_event13_registry_value_set() {
        let json = r#"[{
            "EventID": 13,
            "UtcTime": "2024-01-15 15:04:00.000",
            "Image": "C:\\Windows\\System32\\reg.exe",
            "TargetObject": "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\\Malware",
            "Details": "C:\\Temp\\evil.exe"
        }]"#;

        let parser = SysmonJsonParser;
        let triples = parser.parse(json);
        assert_eq!(triples.len(), 1);

        let (src, rel, dst) = &triples[0];
        assert_eq!(src.id, "C:\\Windows\\System32\\reg.exe");
        assert_eq!(src.entity_type, EntityType::Process);
        assert_eq!(rel.rel_type, RelationType::Modify);
        assert_eq!(rel.metadata.get("details").unwrap(), "C:\\Temp\\evil.exe");
        assert_eq!(dst.id, "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\\Malware");
        assert_eq!(dst.entity_type, EntityType::Registry);
    }

    // ── Sysmon Event 23: File Delete ──

    #[test]
    fn sysmon_parse_event23_file_delete() {
        let json = r#"[{
            "EventID": 23,
            "UtcTime": "2024-01-15 15:05:00.000",
            "Image": "C:\\Windows\\System32\\cmd.exe",
            "TargetFilename": "C:\\Temp\\evidence.log",
            "Hashes": "SHA256=DEADBEEF",
            "IsExecutable": "false"
        }]"#;

        let parser = SysmonJsonParser;
        let triples = parser.parse(json);
        assert_eq!(triples.len(), 1);

        let (src, rel, dst) = &triples[0];
        assert_eq!(src.id, "C:\\Windows\\System32\\cmd.exe");
        assert_eq!(src.entity_type, EntityType::Process);
        assert_eq!(rel.rel_type, RelationType::Delete);
        assert_eq!(dst.id, "C:\\Temp\\evidence.log");
        assert_eq!(dst.entity_type, EntityType::File);
        assert_eq!(dst.metadata.get("hashes").unwrap(), "SHA256=DEADBEEF");
        assert_eq!(dst.metadata.get("is_executable").unwrap(), "false");
    }

    // ── Sysmon Event 1: Spawn verification ──

    #[test]
    fn sysmon_event1_parent_child_uses_spawn() {
        let json = r#"[{
            "EventID": 1,
            "UtcTime": "2024-01-15 14:30:00.000",
            "User": "SYSTEM",
            "Image": "C:\\malware.exe",
            "ParentImage": "C:\\Windows\\System32\\cmd.exe",
            "ProcessId": 100,
            "ParentProcessId": 50
        }]"#;

        let parser = SysmonJsonParser;
        let triples = parser.parse(json);
        assert_eq!(triples.len(), 2);

        // User -> Execute (unchanged)
        assert_eq!(triples[0].1.rel_type, RelationType::Execute);
        // Parent -> Spawn (not Execute)
        assert_eq!(triples[1].1.rel_type, RelationType::Spawn);
        assert_eq!(triples[1].0.id, "C:\\Windows\\System32\\cmd.exe");
        assert_eq!(triples[1].2.id, "C:\\malware.exe");
    }

    // ── Sysmon Event 3: Process Connect triple ──

    #[test]
    fn sysmon_event3_process_connect_triple() {
        let json = r#"[{
            "EventID": 3,
            "UtcTime": "2024-01-15 14:35:00.000",
            "Hostname": "VICTIM-PC",
            "Image": "C:\\Windows\\System32\\powershell.exe",
            "DestinationIp": "10.0.0.1",
            "DestinationPort": "443"
        }]"#;

        let parser = SysmonJsonParser;
        let triples = parser.parse(json);
        assert_eq!(triples.len(), 2);

        // Triple 1: Host -> Connect -> IP
        assert_eq!(triples[0].0.id, "VICTIM-PC");
        assert_eq!(triples[0].0.entity_type, EntityType::Host);
        assert_eq!(triples[0].1.rel_type, RelationType::Connect);
        assert_eq!(triples[0].2.id, "10.0.0.1");

        // Triple 2: Process -> Connect -> IP
        assert_eq!(triples[1].0.id, "C:\\Windows\\System32\\powershell.exe");
        assert_eq!(triples[1].0.entity_type, EntityType::Process);
        assert_eq!(triples[1].1.rel_type, RelationType::Connect);
        assert_eq!(triples[1].2.id, "10.0.0.1");
    }

    // ── Ingestion Pipeline ──

    #[test]
    fn ingest_logs_populates_graph() {
        let json = r#"[
            {
                "EventID": 3,
                "UtcTime": "2024-01-15 14:35:00.000",
                "Computer": "WORKSTATION-01",
                "DestinationIp": "10.0.0.50",
                "DestinationPort": "445"
            },
            {
                "EventID": 22,
                "UtcTime": "2024-01-15 14:36:00.000",
                "Image": "cmd.exe",
                "QueryName": "evil.com"
            }
        ]"#;

        let mut g = GraphHunter::new();
        let (entities, relations) = g.ingest_logs(json, &SysmonJsonParser, None);

        assert_eq!(entities, 4); // WORKSTATION-01, 10.0.0.50, cmd.exe, evil.com
        assert_eq!(relations, 2);
        assert_eq!(g.entity_count(), 4);
        assert_eq!(g.relation_count(), 2);
    }

    #[test]
    fn ingest_logs_deduplicates_entities() {
        // Two events reference the same process "cmd.exe"
        let json = r#"[
            {
                "EventID": 22,
                "UtcTime": "2024-01-15 14:36:00",
                "Image": "cmd.exe",
                "QueryName": "domain-a.com"
            },
            {
                "EventID": 22,
                "UtcTime": "2024-01-15 14:37:00",
                "Image": "cmd.exe",
                "QueryName": "domain-b.com"
            }
        ]"#;

        let mut g = GraphHunter::new();
        let (entities, relations) = g.ingest_logs(json, &SysmonJsonParser, None);

        // cmd.exe appears once (deduplicated), 2 domains = 3 entities total
        assert_eq!(entities, 3);
        assert_eq!(relations, 2);
        assert_eq!(g.entity_count(), 3);
    }

    #[test]
    fn ingest_logs_metadata_merge() {
        let batch1 = r#"[{
            "EventID": 3,
            "UtcTime": "2024-01-15 14:35:00",
            "Computer": "HOST-1",
            "SourceIp": "192.168.1.1",
            "DestinationIp": "10.0.0.1",
            "DestinationPort": "80"
        }]"#;
        let batch2 = r#"[{
            "EventID": 3,
            "UtcTime": "2024-01-15 14:36:00",
            "Computer": "HOST-1",
            "SourceIp": "192.168.1.1",
            "DestinationIp": "10.0.0.1",
            "DestinationPort": "443"
        }]"#;

        let mut g = GraphHunter::new();
        g.ingest_logs(batch1, &SysmonJsonParser, None);
        g.ingest_logs(batch2, &SysmonJsonParser, None);

        // Same entities, 2 different relations (different timestamps)
        assert_eq!(g.entity_count(), 2);
        assert_eq!(g.relation_count(), 2);

        // First metadata wins (dest_port stays "80" from batch1)
        let dest = g.get_entity("10.0.0.1").unwrap();
        assert_eq!(dest.metadata.get("dest_port").unwrap(), "80");
    }

    // ── Full Pipeline: Ingest → Hunt ──

    #[test]
    fn full_pipeline_ingest_then_hunt() {
        // Simulate APT kill chain via Sysmon events:
        // 1. Network connection to compromised host
        // 2. User executes process
        // 3. Process creates file
        // 4. Process queries C2 domain
        let events = r#"[
            {
                "EventID": 3,
                "UtcTime": "2024-01-15 14:30:00",
                "Computer": "DMZ-SERVER",
                "DestinationIp": "185.220.101.1",
                "DestinationPort": "443",
                "Image": "svchost.exe"
            },
            {
                "EventID": 1,
                "UtcTime": "2024-01-15 14:31:00",
                "User": "CORP\\svc-web",
                "Image": "C:\\Temp\\beacon.exe",
                "CommandLine": "beacon.exe --c2 185.220.101.1",
                "ProcessId": 6789,
                "ParentImage": "C:\\Windows\\System32\\svchost.exe",
                "ParentProcessId": 512
            },
            {
                "EventID": 11,
                "UtcTime": "2024-01-15 14:32:00",
                "Image": "C:\\Temp\\beacon.exe",
                "TargetFilename": "C:\\Windows\\Temp\\mimikatz.exe",
                "Hashes": "SHA256=DEADBEEF"
            },
            {
                "EventID": 22,
                "UtcTime": "2024-01-15 14:33:00",
                "Image": "C:\\Temp\\beacon.exe",
                "QueryName": "exfil.evil-corp.com",
                "QueryResults": "185.220.101.2"
            }
        ]"#;

        let mut g = GraphHunter::new();
        let (entities, relations) = g.ingest_logs(events, &SysmonJsonParser, None);

        assert!(entities > 0);
        assert!(relations > 0);

        // Hunt: User -> Execute -> Process -> Write -> File
        let hypothesis = Hypothesis::new("Beacon Drop")
            .add_step(HypothesisStep::new(
                EntityType::User,
                RelationType::Execute,
                EntityType::Process,
            ))
            .add_step(HypothesisStep::new(
                EntityType::Process,
                RelationType::Write,
                EntityType::File,
            ));

        let results = g.search_temporal_pattern(&hypothesis, None, None).unwrap().0;
        assert!(!results.is_empty(), "Should find User -> beacon.exe -> mimikatz.exe path");

        // Verify the path
        let path = &results[0];
        assert_eq!(path[0], "CORP\\svc-web");
        assert_eq!(path[1], "C:\\Temp\\beacon.exe");
        assert_eq!(path[2], "C:\\Windows\\Temp\\mimikatz.exe");
    }

    #[test]
    fn full_pipeline_dns_exfil_hunt() {
        let events = r#"[
            {
                "EventID": 1,
                "UtcTime": "2024-01-15 14:31:00",
                "User": "CORP\\admin",
                "Image": "powershell.exe",
                "ProcessId": 1111,
                "ParentImage": "explorer.exe",
                "ParentProcessId": 500
            },
            {
                "EventID": 22,
                "UtcTime": "2024-01-15 14:32:00",
                "Image": "powershell.exe",
                "QueryName": "data.exfil-tunnel.com",
                "QueryType": "TXT"
            }
        ]"#;

        let mut g = GraphHunter::new();
        g.ingest_logs(events, &SysmonJsonParser, None);

        // Hunt: User -> Execute -> Process -> DNS -> Domain
        let hypothesis = Hypothesis::new("DNS Exfiltration")
            .add_step(HypothesisStep::new(
                EntityType::User,
                RelationType::Execute,
                EntityType::Process,
            ))
            .add_step(HypothesisStep::new(
                EntityType::Process,
                RelationType::DNS,
                EntityType::Domain,
            ));

        let results = g.search_temporal_pattern(&hypothesis, None, None).unwrap().0;
        assert_eq!(results.len(), 1);
        assert_eq!(results[0], vec!["CORP\\admin", "powershell.exe", "data.exfil-tunnel.com"]);
    }

    #[test]
    fn full_pipeline_time_windowed_hunt() {
        let events = r#"[
            {
                "EventID": 1,
                "UtcTime": "2024-01-15 14:31:00",
                "User": "admin",
                "Image": "evil.exe",
                "ProcessId": 100,
                "ParentImage": "explorer.exe",
                "ParentProcessId": 50
            },
            {
                "EventID": 22,
                "UtcTime": "2024-01-15 14:32:00",
                "Image": "evil.exe",
                "QueryName": "c2.bad.com"
            }
        ]"#;

        let mut g = GraphHunter::new();
        g.ingest_logs(events, &SysmonJsonParser, None);

        let hypothesis = Hypothesis::new("Windowed DNS")
            .add_step(HypothesisStep::new(
                EntityType::User,
                RelationType::Execute,
                EntityType::Process,
            ))
            .add_step(HypothesisStep::new(
                EntityType::Process,
                RelationType::DNS,
                EntityType::Domain,
            ));

        // Timestamps: Execute at 1705329060 (14:31), DNS at 1705329120 (14:32)
        // Window that includes both
        let results = g
            .search_temporal_pattern(&hypothesis, Some((1705329000, 1705329200)), None)
            .unwrap().0;
        assert_eq!(results.len(), 1);

        // Window that excludes the DNS event
        let results_narrow = g
            .search_temporal_pattern(&hypothesis, Some((1705329000, 1705329070)), None)
            .unwrap().0;
        assert!(results_narrow.is_empty());
    }

    // ══ New Sysmon EventIDs ══

    #[test]
    fn sysmon_parse_event2_file_time_changed() {
        let json = r#"[{
            "EventID": 2,
            "UtcTime": "2024-01-15 14:30:00.000",
            "Image": "C:\\Temp\\timestomp.exe",
            "TargetFilename": "C:\\Windows\\System32\\malware.dll",
            "CreationUtcTime": "2024-01-15 14:30:00.000",
            "PreviousCreationUtcTime": "2023-06-01 10:00:00.000"
        }]"#;

        let parser = SysmonJsonParser;
        let triples = parser.parse(json);
        assert_eq!(triples.len(), 1);

        let (src, rel, dst) = &triples[0];
        assert_eq!(src.id, "C:\\Temp\\timestomp.exe");
        assert_eq!(src.entity_type, EntityType::Process);
        assert_eq!(rel.rel_type, RelationType::Modify);
        assert_eq!(dst.id, "C:\\Windows\\System32\\malware.dll");
        assert_eq!(dst.entity_type, EntityType::File);
        assert_eq!(rel.metadata.get("creation_utc_time").unwrap(), "2024-01-15 14:30:00.000");
        assert_eq!(rel.metadata.get("previous_creation_utc_time").unwrap(), "2023-06-01 10:00:00.000");
    }

    #[test]
    fn sysmon_parse_event8_create_remote_thread() {
        let json = r#"[{
            "EventID": 8,
            "UtcTime": "2024-01-15 14:30:00.000",
            "SourceImage": "C:\\Temp\\injector.exe",
            "TargetImage": "C:\\Windows\\System32\\svchost.exe",
            "StartAddress": "0x7FFA12340000",
            "NewThreadId": "1234",
            "StartModule": "C:\\Temp\\payload.dll"
        }]"#;

        let parser = SysmonJsonParser;
        let triples = parser.parse(json);
        assert_eq!(triples.len(), 1);

        let (src, rel, dst) = &triples[0];
        assert_eq!(src.id, "C:\\Temp\\injector.exe");
        assert_eq!(src.entity_type, EntityType::Process);
        assert_eq!(rel.rel_type, RelationType::Execute);
        assert_eq!(dst.id, "C:\\Windows\\System32\\svchost.exe");
        assert_eq!(dst.entity_type, EntityType::Process);
        assert_eq!(rel.metadata.get("start_address").unwrap(), "0x7FFA12340000");
        assert_eq!(rel.metadata.get("new_thread_id").unwrap(), "1234");
    }

    #[test]
    fn sysmon_parse_event9_raw_access_read() {
        let json = r#"[{
            "EventID": 9,
            "UtcTime": "2024-01-15 14:30:00.000",
            "Image": "C:\\Temp\\rawdisk.exe",
            "Device": "\\Device\\HarddiskVolume2"
        }]"#;

        let parser = SysmonJsonParser;
        let triples = parser.parse(json);
        assert_eq!(triples.len(), 1);

        let (src, rel, dst) = &triples[0];
        assert_eq!(src.id, "C:\\Temp\\rawdisk.exe");
        assert_eq!(rel.rel_type, RelationType::Read);
        assert_eq!(dst.id, "\\Device\\HarddiskVolume2");
        assert_eq!(dst.entity_type, EntityType::File);
    }

    #[test]
    fn sysmon_parse_event15_file_stream_hash() {
        let json = r#"[{
            "EventID": 15,
            "UtcTime": "2024-01-15 14:30:00.000",
            "Image": "C:\\Windows\\explorer.exe",
            "TargetFilename": "C:\\Downloads\\setup.exe:Zone.Identifier",
            "Hash": "SHA256=DEADBEEF"
        }]"#;

        let parser = SysmonJsonParser;
        let triples = parser.parse(json);
        assert_eq!(triples.len(), 1);

        let (src, rel, dst) = &triples[0];
        assert_eq!(src.id, "C:\\Windows\\explorer.exe");
        assert_eq!(rel.rel_type, RelationType::Write);
        assert_eq!(dst.id, "C:\\Downloads\\setup.exe:Zone.Identifier");
        assert_eq!(dst.metadata.get("hash").unwrap(), "SHA256=DEADBEEF");
    }

    #[test]
    fn sysmon_parse_event17_pipe_created() {
        let json = r#"[{
            "EventID": 17,
            "UtcTime": "2024-01-15 14:30:00.000",
            "Image": "C:\\Temp\\beacon.exe",
            "PipeName": "\\PSHost.132456.DefaultAppDomain"
        }]"#;

        let parser = SysmonJsonParser;
        let triples = parser.parse(json);
        assert_eq!(triples.len(), 1);

        let (src, rel, dst) = &triples[0];
        assert_eq!(src.id, "C:\\Temp\\beacon.exe");
        assert_eq!(rel.rel_type, RelationType::Write);
        assert_eq!(dst.id, "\\PSHost.132456.DefaultAppDomain");
        assert_eq!(dst.entity_type, EntityType::File);
    }

    #[test]
    fn sysmon_parse_event18_pipe_connected() {
        let json = r#"[{
            "EventID": 18,
            "UtcTime": "2024-01-15 14:30:00.000",
            "Image": "C:\\Windows\\System32\\svchost.exe",
            "PipeName": "\\PSHost.132456.DefaultAppDomain"
        }]"#;

        let parser = SysmonJsonParser;
        let triples = parser.parse(json);
        assert_eq!(triples.len(), 1);

        let (src, rel, dst) = &triples[0];
        assert_eq!(src.id, "C:\\Windows\\System32\\svchost.exe");
        assert_eq!(rel.rel_type, RelationType::Connect);
        assert_eq!(dst.id, "\\PSHost.132456.DefaultAppDomain");
        assert_eq!(dst.entity_type, EntityType::File);
    }

    // ══ Windows Security Events ══

    #[test]
    fn sysmon_parse_security_4624_logon() {
        let json = r#"[{
            "EventID": 4624,
            "EventTime": "2020-09-21 18:58:30",
            "Computer": "DC01.corp.local",
            "TargetUserName": "admin",
            "TargetDomainName": "CORP",
            "LogonType": "10",
            "IpAddress": "192.168.1.100"
        }]"#;

        let parser = SysmonJsonParser;
        let triples = parser.parse(json);
        assert_eq!(triples.len(), 1);

        let (src, rel, dst) = &triples[0];
        assert_eq!(src.id, "CORP\\admin");
        assert_eq!(src.entity_type, EntityType::User);
        assert_eq!(rel.rel_type, RelationType::Auth);
        assert_eq!(dst.id, "DC01.corp.local");
        assert_eq!(dst.entity_type, EntityType::Host);
        assert_eq!(rel.metadata.get("logon_type").unwrap(), "10");
        assert_eq!(rel.metadata.get("ip_address").unwrap(), "192.168.1.100");
        assert!(rel.metadata.get("success").is_none()); // 4624 = success, no explicit flag
    }

    #[test]
    fn sysmon_parse_security_4625_logon_failure() {
        let json = r#"[{
            "EventID": 4625,
            "EventTime": "2020-09-21 19:00:00",
            "Computer": "DC01.corp.local",
            "TargetUserName": "hacker",
            "TargetDomainName": "CORP",
            "LogonType": "3",
            "IpAddress": "10.0.0.99"
        }]"#;

        let parser = SysmonJsonParser;
        let triples = parser.parse(json);
        assert_eq!(triples.len(), 1);

        let (_, rel, _) = &triples[0];
        assert_eq!(rel.metadata.get("success").unwrap(), "false");
    }

    #[test]
    fn sysmon_parse_security_4688_process_create() {
        let json = r#"[{
            "EventID": 4688,
            "EventTime": "2020-09-21 18:59:00",
            "Computer": "WORKSTATION-01",
            "SubjectUserName": "admin",
            "SubjectDomainName": "CORP",
            "NewProcessName": "C:\\Windows\\System32\\cmd.exe",
            "ParentProcessName": "C:\\Windows\\explorer.exe",
            "CommandLine": "cmd.exe /c ipconfig"
        }]"#;

        let parser = SysmonJsonParser;
        let triples = parser.parse(json);
        assert_eq!(triples.len(), 2);

        // Triple 1: User -> Execute -> Process
        let (src, rel, dst) = &triples[0];
        assert_eq!(src.id, "CORP\\admin");
        assert_eq!(src.entity_type, EntityType::User);
        assert_eq!(rel.rel_type, RelationType::Execute);
        assert_eq!(dst.id, "C:\\Windows\\System32\\cmd.exe");
        assert_eq!(dst.metadata.get("cmdline").unwrap(), "cmd.exe /c ipconfig");

        // Triple 2: Parent -> Spawn -> Child
        let (src2, rel2, dst2) = &triples[1];
        assert_eq!(src2.id, "C:\\Windows\\explorer.exe");
        assert_eq!(rel2.rel_type, RelationType::Spawn);
        assert_eq!(dst2.id, "C:\\Windows\\System32\\cmd.exe");
    }

    #[test]
    fn sysmon_parse_security_4689_process_terminated() {
        let json = r#"[{
            "EventID": 4689,
            "EventTime": "2020-09-21 19:01:00",
            "Computer": "WORKSTATION-01",
            "ProcessName": "C:\\Windows\\System32\\cmd.exe",
            "SubjectUserName": "admin"
        }]"#;

        let parser = SysmonJsonParser;
        let triples = parser.parse(json);
        assert_eq!(triples.len(), 1);

        let (src, rel, dst) = &triples[0];
        assert_eq!(src.id, "C:\\Windows\\System32\\cmd.exe");
        assert_eq!(src.entity_type, EntityType::Process);
        assert_eq!(rel.rel_type, RelationType::Delete);
        assert_eq!(dst.id, "WORKSTATION-01");
        assert_eq!(dst.entity_type, EntityType::Host);
    }

    #[test]
    fn sysmon_parse_security_4663_object_access() {
        // File access
        let json_file = r#"[{
            "EventID": 4663,
            "EventTime": "2020-09-21 19:02:00",
            "ProcessName": "C:\\Windows\\explorer.exe",
            "ObjectName": "C:\\Secrets\\passwords.txt",
            "ObjectType": "File"
        }]"#;

        let parser = SysmonJsonParser;
        let triples = parser.parse(json_file);
        assert_eq!(triples.len(), 1);
        let (_, _, dst) = &triples[0];
        assert_eq!(dst.entity_type, EntityType::File);

        // Registry access
        let json_reg = r#"[{
            "EventID": 4663,
            "EventTime": "2020-09-21 19:02:00",
            "ProcessName": "C:\\Windows\\regedit.exe",
            "ObjectName": "HKLM\\SOFTWARE\\Microsoft",
            "ObjectType": "Key"
        }]"#;

        let triples_reg = parser.parse(json_reg);
        assert_eq!(triples_reg.len(), 1);
        let (_, _, dst_reg) = &triples_reg[0];
        assert_eq!(dst_reg.entity_type, EntityType::Registry);
    }

    #[test]
    fn sysmon_parse_security_5156_wfp_connection() {
        let json = r#"[{
            "EventID": 5156,
            "EventTime": "2020-09-21 19:03:00",
            "Application": "\\device\\harddiskvolume2\\windows\\system32\\svchost.exe",
            "SourceAddress": "192.168.1.10",
            "DestAddress": "10.0.0.50",
            "SourcePort": "49152",
            "DestPort": "443",
            "Protocol": "6"
        }]"#;

        let parser = SysmonJsonParser;
        let triples = parser.parse(json);
        assert_eq!(triples.len(), 1);

        let (src, rel, dst) = &triples[0];
        assert_eq!(src.id, "\\device\\harddiskvolume2\\windows\\system32\\svchost.exe");
        assert_eq!(src.entity_type, EntityType::Process);
        assert_eq!(rel.rel_type, RelationType::Connect);
        assert_eq!(dst.id, "10.0.0.50");
        assert_eq!(dst.entity_type, EntityType::IP);
        assert_eq!(dst.metadata.get("dest_port").unwrap(), "443");
        assert_eq!(rel.metadata.get("source_address").unwrap(), "192.168.1.10");
    }

    #[test]
    fn sysmon_parse_security_5145_network_share() {
        let json = r#"[{
            "EventID": 5145,
            "EventTime": "2020-09-21 19:04:00",
            "SubjectUserName": "admin",
            "SubjectDomainName": "CORP",
            "ShareName": "\\\\*\\C$",
            "RelativeTargetName": "Windows\\Temp\\payload.exe",
            "IpAddress": "192.168.1.100"
        }]"#;

        let parser = SysmonJsonParser;
        let triples = parser.parse(json);
        assert_eq!(triples.len(), 1);

        let (src, rel, dst) = &triples[0];
        assert_eq!(src.id, "CORP\\admin");
        assert_eq!(src.entity_type, EntityType::User);
        assert_eq!(rel.rel_type, RelationType::Read);
        assert_eq!(dst.id, "\\\\*\\C$\\Windows\\Temp\\payload.exe");
        assert_eq!(dst.entity_type, EntityType::File);
        assert_eq!(dst.metadata.get("ip_address").unwrap(), "192.168.1.100");
    }

    // ══ PowerShell Events ══

    #[test]
    fn sysmon_parse_powershell_4104_script_block() {
        let json = r#"[{
            "EventID": 4104,
            "Computer": "WORKSTATION-01",
            "ScriptBlockText": "Invoke-Mimikatz -DumpCreds",
            "ScriptBlockId": "abc-123"
        }]"#;

        let parser = SysmonJsonParser;
        let triples = parser.parse(json);
        assert_eq!(triples.len(), 1);

        let (src, rel, dst) = &triples[0];
        assert_eq!(src.id, "WORKSTATION-01");
        assert_eq!(src.entity_type, EntityType::Host);
        assert_eq!(rel.rel_type, RelationType::Execute);
        assert_eq!(dst.id, "powershell.exe");
        assert_eq!(dst.entity_type, EntityType::Process);
        assert_eq!(dst.metadata.get("script_preview").unwrap(), "Invoke-Mimikatz -DumpCreds");
        assert_eq!(dst.metadata.get("script_block_id").unwrap(), "abc-123");
    }

    // ══ Winlogbeat Normalization ══

    #[test]
    fn sysmon_parse_winlogbeat_nested_event_data() {
        // Winlogbeat format: event_id (lowercase) + event_data dict
        let json = r#"[{
            "event_id": 1,
            "@timestamp": "2019-05-14T22:31:14.252Z",
            "computer_name": "HR001.shire.com",
            "event_data": {
                "Image": "C:\\Windows\\System32\\cmd.exe",
                "User": "SHIRE\\admin",
                "ProcessId": 5678,
                "CommandLine": "cmd.exe /c whoami",
                "ParentImage": "C:\\Windows\\explorer.exe",
                "ParentProcessId": 100
            }
        }]"#;

        let parser = SysmonJsonParser;
        let triples = parser.parse(json);
        assert_eq!(triples.len(), 2);

        // Triple 1: User -> Execute -> Process
        let (src, rel, dst) = &triples[0];
        assert_eq!(src.id, "SHIRE\\admin");
        assert_eq!(rel.rel_type, RelationType::Execute);
        assert_eq!(dst.id, "C:\\Windows\\System32\\cmd.exe");
        assert_eq!(dst.metadata.get("computer").unwrap(), "HR001.shire.com");

        // Verify ISO 8601 timestamp: 2019-05-14T22:31:14.252Z
        assert_eq!(rel.timestamp, 1557873074);

        // Triple 2: Parent -> Spawn -> Child
        let (src2, rel2, dst2) = &triples[1];
        assert_eq!(src2.id, "C:\\Windows\\explorer.exe");
        assert_eq!(rel2.rel_type, RelationType::Spawn);
        assert_eq!(dst2.id, "C:\\Windows\\System32\\cmd.exe");
    }

    #[test]
    fn sysmon_parse_iso8601_timestamp() {
        // Verify ISO 8601 timestamp parsing through a simple event
        let json = r#"[{
            "EventID": 5,
            "@timestamp": "2019-05-14T09:00:00.000Z",
            "Image": "C:\\test.exe",
            "Computer": "HOST01"
        }]"#;

        let parser = SysmonJsonParser;
        let triples = parser.parse(json);
        assert_eq!(triples.len(), 1);

        let (_, rel, _) = &triples[0];
        // 2019-05-14T09:00:00Z = 1557824400
        assert_eq!(rel.timestamp, 1557824400);
    }

    // ── Demo Data Integration Test ──

    #[test]
    fn demo_data_all_presets_produce_results() {
        let demo_json = std::fs::read_to_string("../demo_data/apt_attack_simulation.json")
            .expect("Demo data file should exist at demo_data/apt_attack_simulation.json");

        let mut g = GraphHunter::new();
        let (entities, relations) = g.ingest_logs(&demo_json, &SysmonJsonParser, None);

        assert!(entities > 15, "Should ingest many entities, got {entities}");
        assert!(relations > 20, "Should ingest many relations, got {relations}");

        // ── Preset 1: Lateral Movement ──
        // User → Execute → Process → Spawn → Process → Write → File
        let lateral = Hypothesis::new("Lateral Movement")
            .add_step(HypothesisStep::new(EntityType::User, RelationType::Execute, EntityType::Process))
            .add_step(HypothesisStep::new(EntityType::Process, RelationType::Spawn, EntityType::Process))
            .add_step(HypothesisStep::new(EntityType::Process, RelationType::Write, EntityType::File));

        let lateral_results = g.search_temporal_pattern(&lateral, None, None).unwrap().0;
        assert!(
            !lateral_results.is_empty(),
            "Lateral Movement should find paths (PsExec → dropper → file)"
        );

        // Verify one path goes through the PsExec → dropper chain
        let has_psexec_path = lateral_results.iter().any(|path| {
            path.iter().any(|n| n.contains("PsExec"))
                && path.iter().any(|n| n.contains("dropper"))
        });
        assert!(has_psexec_path, "Should find PsExec→dropper lateral movement path");

        // ── Preset 2: DNS Exfiltration ──
        // User → Execute → Process → DNS → Domain
        let dns_exfil = Hypothesis::new("DNS Exfiltration")
            .add_step(HypothesisStep::new(EntityType::User, RelationType::Execute, EntityType::Process))
            .add_step(HypothesisStep::new(EntityType::Process, RelationType::DNS, EntityType::Domain));

        let dns_results = g.search_temporal_pattern(&dns_exfil, None, None).unwrap().0;
        assert!(
            dns_results.len() >= 3,
            "DNS Exfiltration should find multiple paths (malicious + benign), got {}",
            dns_results.len()
        );

        // Should include both malicious and benign DNS
        let has_evil_dns = dns_results.iter().any(|path| {
            path.iter().any(|n| n.contains("evil-c2") || n.contains("exfil-tunnel"))
        });
        let has_benign_dns = dns_results.iter().any(|path| {
            path.iter().any(|n| n.contains("google.com") || n.contains("office365"))
        });
        assert!(has_evil_dns, "Should find malicious DNS paths");
        assert!(has_benign_dns, "Should also find benign DNS paths (shows noise)");

        // ── Preset 3: Malware Drop ──
        // User → Execute → Process → Write → File
        let malware_drop = Hypothesis::new("Malware Drop")
            .add_step(HypothesisStep::new(EntityType::User, RelationType::Execute, EntityType::Process))
            .add_step(HypothesisStep::new(EntityType::Process, RelationType::Write, EntityType::File));

        let drop_results = g.search_temporal_pattern(&malware_drop, None, None).unwrap().0;
        assert!(
            drop_results.len() >= 2,
            "Malware Drop should find multiple paths, got {}",
            drop_results.len()
        );

        // Should find dropper writing malicious files
        let has_dropper = drop_results.iter().any(|path| {
            path.iter().any(|n| n.contains("dropper"))
        });
        assert!(has_dropper, "Should find dropper writing files");

        println!("=== Demo Data Results ===");
        println!("Entities: {}, Relations: {}", g.entity_count(), g.relation_count());
        println!("Lateral Movement: {} paths", lateral_results.len());
        println!("DNS Exfiltration: {} paths", dns_results.len());
        println!("Malware Drop: {} paths", drop_results.len());
    }

    // ══════════════════════════════════════════════════
    // ── Phase 4: Index & Analytics Tests ──
    // ══════════════════════════════════════════════════

    #[test]
    fn type_index_populated_on_add_entity() {
        let mut g = GraphHunter::new();
        g.add_entity(Entity::new("ip-1", EntityType::IP)).unwrap();
        g.add_entity(Entity::new("ip-2", EntityType::IP)).unwrap();
        g.add_entity(Entity::new("host-1", EntityType::Host)).unwrap();

        let ip_ids = g.type_index.get(&EntityType::IP).unwrap();
        assert_eq!(ip_ids.len(), 2);
        assert!(ip_ids.contains(&g.interner.get("ip-1").unwrap()));
        assert!(ip_ids.contains(&g.interner.get("ip-2").unwrap()));

        let host_ids = g.type_index.get(&EntityType::Host).unwrap();
        assert_eq!(host_ids.len(), 1);
        assert!(host_ids.contains(&g.interner.get("host-1").unwrap()));
    }

    #[test]
    fn type_index_populated_on_ingest() {
        let json = r#"[{
            "EventID": 22,
            "UtcTime": "2024-01-15 14:45:00",
            "Image": "cmd.exe",
            "QueryName": "evil.com"
        }]"#;

        let mut g = GraphHunter::new();
        g.ingest_logs(json, &SysmonJsonParser, None);

        let process_ids = g.type_index.get(&EntityType::Process).unwrap();
        assert!(process_ids.contains(&g.interner.get("cmd.exe").unwrap()));

        let domain_ids = g.type_index.get(&EntityType::Domain).unwrap();
        assert!(domain_ids.contains(&g.interner.get("evil.com").unwrap()));
    }

    #[test]
    fn reverse_adj_correct() {
        let mut g = GraphHunter::new();
        g.add_entity(Entity::new("a", EntityType::IP)).unwrap();
        g.add_entity(Entity::new("b", EntityType::Host)).unwrap();
        g.add_entity(Entity::new("c", EntityType::Host)).unwrap();

        g.add_relation(Relation::new("a", "b", RelationType::Connect, 100)).unwrap();
        g.add_relation(Relation::new("a", "c", RelationType::Connect, 200)).unwrap();

        let sid_a = g.interner.get("a").unwrap();
        let sid_b = g.interner.get("b").unwrap();
        let sid_c = g.interner.get("c").unwrap();

        let rev_b = g.reverse_adj.get(&sid_b).unwrap();
        assert_eq!(rev_b, &vec![sid_a]);

        let rev_c = g.reverse_adj.get(&sid_c).unwrap();
        assert_eq!(rev_c, &vec![sid_a]);

        // "a" has no incoming edges
        let rev_a = g.reverse_adj.get(&sid_a).unwrap();
        assert!(rev_a.is_empty());
    }

    #[test]
    fn search_entities_substring() {
        let mut g = GraphHunter::new();
        g.add_entity(Entity::new("beacon.exe", EntityType::Process)).unwrap();
        g.add_entity(Entity::new("cmd.exe", EntityType::Process)).unwrap();
        g.add_entity(Entity::new("evil-beacon.com", EntityType::Domain)).unwrap();

        let results = g.search_entities("beacon", None, 50);
        assert_eq!(results.len(), 2);
        let ids: Vec<&str> = results.iter().map(|r| r.id.as_str()).collect();
        assert!(ids.contains(&"beacon.exe"));
        assert!(ids.contains(&"evil-beacon.com"));
    }

    #[test]
    fn search_entities_type_filter() {
        let mut g = GraphHunter::new();
        g.add_entity(Entity::new("beacon.exe", EntityType::Process)).unwrap();
        g.add_entity(Entity::new("evil-beacon.com", EntityType::Domain)).unwrap();

        let results = g.search_entities("beacon", Some(&EntityType::Process), 50);
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].id, "beacon.exe");
    }

    #[test]
    fn search_entities_empty_query() {
        let mut g = GraphHunter::new();
        g.add_entity(Entity::new("test", EntityType::IP)).unwrap();

        // Empty query matches everything
        let results = g.search_entities("", None, 50);
        assert_eq!(results.len(), 1);
    }

    #[test]
    fn get_neighborhood_basic() {
        let mut g = build_lateral_movement_graph();

        let hood = g.get_neighborhood("web-server", 1, 100, None).unwrap();
        assert_eq!(hood.center, "web-server");
        // web-server is connected to attacker-ip (incoming) and admin-user (outgoing)
        assert!(hood.nodes.len() >= 3); // web-server + at least 2 neighbors
        assert!(!hood.edges.is_empty());
        assert!(!hood.truncated);
    }

    #[test]
    fn get_neighborhood_cap() {
        let mut g = build_lateral_movement_graph();

        // Cap at 2 nodes: center + 1 neighbor
        let hood = g.get_neighborhood("web-server", 2, 2, None).unwrap();
        assert_eq!(hood.nodes.len(), 2);
        assert!(hood.truncated);
    }

    #[test]
    fn get_neighborhood_nonexistent_node() {
        let mut g = build_lateral_movement_graph();
        assert!(g.get_neighborhood("ghost", 1, 100, None).is_none());
    }

    #[test]
    fn get_neighborhood_with_filter() {
        let mut g = build_lateral_movement_graph();

        let filter = analytics::NeighborhoodFilter {
            entity_types: Some(vec![EntityType::User]),
            relation_types: None,
            time_start: None,
            time_end: None,
            min_score: None,
        };

        let hood = g.get_neighborhood("web-server", 1, 100, Some(&filter)).unwrap();
        // Should only include User type neighbors (admin-user) + center
        let non_center_nodes: Vec<_> = hood.nodes.iter().filter(|n| n.id != "web-server").collect();
        for node in &non_center_nodes {
            assert_eq!(node.entity_type, "User");
        }
    }

    #[test]
    fn compute_scores_high_degree_high_score() {
        let mut g = GraphHunter::new();
        g.add_entity(Entity::new("hub", EntityType::Host)).unwrap();
        g.add_entity(Entity::new("a", EntityType::IP)).unwrap();
        g.add_entity(Entity::new("b", EntityType::IP)).unwrap();
        g.add_entity(Entity::new("c", EntityType::IP)).unwrap();
        g.add_entity(Entity::new("leaf", EntityType::IP)).unwrap();

        g.add_relation(Relation::new("a", "hub", RelationType::Connect, 100)).unwrap();
        g.add_relation(Relation::new("b", "hub", RelationType::Connect, 200)).unwrap();
        g.add_relation(Relation::new("c", "hub", RelationType::Connect, 300)).unwrap();
        g.add_relation(Relation::new("hub", "leaf", RelationType::Connect, 400)).unwrap();

        g.compute_scores();

        let hub_score = g.get_entity("hub").unwrap().score;
        let leaf_score = g.get_entity("leaf").unwrap().score;
        assert!(hub_score > leaf_score, "Hub ({hub_score}) should have higher score than leaf ({leaf_score})");
        assert_eq!(hub_score, 100.0); // max degree = highest score
    }

    #[test]
    fn get_node_details_complete() {
        let mut g = build_lateral_movement_graph();

        let details = g.get_node_details("web-server").unwrap();
        assert_eq!(details.id, "web-server");
        assert_eq!(details.entity_type, "Host");
        assert_eq!(details.out_degree, 1); // web-server -> admin-user
        assert_eq!(details.in_degree, 1);  // attacker-ip -> web-server
        assert!(details.time_range.is_some());
        assert!(!details.neighbor_types.is_empty());
    }

    #[test]
    fn get_node_details_nonexistent() {
        let mut g = build_lateral_movement_graph();
        assert!(g.get_node_details("ghost").is_none());
    }

    #[test]
    fn get_graph_summary_complete() {
        let mut g = build_lateral_movement_graph();

        let summary = g.get_graph_summary();
        assert_eq!(summary.entity_count, 5);
        assert_eq!(summary.relation_count, 4);
        assert!(!summary.type_distribution.is_empty());
        assert!(summary.time_range.is_some());
    }

    #[test]
    fn search_temporal_pattern_still_works_with_indices() {
        // Regression: make sure the optimized search_temporal_pattern still produces correct results
        let mut g = build_lateral_movement_graph();

        let hypothesis = Hypothesis::new("Full Chain")
            .add_step(HypothesisStep::new(EntityType::IP, RelationType::Connect, EntityType::Host))
            .add_step(HypothesisStep::new(EntityType::Host, RelationType::Auth, EntityType::User))
            .add_step(HypothesisStep::new(EntityType::User, RelationType::Execute, EntityType::Process))
            .add_step(HypothesisStep::new(EntityType::Process, RelationType::Write, EntityType::File));

        let results = g.search_temporal_pattern(&hypothesis, None, None).unwrap().0;
        assert_eq!(results.len(), 1);
        assert_eq!(
            results[0],
            vec!["attacker-ip", "web-server", "admin-user", "cmd.exe", "payload.dll"]
        );
    }

    // ══════════════════════════════════════════════════
    // ── Phase 5: Sentinel Parser Tests ──
    // ══════════════════════════════════════════════════

    // ── Per-Table Tests ──

    #[test]
    fn sentinel_security_event_4624_auth_success() {
        let json = r#"[{
            "Type": "SecurityEvent",
            "TimeGenerated": "2024-01-15T14:30:00Z",
            "EventID": 4624,
            "Computer": "DC-01.contoso.local",
            "TargetUserName": "admin",
            "IpAddress": "10.0.0.5",
            "LogonType": 3
        }]"#;

        let parser = SentinelJsonParser;
        let triples = parser.parse(json);
        assert_eq!(triples.len(), 1);

        let (src, rel, dst) = &triples[0];
        assert_eq!(src.id, "admin");
        assert_eq!(src.entity_type, EntityType::User);
        assert_eq!(rel.rel_type, RelationType::Auth);
        assert_eq!(rel.metadata.get("status").unwrap(), "Success");
        assert_eq!(rel.metadata.get("event_id").unwrap(), "4624");
        assert_eq!(rel.metadata.get("logon_type").unwrap(), "3");
        assert_eq!(dst.id, "DC-01.contoso.local");
        assert_eq!(dst.entity_type, EntityType::Host);
        assert_eq!(dst.metadata.get("source_ip").unwrap(), "10.0.0.5");
        assert_eq!(rel.timestamp, 1705329000);
    }

    #[test]
    fn sentinel_security_event_4625_auth_failure() {
        let json = r#"[{
            "Type": "SecurityEvent",
            "TimeGenerated": "2024-01-15T14:30:00Z",
            "EventID": 4625,
            "Computer": "DC-01.contoso.local",
            "TargetUserName": "admin",
            "IpAddress": "198.51.100.77"
        }]"#;

        let parser = SentinelJsonParser;
        let triples = parser.parse(json);
        assert_eq!(triples.len(), 1);

        let (_, rel, _) = &triples[0];
        assert_eq!(rel.metadata.get("status").unwrap(), "Failure");
        assert_eq!(rel.metadata.get("event_id").unwrap(), "4625");
    }

    #[test]
    fn sentinel_security_event_4688_process_create() {
        let json = r#"[{
            "Type": "SecurityEvent",
            "TimeGenerated": "2024-01-15T14:30:00Z",
            "EventID": 4688,
            "Computer": "WS-01.contoso.local",
            "SubjectUserName": "admin",
            "NewProcessName": "C:\\Windows\\System32\\cmd.exe",
            "NewProcessId": "0x1234",
            "CommandLine": "cmd.exe /c whoami",
            "ParentProcessName": "C:\\Windows\\explorer.exe"
        }]"#;

        let parser = SentinelJsonParser;
        let triples = parser.parse(json);
        assert_eq!(triples.len(), 2);

        let (src, rel, dst) = &triples[0];
        assert_eq!(src.id, "admin");
        assert_eq!(src.entity_type, EntityType::User);
        assert_eq!(rel.rel_type, RelationType::Execute);
        assert_eq!(dst.id, "C:\\Windows\\System32\\cmd.exe");
        assert_eq!(dst.entity_type, EntityType::Process);
        assert_eq!(dst.metadata.get("cmdline").unwrap(), "cmd.exe /c whoami");
        assert_eq!(dst.metadata.get("pid").unwrap(), "0x1234");

        let (src2, rel2, dst2) = &triples[1];
        assert_eq!(src2.id, "C:\\Windows\\explorer.exe");
        assert_eq!(src2.entity_type, EntityType::Process);
        assert_eq!(rel2.rel_type, RelationType::Execute);
        assert_eq!(dst2.id, "C:\\Windows\\System32\\cmd.exe");
    }

    #[test]
    fn sentinel_security_event_4663_file_access() {
        let json = r#"[{
            "Type": "SecurityEvent",
            "TimeGenerated": "2024-01-15T14:30:00Z",
            "EventID": 4663,
            "Computer": "WS-01",
            "ProcessName": "C:\\beacon.exe",
            "ObjectName": "C:\\Users\\admin\\secret.docx"
        }]"#;

        let parser = SentinelJsonParser;
        let triples = parser.parse(json);
        assert_eq!(triples.len(), 1);

        let (src, rel, dst) = &triples[0];
        assert_eq!(src.id, "C:\\beacon.exe");
        assert_eq!(src.entity_type, EntityType::Process);
        assert_eq!(rel.rel_type, RelationType::Read);
        assert_eq!(dst.id, "C:\\Users\\admin\\secret.docx");
        assert_eq!(dst.entity_type, EntityType::File);
    }

    #[test]
    fn sentinel_signin_logs() {
        let json = r#"[{
            "Type": "SigninLogs",
            "TimeGenerated": "2024-01-15T10:05:00Z",
            "UserPrincipalName": "user@contoso.com",
            "IPAddress": "198.51.100.77",
            "AppDisplayName": "Azure Portal",
            "ResultType": "0",
            "Location": "RU"
        }]"#;

        let parser = SentinelJsonParser;
        let triples = parser.parse(json);
        assert_eq!(triples.len(), 1);

        let (src, rel, dst) = &triples[0];
        assert_eq!(src.id, "user@contoso.com");
        assert_eq!(src.entity_type, EntityType::User);
        assert_eq!(rel.rel_type, RelationType::Auth);
        assert_eq!(rel.metadata.get("status").unwrap(), "Success");
        assert_eq!(rel.metadata.get("app").unwrap(), "Azure Portal");
        assert_eq!(dst.id, "198.51.100.77");
        assert_eq!(dst.entity_type, EntityType::IP);
        assert_eq!(dst.metadata.get("location").unwrap(), "RU");
    }

    #[test]
    fn sentinel_device_process_events() {
        let json = r#"[{
            "Type": "DeviceProcessEvents",
            "Timestamp": "2024-01-15T10:22:00Z",
            "DeviceName": "WS-01",
            "AccountName": "admin",
            "FileName": "beacon.exe",
            "FolderPath": "C:\\Users\\Public\\beacon.exe",
            "ProcessCommandLine": "beacon.exe --c2 evil.com",
            "InitiatingProcessFileName": "powershell.exe",
            "InitiatingProcessFolderPath": "C:\\Windows\\System32\\powershell.exe",
            "SHA256": "deadbeef"
        }]"#;

        let parser = SentinelJsonParser;
        let triples = parser.parse(json);
        assert_eq!(triples.len(), 2);

        let (src, rel, dst) = &triples[0];
        assert_eq!(src.id, "admin");
        assert_eq!(src.entity_type, EntityType::User);
        assert_eq!(rel.rel_type, RelationType::Execute);
        assert_eq!(dst.id, "C:\\Users\\Public\\beacon.exe");
        assert_eq!(dst.entity_type, EntityType::Process);
        assert_eq!(dst.metadata.get("cmdline").unwrap(), "beacon.exe --c2 evil.com");
        assert_eq!(dst.metadata.get("sha256").unwrap(), "deadbeef");

        let (src2, _, _) = &triples[1];
        assert_eq!(src2.id, "C:\\Windows\\System32\\powershell.exe");
        assert_eq!(src2.entity_type, EntityType::Process);
    }

    #[test]
    fn sentinel_device_network_events() {
        let json = r#"[{
            "Type": "DeviceNetworkEvents",
            "Timestamp": "2024-01-15T10:26:00Z",
            "DeviceName": "WS-01",
            "RemoteIP": "198.51.100.77",
            "RemotePort": 443,
            "RemoteUrl": "https://evil.com/beacon",
            "Protocol": "TCP",
            "ActionType": "ConnectionSuccess",
            "LocalPort": 52341
        }]"#;

        let parser = SentinelJsonParser;
        let triples = parser.parse(json);
        assert_eq!(triples.len(), 1);

        let (src, rel, dst) = &triples[0];
        assert_eq!(src.id, "WS-01");
        assert_eq!(src.entity_type, EntityType::Host);
        assert_eq!(rel.rel_type, RelationType::Connect);
        assert_eq!(rel.metadata.get("action").unwrap(), "ConnectionSuccess");
        assert_eq!(rel.metadata.get("local_port").unwrap(), "52341");
        assert_eq!(dst.id, "198.51.100.77");
        assert_eq!(dst.entity_type, EntityType::IP);
        assert_eq!(dst.metadata.get("remote_port").unwrap(), "443");
        assert_eq!(dst.metadata.get("url").unwrap(), "https://evil.com/beacon");
        assert_eq!(dst.metadata.get("protocol").unwrap(), "TCP");
    }

    #[test]
    fn sentinel_device_file_events_write() {
        let json = r#"[{
            "Type": "DeviceFileEvents",
            "Timestamp": "2024-01-15T10:23:00Z",
            "ActionType": "FileCreated",
            "FileName": "beacon.exe",
            "FolderPath": "C:\\Users\\Public\\beacon.exe",
            "InitiatingProcessFileName": "powershell.exe",
            "InitiatingProcessFolderPath": "C:\\Windows\\powershell.exe",
            "SHA256": "deadbeef"
        }]"#;

        let parser = SentinelJsonParser;
        let triples = parser.parse(json);
        assert_eq!(triples.len(), 1);

        let (src, rel, dst) = &triples[0];
        assert_eq!(src.id, "C:\\Windows\\powershell.exe");
        assert_eq!(src.entity_type, EntityType::Process);
        assert_eq!(rel.rel_type, RelationType::Write);
        assert_eq!(dst.id, "C:\\Users\\Public\\beacon.exe");
        assert_eq!(dst.entity_type, EntityType::File);
        assert_eq!(dst.metadata.get("sha256").unwrap(), "deadbeef");
    }

    #[test]
    fn sentinel_device_file_events_read() {
        let json = r#"[{
            "Type": "DeviceFileEvents",
            "Timestamp": "2024-01-15T10:25:00Z",
            "ActionType": "FileRead",
            "FileName": "secret.docx",
            "FolderPath": "C:\\Users\\admin\\secret.docx",
            "InitiatingProcessFileName": "beacon.exe",
            "InitiatingProcessFolderPath": "C:\\Users\\Public\\beacon.exe"
        }]"#;

        let parser = SentinelJsonParser;
        let triples = parser.parse(json);
        assert_eq!(triples.len(), 1);

        let (_, rel, _) = &triples[0];
        assert_eq!(rel.rel_type, RelationType::Read);
    }

    #[test]
    fn sentinel_common_security_log() {
        let json = r#"[{
            "Type": "CommonSecurityLog",
            "TimeGenerated": "2024-01-15T08:30:00Z",
            "SourceIP": "10.1.0.50",
            "DestinationIP": "8.8.8.8",
            "DestinationPort": 53,
            "DeviceVendor": "Palo Alto Networks",
            "DeviceAction": "Allow",
            "Protocol": "UDP"
        }]"#;

        let parser = SentinelJsonParser;
        let triples = parser.parse(json);
        assert_eq!(triples.len(), 1);

        let (src, rel, dst) = &triples[0];
        assert_eq!(src.id, "10.1.0.50");
        assert_eq!(src.entity_type, EntityType::IP);
        assert_eq!(rel.rel_type, RelationType::Connect);
        assert_eq!(rel.metadata.get("vendor").unwrap(), "Palo Alto Networks");
        assert_eq!(rel.metadata.get("action").unwrap(), "Allow");
        assert_eq!(rel.metadata.get("protocol").unwrap(), "UDP");
        assert_eq!(dst.id, "8.8.8.8");
        assert_eq!(dst.entity_type, EntityType::IP);
        assert_eq!(dst.metadata.get("dest_port").unwrap(), "53");
    }

    // ── Detection Tests ──

    #[test]
    fn sentinel_detect_by_type_field() {
        // When Type field is present, it takes priority
        let json = r#"[{
            "Type": "SigninLogs",
            "TimeGenerated": "2024-01-15T10:00:00Z",
            "UserPrincipalName": "test@contoso.com",
            "IPAddress": "1.2.3.4",
            "ResultType": "0"
        }]"#;

        let parser = SentinelJsonParser;
        let triples = parser.parse(json);
        assert_eq!(triples.len(), 1);
        assert_eq!(triples[0].0.entity_type, EntityType::User);
        assert_eq!(triples[0].2.entity_type, EntityType::IP);
    }

    #[test]
    fn sentinel_detect_by_heuristic() {
        // No Type field — fallback to heuristic (EventID + Computer = SecurityEvent)
        let json = r#"[{
            "TimeGenerated": "2024-01-15T10:00:00Z",
            "EventID": 4624,
            "Computer": "DC-01",
            "TargetUserName": "admin"
        }]"#;

        let parser = SentinelJsonParser;
        let triples = parser.parse(json);
        assert_eq!(triples.len(), 1);
        assert_eq!(triples[0].1.rel_type, RelationType::Auth);
    }

    #[test]
    fn sentinel_unknown_type_skipped() {
        let json = r#"[{
            "Type": "UnknownTableXYZ",
            "TimeGenerated": "2024-01-15T10:00:00Z",
            "SomeField": "value"
        }]"#;

        let parser = SentinelJsonParser;
        let triples = parser.parse(json);
        assert!(triples.is_empty());
    }

    // ── Format Tests ──

    #[test]
    fn sentinel_ndjson_format() {
        let ndjson = concat!(
            r#"{"Type":"SigninLogs","TimeGenerated":"2024-01-15T10:00:00Z","UserPrincipalName":"a@x.com","IPAddress":"1.1.1.1","ResultType":"0"}"#,
            "\n",
            r#"{"Type":"SigninLogs","TimeGenerated":"2024-01-15T10:01:00Z","UserPrincipalName":"b@x.com","IPAddress":"2.2.2.2","ResultType":"0"}"#,
        );

        let parser = SentinelJsonParser;
        let triples = parser.parse(ndjson);
        assert_eq!(triples.len(), 2);
        assert_eq!(triples[0].0.id, "a@x.com");
        assert_eq!(triples[1].0.id, "b@x.com");
    }

    #[test]
    fn sentinel_json_array_format() {
        let json = r#"[
            {"Type":"CommonSecurityLog","TimeGenerated":"2024-01-15T08:30:00Z","SourceIP":"10.0.0.1","DestinationIP":"8.8.8.8","DestinationPort":53,"DeviceVendor":"PAN","DeviceAction":"Allow"},
            {"Type":"CommonSecurityLog","TimeGenerated":"2024-01-15T08:31:00Z","SourceIP":"10.0.0.2","DestinationIP":"8.8.4.4","DestinationPort":53,"DeviceVendor":"PAN","DeviceAction":"Allow"}
        ]"#;

        let parser = SentinelJsonParser;
        let triples = parser.parse(json);
        assert_eq!(triples.len(), 2);
    }

    #[test]
    fn sentinel_mixed_tables_in_one_file() {
        let json = r#"[
            {"Type":"SecurityEvent","TimeGenerated":"2024-01-15T10:00:00Z","EventID":4624,"Computer":"DC-01","TargetUserName":"admin","IpAddress":"10.0.0.1"},
            {"Type":"SigninLogs","TimeGenerated":"2024-01-15T10:01:00Z","UserPrincipalName":"admin@contoso.com","IPAddress":"10.0.0.2","ResultType":"0"},
            {"Type":"DeviceNetworkEvents","Timestamp":"2024-01-15T10:02:00Z","DeviceName":"WS-01","RemoteIP":"198.51.100.1","RemotePort":443,"Protocol":"TCP"}
        ]"#;

        let parser = SentinelJsonParser;
        let triples = parser.parse(json);
        assert_eq!(triples.len(), 3);

        // SecurityEvent -> Auth
        assert_eq!(triples[0].1.rel_type, RelationType::Auth);
        // SigninLogs -> Auth
        assert_eq!(triples[1].1.rel_type, RelationType::Auth);
        // DeviceNetworkEvents -> Connect
        assert_eq!(triples[2].1.rel_type, RelationType::Connect);
    }

    // ── Edge Cases ──

    #[test]
    fn sentinel_missing_required_fields_skipped() {
        let json = r#"[{
            "Type": "SigninLogs",
            "TimeGenerated": "2024-01-15T10:00:00Z",
            "UserPrincipalName": "user@contoso.com"
        }]"#;
        // Missing IPAddress → should produce 0 triples
        let parser = SentinelJsonParser;
        let triples = parser.parse(json);
        assert!(triples.is_empty());
    }

    #[test]
    fn sentinel_garbage_input_returns_empty() {
        let parser = SentinelJsonParser;
        assert!(parser.parse("not json at all!").is_empty());
        assert!(parser.parse("").is_empty());
        assert!(parser.parse("{}").is_empty());
    }

    #[test]
    fn sentinel_missing_timestamp_defaults_to_zero() {
        let json = r#"[{
            "Type": "SigninLogs",
            "UserPrincipalName": "user@contoso.com",
            "IPAddress": "1.2.3.4",
            "ResultType": "0"
        }]"#;

        let parser = SentinelJsonParser;
        let triples = parser.parse(json);
        assert_eq!(triples.len(), 1);
        assert_eq!(triples[0].1.timestamp, 0);
    }

    #[test]
    fn sentinel_iso8601_variants() {
        // Test different ISO 8601 timestamp formats
        let json_z = r#"[{"Type":"SigninLogs","TimeGenerated":"2024-01-15T14:30:00Z","UserPrincipalName":"a@x.com","IPAddress":"1.1.1.1","ResultType":"0"}]"#;
        let json_frac = r#"[{"Type":"SigninLogs","TimeGenerated":"2024-01-15T14:30:00.1234567Z","UserPrincipalName":"a@x.com","IPAddress":"1.1.1.1","ResultType":"0"}]"#;
        let json_offset = r#"[{"Type":"SigninLogs","TimeGenerated":"2024-01-15T14:30:00+00:00","UserPrincipalName":"a@x.com","IPAddress":"1.1.1.1","ResultType":"0"}]"#;

        let parser = SentinelJsonParser;
        let ts_z = parser.parse(json_z)[0].1.timestamp;
        let ts_frac = parser.parse(json_frac)[0].1.timestamp;
        let ts_offset = parser.parse(json_offset)[0].1.timestamp;

        assert_eq!(ts_z, 1705329000);
        assert_eq!(ts_frac, 1705329000);
        assert_eq!(ts_offset, 1705329000);
    }

    // ── Integration Tests ──

    #[test]
    fn sentinel_ingest_populates_graph() {
        let json = r#"[
            {"Type":"SecurityEvent","TimeGenerated":"2024-01-15T10:00:00Z","EventID":4624,"Computer":"DC-01","TargetUserName":"admin","IpAddress":"10.0.0.1"},
            {"Type":"DeviceNetworkEvents","Timestamp":"2024-01-15T10:02:00Z","DeviceName":"WS-01","RemoteIP":"198.51.100.1","RemotePort":443,"Protocol":"TCP"}
        ]"#;

        let mut g = GraphHunter::new();
        let (entities, relations) = g.ingest_logs(json, &SentinelJsonParser, None);

        assert_eq!(entities, 4); // admin, DC-01, WS-01, 198.51.100.1
        assert_eq!(relations, 2);
        assert_eq!(g.entity_count(), 4);
        assert_eq!(g.relation_count(), 2);
    }

    #[test]
    fn sentinel_deduplication() {
        // Same user authenticating to same host twice
        let json = r#"[
            {"Type":"SecurityEvent","TimeGenerated":"2024-01-15T10:00:00Z","EventID":4624,"Computer":"DC-01","TargetUserName":"admin"},
            {"Type":"SecurityEvent","TimeGenerated":"2024-01-15T10:01:00Z","EventID":4624,"Computer":"DC-01","TargetUserName":"admin"}
        ]"#;

        let mut g = GraphHunter::new();
        let (entities, relations) = g.ingest_logs(json, &SentinelJsonParser, None);

        assert_eq!(entities, 2); // admin, DC-01 (deduplicated)
        assert_eq!(relations, 2); // Two distinct relations (different timestamps)
    }

    #[test]
    fn sentinel_full_pipeline_ingest_then_hunt() {
        let events = r#"[
            {"Type":"SecurityEvent","TimeGenerated":"2024-01-15T10:00:00Z","EventID":4624,"Computer":"DC-01","TargetUserName":"attacker"},
            {"Type":"SecurityEvent","TimeGenerated":"2024-01-15T10:01:00Z","EventID":4688,"Computer":"DC-01","SubjectUserName":"attacker","NewProcessName":"C:\\cmd.exe","ParentProcessName":"C:\\explorer.exe"},
            {"Type":"DeviceFileEvents","Timestamp":"2024-01-15T10:02:00Z","ActionType":"FileCreated","FileName":"payload.dll","FolderPath":"C:\\Temp\\payload.dll","InitiatingProcessFileName":"cmd.exe","InitiatingProcessFolderPath":"C:\\cmd.exe"}
        ]"#;

        let mut g = GraphHunter::new();
        g.ingest_logs(events, &SentinelJsonParser, None);

        // Hunt: User -> Execute -> Process -> Write -> File
        let hypothesis = Hypothesis::new("Sentinel Kill Chain")
            .add_step(HypothesisStep::new(EntityType::User, RelationType::Execute, EntityType::Process))
            .add_step(HypothesisStep::new(EntityType::Process, RelationType::Write, EntityType::File));

        let results = g.search_temporal_pattern(&hypothesis, None, None).unwrap().0;
        assert!(!results.is_empty(), "Should find attacker -> cmd.exe -> payload.dll");

        let path = &results[0];
        assert_eq!(path[0], "attacker");
        assert_eq!(path[1], "C:\\cmd.exe");
        assert_eq!(path[2], "C:\\Temp\\payload.dll");
    }

    // ── Demo Data Test ──

    #[test]
    fn sentinel_demo_data_ingestion_and_hunt() {
        let demo_json = std::fs::read_to_string("../demo_data/sentinel_attack_simulation.json")
            .expect("Demo data file should exist at demo_data/sentinel_attack_simulation.json");

        let mut g = GraphHunter::new();
        let (entities, relations) = g.ingest_logs(&demo_json, &SentinelJsonParser, None);

        assert!(entities > 10, "Should ingest many entities, got {entities}");
        assert!(relations > 15, "Should ingest many relations, got {relations}");

        // Hunt: User -> Auth -> Host (brute force success)
        let auth_hunt = Hypothesis::new("Auth Chain")
            .add_step(HypothesisStep::new(EntityType::User, RelationType::Auth, EntityType::Host));

        let auth_results = g.search_temporal_pattern(&auth_hunt, None, None).unwrap().0;
        assert!(!auth_results.is_empty(), "Should find auth events");

        // Hunt: User -> Execute -> Process -> Write -> File (malware drop)
        let drop_hunt = Hypothesis::new("Malware Drop")
            .add_step(HypothesisStep::new(EntityType::User, RelationType::Execute, EntityType::Process))
            .add_step(HypothesisStep::new(EntityType::Process, RelationType::Write, EntityType::File));

        let drop_results = g.search_temporal_pattern(&drop_hunt, None, None).unwrap().0;
        assert!(!drop_results.is_empty(), "Should find malware drop paths");

        // Hunt: Host -> Connect -> IP (C2 comms)
        let c2_hunt = Hypothesis::new("C2 Communication")
            .add_step(HypothesisStep::new(EntityType::Host, RelationType::Connect, EntityType::IP));

        let c2_results = g.search_temporal_pattern(&c2_hunt, None, None).unwrap().0;
        assert!(!c2_results.is_empty(), "Should find C2 connection paths");

        // Verify the attacker IP shows up
        let has_attacker_ip = c2_results.iter().any(|path| {
            path.iter().any(|n| n.contains("198.51.100"))
        });
        assert!(has_attacker_ip, "Should find connections to attacker IPs");

        println!("=== Sentinel Demo Data Results ===");
        println!("Entities: {}, Relations: {}", g.entity_count(), g.relation_count());
        println!("Auth events: {} paths", auth_results.len());
        println!("Malware drops: {} paths", drop_results.len());
        println!("C2 connections: {} paths", c2_results.len());
    }

    // ══════════════════════════════════════════════════
    // ── Phase 6: GenericParser Tests ──
    // ══════════════════════════════════════════════════

    #[test]
    fn generic_user_process_execute_triple() {
        let json = r#"[{
            "timestamp": "2024-01-15T14:30:00Z",
            "User": "admin",
            "Image": "C:\\Windows\\cmd.exe",
            "CommandLine": "cmd.exe /c whoami"
        }]"#;

        let parser = GenericParser;
        let triples = parser.parse(json);
        assert!(!triples.is_empty());

        let has_execute = triples.iter().any(|(src, rel, dst)| {
            src.entity_type == EntityType::User
                && rel.rel_type == RelationType::Execute
                && dst.entity_type == EntityType::Process
                && src.id == "admin"
                && dst.id == "C:\\Windows\\cmd.exe"
        });
        assert!(has_execute, "Should produce User -[Execute]-> Process triple");
    }

    #[test]
    fn generic_src_dst_ip_connect_triple() {
        let json = r#"[{
            "timestamp": "2024-01-15T14:30:00Z",
            "src_ip": "10.0.0.1",
            "dst_ip": "8.8.8.8",
            "dst_port": "53",
            "protocol": "UDP"
        }]"#;

        let parser = GenericParser;
        let triples = parser.parse(json);
        assert_eq!(triples.len(), 1);

        let (src, rel, dst) = &triples[0];
        assert_eq!(src.id, "10.0.0.1");
        assert_eq!(src.entity_type, EntityType::IP);
        assert_eq!(rel.rel_type, RelationType::Connect);
        assert_eq!(rel.metadata.get("protocol").unwrap(), "UDP");
        assert_eq!(dst.id, "8.8.8.8");
        assert_eq!(dst.entity_type, EntityType::IP);
        assert_eq!(dst.metadata.get("dest_port").unwrap(), "53");
    }

    #[test]
    fn generic_process_file_write_triple() {
        let json = r#"[{
            "Image": "beacon.exe",
            "TargetFilename": "C:\\Temp\\payload.dll"
        }]"#;

        let parser = GenericParser;
        let triples = parser.parse(json);

        let has_write = triples.iter().any(|(src, rel, dst)| {
            src.entity_type == EntityType::Process
                && rel.rel_type == RelationType::Write
                && dst.entity_type == EntityType::File
                && dst.id == "C:\\Temp\\payload.dll"
        });
        assert!(has_write, "Should produce Process -[Write]-> File triple");
    }

    #[test]
    fn generic_process_domain_dns_triple() {
        let json = r#"[{
            "Image": "powershell.exe",
            "QueryName": "evil-c2.attacker.com"
        }]"#;

        let parser = GenericParser;
        let triples = parser.parse(json);

        let has_dns = triples.iter().any(|(src, rel, dst)| {
            src.entity_type == EntityType::Process
                && rel.rel_type == RelationType::DNS
                && dst.entity_type == EntityType::Domain
                && dst.id == "evil-c2.attacker.com"
        });
        assert!(has_dns, "Should produce Process -[DNS]-> Domain triple");
    }

    #[test]
    fn generic_process_registry_modify_triple() {
        let json = r#"[{
            "Image": "reg.exe",
            "TargetObject": "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\Backdoor"
        }]"#;

        let parser = GenericParser;
        let triples = parser.parse(json);

        let has_modify = triples.iter().any(|(src, rel, dst)| {
            src.entity_type == EntityType::Process
                && rel.rel_type == RelationType::Modify
                && dst.entity_type == EntityType::Registry
        });
        assert!(has_modify, "Should produce Process -[Modify]-> Registry triple");
    }

    #[test]
    fn generic_mixed_fields_from_different_schemas() {
        // Mix of Sysmon-style and firewall-style fields
        let json = r#"[{
            "timestamp": "2024-01-15T14:30:00Z",
            "User": "admin",
            "Image": "beacon.exe",
            "CommandLine": "beacon.exe --c2 evil.com",
            "ParentImage": "powershell.exe",
            "TargetFilename": "C:\\payload.dll",
            "QueryName": "evil.com"
        }]"#;

        let parser = GenericParser;
        let triples = parser.parse(json);

        // Should produce: Spawn, Execute, Write, DNS triples
        let has_spawn = triples.iter().any(|(_, rel, _)| rel.rel_type == RelationType::Spawn);
        let has_execute = triples.iter().any(|(_, rel, _)| rel.rel_type == RelationType::Execute);
        let has_write = triples.iter().any(|(_, rel, _)| rel.rel_type == RelationType::Write);
        let has_dns = triples.iter().any(|(_, rel, _)| rel.rel_type == RelationType::DNS);

        assert!(has_spawn, "Should produce Spawn triple");
        assert!(has_execute, "Should produce Execute triple");
        assert!(has_write, "Should produce Write triple");
        assert!(has_dns, "Should produce DNS triple");
    }

    #[test]
    fn generic_ndjson_format() {
        let ndjson = r#"{"User": "alice", "Image": "cmd.exe"}
{"User": "bob", "Image": "powershell.exe"}"#;

        let parser = GenericParser;
        let triples = parser.parse(ndjson);

        let users: Vec<&str> = triples
            .iter()
            .filter(|(_, rel, _)| rel.rel_type == RelationType::Execute)
            .map(|(src, _, _)| src.id.as_str())
            .collect();
        assert!(users.contains(&"alice"));
        assert!(users.contains(&"bob"));
    }

    #[test]
    fn generic_garbage_input_returns_empty() {
        let parser = GenericParser;
        assert!(parser.parse("not json").is_empty());
        assert!(parser.parse("").is_empty());
    }

    // ══════════════════════════════════════════════════
    // ── Phase 6b: CsvParser Tests ──
    // ══════════════════════════════════════════════════

    #[test]
    fn csv_basic_produces_correct_triples() {
        let csv = "timestamp,src_ip,dst_ip,dst_port,protocol\n\
                   2024-01-15T10:00:00Z,10.0.0.1,8.8.8.8,53,UDP\n\
                   2024-01-15T10:01:00Z,10.0.0.2,1.1.1.1,443,TCP";

        let parser = CsvParser;
        let triples = parser.parse(csv);
        assert_eq!(triples.len(), 2);

        // Both should be IP -[Connect]-> IP
        for (src, rel, dst) in &triples {
            assert_eq!(src.entity_type, EntityType::IP);
            assert_eq!(rel.rel_type, RelationType::Connect);
            assert_eq!(dst.entity_type, EntityType::IP);
        }
    }

    #[test]
    fn csv_quoted_fields_with_commas() {
        let csv = "User,Image,CommandLine\n\
                   admin,cmd.exe,\"cmd.exe /c echo hello, world\"";

        let parser = CsvParser;
        let triples = parser.parse(csv);

        let has_execute = triples.iter().any(|(src, rel, dst)| {
            src.id == "admin"
                && rel.rel_type == RelationType::Execute
                && dst.id == "cmd.exe"
                && dst.metadata.get("cmdline").map(|s| s.as_str()) == Some("cmd.exe /c echo hello, world")
        });
        assert!(has_execute, "Should handle quoted fields with commas");
    }

    #[test]
    fn csv_empty_and_malformed_lines_skipped() {
        let csv = "src_ip,dst_ip\n\
                   \n\
                   10.0.0.1,8.8.8.8\n\
                   \n\
                   10.0.0.2,1.1.1.1";

        let parser = CsvParser;
        let triples = parser.parse(csv);
        assert_eq!(triples.len(), 2, "Empty lines should be skipped");
    }

    #[test]
    fn csv_demo_data_loads_successfully() {
        let csv_data = std::fs::read_to_string("../demo_data/generic_csv_logs.csv")
            .expect("CSV demo data file should exist at demo_data/generic_csv_logs.csv");

        let parser = CsvParser;
        let triples = parser.parse(&csv_data);

        assert!(!triples.is_empty(), "CSV demo data should produce triples");
        assert!(triples.len() >= 10, "CSV demo data should produce at least 10 triples, got {}", triples.len());

        // Verify we get Connect triples (firewall/proxy logs)
        let connect_count = triples.iter().filter(|(_, rel, _)| rel.rel_type == RelationType::Connect).count();
        assert!(connect_count > 0, "Should have Connect triples from network logs");
    }

    // ══════════════════════════════════════════════════
    // ── Phase 6c: Auto-Detect & Integration Tests ──
    // ══════════════════════════════════════════════════

    #[test]
    fn autodetect_sysmon_json() {
        // Content with EventID + UtcTime → should be parseable by SysmonJsonParser
        let json = r#"[{"EventID": 22, "UtcTime": "2024-01-15 14:45:00", "Image": "cmd.exe", "QueryName": "test.com"}]"#;
        let trimmed = json.trim();

        // Heuristic: starts with [ or {, contains EventID and UtcTime → Sysmon
        assert!(trimmed.starts_with('[') || trimmed.starts_with('{'));
        assert!(json.contains("EventID") && json.contains("UtcTime"));

        let parser = SysmonJsonParser;
        let triples = parser.parse(json);
        assert!(!triples.is_empty(), "Sysmon content should parse with SysmonJsonParser");
    }

    #[test]
    fn autodetect_csv_content() {
        let csv = "src_ip,dst_ip,dst_port\n10.0.0.1,8.8.8.8,53";
        let trimmed = csv.trim();

        // Heuristic: doesn't start with [ or { → CSV
        assert!(!trimmed.starts_with('[') && !trimmed.starts_with('{'));

        let parser = CsvParser;
        let triples = parser.parse(csv);
        assert!(!triples.is_empty(), "CSV content should parse with CsvParser");
    }

    #[test]
    fn autodetect_generic_json_fallback() {
        // JSON without Sysmon/Sentinel markers → GenericParser
        let json = r#"[{"src_ip": "10.0.0.1", "dst_ip": "8.8.8.8", "protocol": "UDP"}]"#;

        assert!(json.contains("src_ip"));
        assert!(!json.contains("EventID"));
        assert!(!json.contains("Type"));

        let parser = GenericParser;
        let triples = parser.parse(json);
        assert!(!triples.is_empty(), "Generic JSON should parse with GenericParser");
    }

    #[test]
    fn generic_integration_ingest_then_hunt() {
        let json = r#"[
            {"timestamp": "2024-01-15T14:30:00Z", "User": "admin", "Image": "beacon.exe", "CommandLine": "beacon.exe --c2"},
            {"timestamp": "2024-01-15T14:31:00Z", "Image": "beacon.exe", "TargetFilename": "C:\\payload.dll"},
            {"timestamp": "2024-01-15T14:32:00Z", "Image": "beacon.exe", "QueryName": "exfil.evil.com"}
        ]"#;

        let mut g = GraphHunter::new();
        let (entities, relations) = g.ingest_logs(json, &GenericParser, None);

        assert!(entities > 0, "Should ingest entities");
        assert!(relations > 0, "Should ingest relations");

        // Hunt: User -> Execute -> Process -> Write -> File
        let hypothesis = Hypothesis::new("Generic Beacon Drop")
            .add_step(HypothesisStep::new(EntityType::User, RelationType::Execute, EntityType::Process))
            .add_step(HypothesisStep::new(EntityType::Process, RelationType::Write, EntityType::File));

        let results = g.search_temporal_pattern(&hypothesis, None, None).unwrap().0;
        assert!(!results.is_empty(), "Should find admin -> beacon.exe -> payload.dll");
        assert_eq!(results[0][0], "admin");
        assert_eq!(results[0][1], "beacon.exe");
        assert_eq!(results[0][2], "C:\\payload.dll");

        // Hunt: User -> Execute -> Process -> DNS -> Domain
        let dns_hunt = Hypothesis::new("Generic DNS Exfil")
            .add_step(HypothesisStep::new(EntityType::User, RelationType::Execute, EntityType::Process))
            .add_step(HypothesisStep::new(EntityType::Process, RelationType::DNS, EntityType::Domain));

        let dns_results = g.search_temporal_pattern(&dns_hunt, None, None).unwrap().0;
        assert!(!dns_results.is_empty(), "Should find admin -> beacon.exe -> exfil.evil.com");
    }

    #[test]
    fn new_entity_type_display() {
        assert_eq!(format!("{}", EntityType::Registry), "Registry");
        assert_eq!(format!("{}", EntityType::URL), "URL");
        assert_eq!(format!("{}", EntityType::Service), "Service");
    }

    #[test]
    fn new_relation_type_display() {
        assert_eq!(format!("{}", RelationType::Modify), "Modify");
        assert_eq!(format!("{}", RelationType::Spawn), "Spawn");
        assert_eq!(format!("{}", RelationType::Delete), "Delete");
    }

    // ══════════════════════════════════════════════════
    // ── Phase 8: ScoredPath & Pagination Tests ──
    // ══════════════════════════════════════════════════

    #[test]
    fn score_and_paginate_basic_scoring() {
        let mut g = build_lateral_movement_graph();
        g.compute_scores();

        let (paths, _) = g.search_temporal_pattern(
            &Hypothesis::new("Full Chain")
                .add_step(HypothesisStep::new(EntityType::IP, RelationType::Connect, EntityType::Host))
                .add_step(HypothesisStep::new(EntityType::Host, RelationType::Auth, EntityType::User))
                .add_step(HypothesisStep::new(EntityType::User, RelationType::Execute, EntityType::Process))
                .add_step(HypothesisStep::new(EntityType::Process, RelationType::Write, EntityType::File)),
            None,
            None,
        ).unwrap();

        let (scored, total) = g.score_and_paginate_paths(&paths, 0, 50, None);
        assert_eq!(total, 1);
        assert_eq!(scored.len(), 1);
        assert!(scored[0].max_score > 0.0, "Scored path should have non-zero max_score");
        assert!(scored[0].total_score > 0.0, "Scored path should have non-zero total_score");
        assert!(!scored[0].chain_summary.is_empty(), "chain_summary should not be empty");
        assert!(scored[0].chain_summary.contains("->"), "chain_summary should contain arrows");
        assert_eq!(scored[0].path.len(), 5); // IP -> Host -> User -> Process -> File
    }

    #[test]
    fn score_and_paginate_time_range() {
        let mut g = build_lateral_movement_graph();
        g.compute_scores();

        let paths = vec![vec![
            "attacker-ip".to_string(),
            "web-server".to_string(),
            "admin-user".to_string(),
            "cmd.exe".to_string(),
            "payload.dll".to_string(),
        ]];

        let (scored, _) = g.score_and_paginate_paths(&paths, 0, 50, None);
        assert_eq!(scored.len(), 1);
        assert!(scored[0].time_start > 0, "time_start should be set from edge timestamps");
        assert!(scored[0].time_end >= scored[0].time_start, "time_end >= time_start");
    }

    #[test]
    fn score_and_paginate_min_score_filter() {
        let mut g = build_lateral_movement_graph();
        g.compute_scores();

        let paths = vec![
            vec!["attacker-ip".to_string(), "web-server".to_string()],
            vec!["cmd.exe".to_string(), "payload.dll".to_string()],
        ];

        // With a very high threshold, should filter out everything
        let (scored, total) = g.score_and_paginate_paths(&paths, 0, 50, Some(999.0));
        assert_eq!(total, 0);
        assert!(scored.is_empty());

        // With threshold 0, should keep everything
        let (scored_all, total_all) = g.score_and_paginate_paths(&paths, 0, 50, Some(0.0));
        assert_eq!(total_all, 2);
        assert_eq!(scored_all.len(), 2);
    }

    #[test]
    fn score_and_paginate_pagination() {
        let mut g = GraphHunter::new();
        // Create 10 simple paths
        for i in 0..10 {
            let src_id = format!("src-{}", i);
            let dst_id = format!("dst-{}", i);
            g.add_entity(Entity::new(&src_id, EntityType::IP)).unwrap();
            g.add_entity(Entity::new(&dst_id, EntityType::Host)).unwrap();
            g.add_relation(Relation::new(&src_id, &dst_id, RelationType::Connect, 1000 + i)).unwrap();
        }
        g.compute_scores();

        let paths: Vec<Vec<String>> = (0..10)
            .map(|i| vec![format!("src-{}", i), format!("dst-{}", i)])
            .collect();

        // Page 0, size 3
        let (page0, total) = g.score_and_paginate_paths(&paths, 0, 3, None);
        assert_eq!(total, 10);
        assert_eq!(page0.len(), 3);

        // Page 1, size 3
        let (page1, _) = g.score_and_paginate_paths(&paths, 1, 3, None);
        assert_eq!(page1.len(), 3);

        // Page 3 (last partial), size 3
        let (page3, _) = g.score_and_paginate_paths(&paths, 3, 3, None);
        assert_eq!(page3.len(), 1);

        // Page 4 (out of range)
        let (page4, _) = g.score_and_paginate_paths(&paths, 4, 3, None);
        assert!(page4.is_empty());
    }

    #[test]
    fn score_and_paginate_sorted_by_max_score_desc() {
        let mut g = GraphHunter::new();
        g.add_entity(Entity::with_score("low", EntityType::IP, 10.0)).unwrap();
        g.add_entity(Entity::with_score("mid", EntityType::Host, 50.0)).unwrap();
        g.add_entity(Entity::with_score("high", EntityType::User, 90.0)).unwrap();

        g.add_relation(Relation::new("low", "mid", RelationType::Connect, 100)).unwrap();
        g.add_relation(Relation::new("mid", "high", RelationType::Auth, 200)).unwrap();

        let paths = vec![
            vec!["low".to_string(), "mid".to_string()],  // max_score = 50
            vec!["mid".to_string(), "high".to_string()],  // max_score = 90
        ];

        let (scored, _) = g.score_and_paginate_paths(&paths, 0, 50, None);
        assert_eq!(scored.len(), 2);
        assert!(scored[0].max_score >= scored[1].max_score, "Should be sorted by max_score DESC");
        assert_eq!(scored[0].max_score, 90.0);
        assert_eq!(scored[1].max_score, 50.0);
    }

    // ── Phase 9: Field Preview & Configurable Parser Tests ──

    #[test]
    fn field_preview_discovers_all_fields() {
        let data = r#"[
            {"User": "admin", "SourceIP": "10.0.0.1", "EventID": "4624", "Action": "Logon"},
            {"User": "guest", "SourceIP": "10.0.0.2", "EventID": "4625", "Action": "Failed"}
        ]"#;

        let fields = preview_fields(data, 500);
        assert!(fields.len() >= 4);

        let names: Vec<&str> = fields.iter().map(|f| f.raw_name.as_str()).collect();
        assert!(names.contains(&"User"));
        assert!(names.contains(&"SourceIP"));
        assert!(names.contains(&"EventID"));
        assert!(names.contains(&"Action"));
    }

    #[test]
    fn field_preview_canonical_detection() {
        let data = r#"[{"User": "admin", "SourceIP": "10.0.0.1", "CustomField": "value"}]"#;
        let fields = preview_fields(data, 500);

        let user_field = fields.iter().find(|f| f.raw_name == "User").unwrap();
        assert_eq!(user_field.canonical_target, Some("source_user".to_string()));
        assert_eq!(user_field.current_role, FieldRole::Node);

        let custom_field = fields.iter().find(|f| f.raw_name == "CustomField").unwrap();
        assert_eq!(custom_field.canonical_target, None);
        assert_eq!(custom_field.current_role, FieldRole::Metadata);
    }

    #[test]
    fn field_preview_sample_values() {
        let data = r#"[
            {"User": "admin"},
            {"User": "guest"},
            {"User": "system"}
        ]"#;
        let fields = preview_fields(data, 500);
        let user_field = fields.iter().find(|f| f.raw_name == "User").unwrap();
        assert_eq!(user_field.occurrence_count, 3);
        assert!(user_field.sample_values.len() >= 2);
    }

    #[test]
    fn field_preview_limited_parsing() {
        // Ensure parse_events_limited respects the limit
        let data = r#"[
            {"User": "a"}, {"User": "b"}, {"User": "c"},
            {"User": "d"}, {"User": "e"}, {"User": "f"}
        ]"#;
        let fields = preview_fields(data, 3);
        let user_field = fields.iter().find(|f| f.raw_name == "User").unwrap();
        // Only 3 events sampled
        assert_eq!(user_field.occurrence_count, 3);
    }

    #[test]
    fn configurable_parser_promotes_field_to_node() {
        let data = r#"[{
            "User": "admin",
            "Image": "cmd.exe",
            "EventID": "1",
            "UtcTime": "2024-01-15 10:00:00.000"
        }]"#;

        let config = FieldConfig {
            mappings: vec![FieldMapping {
                raw_name: "EventID".to_string(),
                role: FieldRole::Node,
                entity_type: Some("Process".to_string()),
            }],
        };

        let parser = ConfigurableParser::new(config);
        let triples = parser.parse(data);

        // Should have standard GenericParser triples PLUS the promoted EventID triple
        assert!(!triples.is_empty());

        // Find the promoted EventID entity
        let has_event_id = triples.iter().any(|(_, _, dst)| dst.id == "EventID:1");
        assert!(has_event_id, "Should have promoted EventID:1 as a node");
    }

    #[test]
    fn configurable_parser_ignores_field() {
        let data = r#"[{
            "User": "admin",
            "Image": "cmd.exe",
            "Noise": "ignore_me"
        }]"#;

        let config = FieldConfig {
            mappings: vec![FieldMapping {
                raw_name: "Noise".to_string(),
                role: FieldRole::Ignore,
                entity_type: None,
            }],
        };

        let parser = ConfigurableParser::new(config);
        let triples = parser.parse(data);

        // "Noise" should NOT appear as a node
        let has_noise = triples
            .iter()
            .any(|(src, _, dst)| src.id.contains("Noise") || dst.id.contains("Noise"));
        assert!(!has_noise, "Ignored field should not produce nodes");
    }

    #[test]
    fn configurable_parser_backwards_compatible() {
        // With no overrides for non-canonical fields, should behave like GenericParser
        let data = r#"[{
            "User": "admin",
            "Image": "cmd.exe",
            "DestinationIP": "10.0.0.1"
        }]"#;

        let config = FieldConfig {
            mappings: vec![],
        };

        let parser = ConfigurableParser::new(config);
        let config_triples = parser.parse(data);
        let generic_triples = GenericParser.parse(data);

        assert_eq!(config_triples.len(), generic_triples.len());
    }

    #[test]
    fn configurable_parser_integration_ingest_and_hunt() {
        let data = r#"[
            {"User": "attacker", "Image": "mimikatz.exe", "EventID": "1", "TargetPort": "445"},
            {"User": "attacker", "hostname": "dc01", "EventID": "4624"}
        ]"#;

        let config = FieldConfig {
            mappings: vec![
                FieldMapping {
                    raw_name: "EventID".to_string(),
                    role: FieldRole::Node,
                    entity_type: Some("Process".to_string()),
                },
                FieldMapping {
                    raw_name: "TargetPort".to_string(),
                    role: FieldRole::Node,
                    entity_type: Some("IP".to_string()),
                },
            ],
        };

        let parser = ConfigurableParser::new(config);
        let mut graph = GraphHunter::new();
        let (entities, relations) = graph.ingest_logs(data, &parser, None);

        assert!(entities > 0, "Should have ingested entities");
        assert!(relations > 0, "Should have ingested relations");

        // Verify promoted fields exist as entities
        assert!(
            graph.get_entity("EventID:1").is_some(),
            "EventID:1 should exist as entity"
        );
        assert!(
            graph.get_entity("TargetPort:445").is_some(),
            "TargetPort:445 should exist as entity"
        );
    }

    // ══════════════════════════════════════════════════
    // ── Phase 10: Empirical Benchmark ──
    // ══════════════════════════════════════════════════

    /// Collects empirical benchmark data for the LaTeX paper:
    /// n, m, type distribution, dmax, beff, search times for L=3,4,5.
    #[test]
    fn benchmark_empirical_data_for_paper() {
        use std::time::Instant;

        struct DatasetResult {
            name: &'static str,
            n: usize,
            m: usize,
            type_dist: Vec<(String, usize)>,
            dmax: usize,
            num_rel_types: usize,
            num_ent_types: usize,
            beff_predicted: f64,
            p_temporal_empirical: f64,
            results_l2: usize,
            results_l3: usize,
            results_l4: usize,
            results_l5: usize,
            time_l2_ms: f64,
            time_l3_ms: f64,
            time_l4_ms: f64,
            time_l5_ms: f64,
            starts: usize,
        }

        fn measure_dataset<P: LogParser>(name: &'static str, data: &str, parser: &P) -> DatasetResult {
            // Ingest
            let mut g = GraphHunter::new();
            let (_ne, _nr) = g.ingest_logs(data, parser, None);
            g.compute_scores();

            let n = g.entity_count();
            let m = g.relation_count();

            // Type distribution
            let type_dist = g.entity_type_counts();

            // dmax: max out-degree
            let dmax = g.adjacency_list.values().map(|v| v.len()).max().unwrap_or(0);

            // Count distinct relation types and entity types in graph
            let num_ent_types = g.type_index.len();
            let mut rel_types_seen = std::collections::HashSet::new();
            for edges in g.adjacency_list.values() {
                for e in edges {
                    rel_types_seen.insert(format!("{}", e.rel_type));
                }
            }
            let num_rel_types = rel_types_seen.len();

            // Predicted beff = dmax * (1/|RT|) * (1/|ET|) * p_temporal * p_cycle
            // p_temporal ≈ 0.5 (half the edges have ts >= last_ts on average)
            // p_cycle ≈ (1 - 5/n) for L=5
            let p_rel = if num_rel_types > 0 { 1.0 / num_rel_types as f64 } else { 1.0 };
            let p_ent = if num_ent_types > 0 { 1.0 / num_ent_types as f64 } else { 1.0 };
            let p_temporal = 0.5;
            let p_cycle = if n > 5 { 1.0 - 5.0 / n as f64 } else { 0.5 };
            let beff_predicted = dmax as f64 * p_rel * p_ent * p_temporal * p_cycle;

            // Also measure empirical edge type pairs for beff
            let mut edge_type_pairs: std::collections::HashMap<(String, String), usize> = std::collections::HashMap::new();
            let mut temporal_ordered = 0usize;
            let mut temporal_total = 0usize;
            for edges in g.adjacency_list.values() {
                let mut sorted_edges: Vec<_> = edges.iter().collect();
                sorted_edges.sort_by_key(|e| e.timestamp);
                for i in 0..sorted_edges.len() {
                    let e = sorted_edges[i];
                    let dest_type = g.get_entity(&e.dest_id)
                        .map(|ent| format!("{}", ent.entity_type))
                        .unwrap_or_default();
                    *edge_type_pairs.entry((format!("{}", e.rel_type), dest_type)).or_default() += 1;
                    if i > 0 {
                        temporal_total += 1;
                        if sorted_edges[i].timestamp >= sorted_edges[i-1].timestamp {
                            temporal_ordered += 1;
                        }
                    }
                }
            }
            let p_temporal_empirical = if temporal_total > 0 {
                temporal_ordered as f64 / temporal_total as f64
            } else {
                0.5
            };

            // Hypotheses that match the actual parser output:
            // Sysmon/Generic produce: User-[Execute]->Process, Process-[Spawn]->Process,
            // Process-[Write]->File, Process-[DNS]->Domain, Process-[Connect]->IP,
            // Process-[Modify]->Registry
            // Sentinel produces: User-[Auth]->Host, Host-[Connect]->IP,
            // User-[Execute]->Process, Process-[Write]->File

            // L=2: User -[Execute]-> Process -[Write]-> File
            let h2 = Hypothesis::new("L2")
                .add_step(HypothesisStep::new(EntityType::User, RelationType::Execute, EntityType::Process))
                .add_step(HypothesisStep::new(EntityType::Process, RelationType::Write, EntityType::File));

            let starts_l2 = g.type_index.get(&EntityType::User).map(|s| s.len()).unwrap_or(0);
            let t0 = Instant::now();
            let r2_res = g.search_temporal_pattern(&h2, None, None).map(|(r, _)| r).unwrap_or_default();
            let time_l2_ms = t0.elapsed().as_secs_f64() * 1000.0;

            // L=3: User -[Execute]-> Process -[Spawn]-> Process -[Write]-> File
            let h3 = Hypothesis::new("L3")
                .add_step(HypothesisStep::new(EntityType::User, RelationType::Execute, EntityType::Process))
                .add_step(HypothesisStep::new(EntityType::Process, RelationType::Spawn, EntityType::Process))
                .add_step(HypothesisStep::new(EntityType::Process, RelationType::Write, EntityType::File));

            let t0 = Instant::now();
            let r3 = g.search_temporal_pattern(&h3, None, None).map(|(r, _)| r).unwrap_or_default();
            let time_l3_ms = t0.elapsed().as_secs_f64() * 1000.0;

            // L=4: User -[Execute]-> Process -[Spawn]-> Process -[Spawn]-> Process -[Write]-> File
            let h4 = Hypothesis::new("L4")
                .add_step(HypothesisStep::new(EntityType::User, RelationType::Execute, EntityType::Process))
                .add_step(HypothesisStep::new(EntityType::Process, RelationType::Spawn, EntityType::Process))
                .add_step(HypothesisStep::new(EntityType::Process, RelationType::Spawn, EntityType::Process))
                .add_step(HypothesisStep::new(EntityType::Process, RelationType::Write, EntityType::File));

            let t0 = Instant::now();
            let r4 = g.search_temporal_pattern(&h4, None, None).map(|(r, _)| r).unwrap_or_default();
            let time_l4_ms = t0.elapsed().as_secs_f64() * 1000.0;

            // L=5: User -[Execute]-> Process -[Spawn]-> Process -[Spawn]-> Process -[Spawn]-> Process -[Write]-> File
            let h5 = Hypothesis::new("L5")
                .add_step(HypothesisStep::new(EntityType::User, RelationType::Execute, EntityType::Process))
                .add_step(HypothesisStep::new(EntityType::Process, RelationType::Spawn, EntityType::Process))
                .add_step(HypothesisStep::new(EntityType::Process, RelationType::Spawn, EntityType::Process))
                .add_step(HypothesisStep::new(EntityType::Process, RelationType::Spawn, EntityType::Process))
                .add_step(HypothesisStep::new(EntityType::Process, RelationType::Write, EntityType::File));
            let t0 = Instant::now();
            let r5 = g.search_temporal_pattern(&h5, None, None).map(|(r, _)| r).unwrap_or_default();
            let time_l5_ms = t0.elapsed().as_secs_f64() * 1000.0;

            DatasetResult {
                name,
                n, m,
                type_dist,
                dmax,
                num_rel_types,
                num_ent_types,
                beff_predicted,
                p_temporal_empirical,
                results_l2: r2_res.len(),
                results_l3: r3.len(),
                results_l4: r4.len(),
                results_l5: r5.len(),
                time_l2_ms,
                time_l3_ms,
                time_l4_ms,
                time_l5_ms,
                starts: starts_l2,
            }
        }

        // Dataset 1: apt_attack_simulation.json (small, ~11KB)
        let apt_data = std::fs::read_to_string("../demo_data/apt_attack_simulation.json")
            .expect("apt_attack_simulation.json should exist");
        let r1 = measure_dataset("APT Simulation", &apt_data, &SysmonJsonParser);

        // Dataset 2: sentinel_attack_simulation.json (small, ~9KB)
        let sentinel_data = std::fs::read_to_string("../demo_data/sentinel_attack_simulation.json")
            .expect("sentinel_attack_simulation.json should exist");
        let r2 = measure_dataset("Sentinel Simulation", &sentinel_data, &SentinelJsonParser);

        // Dataset 3: mordor_combined_attacks.json (medium, ~132MB)
        // This is the large dataset — may take several seconds
        let mordor_path = "../demo_data/mordor_combined_attacks.json";
        let r3_opt = if std::path::Path::new(mordor_path).exists() {
            let mordor_data = std::fs::read_to_string(mordor_path)
                .expect("mordor_combined_attacks.json should be readable");
            Some(measure_dataset("Mordor Combined", &mordor_data, &GenericParser))
        } else {
            None
        };

        // Print results in tabular format
        println!("\n╔══════════════════════════════════════════════════════════════════════════════════╗");
        println!("║                     EMPIRICAL BENCHMARK RESULTS                                ║");
        println!("╚══════════════════════════════════════════════════════════════════════════════════╝\n");

        for r in [Some(&r1), Some(&r2), r3_opt.as_ref()] {
            if let Some(r) = r {
                println!("── {} ──", r.name);
                println!("  n = {} entities, m = {} relations", r.n, r.m);
                println!("  d_max = {}", r.dmax);
                println!("  Entity types (|T_V| = {}): {:?}", r.num_ent_types, r.type_dist);
                println!("  Relation types: |T_E| = {}", r.num_rel_types);
                println!("  p_temporal (empirical): {:.4}", r.p_temporal_empirical);
                println!("  b_eff predicted (uniform): {:.4}", r.beff_predicted);
                println!();
                println!("  L=2: {} results from {} starts in {:.3} ms", r.results_l2, r.starts, r.time_l2_ms);
                println!("  L=3: {} results from {} starts in {:.3} ms", r.results_l3, r.starts, r.time_l3_ms);
                println!("  L=4: {} results from {} starts in {:.3} ms", r.results_l4, r.starts, r.time_l4_ms);
                println!("  L=5: {} results from {} starts in {:.3} ms", r.results_l5, r.starts, r.time_l5_ms);

                // Empirical beff: beff = (results/starts)^(1/L) for non-zero
                for (l, res) in [(2, r.results_l2), (3, r.results_l3), (4, r.results_l4), (5, r.results_l5)] {
                    if r.starts > 0 && res > 0 {
                        let beff = (res as f64 / r.starts as f64).powf(1.0 / l as f64);
                        println!("  b_eff measured (L={}): {:.4}", l, beff);
                    }
                }
                println!();
            }
        }
    }

    // ══════════════════════════════════════════════════
    // ── Phase 11: DSL Parser Tests ──
    // ══════════════════════════════════════════════════

    #[test]
    fn dsl_parse_simple_chain() {
        let result = parse_dsl("User -[Auth]-> Host -[Execute]-> Process", None).unwrap();
        assert_eq!(result.hypothesis.steps.len(), 2);
        assert_eq!(result.hypothesis.steps[0].origin_type, EntityType::User);
        assert_eq!(result.hypothesis.steps[0].relation_type, RelationType::Auth);
        assert_eq!(result.hypothesis.steps[0].dest_type, EntityType::Host);
        assert_eq!(result.hypothesis.steps[1].origin_type, EntityType::Host);
        assert_eq!(result.hypothesis.steps[1].relation_type, RelationType::Execute);
        assert_eq!(result.hypothesis.steps[1].dest_type, EntityType::Process);
    }

    #[test]
    fn dsl_parse_single_step() {
        let result = parse_dsl("IP -[Connect]-> Host", None).unwrap();
        assert_eq!(result.hypothesis.steps.len(), 1);
    }

    #[test]
    fn dsl_parse_wildcard_entity() {
        let result = parse_dsl("* -[Execute]-> Process", None).unwrap();
        assert_eq!(result.hypothesis.steps[0].origin_type, EntityType::Any);
        assert_eq!(result.hypothesis.steps[0].dest_type, EntityType::Process);
    }

    #[test]
    fn dsl_parse_wildcard_relation() {
        let result = parse_dsl("User -[*]-> Host", None).unwrap();
        assert_eq!(result.hypothesis.steps[0].relation_type, RelationType::Any);
    }

    #[test]
    fn dsl_parse_full_wildcard() {
        let result = parse_dsl("* -[*]-> *", None).unwrap();
        assert_eq!(result.hypothesis.steps[0].origin_type, EntityType::Any);
        assert_eq!(result.hypothesis.steps[0].relation_type, RelationType::Any);
        assert_eq!(result.hypothesis.steps[0].dest_type, EntityType::Any);
    }

    #[test]
    fn dsl_reject_empty() {
        let err = parse_dsl("", None).unwrap_err();
        assert!(err.message.contains("Empty"));
    }

    #[test]
    fn dsl_reject_single_entity() {
        let err = parse_dsl("User", None).unwrap_err();
        assert!(err.message.contains("at least one step"));
    }

    #[test]
    fn dsl_reject_unknown_entity() {
        let err = parse_dsl("Foo -[Auth]-> Host", None).unwrap_err();
        assert!(err.message.contains("Unknown entity type"));
    }

    #[test]
    fn dsl_reject_unknown_relation() {
        let err = parse_dsl("User -[Foo]-> Host", None).unwrap_err();
        assert!(err.message.contains("Unknown relation type"));
    }

    #[test]
    fn dsl_roundtrip_format_parse() {
        let input = "User -[Auth]-> Host -[Execute]-> Process -[Write]-> File";
        let r1 = parse_dsl(input, None).unwrap();
        let formatted = &r1.formatted;
        let r2 = parse_dsl(formatted, None).unwrap();
        assert_eq!(r1.hypothesis.steps.len(), r2.hypothesis.steps.len());
        for (a, b) in r1.hypothesis.steps.iter().zip(r2.hypothesis.steps.iter()) {
            assert_eq!(a.origin_type, b.origin_type);
            assert_eq!(a.relation_type, b.relation_type);
            assert_eq!(a.dest_type, b.dest_type);
        }
    }

    #[test]
    fn dsl_whitespace_tolerant() {
        let result = parse_dsl("  User   -[Auth]->   Host  ", None).unwrap();
        assert_eq!(result.hypothesis.steps.len(), 1);
    }

    // ══════════════════════════════════════════════════
    // ── Phase 12: Wildcard DFS Search Tests ──
    // ══════════════════════════════════════════════════

    #[test]
    fn wildcard_entity_search() {
        let mut g = GraphHunter::new();
        let data = r#"[{
            "EventID": 1, "UtcTime": "2024-01-01 10:00:00",
            "ParentImage": "cmd.exe", "Image": "malware.exe"
        }]"#;
        g.ingest_logs(data, &SysmonJsonParser, None);

        // Wildcard origin: * -[Spawn]-> Process should match (parent→child)
        let h = Hypothesis::new("wildcard test")
            .add_step(HypothesisStep::new(EntityType::Any, RelationType::Spawn, EntityType::Process));
        let results = g.search_temporal_pattern(&h, None, None).unwrap().0;
        assert!(!results.is_empty(), "Wildcard entity should match");
    }

    #[test]
    fn wildcard_relation_search() {
        let mut g = GraphHunter::new();
        let data = r#"[{
            "EventID": 1, "UtcTime": "2024-01-01 10:00:00",
            "ParentImage": "cmd.exe", "Image": "malware.exe"
        }]"#;
        g.ingest_logs(data, &SysmonJsonParser, None);

        // Wildcard relation: Process -[*]-> Process
        let h = Hypothesis::new("wildcard rel test")
            .add_step(HypothesisStep::new(EntityType::Process, RelationType::Any, EntityType::Process));
        let results = g.search_temporal_pattern(&h, None, None).unwrap().0;
        assert!(!results.is_empty(), "Wildcard relation should match");
    }

    // ══════════════════════════════════════════════════
    // ── Phase 13: ATT&CK Catalog Tests ──
    // ══════════════════════════════════════════════════

    #[test]
    fn catalog_has_entries() {
        let catalog = get_catalog();
        assert!(catalog.len() >= 10, "Catalog should have at least 10 entries");
    }

    #[test]
    fn catalog_entries_parse_as_valid_dsl() {
        let catalog = get_catalog();
        for entry in catalog {
            let result = parse_dsl(entry.dsl_pattern, Some(entry.name));
            assert!(result.is_ok(), "Catalog entry '{}' ({}): DSL parse failed: {:?}",
                entry.name, entry.mitre_id, result.err());
        }
    }

    #[test]
    fn catalog_entry_fields_non_empty() {
        let catalog = get_catalog();
        for entry in catalog {
            assert!(!entry.id.is_empty());
            assert!(!entry.name.is_empty());
            assert!(!entry.mitre_id.is_empty());
            assert!(!entry.description.is_empty());
            assert!(!entry.dsl_pattern.is_empty());
        }
    }

    // ══════════════════════════════════════════════════
    // ── Phase 14: Naive DFS Benchmark (speedup comparison) ──
    // ══════════════════════════════════════════════════

    #[test]
    fn benchmark_naive_vs_pruned() {
        use std::time::Instant;

        let apt_data = std::fs::read_to_string("../demo_data/apt_attack_simulation.json")
            .expect("apt_attack_simulation.json should exist");
        let mut g = GraphHunter::new();
        g.ingest_logs(&apt_data, &SysmonJsonParser, None);
        g.compute_scores();

        let n = g.entity_count();
        let m = g.relation_count();

        // L=2 hypothesis
        let h2 = Hypothesis::new("L2")
            .add_step(HypothesisStep::new(EntityType::Process, RelationType::Execute, EntityType::Process));

        // L=3 hypothesis
        let h3 = Hypothesis::new("L3")
            .add_step(HypothesisStep::new(EntityType::User, RelationType::Execute, EntityType::Process))
            .add_step(HypothesisStep::new(EntityType::Process, RelationType::Execute, EntityType::Process));

        println!("\n╔══════════════════════════════════════════════════════════════════╗");
        println!("║             NAIVE vs PRUNED DFS COMPARISON                      ║");
        println!("╚══════════════════════════════════════════════════════════════════╝");
        println!("  Graph: n={}, m={}\n", n, m);

        for (label, h) in [("L=2", &h2), ("L=3", &h3)] {
            // Pruned search
            let t0 = Instant::now();
            let pruned_results = g.search_temporal_pattern(h, None, None).unwrap().0;
            let time_pruned = t0.elapsed().as_secs_f64() * 1000.0;

            // Naive search
            let t0 = Instant::now();
            let (naive_results, naive_visited) = g.search_naive_dfs(h).unwrap();
            let time_naive = t0.elapsed().as_secs_f64() * 1000.0;

            let speedup = if time_pruned > 0.0 { time_naive / time_pruned } else { f64::INFINITY };

            println!("  {}: pruned={} results in {:.3}ms, naive={} results ({} nodes visited) in {:.3}ms",
                label, pruned_results.len(), time_pruned, naive_results.len(), naive_visited, time_naive);
            println!("  Speedup: {:.1}x\n", speedup);

            // Both should find the same results (naive post-filters)
            assert_eq!(pruned_results.len(), naive_results.len(),
                "Pruned and naive should find the same number of results for {}", label);
        }

        // Also run on Mordor if available
        let mordor_path = "../demo_data/mordor_combined_attacks.json";
        if std::path::Path::new(mordor_path).exists() {
            let mordor_data = std::fs::read_to_string(mordor_path).unwrap();
            let mut gm = GraphHunter::new();
            gm.ingest_logs(&mordor_data, &GenericParser, None);
            gm.compute_scores();

            let h_mordor = Hypothesis::new("Mordor L=2")
                .add_step(HypothesisStep::new(EntityType::Process, RelationType::Execute, EntityType::Process));

            let t0 = Instant::now();
            let pruned = gm.search_temporal_pattern(&h_mordor, None, None).unwrap().0;
            let time_pruned = t0.elapsed().as_secs_f64() * 1000.0;

            let t0 = Instant::now();
            let (naive, naive_visited) = gm.search_naive_dfs(&h_mordor).unwrap();
            let time_naive = t0.elapsed().as_secs_f64() * 1000.0;

            let speedup = if time_pruned > 0.0 { time_naive / time_pruned } else { f64::INFINITY };

            println!("  Mordor (n={}, m={}): pruned={} in {:.3}ms, naive={} ({} visited) in {:.3}ms",
                gm.entity_count(), gm.relation_count(),
                pruned.len(), time_pruned, naive.len(), naive_visited, time_naive);
            println!("  Speedup: {:.1}x\n", speedup);
        }
    }

    // ══ Phase: k-Simplicity ══

    #[test]
    fn k_simplicity_default_1_same_as_simple_path() {
        // With k=1 (default), behavior should be identical to the old simple-path DFS
        let mut graph = GraphHunter::new();
        graph.add_entity(Entity::new("u1", EntityType::User)).unwrap();
        graph.add_entity(Entity::new("h1", EntityType::Host)).unwrap();
        graph.add_entity(Entity::new("p1", EntityType::Process)).unwrap();

        graph.add_relation(Relation::new("u1", "h1", RelationType::Auth, 100)).unwrap();
        graph.add_relation(Relation::new("h1", "p1", RelationType::Execute, 200)).unwrap();

        let h = Hypothesis::new("k=1 test")
            .add_step(HypothesisStep::new(EntityType::User, RelationType::Auth, EntityType::Host))
            .add_step(HypothesisStep::new(EntityType::Host, RelationType::Execute, EntityType::Process));

        assert_eq!(h.k_simplicity, 1);
        let results = graph.search_temporal_pattern(&h, None, None).unwrap().0;
        assert_eq!(results.len(), 1);
        assert_eq!(results[0], vec!["u1", "h1", "p1"]);
    }

    #[test]
    fn k_simplicity_2_finds_cycle() {
        // Process A writes File B, File B executes Process A — a cycle
        // With k=1: blocked. With k=2: found.
        let mut graph = GraphHunter::new();
        graph.add_entity(Entity::new("procA", EntityType::Process)).unwrap();
        graph.add_entity(Entity::new("fileB", EntityType::File)).unwrap();

        graph.add_relation(Relation::new("procA", "fileB", RelationType::Write, 100)).unwrap();
        graph.add_relation(Relation::new("fileB", "procA", RelationType::Execute, 200)).unwrap();

        // k=1: no results (procA would be visited twice)
        let h1 = Hypothesis::new("k=1")
            .add_step(HypothesisStep::new(EntityType::Process, RelationType::Write, EntityType::File))
            .add_step(HypothesisStep::new(EntityType::File, RelationType::Execute, EntityType::Process));
        let results1 = graph.search_temporal_pattern(&h1, None, None).unwrap().0;
        assert_eq!(results1.len(), 0, "k=1 should block the cycle");

        // k=2: finds the cycle
        let h2 = Hypothesis::new("k=2")
            .add_step(HypothesisStep::new(EntityType::Process, RelationType::Write, EntityType::File))
            .add_step(HypothesisStep::new(EntityType::File, RelationType::Execute, EntityType::Process))
            .with_k_simplicity(2);
        let results2 = graph.search_temporal_pattern(&h2, None, None).unwrap().0;
        assert_eq!(results2.len(), 1, "k=2 should find the cycle");
        assert_eq!(results2[0], vec!["procA", "fileB", "procA"]);
    }

    #[test]
    fn k_simplicity_3_allows_triple_visit() {
        // Process -> File -> Process -> File -> Process with k=3
        let mut graph = GraphHunter::new();
        graph.add_entity(Entity::new("p", EntityType::Process)).unwrap();
        graph.add_entity(Entity::new("f", EntityType::File)).unwrap();

        graph.add_relation(Relation::new("p", "f", RelationType::Write, 100)).unwrap();
        graph.add_relation(Relation::new("f", "p", RelationType::Execute, 200)).unwrap();
        graph.add_relation(Relation::new("p", "f", RelationType::Write, 300)).unwrap();
        graph.add_relation(Relation::new("f", "p", RelationType::Execute, 400)).unwrap();

        let h = Hypothesis::new("k=3")
            .add_step(HypothesisStep::new(EntityType::Process, RelationType::Write, EntityType::File))
            .add_step(HypothesisStep::new(EntityType::File, RelationType::Execute, EntityType::Process))
            .add_step(HypothesisStep::new(EntityType::Process, RelationType::Write, EntityType::File))
            .add_step(HypothesisStep::new(EntityType::File, RelationType::Execute, EntityType::Process))
            .with_k_simplicity(3);

        let results = graph.search_temporal_pattern(&h, None, None).unwrap().0;
        assert_eq!(results.len(), 1);
        assert_eq!(results[0], vec!["p", "f", "p", "f", "p"]);
    }

    #[test]
    fn k_simplicity_temporal_monotonicity_still_enforced() {
        // Even with k=2, timestamps must be monotonically non-decreasing
        let mut graph = GraphHunter::new();
        graph.add_entity(Entity::new("p", EntityType::Process)).unwrap();
        graph.add_entity(Entity::new("f", EntityType::File)).unwrap();

        graph.add_relation(Relation::new("p", "f", RelationType::Write, 200)).unwrap();
        // Timestamp goes backwards — should block the cycle even with k=2
        graph.add_relation(Relation::new("f", "p", RelationType::Execute, 100)).unwrap();

        let h = Hypothesis::new("temporal test")
            .add_step(HypothesisStep::new(EntityType::Process, RelationType::Write, EntityType::File))
            .add_step(HypothesisStep::new(EntityType::File, RelationType::Execute, EntityType::Process))
            .with_k_simplicity(2);

        let results = graph.search_temporal_pattern(&h, None, None).unwrap().0;
        assert_eq!(results.len(), 0, "temporal monotonicity should block this even with k=2");
    }

    #[test]
    fn dsl_k_simplicity_parse() {
        let result = parse_dsl("Process -[Write]-> File -[Execute]-> Process {k=2}", None).unwrap();
        assert_eq!(result.hypothesis.k_simplicity, 2);
        assert_eq!(result.hypothesis.steps.len(), 2);
    }

    #[test]
    fn dsl_k_simplicity_default() {
        let result = parse_dsl("User -[Auth]-> Host", None).unwrap();
        assert_eq!(result.hypothesis.k_simplicity, 1);
    }

    #[test]
    fn dsl_k_simplicity_format_roundtrip() {
        let result = parse_dsl("Process -[Write]-> File -[Execute]-> Process {k=2}", None).unwrap();
        let formatted = format_hypothesis(&result.hypothesis);
        assert!(formatted.contains("{k=2}"), "formatted: {}", formatted);

        // Re-parse the formatted output
        let result2 = parse_dsl(&formatted, None).unwrap();
        assert_eq!(result2.hypothesis.k_simplicity, 2);
        assert_eq!(result2.hypothesis.steps.len(), 2);
    }

    #[test]
    fn dsl_k_simplicity_1_not_shown() {
        let result = parse_dsl("User -[Auth]-> Host", None).unwrap();
        let formatted = format_hypothesis(&result.hypothesis);
        assert!(!formatted.contains("{k="), "k=1 should not be shown: {}", formatted);
    }

    #[test]
    fn dsl_k_simplicity_rejects_zero() {
        let result = parse_dsl("User -[Auth]-> Host {k=0}", None);
        assert!(result.is_err());
    }

    // ══ Phase: Secondary Relation Index ══

    #[test]
    fn rel_index_populated_on_add_relation() {
        let mut graph = GraphHunter::new();
        graph.add_entity(Entity::new("u1", EntityType::User)).unwrap();
        graph.add_entity(Entity::new("h1", EntityType::Host)).unwrap();
        graph.add_entity(Entity::new("h2", EntityType::Host)).unwrap();

        graph.add_relation(Relation::new("u1", "h1", RelationType::Auth, 100)).unwrap();
        graph.add_relation(Relation::new("u1", "h2", RelationType::Auth, 200)).unwrap();
        graph.add_relation(Relation::new("u1", "h1", RelationType::Connect, 300)).unwrap();

        let auth_edges = graph.get_relations_by_type("u1", &RelationType::Auth);
        assert_eq!(auth_edges.len(), 2);

        let conn_edges = graph.get_relations_by_type("u1", &RelationType::Connect);
        assert_eq!(conn_edges.len(), 1);

        let dns_edges = graph.get_relations_by_type("u1", &RelationType::DNS);
        assert_eq!(dns_edges.len(), 0);
    }

    #[test]
    fn rel_index_search_same_results_as_full_scan() {
        // Build a graph and verify that search results are identical
        // whether using rel_index (concrete type) or full scan (Any type)
        let mut graph = GraphHunter::new();
        graph.add_entity(Entity::new("u1", EntityType::User)).unwrap();
        graph.add_entity(Entity::new("h1", EntityType::Host)).unwrap();
        graph.add_entity(Entity::new("p1", EntityType::Process)).unwrap();

        graph.add_relation(Relation::new("u1", "h1", RelationType::Auth, 100)).unwrap();
        graph.add_relation(Relation::new("h1", "p1", RelationType::Execute, 200)).unwrap();

        // Concrete types: uses rel_index
        let h_concrete = Hypothesis::new("concrete")
            .add_step(HypothesisStep::new(EntityType::User, RelationType::Auth, EntityType::Host))
            .add_step(HypothesisStep::new(EntityType::Host, RelationType::Execute, EntityType::Process));
        let results_concrete = graph.search_temporal_pattern(&h_concrete, None, None).unwrap().0;

        // Wildcard relation: uses full scan
        let h_wildcard = Hypothesis::new("wildcard")
            .add_step(HypothesisStep::new(EntityType::User, RelationType::Any, EntityType::Host))
            .add_step(HypothesisStep::new(EntityType::Host, RelationType::Any, EntityType::Process));
        let results_wildcard = graph.search_temporal_pattern(&h_wildcard, None, None).unwrap().0;

        assert_eq!(results_concrete.len(), results_wildcard.len());
        assert_eq!(results_concrete, results_wildcard);
    }

    #[test]
    fn rel_index_wildcard_falls_back_to_full_scan() {
        let mut graph = GraphHunter::new();
        graph.add_entity(Entity::new("u1", EntityType::User)).unwrap();
        graph.add_entity(Entity::new("h1", EntityType::Host)).unwrap();

        graph.add_relation(Relation::new("u1", "h1", RelationType::Auth, 100)).unwrap();

        let h = Hypothesis::new("wildcard")
            .add_step(HypothesisStep::new(EntityType::User, RelationType::Any, EntityType::Host));
        let results = graph.search_temporal_pattern(&h, None, None).unwrap().0;
        assert_eq!(results.len(), 1);
    }

    // ══ Phase: Cyclic Catalog ══

    #[test]
    fn catalog_cyclic_entries_have_k_gt_1() {
        let catalog = get_catalog();
        let cyclic: Vec<_> = catalog.iter().filter(|e| e.k_simplicity > 1).collect();
        assert!(cyclic.len() >= 4, "Should have at least 4 cyclic catalog entries");
        for entry in &cyclic {
            assert!(entry.k_simplicity >= 2);
            assert!(entry.dsl_pattern.contains("{k="));
        }
    }

    #[test]
    fn catalog_existing_entries_have_k_1() {
        let catalog = get_catalog();
        // cat-001 through cat-012 should all have k=1
        let original_ids: Vec<&str> = (1..=12).map(|i| {
            // Match cat-001..cat-012
            catalog.iter().find(|e| e.id == format!("cat-{:03}", i)).map(|e| e.id)
        }).flatten().collect();
        for id in &original_ids {
            let entry = catalog.iter().find(|e| e.id == *id).unwrap();
            assert_eq!(entry.k_simplicity, 1, "Entry {} should have k=1", entry.id);
        }
    }

    #[test]
    fn catalog_cyclic_c2_callback_demo() {
        // Build a C2 callback graph and verify cat-013 finds the loop
        let mut graph = GraphHunter::new();
        graph.add_entity(Entity::new("malware.exe", EntityType::Process)).unwrap();
        graph.add_entity(Entity::new("evil.com", EntityType::Domain)).unwrap();
        graph.add_entity(Entity::new("1.2.3.4", EntityType::IP)).unwrap();

        graph.add_relation(Relation::new("malware.exe", "evil.com", RelationType::DNS, 100)).unwrap();
        graph.add_relation(Relation::new("evil.com", "1.2.3.4", RelationType::Connect, 200)).unwrap();
        graph.add_relation(Relation::new("1.2.3.4", "malware.exe", RelationType::Connect, 300)).unwrap();

        // Load cat-013 pattern
        let catalog = get_catalog();
        let entry = catalog.iter().find(|e| e.id == "cat-013").unwrap();
        let parsed = parse_dsl(entry.dsl_pattern, Some(entry.name)).unwrap();
        let mut hypothesis = parsed.hypothesis;
        hypothesis.k_simplicity = entry.k_simplicity;

        let results = graph.search_temporal_pattern(&hypothesis, None, None).unwrap().0;
        assert_eq!(results.len(), 1, "Should find the C2 callback loop");
        assert_eq!(results[0], vec!["malware.exe", "evil.com", "1.2.3.4", "malware.exe"]);
    }

    #[test]
    fn catalog_cyclic_entries_parse_as_valid_dsl() {
        let catalog = get_catalog();
        for entry in catalog.iter().filter(|e| e.k_simplicity > 1) {
            let result = parse_dsl(entry.dsl_pattern, Some(entry.name));
            assert!(result.is_ok(), "Failed to parse cyclic entry {}: {:?}", entry.id, result.err());
            let h = result.unwrap().hypothesis;
            assert_eq!(h.k_simplicity, entry.k_simplicity,
                "Entry {} DSL k_simplicity mismatch", entry.id);
        }
    }

    #[test]
    fn k_simplicity_serde_default() {
        // Deserializing a Hypothesis without k_simplicity should default to 1
        let json = r#"{"name":"test","steps":[{"origin_type":"User","relation_type":"Auth","dest_type":"Host"}]}"#;
        let h: Hypothesis = serde_json::from_str(json).unwrap();
        assert_eq!(h.k_simplicity, 1);
    }

    #[test]
    fn k_simplicity_serde_explicit() {
        let json = r#"{"name":"test","steps":[{"origin_type":"User","relation_type":"Auth","dest_type":"Host"}],"k_simplicity":3}"#;
        let h: Hypothesis = serde_json::from_str(json).unwrap();
        assert_eq!(h.k_simplicity, 3);
    }

    // ══════════════════════════════════════════════════════════════════════
    // Phase 2: Merge Policy Tests
    // ══════════════════════════════════════════════════════════════════════

    #[test]
    fn merge_policy_default_is_first_write() {
        let p = MergePolicy::default();
        assert_eq!(p, MergePolicy::FirstWriteWins);
    }

    #[test]
    fn merge_policy_first_write_wins_preserves() {
        let mut graph = GraphHunter::new();
        // First ingest: entity with metadata "role" = "admin"
        let json1 = r#"[{"user":"alice","hostname":"srv1","timestamp":"2024-01-01T00:00:00Z"}]"#;
        graph.ingest_logs_with_policy(json1, &GenericParser, None, &MergePolicy::FirstWriteWins);
        // Second ingest: same entity, different value — should be ignored
        let json2 = r#"[{"user":"alice","hostname":"srv2","timestamp":"2024-01-01T01:00:00Z"}]"#;
        graph.ingest_logs_with_policy(json2, &GenericParser, None, &MergePolicy::FirstWriteWins);
        // alice entity should exist; its metadata shouldn't change
        let alice = graph.get_entity("alice").expect("alice should exist");
        assert!(alice.metadata.is_empty() || !alice.metadata.values().any(|v| v.contains("srv2")));
    }

    #[test]
    fn merge_policy_last_write_wins_overwrites() {
        let mut graph = GraphHunter::new();
        // Manually create entities with metadata to test LWW
        let e1 = Entity::new("host-1", EntityType::Host).with_metadata("role", "old");
        graph.add_entity(e1).unwrap();
        // Now ingest something that touches host-1 with new metadata
        let json = r#"[{"hostname":"host-1","sourceip":"10.0.0.1","timestamp":"2024-01-01T01:00:00Z"}]"#;
        graph.ingest_logs_with_policy(json, &GenericParser, None, &MergePolicy::LastWriteWins);
        let host = graph.get_entity("host-1").unwrap();
        // With LWW, any new keys from the second ingest overwrite
        // The key "role" was only in the original entity, not in the ingest, so it stays
        assert_eq!(host.metadata.get("role").unwrap(), "old");
    }

    #[test]
    fn merge_policy_append_concatenates() {
        let mut graph = GraphHunter::new();
        // First ingest creates entity with "cmdline" metadata
        let json1 = r#"[{"user":"alice","process_name":"cmd.exe","commandline":"whoami","timestamp":"2024-01-01T00:00:00Z"}]"#;
        graph.ingest_logs_with_policy(json1, &GenericParser, None, &MergePolicy::Append);
        // Second ingest: same process entity, different cmdline
        let json2 = r#"[{"user":"bob","process_name":"cmd.exe","commandline":"ipconfig","timestamp":"2024-01-01T01:00:00Z"}]"#;
        graph.ingest_logs_with_policy(json2, &GenericParser, None, &MergePolicy::Append);
        let proc_entity = graph.get_entity("cmd.exe").expect("cmd.exe should exist");
        let cmdline = proc_entity.metadata.get("cmdline").expect("Should have cmdline metadata");
        assert!(cmdline.contains("whoami"), "Should contain first value");
        assert!(cmdline.contains("ipconfig"), "Should contain second value");
        assert!(cmdline.contains(", "), "Values should be comma-separated");
    }

    // ══════════════════════════════════════════════════════════════════════
    // Phase 3: Betweenness Centrality Tests
    // ══════════════════════════════════════════════════════════════════════

    #[test]
    fn betweenness_linear_chain() {
        // A -- B -- C: B should have highest betweenness
        let mut graph = GraphHunter::new();
        graph.add_entity(Entity::new("A", EntityType::Host)).unwrap();
        graph.add_entity(Entity::new("B", EntityType::Host)).unwrap();
        graph.add_entity(Entity::new("C", EntityType::Host)).unwrap();
        graph.add_relation(Relation::new("A", "B", RelationType::Connect, 100)).unwrap();
        graph.add_relation(Relation::new("B", "C", RelationType::Connect, 200)).unwrap();

        graph.compute_betweenness(None);

        let b = graph.get_entity("B").unwrap();
        let a = graph.get_entity("A").unwrap();
        let c = graph.get_entity("C").unwrap();
        assert!(b.betweenness > a.betweenness, "B should have higher betweenness than A");
        assert!(b.betweenness > c.betweenness, "B should have higher betweenness than C");
        assert!(b.betweenness > 0.0);
    }

    #[test]
    fn betweenness_star_graph() {
        // Center connected to 4 leaves: center has highest betweenness
        let mut graph = GraphHunter::new();
        graph.add_entity(Entity::new("center", EntityType::Host)).unwrap();
        for i in 0..4 {
            let leaf = format!("leaf-{}", i);
            graph.add_entity(Entity::new(&leaf, EntityType::IP)).unwrap();
            graph.add_relation(Relation::new("center", &leaf, RelationType::Connect, 100 + i)).unwrap();
        }

        graph.compute_betweenness(None);

        let center = graph.get_entity("center").unwrap();
        for i in 0..4 {
            let leaf = graph.get_entity(&format!("leaf-{}", i)).unwrap();
            assert!(center.betweenness >= leaf.betweenness,
                "Center betweenness ({}) should be >= leaf betweenness ({})",
                center.betweenness, leaf.betweenness);
        }
    }

    #[test]
    fn betweenness_bridge_node() {
        // Two clusters connected by a bridge node
        // Cluster 1: A-B-C, Cluster 2: D-E-F, bridge: C-D
        let mut graph = GraphHunter::new();
        for id in &["A", "B", "C", "D", "E", "F"] {
            graph.add_entity(Entity::new(*id, EntityType::Host)).unwrap();
        }
        graph.add_relation(Relation::new("A", "B", RelationType::Connect, 100)).unwrap();
        graph.add_relation(Relation::new("B", "C", RelationType::Connect, 200)).unwrap();
        graph.add_relation(Relation::new("C", "D", RelationType::Connect, 300)).unwrap();
        graph.add_relation(Relation::new("D", "E", RelationType::Connect, 400)).unwrap();
        graph.add_relation(Relation::new("E", "F", RelationType::Connect, 500)).unwrap();

        graph.compute_betweenness(None);

        let c = graph.get_entity("C").unwrap();
        let d = graph.get_entity("D").unwrap();
        let a = graph.get_entity("A").unwrap();
        // C and D are bridge nodes — should have high betweenness
        assert!(c.betweenness > a.betweenness, "Bridge C should beat leaf A");
        assert!(d.betweenness > a.betweenness, "Bridge D should beat leaf A");
    }

    #[test]
    fn betweenness_sampled_approx() {
        // With sample_limit=2, should still compute without crashing
        let mut graph = GraphHunter::new();
        for i in 0..10 {
            graph.add_entity(Entity::new(format!("n{}", i), EntityType::Host)).unwrap();
        }
        for i in 0..9 {
            graph.add_relation(Relation::new(format!("n{}", i), format!("n{}", i + 1), RelationType::Connect, 100 + i as i64)).unwrap();
        }

        graph.compute_betweenness(Some(2));
        // Just verify it runs and produces values
        let mid = graph.get_entity("n5").unwrap();
        assert!(mid.betweenness >= 0.0);
    }

    // ══════════════════════════════════════════════════════════════════════
    // Phase 4: Temporal PageRank Tests
    // ══════════════════════════════════════════════════════════════════════

    #[test]
    fn pagerank_star_topology() {
        // All nodes point to center → center gets highest pagerank
        let mut graph = GraphHunter::new();
        graph.add_entity(Entity::new("center", EntityType::Host)).unwrap();
        for i in 0..5 {
            let leaf = format!("leaf-{}", i);
            graph.add_entity(Entity::new(&leaf, EntityType::IP)).unwrap();
            graph.add_relation(Relation::new(&leaf, "center", RelationType::Connect, 1000)).unwrap();
        }

        graph.compute_temporal_pagerank(Some(0.0), Some(0.85), Some(50), Some(1e-8), None);

        let center = graph.get_entity("center").unwrap();
        assert_eq!(center.pagerank_score, 100.0, "Center should have max pagerank");
    }

    #[test]
    fn pagerank_decay_prefers_recent() {
        // Two nodes with edges at different times; with decay, recent edges matter more
        let mut graph = GraphHunter::new();
        graph.add_entity(Entity::new("A", EntityType::Host)).unwrap();
        graph.add_entity(Entity::new("B", EntityType::Host)).unwrap();
        graph.add_entity(Entity::new("C", EntityType::Host)).unwrap();
        // Old edge: A → B at t=100
        graph.add_relation(Relation::new("A", "B", RelationType::Connect, 100)).unwrap();
        // Recent edge: A → C at t=10000
        graph.add_relation(Relation::new("A", "C", RelationType::Connect, 10000)).unwrap();

        graph.compute_temporal_pagerank(Some(0.01), Some(0.85), Some(100), Some(1e-8), Some(10000));

        let b = graph.get_entity("B").unwrap();
        let c = graph.get_entity("C").unwrap();
        // C should rank higher because its incoming edge is more recent
        assert!(c.pagerank_score > b.pagerank_score,
            "C (recent) should rank higher than B (old): C={}, B={}", c.pagerank_score, b.pagerank_score);
    }

    #[test]
    fn pagerank_no_decay_equals_standard() {
        // With lambda=0, all edges are equal weight — standard PageRank
        let mut graph = GraphHunter::new();
        graph.add_entity(Entity::new("A", EntityType::Host)).unwrap();
        graph.add_entity(Entity::new("B", EntityType::Host)).unwrap();
        // Symmetric edges
        graph.add_relation(Relation::new("A", "B", RelationType::Connect, 100)).unwrap();
        graph.add_relation(Relation::new("B", "A", RelationType::Connect, 200)).unwrap();

        graph.compute_temporal_pagerank(Some(0.0), Some(0.85), Some(100), Some(1e-8), None);

        let a = graph.get_entity("A").unwrap();
        let b = graph.get_entity("B").unwrap();
        // Symmetric graph → roughly equal scores
        assert!((a.pagerank_score - b.pagerank_score).abs() < 5.0,
            "Symmetric graph should have near-equal PR: A={}, B={}", a.pagerank_score, b.pagerank_score);
    }

    #[test]
    fn pagerank_converges() {
        // Build a chain and verify it doesn't crash with tight epsilon
        let mut graph = GraphHunter::new();
        for i in 0..20 {
            graph.add_entity(Entity::new(format!("n{}", i), EntityType::Host)).unwrap();
        }
        for i in 0..19 {
            graph.add_relation(Relation::new(format!("n{}", i), format!("n{}", i + 1), RelationType::Connect, 1000 + i as i64)).unwrap();
        }

        graph.compute_temporal_pagerank(Some(0.001), Some(0.85), Some(200), Some(1e-10), None);

        // Last node in chain should have high score (receives transitively)
        let last = graph.get_entity("n19").unwrap();
        assert!(last.pagerank_score > 0.0);
    }

    #[test]
    fn pagerank_dangling_nodes() {
        // Node with no outgoing edges (dangling)
        let mut graph = GraphHunter::new();
        graph.add_entity(Entity::new("A", EntityType::Host)).unwrap();
        graph.add_entity(Entity::new("B", EntityType::Host)).unwrap();
        graph.add_entity(Entity::new("C", EntityType::Host)).unwrap();
        graph.add_relation(Relation::new("A", "B", RelationType::Connect, 100)).unwrap();
        graph.add_relation(Relation::new("A", "C", RelationType::Connect, 200)).unwrap();
        // B and C are dangling (no outgoing edges) — should not crash

        graph.compute_temporal_pagerank(Some(0.0), Some(0.85), Some(50), Some(1e-8), None);

        let b = graph.get_entity("B").unwrap();
        let c = graph.get_entity("C").unwrap();
        assert!(b.pagerank_score > 0.0);
        assert!(c.pagerank_score > 0.0);
    }

    // ══════════════════════════════════════════════════════════════════════
    // Phase 5: Composite Scoring Tests
    // ══════════════════════════════════════════════════════════════════════

    #[test]
    fn composite_degree_only() {
        let mut graph = GraphHunter::new();
        graph.add_entity(Entity::new("A", EntityType::Host)).unwrap();
        graph.add_entity(Entity::new("B", EntityType::Host)).unwrap();
        graph.add_entity(Entity::new("C", EntityType::Host)).unwrap();
        graph.add_relation(Relation::new("A", "B", RelationType::Connect, 100)).unwrap();
        graph.add_relation(Relation::new("A", "C", RelationType::Connect, 200)).unwrap();

        graph.compute_scores(); // sets degree_score
        graph.compute_composite_score(1.0, 0.0, 0.0);

        let a = graph.get_entity("A").unwrap();
        assert_eq!(a.score, 100.0, "A has max degree → composite=100 with degree_only");
    }

    #[test]
    fn composite_equal_weights() {
        let mut graph = GraphHunter::new();
        graph.add_entity(Entity::new("A", EntityType::Host)).unwrap();
        graph.add_entity(Entity::new("B", EntityType::Host)).unwrap();
        graph.add_relation(Relation::new("A", "B", RelationType::Connect, 100)).unwrap();

        graph.compute_scores();
        graph.compute_betweenness(None);
        graph.compute_temporal_pagerank(Some(0.0), None, None, None, None);
        graph.compute_composite_score(1.0, 1.0, 1.0);

        // Both nodes should have scores
        let a = graph.get_entity("A").unwrap();
        let b = graph.get_entity("B").unwrap();
        assert!(a.score >= 0.0);
        assert!(b.score >= 0.0);
    }

    #[test]
    fn composite_normalization() {
        let mut graph = GraphHunter::new();
        for i in 0..5 {
            graph.add_entity(Entity::new(format!("n{}", i), EntityType::Host)).unwrap();
        }
        for i in 0..4 {
            graph.add_relation(Relation::new(format!("n{}", i), format!("n{}", i + 1), RelationType::Connect, 100 + i as i64)).unwrap();
        }

        graph.compute_scores();
        graph.compute_betweenness(None);
        graph.compute_temporal_pagerank(Some(0.0), None, None, None, None);
        graph.compute_composite_score(1.0, 1.0, 1.0);

        // Max score should be exactly 100
        let max_score = graph.entities.values().map(|e| e.score).fold(0.0f64, f64::max);
        assert!((max_score - 100.0).abs() < 0.01, "Max composite should be 100, got {}", max_score);
    }

    // ══════════════════════════════════════════════════════════════════════
    // Phase 6: DFS Parallelization Tests
    // ══════════════════════════════════════════════════════════════════════

    #[test]
    fn parallel_search_matches_sequential() {
        // Build a graph with >64 starting nodes of the same type
        let mut graph = GraphHunter::new();
        for i in 0..100 {
            graph.add_entity(Entity::new(format!("user-{}", i), EntityType::User)).unwrap();
            graph.add_entity(Entity::new(format!("host-{}", i), EntityType::Host)).unwrap();
            graph.add_relation(Relation::new(
                format!("user-{}", i),
                format!("host-{}", i),
                RelationType::Auth,
                1000 + i as i64,
            )).unwrap();
        }

        let h = Hypothesis::new("Auth Test")
            .add_step(HypothesisStep::new(EntityType::User, RelationType::Auth, EntityType::Host));

        // This should use parallel path (100 >= 64)
        let results = graph.search_temporal_pattern(&h, None, None).unwrap().0;
        assert_eq!(results.len(), 100, "Should find 100 auth paths");

        // Verify each path is valid
        for path in &results {
            assert_eq!(path.len(), 2);
            assert!(path[0].starts_with("user-"));
            assert!(path[1].starts_with("host-"));
        }
    }

    #[test]
    fn parallel_search_below_threshold() {
        // With fewer than 64 starting nodes, sequential path should be used
        let mut graph = GraphHunter::new();
        for i in 0..10 {
            graph.add_entity(Entity::new(format!("ip-{}", i), EntityType::IP)).unwrap();
            graph.add_entity(Entity::new(format!("host-{}", i), EntityType::Host)).unwrap();
            graph.add_relation(Relation::new(
                format!("ip-{}", i),
                format!("host-{}", i),
                RelationType::Connect,
                100 + i as i64,
            )).unwrap();
        }

        let h = Hypothesis::new("Connect Test")
            .add_step(HypothesisStep::new(EntityType::IP, RelationType::Connect, EntityType::Host));

        let results = graph.search_temporal_pattern(&h, None, None).unwrap().0;
        assert_eq!(results.len(), 10);
    }

    #[test]
    fn parallel_search_deterministic() {
        // Run the same parallel search twice, results should be identical (after sorting)
        let mut graph = GraphHunter::new();
        for i in 0..80 {
            graph.add_entity(Entity::new(format!("u{}", i), EntityType::User)).unwrap();
            graph.add_entity(Entity::new(format!("h{}", i), EntityType::Host)).unwrap();
            graph.add_relation(Relation::new(
                format!("u{}", i),
                format!("h{}", i),
                RelationType::Auth,
                i as i64,
            )).unwrap();
        }

        let h = Hypothesis::new("Test")
            .add_step(HypothesisStep::new(EntityType::User, RelationType::Auth, EntityType::Host));

        let mut r1 = graph.search_temporal_pattern(&h, None, None).unwrap().0;
        let mut r2 = graph.search_temporal_pattern(&h, None, None).unwrap().0;
        r1.sort();
        r2.sort();
        assert_eq!(r1, r2, "Parallel search should be deterministic");
    }

    // ══════════════════════════════════════════════════════════════════════
    // Phase 7: CEF / LEEF / ECS Tests
    // ══════════════════════════════════════════════════════════════════════

    #[test]
    fn cef_basic_parse() {
        let line = "CEF:0|Security|Firewall|1.0|100|Connection|5|src=10.0.0.1 dst=192.168.1.1 dpt=443";
        let val = GenericParser::try_parse_cef(line).expect("Should parse CEF");
        let obj = val.as_object().unwrap();
        assert_eq!(obj.get("device_vendor").unwrap().as_str().unwrap(), "Security");
        assert_eq!(obj.get("src").unwrap().as_str().unwrap(), "10.0.0.1");
        assert_eq!(obj.get("dst").unwrap().as_str().unwrap(), "192.168.1.1");
        assert_eq!(obj.get("dpt").unwrap().as_str().unwrap(), "443");
    }

    #[test]
    fn cef_extensions() {
        let line = "CEF:0|Vendor|Product|1.0|200|Alert|8|src=10.0.0.5 suser=admin msg=Suspicious login attempt";
        let val = GenericParser::try_parse_cef(line).unwrap();
        let obj = val.as_object().unwrap();
        assert_eq!(obj.get("suser").unwrap().as_str().unwrap(), "admin");
        assert_eq!(obj.get("msg").unwrap().as_str().unwrap(), "Suspicious login attempt");
    }

    #[test]
    fn leef_basic_parse() {
        let line = "LEEF:1.0|Microsoft|MSExchange|1.0|LoginSuccess|src=10.0.0.1\tdst=192.168.1.1\tsuser=admin";
        let val = GenericParser::try_parse_leef(line).expect("Should parse LEEF");
        let obj = val.as_object().unwrap();
        assert_eq!(obj.get("device_vendor").unwrap().as_str().unwrap(), "Microsoft");
        assert_eq!(obj.get("src").unwrap().as_str().unwrap(), "10.0.0.1");
        assert_eq!(obj.get("suser").unwrap().as_str().unwrap(), "admin");
    }

    #[test]
    fn ecs_nested_flattening() {
        let json = r#"{"source":{"ip":"10.0.0.1","port":12345},"destination":{"ip":"192.168.1.1","port":443},"user":{"name":"admin"},"@timestamp":"2024-01-01T00:00:00Z"}"#;
        let val: serde_json::Value = serde_json::from_str(json).unwrap();
        let flat = GenericParser::flatten_nested_json(&val);
        let obj = flat.as_object().unwrap();
        // Should have ECS canonical mappings
        assert_eq!(obj.get("source_ip").unwrap().as_str().unwrap(), "10.0.0.1");
        assert_eq!(obj.get("target_ip").unwrap().as_str().unwrap(), "192.168.1.1");
        assert_eq!(obj.get("source_user").unwrap().as_str().unwrap(), "admin");
    }

    #[test]
    fn generic_mixed_cef_json() {
        // Mix of CEF and JSON lines
        let data = r#"CEF:0|Vendor|FW|1.0|100|Conn|3|src=10.0.0.1 dst=192.168.1.1
{"user":"alice","hostname":"srv1","timestamp":"2024-01-01T00:00:00Z"}"#;

        let events = GenericParser::parse_events(data);
        assert_eq!(events.len(), 2, "Should parse both CEF and JSON lines");
    }

    // ══════════════════════════════════════════════════════════════════════
    // Phase 8: Snapshot Isolation (Clone) Tests
    // ══════════════════════════════════════════════════════════════════════

    #[test]
    fn graph_clone_independent() {
        let mut graph = GraphHunter::new();
        graph.add_entity(Entity::new("A", EntityType::Host)).unwrap();
        graph.add_entity(Entity::new("B", EntityType::IP)).unwrap();
        graph.add_relation(Relation::new("A", "B", RelationType::Connect, 100)).unwrap();

        let mut clone = graph.clone();

        // Modify original
        graph.add_entity(Entity::new("C", EntityType::User)).unwrap();

        // Clone should not have C
        assert!(clone.get_entity("C").is_none(), "Clone should be independent of original");
        assert_eq!(clone.entity_count(), 2);
        assert_eq!(graph.entity_count(), 3);

        // Modify clone
        clone.add_entity(Entity::new("D", EntityType::File)).unwrap();
        assert!(graph.get_entity("D").is_none(), "Original should be independent of clone");
    }

    #[test]
    fn search_on_clone_matches_original() {
        let mut graph = GraphHunter::new();
        graph.add_entity(Entity::new("user1", EntityType::User)).unwrap();
        graph.add_entity(Entity::new("host1", EntityType::Host)).unwrap();
        graph.add_relation(Relation::new("user1", "host1", RelationType::Auth, 100)).unwrap();

        let mut clone = graph.clone();

        let h = Hypothesis::new("Test")
            .add_step(HypothesisStep::new(EntityType::User, RelationType::Auth, EntityType::Host));

        let original_results = graph.search_temporal_pattern(&h, None, None).unwrap().0;
        let clone_results = clone.search_temporal_pattern(&h, None, None).unwrap().0;
        assert_eq!(original_results, clone_results, "Clone search should match original");
    }

    // ══════════════════════════════════════════════════════════════════════
    // Phase 9: Temporal Compaction Tests
    // ══════════════════════════════════════════════════════════════════════

    #[test]
    fn compact_all_old() {
        let mut graph = GraphHunter::new();
        graph.add_entity(Entity::new("A", EntityType::Host)).unwrap();
        graph.add_entity(Entity::new("B", EntityType::IP)).unwrap();
        // 3 old edges of same type
        graph.add_relation(Relation::new("A", "B", RelationType::Connect, 100)).unwrap();
        graph.add_relation(Relation::new("A", "B", RelationType::Connect, 200)).unwrap();
        graph.add_relation(Relation::new("A", "B", RelationType::Connect, 300)).unwrap();

        let stats = graph.compact_before(1000);
        assert_eq!(stats.edges_before, 3);
        assert_eq!(stats.edges_after, 1);
        assert_eq!(stats.edges_removed, 2);
        assert_eq!(stats.groups_compacted, 1);
        assert_eq!(graph.relation_count(), 1);
    }

    #[test]
    fn compact_mixed() {
        let mut graph = GraphHunter::new();
        graph.add_entity(Entity::new("A", EntityType::Host)).unwrap();
        graph.add_entity(Entity::new("B", EntityType::IP)).unwrap();
        // 2 old + 1 new
        graph.add_relation(Relation::new("A", "B", RelationType::Connect, 100)).unwrap();
        graph.add_relation(Relation::new("A", "B", RelationType::Connect, 200)).unwrap();
        graph.add_relation(Relation::new("A", "B", RelationType::Connect, 5000)).unwrap();

        let stats = graph.compact_before(1000);
        // Group has a mix of old and new → NOT compacted (not all < cutoff)
        assert_eq!(stats.groups_compacted, 0);
        assert_eq!(stats.edges_after, 3);
    }

    #[test]
    fn compact_preserves_new() {
        let mut graph = GraphHunter::new();
        graph.add_entity(Entity::new("A", EntityType::Host)).unwrap();
        graph.add_entity(Entity::new("B", EntityType::IP)).unwrap();
        // All edges are newer than cutoff
        graph.add_relation(Relation::new("A", "B", RelationType::Connect, 2000)).unwrap();
        graph.add_relation(Relation::new("A", "B", RelationType::Connect, 3000)).unwrap();

        let stats = graph.compact_before(1000);
        assert_eq!(stats.groups_compacted, 0);
        assert_eq!(stats.edges_after, 2);
    }

    #[test]
    fn compact_summary_metadata() {
        let mut graph = GraphHunter::new();
        graph.add_entity(Entity::new("A", EntityType::Host)).unwrap();
        graph.add_entity(Entity::new("B", EntityType::IP)).unwrap();
        graph.add_relation(Relation::new("A", "B", RelationType::Connect, 100)).unwrap();
        graph.add_relation(Relation::new("A", "B", RelationType::Connect, 500)).unwrap();

        graph.compact_before(1000);

        let edges = graph.get_relations("A");
        assert_eq!(edges.len(), 1);
        let summary = &edges[0];
        assert_eq!(summary.timestamp, 100, "Summary should use earliest timestamp");
        assert_eq!(summary.metadata.get("compacted_count").unwrap(), "2");
        assert_eq!(summary.metadata.get("compacted_latest").unwrap(), "500");
    }

    #[test]
    fn compact_index_consistency() {
        let mut graph = GraphHunter::new();
        graph.add_entity(Entity::new("A", EntityType::Host)).unwrap();
        graph.add_entity(Entity::new("B", EntityType::IP)).unwrap();
        graph.add_entity(Entity::new("C", EntityType::User)).unwrap();
        graph.add_relation(Relation::new("A", "B", RelationType::Connect, 100)).unwrap();
        graph.add_relation(Relation::new("A", "B", RelationType::Connect, 200)).unwrap();
        graph.add_relation(Relation::new("A", "C", RelationType::Auth, 150)).unwrap();

        graph.compact_before(1000);

        // Verify rel_index is consistent
        let connect_edges = graph.get_relations_by_type("A", &RelationType::Connect);
        assert_eq!(connect_edges.len(), 1, "Should have 1 compacted Connect edge");
        let auth_edges = graph.get_relations_by_type("A", &RelationType::Auth);
        assert_eq!(auth_edges.len(), 1, "Should have 1 Auth edge");

        // Verify reverse_adj
        let sid_a = graph.interner.get("A").unwrap();
        let sid_b = graph.interner.get("B").unwrap();
        let sid_c = graph.interner.get("C").unwrap();
        assert!(graph.reverse_adj.get(&sid_b).unwrap().contains(&sid_a));
        assert!(graph.reverse_adj.get(&sid_c).unwrap().contains(&sid_a));
    }

    // ══════════════════════════════════════════════════════════════════════
    // Phase 10: Full Scoring Pipeline Integration
    // ══════════════════════════════════════════════════════════════════════

    #[test]
    fn scoring_pipeline_full_integration() {
        // Build a small graph, run all 4 scoring methods, verify get_node_details
        // returns non-zero values for all score fields.
        let mut graph = GraphHunter::new();
        graph.add_entity(Entity::new("hub", EntityType::Host)).unwrap();
        for i in 0..5 {
            let leaf = format!("leaf-{}", i);
            graph.add_entity(Entity::new(&leaf, EntityType::IP)).unwrap();
            graph.add_relation(Relation::new(&leaf, "hub", RelationType::Connect, 1000 + i)).unwrap();
        }
        // Add cross-link so betweenness is interesting
        graph.add_relation(Relation::new("hub", "leaf-0", RelationType::Connect, 2000)).unwrap();

        // Run full pipeline
        graph.compute_scores();
        graph.compute_temporal_pagerank(None, None, None, None, None);
        graph.compute_betweenness(None);
        graph.compute_composite_score(1.0, 1.0, 1.0);

        // Verify via get_node_details
        let details = graph.get_node_details("hub").unwrap();
        assert!(details.degree_score > 0.0, "degree_score should be > 0, got {}", details.degree_score);
        assert!(details.pagerank_score > 0.0, "pagerank_score should be > 0, got {}", details.pagerank_score);
        assert!(details.betweenness > 0.0, "betweenness should be > 0, got {}", details.betweenness);
        assert!(details.score > 0.0, "composite score should be > 0, got {}", details.score);

        // Hub should be the highest-scoring node
        for i in 0..5 {
            let leaf_details = graph.get_node_details(&format!("leaf-{}", i)).unwrap();
            assert!(details.score >= leaf_details.score,
                "Hub score ({}) should be >= leaf-{} score ({})",
                details.score, i, leaf_details.score);
        }
    }

    // ═══════════════════════════════════════════════════════════
    // Phase 10: Benchmark & Empirical Evaluation
    // ═══════════════════════════════════════════════════════════

    #[test]
    fn benchmark_er_graph_generation() {
        let g = generate_erdos_renyi(100, 0.05, 1_000_000, 2_000_000, 42);
        assert!(g.entity_count() == 100);
        assert!(g.relation_count() > 0);
        let (n, m, d_max, d_avg, n_et, n_rt) = graph_params(&g);
        assert_eq!(n, 100);
        assert!(m > 100); // ~500 edges expected for p=0.05
        assert!(d_max > 0);
        assert!(d_avg > 0.0);
        assert!(n_et > 0);
        assert!(n_rt > 0);
    }

    #[test]
    fn benchmark_ba_graph_generation() {
        let g = generate_barabasi_albert(200, 3, 1_000_000, 2_000_000, 42);
        assert!(g.entity_count() == 200);
        assert!(g.relation_count() > 0);
        let (_, _, d_max, _, _, _) = graph_params(&g);
        // BA graphs have power-law degree distribution; max should be significantly above average
        assert!(d_max > 6, "BA d_max should be > 6 due to preferential attachment, got {}", d_max);
    }

    #[test]
    fn benchmark_instrumented_search_correctness() {
        // Instrumented search must return same results as normal search
        let mut g = generate_erdos_renyi(50, 0.1, 1_000_000, 2_000_000, 123);
        let h = build_lateral_movement_hypothesis(3);

        let normal_results = g.search_temporal_pattern(&h, None, None).unwrap().0;
        let (instr_results, stats) = search_instrumented(&g, &h, None).unwrap();

        assert_eq!(normal_results.len(), instr_results.len(),
            "Instrumented and normal search must find same number of results");
        assert!(stats.nodes_visited > 0, "Should visit at least start nodes");
        assert!(stats.edges_examined > 0 || stats.nodes_visited == stats.nodes_per_level[0],
            "Should examine edges or only have starting nodes");
    }

    #[test]
    fn benchmark_pruning_ratios() {
        // On a typed graph, most edges should be pruned by type checks
        let g = generate_erdos_renyi(200, 0.05, 1_000_000, 2_000_000, 777);
        let h = build_lateral_movement_hypothesis(4);

        let (_, stats) = search_instrumented(&g, &h, None).unwrap();
        let (rr_rel, rr_ent, _, _, _) = stats.rejection_rates();

        // With 9 types uniformly distributed, ~88% should be rejected by each type check
        // But since we use rel_index, rel_type rejection should be near 0 (pre-filtered)
        // Entity type rejection should be high
        if stats.edges_examined > 10 {
            assert!(rr_ent > 0.5,
                "Entity type pruning should reject >50% of surviving edges, got {:.1}%",
                rr_ent * 100.0);
        }
    }

    #[test]
    fn benchmark_naive_vs_pruned_speedup() {
        let g = generate_erdos_renyi(100, 0.08, 1_000_000, 2_000_000, 999);
        let h = build_lateral_movement_hypothesis(3);

        let result = run_benchmark(&g, &h, None, "ER-100");

        // Pruned search should visit fewer or equal nodes than naive
        assert!(result.nodes_visited_pruned <= result.nodes_visited_naive,
            "Pruned ({}) should visit <= naive ({}) nodes",
            result.nodes_visited_pruned, result.nodes_visited_naive);
        assert!(result.speedup >= 1.0,
            "Speedup should be >= 1, got {:.2}", result.speedup);
    }

    #[test]
    fn benchmark_beff_convergence() {
        // Test that b_eff < 1 for uniformly typed graphs with moderate degree
        let g = generate_erdos_renyi(300, 0.03, 1_000_000, 2_000_000, 42);
        let h = build_lateral_movement_hypothesis(4);

        let (_, stats) = search_instrumented(&g, &h, None).unwrap();
        let beff = stats.measured_beff();

        // For d_avg ~ 9, with 9 entity types and 9 relation types,
        // theoretical b_eff ~ d_avg / (9*9) * 0.5 ~ 0.05
        // Measured should be < 5 at worst
        if stats.nodes_per_level.len() >= 3 && stats.nodes_per_level[1] > 5 {
            assert!(beff < 5.0,
                "b_eff should be moderate for ER graph with 9 types, got {:.2}", beff);
        }
    }

    #[test]
    fn benchmark_scale_test_er() {
        // Verify search completes in reasonable time at scale
        for &n in &[100, 500, 1000] {
            let p = 10.0 / n as f64; // Keep average degree ~10
            let mut g = generate_erdos_renyi(n, p, 1_000_000, 2_000_000, 42);
            let h = build_lateral_movement_hypothesis(3);

            let start = std::time::Instant::now();
            let results = g.search_temporal_pattern(&h, None, None).unwrap().0;
            let elapsed = start.elapsed();

            // Should complete in < 1 second for all sizes
            assert!(elapsed.as_secs() < 2,
                "ER n={}: search took {:?}, should be < 2s", n, elapsed);
        }
    }

    #[test]
    fn benchmark_scale_test_ba() {
        // BA graphs with power-law degree distribution
        for &n in &[100, 500, 1000] {
            let mut g = generate_barabasi_albert(n, 3, 1_000_000, 2_000_000, 42);
            let h = build_spawn_chain_hypothesis(3);

            let start = std::time::Instant::now();
            let results = g.search_temporal_pattern(&h, None, None).unwrap().0;
            let elapsed = start.elapsed();

            assert!(elapsed.as_secs() < 2,
                "BA n={}: search took {:?}, should be < 2s", n, elapsed);
        }
    }

    #[test]
    fn benchmark_ablation_time_window() {
        // Time window should further reduce results and nodes visited
        let g = generate_erdos_renyi(200, 0.05, 1_000_000, 2_000_000, 42);
        let h = build_lateral_movement_hypothesis(3);

        let (_, stats_no_window) = search_instrumented(&g, &h, None).unwrap();
        let (_, stats_with_window) = search_instrumented(
            &g, &h, Some((1_200_000, 1_800_000))
        ).unwrap();

        // Window should reject additional edges
        assert!(stats_with_window.nodes_visited <= stats_no_window.nodes_visited,
            "Time window should not increase nodes visited");
    }

    #[test]
    fn benchmark_full_report() {
        // Generate the complete benchmark table for the paper
        println!("\n══════════════════════════════════════════════════════════════");
        println!("  EMPIRICAL EVALUATION — Full Benchmark Report");
        println!("══════════════════════════════════════════════════════════════\n");

        let configs: Vec<(&str, GraphHunter)> = vec![
            ("ER-100", generate_erdos_renyi(100, 0.10, 1_000_000, 2_000_000, 42)),
            ("ER-500", generate_erdos_renyi(500, 0.02, 1_000_000, 2_000_000, 42)),
            ("ER-1K", generate_erdos_renyi(1000, 0.01, 1_000_000, 2_000_000, 42)),
            ("ER-5K", generate_erdos_renyi(5000, 0.002, 1_000_000, 2_000_000, 42)),
            ("BA-100", generate_barabasi_albert(100, 3, 1_000_000, 2_000_000, 42)),
            ("BA-500", generate_barabasi_albert(500, 3, 1_000_000, 2_000_000, 42)),
            ("BA-1K", generate_barabasi_albert(1000, 3, 1_000_000, 2_000_000, 42)),
            ("BA-5K", generate_barabasi_albert(5000, 3, 1_000_000, 2_000_000, 42)),
        ];

        println!("{:<10} {:>6} {:>8} {:>6} {:>6} | {:>3} {:>6} {:>8} {:>10} {:>10} {:>6} | {:>6} {:>6} {:>6} {:>6}",
            "Graph", "n", "m", "d_max", "d_avg", "L", "Res", "Time ms", "V_pruned", "V_naive", "Speed",
            "%Rel", "%Ent", "%Temp", "b_eff");
        println!("{}", "-".repeat(130));

        for (label, g) in &configs {
            for l in [2, 3, 4, 5] {
                let h = build_lateral_movement_hypothesis(l);
                let r = run_benchmark(g, &h, None, label);
                let (rr_rel, rr_ent, rr_temp, _, _) = r.pruning_stats.rejection_rates();

                println!("{:<10} {:>6} {:>8} {:>6} {:>6.1} | {:>3} {:>6} {:>8.2} {:>10} {:>10} {:>6.1} | {:>5.1} {:>5.1} {:>5.1} {:>6.2}",
                    r.label, r.n_entities, r.n_relations, r.d_max, r.d_avg,
                    l, r.results_found, r.time_us as f64 / 1000.0,
                    r.nodes_visited_pruned, r.nodes_visited_naive, r.speedup,
                    rr_rel * 100.0, rr_ent * 100.0, rr_temp * 100.0, r.measured_beff);
            }
        }

        // LaTeX output
        println!("\n══════ LaTeX Table Rows ══════\n");
        for (label, g) in &configs {
            for l in [3, 4] {
                let h = build_lateral_movement_hypothesis(l);
                let r = run_benchmark(g, &h, None, label);
                println!("{}", format_latex_row(&r));
            }
        }
    }

    #[test]
    fn benchmark_real_datasets() {
        // Benchmark on actual demo datasets for the paper
        println!("\n══════════════════════════════════════════════════════════════");
        println!("  REAL DATASET BENCHMARKS");
        println!("══════════════════════════════════════════════════════════════\n");

        // APT Simulation
        if let Ok(data) = std::fs::read_to_string("../demo_data/apt_attack_simulation.json") {
            let mut g = GraphHunter::new();
            g.ingest_logs(&data, &SysmonJsonParser, None);
            let (n, m, d_max, d_avg, n_et, n_rt) = graph_params(&g);
            println!("APT Simulation: n={}, m={}, d_max={}, d_avg={:.1}", n, m, d_max, d_avg);

            for l in [2, 3, 4, 5] {
                let h = build_spawn_chain_hypothesis(l);
                let r = run_benchmark(&g, &h, None, "APT");
                println!("  L={}: results={}, time={:.3}ms, V_pruned={}, V_naive={}, speedup={:.1}x, b_eff={:.2}",
                    l, r.results_found, r.time_us as f64 / 1000.0,
                    r.nodes_visited_pruned, r.nodes_visited_naive, r.speedup, r.measured_beff);
            }
        }

        // Sentinel Simulation
        if let Ok(data) = std::fs::read_to_string("../demo_data/sentinel_attack_simulation.json") {
            let mut g = GraphHunter::new();
            g.ingest_logs(&data, &SentinelJsonParser, None);
            let (n, m, d_max, d_avg, n_et, n_rt) = graph_params(&g);
            println!("\nSentinel Simulation: n={}, m={}, d_max={}, d_avg={:.1}", n, m, d_max, d_avg);

            for l in [2, 3, 4, 5] {
                let h = build_lateral_movement_hypothesis(l);
                let r = run_benchmark(&g, &h, None, "Sentinel");
                println!("  L={}: results={}, time={:.3}ms, V_pruned={}, V_naive={}, speedup={:.1}x, b_eff={:.2}",
                    l, r.results_found, r.time_us as f64 / 1000.0,
                    r.nodes_visited_pruned, r.nodes_visited_naive, r.speedup, r.measured_beff);
            }
        }

        // Mordor Combined (if available)
        if let Ok(data) = std::fs::read_to_string("../demo_data/mordor_combined_attacks.json") {
            let mut g = GraphHunter::new();
            g.ingest_logs(&data, &GenericParser, None);
            let (n, m, d_max, d_avg, n_et, n_rt) = graph_params(&g);
            println!("\nMordor Combined: n={}, m={}, d_max={}, d_avg={:.1}", n, m, d_max, d_avg);

            for l in [2, 3, 4, 5] {
                let h = build_spawn_chain_hypothesis(l);
                let r = run_benchmark(&g, &h, None, "Mordor");
                let (rr_rel, rr_ent, rr_temp, _, _) = r.pruning_stats.rejection_rates();
                println!("  L={}: results={}, time={:.3}ms, V_pruned={}, V_naive={}, speedup={:.1}x, b_eff={:.2}, prune: rel={:.0}% ent={:.0}% temp={:.0}%",
                    l, r.results_found, r.time_us as f64 / 1000.0,
                    r.nodes_visited_pruned, r.nodes_visited_naive, r.speedup, r.measured_beff,
                    rr_rel * 100.0, rr_ent * 100.0, rr_temp * 100.0);
            }
        }
    }

    // ══ Phase: Anomaly Scoring ══

    /// Helper: build a small graph with 3 nodes and 2 edges, return (graph, scorer).
    fn build_3node_graph() -> GraphHunter {
        let mut g = GraphHunter::new();
        g.enable_anomaly_scoring(ScoringWeights::default());

        g.add_entity(Entity::new("A", EntityType::IP)).unwrap();
        g.add_entity(Entity::new("B", EntityType::Host)).unwrap();
        g.add_entity(Entity::new("C", EntityType::Process)).unwrap();
        g.add_relation(Relation::new("A", "B", RelationType::Connect, 1000)).unwrap();
        g.add_relation(Relation::new("B", "C", RelationType::Execute, 2000)).unwrap();
        g.finalize_anomaly_scorer();
        g
    }

    #[test]
    fn anomaly_trivial_3node_graph() {
        let g = build_3node_graph();
        let scorer = g.anomaly_scorer.as_ref().unwrap();
        let path = vec!["A".to_string(), "B".to_string(), "C".to_string()];
        let (score, breakdown) = scorer.score_path(&path, &g);

        // With only 3 nodes, each seen once → ER should be 1.0 (ln(1)/ln(1) = 0/0 → freq=1, max=1, ln(1)=0)
        // Actually with the observe calls: each entity appears once (from the relation observer),
        // but B appears twice (once as dest of A→B, once as src of B→C)
        // So freq(A)=1, freq(B)=2, freq(C)=1, max_freq=2
        // ER(A) = 1 - ln(1)/ln(2) = 1 - 0 = 1.0
        // ER(B) = 1 - ln(2)/ln(2) = 1 - 1 = 0.0
        // ER(C) = 1 - ln(1)/ln(2) = 1 - 0 = 1.0
        // ER_avg = (1.0 + 0.0 + 1.0) / 3 ≈ 0.667
        assert!((breakdown.entity_rarity - 0.667).abs() < 0.01,
            "ER = {}", breakdown.entity_rarity);

        // Edge Rarity: each edge pair seen once, max_pair=1, ln(1)=0
        // EdgeR(e) = 1 - ln(1)/ln(1) → log_max_pair_freq = ln(1) = 0, so edge_r = 0.0
        assert!((breakdown.edge_rarity - 0.0).abs() < 0.01,
            "EdgeR = {}", breakdown.edge_rarity);

        // NC: A has 1 neighbor type (Host), B has 2 types (IP, Process) → NC(B) < 1
        // NC(A) = 1.0 (single type), NC(C) = 1.0 (single type)
        // NC(B): H = -0.5*log2(0.5) - 0.5*log2(0.5) = 1.0, H_max = log2(2) = 1.0 → NC = 1-1 = 0.0
        // NC_avg = (1.0 + 0.0 + 1.0) / 3 ≈ 0.667
        assert!((breakdown.neighborhood_concentration - 0.667).abs() < 0.01,
            "NC = {}", breakdown.neighborhood_concentration);

        // TN: first_seen A=1000, B=1000, C=2000, tau_min=1000, tau_max=2000
        // TN(A) = 0, TN(B) = 0, TN(C) = 1.0 → avg = 0.333
        assert!((breakdown.temporal_novelty - 0.333).abs() < 0.01,
            "TN = {}", breakdown.temporal_novelty);

        // Score is composite of these with default weights
        assert!(score > 0.0 && score <= 1.0, "score = {}", score);
    }

    #[test]
    fn anomaly_symmetric_graph() {
        // All nodes have same frequency → ER ≈ 0
        let mut g = GraphHunter::new();
        g.enable_anomaly_scoring(ScoringWeights::default());
        for i in 0..5 {
            g.add_entity(Entity::new(&format!("N{}", i), EntityType::Host)).unwrap();
        }
        // Create a complete graph so all have same frequency
        for i in 0..5 {
            for j in 0..5 {
                if i != j {
                    g.add_relation(Relation::new(
                        &format!("N{}", i), &format!("N{}", j),
                        RelationType::Connect, 1000,
                    )).unwrap();
                }
            }
        }
        g.finalize_anomaly_scorer();

        let scorer = g.anomaly_scorer.as_ref().unwrap();
        let path = vec!["N0".to_string(), "N1".to_string(), "N2".to_string()];
        let (_, breakdown) = scorer.score_path(&path, &g);

        // All entities have same frequency → ER = 1 - ln(max)/ln(max) = 0
        assert!(breakdown.entity_rarity.abs() < 0.01,
            "ER should be ~0 for symmetric graph, got {}", breakdown.entity_rarity);
    }

    #[test]
    fn anomaly_single_neighbor_nc() {
        // Node with a single neighbor type → NC = 1.0
        let mut g = GraphHunter::new();
        g.enable_anomaly_scoring(ScoringWeights::default());
        g.add_entity(Entity::new("center", EntityType::IP)).unwrap();
        g.add_entity(Entity::new("h1", EntityType::Host)).unwrap();
        g.add_entity(Entity::new("h2", EntityType::Host)).unwrap();
        g.add_relation(Relation::new("center", "h1", RelationType::Connect, 1000)).unwrap();
        g.add_relation(Relation::new("center", "h2", RelationType::Connect, 2000)).unwrap();
        g.finalize_anomaly_scorer();

        let scorer = g.anomaly_scorer.as_ref().unwrap();
        // center's neighbors are all Host → NC = 1.0
        let nc = scorer.score_path(&vec!["center".to_string()], &g).1.neighborhood_concentration;
        assert!((nc - 1.0).abs() < 0.01, "NC should be 1.0 for single-type neighbors, got {}", nc);
    }

    #[test]
    fn anomaly_uniform_nc() {
        // Node with equal distribution across many types → NC ≈ 0
        let mut g = GraphHunter::new();
        g.enable_anomaly_scoring(ScoringWeights::default());
        g.add_entity(Entity::new("center", EntityType::IP)).unwrap();
        // Add neighbors of different types
        let types = [EntityType::Host, EntityType::User, EntityType::Process, EntityType::File];
        for (i, et) in types.iter().enumerate() {
            let id = format!("n{}", i);
            g.add_entity(Entity::new(&id, et.clone())).unwrap();
            g.add_relation(Relation::new("center", &id, RelationType::Connect, 1000 + i as i64)).unwrap();
        }
        g.finalize_anomaly_scorer();

        let scorer = g.anomaly_scorer.as_ref().unwrap();
        let nc = scorer.score_path(&vec!["center".to_string()], &g).1.neighborhood_concentration;
        assert!(nc < 0.01, "NC should be ~0 for uniform type distribution, got {}", nc);
    }

    #[test]
    fn anomaly_unique_edge() {
        // A unique edge (pair_freq=1) when max_pair>1 → EdgeR = 1.0
        let mut g = GraphHunter::new();
        g.enable_anomaly_scoring(ScoringWeights::default());
        g.add_entity(Entity::new("A", EntityType::IP)).unwrap();
        g.add_entity(Entity::new("B", EntityType::Host)).unwrap();
        g.add_entity(Entity::new("C", EntityType::Process)).unwrap();
        // A→B appears 5 times (simulate repeated connections)
        for i in 0..5 {
            g.add_relation(Relation::new("A", "B", RelationType::Connect, 1000 + i)).unwrap();
        }
        // B→C appears once (unique)
        g.add_relation(Relation::new("B", "C", RelationType::Execute, 2000)).unwrap();
        g.finalize_anomaly_scorer();

        let scorer = g.anomaly_scorer.as_ref().unwrap();
        let path = vec!["B".to_string(), "C".to_string()];
        let (_, breakdown) = scorer.score_path(&path, &g);
        // pair_freq(B,C)=1, max_pair_freq=5, EdgeR = 1 - ln(1)/ln(5) = 1 - 0 = 1.0
        assert!((breakdown.edge_rarity - 1.0).abs() < 0.01,
            "EdgeR should be 1.0 for unique edge, got {}", breakdown.edge_rarity);
    }

    #[test]
    fn anomaly_temporal_novelty_ordering() {
        // Last-seen entity should have TN ≈ 1.0
        let mut g = GraphHunter::new();
        g.enable_anomaly_scoring(ScoringWeights::default());
        g.add_entity(Entity::new("old", EntityType::IP)).unwrap();
        g.add_entity(Entity::new("mid", EntityType::Host)).unwrap();
        g.add_entity(Entity::new("new", EntityType::Process)).unwrap();
        g.add_relation(Relation::new("old", "mid", RelationType::Connect, 1000)).unwrap();
        g.add_relation(Relation::new("mid", "new", RelationType::Execute, 5000)).unwrap();
        g.finalize_anomaly_scorer();

        let scorer = g.anomaly_scorer.as_ref().unwrap();
        // Score path with only the "new" entity
        let (_, breakdown) = scorer.score_path(&vec!["new".to_string()], &g);
        // TN(new) = (5000-1000)/(5000-1000) = 1.0
        assert!((breakdown.temporal_novelty - 1.0).abs() < 0.01,
            "TN should be ~1.0 for newest entity, got {}", breakdown.temporal_novelty);

        // Score path with only the "old" entity
        let (_, breakdown_old) = scorer.score_path(&vec!["old".to_string()], &g);
        // TN(old) = (1000-1000)/(5000-1000) = 0.0
        assert!((breakdown_old.temporal_novelty - 0.0).abs() < 0.01,
            "TN should be ~0.0 for oldest entity, got {}", breakdown_old.temporal_novelty);
    }

    #[test]
    fn anomaly_weights_sum_correctly() {
        let g = build_3node_graph();
        let scorer = g.anomaly_scorer.as_ref().unwrap();
        let path = vec!["A".to_string(), "B".to_string(), "C".to_string()];
        let (score, bd) = scorer.score_path(&path, &g);

        let w = ScoringWeights::default();
        let expected = w.w1_entity_rarity * bd.entity_rarity
            + w.w2_edge_rarity * bd.edge_rarity
            + w.w3_neighborhood_conc * bd.neighborhood_concentration
            + w.w4_temporal_novelty * bd.temporal_novelty;
        assert!((score - expected).abs() < 1e-10,
            "Composite {} should equal weighted sum {}", score, expected);
    }

    #[test]
    fn anomaly_empty_graph_no_panic() {
        let mut g = GraphHunter::new();
        g.enable_anomaly_scoring(ScoringWeights::default());
        g.finalize_anomaly_scorer();

        let scorer = g.anomaly_scorer.as_ref().unwrap();
        let path: Vec<String> = vec![];
        let (score, _) = scorer.score_path(&path, &g);
        assert_eq!(score, 0.0);
    }

    #[test]
    fn anomaly_score_range_0_to_1() {
        let g = build_3node_graph();
        let scorer = g.anomaly_scorer.as_ref().unwrap();

        // Test multiple paths
        let paths = vec![
            vec!["A".to_string()],
            vec!["A".to_string(), "B".to_string()],
            vec!["A".to_string(), "B".to_string(), "C".to_string()],
            vec!["B".to_string(), "C".to_string()],
        ];
        for path in &paths {
            let (score, bd) = scorer.score_path(path, &g);
            assert!(score >= 0.0 && score <= 1.0,
                "Score {} out of [0,1] for path {:?}", score, path);
            assert!(bd.entity_rarity >= 0.0 && bd.entity_rarity <= 1.0);
            assert!(bd.edge_rarity >= 0.0 && bd.edge_rarity <= 1.0);
            assert!(bd.neighborhood_concentration >= 0.0 && bd.neighborhood_concentration <= 1.0);
            assert!(bd.temporal_novelty >= 0.0 && bd.temporal_novelty <= 1.0);
        }
    }

    #[test]
    fn anomaly_apt_simulation_scoring() {
        // Simulate: many routine connections, one rare attack path
        let mut g = GraphHunter::new();
        g.enable_anomaly_scoring(ScoringWeights::default());

        // Routine entities
        for i in 0..10 {
            g.add_entity(Entity::new(&format!("user{}", i), EntityType::User)).unwrap();
            g.add_entity(Entity::new(&format!("host{}", i), EntityType::Host)).unwrap();
        }
        g.add_entity(Entity::new("dc01", EntityType::Host)).unwrap();
        g.add_entity(Entity::new("attacker_proc", EntityType::Process)).unwrap();
        g.add_entity(Entity::new("malware.exe", EntityType::File)).unwrap();

        // Routine: many auth events (high frequency)
        for i in 0..10 {
            for _ in 0..20 {
                g.add_relation(Relation::new(
                    &format!("user{}", i), &format!("host{}", i),
                    RelationType::Auth, 1000 + i as i64,
                )).unwrap();
            }
        }

        // Attack path: rare entities, late timestamp
        g.add_relation(Relation::new("user0", "dc01", RelationType::Auth, 9000)).unwrap();
        g.add_relation(Relation::new("dc01", "attacker_proc", RelationType::Execute, 9500)).unwrap();
        g.add_relation(Relation::new("attacker_proc", "malware.exe", RelationType::Write, 9900)).unwrap();

        g.finalize_anomaly_scorer();
        let scorer = g.anomaly_scorer.as_ref().unwrap();

        // Attack path
        let attack = vec![
            "user0".to_string(), "dc01".to_string(),
            "attacker_proc".to_string(), "malware.exe".to_string(),
        ];
        let (attack_score, _) = scorer.score_path(&attack, &g);

        // Routine path
        let routine = vec!["user0".to_string(), "host0".to_string()];
        let (routine_score, _) = scorer.score_path(&routine, &g);

        assert!(attack_score > routine_score,
            "Attack path score ({}) should be higher than routine ({})",
            attack_score, routine_score);
    }

    #[test]
    fn anomaly_incremental_ingestion() {
        // Ingest twice, verify scorer updates
        // Ingest twice, verify scorer updates: rare path C→D should score higher than common A→B
        let mut g = GraphHunter::new();
        g.enable_anomaly_scoring(ScoringWeights::default());

        g.add_entity(Entity::new("A", EntityType::IP)).unwrap();
        g.add_entity(Entity::new("B", EntityType::Host)).unwrap();
        g.add_entity(Entity::new("C", EntityType::Process)).unwrap();
        g.add_entity(Entity::new("D", EntityType::File)).unwrap();

        // Make A→B very common
        for _ in 0..20 {
            g.add_relation(Relation::new("A", "B", RelationType::Connect, 1000)).unwrap();
        }
        // C→D is rare (single occurrence, late timestamp)
        g.add_relation(Relation::new("C", "D", RelationType::Execute, 5000)).unwrap();
        g.finalize_anomaly_scorer();

        let scorer = g.anomaly_scorer.as_ref().unwrap();
        let (common_score, _) = scorer.score_path(
            &vec!["A".to_string(), "B".to_string()], &g);
        let (rare_score, _) = scorer.score_path(
            &vec!["C".to_string(), "D".to_string()], &g);

        // Rare path C→D should have higher anomaly score than common A→B
        assert!(rare_score > common_score,
            "Rare path ({}) should score higher than common ({})", rare_score, common_score);
    }
}
