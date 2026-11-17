// Re-export core types at crate root for ergonomic imports.
pub use analytics::{
    AUTO_GROUPED_THRESHOLD, DedupMode, ExplainedPeer, ExplainedScore, GraphSummary,
    GroupedNeighborEdge, GroupedNeighborhood, HuntDiagnostic, HuntDiff, NeighborEdge, NeighborNode,
    Neighborhood, NeighborhoodFilter, NodeDetails, RelSchemaEntry, ScoredPath, SearchResult,
    TopAnomaly, TypeDistribution,
};
pub use anomaly::{AnomalyScorer, ScoreBreakdown, ScoringWeights, ThreatClass};
pub use catalog::{
    CatalogEntry, CatalogEntryWithStatus, CatalogLoadError, CatalogSnapshot, CatalogSource,
    check_catalog_compatibility, get_catalog, get_catalog_snapshot,
};
pub use scoring::{
    CompositeScorer, EdgeRarity, EntityRarity, GnnThreat, NeighborhoodConcentration, PathContext,
    ScoreComponent, ScoreOutcome, ScoringCaches, TemporalNovelty,
};
// GNN inference + training-corpus export moved to `graph_hunter_gnn`
// per F2.14 (ADR-003 precursor). Core no longer re-exports those
// symbols because doing so creates a `core → gnn → core` cycle (gnn
// names `GraphHunter`). Call sites that used
// `graph_hunter_core::{SubgraphFeatures, NpuScorer, ...}` now import
// from `graph_hunter_gnn::` directly.
pub use backend::{GraphRead, GraphWrite};
pub use csv_parser::CsvParser;
pub use entity::Entity;
pub use errors::{GraphError, SpillError};
pub use field_preview::{
    ConfigurableParser, FieldConfig, FieldInfo, FieldMapping, FieldRole, Suggestion,
    SuggestionSource, preview_fields, preview_fields_from_events, suggest_entity_type,
    suggest_entity_type_with_source,
};
pub use generic::GenericParser;
pub use graph::{CompactionStats, GraphHunter};
pub use ingest_adapter::{IngestAdapter, LogSourceAdapter, TripleBatch, TripleBatchStream};
/// Forward-compatibility alias: the plan (P2-B) eventually renames
/// `GraphHunter` → `InMemoryGraph` once every call site has migrated
/// to the trait-based API. Until then, this alias lets new code opt
/// into the target name without touching the 121+ existing
/// references.
pub type InMemoryGraph = graph::GraphHunter;
pub use hypothesis::{AggClause, AggColumn, Hypothesis, HypothesisStep, Predicate};
pub use interner::{InternerMetrics, StrId, StringInterner, StringInternerBackend};
pub use metadata_store::MetadataStore;
pub use parser::{LogParser, ParseStats, ParsedTriple, RawIngestEvent};
pub use preview::{preview_generic_from_keys, preview_sentinel, preview_sysmon};
pub use relation::{CompactRelation, Relation};
pub use sentinel::SentinelJsonParser;
pub use sysmon::SysmonJsonParser;
