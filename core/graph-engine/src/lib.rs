pub mod analytics;
pub mod anomaly;
pub mod backend;
pub mod benchmark;
pub mod catalog;
pub mod config;
pub mod csv_parser;
pub mod dlq;
pub mod drift;
pub mod entity;
pub mod errors;
pub mod export;
pub mod field_preview;
pub mod generic;
pub mod geoip;
pub mod graph;
pub mod interner;
pub mod ip_utils;
pub mod khop_reach;
pub mod lftj;
pub mod lftj_query;
pub mod metadata_store;
pub mod mmap_advise;
pub mod nlf;
pub mod index_storage;
pub mod nauty_symmetry;
pub mod parse_error;
pub mod parser;
pub mod planner;
pub mod streaming;
pub mod yannakakis;

pub mod ingest;
pub mod ingest_adapter;
pub mod invariants;
pub mod mapping_library;
pub mod preview;
pub mod relation;
pub mod scoring;
pub mod semijoin;
pub mod sentinel;
pub mod service_classifier;
pub mod simd_rust;
pub mod symmetry;
pub mod sysmon;
pub mod watermark_store;

// Re-export core types at crate root for ergonomic imports.
pub use analytics::{
    AUTO_GROUPED_THRESHOLD, ChannelBehavior, ChannelBehaviorOpts, ChannelSortBy, DedupMode,
    ExplainedPeer, ExplainedScore, GraphSummary, GroupedNeighborEdge, GroupedNeighborhood,
    HeavyEdge, HeavyEdgesOpts, HuntDiagnostic, HuntDiff, LiveTailCoverage, NeighborEdge,
    NeighborNode, Neighborhood, NeighborhoodFilter, NodeDetails, RelSchemaEntry, ScoredPath,
    SearchResult, TopAnomaly, TypeDistribution,
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
// F2.11: the sources module lives in `platform/sources`. Re-exported
// here so call-sites that imported `graph_hunter_core::sources::X` keep
// resolving during the migration. The alias lets `crate::sources::Y`
// references compile too (used by ingest/*, watermark_store, etc.).
pub use graph_hunter_sources as sources;
pub use graph_hunter_sources::backoff::{
    DEFAULT_BASE_DELAY, DEFAULT_JITTER, DEFAULT_MAX_AUTH_FAILURES, DEFAULT_MAX_DELAY,
    DEFAULT_MULTIPLIER, ExponentialBackoff,
};
pub use graph_hunter_sources::data_lake::DataLakeV2Source;
pub use graph_hunter_sources::defender_xdr::{
    DEFAULT_XDR_ENDPOINT, DefenderXdrConfig, DefenderXdrSource,
};
pub use graph_hunter_sources::http_client::{
    HttpClient, HttpError, HttpMethod, HttpRequest, HttpResponse, MockHttpClient, MockResponse,
    StatusClass,
};
pub use graph_hunter_sources::http_token_fetcher::{DEFAULT_AAD_AUTHORITY, HttpTokenFetcher};
pub use graph_hunter_sources::log_analytics::{
    DEFAULT_LA_ENDPOINT, LogAnalyticsConfig, LogAnalyticsSource,
};
pub use graph_hunter_sources::token_cache::{
    AzureTokenCache, CachedToken, DEFAULT_REFRESH_HORIZON, TokenError, TokenFetcher, TokenKey,
};
pub use graph_hunter_sources::{
    ChunkEncoding, ChunkStream, EntityRef, LogSource, PollStream, QueryScope, RawChunk,
    SourceError, SourceKind, Watermark,
};
pub use ingest::{
    DEFAULT_PARSED_CAPACITY, DEFAULT_POLL_INTERVAL, DEFAULT_RAW_CAPACITY, DEFAULT_WRITE_CHUNK_SIZE,
    GraphAccess, GraphWriter, ParsedBatch, ParsedReceiver, ParsedSender, ParserTask, PollerConfig,
    Priority, RawReceiver, RawSender, SourcePoller, WriterMetrics, WriterMetricsSnapshot,
    parsed_channel, raw_channel,
};
pub use watermark_store::{
    EnrichmentAuditEntry, SourceState, SourceStatus, SqliteWatermarkStore, WatermarkError,
    WatermarkKey, WatermarkStore,
};
// F2.12: dsl + hypothesis + types moved to platform/dsl. Re-exported
// here under the original module paths so all `crate::types::X`,
// `crate::hypothesis::Y`, and `crate::dsl::Z` references inside core
// keep resolving. Downstream crates that imported
// `graph_hunter_core::{EntityType, Hypothesis, parse_dsl, …}` also stay
// source-compatible via the item-level re-exports below.
pub use benchmark::{
    BenchmarkResult, PruningStats, approx_memory, build_lateral_movement_hypothesis,
    build_spawn_chain_hypothesis, format_latex_row, generate_barabasi_albert, generate_erdos_renyi,
    graph_params, run_benchmark, search_instrumented,
};
pub use geoip::{GeoIpError, GeoIpResult, write_geoip_to_metadata};
pub use graph_hunter_dsl as dsl;
pub use graph_hunter_dsl::types::{
    EntityType, MergePolicy, RelationType, entity_type_matches, relation_type_matches,
};
pub use graph_hunter_dsl::{DslError, DslParseResult, format_hypothesis, parse_dsl};
pub use graph_hunter_dsl::{hypothesis, types};
pub use ip_utils::{
    IpClass, classify_ip, group_by_subnet, is_private, is_public, same_subnet_24, subnet_24,
};
pub use service_classifier::{
    ServiceCategory, ServiceInfo, classify_application, is_file_transfer, is_remote_access,
};

#[cfg(test)]
mod tests;
