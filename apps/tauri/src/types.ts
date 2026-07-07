// ── Types mirroring the Rust backend ──

export const ENTITY_TYPES = ["IP", "Host", "User", "Process", "File", "Domain", "Registry", "URL", "Service"] as const;
export const ENTITY_TYPES_WITH_WILDCARD = [...ENTITY_TYPES, "*"] as const;
export type EntityType = (typeof ENTITY_TYPES)[number];
export type EntityTypeOrWildcard = (typeof ENTITY_TYPES_WITH_WILDCARD)[number];

export const RELATION_TYPES = ["Auth", "Connect", "Execute", "Read", "Write", "DNS", "Modify", "Spawn", "Delete"] as const;
export const RELATION_TYPES_WITH_WILDCARD = [...RELATION_TYPES, "*"] as const;
export type RelationType = (typeof RELATION_TYPES)[number];
export type RelationTypeOrWildcard = (typeof RELATION_TYPES_WITH_WILDCARD)[number];

export interface HypothesisStep {
  origin_type: EntityType;
  relation_type: RelationType;
  dest_type: EntityType;
}

export interface Hypothesis {
  name: string;
  steps: HypothesisStep[];
  k_simplicity?: number;
}

// ── Session types ──

export interface SessionInfo {
  id: string;
  name: string;
  created_at: number;
}

// ── Notes (standalone or linked to a node) ──

export interface Note {
  id: string;
  content: string;
  node_id: string | null;
  created_at: number;
}

/** Response from `cmd_create_note` — Note plus a URL to GET /notes/:id */
export interface CreatedNote extends Note {
  url: string;
}

// ── Backend response types ──

export interface GraphStats {
  entity_count: number;
  relation_count: number;
}

export interface LoadResult {
  new_entities: number;
  new_relations: number;
  total_entities: number;
  total_relations: number;
  /** True when the parser saw rows but produced no triples. */
  zero_triples?: boolean;
  /** Aggregate parse statistics. `null` = not reported by the parser. */
  ingest_stats?: ParseStats | null;
  /**
   * Post-ingest data-quality notices: shared-infra IPs, likely-duplicate
   * user identities, etc. Empty/omitted when no patterns fire.
   */
  warnings?: string[];
}

export interface DetectedField {
  field_name: string;
  suggested_entity_type: string;
  /** Canonical target the core recognizes (e.g. "source_user"), if any. */
  canonical_target?: string | null;
  /** Number of sampled rows where this field had a non-empty value. */
  occurrence_count?: number;
  /** Up to 5 distinct sample values from the preview sample. */
  sample_values?: string[];
  /** UI-local: optional chrono format hint for columns that hold a timestamp. */
  timestamp_format?: string | null;
  /** UI-local: optional locale tag ("es" | "en") for timestamp parsing. */
  locale?: string | null;
  /**
   * Where the suggestion came from. `"name"` = column-name keyword match,
   * `"values"` = regex matched sample contents, `"canonical"` = canonical
   * alias table default, `"default"` = fell through to raw column name.
   */
  suggestion_source?: "name" | "values" | "canonical" | "default" | null;
}

export interface PreviewIngestResult {
  format: string;
  detected_fields: DetectedField[];
}

// ── PCAP / PCAPNG preview ──
//
// Mirrors `graph_hunter_api::pcap_preview::PcapPreviewResult`. PCAP is
// binary and doesn't fit the tabular `PreviewIngestResult` model, so
// it gets its own preview shape and command (`cmd_pcap_preview`). The
// frontend dispatches by extension: `.pcap` / `.pcapng` / `.cap` → here.

export interface PcapPreviewResult {
  /** "pcap" | "pcapng" | "unknown" — matches the magic-byte family. */
  format: string;
  file_size: number;
  /** Packets actually decoded (≤ 10_000). */
  packets_sampled: number;
  /** Linear extrapolation from sampled bytes — rough order-of-magnitude. */
  packet_count_estimate: number;
  time_span: PcapTimeSpan | null;
  protocol_mix: PcapProtocolCount[];
  top_src_ips: PcapIpCount[];
  top_dst_ips: PcapIpCount[];
  top_dst_ports: PcapPortCount[];
  /** Soft warnings (truncated file, undecodable packets, …). May be omitted. */
  warnings?: string[];
}

export interface PcapTimeSpan {
  first_unix_secs: number;
  last_unix_secs: number;
  duration_secs: number;
}

export interface PcapProtocolCount {
  /** "TCP" | "UDP" | "ICMP" | "ICMPv6" | "Other". */
  protocol: string;
  packets: number;
  bytes: number;
}

export interface PcapIpCount {
  ip: string;
  packets: number;
  bytes: number;
}

export interface PcapPortCount {
  port: number;
  /** "TCP" | "UDP". */
  protocol: string;
  /** Well-known service name (e.g. "HTTPS", "DNS"), or omitted. */
  service?: string;
  packets: number;
}

export interface ParseStats {
  rows_seen: number;
  rows_with_triples: number;
  rows_skipped: number;
  per_field_occurrence?: Record<string, number>;
  /** Why rows were skipped, aggregated by short reason tag
   *  (e.g. `empty_row`, `no_canonical_fields`, `no_anchor`). */
  skip_reasons?: Record<string, number>;
  /** Up to ~20 sampled skipped rows (raw JSON snippet + reason tag).
   *  Surfaced by the Skipped badge popover so analysts can inspect
   *  concrete drop-outs without persisting per-row metadata. */
  skipped_samples?: Array<[string, string]>;
}

export interface DatasetInfo {
  id: string;
  name: string;
  path?: string;
  created_at: number;
  entity_count: number;
  relation_count: number;
  /** User-supplied field mapping applied at ingest time, if any. */
  field_config?: FieldConfig | null;
  /** Aggregate parse statistics from ingest. `null` = not reported. */
  ingest_stats?: ParseStats | null;
}

export interface HuntResults {
  paths: string[][];
  path_count: number;
  truncated?: boolean;
  live_tail_coverage?: {
    phase: string;
    tail_edge_count: number;
    index_coverage: number;
  };
}

export interface ScoreBreakdown {
  entity_rarity: number;
  edge_rarity: number;
  neighborhood_concentration: number;
  temporal_novelty: number;
  gnn_threat: number;
}

export interface ScoringWeights {
  w1_entity_rarity: number;
  w2_edge_rarity: number;
  w3_neighborhood_conc: number;
  w4_temporal_novelty: number;
  w5_gnn_threat: number;
}

export type AiProvider = "OpenAI" | "Anthropic" | "Google";

export interface AiConfig {
  api_key_set: boolean;
  provider: AiProvider | null;
  model: string;
  base_url: string;
}

export interface ConversationMessage {
  role: string;
  content: string;
  timestamp: number;
}

export interface AiSuggestion {
  action: string;      // "expand_node" | "run_hypothesis" | "search_entities"
  target_id: string;
  label: string;
}

export interface AiAnalysisResponse {
  text: string;
  suggestions: AiSuggestion[];
}

export interface ScoredPath {
  path: string[];
  max_score: number;
  total_score: number;
  time_start: number;
  time_end: number;
  chain_summary: string;
  anomaly_score?: number;
  anomaly_breakdown?: ScoreBreakdown;
  /** How many raw paths this row represents after dedup. 1 when dedup is off. */
  edge_count: number;
  /** Dataset IDs that contributed at least one edge to this path. */
  datasets_used?: string[];
}

/** Matches graph_hunter_core::DedupMode — "None" | "ByPath" | "ByEndpoints". */
export type DedupMode = "None" | "ByPath" | "ByEndpoints";

export interface PaginatedHuntResults {
  total_paths: number;
  filtered_paths: number;
  page: number;
  page_size: number;
  paths: ScoredPath[];
}

/** IP classification returned by the backend for IP entities.
 *  Matches `graph_hunter_core::ip_utils::IpClass` Debug output. */
export type IpClass =
  | "Private"
  | "Loopback"
  | "LinkLocal"
  | "Multicast"
  | "Reserved"
  | "Public";

export interface SubgraphNode {
  id: string;
  entity_type: string;
  score: number;
  metadata: Record<string, string>;
  /** Present only for IP entities; absent/null otherwise. */
  ip_class?: IpClass | null;
}

export interface SubgraphEdge {
  source: string;
  target: string;
  rel_type: string;
  timestamp: number;
  metadata: Record<string, string>;
  /** Dataset this event came from (shown in Events view on hover). */
  dataset_id?: string | null;
}

export interface Subgraph {
  nodes: SubgraphNode[];
  edges: SubgraphEdge[];
}

/**
 * Per-(source, target, rel_type) bundle produced by edge bundling
 * in GraphCanvas. Surfaces both the aggregate (for the canvas
 * label / width / color) and the full list of underlying edges
 * (for drill-down inside EdgeDetailPanel). The underlying list
 * preserves every per-edge `metadata` value (sensor_uid, flow_id,
 * bytes, sni, kerberos_user, …) so the analyst can pivot back to
 * any single observation that contributed to the bundle.
 */
export interface EdgeBundle {
  source: string;
  target: string;
  rel_type: string;
  /** Number of underlying edges in this bundle. */
  count: number;
  /** Earliest `timestamp` across the bundled edges. */
  first_ts: number;
  /** Latest `timestamp` across the bundled edges. */
  last_ts: number;
  /** Every underlying edge, in insertion order. The first element
   *  is what `EdgeDetailPanel` auto-selects on open. */
  underlying: SubgraphEdge[];
}

// ── Color mapping for entity types ──

export const ENTITY_COLORS: Record<EntityType, string> = {
  IP: "#ff6b6b",
  Host: "#4ecdc4",
  User: "#45b7d1",
  Process: "#f9ca24",
  File: "#a29bfe",
  Domain: "#fd79a8",
  Registry: "#e67e22",
  URL: "#1abc9c",
  Service: "#9b59b6",
};

// ── Explorer mode types ──

export interface SearchResult {
  id: string;
  entity_type: string;
  score: number;
  connections: number;
}

export interface NeighborNode {
  id: string;
  entity_type: string;
  score: number;
  metadata: Record<string, string>;
}

export interface NeighborEdge {
  source: string;
  target: string;
  rel_type: string;
  timestamp: number;
  metadata: Record<string, string>;
}

export interface Neighborhood {
  center: string;
  nodes: NeighborNode[];
  edges: NeighborEdge[];
  truncated: boolean;
  /**
   * True when the backend auto-routed the expansion through the grouped
   * path because the node's degree exceeded the threshold. Each edge in
   * `edges` represents a collapsed group; see metadata keys `edge_count`,
   * `first_ts`, `last_ts`.
   */
  auto_grouped?: boolean;
  auto_group_reason?: string | null;
}

export interface GroupedNeighborEdge {
  source: string;
  target: string;
  rel_type: string;
  count: number;
  first_ts: number;
  last_ts: number;
  /** Entity type of the collapsed targets (when grouping by target_type). */
  target_entity_type?: string | null;
  /** Sample of distinct target ids that this group represents (capped server-side). */
  targets?: string[];
}

export interface GroupedNeighborhood {
  center: string;
  nodes: NeighborNode[];
  edges: GroupedNeighborEdge[];
  truncated: boolean;
  total_edge_count: number;
}

export interface PaginatedEvents {
  events: SubgraphEdge[];
  total_count: number;
  page: number;
  page_size: number;
}

export interface NeighborSummary {
  id: string;
  entity_type: string;
}

export interface NodeDetails {
  id: string;
  entity_type: string;
  score: number;
  degree_score: number;
  betweenness: number;
  pagerank_score: number;
  metadata: Record<string, string>;
  in_degree: number;
  out_degree: number;
  time_range: [number, number] | null;
  neighbor_types: Record<string, number>;
  /** Neighbour nodes (id + type) for clickable list in lateral panel (optional for backward compat) */
  neighbors?: NeighborSummary[];
  /** Hint from the backend: plain expand_node will silently auto-fall-back to grouped mode for this node. */
  recommend_grouped_expansion?: boolean;
  /** Four-dimension anomaly breakdown; only present when anomaly scoring is enabled and finalized. */
  anomaly_breakdown?: ScoreBreakdown;
}

export interface ExplainedPeer {
  id: string;
  composite_score: number;
}

export interface ExplainedScore {
  id: string;
  entity_type: string;
  composite_score: number;
  degree_score: number;
  pagerank_score: number;
  betweenness: number;
  /** Inverted-degree rarity signal [0-100]. High = rarely touched. */
  rarity_score?: number;
  anomaly_breakdown?: ScoreBreakdown;
  composite_percentile: number;
  degree_percentile: number;
  /** Percentile rank of rarity_score across all entities. */
  rarity_percentile?: number;
  peers: ExplainedPeer[];
  /** One-paragraph explanation in English, assembled from the fields above. */
  narrative: string;
}

export interface TypeDistribution {
  entity_type: string;
  count: number;
}

export interface TopAnomaly {
  id: string;
  entity_type: string;
  score: number;
}

export interface GraphSummary {
  entity_count: number;
  relation_count: number;
  type_distribution: TypeDistribution[];
  time_range: [number, number] | null;
  top_anomalies: TopAnomaly[];
  /** Active graph state derived from the counts (empty/partial/populated). */
  graph_state?: "empty" | "partial" | "populated";
  /** Advisory nudge for empty/partial graphs; omitted when populated. */
  advisory?: string;
  /** §5: most recent graph_build for the session, or absent if never built. */
  last_build?: {
    build_id: string;
    proposal_id: string;
    at: number;
    entities_created: number;
    relations_created: number;
    merge_mode: string;
  };
}

export interface ExpandFilter {
  entity_types?: string[];
  relation_types?: string[];
  time_start?: number;
  time_end?: number;
  min_score?: number;
}

// ── Field preview / configurable ingestion ──

export type FieldRole = "Node" | "Metadata" | "Ignore";

export interface FieldInfo {
  raw_name: string;
  canonical_target: string | null;
  occurrence_count: number;
  sample_values: string[];
  current_role: FieldRole;
  suggested_entity_type: string | null;
}

export interface FieldMapping {
  raw_name: string;
  role: FieldRole;
  entity_type: string | null;
  /**
   * Optional chrono format string used when this column carries a timestamp
   * the built-in auto-detection can't parse. Example for Zoho exports:
   * `"%b %d, %Y, %I:%M %p"`.
   */
  timestamp_format?: string | null;
  /**
   * Optional locale tag applied before `timestamp_format` to translate
   * localized month names to English (currently supports "es" and "en").
   */
  locale?: string | null;
}

export interface FieldConfig {
  mappings: FieldMapping[];
}

// ── Status log entry ──

export interface LogEntry {
  time: string;
  message: string;
  level: "info" | "success" | "warning" | "error";
  /** Full KQL text for audit trail (present only on KQL-related entries). */
  kql?: string;
  /** Origin of the KQL execution. */
  kqlSource?: "polling" | "adhoc" | "one-shot";
  /** Target table or "custom" for ad-hoc queries. */
  kqlTarget?: string;
  /** Number of rows returned by the KQL query. */
  kqlRowCount?: number;
}

// ── DSL types ──

export interface DslResult {
  hypothesis: Hypothesis;
  formatted: string;
}

export interface DslError {
  message: string;
  position: number;
}

// ── ATT&CK Catalog ──

export interface CatalogEntry {
  id: string;
  name: string;
  mitre_id: string;
  description: string;
  dsl_pattern: string;
  k_simplicity: number;
}

// ── Streaming ingestion progress ──

export interface IngestProgress {
  processed: number;
  total_estimate: number;
  entities: number;
  relations: number;
}

export interface IngestJobStarted {
  job_id: string;
  dataset_id: string;
}

export interface IngestCompleteEvent {
  job_id: string;
  dataset_id: string;
  result: LoadResult;
}

export interface IngestErrorEvent {
  job_id: string;
  dataset_id: string;
  error: string;
}

// ── LLM-as-compiler dispatcher (Phase C/D) ──

export interface FieldMappingSummary {
  raw_name: string;
  role: FieldRole;
  entity_type?: string | null;
}

export interface MappingChange {
  raw_name: string;
  heuristic?: FieldMappingSummary | null;
  refined?: FieldMappingSummary | null;
}

export interface MappingDiff {
  added: FieldMappingSummary[];
  removed: FieldMappingSummary[];
  changed: MappingChange[];
  unchanged_count: number;
}

/**
 * Emitted on `ingest-llm-diagnostic` for every dispatcher decision —
 * heuristic confident, LLM proposal pending, or LLM unavailable. The
 * panel renders this as a status-log entry so the analyst always sees
 * which path was taken; without it, a silent fallback to the heuristic
 * that produces zero triples is indistinguishable from a parser bug.
 */
export interface IngestLlmDiagnosticEvent {
  job_id: string;
  dataset_id: string;
  /** `heuristic_ok` | `llm_proposal` | `llm_unavailable` */
  outcome: "heuristic_ok" | "llm_proposal" | "llm_unavailable" | string;
  reason: string;
  backend_id?: string | null;
}

/**
 * Emitted on the `ingest-llm-proposal` Tauri event when the heuristic
 * config produced zero recognized Node mappings and the local LLM
 * offered a refined alternative. The streaming pipeline aborts before
 * any triples land — the analyst chooses one of the two configs in the
 * confirm banner and the frontend re-triggers `cmd_load_data_streaming`
 * with the chosen one.
 */
export interface IngestLlmProposalEvent {
  job_id: string;
  dataset_id: string;
  source_path: string;
  format: string;
  heuristic: FieldConfig;
  refined: FieldConfig;
  diff: MappingDiff;
  confidence: number;
  backend_id: string;
}

// ── Merge policy ──

export type MergePolicy = "FirstWriteWins" | "LastWriteWins" | "Append";

// ── Compaction stats ──

export interface CompactionStats {
  edges_before: number;
  edges_after: number;
  edges_removed: number;
  groups_compacted: number;
}

// ── Sentinel Real-Time Connector ──

/**
 * Time window for Sentinel queries (Phase L). Either a preset
 * lookback string (matches KQL `ago()` durations) or an absolute
 * datetime range. Backend serializes via `#[serde(tag = "kind")]` so
 * the wire shape is `{ kind: "preset", lookback: "1h" }` or
 * `{ kind: "absolute", from_iso: "...", to_iso: "..." }`.
 */
export type LookbackPreset = "1h" | "6h" | "24h" | "7d" | "30d";
export type TimeWindow =
  | { kind: "preset"; lookback: LookbackPreset }
  | { kind: "absolute"; from_iso: string; to_iso: string };

/**
 * Hunting template identifier (Phase M). The backend renders the
 * matching KQL body with the analyst's chosen `TimeWindow`.
 */
export type HuntingTemplateId =
  | "failed_logon_burst"
  | "lateral_movement"
  | "encoded_power_shell"
  | "suspicious_dns";

export interface SentinelConnectedEvent {
  connector_id: string;
  tables: string[];
  poll_interval_secs: number;
}

export interface SentinelDataEvent {
  new_entities: number;
  new_relations: number;
  timestamp: number;
}

export interface SentinelErrorEvent {
  error: string;
  consecutive_errors: number;
  will_retry: boolean;
}

export interface ConnectorStatusResponse {
  connected: boolean;
  connector_id: string | null;
  status: {
    state: string;
    last_data_at?: string;
    total_entities?: number;
    total_relations?: number;
    message?: string;
    consecutive?: number;
  } | null;
}

export interface SentinelEnvStatus {
  azure_client_id: string | null;
  azure_client_secret_set: boolean;
  azure_client_secret_masked: string | null;
  azure_tenant_id: string | null;
  azure_subscription_id: string | null;
  azure_resource_group: string | null;
  azure_workspace_id: string | null;
  azure_workspace_name: string | null;
}

/** Emitted by the backend every time a KQL query executes (polling or ad-hoc). */
export interface KqlQueryExecutedEvent {
  kql: string;
  source: string;
  target: string;
  row_count: number;
  entities_created: number;
  relations_created: number;
}

/** Result returned by cmd_run_kql for ad-hoc KQL execution. */
export interface KqlResult {
  new_entities: number;
  new_relations: number;
  total_entities: number;
  total_relations: number;
  kql_executed: string;
  row_count: number;
  /** Phase N: wall-time of the KQL roundtrip, ms. */
  took_ms?: number;
  /** Phase N: `take N` clause applied (when detectable). */
  take_limit?: number | null;
  /** Phase N: true when row_count saturates take_limit. */
  truncated?: boolean;
  /** Graph-first nudge: set in inspect mode when the query touches identity/IP-like columns. */
  graph_advisory?: string | null;
  /** §4.7: ready-to-run graph_propose args derived from the query's entity columns. */
  graph_propose?: {
    next_tool: string;
    table: string;
    selected_fields: { table: string; field: string }[];
  } | null;
  /** §4.7: true when an unacknowledged entity-class raw-KQL query was NOT executed. */
  fallback_gated?: boolean;
}

// ── Temporal heatmap ──

export interface HeatmapRow {
  relation_type: string;
  bins: [number, number][];
  /** Bucket width in seconds. Backend default 3600; zero-count buckets are emitted explicitly. */
  bucket_size_seconds: number;
}

// ── Timeline sparkline ──

export interface TimelineRow {
  entity_type: string;
  min_time: number;
  max_time: number;
  bins: [number, number][];
}

// ── IP enrichment & subnet analysis ──

export interface GeoIpResult {
  country_code: string | null;
  country_name: string | null;
  city: string | null;
  asn: number | null;
  as_org: string | null;
  isp: string | null;
}

export interface SubnetGroup {
  subnet: string;
  ip_count: number;
  ips: string[];
  total_bytes: number | null;
  is_internal: boolean;
  top_services: string[];
}
