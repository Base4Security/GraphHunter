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
}

export interface DetectedField {
  field_name: string;
  suggested_entity_type: string;
}

export interface PreviewIngestResult {
  format: string;
  detected_fields: DetectedField[];
}

export interface DatasetInfo {
  id: string;
  name: string;
  path?: string;
  created_at: number;
  entity_count: number;
  relation_count: number;
}

export interface HuntResults {
  paths: string[][];
  path_count: number;
  truncated?: boolean;
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
}

export interface PaginatedHuntResults {
  total_paths: number;
  filtered_paths: number;
  page: number;
  page_size: number;
  paths: ScoredPath[];
}

export interface SubgraphNode {
  id: string;
  entity_type: string;
  score: number;
  metadata: Record<string, string>;
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
}

export interface FieldConfig {
  mappings: FieldMapping[];
}

// ── Status log entry ──

export interface LogEntry {
  time: string;
  message: string;
  level: "info" | "success" | "error";
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

// ── Merge policy ──

export type MergePolicy = "FirstWriteWins" | "LastWriteWins" | "Append";

// ── Compaction stats ──

export interface CompactionStats {
  edges_before: number;
  edges_after: number;
  edges_removed: number;
  groups_compacted: number;
}

// ── Temporal heatmap ──

export interface HeatmapRow {
  relation_type: string;
  bins: [number, number][];
}

// ── Timeline sparkline ──

export interface TimelineRow {
  entity_type: string;
  min_time: number;
  max_time: number;
  bins: [number, number][];
}
