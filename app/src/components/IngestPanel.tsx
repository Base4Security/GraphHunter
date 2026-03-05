import { useState, useEffect, useRef } from "react";
import { invoke } from "../lib/tauri";
import { isTauri } from "../lib/runtime";
import {
  uploadFile,
  createJob,
  createQueryJob,
  connectProgressWS,
  pollJobStatus,
  type JobStatus,
} from "../lib/webIngest";
import {
  Upload,
  BarChart3,
  FolderOpen,
  Database,
  Activity,
  ChevronDown,
  ChevronRight,
  ChevronLeft,
  Palette,
  ArrowRight,
  Layers,
  Trash2,
  Edit3,
  X,
  SlidersHorizontal,
} from "lucide-react";
import type {
  GraphStats,
  LoadResult,
  LogEntry,
  EntityType,
  SessionInfo,
  PreviewIngestResult,
  DetectedField,
  DatasetInfo,
  FieldInfo,
  FieldMapping,
  FieldConfig,
  CompactionStats,
  IngestJobStarted,
  IngestCompleteEvent,
  IngestErrorEvent,
} from "../types";
import { ENTITY_COLORS, ENTITY_TYPES } from "../types";
import FieldSelector from "./FieldSelector";

interface EntityTypeCount {
  entity_type: string;
  count: number;
}

interface IngestPanelProps {
  currentSessionId: string | null;
  onSessionCreated?: (session: SessionInfo) => void;
  stats: GraphStats;
  onStatsUpdate: (stats: GraphStats) => void;
  log: LogEntry[];
  onLog: (entry: LogEntry) => void;
  onClose?: () => void;
  /** Show all nodes of a type on the map (Hunt mode subgraph) */
  onShowTypeOnMap?: (nodeIds: string[]) => void;
  /** Show a single node on the map (Explorer mode, expand node) */
  onShowNodeOnMap?: (nodeId: string) => void;
}

function now(): string {
  return new Date().toLocaleTimeString("en-US", { hour12: false });
}

export default function IngestPanel({
  currentSessionId,
  onSessionCreated,
  stats,
  onStatsUpdate,
  log,
  onLog,
  onClose,
  onShowTypeOnMap,
  onShowNodeOnMap,
}: IngestPanelProps) {
  const [filePath, setFilePath] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);
  const [format, setFormat] = useState<"auto" | "evtx" | "sysmon" | "sentinel" | "generic" | "csv">("auto");
  const [ingestSource, setIngestSource] = useState<"file" | "sentinel" | "elastic">("file");
  const [azureTenantId, setAzureTenantId] = useState("");
  const [azureClientId, setAzureClientId] = useState("");
  const [azureClientSecret, setAzureClientSecret] = useState("");
  const [siemWorkspaceId, setSiemWorkspaceId] = useState("");
  const [elasticUrl, setElasticUrl] = useState("");
  const [elasticIndex, setElasticIndex] = useState("");
  const [elasticQuery, setElasticQuery] = useState("{}");
  const [elasticSize, setElasticSize] = useState(1000);
  const [elasticApiKey, setElasticApiKey] = useState("");
  const [elasticUser, setElasticUser] = useState("");
  const [elasticPassword, setElasticPassword] = useState("");

  // Progress bar state for streaming ingestion
  const [ingestProgress, setIngestProgress] = useState<{ processed: number; total: number; entities: number; relations: number; phase?: string } | null>(null);
  const unlistenRef = useRef<(() => void) | null>(null);

  // Web mode: selected File object + hidden input ref
  const [webFile, setWebFile] = useState<File | null>(null);
  const webFileInputRef = useRef<HTMLInputElement | null>(null);

  // Preview step: result from cmd_preview_ingest and editable mapping (field -> node type)
  const [previewResult, setPreviewResult] = useState<PreviewIngestResult | null>(null);
  const [previewLoading, setPreviewLoading] = useState(false);
  const [mappingRows, setMappingRows] = useState<DetectedField[]>([]);
  // Entity types for preview dropdown: standard + custom from graph + any in current mapping
  const [graphEntityTypes, setGraphEntityTypes] = useState<string[]>([]);

  // Datasets section
  const [showDatasets, setShowDatasets] = useState(true);
  const [datasets, setDatasets] = useState<DatasetInfo[]>([]);
  const [datasetsLoading, setDatasetsLoading] = useState(false);
  const [renameModal, setRenameModal] = useState<{ datasetId: string; datasetName: string } | null>(null);
  const [renameFromType, setRenameFromType] = useState<string>("");
  const [renameToType, setRenameToType] = useState<string>("");
  const [datasetTypes, setDatasetTypes] = useState<string[]>([]);

  // Field preview state
  const [fieldPreview, setFieldPreview] = useState<FieldInfo[] | null>(null);
  const [showFieldSelector, setShowFieldSelector] = useState(false);
  const [configLoading, setConfigLoading] = useState(false);

  // Scoring section state
  const [showScoring, setShowScoring] = useState(false);
  const [degreeWeight, setDegreeWeight] = useState(33);
  const [pagerankWeight, setPagerankWeight] = useState(33);
  const [betweennessWeight, setBetweennessWeight] = useState(33);
  const [pagerankLambda, setPagerankLambda] = useState(0.001);
  const [scoringLoading, setScoringLoading] = useState(false);
  const [compactDate, setCompactDate] = useState("");
  const [compactLoading, setCompactLoading] = useState(false);

  // Top-level left menus (show/hide at top of each menu)
  const [datasetsMenuOpen, setDatasetsMenuOpen] = useState(true);
  const [activityLogMenuOpen, setActivityLogMenuOpen] = useState(true);
  const [graphMetricsMenuOpen, setGraphMetricsMenuOpen] = useState(true);
  // Inner collapsible sections within menus
  const [showDataIngestion, setShowDataIngestion] = useState(false);
  const [showGraphMetrics, setShowGraphMetrics] = useState(true);
  const [showTypesAvailable, setShowTypesAvailable] = useState(true);

  // Types Available: counts from graph, and expanded type with list of entity IDs
  const [typeCounts, setTypeCounts] = useState<EntityTypeCount[]>([]);
  const [typeCountsLoading, setTypeCountsLoading] = useState(false);
  const [expandedType, setExpandedType] = useState<string | null>(null);
  const [entitiesForType, setEntitiesForType] = useState<string[]>([]);
  const [entitiesLoading, setEntitiesLoading] = useState(false);

  useEffect(() => {
    if (!currentSessionId || !showTypesAvailable) {
      setTypeCounts([]);
      return;
    }
    let cancelled = false;
    setTypeCountsLoading(true);
    invoke<EntityTypeCount[]>("cmd_get_entity_type_counts")
      .then((list) => {
        if (!cancelled) setTypeCounts(list);
      })
      .catch(() => {
        if (!cancelled) setTypeCounts([]);
      })
      .finally(() => {
        if (!cancelled) setTypeCountsLoading(false);
      });
    return () => {
      cancelled = true;
    };
  }, [currentSessionId, showTypesAvailable, stats.entity_count, stats.relation_count]);

  // Fetch entity types in graph for preview dropdown (so custom types are available)
  useEffect(() => {
    if (!currentSessionId || !previewResult) {
      setGraphEntityTypes([]);
      return;
    }
    let cancelled = false;
    invoke<string[]>("cmd_get_entity_types_in_graph")
      .then((list) => {
        if (!cancelled) setGraphEntityTypes(list ?? []);
      })
      .catch(() => {
        if (!cancelled) setGraphEntityTypes([]);
      });
    return () => {
      cancelled = true;
    };
  }, [currentSessionId, previewResult]);

  // Fetch datasets when session or stats change
  useEffect(() => {
    if (!currentSessionId || !showDatasets) {
      setDatasets([]);
      return;
    }
    let cancelled = false;
    setDatasetsLoading(true);
    invoke<DatasetInfo[]>("cmd_list_datasets")
      .then((list) => {
        if (!cancelled) setDatasets(list);
      })
      .catch(() => {
        if (!cancelled) setDatasets([]);
      })
      .finally(() => {
        if (!cancelled) setDatasetsLoading(false);
      });
    return () => {
      cancelled = true;
    };
  }, [currentSessionId, showDatasets, stats.entity_count, stats.relation_count]);

  const handleTypeClick = (typeName: string) => {
    if (expandedType === typeName) {
      setExpandedType(null);
      setEntitiesForType([]);
      return;
    }
    setExpandedType(typeName);
    setEntitiesLoading(true);
    setEntitiesForType([]);
    invoke<string[]>("cmd_get_entities_by_type", { typeName })
      .then((ids) => setEntitiesForType(ids))
      .catch(() => setEntitiesForType([]))
      .finally(() => setEntitiesLoading(false));
  };

  async function pickFile() {
    if (isTauri()) {
      // Desktop: use Tauri native file dialog
      try {
        const { open } = await import("@tauri-apps/plugin-dialog");
        const selected = await open({
          multiple: false,
          filters: [], // allow all file types; user can pick any file
        });
        if (selected) {
          setFilePath(selected as string);
          setWebFile(null);
          setPreviewResult(null);
          setMappingRows([]);
          onLog({
            time: now(),
            message: `Selected: ${(selected as string).split(/[/\\]/).pop()}`,
            level: "info",
          });
        }
      } catch (e) {
        onLog({ time: now(), message: `File dialog error: ${e}`, level: "error" });
      }
    } else {
      // Web: trigger hidden <input type="file">
      webFileInputRef.current?.click();
    }
  }

  function handleWebFileChange(e: React.ChangeEvent<HTMLInputElement>) {
    const file = e.target.files?.[0];
    if (file) {
      setWebFile(file);
      setFilePath(file.name);
      setPreviewResult(null);
      setMappingRows([]);
      onLog({ time: now(), message: `Selected: ${file.name}`, level: "info" });
    }
  }

  async function runPreview() {
    if (!filePath) return;
    setPreviewLoading(true);
    setPreviewResult(null);
    setMappingRows([]);
    try {
      const result = await invoke<PreviewIngestResult>("cmd_preview_ingest", {
        path: filePath,
        format,
      });
      setPreviewResult(result);
      setMappingRows(result.detected_fields.map((f) => ({ ...f })));
      onLog({ time: now(), message: `Preview: ${result.format}, ${result.detected_fields.length} fields`, level: "info" });
    } catch (e) {
      onLog({ time: now(), message: `Preview failed: ${e}`, level: "error" });
    } finally {
      setPreviewLoading(false);
    }
  }

  function updateMappingRow(index: number, suggested_entity_type: string) {
    setMappingRows((prev) => {
      const next = [...prev];
      next[index] = { ...next[index], suggested_entity_type };
      return next;
    });
  }

  function removeMappingRow(index: number) {
    setMappingRows((prev) => prev.filter((_, i) => i !== index));
  }

  async function loadData() {
    if (!filePath) return;
    setLoading(true);
    setIngestProgress(null);
    onLog({ time: now(), message: "Ingesting logs...", level: "info" });

    if (isTauri()) {
      // ── Tauri desktop path (async, event-driven) ──
      try {
        const { invoke } = await import("@tauri-apps/api/core");
        const { listen } = await import("@tauri-apps/api/event");

        let sessionId = currentSessionId;
        if (!sessionId) {
          const session = await invoke<SessionInfo>("cmd_create_session", {
            name: "From file",
          });
          sessionId = session.id;
          onSessionCreated?.(session);
        }

        // Clean up any previous listeners
        if (unlistenRef.current) {
          unlistenRef.current();
        }

        // Set up progress listener (handles both legacy and streaming formats)
        const unlistenProgress = await listen<any>(
          "ingest-progress",
          (event) => {
            const p = event.payload;
            setIngestProgress({
              processed: p.processed ?? p.bytes_read ?? 0,
              total: p.total_estimate ?? p.bytes_total ?? 0,
              entities: p.entities ?? 0,
              relations: p.relations ?? 0,
              phase: p.phase,
            });
          }
        );

        // Set up completion listener
        const unlistenComplete = await listen<IngestCompleteEvent>(
          "ingest-complete",
          (event) => {
            const { result } = event.payload;
            onStatsUpdate({
              entity_count: result.total_entities,
              relation_count: result.total_relations,
            });
            onLog({
              time: now(),
              message: `+${result.new_entities} entities, +${result.new_relations} relations`,
              level: "success",
            });
            cleanup();
          }
        );

        // Set up error listener
        const unlistenError = await listen<IngestErrorEvent>(
          "ingest-error",
          (event) => {
            onLog({ time: now(), message: event.payload.error, level: "error" });
            cleanup();
          }
        );

        const cleanup = () => {
          setLoading(false);
          setIngestProgress(null);
          unlistenProgress();
          unlistenComplete();
          unlistenError();
          unlistenRef.current = null;
        };

        // Store a combined unlisten for external cleanup (e.g. unmount)
        unlistenRef.current = cleanup;

        // Fire and forget — returns immediately with job_id. Pass preview mapping when user edited it (e.g. custom node types).
        const config =
          previewResult && mappingRows.length > 0
            ? {
                mappings: mappingRows.map((row) => ({
                  raw_name: row.field_name,
                  role: row.suggested_entity_type === "Skip" ? ("Ignore" as const) : ("Node" as const),
                  entity_type: row.suggested_entity_type === "Skip" ? null : row.suggested_entity_type,
                })),
              }
            : undefined;
        await invoke<IngestJobStarted>("cmd_load_data_streaming", {
          path: filePath,
          format,
          config,
        });

        // Command returned immediately; UI stays responsive while background work runs
      } catch (e) {
        onLog({ time: now(), message: `${e}`, level: "error" });
        setLoading(false);
        setIngestProgress(null);
        if (unlistenRef.current) {
          unlistenRef.current();
          unlistenRef.current = null;
        }
      }
    } else {
      // ── Web path: upload file → create job → poll/WS for progress ──
      if (!webFile) {
        onLog({ time: now(), message: "No file selected", level: "error" });
        setLoading(false);
        return;
      }
      try {
        // 1. Upload file to Go gateway
        onLog({ time: now(), message: "Uploading file...", level: "info" });
        const upload = await uploadFile(webFile);
        onLog({ time: now(), message: `Uploaded (${(upload.size / 1024 / 1024).toFixed(1)} MB)`, level: "info" });

        // 2. We need a session_id — for web mode create one via the CLI through the gateway
        // For now pass a placeholder; the gateway/CLI will handle session creation
        const sessionId = currentSessionId || "default";

        // 3. Connect WebSocket for real-time progress
        const cleanupWS = connectProgressWS((event) => {
          if (event.type === "ingest_progress" && event.data) {
            const p = event.data.progress;
            setIngestProgress({
              processed: p.processed,
              total: p.total,
              entities: p.entities,
              relations: p.relations,
            });
          }
        });
        unlistenRef.current = cleanupWS;

        // 4. Create ingestion job
        const job = await createJob(upload.upload_id, format, sessionId);

        // 5. Poll until completion
        const finalStatus = await pollJobStatus(job.id, (status: JobStatus) => {
          if (status.progress) {
            setIngestProgress({
              processed: status.progress.processed,
              total: status.progress.total,
              entities: status.progress.entities,
              relations: status.progress.relations,
            });
          }
        });

        if (finalStatus.result) {
          onStatsUpdate({
            entity_count: finalStatus.result.total_entities,
            relation_count: finalStatus.result.total_relations,
          });
          onLog({
            time: now(),
            message: `+${finalStatus.result.new_entities} entities, +${finalStatus.result.new_relations} relations`,
            level: "success",
          });
        }
      } catch (e) {
        onLog({ time: now(), message: `${e}`, level: "error" });
      } finally {
        setLoading(false);
        setIngestProgress(null);
        if (unlistenRef.current) {
          unlistenRef.current();
          unlistenRef.current = null;
        }
      }
    }
  }

  async function loadDataSIEM() {
    const params: Record<string, unknown> = {
      source: ingestSource,
    };
    if (ingestSource === "sentinel") {
      if (!azureTenantId.trim() || !azureClientId.trim() || !azureClientSecret.trim()) {
        onLog({ time: now(), message: "Azure Tenant ID, Client ID, and Client Secret are required.", level: "error" });
        return;
      }
      if (!siemWorkspaceId.trim()) {
        onLog({ time: now(), message: "Workspace ID is required.", level: "error" });
        return;
      }
      params.workspace_id = siemWorkspaceId.trim();
      params.azure_tenant_id = azureTenantId.trim();
      params.azure_client_id = azureClientId.trim();
      params.azure_client_secret = azureClientSecret.trim();
    } else {
      if (!elasticUrl.trim()) {
        onLog({ time: now(), message: "Elasticsearch URL is required.", level: "error" });
        return;
      }
      params.url = elasticUrl.trim();
      params.index = elasticIndex.trim() || "_all";
      params.query = elasticQuery.trim() || "{}";
      params.size = elasticSize;
      if (elasticApiKey.trim()) params.elastic_api_key = elasticApiKey.trim();
      if (elasticUser.trim()) params.elastic_user = elasticUser.trim();
      if (elasticPassword.trim()) params.elastic_password = elasticPassword.trim();
    }

    setLoading(true);
    setIngestProgress(null);
    onLog({ time: now(), message: ingestSource === "sentinel" ? "Connecting to Sentinel and ingesting..." : "Connecting to Elasticsearch and ingesting...", level: "info" });
    try {
      if (isTauri()) {
        const result = await invoke<{ new_entities: number; new_relations: number; total_entities: number; total_relations: number }>("cmd_ingest_siem", { params });
        onStatsUpdate({
          entity_count: result.total_entities,
          relation_count: result.total_relations,
        });
        onLog({
          time: now(),
          message: `+${result.new_entities} entities, +${result.new_relations} relations`,
          level: "success",
        });
      } else {
        const sessionId = currentSessionId || "default";
        const queryParams: Parameters<typeof createQueryJob>[0] = { ...params, session_id: sessionId } as Parameters<typeof createQueryJob>[0];
        const cleanupWS = connectProgressWS((event) => {
          if (event.type === "ingest_progress" && event.data) {
            const p = event.data.progress;
            setIngestProgress({
              processed: p.processed,
              total: p.total,
              entities: p.entities,
              relations: p.relations,
            });
          }
        });
        unlistenRef.current = cleanupWS;
        const job = await createQueryJob(queryParams);
        const finalStatus = await pollJobStatus(job.id, (status: JobStatus) => {
          if (status.progress) {
            setIngestProgress({
              processed: status.progress.processed,
              total: status.progress.total,
              entities: status.progress.entities,
              relations: status.progress.relations,
            });
          }
        });
        if (finalStatus.result) {
          onStatsUpdate({
            entity_count: finalStatus.result.total_entities,
            relation_count: finalStatus.result.total_relations,
          });
          onLog({
            time: now(),
            message: `+${finalStatus.result.new_entities} entities, +${finalStatus.result.new_relations} relations`,
            level: "success",
          });
        }
      }
    } catch (e) {
      onLog({ time: now(), message: `${e}`, level: "error" });
    } finally {
      setLoading(false);
      setIngestProgress(null);
      if (unlistenRef.current) {
        unlistenRef.current();
        unlistenRef.current = null;
      }
    }
  }

  async function refreshStats() {
    try {
      const s = await invoke<GraphStats>("cmd_get_graph_stats");
      onStatsUpdate(s);
    } catch (e) {
      onLog({ time: now(), message: `${e}`, level: "error" });
    }
  }

  async function previewFields() {
    if (!filePath) return;
    setPreviewLoading(true);
    onLog({ time: now(), message: "Previewing fields...", level: "info" });
    try {
      const fields = await invoke<FieldInfo[]>("cmd_preview_fields", {
        path: filePath,
        sampleSize: 500,
      });
      setFieldPreview(fields);
      setShowFieldSelector(true);
      onLog({
        time: now(),
        message: `Found ${fields.length} fields in sample`,
        level: "success",
      });
    } catch (e) {
      onLog({ time: now(), message: `Preview failed: ${e}`, level: "error" });
    } finally {
      setPreviewLoading(false);
    }
  }

  async function loadDataWithConfig(mappings: FieldMapping[]) {
    if (!filePath) return;
    setConfigLoading(true);
    onLog({ time: now(), message: "Ingesting with custom field config...", level: "info" });

    try {
      let sessionId = currentSessionId;
      if (!sessionId) {
        const session = await invoke<SessionInfo>("cmd_create_session", {
          name: "From file",
        });
        sessionId = session.id;
        onSessionCreated?.(session);
      }

      const config: FieldConfig = { mappings };
      const result = await invoke<LoadResult>("cmd_load_data_with_config", {
        path: filePath,
        config,
      });

      onStatsUpdate({
        entity_count: result.total_entities,
        relation_count: result.total_relations,
      });

      onLog({
        time: now(),
        message: `+${result.new_entities} entities, +${result.new_relations} relations (custom config)`,
        level: "success",
      });

      setShowFieldSelector(false);
    } catch (e) {
      onLog({ time: now(), message: `${e}`, level: "error" });
    } finally {
      setConfigLoading(false);
    }
  }

  return (
    <div className="panel panel-left">
      {onClose && (
        <div className="panel-left-header">
          <button
            type="button"
            className="panel-left-close"
            onClick={onClose}
            title="Close left panel"
            aria-label="Close left panel"
          >
            <ChevronLeft size={16} />
          </button>
        </div>
      )}

      {/* ── Menu 1: Datasets (ingestion + datasets cards) ── */}
      <div className="panel-left-menu">
        <button
          type="button"
          className="panel-left-menu-toggle"
          onClick={() => setDatasetsMenuOpen((v) => !v)}
          aria-expanded={datasetsMenuOpen}
        >
          {datasetsMenuOpen ? <ChevronDown size={14} /> : <ChevronRight size={14} />}
          <Database size={14} />
          <span>Datasets</span>
        </button>
        {datasetsMenuOpen && (
          <div className="panel-left-menu-content">
            {/* Data Ingestion — collapsible */}
            <button
              type="button"
              className="panel-left-section-toggle"
              onClick={() => setShowDataIngestion((v) => !v)}
              aria-expanded={showDataIngestion}
            >
              {showDataIngestion ? <ChevronDown size={14} /> : <ChevronRight size={14} />}
              <span>Data Ingestion</span>
            </button>
            {showDataIngestion && (
        <div className="panel-left-section">
          <div style={{ marginBottom: 8 }}>
            <label style={{ fontSize: 11, color: "var(--text-muted)", display: "block", marginBottom: 4 }}>
              Ingest source
            </label>
            <select
              value={ingestSource}
              onChange={(e) => setIngestSource(e.target.value as "file" | "sentinel" | "elastic")}
              style={{
                width: "100%",
                padding: "6px 8px",
                background: "var(--bg-tertiary)",
                color: "var(--text-primary)",
                border: "1px solid var(--border)",
                borderRadius: 4,
                fontSize: 12,
              }}
            >
              <option value="file">From file</option>
              <option value="sentinel">Azure Sentinel</option>
              <option value="elastic">Elasticsearch</option>
            </select>
          </div>
          {ingestSource === "file" && (
          <>
          <div style={{ marginBottom: 8 }}>
            <label style={{ fontSize: 11, color: "var(--text-muted)", display: "block", marginBottom: 4 }}>
              Log Format
            </label>
            <select
              className="select"
              value={format}
              onChange={(e) => setFormat(e.target.value as "auto" | "sysmon" | "sentinel" | "generic" | "csv")}
              style={{
                width: "100%",
                padding: "6px 8px",
                background: "var(--bg-tertiary)",
                color: "var(--text-primary)",
                border: "1px solid var(--border)",
                borderRadius: 4,
                fontSize: 12,
              }}
            >
              <option value="auto">Auto-detect (Recommended)</option>
              <option value="evtx">Windows EVTX</option>
              <option value="sysmon">Sysmon (Event Log)</option>
              <option value="sentinel">Azure Sentinel</option>
              <option value="generic">Generic JSON</option>
              <option value="csv">CSV</option>
            </select>
          </div>
          <div style={{ display: "flex", flexDirection: "column", gap: 8 }}>
            <input
              ref={webFileInputRef}
              type="file"
              style={{ display: "none" }}
              accept="*/*"
              onChange={handleWebFileChange}
            />
            <button className="btn" onClick={pickFile}>
              <FolderOpen size={14} />
              {format === "evtx" ? "Select EVTX File" : format === "sysmon" ? "Select Sysmon File" : format === "sentinel" ? "Select Sentinel File" : "Select Log File"}
            </button>
            {filePath && (
              <div className="file-info">{filePath.split(/[/\\]/).pop()}</div>
            )}
            <button
              className="btn"
              onClick={runPreview}
              disabled={!filePath || previewLoading}
            >
              {previewLoading ? "Previewing…" : "Preview"}
            </button>
            {previewResult && (
              <div className="panel-left-section" style={{ marginTop: 8 }}>
                <div style={{ fontSize: 11, color: "var(--text-muted)", marginBottom: 6 }}>
                  Format: <strong>{previewResult.format}</strong>
                </div>
                <div style={{ maxHeight: 200, overflow: "auto" }}>
                  <table style={{ width: "100%", fontSize: 11, borderCollapse: "collapse" }}>
                    <thead>
                      <tr>
                        <th style={{ textAlign: "left", padding: "4px 6px", borderBottom: "1px solid var(--border)" }}>Field</th>
                        <th style={{ textAlign: "left", padding: "4px 6px", borderBottom: "1px solid var(--border)" }}>Node type</th>
                        {(format === "generic" || format === "csv") && <th style={{ width: 28 }} />}
                      </tr>
                    </thead>
                    <tbody>
                      {mappingRows.map((row, i) => (
                        <tr key={`${row.field_name}-${i}`}>
                          <td style={{ padding: "4px 6px", borderBottom: "1px solid var(--border)" }} title={row.field_name}>
                            {row.field_name.length > 18 ? `${row.field_name.slice(0, 15)}…` : row.field_name}
                          </td>
                          <td style={{ padding: "4px 6px", borderBottom: "1px solid var(--border)" }}>
                            {row.suggested_entity_type === "Custom" ? (
                              <input
                                type="text"
                                placeholder="Custom type name..."
                                defaultValue=""
                                onBlur={(e) => {
                                  const v = e.target.value.trim();
                                  if (v) updateMappingRow(i, v);
                                }}
                                onKeyDown={(e) => {
                                  if (e.key === "Enter") {
                                    e.preventDefault();
                                    const v = (e.target as HTMLInputElement).value.trim();
                                    if (v) updateMappingRow(i, v);
                                    (e.target as HTMLInputElement).blur();
                                  }
                                }}
                                style={{
                                  padding: "2px 4px",
                                  fontSize: 11,
                                  background: "var(--bg-tertiary)",
                                  color: "var(--text-primary)",
                                  border: "1px solid var(--border)",
                                  borderRadius: 4,
                                  width: "100%",
                                }}
                                aria-label="Custom node type name"
                              />
                            ) : (
                              <select
                                value={row.suggested_entity_type}
                                onChange={(e) => updateMappingRow(i, e.target.value)}
                                style={{
                                  padding: "2px 4px",
                                  fontSize: 11,
                                  background: "var(--bg-tertiary)",
                                  color: "var(--text-primary)",
                                  border: "1px solid var(--border)",
                                  borderRadius: 4,
                                  width: "100%",
                                }}
                              >
                                {(() => {
                                  const standard = ["Skip", ...ENTITY_TYPES, "Custom"];
                                  const custom = graphEntityTypes.filter((t) => !ENTITY_TYPES.includes(t) && t !== "Custom");
                                  const fromRows = mappingRows.map((r) => r.suggested_entity_type).filter((t) => t && !standard.includes(t) && !custom.includes(t));
                                  const seen = new Set<string>();
                                  const options: string[] = [];
                                  for (const t of [...standard, ...custom, ...fromRows]) {
                                    if (!seen.has(t)) {
                                      seen.add(t);
                                      options.push(t);
                                    }
                                  }
                                  return options.map((t) => (
                                    <option key={t} value={t}>{t}</option>
                                  ));
                                })()}
                              </select>
                            )}
                          </td>
                          {(format === "generic" || format === "csv") && (
                            <td style={{ padding: "4px 2px", borderBottom: "1px solid var(--border)" }}>
                              <button
                                type="button"
                                className="btn btn-sm"
                                onClick={() => removeMappingRow(i)}
                                title="Remove field"
                                aria-label="Remove"
                              >
                                <X size={12} />
                              </button>
                            </td>
                          )}
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </div>
            )}
            <button
              className="btn btn-primary"
              onClick={loadData}
              disabled={!filePath || loading}
            >
              <Upload size={14} />
              {loading ? "Loading..." : "Ingest Logs"}
            </button>
            {loading && ingestProgress && (
              <div style={{ marginTop: 6, width: "100%" }}>
                <div style={{
                  height: 6,
                  background: "var(--bg-secondary)",
                  borderRadius: 3,
                  overflow: "hidden",
                }}>
                  <div style={{
                    height: "100%",
                    width: `${ingestProgress.phase === "scoring" ? 100 : ingestProgress.total > 0 ? Math.round((ingestProgress.processed / ingestProgress.total) * 100) : 0}%`,
                    background: "var(--accent)",
                    borderRadius: 3,
                    transition: "width 0.2s",
                  }} />
                </div>
                <div style={{ fontSize: 10, color: "var(--text-muted)", marginTop: 2 }}>
                  {ingestProgress.phase === "scoring"
                    ? `Scoring — ${ingestProgress.entities.toLocaleString()} entities, ${ingestProgress.relations.toLocaleString()} relations`
                    : ingestProgress.phase
                      ? `${ingestProgress.total > 1_000_000
                          ? `${(ingestProgress.processed / 1_048_576).toFixed(0)} / ${(ingestProgress.total / 1_048_576).toFixed(0)} MB`
                          : `${ingestProgress.processed.toLocaleString()} / ${ingestProgress.total.toLocaleString()}`
                        } — ${ingestProgress.entities.toLocaleString()} entities, ${ingestProgress.relations.toLocaleString()} relations`
                      : `${ingestProgress.processed.toLocaleString()} / ${ingestProgress.total.toLocaleString()} events — ${ingestProgress.entities.toLocaleString()} entities, ${ingestProgress.relations.toLocaleString()} relations`
                  }
                </div>
              </div>
            )}
            <button
              className="btn"
              onClick={previewFields}
              disabled={!filePath || previewLoading}
            >
              <SlidersHorizontal size={14} />
              {previewLoading ? "Previewing..." : "Preview Fields"}
            </button>
          </div>
          </>
          )}
          {ingestSource === "sentinel" && (
            <div style={{ display: "flex", flexDirection: "column", gap: 8 }}>
              <label style={{ fontSize: 11, color: "var(--text-muted)" }}>Azure Tenant ID (GUID)</label>
              <input
                type="text"
                value={azureTenantId}
                onChange={(e) => setAzureTenantId(e.target.value)}
                placeholder="AZURE_TENANT_ID"
                style={{ padding: "6px 8px", fontSize: 12, background: "var(--bg-tertiary)", color: "var(--text-primary)", border: "1px solid var(--border)", borderRadius: 4 }}
              />
              <label style={{ fontSize: 11, color: "var(--text-muted)" }}>Azure Client ID (App registration)</label>
              <input
                type="text"
                value={azureClientId}
                onChange={(e) => setAzureClientId(e.target.value)}
                placeholder="AZURE_CLIENT_ID"
                style={{ padding: "6px 8px", fontSize: 12, background: "var(--bg-tertiary)", color: "var(--text-primary)", border: "1px solid var(--border)", borderRadius: 4 }}
              />
              <label style={{ fontSize: 11, color: "var(--text-muted)" }}>Azure Client Secret</label>
              <input
                type="password"
                value={azureClientSecret}
                onChange={(e) => setAzureClientSecret(e.target.value)}
                placeholder="AZURE_CLIENT_SECRET"
                style={{ padding: "6px 8px", fontSize: 12, background: "var(--bg-tertiary)", color: "var(--text-primary)", border: "1px solid var(--border)", borderRadius: 4 }}
              />
              <label style={{ fontSize: 11, color: "var(--text-muted)" }}>Workspace ID (Log Analytics)</label>
              <input
                type="text"
                value={siemWorkspaceId}
                onChange={(e) => setSiemWorkspaceId(e.target.value)}
                placeholder="Log Analytics workspace GUID"
                style={{ padding: "6px 8px", fontSize: 12, background: "var(--bg-tertiary)", color: "var(--text-primary)", border: "1px solid var(--border)", borderRadius: 4 }}
              />
              <button className="btn btn-primary" onClick={loadDataSIEM} disabled={loading}>
                <Upload size={14} />
                {loading ? "Connecting…" : "Connect and ingest"}
              </button>
            </div>
          )}
          {ingestSource === "elastic" && (
          <div style={{ display: "flex", flexDirection: "column", gap: 8 }}>
            <label style={{ fontSize: 11, color: "var(--text-muted)" }}>Cluster URL</label>
            <input
              type="text"
              value={elasticUrl}
              onChange={(e) => setElasticUrl(e.target.value)}
              placeholder="https://localhost:9200"
              style={{ padding: "6px 8px", fontSize: 12, background: "var(--bg-tertiary)", color: "var(--text-primary)", border: "1px solid var(--border)", borderRadius: 4 }}
            />
            <label style={{ fontSize: 11, color: "var(--text-muted)" }}>Index</label>
            <input
              type="text"
              value={elasticIndex}
              onChange={(e) => setElasticIndex(e.target.value)}
              placeholder="_all or index name"
              style={{ padding: "6px 8px", fontSize: 12, background: "var(--bg-tertiary)", color: "var(--text-primary)", border: "1px solid var(--border)", borderRadius: 4 }}
            />
            <label style={{ fontSize: 11, color: "var(--text-muted)" }}>API Key (optional; else use ELASTIC_API_KEY env)</label>
            <input
              type="password"
              value={elasticApiKey}
              onChange={(e) => setElasticApiKey(e.target.value)}
              placeholder="ApiKey base64 or leave empty for env"
              style={{ padding: "6px 8px", fontSize: 12, background: "var(--bg-tertiary)", color: "var(--text-primary)", border: "1px solid var(--border)", borderRadius: 4 }}
            />
            <label style={{ fontSize: 11, color: "var(--text-muted)" }}>User (optional; else use ELASTIC_USER env)</label>
            <input
              type="text"
              value={elasticUser}
              onChange={(e) => setElasticUser(e.target.value)}
              placeholder="ELASTIC_USER"
              style={{ padding: "6px 8px", fontSize: 12, background: "var(--bg-tertiary)", color: "var(--text-primary)", border: "1px solid var(--border)", borderRadius: 4 }}
            />
            <label style={{ fontSize: 11, color: "var(--text-muted)" }}>Password (optional; else use ELASTIC_PASSWORD env)</label>
            <input
              type="password"
              value={elasticPassword}
              onChange={(e) => setElasticPassword(e.target.value)}
              placeholder="ELASTIC_PASSWORD"
              style={{ padding: "6px 8px", fontSize: 12, background: "var(--bg-tertiary)", color: "var(--text-primary)", border: "1px solid var(--border)", borderRadius: 4 }}
            />
            <label style={{ fontSize: 11, color: "var(--text-muted)" }}>Query (JSON)</label>
            <textarea
              value={elasticQuery}
              onChange={(e) => setElasticQuery(e.target.value)}
              placeholder='{"match_all": {}}'
              rows={2}
              style={{ padding: "6px 8px", fontSize: 12, background: "var(--bg-tertiary)", color: "var(--text-primary)", border: "1px solid var(--border)", borderRadius: 4, resize: "vertical" }}
            />
            <label style={{ fontSize: 11, color: "var(--text-muted)" }}>Size</label>
            <input
              type="number"
              value={elasticSize}
              onChange={(e) => setElasticSize(parseInt(e.target.value, 10) || 1000)}
              min={1}
              max={10000}
              style={{ padding: "6px 8px", fontSize: 12, background: "var(--bg-tertiary)", color: "var(--text-primary)", border: "1px solid var(--border)", borderRadius: 4 }}
            />
            <button className="btn btn-primary" onClick={loadDataSIEM} disabled={loading}>
              <Upload size={14} />
              {loading ? "Running query..." : "Run query and ingest"}
            </button>
          </div>
          )}
          {(ingestSource === "sentinel" || ingestSource === "elastic") && loading && ingestProgress && (
            <div style={{ marginTop: 6, width: "100%" }}>
              <div style={{ height: 6, background: "var(--bg-secondary)", borderRadius: 3, overflow: "hidden" }}>
                <div style={{ height: "100%", width: `${ingestProgress.total > 0 ? Math.round((ingestProgress.processed / ingestProgress.total) * 100) : 0}%`, background: "var(--accent)", borderRadius: 3 }} />
              </div>
              <div style={{ fontSize: 10, color: "var(--text-muted)", marginTop: 2 }}>
                {ingestProgress.processed.toLocaleString()} / {ingestProgress.total.toLocaleString()} — {ingestProgress.entities.toLocaleString()} entities, {ingestProgress.relations.toLocaleString()} relations
              </div>
            </div>
          )}
          {showFieldSelector && fieldPreview && (
            <div style={{ marginTop: 8 }}>
              <FieldSelector
                fields={fieldPreview}
                loading={configLoading}
                onIngest={loadDataWithConfig}
              />
            </div>
          )}
        </div>
            )}
            <hr className="section-divider" />
            {/* Datasets cards */}
            <button
              type="button"
              className="panel-left-section-toggle"
              onClick={() => setShowDatasets((v) => !v)}
              aria-expanded={showDatasets}
            >
              {showDatasets ? <ChevronDown size={14} /> : <ChevronRight size={14} />}
              <Layers size={14} />
              <span>Datasets</span>
            </button>
            {showDatasets && (
        <div className="panel-left-section">
          {datasetsLoading ? (
            <div className="types-available-loading">Loading…</div>
          ) : datasets.length === 0 ? (
            <div className="types-available-empty">No datasets yet. Ingest a file to see them here.</div>
          ) : (
            <ul style={{ listStyle: "none", padding: 0, margin: 0 }}>
              {datasets.map((d) => (
                <li
                  key={d.id}
                  style={{
                    padding: "6px 8px",
                    marginBottom: 6,
                    background: "var(--bg-tertiary)",
                    borderRadius: 4,
                    fontSize: 11,
                  }}
                >
                  <div style={{ fontWeight: 600, marginBottom: 2 }}>{d.name}</div>
                  <div style={{ color: "var(--text-muted)", marginBottom: 6 }}>
                    {d.entity_count} entities, {d.relation_count} relations
                  </div>
                  <div style={{ display: "flex", gap: 6, flexWrap: "wrap" }}>
                    <button
                      type="button"
                      className="btn btn-sm"
                      onClick={() => {
                        setRenameModal({ datasetId: d.id, datasetName: d.name });
                        setRenameFromType("");
                        setRenameToType("");
                        invoke<string[]>("cmd_dataset_entity_types", { datasetId: d.id })
                          .then((types) => setDatasetTypes(types))
                          .catch(() => setDatasetTypes([]));
                      }}
                      title="Rename entity type in this dataset"
                    >
                      <Edit3 size={12} />
                      Rename types
                    </button>
                    <button
                      type="button"
                      className="btn btn-sm"
                      onClick={async () => {
                        if (!confirm(`Remove dataset "${d.name}"? This will delete ${d.entity_count} entities and ${d.relation_count} relations.`)) return;
                        try {
                          await invoke<[number, number]>("cmd_remove_dataset", { datasetId: d.id });
                          const s = await invoke<GraphStats>("cmd_get_graph_stats");
                          onStatsUpdate(s);
                          const list = await invoke<DatasetInfo[]>("cmd_list_datasets");
                          setDatasets(list);
                          onLog({ time: now(), message: `Removed dataset: ${d.name}`, level: "success" });
                        } catch (e) {
                          onLog({ time: now(), message: `Remove failed: ${e}`, level: "error" });
                        }
                      }}
                      title="Remove this dataset from the graph"
                    >
                      <Trash2 size={12} />
                      Remove
                    </button>
                  </div>
                </li>
              ))}
            </ul>
          )}
          {renameModal && (
            <div
              style={{
                position: "fixed",
                inset: 0,
                background: "rgba(0,0,0,0.4)",
                display: "flex",
                alignItems: "center",
                justifyContent: "center",
                zIndex: 1000,
              }}
              onClick={() => setRenameModal(null)}
            >
              <div
                style={{
                  background: "var(--bg-secondary)",
                  padding: 16,
                  borderRadius: 8,
                  minWidth: 280,
                  border: "1px solid var(--border)",
                }}
                onClick={(e) => e.stopPropagation()}
              >
                <div style={{ marginBottom: 12, fontWeight: 600 }}>Rename type in “{renameModal.datasetName}”</div>
                <div style={{ marginBottom: 8 }}>
                  <label style={{ fontSize: 11, color: "var(--text-muted)", display: "block", marginBottom: 4 }}>From type</label>
                  <select
                    value={renameFromType}
                    onChange={(e) => setRenameFromType(e.target.value)}
                    style={{
                      width: "100%",
                      padding: "6px 8px",
                      background: "var(--bg-tertiary)",
                      color: "var(--text-primary)",
                      border: "1px solid var(--border)",
                      borderRadius: 4,
                      fontSize: 12,
                    }}
                  >
                    <option value="">Select…</option>
                    {datasetTypes.map((t) => (
                      <option key={t} value={t}>{t}</option>
                    ))}
                  </select>
                </div>
                <div style={{ marginBottom: 12 }}>
                  <label style={{ fontSize: 11, color: "var(--text-muted)", display: "block", marginBottom: 4 }}>To type</label>
                  <select
                    value={renameToType}
                    onChange={(e) => setRenameToType(e.target.value)}
                    style={{
                      width: "100%",
                      padding: "6px 8px",
                      background: "var(--bg-tertiary)",
                      color: "var(--text-primary)",
                      border: "1px solid var(--border)",
                      borderRadius: 4,
                      fontSize: 12,
                    }}
                  >
                    <option value="">Select…</option>
                    {ENTITY_TYPES.map((t) => (
                      <option key={t} value={t}>{t}</option>
                    ))}
                  </select>
                </div>
                <div style={{ display: "flex", justifyContent: "flex-end", gap: 8 }}>
                  <button type="button" className="btn" onClick={() => setRenameModal(null)}>Cancel</button>
                  <button
                    type="button"
                    className="btn btn-primary"
                    disabled={!renameFromType || !renameToType || renameFromType === renameToType}
                    onClick={async () => {
                      if (!renameModal || !renameFromType || !renameToType) return;
                      try {
                        await invoke<number>("cmd_rename_type_in_dataset", {
                          datasetId: renameModal.datasetId,
                          fromType: renameFromType,
                          toType: renameToType,
                        });
                        setRenameModal(null);
                        invoke<GraphStats>("cmd_get_graph_stats").then(onStatsUpdate).catch(() => {});
                        setDatasets((prev) => prev.map((d) => (d.id === renameModal.datasetId ? { ...d } : d)));
                        invoke<DatasetInfo[]>("cmd_list_datasets").then(setDatasets).catch(() => {});
                        onLog({ time: now(), message: `Renamed ${renameFromType} → ${renameToType} in dataset`, level: "success" });
                      } catch (e) {
                        onLog({ time: now(), message: `Rename failed: ${e}`, level: "error" });
                      }
                    }}
                  >
                    Apply
                  </button>
                </div>
              </div>
            </div>
          )}
        </div>
            )}
          </div>
        )}
      </div>

      {/* ── Menu 2: Activity log ── */}
      <div className="panel-left-menu">
        <button
          type="button"
          className="panel-left-menu-toggle"
          onClick={() => setActivityLogMenuOpen((v) => !v)}
          aria-expanded={activityLogMenuOpen}
        >
          {activityLogMenuOpen ? <ChevronDown size={14} /> : <ChevronRight size={14} />}
          <Activity size={14} />
          <span>Activity Log</span>
        </button>
        {activityLogMenuOpen && (
          <div className="panel-left-menu-content">
            <div className="panel-left-section">
              <div className="status-log">
                {log.length === 0 && (
                  <div className="entry" style={{ color: "var(--text-muted)" }}>
                    No activity yet
                  </div>
                )}
                {log.map((entry, i) => (
                  <div key={i} className={`entry ${entry.level}`}>
                    <span className="time">{entry.time}</span>
                    {entry.message}
                  </div>
                ))}
              </div>
            </div>
          </div>
        )}
      </div>

      {/* ── Menu 3: Graph metrics (scoring + types) ── */}
      <div className="panel-left-menu">
        <button
          type="button"
          className="panel-left-menu-toggle"
          onClick={() => setGraphMetricsMenuOpen((v) => !v)}
          aria-expanded={graphMetricsMenuOpen}
        >
          {graphMetricsMenuOpen ? <ChevronDown size={14} /> : <ChevronRight size={14} />}
          <BarChart3 size={14} />
          <span>Graph Metrics</span>
        </button>
        {graphMetricsMenuOpen && (
          <div className="panel-left-menu-content">
            {/* Stats + Scoring + Types */}
            <button
              type="button"
              className="panel-left-section-toggle"
              onClick={() => setShowGraphMetrics((v) => !v)}
              aria-expanded={showGraphMetrics}
            >
              {showGraphMetrics ? <ChevronDown size={14} /> : <ChevronRight size={14} />}
              <span>Stats</span>
            </button>
            {showGraphMetrics && (
              <div className="panel-left-section">
                <div style={{ display: "flex", justifyContent: "flex-end", marginBottom: 6 }}>
                  <button className="btn btn-sm" onClick={refreshStats} title="Refresh stats">
                    <Activity size={12} />
                  </button>
                </div>
                <div className="stats-grid">
                  <div className="stat-card">
                    <div className="value">{stats.entity_count.toLocaleString()}</div>
                    <div className="label">Entities</div>
                  </div>
                  <div className="stat-card">
                    <div className="value">{stats.relation_count.toLocaleString()}</div>
                    <div className="label">Relations</div>
                  </div>
                </div>
              </div>
            )}

            <hr className="section-divider" />

            {/* Scoring — collapsible */}
            <button
              type="button"
              className="panel-left-section-toggle"
              onClick={() => setShowScoring((v) => !v)}
              aria-expanded={showScoring}
            >
              {showScoring ? <ChevronDown size={14} /> : <ChevronRight size={14} />}
              <SlidersHorizontal size={14} />
              <span>Scoring</span>
            </button>
            {showScoring && (
              <div className="panel-left-section">
                <div style={{ fontSize: 11, color: "var(--text-muted)", marginBottom: 8 }}>
                  Adjust scoring weights and recalculate composite scores.
                </div>
                {[
                  { label: "Degree", value: degreeWeight, set: setDegreeWeight },
                  { label: "PageRank", value: pagerankWeight, set: setPagerankWeight },
                  { label: "Betweenness", value: betweennessWeight, set: setBetweennessWeight },
                ].map(({ label, value, set }) => (
                  <div key={label} style={{ marginBottom: 6 }}>
                    <div style={{ display: "flex", justifyContent: "space-between", fontSize: 11, marginBottom: 2 }}>
                      <span>{label}</span>
                      <span style={{ color: "var(--text-muted)" }}>{value}</span>
                    </div>
                    <input
                      type="range"
                      min={0}
                      max={100}
                      value={value}
                      onChange={(e) => set(Number(e.target.value))}
                      style={{ width: "100%" }}
                    />
                  </div>
                ))}
                <div style={{ marginBottom: 6 }}>
                  <div style={{ display: "flex", justifyContent: "space-between", fontSize: 11, marginBottom: 2 }}>
                    <span>PageRank λ (decay)</span>
                    <span style={{ color: "var(--text-muted)" }}>{pagerankLambda.toFixed(4)}</span>
                  </div>
                  <input
                    type="range"
                    min={0}
                    max={0.01}
                    step={0.0001}
                    value={pagerankLambda}
                    onChange={(e) => setPagerankLambda(Number(e.target.value))}
                    style={{ width: "100%" }}
                  />
                </div>
                <button
                  className="btn btn-primary"
                  disabled={scoringLoading || !currentSessionId}
                  onClick={async () => {
                    setScoringLoading(true);
                    try {
                      await invoke("cmd_compute_pagerank", { lambda: pagerankLambda });
                      await invoke("cmd_compute_composite_scores", {
                        degreeWeight: degreeWeight / 100,
                        pagerankWeight: pagerankWeight / 100,
                        betweennessWeight: betweennessWeight / 100,
                      });
                      onLog({ time: now(), message: "Scores recalculated", level: "success" });
                    } catch (e) {
                      onLog({ time: now(), message: `Scoring failed: ${e}`, level: "error" });
                    } finally {
                      setScoringLoading(false);
                    }
                  }}
                >
                  <SlidersHorizontal size={14} />
                  {scoringLoading ? "Recalculating..." : "Recalculate"}
                </button>

                {/* Temporal Compaction */}
                <div style={{ marginTop: 12, paddingTop: 8, borderTop: "1px solid var(--border)" }}>
                  <div style={{ fontSize: 11, color: "var(--text-muted)", marginBottom: 6 }}>
                    Temporal Compaction — merge duplicate edges before a cutoff time.
                  </div>
                  <input
                    type="datetime-local"
                    value={compactDate}
                    onChange={(e) => setCompactDate(e.target.value)}
                    style={{
                      width: "100%",
                      padding: "6px 8px",
                      background: "var(--bg-tertiary)",
                      color: "var(--text-primary)",
                      border: "1px solid var(--border)",
                      borderRadius: 4,
                      fontSize: 12,
                      marginBottom: 6,
                    }}
                  />
                  <button
                    className="btn"
                    disabled={compactLoading || !compactDate || !currentSessionId}
                    onClick={async () => {
                      setCompactLoading(true);
                      try {
                        const cutoff = Math.floor(new Date(compactDate).getTime() / 1000);
                        const result = await invoke<CompactionStats>("cmd_compact", { cutoffTimestamp: cutoff });
                        onLog({
                          time: now(),
                          message: `Compacted: ${result.edges_removed} edges removed (${result.groups_compacted} groups)`,
                          level: "success",
                        });
                        refreshStats();
                      } catch (e) {
                        onLog({ time: now(), message: `Compaction failed: ${e}`, level: "error" });
                      } finally {
                        setCompactLoading(false);
                      }
                    }}
                  >
                    {compactLoading ? "Compacting..." : "Compact"}
                  </button>
                </div>
              </div>
            )}

            <hr className="section-divider" />

            {/* Types available (legend) — collapsible */}
            <button
              type="button"
              className="panel-left-section-toggle"
              onClick={() => setShowTypesAvailable((v) => !v)}
              aria-expanded={showTypesAvailable}
            >
              {showTypesAvailable ? <ChevronDown size={14} /> : <ChevronRight size={14} />}
              <Palette size={14} />
              <span>Types Available</span>
            </button>
            {showTypesAvailable && (
              <div className="panel-left-section">
                {typeCountsLoading ? (
                  <div className="types-available-loading">Loading…</div>
                ) : typeCounts.length === 0 ? (
                  <div className="types-available-empty">No types in graph yet.</div>
                ) : (
                  <div className="legend">
                    {typeCounts.map(({ entity_type: typeName, count }) => (
                      <div key={typeName}>
                        <div className="legend-item-row">
                          <button
                            type="button"
                            className="legend-item legend-item-clickable"
                            onClick={() => handleTypeClick(typeName)}
                            title={`Expand to list ${count} ${typeName} elements`}
                          >
                            <span
                              className="legend-dot"
                              style={{
                                background: ENTITY_COLORS[typeName as EntityType] ?? "var(--text-muted)",
                              }}
                            />
                            <span className="legend-label">{typeName}</span>
                            <span className="legend-count">({count})</span>
                          </button>
                          {expandedType === typeName && entitiesForType.length > 0 && (
                            <button
                              type="button"
                              className="legend-goto-btn"
                              onClick={(e) => {
                                e.stopPropagation();
                                onShowTypeOnMap?.(entitiesForType);
                              }}
                              title="Show this type on map"
                              aria-label="Show on map"
                            >
                              <ArrowRight size={14} />
                            </button>
                          )}
                        </div>
                        {expandedType === typeName && (
                          <div className="legend-entities-list">
                            {entitiesLoading ? (
                              <div className="legend-entities-loading">Loading…</div>
                            ) : (
                              <ul className="legend-entities-ul">
                                {entitiesForType.map((id) => (
                                  <li key={id} className="legend-entity-row">
                                    <span
                                      className="legend-entity-id"
                                      title={id}
                                    >
                                      {id.length > 36 ? `${id.slice(0, 32)}…` : id}
                                    </span>
                                    <button
                                      type="button"
                                      className="legend-goto-btn"
                                      onClick={() => onShowNodeOnMap?.(id)}
                                      title={`Show on map: ${id}`}
                                      aria-label="Show on map"
                                    >
                                      <ArrowRight size={14} />
                                    </button>
                                  </li>
                                ))}
                              </ul>
                            )}
                          </div>
                        )}
                      </div>
                    ))}
                  </div>
                )}
              </div>
            )}
          </div>
        )}
      </div>
    </div>
  );
}
