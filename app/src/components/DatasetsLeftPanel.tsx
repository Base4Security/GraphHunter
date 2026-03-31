import { useState, useEffect, useRef } from "react";
import { invoke, errorMessage } from "../lib/tauri";
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
  Database,
  ChevronDown,
  ChevronRight,
  Layers,
  X,
} from "lucide-react";
import type {
  GraphStats,
  LoadResult,
  LogEntry,
  SessionInfo,
  PreviewIngestResult,
  DetectedField,
  DatasetInfo,
  FieldInfo,
  FieldMapping,
  FieldConfig,
  IngestJobStarted,
  IngestCompleteEvent,
  IngestErrorEvent,
  SentinelConnectedEvent,
  SentinelDataEvent,
  SentinelErrorEvent,
  ConnectorStatusResponse,
  SentinelEnvStatus,
} from "../types";
import FieldSelector from "./FieldSelector";
import { FileUploadSection, SentinelConnectForm, ElasticConnectForm } from "./ingest";
import { DatasetList } from "./datasets";

interface DatasetsLeftPanelProps {
  currentSessionId: string | null;
  onSessionCreated?: (session: SessionInfo) => void;
  stats: GraphStats;
  onStatsUpdate: (stats: GraphStats) => void;
  onLog: (entry: LogEntry) => void;
  onClose: () => void;
  onShowTypeOnMap?: (nodeIds: string[]) => void;
  onShowNodeOnMap?: (nodeId: string) => void;
}

function now(): string {
  return new Date().toLocaleTimeString("en-US", { hour12: false });
}

export default function DatasetsLeftPanel({
  currentSessionId,
  onSessionCreated,
  stats,
  onStatsUpdate,
  onLog,
  onClose,
  onShowTypeOnMap: _onShowTypeOnMap,
  onShowNodeOnMap: _onShowNodeOnMap,
}: DatasetsLeftPanelProps) {
  const [filePaths, setFilePaths] = useState<string[]>([]);
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

  const [azureSubscriptionId, setAzureSubscriptionId] = useState("");
  const [azureResourceGroup, setAzureResourceGroup] = useState("");
  const [azureWorkspaceName, setAzureWorkspaceName] = useState("");

  // Sentinel real-time state
  const [sentinelStreaming, setSentinelStreaming] = useState(false);
  const [, setSentinelConnectorId] = useState<string | null>(null);
  const [sentinelStatus, setSentinelStatus] = useState<string>("disconnected");
  const [sentinelLiveStats, setSentinelLiveStats] = useState<{ entities: number; relations: number }>({ entities: 0, relations: 0 });
  const [sentinelPollInterval, setSentinelPollInterval] = useState(30);
  const sentinelUnlistenRef = useRef<(() => void) | null>(null);
  const statsRef = useRef(stats);
  statsRef.current = stats;

  const [ingestProgress, setIngestProgress] = useState<{
    processed: number;
    total: number;
    entities: number;
    relations: number;
  } | null>(null);
  const unlistenRef = useRef<(() => void) | null>(null);

  const [webFiles, setWebFiles] = useState<File[]>([]);

  const [previewResult, setPreviewResult] = useState<PreviewIngestResult | null>(null);
  const [previewLoading, setPreviewLoading] = useState(false);
  const [mappingRows, setMappingRows] = useState<DetectedField[]>([]);
  const [graphEntityTypes, setGraphEntityTypes] = useState<string[]>([]);

  const [showDataIngestion, setShowDataIngestion] = useState(false);
  const [showDatasets, setShowDatasets] = useState(true);
  const [datasets, setDatasets] = useState<DatasetInfo[]>([]);
  const [datasetsLoading, setDatasetsLoading] = useState(false);

  const [fieldPreview, setFieldPreview] = useState<FieldInfo[] | null>(null);
  const [showFieldSelector, setShowFieldSelector] = useState(false);
  const [configLoading, setConfigLoading] = useState(false);

  const SIEM_CONFIG_KEY = "graph_hunter_siem_config";

  function getSiemConfigKey(sessionId: string | null): string | null {
    return sessionId ? `${SIEM_CONFIG_KEY}_${sessionId}` : null;
  }

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

  useEffect(() => {
    const key = getSiemConfigKey(currentSessionId);
    if (!key) return;
    try {
      const raw = localStorage.getItem(key);
      if (raw) {
        const c = JSON.parse(raw) as {
          ingestSource?: "file" | "sentinel" | "elastic";
          azureTenantId?: string;
          azureClientId?: string;
          azureClientSecret?: string;
          siemWorkspaceId?: string;
          elasticUrl?: string;
          elasticIndex?: string;
          elasticQuery?: string;
          elasticSize?: number;
          elasticApiKey?: string;
          elasticUser?: string;
          elasticPassword?: string;
        };
        if (c.ingestSource) setIngestSource(c.ingestSource);
        if (c.azureTenantId != null) setAzureTenantId(c.azureTenantId);
        if (c.azureClientId != null) setAzureClientId(c.azureClientId);
        if (c.azureClientSecret != null) setAzureClientSecret(c.azureClientSecret);
        if (c.siemWorkspaceId != null) setSiemWorkspaceId(c.siemWorkspaceId);
        if (c.elasticUrl != null) setElasticUrl(c.elasticUrl);
        if (c.elasticIndex != null) setElasticIndex(c.elasticIndex);
        if (c.elasticQuery != null) setElasticQuery(c.elasticQuery);
        if (c.elasticSize != null) setElasticSize(c.elasticSize);
        if (c.elasticApiKey != null) setElasticApiKey(c.elasticApiKey);
        if (c.elasticUser != null) setElasticUser(c.elasticUser);
        if (c.elasticPassword != null) setElasticPassword(c.elasticPassword);
      }
    } catch {
      // ignore invalid stored config
    }
  }, [currentSessionId]);

  useEffect(() => {
    const key = getSiemConfigKey(currentSessionId);
    if (!key) return;
    const config = {
      ingestSource,
      azureTenantId,
      azureClientId,
      azureClientSecret,
      siemWorkspaceId,
      elasticUrl,
      elasticIndex,
      elasticQuery,
      elasticSize,
      elasticApiKey,
      elasticUser,
      elasticPassword,
    };
    try {
      localStorage.setItem(key, JSON.stringify(config));
    } catch {
      // ignore quota errors
    }
  }, [
    currentSessionId,
    ingestSource,
    azureTenantId,
    azureClientId,
    azureClientSecret,
    siemWorkspaceId,
    elasticUrl,
    elasticIndex,
    elasticQuery,
    elasticSize,
    elasticApiKey,
    elasticUser,
    elasticPassword,
  ]);

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

  // Auto-load Sentinel credentials from .env on mount
  useEffect(() => {
    if (!isTauri()) return;
    invoke<SentinelEnvStatus>("cmd_sentinel_check_env").then((env) => {
      if (env.azure_workspace_name) setAzureWorkspaceName(env.azure_workspace_name);
      // Fields are loaded from .env server-side; show placeholder hints
    }).catch(() => {});
    // Check if connector is already running
    invoke<ConnectorStatusResponse>("cmd_sentinel_status").then((st) => {
      if (st.connected) {
        setSentinelStreaming(true);
        setSentinelConnectorId(st.connector_id);
        setSentinelStatus(st.status?.state ?? "connected");
      }
    }).catch(() => {});
  }, []);

  // Sentinel real-time event listeners
  useEffect(() => {
    if (!sentinelStreaming || !isTauri()) return;
    let unData: (() => void) | null = null;
    let unError: (() => void) | null = null;
    let unDisconnected: (() => void) | null = null;

    (async () => {
      const { listen } = await import("@tauri-apps/api/event");
      unData = await listen<SentinelDataEvent>("sentinel-data", (event) => {
        const d = event.payload;
        setSentinelLiveStats((prev) => ({
          entities: prev.entities + d.new_entities,
          relations: prev.relations + d.new_relations,
        }));
        setSentinelStatus("connected");
        onStatsUpdate({
          entity_count: statsRef.current.entity_count + d.new_entities,
          relation_count: statsRef.current.relation_count + d.new_relations,
        });
      });

      unError = await listen<SentinelErrorEvent>("sentinel-error", (event) => {
        const e = event.payload;
        setSentinelStatus("error");
        onLog({ time: now(), message: `Sentinel: ${e.error}`, level: "error" });
        if (!e.will_retry) {
          setSentinelStreaming(false);
          setSentinelConnectorId(null);
        }
      });

      unDisconnected = await listen("sentinel-disconnected", () => {
        setSentinelStreaming(false);
        setSentinelConnectorId(null);
        setSentinelStatus("disconnected");
        setSentinelLiveStats({ entities: 0, relations: 0 });
        onLog({ time: now(), message: "Sentinel: Disconnected", level: "info" });
      });

      sentinelUnlistenRef.current = () => {
        unData?.();
        unError?.();
        unDisconnected?.();
      };
    })();

    return () => {
      sentinelUnlistenRef.current?.();
      sentinelUnlistenRef.current = null;
    };
  }, [sentinelStreaming]);

  async function startSentinelStream() {
    try {
      setLoading(true);
      const result = await invoke<SentinelConnectedEvent>("cmd_sentinel_connect", {
        params: {
          workspace_id: siemWorkspaceId.trim(),
          azure_tenant_id: azureTenantId.trim(),
          azure_client_id: azureClientId.trim(),
          azure_client_secret: azureClientSecret.trim(),
          poll_interval_secs: sentinelPollInterval,
          tables: [],
          batch_size: 0,
        },
      });
      setSentinelStreaming(true);
      setSentinelConnectorId(result.connector_id);
      setSentinelStatus("connected");
      setSentinelLiveStats({ entities: 0, relations: 0 });
      onLog({
        time: now(),
        message: `Sentinel: Connected (polling every ${result.poll_interval_secs}s, ${result.tables.length} tables)`,
        level: "info",
      });
    } catch (e) {
      onLog({ time: now(), message: `Sentinel connect failed: ${errorMessage(e)}`, level: "error" });
    } finally {
      setLoading(false);
    }
  }

  async function stopSentinelStream() {
    try {
      setLoading(true);
      await invoke("cmd_sentinel_disconnect");
      setSentinelStreaming(false);
      setSentinelConnectorId(null);
      setSentinelStatus("disconnected");
      onLog({ time: now(), message: "Sentinel: Disconnected, full scoring completed", level: "info" });
    } catch (e) {
      onLog({ time: now(), message: `Sentinel disconnect failed: ${errorMessage(e)}`, level: "error" });
    } finally {
      setLoading(false);
    }
  }

  async function pickFile() {
    if (isTauri()) {
      try {
        const { open } = await import("@tauri-apps/plugin-dialog");
        const selected = await open({
          multiple: true,
          filters: [
            { name: "EVTX Files", extensions: ["evtx"] },
            { name: "Log Files", extensions: ["json", "ndjson", "csv", "log", "evtx"] },
            { name: "All Files", extensions: ["*"] },
          ],
        });
        if (selected) {
          const paths = Array.isArray(selected) ? selected : [selected];
          setFilePaths(paths);
          setWebFiles([]);
          setPreviewResult(null);
          setMappingRows([]);
          onLog({
            time: now(),
            message: `Selected ${paths.length} file(s): ${paths.map((p) => p.split(/[/\\]/).pop()).join(", ")}`,
            level: "info",
          });
        }
      } catch (e) {
        onLog({ time: now(), message: `File dialog error: ${errorMessage(e)}`, level: "error" });
      }
    }
  }

  async function runPreview() {
    if (filePaths.length === 0) return;
    setPreviewLoading(true);
    setPreviewResult(null);
    setMappingRows([]);
    try {
      const result = await invoke<PreviewIngestResult>("cmd_preview_ingest", {
        path: filePaths[0],
        format,
      });
      setPreviewResult(result);
      setMappingRows(result.detected_fields.map((f) => ({ ...f })));
      onLog({
        time: now(),
        message: `Preview: ${result.format}, ${result.detected_fields.length} fields`,
        level: "info",
      });
    } catch (e) {
      onLog({ time: now(), message: `Preview failed: ${errorMessage(e)}`, level: "error" });
    } finally {
      setPreviewLoading(false);
    }
  }

  async function loadData() {
    if (filePaths.length === 0) return;
    setLoading(true);
    setIngestProgress(null);
    onLog({ time: now(), message: `Ingesting ${filePaths.length} file(s)...`, level: "info" });

    if (isTauri()) {
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

        if (unlistenRef.current) {
          unlistenRef.current();
        }

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

        for (let i = 0; i < filePaths.length; i++) {
          const currentPath = filePaths[i];
          const fileName = currentPath.split(/[/\\]/).pop() || currentPath;
          if (filePaths.length > 1) {
            onLog({ time: now(), message: `[${i + 1}/${filePaths.length}] Ingesting: ${fileName}`, level: "info" });
          }

          await new Promise<void>((resolve) => {
            let unlistenProgress: (() => void) | null = null;
            let unlistenComplete: (() => void) | null = null;
            let unlistenError: (() => void) | null = null;

            const fileCleanup = () => {
              unlistenProgress?.();
              unlistenComplete?.();
              unlistenError?.();
            };

            (async () => {
              unlistenProgress = await listen<any>("ingest-progress", (event) => {
                const p = event.payload;
                setIngestProgress({
                  processed: Number(p.processed ?? p.bytes_read ?? 0),
                  total: Number(p.total_estimate ?? p.bytes_total ?? 0),
                  entities: Number(p.entities ?? 0),
                  relations: Number(p.relations ?? 0),
                });
              });

              unlistenComplete = await listen<IngestCompleteEvent>("ingest-complete", (event) => {
                const { result } = event.payload;
                onStatsUpdate({
                  entity_count: result.total_entities,
                  relation_count: result.total_relations,
                });
                onLog({
                  time: now(),
                  message: `${fileName}: +${result.new_entities} entities, +${result.new_relations} relations`,
                  level: "success",
                });
                fileCleanup();
                resolve();
              });

              unlistenError = await listen<IngestErrorEvent>("ingest-error", (event) => {
                onLog({ time: now(), message: `${fileName}: ${event.payload.error}`, level: "error" });
                fileCleanup();
                resolve();
              });

              unlistenRef.current = () => {
                fileCleanup();
                resolve();
              };

              await invoke<IngestJobStarted>("cmd_load_data_streaming", {
                path: currentPath,
                format,
                config,
                dateFrom: null,
                dateTo: null,
              });
            })().catch(() => {
              fileCleanup();
              resolve();
            });
          });
        }

        if (filePaths.length > 1) {
          onLog({ time: now(), message: `All ${filePaths.length} files ingested.`, level: "success" });
        }
      } catch (e) {
        onLog({ time: now(), message: errorMessage(e), level: "error" });
      } finally {
        setLoading(false);
        setIngestProgress(null);
        unlistenRef.current = null;
      }
    } else {
      if (webFiles.length === 0) {
        onLog({ time: now(), message: "No file selected", level: "error" });
        setLoading(false);
        return;
      }
      try {
        const sessionId = currentSessionId || "default";

        for (let i = 0; i < webFiles.length; i++) {
          const webFile = webFiles[i];
          if (webFiles.length > 1) {
            onLog({ time: now(), message: `[${i + 1}/${webFiles.length}] Uploading: ${webFile.name}`, level: "info" });
          } else {
            onLog({ time: now(), message: "Uploading file...", level: "info" });
          }
          const upload = await uploadFile(webFile);
          onLog({ time: now(), message: `Uploaded (${(upload.size / 1024 / 1024).toFixed(1)} MB)`, level: "info" });

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

          const job = await createJob(upload.upload_id, format, sessionId);
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
              message: `${webFile.name}: +${finalStatus.result.new_entities} entities, +${finalStatus.result.new_relations} relations`,
              level: "success",
            });
          }
          cleanupWS();
        }

        if (webFiles.length > 1) {
          onLog({ time: now(), message: `All ${webFiles.length} files ingested.`, level: "success" });
        }
      } catch (e) {
        onLog({ time: now(), message: errorMessage(e), level: "error" });
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
        onLog({
          time: now(),
          message: "Azure Tenant ID, Client ID, and Client Secret are required.",
          level: "error",
        });
        return;
      }
      if (!siemWorkspaceId.trim()) {
        onLog({
          time: now(),
          message: "Workspace ID is required.",
          level: "error",
        });
        return;
      }
      params.workspace_id = siemWorkspaceId.trim();
      params.azure_tenant_id = azureTenantId.trim();
      params.azure_client_id = azureClientId.trim();
      params.azure_client_secret = azureClientSecret.trim();
    } else {
      if (!elasticUrl.trim()) {
        onLog({
          time: now(),
          message: "Elasticsearch URL is required.",
          level: "error",
        });
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
    onLog({ time: now(), message: "Running query and ingesting...", level: "info" });
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
      onLog({ time: now(), message: errorMessage(e), level: "error" });
    } finally {
      setLoading(false);
      setIngestProgress(null);
      if (unlistenRef.current) {
        unlistenRef.current();
        unlistenRef.current = null;
      }
    }
  }

  async function previewFields() {
    if (filePaths.length === 0) return;
    setPreviewLoading(true);
    onLog({ time: now(), message: "Previewing fields...", level: "info" });
    try {
      const fields = await invoke<FieldInfo[]>("cmd_preview_fields", {
        path: filePaths[0],
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
      onLog({ time: now(), message: `Preview failed: ${errorMessage(e)}`, level: "error" });
    } finally {
      setPreviewLoading(false);
    }
  }

  async function loadDataWithConfig(mappings: FieldMapping[]) {
    if (filePaths.length === 0) return;
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
        path: filePaths[0],
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
      onLog({ time: now(), message: errorMessage(e), level: "error" });
    } finally {
      setConfigLoading(false);
    }
  }

  return (
    <aside className="left-menu-panel" aria-label="Datasets">
      <div className="left-menu-panel-header">
        <span className="left-menu-panel-title">
          <Database size={14} />
          Datasets
        </span>
        <button
          type="button"
          className="left-menu-panel-close"
          onClick={onClose}
          title="Close Datasets panel"
          aria-label="Close Datasets panel"
        >
          <X size={14} />
        </button>
      </div>
      <div className="left-menu-panel-content">
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
              <label
                style={{
                  fontSize: 11,
                  color: "var(--text-muted)",
                  display: "block",
                  marginBottom: 4,
                }}
              >
                Ingest source
              </label>
              <select
                value={ingestSource}
                onChange={(e) =>
                  setIngestSource(e.target.value as "file" | "sentinel" | "elastic")
                }
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
              <FileUploadSection
                filePaths={filePaths}
                setFilePaths={setFilePaths}
                webFiles={webFiles}
                setWebFiles={setWebFiles}
                format={format}
                setFormat={setFormat}
                loading={loading}
                previewLoading={previewLoading}
                previewResult={previewResult}
                setPreviewResult={setPreviewResult}
                mappingRows={mappingRows}
                setMappingRows={setMappingRows}
                graphEntityTypes={graphEntityTypes}
                ingestProgress={ingestProgress}
                onLog={onLog}
                onPickFile={pickFile}
                onRunPreview={runPreview}
                onLoadData={loadData}
                onPreviewFields={previewFields}
              />
            </>
            )}
            {ingestSource === "sentinel" && (
              <SentinelConnectForm
                azureTenantId={azureTenantId}
                setAzureTenantId={setAzureTenantId}
                azureClientId={azureClientId}
                setAzureClientId={setAzureClientId}
                azureClientSecret={azureClientSecret}
                setAzureClientSecret={setAzureClientSecret}
                siemWorkspaceId={siemWorkspaceId}
                setSiemWorkspaceId={setSiemWorkspaceId}
                loading={loading}
                onLoadDataSIEM={loadDataSIEM}
                ingestProgress={ingestProgress}
                extended={{
                  azureSubscriptionId,
                  setAzureSubscriptionId,
                  azureResourceGroup,
                  setAzureResourceGroup,
                  azureWorkspaceName,
                  setAzureWorkspaceName,
                  sentinelStreaming,
                  sentinelPollInterval,
                  setSentinelPollInterval,
                  sentinelStatus,
                  sentinelLiveStats,
                  onStartStream: startSentinelStream,
                  onStopStream: stopSentinelStream,
                }}
              />
            )}
            {ingestSource === "elastic" && (
              <ElasticConnectForm
                elasticUrl={elasticUrl}
                setElasticUrl={setElasticUrl}
                elasticIndex={elasticIndex}
                setElasticIndex={setElasticIndex}
                elasticApiKey={elasticApiKey}
                setElasticApiKey={setElasticApiKey}
                elasticUser={elasticUser}
                setElasticUser={setElasticUser}
                elasticPassword={elasticPassword}
                setElasticPassword={setElasticPassword}
                elasticQuery={elasticQuery}
                setElasticQuery={setElasticQuery}
                elasticSize={elasticSize}
                setElasticSize={setElasticSize}
                loading={loading}
                onLoadDataSIEM={loadDataSIEM}
                ingestProgress={ingestProgress}
              />
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
            <DatasetList
              datasets={datasets}
              datasetsLoading={datasetsLoading}
              onStatsUpdate={onStatsUpdate}
              onLog={onLog}
              onDatasetsChange={setDatasets}
              allowCustomType
            />
          </div>
        )}
      </div>
    </aside>
  );
}
