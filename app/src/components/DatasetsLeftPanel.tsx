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
  FolderOpen,
  Database,
  ChevronDown,
  ChevronRight,
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
} from "../types";
import { ENTITY_TYPES } from "../types";
import FieldSelector from "./FieldSelector";

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

  const [ingestProgress, setIngestProgress] = useState<{
    processed: number;
    total: number;
    entities: number;
    relations: number;
  } | null>(null);
  const unlistenRef = useRef<(() => void) | null>(null);

  const [webFile, setWebFile] = useState<File | null>(null);
  const webFileInputRef = useRef<HTMLInputElement | null>(null);

  const [previewResult, setPreviewResult] = useState<PreviewIngestResult | null>(null);
  const [previewLoading, setPreviewLoading] = useState(false);
  const [mappingRows, setMappingRows] = useState<DetectedField[]>([]);
  const [graphEntityTypes, setGraphEntityTypes] = useState<string[]>([]);

  const [showDataIngestion, setShowDataIngestion] = useState(false);
  const [showDatasets, setShowDatasets] = useState(true);
  const [datasets, setDatasets] = useState<DatasetInfo[]>([]);
  const [datasetsLoading, setDatasetsLoading] = useState(false);
  const [renameModal, setRenameModal] = useState<{ datasetId: string; datasetName: string } | null>(null);
  const [renameFromType, setRenameFromType] = useState<string>("");
  const [renameToType, setRenameToType] = useState<string>("");
  const [renameToTypeCustom, setRenameToTypeCustom] = useState<string>("");
  const [datasetTypes, setDatasetTypes] = useState<string[]>([]);
  const [renameApplying, setRenameApplying] = useState(false);
  const [renameError, setRenameError] = useState<string | null>(null);

  const RENAME_TO_CUSTOM = "__custom__";
  const effectiveToType = renameToType === RENAME_TO_CUSTOM ? renameToTypeCustom.trim() : renameToType;

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

  const [fieldPreview, setFieldPreview] = useState<FieldInfo[] | null>(null);
  const [showFieldSelector, setShowFieldSelector] = useState(false);
  const [configLoading, setConfigLoading] = useState(false);

  const SIEM_CONFIG_KEY = "graph_hunter_siem_config";

  function getSiemConfigKey(sessionId: string | null): string | null {
    return sessionId ? `${SIEM_CONFIG_KEY}_${sessionId}` : null;
  }

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

  async function pickFile() {
    if (isTauri()) {
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
      onLog({
        time: now(),
        message: `Preview: ${result.format}, ${result.detected_fields.length} fields`,
        level: "info",
      });
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

        const unlistenProgress = await listen<{
          processed?: number;
          total_estimate?: number;
          bytes_read?: number;
          bytes_total?: number;
          entities?: number;
          relations?: number;
        }>("ingest-progress", (event) => {
          const p = event.payload;
          const processed = p.processed ?? p.bytes_read ?? 0;
          const total = p.total_estimate ?? p.bytes_total ?? 0;
          setIngestProgress({
            processed: Number(processed),
            total: Number(total),
            entities: Number(p.entities ?? 0),
            relations: Number(p.relations ?? 0),
          });
        });

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

        unlistenRef.current = cleanup;

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
      if (!webFile) {
        onLog({ time: now(), message: "No file selected", level: "error" });
        setLoading(false);
        return;
      }
      try {
        onLog({ time: now(), message: "Uploading file...", level: "info" });
        const upload = await uploadFile(webFile);
        onLog({
          time: now(),
          message: `Uploaded (${(upload.size / 1024 / 1024).toFixed(1)} MB)`,
          level: "info",
        });

        const sessionId = currentSessionId || "default";

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
            <div style={{ marginBottom: 8 }}>
              <label
                style={{
                  fontSize: 11,
                  color: "var(--text-muted)",
                  display: "block",
                  marginBottom: 4,
                }}
              >
                Log Format
              </label>
              <select
                className="select"
                value={format}
                onChange={(e) =>
                  setFormat(e.target.value as "auto" | "sysmon" | "sentinel" | "generic" | "csv")
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
                {format === "evtx"
                  ? "Select EVTX File"
                  : format === "sysmon"
                    ? "Select Sysmon File"
                    : format === "sentinel"
                      ? "Select Sentinel File"
                      : "Select Log File"}
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
                  <div
                    style={{
                      fontSize: 11,
                      color: "var(--text-muted)",
                      marginBottom: 6,
                    }}
                  >
                    Format: <strong>{previewResult.format}</strong>
                  </div>
                  <div style={{ maxHeight: 200, overflow: "auto" }}>
                    <table
                      style={{
                        width: "100%",
                        fontSize: 11,
                        borderCollapse: "collapse",
                      }}
                    >
                      <thead>
                        <tr>
                          <th
                            style={{
                              textAlign: "left",
                              padding: "4px 6px",
                              borderBottom: "1px solid var(--border)",
                            }}
                          >
                            Field
                          </th>
                          <th
                            style={{
                              textAlign: "left",
                              padding: "4px 6px",
                              borderBottom: "1px solid var(--border)",
                            }}
                          >
                            Node type
                          </th>
                          {(format === "generic" || format === "csv") && (
                            <th style={{ width: 28 }} />
                          )}
                        </tr>
                      </thead>
                      <tbody>
                        {mappingRows.map((row, i) => (
                          <tr key={`${row.field_name}-${i}`}>
                            <td
                              style={{
                                padding: "4px 6px",
                                borderBottom: "1px solid var(--border)",
                              }}
                              title={row.field_name}
                            >
                              {row.field_name.length > 18
                                ? `${row.field_name.slice(0, 15)}…`
                                : row.field_name}
                            </td>
                            <td
                              style={{
                                padding: "4px 6px",
                                borderBottom: "1px solid var(--border)",
                              }}
                            >
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
                                  onChange={(e) =>
                                    updateMappingRow(i, e.target.value)
                                  }
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
                              <td
                                style={{
                                  padding: "4px 2px",
                                  borderBottom: "1px solid var(--border)",
                                }}
                              >
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
                  <div
                    style={{
                      height: 6,
                      background: "var(--bg-secondary)",
                      borderRadius: 3,
                      overflow: "hidden",
                    }}
                  >
                    <div
                      style={{
                        height: "100%",
                        width: `${
                          (ingestProgress.total ?? 0) > 0
                            ? Math.round(
                                ((ingestProgress.processed ?? 0) /
                                  (ingestProgress.total ?? 1)) *
                                  100
                              )
                            : 0
                        }%`,
                        background: "var(--accent)",
                        borderRadius: 3,
                        transition: "width 0.2s",
                      }}
                    />
                  </div>
                  <div
                    style={{
                      fontSize: 10,
                      color: "var(--text-muted)",
                      marginTop: 2,
                    }}
                  >
                    {(ingestProgress.processed ?? 0).toLocaleString()} /{" "}
                    {(ingestProgress.total ?? 0).toLocaleString()}
                    {(ingestProgress.total ?? 0) > 1000000 ? " bytes" : ""}
                    {" — "}
                    {(ingestProgress.entities ?? 0).toLocaleString()} entities,{" "}
                    {(ingestProgress.relations ?? 0).toLocaleString()} relations
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
              <div className="types-available-empty">
                No datasets yet. Ingest a file to see them here.
              </div>
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
                    <div style={{ fontWeight: 600, marginBottom: 2 }}>
                      {d.name}
                    </div>
                    <div
                      style={{
                        color: "var(--text-muted)",
                        marginBottom: 6,
                      }}
                    >
                      {d.entity_count} entities, {d.relation_count} relations
                    </div>
                    <div
                      style={{
                        display: "flex",
                        gap: 6,
                        flexWrap: "wrap",
                      }}
                    >
                      <button
                        type="button"
                        className="btn btn-sm"
                        onClick={async () => {
                          setRenameFromType("");
                          setRenameToType("");
                          setRenameToTypeCustom("");
                          setRenameError(null);
                          let types: string[] = [];
                          try {
                            types = await invoke<string[]>("cmd_dataset_entity_types", {
                              datasetId: d.id,
                            });
                          } catch {
                            // ignore
                          }
                          if (types.length === 0) {
                            try {
                              types = await invoke<string[]>("cmd_get_entity_types_in_graph");
                            } catch {
                              types = [];
                            }
                          }
                          setDatasetTypes(types);
                          setRenameModal({
                            datasetId: d.id,
                            datasetName: d.name,
                          });
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
                          if (
                            !confirm(
                              `Remove dataset "${d.name}"? This will delete ${d.entity_count} entities and ${d.relation_count} relations.`
                            )
                          )
                            return;
                          try {
                            await invoke<[number, number]>(
                              "cmd_remove_dataset",
                              { datasetId: d.id }
                            );
                            const s = await invoke<GraphStats>(
                              "cmd_get_graph_stats"
                            );
                            onStatsUpdate(s);
                            const list = await invoke<DatasetInfo[]>(
                              "cmd_list_datasets"
                            );
                            setDatasets(list);
                            onLog({
                              time: now(),
                              message: `Removed dataset: ${d.name}`,
                              level: "success",
                            });
                          } catch (e) {
                            onLog({
                              time: now(),
                              message: `Remove failed: ${e}`,
                              level: "error",
                            });
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
                  <div style={{ marginBottom: 12, fontWeight: 600 }}>
                    Rename type in "{renameModal.datasetName}"
                  </div>
                  <div style={{ marginBottom: 8 }}>
                    <label
                      style={{
                        fontSize: 11,
                        color: "var(--text-muted)",
                        display: "block",
                        marginBottom: 4,
                      }}
                    >
                      From type
                    </label>
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
                        <option key={t} value={t}>
                          {t}
                        </option>
                      ))}
                    </select>
                  </div>
                  <div style={{ marginBottom: 12 }}>
                    <label
                      style={{
                        fontSize: 11,
                        color: "var(--text-muted)",
                        display: "block",
                        marginBottom: 4,
                      }}
                    >
                      To type
                    </label>
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
                        <option key={t} value={t}>
                          {t}
                        </option>
                      ))}
                      <option value={RENAME_TO_CUSTOM}>Custom…</option>
                    </select>
                    {renameToType === RENAME_TO_CUSTOM && (
                      <input
                        type="text"
                        value={renameToTypeCustom}
                        onChange={(e) => setRenameToTypeCustom(e.target.value)}
                        placeholder="Type name"
                        style={{
                          marginTop: 6,
                          width: "100%",
                          padding: "6px 8px",
                          background: "var(--bg-tertiary)",
                          color: "var(--text-primary)",
                          border: "1px solid var(--border)",
                          borderRadius: 4,
                          fontSize: 12,
                          boxSizing: "border-box",
                        }}
                      />
                    )}
                  </div>
                  {renameError && (
                    <div
                      style={{
                        marginBottom: 12,
                        padding: 8,
                        background: "rgba(239, 68, 68, 0.15)",
                        border: "1px solid var(--danger)",
                        borderRadius: 4,
                        fontSize: 12,
                        color: "var(--danger)",
                      }}
                    >
                      {renameError}
                    </div>
                  )}
                  <div
                    style={{
                      display: "flex",
                      justifyContent: "flex-end",
                      gap: 8,
                    }}
                  >
                    <button
                      type="button"
                      className="btn"
                      onClick={() => {
                        setRenameModal(null);
                        setRenameError(null);
                      }}
                      disabled={renameApplying}
                    >
                      Cancel
                    </button>
                    <button
                      type="button"
                      className="btn btn-primary"
                      disabled={
                        renameApplying ||
                        !renameFromType ||
                        !effectiveToType ||
                        renameFromType === effectiveToType
                      }
                      onClick={async (e) => {
                        e.preventDefault();
                        e.stopPropagation();
                        if (
                          !renameModal ||
                          !renameFromType ||
                          !effectiveToType
                        )
                          return;
                        setRenameError(null);
                        setRenameApplying(true);
                        try {
                          await invoke<number>(
                            "cmd_rename_type_in_dataset",
                            {
                              datasetId: renameModal.datasetId,
                              fromType: renameFromType,
                              toType: effectiveToType,
                            }
                          );
                          setRenameModal(null);
                          setRenameError(null);
                          setRenameApplying(false);
                          invoke<GraphStats>("cmd_get_graph_stats")
                            .then(onStatsUpdate)
                            .catch(() => {});
                          invoke<DatasetInfo[]>("cmd_list_datasets")
                            .then(setDatasets)
                            .catch(() => {});
                          onLog({
                            time: now(),
                            message: `Renamed ${renameFromType} → ${effectiveToType} in dataset`,
                            level: "success",
                          });
                        } catch (err) {
                          const msg = err instanceof Error ? err.message : String(err);
                          setRenameError(msg);
                          setRenameApplying(false);
                          onLog({
                            time: now(),
                            message: `Rename failed: ${msg}`,
                            level: "error",
                          });
                        }
                      }}
                    >
                      {renameApplying ? "Applying…" : "Apply"}
                    </button>
                  </div>
                </div>
              </div>
            )}
          </div>
        )}
      </div>
    </aside>
  );
}
