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
  BarChart3,
  Database,
  Activity,
  ChevronDown,
  ChevronRight,
  ChevronLeft,
  Palette,
  ArrowRight,
  Layers,
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
  FieldRole,
  CompactionStats,
  IngestJobStarted,
  IngestCompleteEvent,
  IngestErrorEvent,
  IngestLlmProposalEvent,
  IngestLlmDiagnosticEvent,
} from "../types";
import { ENTITY_COLORS } from "../types";
import FieldSelector from "./FieldSelector";
import { FileUploadSection } from "./ingest";
import { SentinelConnectForm } from "./ingest";
import { ElasticConnectForm } from "./ingest";
import { LlmIngestConfirmBanner } from "./ingest/LlmIngestConfirmBanner";
import { DatasetList } from "./datasets";

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
  const [filePaths, setFilePaths] = useState<string[]>([]);
  const [loading, setLoading] = useState(false);
  const [format, setFormat] = useState<"auto" | "evtx" | "sysmon" | "sentinel" | "generic" | "csv">("auto");
  const [dateFrom, setDateFrom] = useState("");
  const [dateTo, setDateTo] = useState("");
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

  // Web mode: selected File objects
  const [webFiles, setWebFiles] = useState<File[]>([]);

  // Preview step: result from cmd_preview_ingest and editable mapping (field -> node type)
  const [previewResult, setPreviewResult] = useState<PreviewIngestResult | null>(null);
  const [previewLoading, setPreviewLoading] = useState(false);
  const [mappingRows, setMappingRows] = useState<DetectedField[]>([]);
  // Set when the most recent ingest produced 0 triples — surfaces a remap
  // prompt so the Zoho-class silent-zero incident is visible immediately.
  const [zeroTripleWarning, setZeroTripleWarning] = useState<string | null>(
    null
  );
  // Set when the LLM-as-compiler dispatcher (Phase C) halts an ingest
  // because the heuristic produced zero recognized Node mappings and the
  // local LLM offered a refined alternative. The banner renders the diff
  // and lets the analyst pick which config to re-ingest with.
  const [llmProposal, setLlmProposal] = useState<IngestLlmProposalEvent | null>(
    null
  );
  const [llmProposalLoading, setLlmProposalLoading] = useState(false);
  // Entity types for preview dropdown: standard + custom from graph + any in current mapping
  const [graphEntityTypes, setGraphEntityTypes] = useState<string[]>([]);

  // Datasets section
  const [showDatasets, setShowDatasets] = useState(true);
  const [datasets, setDatasets] = useState<DatasetInfo[]>([]);
  const [datasetsLoading, setDatasetsLoading] = useState(false);

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

  // Permanent mount-time listener for `ingest-llm-proposal`. Without
  // this, the per-file listeners inside loadData() are the only thing
  // attached — meaning the synthetic debug emit (and any out-of-band
  // proposal from a future async path) lands in the void if there's
  // no active ingest. With this hook the banner state always updates
  // when an event lands, regardless of ingest lifecycle.
  useEffect(() => {
    if (!isTauri()) return;
    let unlisten: (() => void) | null = null;
    let cancelled = false;
    (async () => {
      const { listen } = await import("@tauri-apps/api/event");
      const u = await listen<IngestLlmProposalEvent>(
        "ingest-llm-proposal",
        (event) => {
          if (!cancelled) setLlmProposal(event.payload);
        },
      );
      if (cancelled) {
        u();
      } else {
        unlisten = u;
      }
    })().catch((err) => console.error("listen ingest-llm-proposal (IngestPanel):", err));
    return () => {
      cancelled = true;
      unlisten?.();
    };
  }, []);

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
      // Desktop: use Tauri native file dialog with multi-select and filters
      try {
        const { open } = await import("@tauri-apps/plugin-dialog");
        const selected = await open({
          multiple: true,
          filters: [
            { name: "EVTX Files", extensions: ["evtx"] },
            { name: "FortiAnalyzer XML Reports", extensions: ["xml"] },
            { name: "Log Files", extensions: ["json", "ndjson", "csv", "log", "evtx", "xml"] },
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
      onLog({ time: now(), message: `Preview: ${result.format}, ${result.detected_fields.length} fields`, level: "info" });
    } catch (e) {
      onLog({ time: now(), message: `Preview failed: ${errorMessage(e)}`, level: "error" });
    } finally {
      setPreviewLoading(false);
    }
  }

  /**
   * Re-trigger `cmd_load_data_streaming` with the analyst's chosen
   * config (refined-by-LLM or heuristic) after the dispatcher halted
   * an ambiguous ingest. Backend dispatcher sees `bg_config.is_some()`
   * on the second call and skips its own negotiation, so this can't
   * recurse into another proposal banner.
   */
  async function reingestWithProposalChoice(choice: "refined" | "heuristic") {
    if (!llmProposal) return;
    const proposal = llmProposal;
    const sourcePath = proposal.source_path;
    const fileName = sourcePath.split(/[/\\]/).pop() || sourcePath;
    const chosenConfig =
      choice === "refined" ? proposal.refined : proposal.heuristic;
    setLlmProposalLoading(true);
    try {
      onLog({
        time: now(),
        message: `Re-ingesting ${fileName} with ${
          choice === "refined" ? "AI compiler" : "heuristic"
        } mapping…`,
        level: "info",
      });

      const { invoke } = await import("@tauri-apps/api/core");
      const { listen } = await import("@tauri-apps/api/event");

      await new Promise<void>((resolve) => {
        let unlistenComplete: (() => void) | null = null;
        let unlistenError: (() => void) | null = null;
        const cleanup = () => {
          unlistenComplete?.();
          unlistenError?.();
        };
        (async () => {
          unlistenComplete = await listen<IngestCompleteEvent>(
            "ingest-complete",
            (event) => {
              const { result } = event.payload;
              onStatsUpdate({
                entity_count: result.total_entities,
                relation_count: result.total_relations,
              });
              if (result.zero_triples) {
                setZeroTripleWarning(fileName);
                onLog({
                  time: now(),
                  message: `${fileName}: re-ingest produced 0 triples — mapping rejected by parser.`,
                  level: "error",
                });
              } else {
                onLog({
                  time: now(),
                  message: `${fileName}: +${result.new_entities} entities, +${result.new_relations} relations (via ${
                    choice === "refined" ? "AI" : "heuristic"
                  } mapping).`,
                  level: "success",
                });
              }
              cleanup();
              resolve();
            },
          );
          unlistenError = await listen<IngestErrorEvent>(
            "ingest-error",
            (event) => {
              onLog({
                time: now(),
                message: `${fileName}: ${event.payload.error}`,
                level: "error",
              });
              cleanup();
              resolve();
            },
          );
          await invoke<IngestJobStarted>("cmd_load_data_streaming", {
            path: sourcePath,
            format: proposal.format,
            config: chosenConfig,
            dateFrom: null,
            dateTo: null,
          });
        })().catch((err) => {
          onLog({
            time: now(),
            message: `Re-ingest call failed: ${errorMessage(err)}`,
            level: "error",
          });
          cleanup();
          resolve();
        });
      });

      setLlmProposal(null);
    } catch (e) {
      onLog({
        time: now(),
        message: `Re-ingest error: ${errorMessage(e)}`,
        level: "error",
      });
    } finally {
      setLlmProposalLoading(false);
    }
  }

  async function loadData() {
    if (filePaths.length === 0) return;
    setLoading(true);
    setIngestProgress(null);
    onLog({ time: now(), message: `Ingesting ${filePaths.length} file(s)...`, level: "info" });

    const config =
      previewResult && mappingRows.length > 0
        ? {
            mappings: mappingRows.map((row) => {
              const isTimestamp =
                row.canonical_target === "timestamp" ||
                !!row.timestamp_format;
              const role: FieldRole = isTimestamp
                ? "Metadata"
                : row.suggested_entity_type === "Skip"
                ? "Ignore"
                : "Node";
              return {
                raw_name: row.field_name,
                role,
                entity_type:
                  row.suggested_entity_type === "Skip" || isTimestamp
                    ? null
                    : row.suggested_entity_type,
                timestamp_format: row.timestamp_format || null,
                locale: row.locale || null,
              };
            }),
          }
        : undefined;

    if (isTauri()) {
      // ── Tauri desktop path (async, event-driven, sequential multi-file) ──
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

        // Process each file sequentially
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
            let unlistenProposal: (() => void) | null = null;
            let unlistenDiagnostic: (() => void) | null = null;

            const fileCleanup = () => {
              unlistenProgress?.();
              unlistenComplete?.();
              unlistenError?.();
              unlistenProposal?.();
              unlistenDiagnostic?.();
            };

            (async () => {
              unlistenProgress = await listen<any>("ingest-progress", (event) => {
                const p = event.payload;
                setIngestProgress({
                  processed: p.processed ?? p.bytes_read ?? 0,
                  total: p.total_estimate ?? p.bytes_total ?? 0,
                  entities: p.entities ?? 0,
                  relations: p.relations ?? 0,
                  phase: p.phase,
                });
              });

              unlistenComplete = await listen<IngestCompleteEvent>("ingest-complete", (event) => {
                const { result } = event.payload;
                onStatsUpdate({
                  entity_count: result.total_entities,
                  relation_count: result.total_relations,
                });
                if (result.zero_triples) {
                  setZeroTripleWarning(fileName);
                  onLog({
                    time: now(),
                    message: `${fileName}: parser produced 0 triples — open Preview to adjust the mapping.`,
                    level: "error",
                  });
                } else {
                  setZeroTripleWarning(null);
                  onLog({
                    time: now(),
                    message: `${fileName}: +${result.new_entities} entities, +${result.new_relations} relations`,
                    level: "success",
                  });
                }
                for (const w of result.warnings ?? []) {
                  onLog({ time: now(), message: `${fileName}: ${w}`, level: "warning" });
                }
                fileCleanup();
                resolve();
              });

              unlistenError = await listen<IngestErrorEvent>("ingest-error", (event) => {
                onLog({ time: now(), message: `${fileName}: ${event.payload.error}`, level: "error" });
                fileCleanup();
                resolve(); // continue with next file
              });

              // Fire-and-forget dispatcher diagnostic. Logged for
              // every decision (heuristic confident / LLM proposal
              // pending / LLM unavailable) so the analyst always
              // sees which path the dispatcher took. Without it a
              // silent fall-back that produces zero triples looks
              // identical to a parser bug.
              unlistenDiagnostic = await listen<IngestLlmDiagnosticEvent>(
                "ingest-llm-diagnostic",
                (event) => {
                  const p = event.payload;
                  const level: LogEntry["level"] =
                    p.outcome === "llm_proposal" ? "warning" : "info";
                  const tag =
                    p.outcome === "heuristic_ok"
                      ? "Compilador IA (heurística)"
                      : p.outcome === "llm_proposal"
                        ? "Compilador IA (propuesta)"
                        : "Compilador IA (fallback)";
                  onLog({
                    time: now(),
                    message: `${fileName}: ${tag} — ${p.reason}`,
                    level,
                  });
                },
              );

              // LLM-as-compiler dispatcher: heuristic produced zero
              // recognized Node mappings, local LLM offered a refined
              // alternative. Streaming was halted backend-side before
              // any triples landed; the analyst now picks one of the
              // two configs in the confirm banner. We unblock this
              // file's Promise — the banner buttons re-trigger
              // `cmd_load_data_streaming` with the chosen config.
              unlistenProposal = await listen<IngestLlmProposalEvent>(
                "ingest-llm-proposal",
                (event) => {
                  setLlmProposal(event.payload);
                  onLog({
                    time: now(),
                    message: `${fileName}: compilador IA propone otro mapeo (confianza ${Math.round(
                      Math.max(0, Math.min(1, event.payload.confidence)) * 100,
                    )}%) — revisar el banner antes de continuar.`,
                    level: "warning",
                  });
                  fileCleanup();
                  resolve();
                },
              );

              // Store cleanup for external abort (e.g. unmount)
              unlistenRef.current = () => {
                fileCleanup();
                resolve();
              };

              await invoke<IngestJobStarted>("cmd_load_data_streaming", {
                path: currentPath,
                format,
                config,
                dateFrom: dateFrom || null,
                dateTo: dateTo || null,
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
      // ── Web path: upload files → create jobs → poll/WS for progress ──
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

          const job = await createJob(upload.upload_id, format, sessionId, config);
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
            if ((finalStatus.result as { zero_triples?: boolean }).zero_triples) {
              setZeroTripleWarning(webFile.name);
              onLog({
                time: now(),
                message: `${webFile.name}: parser produced 0 triples — adjust your mapping and re-ingest.`,
                level: "error",
              });
            } else {
              setZeroTripleWarning(null);
              onLog({
                time: now(),
                message: `${webFile.name}: +${finalStatus.result.new_entities} entities, +${finalStatus.result.new_relations} relations`,
                level: "success",
              });
            }
            const warnings = (finalStatus.result as { warnings?: string[] }).warnings ?? [];
            for (const w of warnings) {
              onLog({ time: now(), message: `${webFile.name}: ${w}`, level: "warning" });
            }
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

  async function refreshStats() {
    try {
      const s = await invoke<GraphStats>("cmd_get_graph_stats");
      onStatsUpdate(s);
    } catch (e) {
      onLog({ time: now(), message: errorMessage(e), level: "error" });
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
            {llmProposal && (
              <LlmIngestConfirmBanner
                proposal={llmProposal}
                loading={llmProposalLoading}
                onApplyRefined={() => reingestWithProposalChoice("refined")}
                onApplyHeuristic={() => reingestWithProposalChoice("heuristic")}
                onDismiss={() => setLlmProposal(null)}
              />
            )}
            {zeroTripleWarning && (
              <div
                role="alert"
                style={{
                  padding: "8px 10px",
                  margin: "0 0 8px 0",
                  background: "rgba(220, 38, 38, 0.12)",
                  border: "1px solid rgba(220, 38, 38, 0.4)",
                  borderRadius: 4,
                  color: "#f87171",
                  fontSize: 11,
                  display: "flex",
                  alignItems: "flex-start",
                  gap: 6,
                }}
              >
                <span>&#9888;</span>
                <div style={{ flex: 1 }}>
                  <strong>{zeroTripleWarning}</strong>: the parser saw rows but
                  produced 0 triples. Run <em>Preview</em> on this file,
                  adjust the mapping (and a timestamp format if needed), and
                  re-ingest.
                </div>
                <button
                  type="button"
                  onClick={() => setZeroTripleWarning(null)}
                  aria-label="Dismiss warning"
                  style={{
                    padding: 0,
                    background: "none",
                    border: "none",
                    color: "#f87171",
                    cursor: "pointer",
                    fontSize: 14,
                    lineHeight: 1,
                  }}
                >
                  &times;
                </button>
              </div>
            )}
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
              showDateFilter
              dateFrom={dateFrom}
              setDateFrom={setDateFrom}
              dateTo={dateTo}
              setDateTo={setDateTo}
              showPhase
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
          <DatasetList
            datasets={datasets}
            datasetsLoading={datasetsLoading}
            onStatsUpdate={onStatsUpdate}
            onLog={onLog}
            onDatasetsChange={setDatasets}
          />
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
                      onLog({ time: now(), message: `Scoring failed: ${errorMessage(e)}`, level: "error" });
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
                        onLog({ time: now(), message: `Compaction failed: ${errorMessage(e)}`, level: "error" });
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
                                {(entitiesForType.length > 100
                                  ? entitiesForType.slice(0, 100)
                                  : entitiesForType
                                ).map((id) => (
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
                                {entitiesForType.length > 100 && (
                                  <li
                                    className="legend-entity-row"
                                    style={{ color: "var(--text-muted)", fontSize: 10, padding: "4px 0" }}
                                  >
                                    … and {(entitiesForType.length - 100).toLocaleString()} more
                                  </li>
                                )}
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
