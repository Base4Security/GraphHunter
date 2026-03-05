import { useState, useCallback, useEffect, useRef } from "react";
import { listen } from "@tauri-apps/api/event";
import { invoke } from "./lib/tauri";
import DatasetsLeftPanel from "./components/DatasetsLeftPanel";
import ActivityLogLeftPanel from "./components/ActivityLogLeftPanel";
import GraphMetricsLeftPanel from "./components/GraphMetricsLeftPanel";
import SessionSelector from "./components/SessionSelector";
import WelcomePage from "./components/WelcomePage";
import HelpPanel from "./components/HelpPanel";
import HypothesisBuilder from "./components/HypothesisBuilder";
import GraphCanvas from "./components/GraphCanvas";
import ExplorerPanel from "./components/ExplorerPanel";
import PathNodesPanel from "./components/PathNodesPanel";
import NotesPanel from "./components/NotesPanel";
import NodeDetailPanel from "./components/NodeDetailPanel";
import HuntResultsTable from "./components/HuntResultsTable";
import EventsViewPanel from "./components/EventsViewPanel";
import HeatmapView from "./components/HeatmapView";
import TimelineView from "./components/TimelineView";
import { ChevronLeft, ChevronRight, Sparkles, Database, Activity, BarChart3, X, MapPin, FileText, HelpCircle } from "lucide-react";
import type {
  GraphStats,
  HuntResults,
  PaginatedHuntResults,
  Subgraph,
  Neighborhood,
  NodeDetails,
  ExpandFilter,
  LogEntry,
  SessionInfo,
  Note,
  AiProvider,
  AiAnalysisResponse,
  AiSuggestion,
  ConversationMessage,
} from "./types";
import "./App.css";

type AppMode = "hunt" | "explore";
type BottomTab = "hunt" | "explore" | "events" | "heatmap" | "timeline";

/** Snapshot of map view for back/forward navigation */
interface MapState {
  mode: AppMode;
  bottomTab: BottomTab;
  subgraph: Subgraph | null;
  highlightPaths: string[][] | null;
  neighborhood: Neighborhood | null;
  selectedNodeId: string | null;
  nodeDetails: NodeDetails | null;
}

function App() {
  const [stats, setStats] = useState<GraphStats>({
    entity_count: 0,
    relation_count: 0,
  });
  const [log, setLog] = useState<LogEntry[]>([]);
  const [mode, setMode] = useState<AppMode>("hunt");

  // Session state
  const [currentSession, setCurrentSession] = useState<SessionInfo | null>(null);
  const [sessions, setSessions] = useState<SessionInfo[]>([]);
  const [sessionError, setSessionError] = useState<string>("");

  // Hunt mode state
  const [subgraph, setSubgraph] = useState<Subgraph | null>(null);
  const [highlightPaths, setHighlightPaths] = useState<string[][] | null>(null);
  const [huntPathCount, setHuntPathCount] = useState(0);
  const [showHuntTable, setShowHuntTable] = useState(false);

  // Explorer mode state
  const [selectedNodeId, setSelectedNodeId] = useState<string | null>(null);
  const [nodeDetails, setNodeDetails] = useState<NodeDetails | null>(null);
  const [explorerNeighborhood, setExplorerNeighborhood] =
    useState<Neighborhood | null>(null);

  // Path nodes (pinned/fixed nodes) for the current session
  const [pathNodeIds, setPathNodeIds] = useState<string[]>([]);
  // Entity types present in the current graph (for Show neighbours By Type dropdown)
  const [entityTypesInGraph, setEntityTypesInGraph] = useState<string[]>([]);
  // Right menu: only one at a time (pathNodes | notes | none)
  const [rightMenuOpen, setRightMenuOpen] = useState<"pathNodes" | "notes" | null>(null);
  // Notes (standalone or linked to node)
  const [notes, setNotes] = useState<Note[]>([]);
  // When set, GraphCanvas centers on this node (Hunt mode); cleared after centering
  const [centerNodeId, setCenterNodeId] = useState<string | null>(null);
  // Bottom panel: which tab is active (hunt / explore / events)
  const [bottomTab, setBottomTab] = useState<BottomTab>("explore");
  // Bottom panel height (px) for resizable split; min 120, max 80vh
  const [bottomPanelHeight, setBottomPanelHeight] = useState(300);
  // Left menu: only one at a time (datasets | activity | metrics | none)
  const [leftMenuOpen, setLeftMenuOpen] = useState<"datasets" | "activity" | "metrics" | null>("datasets");
  // Map back/forward history (snapshots of map state)
  const [mapPast, setMapPast] = useState<MapState[]>([]);
  const [mapFuture, setMapFuture] = useState<MapState[]>([]);
  const mapStateRef = useRef<MapState | null>(null);
  // Analyze with AI panel (current graph)
  const [analyzeAiOpen, setAnalyzeAiOpen] = useState(false);
  const [analyzeAiLoading, setAnalyzeAiLoading] = useState(false);
  const [analyzeAiError, setAnalyzeAiError] = useState<string | null>(null);
  const [analyzeAiQuestion, setAnalyzeAiQuestion] = useState("");
  // AI conversation history (displayed in panel)
  const [aiConversation, setAiConversation] = useState<ConversationMessage[]>([]);
  const [aiLastSuggestions, setAiLastSuggestions] = useState<AiSuggestion[]>([]);
  // AI provider settings
  const [aiProvider, setAiProvider] = useState<AiProvider>("OpenAI");
  const [aiApiKey, setAiApiKey] = useState("");
  const [aiModel, setAiModel] = useState("");
  const [aiBaseUrl, setAiBaseUrl] = useState("");
  const [aiSettingsOpen, setAiSettingsOpen] = useState(false);
  const [helpPanelOpen, setHelpPanelOpen] = useState(false);
  const aiChatEndRef = useRef<HTMLDivElement>(null);
  const addLog = useCallback((entry: LogEntry) => {
    setLog((prev) => [entry, ...prev].slice(0, 100));
  }, []);

  // Auto-save session after notes or path nodes change (no-op if no session).
  const handleAutoSave = useCallback(async () => {
    if (!currentSession?.id) return;
    try {
      await invoke("cmd_save_session", { sessionId: currentSession.id });
    } catch {
      // ignore; user can save manually
    }
  }, [currentSession?.id]);

  // ── Initial load: get current session and list ──
  useEffect(() => {
    let cancelled = false;
    (async () => {
      try {
        const cur = await invoke<SessionInfo | null>("cmd_get_current_session");
        if (!cancelled && cur) setCurrentSession(cur);
        const list = await invoke<SessionInfo[]>("cmd_list_sessions");
        if (!cancelled) setSessions(list);
      } catch {
        // ignore
      }
    })();
    return () => {
      cancelled = true;
    };
  }, []);

  // ── When session changes: refetch stats, path nodes, and clear graph state ──
  useEffect(() => {
    if (!currentSession) {
      setStats({ entity_count: 0, relation_count: 0 });
      setSubgraph(null);
      setHighlightPaths(null);
      setExplorerNeighborhood(null);
      setSelectedNodeId(null);
      setNodeDetails(null);
      setHuntPathCount(0);
      setShowHuntTable(false);
      setPathNodeIds([]);
      setEntityTypesInGraph([]);
      setNotes([]);
      setMapPast([]);
      setMapFuture([]);
      return;
    }
    let cancelled = false;
    invoke<GraphStats>("cmd_get_graph_stats")
      .then((s) => {
        if (!cancelled) setStats(s);
      })
      .catch(() => {});
    invoke<string[]>("cmd_get_path_nodes")
      .then((ids) => {
        if (!cancelled) setPathNodeIds(ids);
      })
      .catch(() => {
        if (!cancelled) setPathNodeIds([]);
      });
    invoke<string[]>("cmd_get_entity_types_in_graph")
      .then((types) => {
        if (!cancelled) setEntityTypesInGraph(types);
      })
      .catch(() => {
        if (!cancelled) setEntityTypesInGraph([]);
      });
    invoke<Note[]>("cmd_get_notes")
      .then((list) => {
        if (!cancelled) setNotes(list);
      })
      .catch(() => {
        if (!cancelled) setNotes([]);
      });
    return () => {
      cancelled = true;
    };
  }, [currentSession?.id]);

  // Refetch entity types when graph size changes (e.g. after ingest) so dropdown stays in sync
  useEffect(() => {
    if (!currentSession) return;
    const total = stats.entity_count + stats.relation_count;
    if (total === 0) return;
    let cancelled = false;
    invoke<string[]>("cmd_get_entity_types_in_graph")
      .then((types) => {
        if (!cancelled) setEntityTypesInGraph(types);
      })
      .catch(() => {});
    return () => {
      cancelled = true;
    };
  }, [currentSession?.id, stats.entity_count, stats.relation_count]);

  // Keep ref in sync with current map state (for back/forward)
  useEffect(() => {
    mapStateRef.current = {
      mode,
      bottomTab,
      subgraph,
      highlightPaths,
      neighborhood: explorerNeighborhood,
      selectedNodeId,
      nodeDetails,
    };
  }, [mode, bottomTab, subgraph, highlightPaths, explorerNeighborhood, selectedNodeId, nodeDetails]);

  // When MCP calls expand or subgraph, HTTP API emits mcp-view-update; update live map to show that view
  useEffect(() => {
    let unlisten: (() => void) | undefined;
    (async () => {
      try {
        unlisten = await listen<Subgraph>("mcp-view-update", (event) => {
          const sg = event.payload;
          if (sg != null) {
            setMode("hunt");
            setSubgraph(sg);
            setHighlightPaths(null);
            setShowHuntTable(false);
            setExplorerNeighborhood(null);
            setSelectedNodeId(null);
            setNodeDetails(null);
            addLog({
              time: new Date().toLocaleTimeString("en-US", { hour12: false }),
              message: `Map updated from MCP: ${sg.nodes?.length ?? 0} nodes, ${sg.edges?.length ?? 0} edges (audit: external)`,
              level: "info",
            });
          }
        });
      } catch {
        // ignore if event API unavailable
      }
    })();
    return () => {
      unlisten?.();
    };
  }, [addLog]);

  // When MCP create_note is called via HTTP API, backend emits notes-changed; refresh notes list
  useEffect(() => {
    let unlisten: (() => void) | undefined;
    (async () => {
      try {
        unlisten = await listen("notes-changed", () => {
          addLog({ time: new Date().toLocaleTimeString("en-US", { hour12: false }), message: "Notes updated from MCP (audit: external)", level: "info" });
          invoke<Note[]>("cmd_get_notes")
            .then((list) => setNotes(list))
            .catch(() => setNotes([]));
        });
      } catch {
        // ignore if event API unavailable
      }
    })();
    return () => {
      unlisten?.();
    };
  }, [addLog]);

  const pushMapState = useCallback(() => {
    const s = mapStateRef.current;
    if (s) {
      setMapPast((prev) => [...prev, s]);
      setMapFuture([]);
    }
  }, []);

  const restoreMapState = useCallback((s: MapState) => {
    setMode(s.mode);
    setBottomTab(s.bottomTab);
    setSubgraph(s.subgraph);
    setHighlightPaths(s.highlightPaths);
    setExplorerNeighborhood(s.neighborhood);
    setSelectedNodeId(s.selectedNodeId);
    setNodeDetails(s.nodeDetails);
  }, []);

  const handleMapBack = useCallback(() => {
    if (mapPast.length === 0) return;
    const prev = mapPast[mapPast.length - 1];
    setMapPast((p) => p.slice(0, -1));
    const current = mapStateRef.current;
    if (current) setMapFuture((f) => [...f, current]);
    restoreMapState(prev);
    addLog({ time: new Date().toLocaleTimeString("en-US", { hour12: false }), message: "Navigation: Back", level: "info" });
  }, [mapPast.length, restoreMapState, addLog]);

  const handleMapForward = useCallback(() => {
    if (mapFuture.length === 0) return;
    const next = mapFuture[mapFuture.length - 1];
    setMapFuture((f) => f.slice(0, -1));
    const current = mapStateRef.current;
    if (current) setMapPast((p) => [...p, current]);
    restoreMapState(next);
    addLog({ time: new Date().toLocaleTimeString("en-US", { hour12: false }), message: "Navigation: Forward", level: "info" });
  }, [mapFuture.length, restoreMapState, addLog]);

  // ── Hunt mode handler ──
  const handleHuntResults = useCallback(
    async (results: HuntResults) => {
      pushMapState();
      setHuntPathCount(results.path_count);
      const t = new Date().toLocaleTimeString("en-US", { hour12: false });

      if (results.path_count === 0) {
        setSubgraph(null);
        setHighlightPaths(null);
        setShowHuntTable(false);
        addLog({ time: t, message: "Hunt: 0 paths", level: "info" });
        return;
      }

      // Large result sets: show table, let user pick paths to render
      if (results.path_count > 100) {
        setShowHuntTable(true);
        setSubgraph(null);
        setHighlightPaths(null);
        addLog({ time: t, message: `Hunt: ${results.path_count} paths (table view)`, level: "info" });
        return;
      }

      // Small result sets: fetch first page and render all in graph
      setShowHuntTable(false);
      try {
        const page = await invoke<PaginatedHuntResults>("cmd_get_hunt_page", {
          page: 0,
          pageSize: 100,
          minScore: null,
        });

        const allNodeIds = new Set<string>();
        const allPaths: string[][] = [];
        for (const sp of page.paths) {
          allPaths.push(sp.path);
          for (const nodeId of sp.path) {
            allNodeIds.add(nodeId);
          }
        }

        const sg = await invoke<Subgraph>("cmd_get_subgraph", {
          nodeIds: Array.from(allNodeIds),
        });
        setSubgraph(sg);
        setHighlightPaths(allPaths);
        addLog({ time: t, message: `Hunt: ${results.path_count} paths — graph updated`, level: "info" });
      } catch (e) {
        addLog({
          time: t,
          message: `Subgraph error: ${e}`,
          level: "error",
        });
      }
    },
    [addLog, pushMapState]
  );

  // ── Hunt mode: view a single path from the table ──
  const handleViewPath = useCallback(
    async (pathNodeIds: string[]) => {
      pushMapState();
      const t = new Date().toLocaleTimeString("en-US", { hour12: false });
      addLog({ time: t, message: `View path: ${pathNodeIds.length} nodes`, level: "info" });
      try {
        const sg = await invoke<Subgraph>("cmd_get_subgraph", {
          nodeIds: pathNodeIds,
        });
        setSubgraph(sg);
        setHighlightPaths([pathNodeIds]);
      } catch (e) {
        addLog({
          time: t,
          message: `Path view error: ${e}`,
          level: "error",
        });
      }
    },
    [addLog, pushMapState]
  );

  // ── Explorer mode: expand a node (Show neighbours: All or By Type) ──
  const handleExploreNode = useCallback(
    async (nodeId: string, filter?: ExpandFilter) => {
      pushMapState();
      try {
        const hood = await invoke<Neighborhood>("cmd_expand_node", {
          nodeId,
          maxHops: 1,
          maxNodes: 50,
          filter: filter ?? null,
        });
        setExplorerNeighborhood(hood);
        setSelectedNodeId(nodeId);

        // Also fetch details
        const details = await invoke<NodeDetails>("cmd_get_node_details", {
          nodeId,
        });
        setNodeDetails(details);
        const filterDesc = filter?.entity_types?.length ? ` (filter: ${filter.entity_types.join(", ")})` : "";
        addLog({
          time: new Date().toLocaleTimeString("en-US", { hour12: false }),
          message: `Expand: node ${nodeId}${filterDesc} — ${hood.nodes.length} nodes`,
          level: "info",
        });
      } catch (e) {
        const msg = e instanceof Error ? e.message : String(e);
        addLog({
          time: new Date().toLocaleTimeString("en-US", { hour12: false }),
          message: `Show neighbours error: ${msg}`,
          level: "error",
        });
      }
    },
    [addLog, pushMapState]
  );

  // ── Click a node to show details in the lateral panel (works in both Hunt and Explorer) ──
  const handleNodeClick = useCallback(
    async (nodeId: string) => {
      setSelectedNodeId(nodeId);
      addLog({ time: new Date().toLocaleTimeString("en-US", { hour12: false }), message: `Selected node: ${nodeId}`, level: "info" });
      try {
        const details = await invoke<NodeDetails>("cmd_get_node_details", {
          nodeId,
        });
        setNodeDetails(details);
      } catch (e) {
        console.error("Failed to get node details:", e);
      }
    },
    [addLog]
  );

  // ── Explorer mode: double-click to expand ──
  const handleNodeDoubleClick = useCallback(
    async (nodeId: string) => {
      if (mode !== "explore") return;
      handleExploreNode(nodeId);
    },
    [mode, handleExploreNode]
  );

  // Context menu Expand/Center/Show neighbours: if in Hunt mode, switch to Explorer first so the graph updates
  const handleNodeContextExpandOrShow = useCallback(
    (nodeId: string, filter?: ExpandFilter) => {
      if (mode !== "explore") {
        setBottomTab("explore");
        setMode("explore");
        setSubgraph(null);
        setHighlightPaths(null);
      }
      handleExploreNode(nodeId, filter);
    },
    [mode, handleExploreNode]
  );

  // ── Types Available: show type or single node on map ──
  const handleShowTypeOnMap = useCallback(
    async (nodeIds: string[]) => {
      pushMapState();
      setBottomTab("hunt");
      setMode("hunt");
      setSelectedNodeId(null);
      setNodeDetails(null);
      setExplorerNeighborhood(null);
      setHighlightPaths(null);
      if (nodeIds.length === 0) {
        addLog({
          time: new Date().toLocaleTimeString("en-US", { hour12: false }),
          message: "No nodes found for this relation type.",
          level: "info",
        });
        return;
      }
      try {
        const sg = await invoke<Subgraph>("cmd_get_subgraph", {
          nodeIds,
        });
        setSubgraph(sg);
        setHighlightPaths([nodeIds]);
        addLog({
          time: new Date().toLocaleTimeString("en-US", { hour12: false }),
          message: `Showing ${nodeIds.length} nodes with this relation on map`,
          level: "info",
        });
      } catch (e) {
        addLog({
          time: new Date().toLocaleTimeString("en-US", { hour12: false }),
          message: `Failed to show on map: ${e}`,
          level: "error",
        });
      }
    },
    [addLog, pushMapState]
  );

  const handleShowNodeOnMap = useCallback(
    (nodeId: string) => {
      addLog({ time: new Date().toLocaleTimeString("en-US", { hour12: false }), message: `Show on map: node ${nodeId}`, level: "info" });
      setBottomTab("explore");
      setMode("explore");
      setSubgraph(null);
      setHighlightPaths(null);
      handleExploreNode(nodeId); // handleExploreNode pushes current state
    },
    [handleExploreNode, addLog]
  );

  /** Show on map the clicked node and only its neighbours of the given entity type (Explorer + type filter). */
  const handleShowNeighbourTypeOnMap = useCallback(
    (nodeId: string, entityType: string) => {
      if (mode !== "explore") {
        setBottomTab("explore");
        setMode("explore");
        setSubgraph(null);
        setHighlightPaths(null);
      }
      handleExploreNode(nodeId, { entity_types: [entityType] });
    },
    [mode, handleExploreNode]
  );

  // ── Path nodes: add/remove pinned nodes (persisted with session) ──
  const handleAddToPathNodes = useCallback(async (nodeId: string) => {
    try {
      await invoke("cmd_add_path_node", { nodeId });
      setPathNodeIds((prev) => (prev.includes(nodeId) ? prev : [...prev, nodeId]));
      await handleAutoSave();
      addLog({ time: new Date().toLocaleTimeString("en-US", { hour12: false }), message: `Path node added: ${nodeId}`, level: "info" });
    } catch (e) {
      addLog({
        time: new Date().toLocaleTimeString("en-US", { hour12: false }),
        message: `Failed to add path node: ${e}`,
        level: "error",
      });
    }
  }, [addLog, handleAutoSave]);

  const handleRemoveFromPathNodes = useCallback(async (nodeId: string) => {
    try {
      await invoke("cmd_remove_path_node", { nodeId });
      setPathNodeIds((prev) => prev.filter((id) => id !== nodeId));
      await handleAutoSave();
      addLog({ time: new Date().toLocaleTimeString("en-US", { hour12: false }), message: `Path node removed: ${nodeId}`, level: "info" });
    } catch (e) {
      addLog({
        time: new Date().toLocaleTimeString("en-US", { hour12: false }),
        message: `Failed to remove path node: ${e}`,
        level: "error",
      });
    }
  }, [addLog, handleAutoSave]);

  // ── Mode switch (Hunt / Explorer tabs; Events view doesn't change graph mode) ──
  const handleBottomTabChange = useCallback((tab: BottomTab) => {
    setBottomTab(tab);
    if (tab === "hunt") {
      setMode("hunt");
      setSelectedNodeId(null);
      setNodeDetails(null);
      setShowHuntTable(false);
      setHuntPathCount(0);
      setExplorerNeighborhood(null);
    } else if (tab === "explore") {
      setMode("explore");
      setSubgraph(null);
      setHighlightPaths(null);
    }
    const tabLabels: Record<BottomTab, string> = { hunt: "Hunt", explore: "Explorer", events: "Events", heatmap: "Heatmap", timeline: "Timeline" };
    addLog({ time: new Date().toLocaleTimeString("en-US", { hour12: false }), message: `Switched to ${tabLabels[tab]}`, level: "info" });
  }, [addLog]);

  // Click path node in list: Explorer = load neighborhood; Hunt = pan/zoom to center node
  const handlePathNodeFocus = useCallback(
    (nodeId: string) => {
      if (mode === "explore") {
        handleExploreNode(nodeId);
      } else {
        addLog({ time: new Date().toLocaleTimeString("en-US", { hour12: false }), message: `Centered on node: ${nodeId}`, level: "info" });
        setCenterNodeId(nodeId);
      }
    },
    [mode, handleExploreNode, addLog]
  );

  const handleResizeStart = useCallback((e: React.MouseEvent) => {
    e.preventDefault();
    const startY = e.clientY;
    const startHeight = bottomPanelHeight;
    const onMove = (e2: MouseEvent) => {
      const delta = startY - e2.clientY;
      setBottomPanelHeight((_) => Math.min(600, Math.max(120, startHeight + delta)));
    };
    const onUp = () => {
      document.removeEventListener("mousemove", onMove);
      document.removeEventListener("mouseup", onUp);
      document.body.style.cursor = "";
      document.body.style.userSelect = "";
    };
    document.body.style.cursor = "ns-resize";
    document.body.style.userSelect = "none";
    document.addEventListener("mousemove", onMove);
    document.addEventListener("mouseup", onUp);
  }, [bottomPanelHeight]);

  const sendAiMessage = useCallback(async (message: string) => {
    // Show user message immediately + thinking indicator
    const now = Math.floor(Date.now() / 1000);
    setAiConversation((prev) => [
      ...prev,
      { role: "user", content: message, timestamp: now },
    ]);
    setAiLastSuggestions([]);
    setAnalyzeAiLoading(true);
    setAnalyzeAiError(null);
    setAnalyzeAiQuestion("");
    setTimeout(() => aiChatEndRef.current?.scrollIntoView({ behavior: "smooth" }), 50);
    try {
      const response = await invoke<AiAnalysisResponse>("cmd_ai_chat", {
        userMessage: message,
      });
      const nowDone = Math.floor(Date.now() / 1000);
      setAiConversation((prev) => [
        ...prev,
        { role: "assistant", content: response.text, timestamp: nowDone },
      ]);
      setAiLastSuggestions(response.suggestions || []);
      setTimeout(() => aiChatEndRef.current?.scrollIntoView({ behavior: "smooth" }), 100);
    } catch (e) {
      setAnalyzeAiError(String(e));
    } finally {
      setAnalyzeAiLoading(false);
    }
  }, []);

  const runAnalyzeAi = useCallback(async () => {
    const message = analyzeAiQuestion.trim() || "Analyze the graph for suspicious activity.";
    sendAiMessage(message);
  }, [analyzeAiQuestion, sendAiMessage]);

  const clearAiConversation = useCallback(async () => {
    try {
      await invoke("cmd_ai_clear_conversation");
    } catch { /* ignore */ }
    setAiConversation([]);
    setAiLastSuggestions([]);
  }, []);

  const saveAiProvider = useCallback(async () => {
    try {
      const detected = await invoke<string>("cmd_ai_set_provider", {
        provider: aiProvider.toLowerCase(),
        apiKey: aiApiKey,
        model: aiModel || null,
        baseUrl: aiBaseUrl || null,
      });
      if (detected && detected !== "none") {
        setAiProvider(detected as AiProvider);
      }
      setAiSettingsOpen(false);
      addLog({ time: new Date().toLocaleTimeString(), message: `AI provider set to ${detected || aiProvider}`, level: "success" });
    } catch (e) {
      setAnalyzeAiError(String(e));
    }
  }, [aiProvider, aiApiKey, aiModel, aiBaseUrl, addLog]);

  const handleAiSuggestion = useCallback(async (suggestion: AiSuggestion) => {
    // Feed all suggestions back through the agentic chat so the AI uses tools and shows results
    const message =
      suggestion.action === "expand_node"
        ? `Expand node "${suggestion.target_id}" and analyze its connections.`
        : suggestion.action === "run_hypothesis"
        ? `Run this hunt hypothesis: ${suggestion.target_id}`
        : suggestion.action === "search_entities"
        ? `Search for entities matching "${suggestion.target_id}"`
        : suggestion.label;
    sendAiMessage(message);
  }, [sendAiMessage]);

  const currentGraphSummary =
    mode === "hunt"
      ? subgraph
        ? `${subgraph.nodes.length} nodes, ${subgraph.edges.length} edges`
        : null
      : explorerNeighborhood
        ? `${explorerNeighborhood.nodes.length} nodes, ${explorerNeighborhood.edges.length} edges`
        : null;

  const leftPanelCount = leftMenuOpen !== null ? 1 : 0;
  const leftPanelWidth = leftPanelCount * 280;
  const rightPanelCount = rightMenuOpen !== null ? 1 : 0;
  const rightPanelWidth = rightPanelCount * 280;

  // When no session is selected, show the welcome page (session selector + lateral guide)
  if (!currentSession) {
    return (
      <div className="app-container app-container--welcome">
        <div className="app-top-bar">
          <div className="app-logo">
            <img src="/Logo.png" alt="" height="28" />
            <span className="app-logo-title">Graph Hunter</span>
          </div>
          <button
            type="button"
            className="app-toolbar-btn app-toolbar-btn-icon app-help-btn"
            onClick={() => setHelpPanelOpen(true)}
            title="Guide (how to use & about)"
            aria-label="Open guide"
          >
            <HelpCircle size={18} />
          </button>
        </div>
        {sessionError && (
          <div className="session-error" role="alert">
            {sessionError}
          </div>
        )}
        {helpPanelOpen && (
          <HelpPanel onClose={() => setHelpPanelOpen(false)} />
        )}
        <div className="welcome-page-wrapper">
          <WelcomePage
            currentSession={currentSession}
            sessions={sessions}
            onSessionChange={setCurrentSession}
            onSessionsListChange={setSessions}
            onError={setSessionError}
            onLog={addLog}
          />
        </div>
      </div>
    );
  }

  return (
    <div
      className="app-container"
      style={
        {
          "--bottom-panel-height": `${bottomPanelHeight}px`,
          "--left-panel-width": leftPanelCount === 0 ? "0px" : `${leftPanelWidth}px`,
          "--right-panel-width": rightPanelCount === 0 ? "0px" : `${rightPanelWidth}px`,
        } as React.CSSProperties
      }
    >
      <div className="app-top-bar">
        <div className="app-logo">
          <img src="/Logo.png" alt="" height="28" />
          <span className="app-logo-title">Graph Hunter</span>
        </div>
        <SessionSelector
          currentSession={currentSession}
          sessions={sessions}
          onSessionChange={setCurrentSession}
          onSessionsListChange={setSessions}
          onError={setSessionError}
          onLog={addLog}
        />
        <div className="app-toolbar">
          <button
            type="button"
            className="app-toolbar-btn app-toolbar-btn-icon"
            onClick={handleMapBack}
            disabled={mapPast.length === 0}
            title="Back (previous map view)"
            aria-label="Back"
          >
            <ChevronLeft size={18} />
          </button>
          <button
            type="button"
            className="app-toolbar-btn app-toolbar-btn-icon"
            onClick={handleMapForward}
            disabled={mapFuture.length === 0}
            title="Forward (next map view)"
            aria-label="Forward"
          >
            <ChevronRight size={18} />
          </button>
          <button
            type="button"
            className={`app-toolbar-btn ${leftMenuOpen === "datasets" ? "active" : ""}`}
            onClick={() => setLeftMenuOpen((o) => (o === "datasets" ? null : "datasets"))}
            title={leftMenuOpen === "datasets" ? "Hide Datasets" : "Show Datasets"}
          >
            <Database size={14} style={{ marginRight: 4 }} />
            Datasets
          </button>
          <button
            type="button"
            className={`app-toolbar-btn ${leftMenuOpen === "activity" ? "active" : ""}`}
            onClick={() => setLeftMenuOpen((o) => (o === "activity" ? null : "activity"))}
            title={leftMenuOpen === "activity" ? "Hide Activity Log" : "Show Activity Log"}
          >
            <Activity size={14} style={{ marginRight: 4 }} />
            Activity
          </button>
          <button
            type="button"
            className={`app-toolbar-btn ${leftMenuOpen === "metrics" ? "active" : ""}`}
            onClick={() => setLeftMenuOpen((o) => (o === "metrics" ? null : "metrics"))}
            title={leftMenuOpen === "metrics" ? "Hide Graph Metrics" : "Show Graph Metrics"}
          >
            <BarChart3 size={14} style={{ marginRight: 4 }} />
            Metrics
          </button>
          <button
            type="button"
            className={`app-toolbar-btn ${rightMenuOpen === "pathNodes" ? "active" : ""}`}
            onClick={() => setRightMenuOpen((o) => (o === "pathNodes" ? null : "pathNodes"))}
            title={rightMenuOpen === "pathNodes" ? "Close Path Nodes" : "Open Path Nodes"}
          >
            Path Nodes
            {pathNodeIds.length > 0 && (
              <span className="app-toolbar-badge">{pathNodeIds.length}</span>
            )}
          </button>
          <button
            type="button"
            className={`app-toolbar-btn ${rightMenuOpen === "notes" ? "active" : ""}`}
            onClick={() => setRightMenuOpen((o) => (o === "notes" ? null : "notes"))}
            title={rightMenuOpen === "notes" ? "Close Notes" : "Open Notes"}
          >
            Notes
            {notes.length > 0 && (
              <span className="app-toolbar-badge">{notes.length}</span>
            )}
          </button>
          <button
            type="button"
            className={`app-toolbar-btn ${analyzeAiOpen ? "active" : ""}`}
            onClick={() => {
              setAnalyzeAiOpen((o) => !o);
              if (!analyzeAiOpen) {
                setAnalyzeAiError(null);
              }
            }}
            title="Analyze current graph with AI (malicious? next node to expand?)"
          >
            <Sparkles size={14} style={{ marginRight: 4 }} />
            Analysis
          </button>
          <button
            type="button"
            className="app-toolbar-btn app-toolbar-btn-icon app-help-btn"
            onClick={() => setHelpPanelOpen(true)}
            title="Guide (how to use & about)"
            aria-label="Open guide"
          >
            <HelpCircle size={18} />
          </button>
        </div>
      </div>
      {sessionError && (
        <div className="session-error" role="alert">
          {sessionError}
        </div>
      )}
      <div className="app-left-menus" style={{ width: leftPanelCount === 0 ? 0 : leftPanelWidth }}>
        {leftMenuOpen === "datasets" && (
          <DatasetsLeftPanel
            currentSessionId={currentSession?.id ?? null}
            onSessionCreated={(session) => {
              setCurrentSession(session);
              setSessions((prev) => (prev.some((s) => s.id === session.id) ? prev : [...prev, session]));
            }}
            stats={stats}
            onStatsUpdate={setStats}
            onLog={addLog}
            onClose={() => setLeftMenuOpen(null)}
            onShowTypeOnMap={handleShowTypeOnMap}
            onShowNodeOnMap={handleShowNodeOnMap}
          />
        )}
        {leftMenuOpen === "activity" && (
          <ActivityLogLeftPanel log={log} onClose={() => setLeftMenuOpen(null)} />
        )}
        {leftMenuOpen === "metrics" && (
          <GraphMetricsLeftPanel
            currentSessionId={currentSession?.id ?? null}
            stats={stats}
            onStatsUpdate={setStats}
            onLog={addLog}
            onClose={() => setLeftMenuOpen(null)}
            onShowTypeOnMap={handleShowTypeOnMap}
            onShowNodeOnMap={handleShowNodeOnMap}
          />
        )}
      </div>
      <GraphCanvas
        subgraph={subgraph}
        highlightPaths={highlightPaths}
        explorerMode={mode === "explore"}
        neighborhood={explorerNeighborhood}
        selectedNodeId={selectedNodeId}
        pathNodeIds={pathNodeIds}
        centerNodeId={centerNodeId}
        onCenterDone={() => setCenterNodeId(null)}
        onNodeClick={handleNodeClick}
        onNodeDoubleClick={handleNodeDoubleClick}
        onNodeContextExpand={handleNodeContextExpandOrShow}
        onNodeContextCenter={handleNodeContextExpandOrShow}
        onNodeContextCopy={(nodeId) => {
          navigator.clipboard.writeText(nodeId);
        }}
        onNodeContextShowNeighbours={handleNodeContextExpandOrShow}
        entityTypesInGraph={entityTypesInGraph}
        onNodeContextAddToPathNodes={handleAddToPathNodes}
        onNodeContextRemoveFromPathNodes={handleRemoveFromPathNodes}
      >
        {showHuntTable && mode === "hunt" && (
          <HuntResultsTable
            totalPaths={huntPathCount}
            onViewPath={handleViewPath}
            onLog={addLog}
          />
        )}
      </GraphCanvas>

      {/* Resize handle for bottom panel */}
      <div
        className="panel-bottom-resize-handle"
        onMouseDown={handleResizeStart}
        role="separator"
        aria-label="Resize bottom panel"
      />

      {/* Bottom panel with mode tabs */}
      <div className="panel panel-bottom-container">
        <div className="mode-tabs">
          <button
            className={`mode-tab ${bottomTab === "hunt" ? "active" : ""}`}
            onClick={() => handleBottomTabChange("hunt")}
          >
            Hunt Mode
          </button>
          <button
            className={`mode-tab ${bottomTab === "explore" ? "active" : ""}`}
            onClick={() => handleBottomTabChange("explore")}
          >
            Explorer Mode
          </button>
          <button
            className={`mode-tab ${bottomTab === "events" ? "active" : ""}`}
            onClick={() => handleBottomTabChange("events")}
          >
            Events view
          </button>
          <button
            className={`mode-tab ${bottomTab === "heatmap" ? "active" : ""}`}
            onClick={() => handleBottomTabChange("heatmap")}
          >
            Heatmap
          </button>
          <button
            className={`mode-tab ${bottomTab === "timeline" ? "active" : ""}`}
            onClick={() => handleBottomTabChange("timeline")}
          >
            Timeline
          </button>
        </div>

        {bottomTab === "hunt" && (
          <HypothesisBuilder
            onHuntResults={handleHuntResults}
            onLog={addLog}
          />
        )}
        {bottomTab === "explore" && (
          <ExplorerPanel
            onExploreNode={handleExploreNode}
            neighborhood={explorerNeighborhood}
            onLog={addLog}
          />
        )}
        {bottomTab === "events" && (
          <EventsViewPanel selectedNodeId={selectedNodeId} />
        )}
        {bottomTab === "heatmap" && (
          <HeatmapView
            statsKey={stats.entity_count + stats.relation_count}
            onShowRelationOnMap={handleShowTypeOnMap}
            onLog={addLog}
          />
        )}
        {bottomTab === "timeline" && (
          <TimelineView
            statsKey={stats.entity_count + stats.relation_count}
            onShowTypeOnMap={handleShowTypeOnMap}
          />
        )}
      </div>

      {/* Right menus (only one at a time: Path Nodes or Notes) */}
      <div className="app-right-menus" style={{ width: rightPanelCount === 0 ? 0 : rightPanelWidth }}>
        {rightMenuOpen === "pathNodes" && (
          <div className="left-menu-panel right-menu-panel" role="region" aria-label="Path Nodes">
            <div className="left-menu-panel-header">
              <span className="left-menu-panel-title"><MapPin size={14} /> Path Nodes</span>
              <button
                type="button"
                className="left-menu-panel-close"
                onClick={() => setRightMenuOpen(null)}
                title="Hide Path Nodes"
                aria-label="Hide Path Nodes menu"
              >
                <X size={14} />
              </button>
            </div>
            <div className="left-menu-panel-content">
              <PathNodesPanel
                pathNodeIds={pathNodeIds}
                onRemove={handleRemoveFromPathNodes}
                onFocusNode={handlePathNodeFocus}
              />
            </div>
          </div>
        )}
        {rightMenuOpen === "notes" && (
          <div className="left-menu-panel right-menu-panel" role="region" aria-label="Notes">
            <div className="left-menu-panel-header">
              <span className="left-menu-panel-title"><FileText size={14} /> Notes</span>
              <button
                type="button"
                className="left-menu-panel-close"
                onClick={() => setRightMenuOpen(null)}
                title="Hide Notes"
                aria-label="Hide Notes menu"
              >
                <X size={14} />
              </button>
            </div>
            <div className="left-menu-panel-content">
              <NotesPanel
                notes={notes}
                selectedNodeId={selectedNodeId}
                onNotesChange={setNotes}
                onAutoSave={handleAutoSave}
                onShowNodeOnMap={(nodeId) => handleNodeContextExpandOrShow(nodeId)}
              />
            </div>
          </div>
        )}
      </div>

      {/* Node detail sidebar (shown when a node is selected, in Hunt or Explorer) */}
      {nodeDetails && (
        <NodeDetailPanel
          details={nodeDetails}
          onClose={() => {
            addLog({ time: new Date().toLocaleTimeString("en-US", { hour12: false }), message: "Cleared selection", level: "info" });
            setNodeDetails(null);
            setSelectedNodeId(null);
          }}
          onExpand={handleExploreNode}
          onSetCenter={handleExploreNode}
          onShowNeighbourTypeOnMap={handleShowNeighbourTypeOnMap}
        />
      )}

      {/* Guide panel (slide-out, ? button in header) */}
      {helpPanelOpen && (
        <HelpPanel onClose={() => setHelpPanelOpen(false)} />
      )}

      {/* AI Analysis Panel (slide-out) */}
      {analyzeAiOpen && (
        <div
          style={{
            position: "fixed",
            top: 0,
            right: 0,
            bottom: 0,
            width: 420,
            background: "var(--bg-primary)",
            borderLeft: "1px solid var(--border)",
            zIndex: 1000,
            display: "flex",
            flexDirection: "column",
            boxShadow: "-4px 0 12px rgba(0,0,0,0.3)",
          }}
        >
          {/* Header */}
          <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", padding: "10px 12px", borderBottom: "1px solid var(--border)" }}>
            <h3 style={{ margin: 0, fontSize: 14, display: "flex", alignItems: "center", gap: 6 }}>
              <Sparkles size={16} /> AI Analysis
            </h3>
            <div style={{ display: "flex", gap: 6 }}>
              <button type="button" className="btn btn-sm" onClick={() => setAiSettingsOpen((o) => !o)} title="AI Settings" style={{ fontSize: 11 }}>
                Settings
              </button>
              <button type="button" className="btn btn-sm" onClick={clearAiConversation} title="Clear conversation" style={{ fontSize: 11 }}>
                Clear
              </button>
              <button type="button" className="btn btn-sm" onClick={() => setAnalyzeAiOpen(false)}>
                <X size={14} />
              </button>
            </div>
          </div>

          {/* Settings panel (collapsible) */}
          {aiSettingsOpen && (
            <div style={{ padding: "8px 12px", borderBottom: "1px solid var(--border)", background: "var(--bg-secondary)" }}>
              <div style={{ display: "flex", gap: 8, marginBottom: 6 }}>
                <label style={{ fontSize: 11, color: "var(--text-secondary)", flex: 1 }}>
                  Provider
                  <select
                    value={aiProvider}
                    onChange={(e) => setAiProvider(e.target.value as AiProvider)}
                    style={{ width: "100%", fontSize: 11, padding: "3px 4px", background: "var(--bg-primary)", color: "var(--text-primary)", border: "1px solid var(--border)", borderRadius: 3, marginTop: 2 }}
                  >
                    <option value="OpenAI">OpenAI</option>
                    <option value="Anthropic">Anthropic</option>
                    <option value="Google">Google</option>
                  </select>
                </label>
                <label style={{ fontSize: 11, color: "var(--text-secondary)", flex: 1 }}>
                  Model (optional)
                  <input
                    value={aiModel}
                    onChange={(e) => setAiModel(e.target.value)}
                    placeholder={aiProvider === "OpenAI" ? "gpt-4o" : aiProvider === "Anthropic" ? "claude-sonnet-4-20250514" : "gemini-2.0-flash"}
                    style={{ width: "100%", fontSize: 11, padding: "3px 4px", background: "var(--bg-primary)", color: "var(--text-primary)", border: "1px solid var(--border)", borderRadius: 3, marginTop: 2, boxSizing: "border-box" }}
                  />
                </label>
              </div>
              <label style={{ fontSize: 11, color: "var(--text-secondary)" }}>
                API Key
                <input
                  type="password"
                  value={aiApiKey}
                  onChange={(e) => {
                    const key = e.target.value;
                    setAiApiKey(key);
                    // Auto-detect provider from key format
                    if (key.startsWith("sk-ant-")) setAiProvider("Anthropic");
                    else if (key.startsWith("sk-")) setAiProvider("OpenAI");
                    else if (key.startsWith("AI")) setAiProvider("Google");
                  }}
                  placeholder="sk-..."
                  style={{ width: "100%", fontSize: 11, padding: "3px 4px", background: "var(--bg-primary)", color: "var(--text-primary)", border: "1px solid var(--border)", borderRadius: 3, marginTop: 2, boxSizing: "border-box" }}
                />
              </label>
              <label style={{ fontSize: 11, color: "var(--text-secondary)", marginTop: 4, display: "block" }}>
                Base URL (optional)
                <input
                  value={aiBaseUrl}
                  onChange={(e) => setAiBaseUrl(e.target.value)}
                  placeholder="Leave empty for default"
                  style={{ width: "100%", fontSize: 11, padding: "3px 4px", background: "var(--bg-primary)", color: "var(--text-primary)", border: "1px solid var(--border)", borderRadius: 3, marginTop: 2, boxSizing: "border-box" }}
                />
              </label>
              <button type="button" className="btn btn-primary" onClick={saveAiProvider} style={{ marginTop: 8, fontSize: 11 }}>
                Save
              </button>
            </div>
          )}

          {/* Context info */}
          {currentGraphSummary && (
            <div style={{ padding: "6px 12px", fontSize: 11, color: "var(--text-secondary)", borderBottom: "1px solid var(--border)" }}>
              View: {currentGraphSummary}
              {selectedNodeId && " · Node: " + (selectedNodeId.length > 20 ? "..." + selectedNodeId.slice(-17) : selectedNodeId)}
            </div>
          )}

          {/* Conversation messages */}
          <div style={{ flex: 1, overflow: "auto", padding: "8px 12px" }}>
            {aiConversation.length === 0 && !analyzeAiError && (
              <p style={{ fontSize: 12, color: "var(--text-secondary)", textAlign: "center", marginTop: 40 }}>
                {stats.entity_count > 0
                  ? "Ask a question about the graph — the AI will search it for you..."
                  : "Load data first, then ask questions about the graph."}
              </p>
            )}
            {aiConversation.map((msg, i) => (
              <div
                key={i}
                style={{
                  marginBottom: 10,
                  display: "flex",
                  flexDirection: "column",
                  alignItems: msg.role === "user" ? "flex-end" : "flex-start",
                }}
              >
                <span style={{ fontSize: 10, color: "var(--text-secondary)", marginBottom: 2 }}>
                  {msg.role === "user" ? "You" : "AI"}
                </span>
                <div
                  style={{
                    padding: "8px 10px",
                    borderRadius: 8,
                    fontSize: 12,
                    whiteSpace: "pre-wrap",
                    maxWidth: "90%",
                    background: msg.role === "user" ? "var(--accent)" : "var(--bg-secondary)",
                    color: msg.role === "user" ? "#fff" : "var(--text-primary)",
                  }}
                >
                  {msg.content}
                </div>
              </div>
            ))}
            {/* Thinking indicator */}
            {analyzeAiLoading && (
              <div style={{ display: "flex", alignItems: "center", gap: 8, marginBottom: 10 }}>
                <span style={{ fontSize: 10, color: "var(--text-secondary)" }}>AI</span>
                <div style={{
                  padding: "8px 14px",
                  borderRadius: 8,
                  background: "var(--bg-secondary)",
                  fontSize: 12,
                  color: "var(--text-secondary)",
                  display: "flex",
                  alignItems: "center",
                  gap: 4,
                }}>
                  <span className="ai-thinking-dots">
                    <span>●</span><span>●</span><span>●</span>
                  </span>
                  <span style={{ marginLeft: 4 }}>Querying graph & analyzing...</span>
                </div>
              </div>
            )}
            {/* Suggestion buttons after last AI message */}
            {aiLastSuggestions.length > 0 && (
              <div style={{ display: "flex", flexWrap: "wrap", gap: 6, marginBottom: 10 }}>
                {aiLastSuggestions.map((s, i) => (
                  <button
                    key={i}
                    type="button"
                    className="btn btn-sm"
                    onClick={() => handleAiSuggestion(s)}
                    style={{ fontSize: 11, display: "flex", alignItems: "center", gap: 4 }}
                    title={`${s.action}: ${s.target_id}`}
                  >
                    {s.action === "expand_node" ? <ChevronRight size={12} /> : <Sparkles size={12} />}
                    {s.label.length > 40 ? s.label.slice(0, 37) + "..." : s.label}
                  </button>
                ))}
              </div>
            )}
            {analyzeAiError && (
              <div style={{ color: "var(--danger)", fontSize: 11, marginBottom: 8 }}>{analyzeAiError}</div>
            )}
            <div ref={aiChatEndRef} />
          </div>

          {/* Input area */}
          {stats.entity_count > 0 && (
            <div style={{ padding: "8px 12px", borderTop: "1px solid var(--border)", display: "flex", gap: 6 }}>
              <input
                value={analyzeAiQuestion}
                onChange={(e) => setAnalyzeAiQuestion(e.target.value)}
                onKeyDown={(e) => { if (e.key === "Enter" && !analyzeAiLoading) runAnalyzeAi(); }}
                placeholder="Ask about the graph..."
                disabled={analyzeAiLoading}
                style={{
                  flex: 1,
                  fontSize: 12,
                  padding: "6px 8px",
                  background: "var(--bg-secondary)",
                  border: "1px solid var(--border)",
                  borderRadius: 4,
                  color: "var(--text-primary)",
                  boxSizing: "border-box",
                }}
              />
              <button
                type="button"
                className="btn btn-primary"
                onClick={runAnalyzeAi}
                disabled={analyzeAiLoading}
                style={{ fontSize: 12 }}
              >
                {analyzeAiLoading ? "..." : "Send"}
              </button>
            </div>
          )}
        </div>
      )}
    </div>
  );
}

export default App;
