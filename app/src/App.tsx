import { lazy, Suspense, useCallback, useEffect, useRef } from "react";
import { listen } from "@tauri-apps/api/event";
import { invoke, errorMessage } from "./lib/tauri";
// Eager: everything on the initial-render path. The Welcome page, the left-
// side panels, the graph canvas and the Explorer bottom panel (default tab)
// must be in the main bundle so the first paint has no flicker.
import DatasetsLeftPanel from "./components/DatasetsLeftPanel";
import ActivityLogContainer from "./components/ActivityLogContainer";
import GraphMetricsLeftPanel from "./components/GraphMetricsLeftPanel";
import SessionSelector from "./components/SessionSelector";
import WelcomePage from "./components/WelcomePage";
import GraphCanvas from "./components/GraphCanvas";
import ExplorerPanel from "./components/ExplorerPanel";
import PathNodesPanel from "./components/PathNodesPanel";
import { SectionLoader } from "./components/ui";
// Lazy: only mounted when the user opens a specific tab, slide-out or
// modal. Each becomes its own chunk so the initial bundle stays small.
const HelpPanel = lazy(() => import("./components/HelpPanel"));
const HypothesisBuilder = lazy(() => import("./components/HypothesisBuilder"));
const NotesPanel = lazy(() => import("./components/NotesPanel"));
const NodeDetailPanel = lazy(() => import("./components/NodeDetailPanel"));
const HuntResultsTable = lazy(() => import("./components/HuntResultsTable"));
const EventsViewPanel = lazy(() => import("./components/EventsViewPanel"));
const HeatmapView = lazy(() => import("./components/HeatmapView"));
const TimelineView = lazy(() => import("./components/TimelineView"));
import { ChevronLeft, ChevronRight, Sparkles, Database, Activity, BarChart3, X, MapPin, FileText, HelpCircle } from "lucide-react";
import { useAppState, useAppDispatch } from "./context/AppStateContext";
import { useLogDispatch, LogProvider } from "./context/LogContext";
import { useNotifications } from "./hooks/useNotifications";
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
import type { MapState, BottomTab } from "./context/AppStateContext";
import "./App.css";

import { useState, type ReactNode } from "react";

/**
 * Suspense boundary used for every lazy-loaded chunk in this file.
 *
 * Using a single wrapper keeps the JSX tidy and guarantees a consistent
 * fallback (a centred spinner) whenever React needs to stream a chunk in.
 * Chunks typically resolve in a single animation frame on a warm cache,
 * so the fallback is rarely visible — but we still want a graceful state
 * for first-time loads and cold tabs.
 */
function LazyBoundary({ children }: { children: ReactNode }) {
  return <Suspense fallback={<SectionLoader />}>{children}</Suspense>;
}

function AppInner() {
  const state = useAppState();
  const dispatch = useAppDispatch();
  // Log dispatch lives in its own context so addLog() does not re-render
  // App tree when the log grows — see context/LogContext.tsx.
  const logDispatch = useLogDispatch();
  const { addNotification } = useNotifications();

  const {
    stats,
    mode,
    bottomTab,
    currentSession,
    sessions,
    sessionError,
    subgraph,
    highlightPaths,
    huntPathCount,
    showHuntTable,
    selectedNodeId,
    nodeDetails,
    explorerNeighborhood,
    pathNodeIds,
    entityTypesInGraph,
    rightMenuOpen,
    leftMenuOpen,
    notes,
    centerNodeId,
    bottomPanelHeight,
    mapPast,
    mapFuture,
  } = state;

  // AI state stays local (not part of core app state to keep context focused)
  const [analyzeAiOpen, setAnalyzeAiOpen] = useState(false);
  const [analyzeAiLoading, setAnalyzeAiLoading] = useState(false);
  const [analyzeAiError, setAnalyzeAiError] = useState<string | null>(null);
  const [analyzeAiQuestion, setAnalyzeAiQuestion] = useState("");
  const [aiConversation, setAiConversation] = useState<ConversationMessage[]>([]);
  const [aiLastSuggestions, setAiLastSuggestions] = useState<AiSuggestion[]>([]);
  const [aiProvider, setAiProvider] = useState<AiProvider>("OpenAI");
  const [aiApiKey, setAiApiKey] = useState("");
  const [aiModel, setAiModel] = useState("");
  const [aiBaseUrl, setAiBaseUrl] = useState("");
  const [aiSettingsOpen, setAiSettingsOpen] = useState(false);
  const [helpPanelOpen, setHelpPanelOpen] = useState(false);
  const aiChatEndRef = useRef<HTMLDivElement>(null);

  const mapStateRef = useRef<MapState | null>(null);

  const addLog = useCallback(
    (entry: LogEntry) => {
      logDispatch({ type: "ADD_LOG", payload: entry });
    },
    [logDispatch]
  );

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
        if (!cancelled && cur) dispatch({ type: "SET_CURRENT_SESSION", payload: cur });
        const list = await invoke<SessionInfo[]>("cmd_list_sessions");
        if (!cancelled) dispatch({ type: "SET_SESSIONS", payload: list });
      } catch {
        // ignore
      }
    })();
    return () => {
      cancelled = true;
    };
  }, [dispatch]);

  // ── When session changes: refetch stats, path nodes, and clear graph state ──
  useEffect(() => {
    if (!currentSession) {
      dispatch({ type: "CLEAR_SESSION_STATE" });
      return;
    }
    let cancelled = false;
    invoke<GraphStats>("cmd_get_graph_stats")
      .then((s) => {
        if (!cancelled) dispatch({ type: "SET_STATS", payload: s });
      })
      .catch(() => {});
    invoke<string[]>("cmd_get_path_nodes")
      .then((ids) => {
        if (!cancelled) dispatch({ type: "SET_PATH_NODE_IDS", payload: ids });
      })
      .catch(() => {
        if (!cancelled) dispatch({ type: "SET_PATH_NODE_IDS", payload: [] });
      });
    invoke<string[]>("cmd_get_entity_types_in_graph")
      .then((types) => {
        if (!cancelled) dispatch({ type: "SET_ENTITY_TYPES_IN_GRAPH", payload: types });
      })
      .catch(() => {
        if (!cancelled) dispatch({ type: "SET_ENTITY_TYPES_IN_GRAPH", payload: [] });
      });
    invoke<Note[]>("cmd_get_notes")
      .then((list) => {
        if (!cancelled) dispatch({ type: "SET_NOTES", payload: list });
      })
      .catch(() => {
        if (!cancelled) dispatch({ type: "SET_NOTES", payload: [] });
      });
    return () => {
      cancelled = true;
    };
  }, [currentSession?.id, dispatch]);

  // Refetch entity types when graph size changes (e.g. after ingest) so dropdown stays in sync
  useEffect(() => {
    if (!currentSession) return;
    const total = stats.entity_count + stats.relation_count;
    if (total === 0) return;
    let cancelled = false;
    invoke<string[]>("cmd_get_entity_types_in_graph")
      .then((types) => {
        if (!cancelled) dispatch({ type: "SET_ENTITY_TYPES_IN_GRAPH", payload: types });
      })
      .catch(() => {});
    return () => {
      cancelled = true;
    };
  }, [currentSession?.id, stats.entity_count, stats.relation_count, dispatch]);

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
            dispatch({ type: "SET_MODE", payload: "hunt" });
            dispatch({ type: "SET_SUBGRAPH", payload: sg });
            dispatch({ type: "SET_HIGHLIGHT_PATHS", payload: null });
            dispatch({ type: "SET_SHOW_HUNT_TABLE", payload: false });
            dispatch({ type: "SET_EXPLORER_NEIGHBORHOOD", payload: null });
            dispatch({ type: "SET_SELECTED_NODE_ID", payload: null });
            dispatch({ type: "SET_NODE_DETAILS", payload: null });
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
  }, [addLog, dispatch]);

  // When MCP create_note is called via HTTP API, backend emits notes-changed; refresh notes list
  useEffect(() => {
    let unlisten: (() => void) | undefined;
    (async () => {
      try {
        unlisten = await listen("notes-changed", () => {
          addLog({ time: new Date().toLocaleTimeString("en-US", { hour12: false }), message: "Notes updated from MCP (audit: external)", level: "info" });
          invoke<Note[]>("cmd_get_notes")
            .then((list) => dispatch({ type: "SET_NOTES", payload: list }))
            .catch(() => dispatch({ type: "SET_NOTES", payload: [] }));
        });
      } catch {
        // ignore if event API unavailable
      }
    })();
    return () => {
      unlisten?.();
    };
  }, [addLog, dispatch]);

  const pushMapState = useCallback(() => {
    const s = mapStateRef.current;
    if (s) {
      dispatch({ type: "PUSH_MAP_STATE", payload: s });
    }
  }, [dispatch]);

  const restoreMapState = useCallback((s: MapState) => {
    dispatch({ type: "RESTORE_MAP_STATE", payload: s });
  }, [dispatch]);

  const handleMapBack = useCallback(() => {
    if (mapPast.length === 0) return;
    const prev = mapPast[mapPast.length - 1];
    dispatch({ type: "SET_MAP_PAST", payload: mapPast.slice(0, -1) });
    const current = mapStateRef.current;
    if (current) dispatch({ type: "SET_MAP_FUTURE", payload: [...mapFuture, current] });
    restoreMapState(prev);
    addLog({ time: new Date().toLocaleTimeString("en-US", { hour12: false }), message: "Navigation: Back", level: "info" });
  }, [mapPast, mapFuture, restoreMapState, addLog, dispatch]);

  const handleMapForward = useCallback(() => {
    if (mapFuture.length === 0) return;
    const next = mapFuture[mapFuture.length - 1];
    dispatch({ type: "SET_MAP_FUTURE", payload: mapFuture.slice(0, -1) });
    const current = mapStateRef.current;
    if (current) dispatch({ type: "SET_MAP_PAST", payload: [...mapPast, current] });
    restoreMapState(next);
    addLog({ time: new Date().toLocaleTimeString("en-US", { hour12: false }), message: "Navigation: Forward", level: "info" });
  }, [mapFuture, mapPast, restoreMapState, addLog, dispatch]);

  // ── Hunt mode handler ──
  const handleHuntResults = useCallback(
    async (results: HuntResults) => {
      pushMapState();
      dispatch({ type: "SET_HUNT_PATH_COUNT", payload: results.path_count });
      const t = new Date().toLocaleTimeString("en-US", { hour12: false });

      if (results.path_count === 0) {
        dispatch({ type: "SET_SUBGRAPH", payload: null });
        dispatch({ type: "SET_HIGHLIGHT_PATHS", payload: null });
        dispatch({ type: "SET_SHOW_HUNT_TABLE", payload: false });
        addLog({ time: t, message: "Hunt: 0 paths", level: "info" });
        return;
      }

      // Large result sets: show table, let user pick paths to render
      if (results.path_count > 100) {
        dispatch({ type: "SET_SHOW_HUNT_TABLE", payload: true });
        dispatch({ type: "SET_SUBGRAPH", payload: null });
        dispatch({ type: "SET_HIGHLIGHT_PATHS", payload: null });
        addLog({ time: t, message: `Hunt: ${results.path_count} paths (table view)`, level: "info" });
        return;
      }

      // Small result sets: fetch first page and render all in graph
      dispatch({ type: "SET_SHOW_HUNT_TABLE", payload: false });
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
        dispatch({ type: "SET_SUBGRAPH", payload: sg });
        dispatch({ type: "SET_HIGHLIGHT_PATHS", payload: allPaths });
        addLog({ time: t, message: `Hunt: ${results.path_count} paths — graph updated`, level: "info" });
      } catch (e) {
        addLog({
          time: t,
          message: `Subgraph error: ${errorMessage(e)}`,
          level: "error",
        });
      }
    },
    [addLog, pushMapState, dispatch]
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
        dispatch({ type: "SET_SUBGRAPH", payload: sg });
        dispatch({ type: "SET_HIGHLIGHT_PATHS", payload: [pathNodeIds] });
      } catch (e) {
        addLog({
          time: t,
          message: `Path view error: ${errorMessage(e)}`,
          level: "error",
        });
      }
    },
    [addLog, pushMapState, dispatch]
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
        dispatch({ type: "SET_EXPLORER_NEIGHBORHOOD", payload: hood });
        dispatch({ type: "SET_SELECTED_NODE_ID", payload: nodeId });

        // Also fetch details
        const details = await invoke<NodeDetails>("cmd_get_node_details", {
          nodeId,
        });
        dispatch({ type: "SET_NODE_DETAILS", payload: details });
        const filterDesc = filter?.entity_types?.length ? ` (filter: ${filter.entity_types.join(", ")})` : "";
        addLog({
          time: new Date().toLocaleTimeString("en-US", { hour12: false }),
          message: `Expand: node ${nodeId}${filterDesc} — ${hood.nodes.length} nodes`,
          level: "info",
        });
      } catch (e) {
        const msg = errorMessage(e);
        addLog({
          time: new Date().toLocaleTimeString("en-US", { hour12: false }),
          message: `Show neighbours error: ${msg}`,
          level: "error",
        });
      }
    },
    [addLog, pushMapState, dispatch]
  );

  // ── Click a node to show details in the lateral panel (works in both Hunt and Explorer) ──
  const handleNodeClick = useCallback(
    async (nodeId: string) => {
      dispatch({ type: "SET_SELECTED_NODE_ID", payload: nodeId });
      addLog({ time: new Date().toLocaleTimeString("en-US", { hour12: false }), message: `Selected node: ${nodeId}`, level: "info" });
      try {
        const details = await invoke<NodeDetails>("cmd_get_node_details", {
          nodeId,
        });
        dispatch({ type: "SET_NODE_DETAILS", payload: details });
      } catch (e) {
        addNotification({ message: `Failed to get node details: ${errorMessage(e)}`, type: "error" });
      }
    },
    [addLog, dispatch, addNotification]
  );

  // ── Explorer mode: double-click to expand ──
  const handleNodeDoubleClick = useCallback(
    async (nodeId: string) => {
      if (mode !== "explore") return;
      handleExploreNode(nodeId);
    },
    [mode, handleExploreNode]
  );

  // Switch to explorer mode, clearing hunt-specific state
  const switchToExploreMode = useCallback(() => {
    dispatch({ type: "SET_BOTTOM_TAB", payload: "explore" });
    dispatch({ type: "SET_MODE", payload: "explore" });
    dispatch({ type: "SET_SUBGRAPH", payload: null });
    dispatch({ type: "SET_HIGHLIGHT_PATHS", payload: null });
  }, [dispatch]);

  // Context menu Expand/Center/Show neighbours: if in Hunt mode, switch to Explorer first so the graph updates
  const handleNodeContextExpandOrShow = useCallback(
    (nodeId: string, filter?: ExpandFilter) => {
      if (mode !== "explore") switchToExploreMode();
      handleExploreNode(nodeId, filter);
    },
    [mode, handleExploreNode, switchToExploreMode]
  );

  // ── Types Available: show type or single node on map ──
  const handleShowTypeOnMap = useCallback(
    async (nodeIds: string[]) => {
      pushMapState();
      dispatch({ type: "SET_BOTTOM_TAB", payload: "hunt" });
      dispatch({ type: "SET_MODE", payload: "hunt" });
      dispatch({ type: "SET_SELECTED_NODE_ID", payload: null });
      dispatch({ type: "SET_NODE_DETAILS", payload: null });
      dispatch({ type: "SET_EXPLORER_NEIGHBORHOOD", payload: null });
      dispatch({ type: "SET_HIGHLIGHT_PATHS", payload: null });
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
        dispatch({ type: "SET_SUBGRAPH", payload: sg });
        dispatch({ type: "SET_HIGHLIGHT_PATHS", payload: [nodeIds] });
        addLog({
          time: new Date().toLocaleTimeString("en-US", { hour12: false }),
          message: `Showing ${nodeIds.length} nodes with this relation on map`,
          level: "info",
        });
      } catch (e) {
        addLog({
          time: new Date().toLocaleTimeString("en-US", { hour12: false }),
          message: `Failed to show on map: ${errorMessage(e)}`,
          level: "error",
        });
      }
    },
    [addLog, pushMapState, dispatch]
  );

  const handleShowNodeOnMap = useCallback(
    (nodeId: string) => {
      addLog({ time: new Date().toLocaleTimeString("en-US", { hour12: false }), message: `Show on map: node ${nodeId}`, level: "info" });
      switchToExploreMode();
      handleExploreNode(nodeId);
    },
    [handleExploreNode, addLog, switchToExploreMode]
  );

  /** Show on map the clicked node and only its neighbours of the given entity type (Explorer + type filter). */
  const handleShowNeighbourTypeOnMap = useCallback(
    (nodeId: string, entityType: string) => {
      if (mode !== "explore") switchToExploreMode();
      handleExploreNode(nodeId, { entity_types: [entityType] });
    },
    [mode, handleExploreNode, switchToExploreMode]
  );

  // ── Path nodes: add/remove pinned nodes (persisted with session) ──
  const handleAddToPathNodes = useCallback(async (nodeId: string) => {
    try {
      await invoke("cmd_add_path_node", { nodeId });
      dispatch({ type: "ADD_PATH_NODE", payload: nodeId });
      await handleAutoSave();
      addLog({ time: new Date().toLocaleTimeString("en-US", { hour12: false }), message: `Path node added: ${nodeId}`, level: "info" });
    } catch (e) {
      addLog({
        time: new Date().toLocaleTimeString("en-US", { hour12: false }),
        message: `Failed to add path node: ${errorMessage(e)}`,
        level: "error",
      });
    }
  }, [addLog, handleAutoSave, dispatch]);

  const handleRemoveFromPathNodes = useCallback(async (nodeId: string) => {
    try {
      await invoke("cmd_remove_path_node", { nodeId });
      dispatch({ type: "REMOVE_PATH_NODE", payload: nodeId });
      await handleAutoSave();
      addLog({ time: new Date().toLocaleTimeString("en-US", { hour12: false }), message: `Path node removed: ${nodeId}`, level: "info" });
    } catch (e) {
      addLog({
        time: new Date().toLocaleTimeString("en-US", { hour12: false }),
        message: `Failed to remove path node: ${errorMessage(e)}`,
        level: "error",
      });
    }
  }, [addLog, handleAutoSave, dispatch]);

  // ── Mode switch (Hunt / Explorer tabs; Events view doesn't change graph mode) ──
  const handleBottomTabChange = useCallback((tab: BottomTab) => {
    dispatch({ type: "SET_BOTTOM_TAB", payload: tab });
    if (tab === "hunt") {
      dispatch({ type: "SET_MODE", payload: "hunt" });
      dispatch({ type: "SET_SELECTED_NODE_ID", payload: null });
      dispatch({ type: "SET_NODE_DETAILS", payload: null });
      dispatch({ type: "SET_SHOW_HUNT_TABLE", payload: false });
      dispatch({ type: "SET_HUNT_PATH_COUNT", payload: 0 });
      dispatch({ type: "SET_EXPLORER_NEIGHBORHOOD", payload: null });
    } else if (tab === "explore") {
      dispatch({ type: "SET_MODE", payload: "explore" });
      dispatch({ type: "SET_SUBGRAPH", payload: null });
      dispatch({ type: "SET_HIGHLIGHT_PATHS", payload: null });
    }
    const tabLabels: Record<BottomTab, string> = { hunt: "Hunt", explore: "Explorer", events: "Events", heatmap: "Heatmap", timeline: "Timeline" };
    addLog({ time: new Date().toLocaleTimeString("en-US", { hour12: false }), message: `Switched to ${tabLabels[tab]}`, level: "info" });
  }, [addLog, dispatch]);

  // Click path node in list: Explorer = load neighborhood; Hunt = pan/zoom to center node
  const handlePathNodeFocus = useCallback(
    (nodeId: string) => {
      if (mode === "explore") {
        handleExploreNode(nodeId);
      } else {
        addLog({ time: new Date().toLocaleTimeString("en-US", { hour12: false }), message: `Centered on node: ${nodeId}`, level: "info" });
        dispatch({ type: "SET_CENTER_NODE_ID", payload: nodeId });
      }
    },
    [mode, handleExploreNode, addLog, dispatch]
  );

  const handleResizeStart = useCallback((e: React.MouseEvent) => {
    e.preventDefault();
    const startY = e.clientY;
    const startHeight = bottomPanelHeight;
    const onMove = (e2: MouseEvent) => {
      const delta = startY - e2.clientY;
      dispatch({ type: "SET_BOTTOM_PANEL_HEIGHT", payload: Math.min(600, Math.max(120, startHeight + delta)) });
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
  }, [bottomPanelHeight, dispatch]);

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
      setAnalyzeAiError(errorMessage(e));
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
      setAnalyzeAiError(errorMessage(e));
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

  // Setter callbacks for child components that expect (value) => void
  const setCurrentSession = useCallback(
    (session: SessionInfo | null) => dispatch({ type: "SET_CURRENT_SESSION", payload: session }),
    [dispatch]
  );
  const setSessions = useCallback(
    (sessions: SessionInfo[]) => dispatch({ type: "SET_SESSIONS", payload: sessions }),
    [dispatch]
  );
  const setSessionError = useCallback(
    (error: string) => dispatch({ type: "SET_SESSION_ERROR", payload: error }),
    [dispatch]
  );
  const setStats = useCallback(
    (stats: GraphStats) => dispatch({ type: "SET_STATS", payload: stats }),
    [dispatch]
  );
  const setNotes = useCallback(
    (notes: Note[]) => dispatch({ type: "SET_NOTES", payload: notes }),
    [dispatch]
  );

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
          <LazyBoundary>
            <HelpPanel onClose={() => setHelpPanelOpen(false)} />
          </LazyBoundary>
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
            onClick={() => dispatch({ type: "SET_LEFT_MENU", payload: leftMenuOpen === "datasets" ? null : "datasets" })}
            title={leftMenuOpen === "datasets" ? "Hide Datasets" : "Show Datasets"}
          >
            <Database size={14} style={{ marginRight: 4 }} />
            Datasets
          </button>
          <button
            type="button"
            className={`app-toolbar-btn ${leftMenuOpen === "activity" ? "active" : ""}`}
            onClick={() => dispatch({ type: "SET_LEFT_MENU", payload: leftMenuOpen === "activity" ? null : "activity" })}
            title={leftMenuOpen === "activity" ? "Hide Activity Log" : "Show Activity Log"}
          >
            <Activity size={14} style={{ marginRight: 4 }} />
            Activity
          </button>
          <button
            type="button"
            className={`app-toolbar-btn ${leftMenuOpen === "metrics" ? "active" : ""}`}
            onClick={() => dispatch({ type: "SET_LEFT_MENU", payload: leftMenuOpen === "metrics" ? null : "metrics" })}
            title={leftMenuOpen === "metrics" ? "Hide Graph Metrics" : "Show Graph Metrics"}
          >
            <BarChart3 size={14} style={{ marginRight: 4 }} />
            Metrics
          </button>
          <button
            type="button"
            className={`app-toolbar-btn ${rightMenuOpen === "pathNodes" ? "active" : ""}`}
            onClick={() => dispatch({ type: "SET_RIGHT_MENU", payload: rightMenuOpen === "pathNodes" ? null : "pathNodes" })}
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
            onClick={() => dispatch({ type: "SET_RIGHT_MENU", payload: rightMenuOpen === "notes" ? null : "notes" })}
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
              dispatch({ type: "SET_CURRENT_SESSION", payload: session });
              dispatch({ type: "ADD_SESSION", payload: session });
            }}
            stats={stats}
            onStatsUpdate={setStats}
            onLog={addLog}
            onClose={() => dispatch({ type: "SET_LEFT_MENU", payload: null })}
            onShowTypeOnMap={handleShowTypeOnMap}
            onShowNodeOnMap={handleShowNodeOnMap}
          />
        )}
        {leftMenuOpen === "activity" && (
          <ActivityLogContainer onClose={() => dispatch({ type: "SET_LEFT_MENU", payload: null })} />
        )}
        {leftMenuOpen === "metrics" && (
          <GraphMetricsLeftPanel
            currentSessionId={currentSession?.id ?? null}
            stats={stats}
            onStatsUpdate={setStats}
            onLog={addLog}
            onClose={() => dispatch({ type: "SET_LEFT_MENU", payload: null })}
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
        onCenterDone={() => dispatch({ type: "SET_CENTER_NODE_ID", payload: null })}
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
          <LazyBoundary>
            <HuntResultsTable
              totalPaths={huntPathCount}
              onViewPath={handleViewPath}
              onLog={addLog}
            />
          </LazyBoundary>
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

        {/* `ExplorerPanel` is the default tab and stays eager so the
            first paint has no Suspense flicker. The other four tabs are
            lazy chunks and share a single Suspense boundary — only one
            can be mounted at a time, so a shared boundary is sufficient. */}
        {bottomTab === "explore" && (
          <ExplorerPanel
            onExploreNode={handleExploreNode}
            neighborhood={explorerNeighborhood}
            onLog={addLog}
          />
        )}
        {bottomTab !== "explore" && (
          <LazyBoundary>
            {bottomTab === "hunt" && (
              <HypothesisBuilder
                onHuntResults={handleHuntResults}
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
          </LazyBoundary>
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
                onClick={() => dispatch({ type: "SET_RIGHT_MENU", payload: null })}
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
                onClick={() => dispatch({ type: "SET_RIGHT_MENU", payload: null })}
                title="Hide Notes"
                aria-label="Hide Notes menu"
              >
                <X size={14} />
              </button>
            </div>
            <div className="left-menu-panel-content">
              <LazyBoundary>
                <NotesPanel
                  notes={notes}
                  selectedNodeId={selectedNodeId}
                  onNotesChange={setNotes}
                  onAutoSave={handleAutoSave}
                  onShowNodeOnMap={(nodeId) => handleNodeContextExpandOrShow(nodeId)}
                />
              </LazyBoundary>
            </div>
          </div>
        )}
      </div>

      {/* Node detail sidebar (shown when a node is selected, in Hunt or Explorer) */}
      {nodeDetails && (
        <LazyBoundary>
          <NodeDetailPanel
            details={nodeDetails}
            onClose={() => {
              addLog({ time: new Date().toLocaleTimeString("en-US", { hour12: false }), message: "Cleared selection", level: "info" });
              dispatch({ type: "SET_NODE_DETAILS", payload: null });
              dispatch({ type: "SET_SELECTED_NODE_ID", payload: null });
            }}
            onExpand={handleExploreNode}
            onSetCenter={handleExploreNode}
            onShowNeighbourTypeOnMap={handleShowNeighbourTypeOnMap}
          />
        </LazyBoundary>
      )}

      {/* Guide panel (slide-out, ? button in header) */}
      {helpPanelOpen && (
        <LazyBoundary>
          <HelpPanel onClose={() => setHelpPanelOpen(false)} />
        </LazyBoundary>
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

// ── Root App component wrapping with providers ──

import { AppStateProvider } from "./context/AppStateContext";
import { NotificationProvider } from "./hooks/useNotifications";

function App() {
  return (
    <AppStateProvider>
      <LogProvider>
        <NotificationProvider>
          <AppInner />
        </NotificationProvider>
      </LogProvider>
    </AppStateProvider>
  );
}

export default App;
