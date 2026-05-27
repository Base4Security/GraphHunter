import { lazy, Suspense, useCallback, useEffect, useMemo } from "react";
import { listen } from "@tauri-apps/api/event";
import { invoke, errorMessage } from "./lib/tauri";
// Eager: everything on the initial-render path. The Welcome page, the left-
// side panels, the graph canvas and the Explorer bottom panel (default tab)
// must be in the main bundle so the first paint has no flicker.
import ErrorBoundary from "./components/ErrorBoundary";
import AzureStreamingSmokeTest from "./components/AzureStreamingSmokeTest";
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
const EdgeDetailPanel = lazy(() => import("./components/EdgeDetailPanel"));
const CommandPalette = lazy(() => import("./components/CommandPalette"));
const HuntResultsTable = lazy(() => import("./components/HuntResultsTable"));
const EventsViewPanel = lazy(() => import("./components/EventsViewPanel"));
const HeatmapView = lazy(() => import("./components/HeatmapView"));
const TimelineView = lazy(() => import("./components/TimelineView"));
import { ChevronLeft, ChevronRight, Sparkles, Database, Activity, BarChart3, X, MapPin, FileText, HelpCircle } from "lucide-react";
import { useAppState, useAppDispatch } from "./context/AppStateContext";
import { useLogDispatch, LogProvider } from "./context/LogContext";
import { useNotifications } from "./hooks/useNotifications";
import { useAiAnalysis } from "./hooks/useAiAnalysis";
import { useMapNavigation } from "./hooks/useMapNavigation";
import { usePanelResize } from "./hooks/usePanelResize";
import { useSentinelEvents } from "./hooks/useSentinelEvents";
import { useViewportWidth, TOOLBAR_COMPACT_THRESHOLD_PX } from "./hooks/useViewportWidth";
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
} from "./types";
import type { BottomTab } from "./context/AppStateContext";
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
  } = state;

  // PR-A: drive the top-toolbar compact-mode toggle off the viewport
  // width. Below ~1100px the full row of 8–11 buttons + status badges
  // overflows, so we collapse to icon-only and let tooltips carry the
  // labels.
  const viewportWidth = useViewportWidth();
  const compactToolbar = viewportWidth < TOOLBAR_COMPACT_THRESHOLD_PX;

  const addLog = useCallback(
    (entry: LogEntry) => {
      logDispatch({ type: "ADD_LOG", payload: entry });
    },
    [logDispatch]
  );

  // AI state + handlers extracted to dedicated hook
  const ai = useAiAnalysis(addLog);
  // Map navigation (back/forward) extracted to dedicated hook
  const nav = useMapNavigation(addLog);
  // Bottom panel resize extracted to dedicated hook
  const { bottomPanelHeight, handleResizeStart } = usePanelResize();

  const [helpPanelOpen, setHelpPanelOpen] = useState(false);

  // PR-D: Ctrl+K (Cmd+K) command palette. Global keydown listener
  // mounted at the AppInner level so the shortcut is reachable from
  // any focused element (graph canvas, hunt results table, search
  // input, …).
  const [commandPaletteOpen, setCommandPaletteOpen] = useState(false);
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === "k") {
        e.preventDefault();
        setCommandPaletteOpen((v) => !v);
      }
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, []);

  // Perf-flag introspection — populated once at mount from
  // `cmd_get_perf_status`. Renders as a small toolbar badge so the
  // user perceives the M-track flags are active without any manual
  // configuration. `null` until the first invoke resolves.
  const [perfStatus, setPerfStatus] = useState<{
    summary: string;
    lftjPlanner: boolean;
    k4Lftj: boolean;
    yannakakis: boolean;
    amac: boolean;
    semijoin: boolean;
    hugepages: boolean;
    hasNauty: boolean;
    indexHeapBudgetBytes: number;
  } | null>(null);

  useEffect(() => {
    let cancelled = false;
    (async () => {
      try {
        const status = await invoke<typeof perfStatus>("cmd_get_perf_status");
        if (!cancelled) setPerfStatus(status);
      } catch {
        // Backend missing the command (older daemon) — leave null,
        // badge won't render.
      }
    })();
    return () => {
      cancelled = true;
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  // Ingest-engine status — populated once at mount from
  // `cmd_get_ingest_engine_status`. Renders as a small toolbar badge
  // next to the perf badge so the user perceives that the new
  // RawIngestEvent + VRL/LLM compiler stack is on by default. Same
  // null-on-missing pattern as `perfStatus` so older daemons just
  // skip the badge.
  const [ingestEngineStatus, setIngestEngineStatus] = useState<{
    summary: string;
    rawEventActive: boolean;
    parsersWithNativeRaw: string[];
    vrlCompilerActive: boolean;
    llmCompilerAvailable: boolean;
    llmCompilerModelPath: string | null;
    llmCompilerDispatcherEnabled: boolean;
  } | null>(null);
  useEffect(() => {
    let cancelled = false;
    (async () => {
      try {
        const status = await invoke<typeof ingestEngineStatus>(
          "cmd_get_ingest_engine_status"
        );
        if (!cancelled) setIngestEngineStatus(status);
      } catch {
        // Older daemon without the command — leave null.
      }
    })();
    return () => {
      cancelled = true;
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  // Heavy-logs #4 — memory pressure pill. Polls cmd_get_memory_status
  // every 5 s; the badge shifts from green ("normal") to amber when
  // process RSS exceeds `warnAt` (default 75% of host RAM) and to red
  // when it exceeds `criticalAt` (default 90%). Plug-and-play: no env
  // vars to set, no toggle.
  const [memStatus, setMemStatus] = useState<{
    rssBytes: number;
    hostTotalBytes: number;
    hostAvailableBytes: number;
    usageRatio: number;
    warnAt: number;
    criticalAt: number;
  } | null>(null);
  useEffect(() => {
    let cancelled = false;
    const tick = async () => {
      try {
        const status = await invoke<typeof memStatus>("cmd_get_memory_status");
        if (!cancelled) setMemStatus(status);
      } catch {
        // Older daemon — skip.
      }
    };
    tick();
    const handle = window.setInterval(tick, 5000);
    return () => {
      cancelled = true;
      window.clearInterval(handle);
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
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
      .catch((err) => console.error("cmd_get_graph_stats:", err));
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
      .catch((err) => console.error("cmd_get_entity_types_in_graph (refresh):", err));
    return () => {
      cancelled = true;
    };
  }, [currentSession?.id, stats.entity_count, stats.relation_count, dispatch]);

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

  const { pushMapState, handleMapBack, handleMapForward, mapPast, mapFuture } = nav;

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
      // PR-B follow-up: clicking a node closes the EdgeDetailPanel
      // (if open) so the two inspectors stay mutually exclusive.
      dispatch({ type: "SET_SELECTED_EDGE_BUNDLE", payload: null });
      if (rightMenuOpen === "edgeDetail") {
        dispatch({ type: "SET_RIGHT_MENU", payload: null });
      }
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
    [addLog, dispatch, addNotification, rightMenuOpen]
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

  // Sentinel event listeners — lives here (never unmounts) so polling
  // continues even when the Datasets panel is closed.
  const sentinel = useSentinelEvents(addLog, stats, setStats);

  // PR-D: curated Command Palette items. Hand-picked rather than
  // auto-generated from the full Tauri command surface — most
  // commands need typed payloads (FieldConfig, hypothesis JSON,
  // node IDs) that the palette can't compose. The items below are
  // the ones that take no args or trivial args, i.e. things the
  // analyst would reach for from anywhere.
  const commandItems = useMemo(
    () => [
      // Navigation — toggle the left panels.
      {
        id: "nav.datasets",
        label: "Toggle Datasets panel",
        category: "navigation" as const,
        keywords: "left sidebar ingest",
        action: () =>
          dispatch({
            type: "SET_LEFT_MENU",
            payload: leftMenuOpen === "datasets" ? null : "datasets",
          }),
      },
      {
        id: "nav.activity",
        label: "Toggle Activity Log",
        category: "navigation" as const,
        keywords: "left sidebar log",
        action: () =>
          dispatch({
            type: "SET_LEFT_MENU",
            payload: leftMenuOpen === "activity" ? null : "activity",
          }),
      },
      {
        id: "nav.metrics",
        label: "Toggle Graph Metrics",
        category: "navigation" as const,
        keywords: "left sidebar entity relation",
        action: () =>
          dispatch({
            type: "SET_LEFT_MENU",
            payload: leftMenuOpen === "metrics" ? null : "metrics",
          }),
      },
      // Navigation — toggle the right panels.
      {
        id: "nav.pathnodes",
        label: "Toggle Path Nodes",
        category: "navigation" as const,
        keywords: "right sidebar pinned",
        action: () =>
          dispatch({
            type: "SET_RIGHT_MENU",
            payload: rightMenuOpen === "pathNodes" ? null : "pathNodes",
          }),
      },
      {
        id: "nav.notes",
        label: "Toggle Notes",
        category: "navigation" as const,
        keywords: "right sidebar markdown",
        action: () =>
          dispatch({
            type: "SET_RIGHT_MENU",
            payload: rightMenuOpen === "notes" ? null : "notes",
          }),
      },
      {
        id: "nav.analysis",
        label: "Toggle Analysis (AI)",
        category: "navigation" as const,
        keywords: "ai llm sparkles",
        action: () => ai.setAnalyzeAiOpen(!ai.analyzeAiOpen),
      },
      {
        id: "nav.help",
        label: "Open Help / Guide",
        category: "navigation" as const,
        keywords: "manual docs about dsl",
        hint: "?",
        action: () => setHelpPanelOpen(true),
      },
      // View — switch the bottom tab.
      {
        id: "view.hunt",
        label: "Switch to Hunt mode",
        category: "view" as const,
        keywords: "hypothesis dsl",
        action: () => dispatch({ type: "SET_BOTTOM_TAB", payload: "hunt" }),
      },
      {
        id: "view.explore",
        label: "Switch to Explorer mode",
        category: "view" as const,
        keywords: "search neighbours",
        action: () => dispatch({ type: "SET_BOTTOM_TAB", payload: "explore" }),
      },
      {
        id: "view.events",
        label: "Switch to Events view",
        category: "view" as const,
        keywords: "timeline rows raw",
        action: () => dispatch({ type: "SET_BOTTOM_TAB", payload: "events" }),
      },
      {
        id: "view.heatmap",
        label: "Switch to Heatmap view",
        category: "view" as const,
        keywords: "temporal density",
        action: () => dispatch({ type: "SET_BOTTOM_TAB", payload: "heatmap" }),
      },
      {
        id: "view.timeline",
        label: "Switch to Timeline view",
        category: "view" as const,
        keywords: "chronological",
        action: () => dispatch({ type: "SET_BOTTOM_TAB", payload: "timeline" }),
      },
      // Export quick-actions — surfaces commands with no other UI.
      {
        id: "export.subgraph",
        label: "Export current subgraph as JSON",
        category: "export" as const,
        keywords: "download graph snapshot",
        invoke: { command: "cmd_export_subgraph", args: { format: "json", nodes: [] } },
      },
      {
        id: "export.ocsf.json",
        label: "Export OCSF v1.4 events (JSON)",
        category: "export" as const,
        keywords: "schema events provenance",
        invoke: {
          command: "cmd_export_ocsf",
          args: {
            format: "json",
            datasetId: null,
            pageSize: null,
            offset: null,
          },
        },
      },
      {
        id: "export.ocsf.ndjson",
        label: "Export OCSF v1.4 events (NDJSON)",
        category: "export" as const,
        keywords: "schema events streamable",
        invoke: {
          command: "cmd_export_ocsf",
          args: {
            format: "ndjson",
            datasetId: null,
            pageSize: null,
            offset: null,
          },
        },
      },
      // Advanced — backend commands without a UI surface today.
      {
        id: "adv.betweenness",
        label: "Compute Betweenness centrality",
        category: "advanced" as const,
        keywords: "scoring graph centrality slow",
        invoke: { command: "cmd_compute_betweenness" },
      },
    ],
    [dispatch, leftMenuOpen, rightMenuOpen, ai],
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
          {/* Azure streaming plan Phase 5-9 smoke test.
              Visible on the welcome page so the diagnostic is one click
              away without needing a session. Delete this wrapper and
              the AzureStreamingSmokeTest import once real Tauri
              commands (cmd_enrich_entity etc.) land. */}
          <div style={{ marginTop: 32, display: "flex", justifyContent: "center" }}>
            <AzureStreamingSmokeTest />
          </div>
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
          // PR-A v3 follow-up: NodeDetailPanel is a fixed-position
          // floating rail (320 px) that lives OUTSIDE the right-menu
          // cluster. Expose its width via a CSS var so the top-bar
          // can reserve matching right-margin and avoid the
          // "atravezado" overlap.
          "--node-detail-width": nodeDetails ? "320px" : "0px",
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
        <div className={`app-toolbar${compactToolbar ? " app-toolbar--compact" : ""}`}>
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
            <Database size={14} />
            <span className="app-toolbar-btn-label">Datasets</span>
          </button>
          <button
            type="button"
            className={`app-toolbar-btn ${leftMenuOpen === "activity" ? "active" : ""}`}
            onClick={() => dispatch({ type: "SET_LEFT_MENU", payload: leftMenuOpen === "activity" ? null : "activity" })}
            title={leftMenuOpen === "activity" ? "Hide Activity Log" : "Show Activity Log"}
          >
            <Activity size={14} />
            <span className="app-toolbar-btn-label">Activity</span>
          </button>
          <button
            type="button"
            className={`app-toolbar-btn ${leftMenuOpen === "metrics" ? "active" : ""}`}
            onClick={() => dispatch({ type: "SET_LEFT_MENU", payload: leftMenuOpen === "metrics" ? null : "metrics" })}
            title={leftMenuOpen === "metrics" ? "Hide Graph Metrics" : "Show Graph Metrics"}
          >
            <BarChart3 size={14} />
            <span className="app-toolbar-btn-label">Metrics</span>
          </button>
          <button
            type="button"
            className={`app-toolbar-btn ${rightMenuOpen === "pathNodes" ? "active" : ""}`}
            onClick={() => dispatch({ type: "SET_RIGHT_MENU", payload: rightMenuOpen === "pathNodes" ? null : "pathNodes" })}
            title={rightMenuOpen === "pathNodes" ? "Close Path Nodes" : "Open Path Nodes"}
            aria-label="Path Nodes"
          >
            <MapPin size={14} />
            <span className="app-toolbar-btn-label">Path Nodes</span>
            {pathNodeIds.length > 0 && (
              <span className="app-toolbar-badge">{pathNodeIds.length}</span>
            )}
          </button>
          <button
            type="button"
            className={`app-toolbar-btn ${rightMenuOpen === "notes" ? "active" : ""}`}
            onClick={() => dispatch({ type: "SET_RIGHT_MENU", payload: rightMenuOpen === "notes" ? null : "notes" })}
            title={rightMenuOpen === "notes" ? "Close Notes" : "Open Notes"}
            aria-label="Notes"
          >
            <FileText size={14} />
            <span className="app-toolbar-btn-label">Notes</span>
            {notes.length > 0 && (
              <span className="app-toolbar-badge">{notes.length}</span>
            )}
          </button>
          <button
            type="button"
            className={`app-toolbar-btn ${ai.analyzeAiOpen ? "active" : ""}`}
            onClick={() => {
              ai.setAnalyzeAiOpen(!ai.analyzeAiOpen);
              if (!ai.analyzeAiOpen) {
                // error is cleared internally by the hook on open
              }
            }}
            title="Analyze current graph with AI (malicious? next node to expand?)"
            aria-label="Analysis"
          >
            <Sparkles size={14} />
            <span className="app-toolbar-btn-label">Analysis</span>
          </button>
          {perfStatus && (
            <span
              className="app-toolbar-perf-badge"
              data-active={
                perfStatus.lftjPlanner || perfStatus.k4Lftj || perfStatus.yannakakis
                  ? "true"
                  : "false"
              }
              title={perfStatus.summary}
              aria-label={perfStatus.summary}
            >
              {perfStatus.lftjPlanner || perfStatus.k4Lftj || perfStatus.yannakakis
                ? "Perf: M+L1"
                : "Perf: Legacy"}
            </span>
          )}
          {ingestEngineStatus && ingestEngineStatus.rawEventActive && (
            <span
              className="app-toolbar-ingest-badge"
              data-active="true"
              data-llm={
                ingestEngineStatus.llmCompilerAvailable &&
                ingestEngineStatus.llmCompilerDispatcherEnabled
                  ? "true"
                  : ingestEngineStatus.llmCompilerAvailable
                    ? "loaded"
                    : "false"
              }
              title={ingestEngineStatus.summary}
              aria-label={ingestEngineStatus.summary}
            >
              {ingestEngineStatus.llmCompilerAvailable &&
              ingestEngineStatus.llmCompilerDispatcherEnabled
                ? "Ingest: v2 + IA Compiler"
                : ingestEngineStatus.llmCompilerAvailable
                  ? "Ingest: v2 + LLM (idle)"
                  : "Ingest: v2"}
            </span>
          )}
          {memStatus && memStatus.hostTotalBytes > 0 && (
            <span
              className="app-toolbar-mem-badge"
              data-level={
                memStatus.usageRatio >= memStatus.criticalAt
                  ? "critical"
                  : memStatus.usageRatio >= memStatus.warnAt
                    ? "warn"
                    : "normal"
              }
              title={`Process RSS ${(memStatus.rssBytes / (1024 ** 3)).toFixed(2)} GiB / host total ${(memStatus.hostTotalBytes / (1024 ** 3)).toFixed(0)} GiB (${(memStatus.usageRatio * 100).toFixed(0)}%)`}
              aria-label="Memory pressure indicator"
            >
              {`Mem: ${(memStatus.usageRatio * 100).toFixed(0)}%`}
            </span>
          )}
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
            sentinel={sentinel}
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
      <ErrorBoundary section="Graph Canvas">
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
          onEdgeClick={(bundle) => {
            // PR-B follow-up: clear the floating NodeDetailPanel so
            // it doesn't visually cover the new EdgeDetailPanel.
            // The two inspectors are mutually exclusive — you're
            // looking at one thing at a time.
            dispatch({ type: "SET_NODE_DETAILS", payload: null });
            dispatch({ type: "SET_SELECTED_NODE_ID", payload: null });
            dispatch({ type: "SET_SELECTED_EDGE_BUNDLE", payload: bundle });
            dispatch({ type: "SET_RIGHT_MENU", payload: "edgeDetail" });
          }}
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
      </ErrorBoundary>

      {/* Resize handle for bottom panel */}
      <div
        className="panel-bottom-resize-handle"
        onMouseDown={handleResizeStart}
        role="separator"
        aria-label="Resize bottom panel"
      />

      {/* Bottom panel with mode tabs (WAI-ARIA tablist pattern). */}
      <ErrorBoundary section="Bottom Panel">
      <div className="panel panel-bottom-container">
        <div
          className="mode-tabs"
          role="tablist"
          aria-label="Bottom panel mode"
          onKeyDown={(e) => {
            // Roving-tabindex arrow-key nav. Home/End jump to ends.
            const order: BottomTab[] = ["hunt", "explore", "events", "heatmap", "timeline"];
            const idx = order.indexOf(bottomTab);
            if (idx < 0) return;
            let next = idx;
            if (e.key === "ArrowRight") next = (idx + 1) % order.length;
            else if (e.key === "ArrowLeft") next = (idx - 1 + order.length) % order.length;
            else if (e.key === "Home") next = 0;
            else if (e.key === "End") next = order.length - 1;
            else return;
            e.preventDefault();
            handleBottomTabChange(order[next]);
            // Move focus to the new tab so screen readers announce it.
            (document.getElementById(`mode-tab-${order[next]}`) as HTMLElement | null)?.focus();
          }}
        >
          {([
            { id: "hunt", label: "Hunt Mode" },
            { id: "explore", label: "Explorer Mode" },
            { id: "events", label: "Events view" },
            { id: "heatmap", label: "Heatmap" },
            { id: "timeline", label: "Timeline" },
          ] as const).map(({ id, label }) => (
            <button
              key={id}
              id={`mode-tab-${id}`}
              role="tab"
              type="button"
              aria-selected={bottomTab === id}
              aria-controls={`mode-panel-${id}`}
              tabIndex={bottomTab === id ? 0 : -1}
              className={`mode-tab ${bottomTab === id ? "active" : ""}`}
              onClick={() => handleBottomTabChange(id)}
            >
              {label}
            </button>
          ))}
        </div>

        {/* `ExplorerPanel` is the default tab and stays eager so the
            first paint has no Suspense flicker. The other four tabs are
            lazy chunks and share a single Suspense boundary — only one
            can be mounted at a time, so a shared boundary is sufficient. */}
        {bottomTab === "explore" && (
          <div role="tabpanel" id="mode-panel-explore" aria-labelledby="mode-tab-explore">
            <ExplorerPanel
              onExploreNode={handleExploreNode}
              neighborhood={explorerNeighborhood}
              onLog={addLog}
            />
          </div>
        )}
        {bottomTab !== "explore" && (
          <LazyBoundary>
            {bottomTab === "hunt" && (
              <div role="tabpanel" id="mode-panel-hunt" aria-labelledby="mode-tab-hunt">
                <HypothesisBuilder
                  onHuntResults={handleHuntResults}
                  onLog={addLog}
                />
              </div>
            )}
            {bottomTab === "events" && (
              <div role="tabpanel" id="mode-panel-events" aria-labelledby="mode-tab-events">
                <EventsViewPanel selectedNodeId={selectedNodeId} />
              </div>
            )}
            {bottomTab === "heatmap" && (
              <div role="tabpanel" id="mode-panel-heatmap" aria-labelledby="mode-tab-heatmap">
                <HeatmapView
                  statsKey={stats.entity_count + stats.relation_count}
                  onShowRelationOnMap={handleShowTypeOnMap}
                  onLog={addLog}
                />
              </div>
            )}
            {bottomTab === "timeline" && (
              <div role="tabpanel" id="mode-panel-timeline" aria-labelledby="mode-tab-timeline">
                <TimelineView
                  statsKey={stats.entity_count + stats.relation_count}
                  onShowTypeOnMap={handleShowTypeOnMap}
                />
              </div>
            )}
          </LazyBoundary>
        )}
      </div>
      </ErrorBoundary>

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
        {rightMenuOpen === "edgeDetail" && state.selectedEdgeBundle && (
          <div className="left-menu-panel right-menu-panel" role="region" aria-label="Edge Detail">
            <div className="left-menu-panel-content" style={{ padding: 0 }}>
              <LazyBoundary>
                <EdgeDetailPanel
                  bundle={state.selectedEdgeBundle}
                  onClose={() => dispatch({ type: "SET_RIGHT_MENU", payload: null })}
                  onCentreNode={(nodeId) =>
                    dispatch({ type: "SET_CENTER_NODE_ID", payload: nodeId })
                  }
                  onPinNode={handleAddToPathNodes}
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
      {ai.analyzeAiOpen && (
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
              <button type="button" className="btn btn-sm" onClick={() => ai.setAiSettingsOpen(!ai.aiSettingsOpen)} title="AI Settings" style={{ fontSize: 11 }}>
                Settings
              </button>
              <button type="button" className="btn btn-sm" onClick={ai.clearAiConversation} title="Clear conversation" style={{ fontSize: 11 }}>
                Clear
              </button>
              <button type="button" className="btn btn-sm" onClick={() => ai.setAnalyzeAiOpen(false)}>
                <X size={14} />
              </button>
            </div>
          </div>

          {/* Settings panel (collapsible) */}
          {ai.aiSettingsOpen && (
            <div style={{ padding: "8px 12px", borderBottom: "1px solid var(--border)", background: "var(--bg-secondary)" }}>
              <div style={{ display: "flex", gap: 8, marginBottom: 6 }}>
                <label style={{ fontSize: 11, color: "var(--text-secondary)", flex: 1 }}>
                  Provider
                  <select
                    value={ai.aiProvider}
                    onChange={(e) => ai.setAiProvider(e.target.value as AiProvider)}
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
                    value={ai.aiModel}
                    onChange={(e) => ai.setAiModel(e.target.value)}
                    placeholder={ai.aiProvider === "OpenAI" ? "gpt-4o" : ai.aiProvider === "Anthropic" ? "claude-sonnet-4-20250514" : "gemini-2.0-flash"}
                    style={{ width: "100%", fontSize: 11, padding: "3px 4px", background: "var(--bg-primary)", color: "var(--text-primary)", border: "1px solid var(--border)", borderRadius: 3, marginTop: 2, boxSizing: "border-box" }}
                  />
                </label>
              </div>
              <label style={{ fontSize: 11, color: "var(--text-secondary)" }}>
                API Key
                <input
                  type="password"
                  value={ai.aiApiKey}
                  onChange={(e) => {
                    const key = e.target.value;
                    ai.setAiApiKey(key);
                    // Auto-detect provider from key format
                    if (key.startsWith("sk-ant-")) ai.setAiProvider("Anthropic");
                    else if (key.startsWith("sk-")) ai.setAiProvider("OpenAI");
                    else if (key.startsWith("AI")) ai.setAiProvider("Google");
                  }}
                  placeholder="sk-..."
                  style={{ width: "100%", fontSize: 11, padding: "3px 4px", background: "var(--bg-primary)", color: "var(--text-primary)", border: "1px solid var(--border)", borderRadius: 3, marginTop: 2, boxSizing: "border-box" }}
                />
              </label>
              <label style={{ fontSize: 11, color: "var(--text-secondary)", marginTop: 4, display: "block" }}>
                Base URL (optional)
                <input
                  value={ai.aiBaseUrl}
                  onChange={(e) => ai.setAiBaseUrl(e.target.value)}
                  placeholder="Leave empty for default"
                  style={{ width: "100%", fontSize: 11, padding: "3px 4px", background: "var(--bg-primary)", color: "var(--text-primary)", border: "1px solid var(--border)", borderRadius: 3, marginTop: 2, boxSizing: "border-box" }}
                />
              </label>
              <button type="button" className="btn btn-primary" onClick={ai.saveAiProvider} style={{ marginTop: 8, fontSize: 11 }}>
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
            {ai.aiConversation.length === 0 && !ai.analyzeAiError && (
              <p style={{ fontSize: 12, color: "var(--text-secondary)", textAlign: "center", marginTop: 40 }}>
                {stats.entity_count > 0
                  ? "Ask a question about the graph — the AI will search it for you..."
                  : "Load data first, then ask questions about the graph."}
              </p>
            )}
            {ai.aiConversation.map((msg, i) => (
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
            {ai.analyzeAiLoading && (
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
            {ai.aiLastSuggestions.length > 0 && (
              <div style={{ display: "flex", flexWrap: "wrap", gap: 6, marginBottom: 10 }}>
                {ai.aiLastSuggestions.map((s, i) => (
                  <button
                    key={i}
                    type="button"
                    className="btn btn-sm"
                    onClick={() => ai.handleAiSuggestion(s)}
                    style={{ fontSize: 11, display: "flex", alignItems: "center", gap: 4 }}
                    title={`${s.action}: ${s.target_id}`}
                  >
                    {s.action === "expand_node" ? <ChevronRight size={12} /> : <Sparkles size={12} />}
                    {s.label.length > 40 ? s.label.slice(0, 37) + "..." : s.label}
                  </button>
                ))}
              </div>
            )}
            {ai.analyzeAiError && (
              <div style={{ color: "var(--danger)", fontSize: 11, marginBottom: 8 }}>{ai.analyzeAiError}</div>
            )}
            <div ref={ai.aiChatEndRef} />
          </div>

          {/* Input area */}
          {stats.entity_count > 0 && (
            <div style={{ padding: "8px 12px", borderTop: "1px solid var(--border)", display: "flex", gap: 6 }}>
              <input
                value={ai.analyzeAiQuestion}
                onChange={(e) => ai.setAnalyzeAiQuestion(e.target.value)}
                onKeyDown={(e) => { if (e.key === "Enter" && !ai.analyzeAiLoading) ai.runAnalyzeAi(); }}
                placeholder="Ask about the graph..."
                disabled={ai.analyzeAiLoading}
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
                onClick={ai.runAnalyzeAi}
                disabled={ai.analyzeAiLoading}
                style={{ fontSize: 12 }}
              >
                {ai.analyzeAiLoading ? "..." : "Send"}
              </button>
            </div>
          )}
        </div>
      )}
      {/* PR-D: global command palette (Ctrl+K / Cmd+K). Lazy-loaded
          so the initial bundle isn't paying for it until the
          analyst actually opens it. */}
      {commandPaletteOpen && (
        <LazyBoundary>
          <CommandPalette
            open={commandPaletteOpen}
            onClose={() => setCommandPaletteOpen(false)}
            items={commandItems}
            onLog={addLog}
            invokeFn={(cmd, args) => invoke(cmd, args)}
          />
        </LazyBoundary>
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
