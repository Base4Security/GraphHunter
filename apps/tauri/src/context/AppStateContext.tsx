import { createContext, useContext, useReducer, useMemo } from "react";
import type { ReactNode, Dispatch } from "react";
import type {
  GraphStats,
  Subgraph,
  Neighborhood,
  NodeDetails,
  SessionInfo,
  Note,
  EdgeBundle,
} from "../types";

// ── Mode types ──

export type AppMode = "hunt" | "explore";
export type BottomTab = "hunt" | "explore" | "events" | "heatmap" | "timeline";

/** Snapshot of map view for back/forward navigation */
export interface MapState {
  mode: AppMode;
  bottomTab: BottomTab;
  subgraph: Subgraph | null;
  highlightPaths: string[][] | null;
  neighborhood: Neighborhood | null;
  selectedNodeId: string | null;
  nodeDetails: NodeDetails | null;
}

// ── Sliced state interfaces ──
// Splitting the monolithic state into domain slices lets consumers subscribe
// to only the fields they need, so a pixel-drag of the bottom panel handle
// (UISlice.bottomPanelHeight) doesn't re-render the graph canvas or the
// session selector.

/** High-frequency UI state: panels, tabs, resize, viewport. */
export interface UISlice {
  mode: AppMode;
  bottomTab: BottomTab;
  rightMenuOpen: "pathNodes" | "notes" | "edgeDetail" | null;
  leftMenuOpen: "datasets" | "activity" | "metrics" | null;
  centerNodeId: string | null;
  bottomPanelHeight: number;
  viewState: { zoom: number; pan: { x: number; y: number } } | null;
  /** Edge currently displayed in the right-side EdgeDetailPanel.
   *  `null` when no edge is selected. Set via `onEdgeClick` in
   *  GraphCanvas; cleared when the panel closes or another panel
   *  opens. The bundle carries the full list of underlying edges
   *  so the panel can drill into per-edge metadata without
   *  another backend round-trip. */
  selectedEdgeBundle: EdgeBundle | null;
}

/** Session-scoped data: session identity, stats, notes, path nodes. */
export interface SessionSlice {
  currentSession: SessionInfo | null;
  sessions: SessionInfo[];
  sessionError: string;
  stats: GraphStats;
  notes: Note[];
  pathNodeIds: string[];
  entityTypesInGraph: string[];
}

/** Graph view state: subgraph, hunt results, explorer, navigation history. */
export interface GraphSlice {
  subgraph: Subgraph | null;
  highlightPaths: string[][] | null;
  huntPathCount: number;
  showHuntTable: boolean;
  selectedNodeId: string | null;
  nodeDetails: NodeDetails | null;
  explorerNeighborhood: Neighborhood | null;
  mapPast: MapState[];
  mapFuture: MapState[];
}

// ── Full AppState (union of slices) ──

export interface AppState extends UISlice, SessionSlice, GraphSlice {}

// ── Initial state ──

export const initialAppState: AppState = {
  stats: { entity_count: 0, relation_count: 0 },
  mode: "hunt",
  bottomTab: "explore",
  currentSession: null,
  sessions: [],
  sessionError: "",
  subgraph: null,
  highlightPaths: null,
  huntPathCount: 0,
  showHuntTable: false,
  selectedNodeId: null,
  nodeDetails: null,
  explorerNeighborhood: null,
  pathNodeIds: [],
  entityTypesInGraph: [],
  rightMenuOpen: null,
  leftMenuOpen: "datasets",
  notes: [],
  centerNodeId: null,
  bottomPanelHeight: 300,
  mapPast: [],
  mapFuture: [],
  viewState: null,
  selectedEdgeBundle: null,
};

// ── Action types ──

export type AppAction =
  | { type: "SET_STATS"; payload: GraphStats }
  | { type: "SET_MODE"; payload: AppMode }
  | { type: "SET_BOTTOM_TAB"; payload: BottomTab }
  | { type: "SET_CURRENT_SESSION"; payload: SessionInfo | null }
  | { type: "SET_SESSIONS"; payload: SessionInfo[] }
  | { type: "ADD_SESSION"; payload: SessionInfo }
  | { type: "SET_SESSION_ERROR"; payload: string }
  | { type: "SET_SUBGRAPH"; payload: Subgraph | null }
  | { type: "SET_HIGHLIGHT_PATHS"; payload: string[][] | null }
  | { type: "SET_HUNT_PATH_COUNT"; payload: number }
  | { type: "SET_SHOW_HUNT_TABLE"; payload: boolean }
  | { type: "SET_SELECTED_NODE_ID"; payload: string | null }
  | { type: "SET_NODE_DETAILS"; payload: NodeDetails | null }
  | { type: "SET_EXPLORER_NEIGHBORHOOD"; payload: Neighborhood | null }
  | { type: "SET_PATH_NODE_IDS"; payload: string[] }
  | { type: "ADD_PATH_NODE"; payload: string }
  | { type: "REMOVE_PATH_NODE"; payload: string }
  | { type: "SET_ENTITY_TYPES_IN_GRAPH"; payload: string[] }
  | { type: "SET_RIGHT_MENU"; payload: "pathNodes" | "notes" | "edgeDetail" | null }
  | { type: "SET_LEFT_MENU"; payload: "datasets" | "activity" | "metrics" | null }
  | { type: "SET_SELECTED_EDGE_BUNDLE"; payload: EdgeBundle | null }
  | { type: "SET_NOTES"; payload: Note[] }
  | { type: "SET_CENTER_NODE_ID"; payload: string | null }
  | { type: "SET_BOTTOM_PANEL_HEIGHT"; payload: number }
  | { type: "PUSH_MAP_STATE"; payload: MapState }
  | { type: "SET_MAP_PAST"; payload: MapState[] }
  | { type: "SET_MAP_FUTURE"; payload: MapState[] }
  | { type: "RESTORE_MAP_STATE"; payload: MapState }
  | { type: "SET_VIEW_STATE"; payload: { zoom: number; pan: { x: number; y: number } } | null }
  | { type: "CLEAR_SESSION_STATE" };

// ── Reducer ──

export function appReducer(state: AppState, action: AppAction): AppState {
  switch (action.type) {
    case "SET_STATS":
      return { ...state, stats: action.payload };
    case "SET_MODE":
      return { ...state, mode: action.payload };
    case "SET_BOTTOM_TAB":
      return { ...state, bottomTab: action.payload };
    case "SET_CURRENT_SESSION":
      return { ...state, currentSession: action.payload };
    case "SET_SESSIONS":
      return { ...state, sessions: action.payload };
    case "ADD_SESSION": {
      const exists = state.sessions.some((s) => s.id === action.payload.id);
      return exists ? state : { ...state, sessions: [...state.sessions, action.payload] };
    }
    case "SET_SESSION_ERROR":
      return { ...state, sessionError: action.payload };
    case "SET_SUBGRAPH":
      return { ...state, subgraph: action.payload };
    case "SET_HIGHLIGHT_PATHS":
      return { ...state, highlightPaths: action.payload };
    case "SET_HUNT_PATH_COUNT":
      return { ...state, huntPathCount: action.payload };
    case "SET_SHOW_HUNT_TABLE":
      return { ...state, showHuntTable: action.payload };
    case "SET_SELECTED_NODE_ID":
      return { ...state, selectedNodeId: action.payload };
    case "SET_NODE_DETAILS":
      return { ...state, nodeDetails: action.payload };
    case "SET_EXPLORER_NEIGHBORHOOD":
      return { ...state, explorerNeighborhood: action.payload };
    case "SET_PATH_NODE_IDS":
      return { ...state, pathNodeIds: action.payload };
    case "ADD_PATH_NODE":
      return state.pathNodeIds.includes(action.payload)
        ? state
        : { ...state, pathNodeIds: [...state.pathNodeIds, action.payload] };
    case "REMOVE_PATH_NODE":
      return { ...state, pathNodeIds: state.pathNodeIds.filter((id) => id !== action.payload) };
    case "SET_ENTITY_TYPES_IN_GRAPH":
      return { ...state, entityTypesInGraph: action.payload };
    case "SET_RIGHT_MENU":
      // Clearing the right menu also clears the edge selection so a
      // future open of the edgeDetail panel doesn't flash stale data.
      return {
        ...state,
        rightMenuOpen: action.payload,
        selectedEdgeBundle:
          action.payload === "edgeDetail" ? state.selectedEdgeBundle : null,
      };
    case "SET_LEFT_MENU":
      return { ...state, leftMenuOpen: action.payload };
    case "SET_SELECTED_EDGE_BUNDLE":
      return { ...state, selectedEdgeBundle: action.payload };
    case "SET_NOTES":
      return { ...state, notes: action.payload };
    case "SET_CENTER_NODE_ID":
      return { ...state, centerNodeId: action.payload };
    case "SET_BOTTOM_PANEL_HEIGHT":
      return { ...state, bottomPanelHeight: action.payload };
    case "PUSH_MAP_STATE":
      return {
        ...state,
        mapPast: [...state.mapPast, action.payload],
        mapFuture: [],
      };
    case "SET_MAP_PAST":
      return { ...state, mapPast: action.payload };
    case "SET_MAP_FUTURE":
      return { ...state, mapFuture: action.payload };
    case "RESTORE_MAP_STATE":
      return {
        ...state,
        mode: action.payload.mode,
        bottomTab: action.payload.bottomTab,
        subgraph: action.payload.subgraph,
        highlightPaths: action.payload.highlightPaths,
        explorerNeighborhood: action.payload.neighborhood,
        selectedNodeId: action.payload.selectedNodeId,
        nodeDetails: action.payload.nodeDetails,
      };
    case "SET_VIEW_STATE":
      return { ...state, viewState: action.payload };
    case "CLEAR_SESSION_STATE":
      return {
        ...state,
        stats: { entity_count: 0, relation_count: 0 },
        subgraph: null,
        highlightPaths: null,
        explorerNeighborhood: null,
        selectedNodeId: null,
        nodeDetails: null,
        huntPathCount: 0,
        showHuntTable: false,
        pathNodeIds: [],
        entityTypesInGraph: [],
        notes: [],
        mapPast: [],
        mapFuture: [],
        viewState: null,
        selectedEdgeBundle: null,
      };
    default:
      return state;
  }
}

// ── Contexts ──
// One dispatch shared by all slices (actions go to the single reducer).
// Three slice contexts so consumers only re-render when their slice changes.

const UIContext = createContext<UISlice | null>(null);
const SessionContext = createContext<SessionSlice | null>(null);
const GraphContext = createContext<GraphSlice | null>(null);
const AppDispatchContext = createContext<Dispatch<AppAction> | null>(null);

// Legacy full-state context — kept for backward compatibility; prefer the
// slice hooks below in new code.
const AppStateContext = createContext<AppState | null>(null);

export function AppStateProvider({ children }: { children: ReactNode }) {
  const [state, dispatch] = useReducer(appReducer, initialAppState);

  // Memoize each slice so the context value only changes when its fields do.
  // React skips re-renders for consumers whose context value is referentially
  // identical, so this is the key mechanism that prevents cascade re-renders.

  const ui: UISlice = useMemo(() => ({
    mode: state.mode,
    bottomTab: state.bottomTab,
    rightMenuOpen: state.rightMenuOpen,
    leftMenuOpen: state.leftMenuOpen,
    centerNodeId: state.centerNodeId,
    bottomPanelHeight: state.bottomPanelHeight,
    viewState: state.viewState,
    selectedEdgeBundle: state.selectedEdgeBundle,
  }), [
    state.mode, state.bottomTab, state.rightMenuOpen, state.leftMenuOpen,
    state.centerNodeId, state.bottomPanelHeight, state.viewState,
    state.selectedEdgeBundle,
  ]);

  const session: SessionSlice = useMemo(() => ({
    currentSession: state.currentSession,
    sessions: state.sessions,
    sessionError: state.sessionError,
    stats: state.stats,
    notes: state.notes,
    pathNodeIds: state.pathNodeIds,
    entityTypesInGraph: state.entityTypesInGraph,
  }), [
    state.currentSession, state.sessions, state.sessionError, state.stats,
    state.notes, state.pathNodeIds, state.entityTypesInGraph,
  ]);

  const graph: GraphSlice = useMemo(() => ({
    subgraph: state.subgraph,
    highlightPaths: state.highlightPaths,
    huntPathCount: state.huntPathCount,
    showHuntTable: state.showHuntTable,
    selectedNodeId: state.selectedNodeId,
    nodeDetails: state.nodeDetails,
    explorerNeighborhood: state.explorerNeighborhood,
    mapPast: state.mapPast,
    mapFuture: state.mapFuture,
  }), [
    state.subgraph, state.highlightPaths, state.huntPathCount,
    state.showHuntTable, state.selectedNodeId, state.nodeDetails,
    state.explorerNeighborhood, state.mapPast, state.mapFuture,
  ]);

  return (
    <AppDispatchContext.Provider value={dispatch}>
      <AppStateContext.Provider value={state}>
        <UIContext.Provider value={ui}>
          <SessionContext.Provider value={session}>
            <GraphContext.Provider value={graph}>
              {children}
            </GraphContext.Provider>
          </SessionContext.Provider>
        </UIContext.Provider>
      </AppStateContext.Provider>
    </AppDispatchContext.Provider>
  );
}

// ── Slice hooks (prefer these in new code) ──

export function useUIState(): UISlice {
  const ctx = useContext(UIContext);
  if (!ctx) throw new Error("useUIState must be used within AppStateProvider");
  return ctx;
}

export function useSessionState(): SessionSlice {
  const ctx = useContext(SessionContext);
  if (!ctx) throw new Error("useSessionState must be used within AppStateProvider");
  return ctx;
}

export function useGraphState(): GraphSlice {
  const ctx = useContext(GraphContext);
  if (!ctx) throw new Error("useGraphState must be used within AppStateProvider");
  return ctx;
}

// ── Legacy hooks (backward compatible) ──

export function useAppState(): AppState {
  const ctx = useContext(AppStateContext);
  if (!ctx) {
    throw new Error("useAppState must be used within AppStateProvider");
  }
  return ctx;
}

export function useAppDispatch(): Dispatch<AppAction> {
  const ctx = useContext(AppDispatchContext);
  if (!ctx) {
    throw new Error("useAppDispatch must be used within AppStateProvider");
  }
  return ctx;
}
