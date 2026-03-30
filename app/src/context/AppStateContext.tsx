import { createContext, useContext, useReducer } from "react";
import type { ReactNode, Dispatch } from "react";
import type {
  GraphStats,
  Subgraph,
  Neighborhood,
  NodeDetails,
  LogEntry,
  SessionInfo,
  Note,
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

// ── AppState interface ──

export interface AppState {
  // Graph data
  stats: GraphStats;
  log: LogEntry[];

  // UI mode
  mode: AppMode;
  bottomTab: BottomTab;

  // Session
  currentSession: SessionInfo | null;
  sessions: SessionInfo[];
  sessionError: string;

  // Hunt mode
  subgraph: Subgraph | null;
  highlightPaths: string[][] | null;
  huntPathCount: number;
  showHuntTable: boolean;

  // Explorer mode
  selectedNodeId: string | null;
  nodeDetails: NodeDetails | null;
  explorerNeighborhood: Neighborhood | null;

  // Path nodes & entity types
  pathNodeIds: string[];
  entityTypesInGraph: string[];

  // Right/left menus
  rightMenuOpen: "pathNodes" | "notes" | null;
  leftMenuOpen: "datasets" | "activity" | "metrics" | null;

  // Notes
  notes: Note[];

  // Center node (for panning the graph view)
  centerNodeId: string | null;

  // Bottom panel height
  bottomPanelHeight: number;

  // Map navigation history
  mapPast: MapState[];
  mapFuture: MapState[];
}

// ── Initial state ──

export const initialAppState: AppState = {
  stats: { entity_count: 0, relation_count: 0 },
  log: [],
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
};

// ── Action types ──

export type AppAction =
  | { type: "SET_STATS"; payload: GraphStats }
  | { type: "ADD_LOG"; payload: LogEntry }
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
  | { type: "SET_RIGHT_MENU"; payload: "pathNodes" | "notes" | null }
  | { type: "SET_LEFT_MENU"; payload: "datasets" | "activity" | "metrics" | null }
  | { type: "SET_NOTES"; payload: Note[] }
  | { type: "SET_CENTER_NODE_ID"; payload: string | null }
  | { type: "SET_BOTTOM_PANEL_HEIGHT"; payload: number }
  | { type: "PUSH_MAP_STATE"; payload: MapState }
  | { type: "SET_MAP_PAST"; payload: MapState[] }
  | { type: "SET_MAP_FUTURE"; payload: MapState[] }
  | { type: "RESTORE_MAP_STATE"; payload: MapState }
  | { type: "CLEAR_SESSION_STATE" };

// ── Reducer ──

export function appReducer(state: AppState, action: AppAction): AppState {
  switch (action.type) {
    case "SET_STATS":
      return { ...state, stats: action.payload };
    case "ADD_LOG":
      return { ...state, log: [action.payload, ...state.log].slice(0, 100) };
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
      return { ...state, rightMenuOpen: action.payload };
    case "SET_LEFT_MENU":
      return { ...state, leftMenuOpen: action.payload };
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
      };
    default:
      return state;
  }
}

// ── Context ──

const AppStateContext = createContext<AppState | null>(null);
const AppDispatchContext = createContext<Dispatch<AppAction> | null>(null);

export function AppStateProvider({ children }: { children: ReactNode }) {
  const [state, dispatch] = useReducer(appReducer, initialAppState);

  return (
    <AppStateContext.Provider value={state}>
      <AppDispatchContext.Provider value={dispatch}>
        {children}
      </AppDispatchContext.Provider>
    </AppStateContext.Provider>
  );
}

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
