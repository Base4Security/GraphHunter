import { createContext, useContext, useReducer } from "react";
import type { ReactNode, Dispatch } from "react";
import type { LogEntry } from "../types";

/**
 * Standalone context for the activity log.
 *
 * The log is the highest-frequency state update in the app — every user
 * action and every backend event pushes a new entry. Keeping it in the
 * main `AppStateContext` caused the whole App tree to re-render on every
 * log push. This module isolates log state so only subscribers of
 * `useLogState()` re-render when a new entry is added.
 *
 * `addLog` / `clearLog` are the only mutations. Dispatch has stable
 * identity from `useReducer`, so callers that only need to push entries
 * can subscribe to `useLogDispatch()` without ever re-rendering.
 *
 * The reducer truncates to 100 entries on every push — matching the
 * previous behaviour and keeping memory bounded for long-running sessions.
 */

const LOG_MAX_ENTRIES = 300;

export type LogAction =
  | { type: "ADD_LOG"; payload: LogEntry }
  | { type: "CLEAR_LOG" };

function logReducer(state: LogEntry[], action: LogAction): LogEntry[] {
  switch (action.type) {
    case "ADD_LOG":
      // New entry is prepended so the newest appears first in the UI list.
      return [action.payload, ...state].slice(0, LOG_MAX_ENTRIES);
    case "CLEAR_LOG":
      return [];
    default:
      return state;
  }
}

const LogStateContext = createContext<LogEntry[] | null>(null);
const LogDispatchContext = createContext<Dispatch<LogAction> | null>(null);

export function LogProvider({ children }: { children: ReactNode }) {
  const [log, dispatch] = useReducer(logReducer, []);
  return (
    <LogDispatchContext.Provider value={dispatch}>
      <LogStateContext.Provider value={log}>
        {children}
      </LogStateContext.Provider>
    </LogDispatchContext.Provider>
  );
}

/** Subscribe to the activity log. Components using this will re-render on every log change. */
export function useLogState(): LogEntry[] {
  const ctx = useContext(LogStateContext);
  if (ctx === null) {
    throw new Error("useLogState must be used within a LogProvider");
  }
  return ctx;
}

/**
 * Access the log dispatch. Dispatch identity is stable from `useReducer`,
 * so subscribing to this hook does NOT cause re-renders when log changes —
 * ideal for components that only need to push entries.
 */
export function useLogDispatch(): Dispatch<LogAction> {
  const ctx = useContext(LogDispatchContext);
  if (ctx === null) {
    throw new Error("useLogDispatch must be used within a LogProvider");
  }
  return ctx;
}
