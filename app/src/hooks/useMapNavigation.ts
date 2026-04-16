import { useCallback, useEffect, useRef } from "react";
import { useUIState, useGraphState, useAppDispatch } from "../context/AppStateContext";
import type { MapState } from "../context/AppStateContext";
import type { LogEntry } from "../types";

export function useMapNavigation(addLog: (entry: LogEntry) => void) {
  const dispatch = useAppDispatch();
  const { mode, bottomTab } = useUIState();
  const {
    subgraph,
    highlightPaths,
    explorerNeighborhood,
    selectedNodeId,
    nodeDetails,
    mapPast,
    mapFuture,
  } = useGraphState();

  const mapStateRef = useRef<MapState | null>(null);

  // Keep ref in sync with current map state
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

  return {
    mapPast,
    mapFuture,
    pushMapState,
    handleMapBack,
    handleMapForward,
  };
}
