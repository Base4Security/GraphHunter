/**
 * Global Sentinel event listener hook.
 *
 * Lives in App.tsx (never unmounts) so polling‐loop events
 * (sentinel-data, sentinel-error, sentinel-disconnected, kql-executed)
 * continue to be processed even when the Datasets panel is closed.
 */
import { useEffect, useRef, useState, useCallback } from "react";
import { isTauri } from "../lib/runtime";
import type {
  GraphStats,
  LogEntry,
  SentinelDataEvent,
  SentinelErrorEvent,
  KqlQueryExecutedEvent,
  ConnectorStatusResponse,
} from "../types";
import { invoke } from "../lib/tauri";

function now(): string {
  return new Date().toLocaleTimeString("en-US", { hour12: false });
}

export interface SentinelState {
  streaming: boolean;
  status: string;
  liveStats: { entities: number; relations: number };
}

export function useSentinelEvents(
  addLog: (entry: LogEntry) => void,
  stats: GraphStats,
  onStatsUpdate: (stats: GraphStats) => void,
) {
  const [sentinel, setSentinel] = useState<SentinelState>({
    streaming: false,
    status: "disconnected",
    liveStats: { entities: 0, relations: 0 },
  });

  const statsRef = useRef(stats);
  statsRef.current = stats;

  // Check if connector is already running on mount
  useEffect(() => {
    if (!isTauri()) return;
    invoke<ConnectorStatusResponse>("cmd_sentinel_status")
      .then((st) => {
        if (st.connected) {
          setSentinel((prev) => ({
            ...prev,
            streaming: true,
            status: st.status?.state ?? "connected",
          }));
        }
      })
      .catch((err) => console.error("cmd_sentinel_status:", err));
  }, []);

  // Global event listeners — always active when streaming
  useEffect(() => {
    if (!sentinel.streaming || !isTauri()) return;

    let unData: (() => void) | null = null;
    let unError: (() => void) | null = null;
    let unDisconnected: (() => void) | null = null;
    let unKql: (() => void) | null = null;

    (async () => {
      const { listen } = await import("@tauri-apps/api/event");

      unData = await listen<SentinelDataEvent>("sentinel-data", (event) => {
        const d = event.payload;
        setSentinel((prev) => ({
          ...prev,
          status: "connected",
          liveStats: {
            entities: prev.liveStats.entities + d.new_entities,
            relations: prev.liveStats.relations + d.new_relations,
          },
        }));
        onStatsUpdate({
          entity_count: statsRef.current.entity_count + d.new_entities,
          relation_count: statsRef.current.relation_count + d.new_relations,
        });
      });

      unError = await listen<SentinelErrorEvent>("sentinel-error", (event) => {
        const e = event.payload;
        setSentinel((prev) => ({
          ...prev,
          status: "error",
          ...(e.will_retry ? {} : { streaming: false }),
        }));
        addLog({ time: now(), message: `Sentinel: ${e.error}`, level: "error" });
      });

      unDisconnected = await listen("sentinel-disconnected", () => {
        setSentinel({
          streaming: false,
          status: "disconnected",
          liveStats: { entities: 0, relations: 0 },
        });
        addLog({ time: now(), message: "Sentinel: Disconnected", level: "info" });
      });

      unKql = await listen<KqlQueryExecutedEvent>("kql-executed", (event) => {
        const e = event.payload;
        addLog({
          time: now(),
          message: `KQL [${e.source}] ${e.target}: ${e.row_count} rows → +${e.entities_created}E +${e.relations_created}R`,
          level: "info",
          kql: e.kql,
          kqlSource: e.source as "polling" | "adhoc",
          kqlTarget: e.target,
          kqlRowCount: e.row_count,
        });
      });
    })();

    return () => {
      unData?.();
      unError?.();
      unDisconnected?.();
      unKql?.();
    };
  }, [sentinel.streaming, addLog, onStatsUpdate]);

  const setStreaming = useCallback((streaming: boolean) => {
    setSentinel((prev) => ({
      ...prev,
      streaming,
      ...(streaming ? {} : { status: "disconnected", liveStats: { entities: 0, relations: 0 } }),
    }));
  }, []);

  const setStatus = useCallback((status: string) => {
    setSentinel((prev) => ({ ...prev, status }));
  }, []);

  const resetLiveStats = useCallback(() => {
    setSentinel((prev) => ({ ...prev, liveStats: { entities: 0, relations: 0 } }));
  }, []);

  return {
    sentinelStreaming: sentinel.streaming,
    sentinelStatus: sentinel.status,
    sentinelLiveStats: sentinel.liveStats,
    setStreaming,
    setStatus,
    resetLiveStats,
  };
}
