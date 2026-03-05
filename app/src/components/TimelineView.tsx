import { useState, useEffect } from "react";
import { invoke } from "../lib/tauri";
import type { TimelineRow } from "../types";
import { ENTITY_COLORS, type EntityType } from "../types";

interface TimelineViewProps {
  statsKey: number;
  /** When provided, clicking an entity type row fetches its node IDs and calls this to show them on the map */
  onShowTypeOnMap?: (nodeIds: string[]) => void;
  /** @deprecated Use onShowTypeOnMap for "show on map". Kept for backward compatibility. */
  onFilterByType?: (entityType: string) => void;
}

function formatTs(ts: number): string {
  if (ts === 0) return "-";
  return new Date(ts * 1000).toLocaleString("en-US", {
    month: "short",
    day: "numeric",
    hour: "2-digit",
    minute: "2-digit",
    hour12: false,
  });
}

export default function TimelineView({ statsKey, onShowTypeOnMap, onFilterByType }: TimelineViewProps) {
  const [rows, setRows] = useState<TimelineRow[]>([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [loadingType, setLoadingType] = useState<string | null>(null);

  async function handleRowClick(entityType: string) {
    if (onShowTypeOnMap) {
      setLoadingType(entityType);
      try {
        const nodeIds = await invoke<string[]>("cmd_get_entities_by_type", { typeName: entityType });
        if (nodeIds.length > 0) {
          onShowTypeOnMap(nodeIds);
        }
      } catch (e) {
        console.error("Failed to get entities by type:", e);
      } finally {
        setLoadingType(null);
      }
    }
    onFilterByType?.(entityType);
  }

  useEffect(() => {
    let cancelled = false;
    setLoading(true);
    invoke<TimelineRow[]>("cmd_get_timeline_data")
      .then((data) => {
        if (!cancelled) {
          setRows(data);
          setError(null);
        }
      })
      .catch((e) => {
        if (!cancelled) setError(String(e));
      })
      .finally(() => {
        if (!cancelled) setLoading(false);
      });
    return () => { cancelled = true; };
  }, [statsKey]);

  if (loading) return <div style={{ padding: 12, color: "var(--text-muted)" }}>Loading timeline...</div>;
  if (error) return <div style={{ padding: 12, color: "var(--danger)" }}>{error}</div>;
  if (rows.length === 0) return <div style={{ padding: 12, color: "var(--text-muted)" }}>No timeline data. Ingest logs first.</div>;

  // Global time range (use at least 1 hour so bar width/position scale is sensible)
  const globalMin = Math.min(...rows.map((r) => r.min_time));
  const globalMax = Math.max(...rows.map((r) => r.max_time));
  const globalRange = Math.max(globalMax - globalMin, 3600);

  const SVG_WIDTH = 400;
  const SVG_HEIGHT = 30;
  const MIN_BAR_HEIGHT = 2;

  return (
    <div style={{ padding: "8px 12px" }}>
      <h3 style={{ margin: "0 0 8px", fontSize: 13, color: "var(--text-secondary)" }}>
        Activity Timeline (per entity type)
      </h3>
      <div style={{ fontSize: 10, color: "var(--text-muted)", marginBottom: 8 }}>
        {formatTs(globalMin)} — {formatTs(globalMax)}
      </div>
      {rows.map((row) => {
        const color = ENTITY_COLORS[row.entity_type as EntityType] || "#888";
        const maxCount = Math.max(...row.bins.map(([, c]) => c), 1);

        return (
          <div
            key={row.entity_type}
            style={{
              display: "flex",
              alignItems: "center",
              gap: 8,
              marginBottom: 4,
              cursor: onShowTypeOnMap ? "pointer" : onFilterByType ? "pointer" : "default",
              opacity: loadingType === row.entity_type ? 0.6 : 1,
            }}
            onClick={() => handleRowClick(row.entity_type)}
            title={onShowTypeOnMap ? `Show all ${row.entity_type} on map` : `${row.entity_type}: ${row.bins.reduce((s, [, c]) => s + c, 0)} events`}
          >
            <span
              style={{
                width: 70,
                fontSize: 11,
                fontWeight: "bold",
                color,
                textAlign: "right",
                flexShrink: 0,
              }}
            >
              {row.entity_type}
            </span>
            <svg
              width={SVG_WIDTH}
              height={SVG_HEIGHT}
              viewBox={`0 0 ${SVG_WIDTH} ${SVG_HEIGHT}`}
              style={{ flexShrink: 0, background: "rgba(255,255,255,0.03)", borderRadius: 3 }}
            >
              {row.bins
                .filter(([, count]) => count > 0)
                .map(([ts, count]) => {
                  const barWidth = Math.max(2, (3600 / globalRange) * SVG_WIDTH);
                  let x = ((ts - globalMin) / globalRange) * SVG_WIDTH;
                  x = Math.max(0, Math.min(SVG_WIDTH - barWidth, x));
                  const barHeight =
                    count > 0
                      ? Math.max(MIN_BAR_HEIGHT, (count / maxCount) * SVG_HEIGHT)
                      : 0;
                  return (
                    <rect
                      key={ts}
                      x={x}
                      y={SVG_HEIGHT - barHeight}
                      width={barWidth}
                      height={barHeight}
                      fill={color}
                      opacity={0.7}
                    >
                      <title>{`${count} events`}</title>
                    </rect>
                  );
                })}
            </svg>
            <span style={{ fontSize: 10, color: "var(--text-muted)", flexShrink: 0, width: 40 }}>
              {row.bins.reduce((s, [, c]) => s + c, 0)}
            </span>
          </div>
        );
      })}
    </div>
  );
}
