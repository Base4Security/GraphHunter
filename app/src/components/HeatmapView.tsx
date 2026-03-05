import { useState, useEffect } from "react";
import { invoke } from "../lib/tauri";
import type { HeatmapRow, LogEntry } from "../types";

interface HeatmapViewProps {
  statsKey: number; // changes when graph data changes to trigger refetch
  /** When provided, clicking a relation type row fetches node IDs for that relation and shows them on the map */
  onShowRelationOnMap?: (nodeIds: string[]) => void;
  /** Optional log callback to surface errors (e.g. backend failure) */
  onLog?: (entry: LogEntry) => void;
}

function formatHour(ts: number): string {
  if (ts === 0) return "-";
  const d = new Date(ts * 1000);
  return d.toLocaleString("en-US", {
    month: "short",
    day: "numeric",
    hour: "2-digit",
    hour12: false,
  });
}

function intensityColor(count: number, max: number): string {
  if (count === 0) return "transparent";
  const ratio = Math.min(count / max, 1);
  const alpha = 0.15 + ratio * 0.85;
  return `rgba(255, 107, 107, ${alpha})`;
}

export default function HeatmapView({ statsKey, onShowRelationOnMap, onLog }: HeatmapViewProps) {
  const [rows, setRows] = useState<HeatmapRow[]>([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [loadingRelation, setLoadingRelation] = useState<string | null>(null);

  async function handleRelationTypeClick(relationType: string) {
    if (!onShowRelationOnMap) return;
    setLoadingRelation(relationType);
    try {
      const nodeIds = await invoke<string[]>("cmd_get_node_ids_by_relation_type", {
        relationType,
      });
      onShowRelationOnMap(nodeIds);
    } catch (e) {
      const msg = e instanceof Error ? e.message : String(e);
      console.error("Failed to get node IDs by relation type:", e);
      onLog?.({
        time: new Date().toLocaleTimeString("en-US", { hour12: false }),
        message: `Heatmap: failed to load nodes for "${relationType}": ${msg}`,
        level: "error",
      });
    } finally {
      setLoadingRelation(null);
    }
  }

  useEffect(() => {
    let cancelled = false;
    setLoading(true);
    invoke<HeatmapRow[]>("cmd_get_temporal_heatmap")
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

  if (loading) return <div style={{ padding: 12, color: "var(--text-muted)" }}>Loading heatmap...</div>;
  if (error) return <div style={{ padding: 12, color: "var(--danger)" }}>{error}</div>;
  if (rows.length === 0) return <div style={{ padding: 12, color: "var(--text-muted)" }}>No temporal data available. Ingest logs first.</div>;

  // Collect all unique time buckets across all rows
  const allBuckets = new Set<number>();
  let globalMax = 0;
  for (const row of rows) {
    for (const [ts, count] of row.bins) {
      allBuckets.add(ts);
      if (count > globalMax) globalMax = count;
    }
  }
  const sortedBuckets = Array.from(allBuckets).sort((a, b) => a - b);

  // Downsample if too many columns (max 48 visible)
  const MAX_COLS = 48;
  const step = Math.max(1, Math.ceil(sortedBuckets.length / MAX_COLS));
  const displayBuckets = sortedBuckets.filter((_, i) => i % step === 0);

  return (
    <div style={{ padding: "8px 12px", overflowX: "auto" }}>
      <h3 style={{ margin: "0 0 8px", fontSize: 13, color: "var(--text-secondary)" }}>
        Temporal Heatmap (hourly bins)
      </h3>
      <div style={{ display: "grid", gridTemplateColumns: `120px repeat(${displayBuckets.length}, 1fr)`, gap: 1, fontSize: 10 }}>
        {/* Header row */}
        <div style={{ fontWeight: "bold", color: "var(--text-secondary)", padding: "2px 4px" }}>
          Relation Type
        </div>
        {displayBuckets.map((ts) => (
          <div
            key={ts}
            style={{
              writingMode: "vertical-rl",
              transform: "rotate(180deg)",
              fontSize: 8,
              color: "var(--text-muted)",
              padding: "2px 0",
              textAlign: "center",
              maxHeight: 60,
              overflow: "hidden",
            }}
          >
            {formatHour(ts)}
          </div>
        ))}

        {/* Data rows - relation type name is a link to show those nodes on the map */}
        {rows.map((row) => {
          const binMap = new Map(row.bins);
          const isClickable = !!onShowRelationOnMap;
          const isLoading = loadingRelation === row.relation_type;
          const handleClick = (evt: React.MouseEvent) => {
            evt.preventDefault();
            if (isClickable) handleRelationTypeClick(row.relation_type);
          };
          return (
            <div
              key={row.relation_type}
              style={{
                gridColumn: "1 / -1",
                display: "grid",
                gridTemplateColumns: `120px repeat(${displayBuckets.length}, 1fr)`,
                gap: 1,
                opacity: isLoading ? 0.6 : 1,
                alignItems: "stretch",
              }}
            >
              <div
                style={{
                  fontWeight: "bold",
                  padding: "4px",
                  display: "flex",
                  alignItems: "center",
                }}
              >
                {isClickable ? (
                  <button
                    type="button"
                    onClick={handleClick}
                    disabled={isLoading}
                    title={`Show nodes with ${row.relation_type} relations on map`}
                    style={{
                      background: "none",
                      border: "none",
                      padding: 0,
                      font: "inherit",
                      color: "var(--accent)",
                      textDecoration: "underline",
                      cursor: isLoading ? "wait" : "pointer",
                    }}
                  >
                    {row.relation_type}
                  </button>
                ) : (
                  <span style={{ color: "var(--accent)" }}>{row.relation_type}</span>
                )}
              </div>
              {displayBuckets.map((ts) => {
                let count = 0;
                for (let i = 0; i < step; i++) {
                  const idx = sortedBuckets.indexOf(ts) + i;
                  if (idx < sortedBuckets.length) {
                    count += binMap.get(sortedBuckets[idx]) || 0;
                  }
                }
                return (
                  <div
                    key={`${row.relation_type}-${ts}`}
                    title={isClickable ? `Show nodes with ${row.relation_type} relations on map` : `${row.relation_type}: ${count} events at ${formatHour(ts)}`}
                    style={{
                      backgroundColor: intensityColor(count, globalMax),
                      minHeight: 18,
                      borderRadius: 2,
                    }}
                  />
                );
              })}
            </div>
          );
        })}
      </div>
      <div style={{ marginTop: 8, fontSize: 10, color: "var(--text-muted)" }}>
        Color intensity: higher = more events in that time bin. {sortedBuckets.length} total bins, showing {displayBuckets.length}.
      </div>
    </div>
  );
}
