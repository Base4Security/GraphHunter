import { useState, useEffect, useCallback, useMemo } from "react";
import { invoke, errorMessage } from "../lib/tauri";
import type {
  DatasetInfo,
  LogEntry,
  PaginatedHuntResults,
  ScoreBreakdown,
  ScoredPath,
} from "../types";
import { formatTimestamp } from "../utils/time";
import ExportMenu from "./ExportMenu";

interface HuntResultsTableProps {
  totalPaths: number;
  onViewPath: (path: string[]) => void;
  onLog: (entry: LogEntry) => void;
}

const PAGE_SIZE = 50;

function scoreColor(score: number): string {
  if (score > 50) return "var(--danger)";
  if (score > 20) return "var(--warning)";
  return "var(--text-muted)";
}

function anomalyColor(score: number): string {
  if (score > 0.7) return "#ff4444";
  if (score > 0.4) return "#ffaa00";
  return "#44bb44";
}

function anomalyBg(score: number): string {
  if (score > 0.7) return "rgba(255,68,68,0.15)";
  if (score > 0.4) return "rgba(255,170,0,0.15)";
  return "rgba(68,187,68,0.15)";
}

function formatBreakdown(bd: ScoreBreakdown): string {
  let s = `Entity Rarity: ${(bd.entity_rarity * 100).toFixed(0)}%\nEdge Rarity: ${(bd.edge_rarity * 100).toFixed(0)}%\nNeighborhood Conc: ${(bd.neighborhood_concentration * 100).toFixed(0)}%\nTemporal Novelty: ${(bd.temporal_novelty * 100).toFixed(0)}%`;
  if (bd.gnn_threat > 0) {
    s += `\nGNN Threat: ${(bd.gnn_threat * 100).toFixed(0)}%`;
  }
  return s;
}

const formatTime = (ts: number) => formatTimestamp(ts, "time");

export default function HuntResultsTable({
  totalPaths,
  onViewPath,
  onLog,
}: HuntResultsTableProps) {
  const [page, setPage] = useState(0);
  const [minScore, setMinScore] = useState<number | null>(null);
  const [minScoreInput, setMinScoreInput] = useState("");
  const [results, setResults] = useState<PaginatedHuntResults | null>(null);
  const [selectedIdx, setSelectedIdx] = useState<number | null>(null);
  const [loading, setLoading] = useState(false);

  const hasAnomaly = results?.paths.some((p) => p.anomaly_score != null) ?? false;
  const hasDatasets =
    results?.paths.some((p) => (p.datasets_used?.length ?? 0) > 0) ?? false;
  const [datasetNameById, setDatasetNameById] = useState<Map<string, string>>(
    new Map()
  );

  // Load datasets once so badge labels can show friendly names instead of UUIDs.
  // Non-fatal on failure — badges fall back to a truncated UUID — but the
  // failure is logged so the analyst notices when names go missing instead
  // of silently seeing UUID stubs.
  useEffect(() => {
    (async () => {
      try {
        const list = await invoke<DatasetInfo[]>("cmd_list_datasets");
        const map = new Map<string, string>();
        for (const d of list) map.set(d.id, d.name);
        setDatasetNameById(map);
      } catch (e) {
        onLog({
          time: new Date().toLocaleTimeString("en-US", { hour12: false }),
          message: `Dataset list unavailable — badges will show truncated IDs (${errorMessage(e)})`,
          level: "warning",
        });
      }
    })();
  }, [onLog]);

  const resolveDatasetLabel = useMemo(
    () => (id: string) => {
      const name = datasetNameById.get(id);
      if (!name) return id.length > 10 ? `${id.slice(0, 8)}\u2026` : id;
      return name.length > 18 ? `${name.slice(0, 16)}\u2026` : name;
    },
    [datasetNameById]
  );

  const fetchPage = useCallback(
    async (p: number, score: number | null) => {
      setLoading(true);
      try {
        const res = await invoke<PaginatedHuntResults>("cmd_get_hunt_page", {
          page: p,
          pageSize: PAGE_SIZE,
          minScore: score,
        });
        setResults(res);
      } catch (e) {
        onLog({
          time: new Date().toLocaleTimeString("en-US", { hour12: false }),
          message: `Page fetch error: ${errorMessage(e)}`,
          level: "error",
        });
      } finally {
        setLoading(false);
      }
    },
    [onLog]
  );

  // Fetch on mount and when page/filter changes
  useEffect(() => {
    fetchPage(page, minScore);
  }, [page, minScore, fetchPage]);

  const handleRowClick = (sp: ScoredPath, idx: number) => {
    setSelectedIdx(idx);
    onViewPath(sp.path);
  };

  const handleFilterApply = () => {
    const val = minScoreInput.trim();
    const parsed = val === "" ? null : parseFloat(val);
    setMinScore(parsed !== null && isNaN(parsed) ? null : parsed);
    setPage(0);
    setSelectedIdx(null);
  };

  const handleTopAnomalies = () => {
    setMinScoreInput("20");
    setMinScore(20);
    setPage(0);
    setSelectedIdx(null);
  };

  const totalPages = results
    ? Math.max(1, Math.ceil(results.filtered_paths / PAGE_SIZE))
    : 1;
  const colSpan = 4 + (hasAnomaly ? 1 : 0) + (hasDatasets ? 1 : 0);

  return (
    <div className="hunt-table-overlay">
      <div className="hrt-header">
        <span className="hrt-title">
          Hunt Results: {results ? results.filtered_paths.toLocaleString() : totalPaths.toLocaleString()} paths
          {minScore !== null && ` (score >= ${minScore})`}
        </span>
        <div className="hrt-filter">
          <input
            type="text"
            value={minScoreInput}
            onChange={(e) => setMinScoreInput(e.target.value)}
            onKeyDown={(e) => e.key === "Enter" && handleFilterApply()}
            placeholder="Min score"
            style={{ width: 80 }}
          />
          <button className="btn btn-sm" onClick={handleFilterApply}>
            Filter
          </button>
          <button className="btn btn-sm" onClick={handleTopAnomalies}>
            Top Anomalies
          </button>
          {/* PR-D: single ExportMenu replaces the two dropdowns
              (hunt CSV/JSON + IOC formats). The new menu also
              surfaces subgraph + OCSF exports that previously had
              no UI surface. */}
          <ExportMenu enableHunt={true} onLog={onLog} size="sm" />
        </div>
      </div>

      <div className="hrt-table-wrap">
        <table className="hrt-table">
          <thead>
            <tr>
              <th style={{ width: 40 }}>#</th>
              <th>Path Chain</th>
              {hasAnomaly && <th style={{ width: 75 }}>Anomaly</th>}
              <th style={{ width: 80 }}>Max Score</th>
              <th style={{ width: 120 }}>Time Window</th>
              {hasDatasets && <th style={{ width: 140 }}>Source(s)</th>}
            </tr>
          </thead>
          <tbody>
            {loading ? (
              <tr>
                <td colSpan={colSpan} style={{ textAlign: "center", color: "var(--text-muted)" }}>
                  Loading...
                </td>
              </tr>
            ) : results && results.paths.length > 0 ? (
              results.paths.map((sp, idx) => {
                const globalIdx = page * PAGE_SIZE + idx + 1;
                return (
                  <tr
                    key={idx}
                    className={selectedIdx === idx ? "hrt-row-selected" : ""}
                    onClick={() => handleRowClick(sp, idx)}
                  >
                    <td style={{ color: "var(--text-muted)" }}>{globalIdx}</td>
                    <td className="hrt-chain">{sp.chain_summary}</td>
                    {hasAnomaly && (
                      <td>
                        {sp.anomaly_score != null && (
                          <span
                            title={sp.anomaly_breakdown ? formatBreakdown(sp.anomaly_breakdown) : undefined}
                            style={{
                              display: "inline-block",
                              padding: "1px 6px",
                              borderRadius: 4,
                              fontSize: 11,
                              fontWeight: "bold",
                              color: anomalyColor(sp.anomaly_score),
                              background: anomalyBg(sp.anomaly_score),
                              cursor: "default",
                            }}
                          >
                            {(sp.anomaly_score * 100).toFixed(0)}%
                          </span>
                        )}
                      </td>
                    )}
                    <td style={{ color: scoreColor(sp.max_score), fontWeight: "bold" }}>
                      {sp.max_score.toFixed(1)}
                    </td>
                    <td style={{ color: "var(--text-secondary)", fontSize: 11 }}>
                      {formatTime(sp.time_start)} - {formatTime(sp.time_end)}
                    </td>
                    {hasDatasets && (
                      <td>
                        <div style={{ display: "flex", flexWrap: "wrap", gap: 3 }}>
                          {(sp.datasets_used ?? []).map((id) => (
                            <span
                              key={id}
                              title={id}
                              style={{
                                padding: "1px 6px",
                                borderRadius: 3,
                                fontSize: 10,
                                background: "rgba(59, 130, 246, 0.18)",
                                color: "#93c5fd",
                                whiteSpace: "nowrap",
                              }}
                            >
                              {resolveDatasetLabel(id)}
                            </span>
                          ))}
                        </div>
                      </td>
                    )}
                  </tr>
                );
              })
            ) : (
              <tr>
                <td colSpan={colSpan} style={{ textAlign: "center", color: "var(--text-muted)" }}>
                  No results
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>

      <div className="hrt-pagination">
        <button
          className="btn btn-sm"
          disabled={page === 0}
          onClick={() => { setPage((p) => p - 1); setSelectedIdx(null); }}
        >
          Prev
        </button>
        <span style={{ color: "var(--text-secondary)", fontSize: 11 }}>
          Page {page + 1} / {totalPages}
        </span>
        <button
          className="btn btn-sm"
          disabled={page >= totalPages - 1}
          onClick={() => { setPage((p) => p + 1); setSelectedIdx(null); }}
        >
          Next
        </button>
      </div>
    </div>
  );
}
