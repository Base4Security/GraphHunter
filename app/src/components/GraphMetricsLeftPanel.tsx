import { useState, useEffect } from "react";
import { invoke } from "../lib/tauri";
import { BarChart3, X, SlidersHorizontal, Palette, Activity, ArrowRight, Shield, Brain } from "lucide-react";
import type {
  GraphStats,
  LogEntry,
  EntityType,
  CompactionStats,
  ScoringWeights,
} from "../types";
import { ENTITY_COLORS } from "../types";

interface EntityTypeCount {
  entity_type: string;
  count: number;
}

interface GraphMetricsLeftPanelProps {
  currentSessionId: string | null;
  stats: GraphStats;
  onStatsUpdate: (stats: GraphStats) => void;
  onLog: (entry: LogEntry) => void;
  onClose: () => void;
  onShowTypeOnMap?: (nodeIds: string[]) => void;
  onShowNodeOnMap?: (nodeId: string) => void;
}

function now(): string {
  return new Date().toLocaleTimeString("en-US", { hour12: false });
}

export default function GraphMetricsLeftPanel({
  currentSessionId,
  stats,
  onStatsUpdate,
  onLog,
  onClose,
  onShowTypeOnMap,
  onShowNodeOnMap,
}: GraphMetricsLeftPanelProps) {
  const [showScoring, setShowScoring] = useState(false);
  const [degreeWeight, setDegreeWeight] = useState(33);
  const [pagerankWeight, setPagerankWeight] = useState(33);
  const [betweennessWeight, setBetweennessWeight] = useState(33);
  const [pagerankLambda, setPagerankLambda] = useState(0.001);
  const [scoringLoading, setScoringLoading] = useState(false);
  const [compactDate, setCompactDate] = useState("");
  const [compactLoading, setCompactLoading] = useState(false);
  const [showGraphMetrics, setShowGraphMetrics] = useState(true);
  const [showTypesAvailable, setShowTypesAvailable] = useState(true);

  const [typeCounts, setTypeCounts] = useState<EntityTypeCount[]>([]);
  const [typeCountsLoading, setTypeCountsLoading] = useState(false);
  const [expandedType, setExpandedType] = useState<string | null>(null);
  const [entitiesForType, setEntitiesForType] = useState<string[]>([]);
  const [entitiesLoading, setEntitiesLoading] = useState(false);
  const [entitiesTotalCount, setEntitiesTotalCount] = useState(0);
  const [entitiesLoadingMore, setEntitiesLoadingMore] = useState(false);

  // Anomaly scoring state
  const [showAnomaly, setShowAnomaly] = useState(false);
  const [anomalyEnabled, setAnomalyEnabled] = useState(false);
  const [anomalyLoading, setAnomalyLoading] = useState(false);
  const [w1, setW1] = useState(25);
  const [w2, setW2] = useState(30);
  const [w3, setW3] = useState(25);
  const [w4, setW4] = useState(20);
  const [w5, setW5] = useState(0);

  // GNN Threat Model state
  const [showGnn, setShowGnn] = useState(false);
  const [gnnLoaded, setGnnLoaded] = useState(false);
  const [gnnModelName, setGnnModelName] = useState("");
  const [gnnLoading, setGnnLoading] = useState(false);
  const [gnnKHops, setGnnKHops] = useState(2);
  const [gnnScoredCount, setGnnScoredCount] = useState<number | null>(null);

  useEffect(() => {
    if (!currentSessionId) {
      setTypeCounts([]);
      setAnomalyEnabled(false);
      return;
    }
    let cancelled = false;
    setTypeCountsLoading(true);
    invoke<EntityTypeCount[]>("cmd_get_entity_type_counts")
      .then((list) => {
        if (!cancelled) setTypeCounts(list);
      })
      .catch(() => {
        if (!cancelled) setTypeCounts([]);
      })
      .finally(() => {
        if (!cancelled) setTypeCountsLoading(false);
      });
    // Check anomaly config
    invoke<ScoringWeights | null>("cmd_get_anomaly_config")
      .then((config) => {
        if (!cancelled && config) {
          setAnomalyEnabled(true);
          setW1(Math.round(config.w1_entity_rarity * 100));
          setW2(Math.round(config.w2_edge_rarity * 100));
          setW3(Math.round(config.w3_neighborhood_conc * 100));
          setW4(Math.round(config.w4_temporal_novelty * 100));
          setW5(Math.round((config.w5_gnn_threat ?? 0) * 100));
        }
      })
      .catch(() => {});
    // Check GNN model status
    invoke<boolean>("cmd_gnn_model_status")
      .then((loaded) => {
        if (!cancelled) setGnnLoaded(loaded);
      })
      .catch(() => {});
    return () => {
      cancelled = true;
    };
  }, [currentSessionId, stats.entity_count, stats.relation_count]);

  const ENTITY_PAGE_SIZE = 100;

  const handleTypeClick = (typeName: string) => {
    if (expandedType === typeName) {
      setExpandedType(null);
      setEntitiesForType([]);
      setEntitiesTotalCount(0);
      return;
    }
    setExpandedType(typeName);
    setEntitiesLoading(true);
    setEntitiesForType([]);
    setEntitiesTotalCount(0);
    invoke<{ entities: string[]; total_count: number }>("cmd_get_entities_by_type_paginated", {
      typeName,
      offset: 0,
      limit: ENTITY_PAGE_SIZE,
    })
      .then((result) => {
        setEntitiesForType(result.entities);
        setEntitiesTotalCount(result.total_count);
      })
      .catch(() => setEntitiesForType([]))
      .finally(() => setEntitiesLoading(false));
  };

  const loadMoreEntities = () => {
    if (!expandedType) return;
    setEntitiesLoadingMore(true);
    invoke<{ entities: string[]; total_count: number }>("cmd_get_entities_by_type_paginated", {
      typeName: expandedType,
      offset: entitiesForType.length,
      limit: ENTITY_PAGE_SIZE,
    })
      .then((result) => {
        setEntitiesForType((prev) => [...prev, ...result.entities]);
        setEntitiesTotalCount(result.total_count);
      })
      .catch(() => {})
      .finally(() => setEntitiesLoadingMore(false));
  };

  async function refreshStats() {
    try {
      const s = await invoke<GraphStats>("cmd_get_graph_stats");
      onStatsUpdate(s);
    } catch (e) {
      onLog({ time: now(), message: `${e}`, level: "error" });
    }
  }

  async function toggleAnomaly() {
    if (anomalyEnabled) {
      // Can't disable once enabled in this session — just inform
      onLog({ time: now(), message: "Anomaly scoring is active for this session", level: "info" });
      return;
    }
    setAnomalyLoading(true);
    try {
      const weights: ScoringWeights = {
        w1_entity_rarity: w1 / 100,
        w2_edge_rarity: w2 / 100,
        w3_neighborhood_conc: w3 / 100,
        w4_temporal_novelty: w4 / 100,
        w5_gnn_threat: w5 / 100,
      };
      await invoke("cmd_enable_anomaly_scoring", { weights });
      setAnomalyEnabled(true);
      onLog({ time: now(), message: "Anomaly scoring enabled", level: "success" });
    } catch (e) {
      onLog({ time: now(), message: `Anomaly enable failed: ${e}`, level: "error" });
    } finally {
      setAnomalyLoading(false);
    }
  }

  async function updateAnomalyWeights() {
    setAnomalyLoading(true);
    try {
      const weights: ScoringWeights = {
        w1_entity_rarity: w1 / 100,
        w2_edge_rarity: w2 / 100,
        w3_neighborhood_conc: w3 / 100,
        w4_temporal_novelty: w4 / 100,
        w5_gnn_threat: w5 / 100,
      };
      await invoke("cmd_update_anomaly_weights", { weights });
      onLog({ time: now(), message: "Anomaly weights updated", level: "success" });
    } catch (e) {
      onLog({ time: now(), message: `Weight update failed: ${e}`, level: "error" });
    } finally {
      setAnomalyLoading(false);
    }
  }

  async function loadGnnModel() {
    setGnnLoading(true);
    try {
      const { open } = await import("@tauri-apps/plugin-dialog");
      const selected = await open({
        multiple: false,
        filters: [{ name: "ONNX Models", extensions: ["onnx"] }],
      });
      if (!selected) {
        setGnnLoading(false);
        return;
      }
      const modelPath = selected as string;
      await invoke<string>("cmd_load_gnn_model", { modelPath });
      const fileName = modelPath.split(/[/\\]/).pop() ?? modelPath;
      setGnnLoaded(true);
      setGnnModelName(fileName);
      setGnnScoredCount(null);
      onLog({ time: now(), message: `GNN model loaded: ${fileName}`, level: "success" });
    } catch (e) {
      onLog({ time: now(), message: `GNN load failed: ${e}`, level: "error" });
    } finally {
      setGnnLoading(false);
    }
  }

  async function computeGnnScores() {
    setGnnLoading(true);
    try {
      const count = await invoke<number>("cmd_compute_gnn_scores", { kHops: gnnKHops });
      setGnnScoredCount(count);
      onLog({ time: now(), message: `GNN scores computed for ${count} entities`, level: "success" });
    } catch (e) {
      onLog({ time: now(), message: `GNN scoring failed: ${e}`, level: "error" });
    } finally {
      setGnnLoading(false);
    }
  }

  return (
    <aside className="left-menu-panel" aria-label="Graph Metrics">
      <div className="left-menu-panel-header">
        <span className="left-menu-panel-title">
          <BarChart3 size={14} />
          Graph Metrics
        </span>
        <button
          type="button"
          className="left-menu-panel-close"
          onClick={onClose}
          title="Hide Graph Metrics"
          aria-label="Hide Graph Metrics"
        >
          <X size={14} />
        </button>
      </div>
      <div className="left-menu-panel-content">
        <button
          type="button"
          className="panel-left-section-toggle"
          onClick={() => setShowGraphMetrics((v) => !v)}
          aria-expanded={showGraphMetrics}
        >
          {showGraphMetrics ? "▼" : "▶"}
          <span>Stats</span>
        </button>
        {showGraphMetrics && (
          <div className="panel-left-section">
            <div style={{ display: "flex", justifyContent: "flex-end", marginBottom: 6 }}>
              <button className="btn btn-sm" onClick={refreshStats} title="Refresh stats">
                <Activity size={12} />
              </button>
            </div>
            <div className="stats-grid">
              <div className="stat-card">
                <div className="value">{stats.entity_count.toLocaleString()}</div>
                <div className="label">Entities</div>
              </div>
              <div className="stat-card">
                <div className="value">{stats.relation_count.toLocaleString()}</div>
                <div className="label">Relations</div>
              </div>
            </div>
          </div>
        )}

        <hr className="section-divider" />

        <button
          type="button"
          className="panel-left-section-toggle"
          onClick={() => setShowScoring((v) => !v)}
          aria-expanded={showScoring}
        >
          {showScoring ? "▼" : "▶"}
          <SlidersHorizontal size={14} />
          <span>Scoring</span>
        </button>
        {showScoring && (
          <div className="panel-left-section">
            <div style={{ fontSize: 11, color: "var(--text-muted)", marginBottom: 8 }}>
              Adjust scoring weights and recalculate composite scores.
            </div>
            {[
              { label: "Degree", value: degreeWeight, set: setDegreeWeight },
              { label: "PageRank", value: pagerankWeight, set: setPagerankWeight },
              { label: "Betweenness", value: betweennessWeight, set: setBetweennessWeight },
            ].map(({ label, value, set }) => (
              <div key={label} style={{ marginBottom: 6 }}>
                <div style={{ display: "flex", justifyContent: "space-between", fontSize: 11, marginBottom: 2 }}>
                  <span>{label}</span>
                  <span style={{ color: "var(--text-muted)" }}>{value}</span>
                </div>
                <input
                  type="range"
                  min={0}
                  max={100}
                  value={value}
                  onChange={(e) => set(Number(e.target.value))}
                  style={{ width: "100%" }}
                />
              </div>
            ))}
            <div style={{ marginBottom: 6 }}>
              <div style={{ display: "flex", justifyContent: "space-between", fontSize: 11, marginBottom: 2 }}>
                <span>PageRank λ (decay)</span>
                <span style={{ color: "var(--text-muted)" }}>{pagerankLambda.toFixed(4)}</span>
              </div>
              <input
                type="range"
                min={0}
                max={0.01}
                step={0.0001}
                value={pagerankLambda}
                onChange={(e) => setPagerankLambda(Number(e.target.value))}
                style={{ width: "100%" }}
              />
            </div>
            <button
              className="btn btn-primary"
              disabled={scoringLoading || !currentSessionId}
              onClick={async () => {
                setScoringLoading(true);
                try {
                  await invoke("cmd_compute_pagerank", { lambda: pagerankLambda });
                  await invoke("cmd_compute_composite_scores", {
                    degreeWeight: degreeWeight / 100,
                    pagerankWeight: pagerankWeight / 100,
                    betweennessWeight: betweennessWeight / 100,
                  });
                  onLog({ time: now(), message: "Scores recalculated", level: "success" });
                } catch (e) {
                  onLog({ time: now(), message: `Scoring failed: ${e}`, level: "error" });
                } finally {
                  setScoringLoading(false);
                }
              }}
            >
              <SlidersHorizontal size={14} />
              {scoringLoading ? "Recalculating..." : "Recalculate"}
            </button>

            <div style={{ marginTop: 12, paddingTop: 8, borderTop: "1px solid var(--border)" }}>
              <div style={{ fontSize: 11, color: "var(--text-muted)", marginBottom: 6 }}>
                Temporal Compaction — merge duplicate edges before a cutoff time.
              </div>
              <input
                type="datetime-local"
                value={compactDate}
                onChange={(e) => setCompactDate(e.target.value)}
                style={{
                  width: "100%",
                  padding: "6px 8px",
                  background: "var(--bg-tertiary)",
                  color: "var(--text-primary)",
                  border: "1px solid var(--border)",
                  borderRadius: 4,
                  fontSize: 12,
                  marginBottom: 6,
                }}
              />
              <button
                className="btn"
                disabled={compactLoading || !compactDate || !currentSessionId}
                onClick={async () => {
                  setCompactLoading(true);
                  try {
                    const cutoff = Math.floor(new Date(compactDate).getTime() / 1000);
                    const result = await invoke<CompactionStats>("cmd_compact", { cutoffTimestamp: cutoff });
                    onLog({
                      time: now(),
                      message: `Compacted: ${result.edges_removed} edges removed (${result.groups_compacted} groups)`,
                      level: "success",
                    });
                    refreshStats();
                  } catch (e) {
                    onLog({ time: now(), message: `Compaction failed: ${e}`, level: "error" });
                  } finally {
                    setCompactLoading(false);
                  }
                }}
              >
                {compactLoading ? "Compacting..." : "Compact"}
              </button>
            </div>
          </div>
        )}

        <hr className="section-divider" />

        <button
          type="button"
          className="panel-left-section-toggle"
          onClick={() => setShowAnomaly((v) => !v)}
          aria-expanded={showAnomaly}
        >
          {showAnomaly ? "▼" : "▶"}
          <Shield size={14} />
          <span>Anomaly Scoring</span>
          {anomalyEnabled && (
            <span style={{ fontSize: 9, color: "#44bb44", marginLeft: 4 }}>ON</span>
          )}
        </button>
        {showAnomaly && (
          <div className="panel-left-section">
            <div style={{ fontSize: 11, color: "var(--text-muted)", marginBottom: 8 }}>
              Endogenous anomaly scoring for hunt path ranking. Weights should sum to 100.
            </div>
            {[
              { label: "Entity Rarity", value: w1, set: setW1 },
              { label: "Edge Rarity", value: w2, set: setW2 },
              { label: "Neighborhood Conc.", value: w3, set: setW3 },
              { label: "Temporal Novelty", value: w4, set: setW4 },
              { label: "GNN Threat", value: w5, set: setW5 },
            ].map(({ label, value, set }) => (
              <div key={label} style={{ marginBottom: 6 }}>
                <div style={{ display: "flex", justifyContent: "space-between", fontSize: 11, marginBottom: 2 }}>
                  <span>{label}</span>
                  <span style={{ color: "var(--text-muted)" }}>{value}%</span>
                </div>
                <input
                  type="range"
                  min={0}
                  max={100}
                  value={value}
                  onChange={(e) => set(Number(e.target.value))}
                  disabled={anomalyLoading}
                  style={{ width: "100%" }}
                />
              </div>
            ))}
            <div style={{ display: "flex", gap: 4 }}>
              {!anomalyEnabled ? (
                <button
                  className="btn btn-primary"
                  disabled={anomalyLoading || !currentSessionId}
                  onClick={toggleAnomaly}
                >
                  <Shield size={14} />
                  {anomalyLoading ? "Enabling..." : "Enable"}
                </button>
              ) : (
                <button
                  className="btn btn-primary"
                  disabled={anomalyLoading || !currentSessionId}
                  onClick={updateAnomalyWeights}
                >
                  <SlidersHorizontal size={14} />
                  {anomalyLoading ? "Updating..." : "Update Weights"}
                </button>
              )}
            </div>
          </div>
        )}

        <hr className="section-divider" />

        <button
          type="button"
          className="panel-left-section-toggle"
          onClick={() => setShowGnn((v) => !v)}
          aria-expanded={showGnn}
        >
          {showGnn ? "▼" : "▶"}
          <Brain size={14} />
          <span>GNN Threat Model</span>
          <span style={{ fontSize: 9, color: gnnLoaded ? "#44bb44" : "var(--text-muted)", marginLeft: 4 }}>
            {gnnLoaded ? "READY" : "OFF"}
          </span>
        </button>
        {showGnn && (
          <div className="panel-left-section">
            <div style={{ fontSize: 11, color: "var(--text-muted)", marginBottom: 8 }}>
              Load an ONNX model exported from GraphOS-APT to compute GNN-based threat scores.
              The model classifies k-hop subgraphs into: benign, exfiltration, c2_beacon,
              lateral_movement, privilege_escalation. Scores feed into anomaly weight W5 (GNN Threat).
            </div>

            <button
              className="btn"
              disabled={gnnLoading || !currentSessionId}
              onClick={loadGnnModel}
              style={{ width: "100%", marginBottom: 8 }}
            >
              <Brain size={14} />
              {gnnLoading && !gnnLoaded ? "Loading..." : "Load Model (.onnx)"}
            </button>

            {gnnLoaded && gnnModelName && (
              <div style={{ fontSize: 11, color: "#44bb44", marginBottom: 8, wordBreak: "break-all" }}>
                Model: {gnnModelName}
              </div>
            )}

            <div style={{ marginBottom: 8 }}>
              <div style={{ display: "flex", justifyContent: "space-between", fontSize: 11, marginBottom: 2 }}>
                <span>K-Hops (subgraph depth)</span>
                <span style={{ color: "var(--text-muted)" }}>{gnnKHops}</span>
              </div>
              <input
                type="range"
                min={1}
                max={5}
                value={gnnKHops}
                onChange={(e) => setGnnKHops(Number(e.target.value))}
                disabled={gnnLoading}
                style={{ width: "100%" }}
              />
            </div>

            <button
              className="btn btn-primary"
              disabled={gnnLoading || !gnnLoaded || !anomalyEnabled || !currentSessionId}
              onClick={computeGnnScores}
              style={{ width: "100%" }}
            >
              <Brain size={14} />
              {gnnLoading && gnnLoaded ? "Computing..." : "Compute Scores"}
            </button>

            {!anomalyEnabled && gnnLoaded && (
              <div style={{ fontSize: 10, color: "var(--warning, #cc8800)", marginTop: 6 }}>
                Enable Anomaly Scoring first to use GNN scores.
              </div>
            )}

            {gnnScoredCount !== null && (
              <div style={{ fontSize: 11, color: "var(--text-muted)", marginTop: 6 }}>
                Last run: {gnnScoredCount.toLocaleString()} entities scored
              </div>
            )}
          </div>
        )}

        <hr className="section-divider" />

        <button
          type="button"
          className="panel-left-section-toggle"
          onClick={() => setShowTypesAvailable((v) => !v)}
          aria-expanded={showTypesAvailable}
        >
          {showTypesAvailable ? "▼" : "▶"}
          <Palette size={14} />
          <span>Types Available</span>
        </button>
        {showTypesAvailable && (
          <div className="panel-left-section">
            {typeCountsLoading ? (
              <div className="types-available-loading">Loading…</div>
            ) : typeCounts.length === 0 ? (
              <div className="types-available-empty">No types in graph yet.</div>
            ) : (
              <div className="legend">
                {typeCounts.map(({ entity_type: typeName, count }) => (
                  <div key={typeName}>
                    <div className="legend-item-row">
                      <button
                        type="button"
                        className="legend-item legend-item-clickable"
                        onClick={() => handleTypeClick(typeName)}
                        title={`Expand to list ${count} ${typeName} elements`}
                      >
                        <span
                          className="legend-dot"
                          style={{
                            background: ENTITY_COLORS[typeName as EntityType] ?? "var(--text-muted)",
                          }}
                        />
                        <span className="legend-label">{typeName}</span>
                        <span className="legend-count">({count})</span>
                      </button>
                      {expandedType === typeName && entitiesForType.length > 0 && (
                        <button
                          type="button"
                          className="legend-goto-btn"
                          onClick={(e) => {
                            e.stopPropagation();
                            onShowTypeOnMap?.(entitiesForType);
                          }}
                          title="Show this type on map"
                          aria-label="Show on map"
                        >
                          <ArrowRight size={14} />
                        </button>
                      )}
                    </div>
                    {expandedType === typeName && (
                      <div className="legend-entities-list">
                        {entitiesLoading ? (
                          <div className="legend-entities-loading">Loading…</div>
                        ) : (
                          <>
                            <ul className="legend-entities-ul">
                              {entitiesForType.map((id) => (
                                <li key={id} className="legend-entity-row">
                                  <span className="legend-entity-id" title={id}>
                                    {id.length > 36 ? `${id.slice(0, 32)}…` : id}
                                  </span>
                                  <button
                                    type="button"
                                    className="legend-goto-btn"
                                    onClick={() => onShowNodeOnMap?.(id)}
                                    title={`Show on map: ${id}`}
                                    aria-label="Show on map"
                                  >
                                    <ArrowRight size={14} />
                                  </button>
                                </li>
                              ))}
                            </ul>
                            {entitiesForType.length < entitiesTotalCount && (
                              <button
                                type="button"
                                className="btn btn-sm"
                                style={{ width: "100%", marginTop: 4, fontSize: 10 }}
                                onClick={loadMoreEntities}
                                disabled={entitiesLoadingMore}
                              >
                                {entitiesLoadingMore
                                  ? "Loading..."
                                  : `Load more (${entitiesForType.length}/${entitiesTotalCount})`}
                              </button>
                            )}
                          </>
                        )}
                      </div>
                    )}
                  </div>
                ))}
              </div>
            )}
          </div>
        )}
      </div>
    </aside>
  );
}
