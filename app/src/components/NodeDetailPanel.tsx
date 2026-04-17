import { useState } from "react";
import { X, Expand, Crosshair, Copy, MapPin, Globe } from "lucide-react";
import { invoke } from "@tauri-apps/api/core";
import type { NodeDetails, EntityType, ExplainedScore } from "../types";
import { ENTITY_COLORS } from "../types";
import { formatTimestamp } from "../utils/time";

interface NodeDetailPanelProps {
  details: NodeDetails;
  onClose: () => void;
  onExpand: (nodeId: string) => void;
  onSetCenter: (nodeId: string) => void;
  /** Show neighbours of the current node that have this entity type on the map (expand with type filter). */
  onShowNeighbourTypeOnMap?: (nodeId: string, entityType: string) => void;
}

/** Metadata keys rendered as enrichment badges instead of plain key-value rows. */
const ENRICHMENT_KEYS = new Set([
  "ip_class", "is_internal", "subnet",
  "geo_country", "geo_country_code", "geo_city", "geo_asn", "geo_as_org", "geo_isp",
  "service_category", "risk_tag", "service_description",
]);

export default function NodeDetailPanel({
  details,
  onClose,
  onExpand,
  onSetCenter,
  onShowNeighbourTypeOnMap,
}: NodeDetailPanelProps) {
  const color =
    ENTITY_COLORS[details.entity_type as EntityType] || "#94a3b8";
  const [enriching, setEnriching] = useState(false);
  const [explanation, setExplanation] = useState<ExplainedScore | null>(null);
  const [explaining, setExplaining] = useState(false);

  const loadExplanation = async () => {
    setExplaining(true);
    try {
      const exp = await invoke<ExplainedScore>("cmd_explain_score", {
        nodeId: details.id,
      });
      setExplanation(exp);
    } catch {
      setExplanation(null);
    } finally {
      setExplaining(false);
    }
  };

  const copyToClipboard = () => {
    navigator.clipboard.writeText(details.id);
  };

  const handleEnrichIp = async () => {
    setEnriching(true);
    try {
      await invoke("cmd_enrich_ip", { ip: details.id });
      // Trigger a re-fetch of node details by clicking the node again
      // (the enrichment data is now written into the entity's metadata)
      onExpand(details.id);
    } catch {
      // Silently ignore — user can retry
    } finally {
      setEnriching(false);
    }
  };

  const meta = details.metadata;
  const isIp = details.entity_type === "IP";
  const isApp = details.entity_type === "Application" || meta.service_category;
  const isExternal = meta.is_internal === "false";
  const hasGeo = !!meta.geo_country;

  // Remaining metadata keys (not rendered as badges)
  const regularMeta = Object.entries(meta).filter(([k]) => !ENRICHMENT_KEYS.has(k));

  const formatTs = (ts: number) => formatTimestamp(ts, "iso_space");

  return (
    <div className="node-detail-panel">
      {/* Header */}
      <div className="detail-header">
        <div className="detail-title" title={details.id}>
          {details.id.length > 28
            ? "..." + details.id.slice(-25)
            : details.id}
        </div>
        <button className="detail-close" onClick={onClose}>
          <X size={14} />
        </button>
      </div>

      {/* Type + Score */}
      <div className="detail-type-row">
        <span className="legend-dot" style={{ backgroundColor: color }} />
        <span className="detail-type">{details.entity_type}</span>
        {details.score > 0 && (
          <span className="detail-score">
            Score: {details.score.toFixed(1)}
          </span>
        )}
      </div>

      {/* Enrichment badges */}
      {(isIp || isApp) && (
        <div className="detail-badges">
          {isIp && meta.is_internal === "true" && (
            <span className="badge badge-internal">Internal</span>
          )}
          {isIp && isExternal && (
            <span className="badge badge-external">External</span>
          )}
          {meta.subnet && (
            <span className="badge badge-subnet">{meta.subnet}</span>
          )}
          {meta.geo_country && (
            <span className="badge badge-geo">
              {meta.geo_country_code || meta.geo_country}
              {meta.geo_as_org ? ` / ${meta.geo_as_org}` : ""}
            </span>
          )}
          {meta.geo_city && (
            <span className="badge badge-geo">{meta.geo_city}</span>
          )}
          {meta.geo_asn && (
            <span className="badge badge-geo">{meta.geo_asn}</span>
          )}
          {meta.service_category && (
            <span className={`badge risk-${meta.risk_tag || "info"}`}>
              {meta.service_category}
            </span>
          )}
          {meta.service_description && (
            <span className="badge badge-desc">{meta.service_description}</span>
          )}
          {isIp && isExternal && !hasGeo && (
            <button
              className="badge badge-action"
              onClick={handleEnrichIp}
              disabled={enriching}
              title="Enrich IP with GeoIP data"
            >
              <Globe size={10} /> {enriching ? "..." : "Enrich IP"}
            </button>
          )}
        </div>
      )}

      {/* Degrees */}
      <div className="detail-degrees">
        <div className="degree-item">
          <span className="degree-value">{details.in_degree}</span>
          <span className="degree-label">In</span>
        </div>
        <div className="degree-item">
          <span className="degree-value">{details.out_degree}</span>
          <span className="degree-label">Out</span>
        </div>
        <div className="degree-item">
          <span className="degree-value">
            {details.in_degree + details.out_degree}
          </span>
          <span className="degree-label">Total</span>
        </div>
      </div>

      {details.recommend_grouped_expansion && (
        <div
          className="detail-hint"
          style={{
            marginTop: 6,
            padding: "4px 8px",
            fontSize: 11,
            background: "var(--surface-alt, rgba(255, 200, 80, 0.08))",
            border: "1px solid var(--warn-border, rgba(255, 200, 80, 0.3))",
            borderRadius: 4,
          }}
          title="Plain expand_node will silently route this node through grouped expansion to avoid unwieldy output. You can also call cmd_expand_node_grouped directly."
        >
          High-degree node — expansion will auto-group parallel edges.
        </div>
      )}

      {/* Score Breakdown */}
      {(details.degree_score > 0 || details.pagerank_score > 0 || details.betweenness > 0) && (
        <div className="detail-section">
          <div className="detail-section-title">Score Breakdown</div>
          <div className="detail-degrees">
            <div className="degree-item">
              <span className="degree-value">{details.score.toFixed(1)}</span>
              <span className="degree-label">Composite</span>
            </div>
            <div className="degree-item">
              <span className="degree-value">{details.degree_score.toFixed(1)}</span>
              <span className="degree-label">Degree</span>
            </div>
            <div className="degree-item">
              <span className="degree-value">{details.pagerank_score.toFixed(1)}</span>
              <span className="degree-label">PageRank</span>
            </div>
            <div className="degree-item">
              <span className="degree-value">{details.betweenness.toFixed(1)}</span>
              <span className="degree-label">Betweenness</span>
            </div>
          </div>
        </div>
      )}

      {/* Anomaly breakdown (only when anomaly scoring is enabled) */}
      {details.anomaly_breakdown && (
        <div className="detail-section">
          <div className="detail-section-title">Anomaly Breakdown</div>
          <div className="detail-degrees">
            <div className="degree-item">
              <span className="degree-value">{details.anomaly_breakdown.entity_rarity.toFixed(2)}</span>
              <span className="degree-label">Entity Rarity</span>
            </div>
            <div className="degree-item">
              <span className="degree-value">{details.anomaly_breakdown.edge_rarity.toFixed(2)}</span>
              <span className="degree-label">Edge Rarity</span>
            </div>
            <div className="degree-item">
              <span className="degree-value">{details.anomaly_breakdown.neighborhood_concentration.toFixed(2)}</span>
              <span className="degree-label">Neighborhood</span>
            </div>
            <div className="degree-item">
              <span className="degree-value">{details.anomaly_breakdown.temporal_novelty.toFixed(2)}</span>
              <span className="degree-label">Temporal Novelty</span>
            </div>
          </div>
          <button
            type="button"
            className="btn btn-sm"
            style={{ marginTop: 6, width: "100%" }}
            onClick={loadExplanation}
            disabled={explaining}
          >
            {explaining ? "Explaining…" : explanation ? "Refresh explanation" : "Explain this score"}
          </button>
          {explanation && (
            <div
              style={{
                marginTop: 6,
                padding: "6px 8px",
                fontSize: 11,
                lineHeight: 1.4,
                background: "var(--surface-alt, rgba(0,0,0,0.04))",
                borderRadius: 4,
              }}
            >
              <div>{explanation.narrative}</div>
              {explanation.peers.length > 0 && (
                <div style={{ marginTop: 4, opacity: 0.8 }}>
                  Composite pctl: {explanation.composite_percentile.toFixed(1)} · Degree pctl: {explanation.degree_percentile.toFixed(1)}
                </div>
              )}
            </div>
          )}
        </div>
      )}

      {/* Time range */}
      {details.time_range && (
        <div className="detail-section">
          <div className="detail-section-title">Time Range</div>
          <div className="detail-time">
            {formatTs(details.time_range[0])} &mdash;{" "}
            {formatTs(details.time_range[1])}
          </div>
        </div>
      )}

      {/* Metadata (keys not rendered as badges above) */}
      {regularMeta.length > 0 && (
        <div className="detail-section">
          <div className="detail-section-title">Metadata</div>
          <div className="detail-metadata">
            {regularMeta.map(([k, v]) => (
              <div key={k} className="metadata-row">
                <span className="metadata-key">{k}</span>
                <span className="metadata-value" title={v}>
                  {v.length > 30 ? v.slice(0, 30) + "..." : v}
                </span>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Neighbors: types only, with "Show on map" per type (shows this node + neighbours of that type) */}
      {Object.keys(details.neighbor_types ?? {}).length > 0 && (
        <div className="detail-section">
          <div className="detail-section-title">Neighbors</div>
          <div className="detail-neighbor-types">
            {Object.entries(details.neighbor_types).map(([type_, count]) => (
              <div
                key={type_}
                className="neighbor-type-item"
                style={{
                  display: "flex",
                  alignItems: "center",
                  gap: 8,
                  padding: "4px 0",
                  borderBottom: "1px solid var(--border-subtle, rgba(255,255,255,0.06))",
                }}
              >
                <span
                  className="legend-dot"
                  style={{
                    backgroundColor:
                      ENTITY_COLORS[type_ as EntityType] || "#94a3b8",
                  }}
                />
                <span style={{ flex: 1 }}>{type_}</span>
                <span className="neighbor-count">{count}</span>
                {onShowNeighbourTypeOnMap && (
                  <button
                    type="button"
                    title={`Show ${type_} neighbours on map`}
                    onClick={() => onShowNeighbourTypeOnMap(details.id, type_)}
                    style={{
                      padding: "2px 6px",
                      fontSize: 10,
                      background: "none",
                      color: "var(--accent)",
                      border: "1px solid var(--accent)",
                      borderRadius: 4,
                      cursor: "pointer",
                      display: "flex",
                      alignItems: "center",
                      gap: 4,
                    }}
                  >
                    <MapPin size={10} />
                    Show on map
                  </button>
                )}
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Actions */}
      <div className="detail-actions">
        <button
          className="btn btn-sm btn-primary"
          onClick={() => onExpand(details.id)}
        >
          <Expand size={12} /> Expand
        </button>
        <button
          className="btn btn-sm"
          onClick={() => onSetCenter(details.id)}
        >
          <Crosshair size={12} /> Center
        </button>
        <button className="btn btn-sm" onClick={copyToClipboard}>
          <Copy size={12} /> Copy
        </button>
      </div>
    </div>
  );
}
