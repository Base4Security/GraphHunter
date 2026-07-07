import { useMemo, useState } from "react";
import { X, Crosshair, Copy, MapPin, ChevronLeft, ChevronRight, Pin } from "lucide-react";
import type { EdgeBundle, SubgraphEdge } from "../types";
import { relColor, relGroup } from "../styles/relationPalette";
import { formatTimestamp } from "../utils/time";

/**
 * Right-side panel for inspecting a single graph edge (or bundle of
 * parallel edges). Mirrors `NodeDetailPanel`'s visual surface — same
 * sticky header, badge row, metadata grid, action row — but the data
 * is per-edge rather than per-entity.
 *
 * **Why drill-down inside the panel?** The canvas bundles edges with
 * the same (source, target, rel_type) into one drawn line so dense
 * incidents stay legible. The metadata of each underlying edge
 * differs (flow_id, sensor_uid, bytes_fwd/rev, sni, kerberos_user,
 * ntlm_domain\\user, suricata_alert_signature, …), so when N > 1
 * we paginate through the underlying records right here. The first
 * record is auto-selected; the user can step through with the
 * prev/next buttons or click a row in the list.
 */
interface EdgeDetailPanelProps {
  bundle: EdgeBundle;
  onClose: () => void;
  /** Centre the viewport on the bundle's source or target node. */
  onCentreNode: (nodeId: string) => void;
  /** Pin a node to Path Nodes for hunt-style multi-hop pivots. */
  onPinNode: (nodeId: string) => void;
}

/**
 * Metadata keys that contribute structural identity to the edge
 * (source IDs, flow IDs, sensor pivots). Surfaced first so the
 * analyst gets the pivot keys before raw counters.
 */
const PIVOT_KEYS = new Set([
  "source",
  "sensor_uid",
  "flow_id",
  "sensor",
  "exporter_domain_id",
  "flow_sequence",
  "dataset_id",
  "source_file",
  "pcap_file",
]);

/** L4 telemetry — bytes, packets, ports, protocol, tcp flags. */
const L4_KEYS = new Set([
  "protocol",
  "protocol_num",
  "src_port",
  "dst_port",
  "bytes_fwd",
  "bytes_rev",
  "packets_fwd",
  "packets_rev",
  "tcp_flags",
  "duration_ms",
  "icmp_type",
  "icmp_code",
]);

/** L7 / application-layer signal. */
const L7_KEYS = new Set([
  "l7_decoded",
  "sni",
  "ja3",
  "ja3s",
  "tls_ech",
  "tls_version",
  "http_host",
  "http_method",
  "http_status",
  "qname",
  "qtype",
  "resolver",
  "service",
  "smb2_command",
  "smb2_command_name",
  "smb_dialect",
  "ssh_banner",
  "ftp_user",
  "suspected_doh",
  "suspected_dot",
]);

/** Auth-protocol identity extraction (PR1b in the ingest stack). */
const AUTH_KEYS = new Set([
  "kerberos_user",
  "kerberos_kind",
  "kerberos_realm",
  "kerberos_service",
  "kerberos_error",
  "ldap_user",
  "ntlm_user",
  "ntlm_domain",
]);

/** Suricata alert payload (PR2 in the ingest stack). */
const ALERT_KEYS = new Set([
  "suricata_alert_signature",
  "suricata_alert_category",
  "suricata_alert_severity",
  "suricata_alert_sid",
  "event_type",
]);

interface MetaGroup {
  title: string;
  entries: Array<[string, string]>;
}

/** Group an edge's metadata into stable sections so the eye finds
 *  the pivot keys first, then L4, then L7, then auth, then alert,
 *  with everything else falling into "Other". */
function groupMetadata(meta: Record<string, string>): MetaGroup[] {
  const pivot: Array<[string, string]> = [];
  const l4: Array<[string, string]> = [];
  const l7: Array<[string, string]> = [];
  const auth: Array<[string, string]> = [];
  const alert: Array<[string, string]> = [];
  const other: Array<[string, string]> = [];
  for (const [k, v] of Object.entries(meta)) {
    if (PIVOT_KEYS.has(k)) pivot.push([k, v]);
    else if (L4_KEYS.has(k)) l4.push([k, v]);
    else if (L7_KEYS.has(k)) l7.push([k, v]);
    else if (AUTH_KEYS.has(k)) auth.push([k, v]);
    else if (ALERT_KEYS.has(k)) alert.push([k, v]);
    else other.push([k, v]);
  }
  const out: MetaGroup[] = [];
  if (pivot.length) out.push({ title: "Pivot", entries: pivot });
  if (l4.length) out.push({ title: "L4", entries: l4 });
  if (l7.length) out.push({ title: "L7", entries: l7 });
  if (auth.length) out.push({ title: "Auth", entries: auth });
  if (alert.length) out.push({ title: "Alert", entries: alert });
  if (other.length) out.push({ title: "Other", entries: other });
  return out;
}

function shortId(id: string, max = 28): string {
  return id.length > max ? "..." + id.slice(-(max - 3)) : id;
}

export default function EdgeDetailPanel({
  bundle,
  onClose,
  onCentreNode,
  onPinNode,
}: EdgeDetailPanelProps) {
  // `selected` is the index into bundle.underlying. The first edge
  // is auto-selected on mount, and the user can step through with
  // ChevronLeft/ChevronRight or by clicking a row in the bundle list.
  const [selected, setSelected] = useState(0);

  const selectedEdge: SubgraphEdge | undefined = bundle.underlying[selected];
  const groups = useMemo(
    () => (selectedEdge ? groupMetadata(selectedEdge.metadata) : []),
    [selectedEdge],
  );
  const color = relColor(bundle.rel_type);
  const group = relGroup(bundle.rel_type);

  const copyAsJson = () => {
    if (!selectedEdge) return;
    const payload = {
      source: bundle.source,
      target: bundle.target,
      rel_type: bundle.rel_type,
      timestamp: selectedEdge.timestamp,
      metadata: selectedEdge.metadata,
      dataset_id: selectedEdge.dataset_id ?? null,
    };
    navigator.clipboard.writeText(JSON.stringify(payload, null, 2));
  };

  const fmtTs = (ts: number) =>
    ts > 0 ? formatTimestamp(ts, "iso_space") : "—";

  return (
    <div className="node-detail-panel">
      {/* Header — mirror NodeDetailPanel.detail-header */}
      <div className="detail-header">
        <div className="detail-title" title={`${bundle.source} → ${bundle.target}`}>
          {shortId(bundle.source, 14)} → {shortId(bundle.target, 14)}
        </div>
        <button className="detail-close" onClick={onClose} aria-label="Close edge detail">
          <X size={14} />
        </button>
      </div>

      {/* Type + group badge */}
      <div className="detail-type-row">
        <span className="legend-dot" style={{ backgroundColor: color }} />
        <span className="detail-type">{bundle.rel_type}</span>
        <span
          className="detail-score"
          style={{ textTransform: "capitalize", color: "var(--text-secondary)" }}
          title="Semantic group of this relation type"
        >
          {group}
        </span>
      </div>

      {/* Bundle disclosure: list of underlying edges with a count.
          When count = 1 we still show the timestamp row but skip the
          paginator. */}
      <div className="detail-section">
        <div className="detail-section-title">
          {bundle.count > 1
            ? `Showing ${selected + 1} of ${bundle.count} flows`
            : "Edge"}
        </div>
        <div className="detail-degrees">
          <div className="degree-item">
            <span className="degree-value">{bundle.count}</span>
            <span className="degree-label">Records</span>
          </div>
          <div className="degree-item">
            <span className="degree-value" title={fmtTs(bundle.first_ts)}>
              {fmtTs(bundle.first_ts).slice(11)}
            </span>
            <span className="degree-label">First</span>
          </div>
          <div className="degree-item">
            <span className="degree-value" title={fmtTs(bundle.last_ts)}>
              {fmtTs(bundle.last_ts).slice(11)}
            </span>
            <span className="degree-label">Last</span>
          </div>
        </div>
        {bundle.count > 1 && (
          <div style={{ display: "flex", gap: 4, marginTop: 6 }}>
            <button
              type="button"
              className="btn btn-sm"
              onClick={() => setSelected((i) => Math.max(0, i - 1))}
              disabled={selected === 0}
              title="Previous record"
              aria-label="Previous record"
            >
              <ChevronLeft size={12} />
            </button>
            <button
              type="button"
              className="btn btn-sm"
              onClick={() =>
                setSelected((i) => Math.min(bundle.count - 1, i + 1))
              }
              disabled={selected >= bundle.count - 1}
              title="Next record"
              aria-label="Next record"
            >
              <ChevronRight size={12} />
            </button>
            <span
              style={{
                fontSize: 11,
                color: "var(--text-secondary)",
                alignSelf: "center",
                marginLeft: 4,
              }}
            >
              {fmtTs(selectedEdge?.timestamp ?? 0)}
            </span>
          </div>
        )}
      </div>

      {/* Bundle list — only when N > 1. Each row is one underlying
          edge; click to switch the metadata view. Capped at 200 rows
          in the UI; the rest are still reachable via the paginator. */}
      {bundle.count > 1 && (
        <div className="detail-section">
          <div className="detail-section-title">Records</div>
          <div
            style={{
              maxHeight: 160,
              overflowY: "auto",
              border: "1px solid var(--border)",
              borderRadius: 4,
              background: "var(--bg-input)",
            }}
          >
            {bundle.underlying.slice(0, 200).map((edge, idx) => {
              const isSelected = idx === selected;
              // Pick a single distinguishing key per row so the
              // analyst can tell flows apart at a glance. Order
              // matters: most distinguishing first.
              const pivot =
                edge.metadata.sensor_uid ??
                edge.metadata.flow_id ??
                edge.metadata.qname ??
                edge.metadata.sni ??
                edge.metadata.http_host ??
                edge.metadata.kerberos_user ??
                edge.metadata.ntlm_user ??
                "";
              return (
                <button
                  key={`${idx}-${edge.timestamp}`}
                  type="button"
                  className="bundle-row"
                  onClick={() => setSelected(idx)}
                  style={{
                    display: "flex",
                    width: "100%",
                    alignItems: "center",
                    gap: 8,
                    padding: "4px 8px",
                    background: isSelected
                      ? "var(--bg-panel)"
                      : "transparent",
                    border: "none",
                    borderBottom: "1px solid var(--border)",
                    color: isSelected ? "var(--accent)" : "var(--text-primary)",
                    cursor: "pointer",
                    fontFamily: "var(--font-mono)",
                    fontSize: 11,
                    textAlign: "left",
                  }}
                  title={pivot || `#${idx + 1}`}
                >
                  <span style={{ flex: "0 0 28px", color: "var(--text-secondary)" }}>
                    #{idx + 1}
                  </span>
                  <span style={{ flex: 1, minWidth: 0, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>
                    {pivot || "—"}
                  </span>
                  <span style={{ flex: "0 0 auto", color: "var(--text-secondary)" }}>
                    {fmtTs(edge.timestamp).slice(11)}
                  </span>
                </button>
              );
            })}
            {bundle.underlying.length > 200 && (
              <div
                style={{
                  padding: "4px 8px",
                  fontSize: 11,
                  color: "var(--text-secondary)",
                  background: "var(--bg-secondary)",
                }}
              >
                + {bundle.underlying.length - 200} more — use ‹ / › to
                step through
              </div>
            )}
          </div>
        </div>
      )}

      {/* Endpoints — copyable src/dst with quick actions. Resolves
          the symmetry gap from the option-audit (centre + pin should
          be reachable from both directions on every edge). */}
      <div className="detail-section">
        <div className="detail-section-title">Endpoints</div>
        {(["source", "target"] as const).map((kind) => {
          const id = bundle[kind];
          return (
            <div
              key={kind}
              style={{
                display: "flex",
                alignItems: "center",
                gap: 4,
                marginBottom: 4,
              }}
            >
              <span
                style={{
                  flex: "0 0 50px",
                  fontSize: 11,
                  textTransform: "uppercase",
                  letterSpacing: 0.5,
                  color: "var(--text-secondary)",
                }}
              >
                {kind === "source" ? "From" : "To"}
              </span>
              <code
                style={{
                  flex: 1,
                  minWidth: 0,
                  overflow: "hidden",
                  textOverflow: "ellipsis",
                  whiteSpace: "nowrap",
                  fontSize: 11,
                }}
                title={id}
              >
                {id}
              </code>
              <button
                type="button"
                className="btn btn-sm"
                onClick={() => onCentreNode(id)}
                title={`Centre on ${kind}`}
                aria-label={`Centre on ${kind}`}
              >
                <Crosshair size={12} />
              </button>
              <button
                type="button"
                className="btn btn-sm"
                onClick={() => onPinNode(id)}
                title={`Pin ${kind} to Path Nodes`}
                aria-label={`Pin ${kind} to Path Nodes`}
              >
                <Pin size={12} />
              </button>
              <button
                type="button"
                className="btn btn-sm"
                onClick={() => navigator.clipboard.writeText(id)}
                title="Copy ID"
                aria-label="Copy ID"
              >
                <Copy size={12} />
              </button>
            </div>
          );
        })}
      </div>

      {/* Metadata — grouped by category so the eye finds the pivot
          keys first, then L4 → L7 → auth → alert → other. */}
      {selectedEdge && groups.length > 0 && (
        <div className="detail-section">
          <div className="detail-section-title">Metadata</div>
          {groups.map((g) => (
            <div key={g.title} style={{ marginBottom: 6 }}>
              <div
                style={{
                  fontSize: 10,
                  textTransform: "uppercase",
                  letterSpacing: 0.6,
                  color: "var(--text-secondary)",
                  marginBottom: 2,
                }}
              >
                {g.title}
              </div>
              <div
                style={{
                  fontFamily: "var(--font-mono)",
                  fontSize: 11,
                }}
              >
                {g.entries.map(([k, v]) => (
                  <div
                    key={k}
                    style={{
                      display: "flex",
                      gap: 8,
                      padding: "2px 0",
                      borderBottom: "1px dotted var(--border)",
                    }}
                  >
                    <span
                      style={{
                        flex: "0 0 110px",
                        color: "var(--text-secondary)",
                        overflow: "hidden",
                        textOverflow: "ellipsis",
                        whiteSpace: "nowrap",
                      }}
                      title={k}
                    >
                      {k}
                    </span>
                    <span
                      style={{
                        flex: 1,
                        minWidth: 0,
                        wordBreak: "break-all",
                        color: "var(--text-primary)",
                      }}
                    >
                      {v}
                    </span>
                  </div>
                ))}
              </div>
            </div>
          ))}
        </div>
      )}

      {/* Footer actions row */}
      <div
        style={{
          display: "flex",
          gap: 4,
          marginTop: "auto",
          paddingTop: 8,
          borderTop: "1px solid var(--border)",
        }}
      >
        <button
          type="button"
          className="btn btn-sm"
          onClick={copyAsJson}
          disabled={!selectedEdge}
          title="Copy this edge as JSON to the clipboard"
          style={{ flex: 1 }}
        >
          <Copy size={12} style={{ marginRight: 4 }} />
          Copy JSON
        </button>
        <button
          type="button"
          className="btn btn-sm"
          onClick={() => {
            onPinNode(bundle.source);
            onPinNode(bundle.target);
          }}
          title="Pin both endpoints to Path Nodes"
          style={{ flex: 1 }}
        >
          <MapPin size={12} style={{ marginRight: 4 }} />
          Pin both
        </button>
      </div>
    </div>
  );
}
