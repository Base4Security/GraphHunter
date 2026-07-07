import type { PcapPreviewResult } from "../../types";

interface Props {
  result: PcapPreviewResult;
}

/**
 * Non-tabular preview for offline PCAP / PCAPNG captures.
 *
 * The standard `FileUploadSection` mapping table assumes a `field →
 * entity-type` model that doesn't apply to packet captures (the schema
 * is fixed by the L2-L4 decoder, the user has no mapping to make).
 * Instead, this surfaces the signal an analyst actually wants before
 * committing the file to the graph: top conversation peers, protocol
 * mix, and the time span of the capture.
 */
export default function PcapPreviewSummary({ result }: Props) {
  const totalProtoPackets = result.protocol_mix.reduce(
    (sum, p) => sum + p.packets,
    0,
  );

  return (
    <div className="panel-left-section" style={{ marginTop: 8 }}>
      <div
        style={{
          fontSize: 11,
          color: "var(--text-muted)",
          marginBottom: 8,
        }}
      >
        Format: <strong>{result.format.toUpperCase()}</strong> · binary capture
        · {formatBytes(result.file_size)} on disk
      </div>

      <SummaryRow
        label="Packets sampled"
        value={`${result.packets_sampled.toLocaleString()} of ~${result.packet_count_estimate.toLocaleString()} est.`}
      />

      {result.time_span && (
        <SummaryRow
          label="Time span"
          value={formatTimeSpan(result.time_span)}
        />
      )}

      {result.warnings && result.warnings.length > 0 && (
        <div
          role="status"
          aria-live="polite"
          style={{
            marginTop: 6,
            padding: "4px 6px",
            border: "1px solid var(--border)",
            background: "var(--bg-tertiary)",
            borderRadius: 4,
            fontSize: 10,
            color: "var(--text-muted)",
          }}
        >
          {result.warnings.map((w, i) => (
            <div key={i}>⚠ {w}</div>
          ))}
        </div>
      )}

      {result.protocol_mix.length > 0 && (
        <Section title="Protocol mix">
          {result.protocol_mix.map((p) => {
            const pct =
              totalProtoPackets > 0
                ? (p.packets / totalProtoPackets) * 100
                : 0;
            return (
              <ProtocolRow
                key={p.protocol}
                name={p.protocol}
                packets={p.packets}
                bytes={p.bytes}
                pct={pct}
              />
            );
          })}
        </Section>
      )}

      {result.top_src_ips.length > 0 && (
        <Section title="Top source IPs">
          <IpTable rows={result.top_src_ips} />
        </Section>
      )}

      {result.top_dst_ips.length > 0 && (
        <Section title="Top destination IPs">
          <IpTable rows={result.top_dst_ips} />
        </Section>
      )}

      {result.top_dst_ports.length > 0 && (
        <Section title="Top destination ports">
          <PortTable rows={result.top_dst_ports} />
        </Section>
      )}
    </div>
  );
}

function SummaryRow({ label, value }: { label: string; value: string }) {
  return (
    <div
      style={{
        display: "flex",
        justifyContent: "space-between",
        fontSize: 11,
        padding: "2px 0",
      }}
    >
      <span style={{ color: "var(--text-muted)" }}>{label}</span>
      <span style={{ color: "var(--text-primary)" }}>{value}</span>
    </div>
  );
}

function Section({
  title,
  children,
}: {
  title: string;
  children: React.ReactNode;
}) {
  return (
    <div style={{ marginTop: 10 }}>
      <div
        style={{
          fontSize: 10,
          color: "var(--text-muted)",
          textTransform: "uppercase",
          letterSpacing: "0.5px",
          marginBottom: 4,
        }}
      >
        {title}
      </div>
      {children}
    </div>
  );
}

function ProtocolRow({
  name,
  packets,
  bytes,
  pct,
}: {
  name: string;
  packets: number;
  bytes: number;
  pct: number;
}) {
  return (
    <div
      style={{
        display: "grid",
        gridTemplateColumns: "55px 1fr auto",
        alignItems: "center",
        gap: 6,
        fontSize: 11,
        padding: "2px 0",
      }}
    >
      <span title={name}>{name}</span>
      <div
        style={{
          height: 6,
          background: "var(--bg-tertiary)",
          borderRadius: 3,
          overflow: "hidden",
        }}
        aria-label={`${pct.toFixed(1)} percent`}
      >
        <div
          style={{
            width: `${Math.min(100, Math.max(0, pct)).toFixed(1)}%`,
            height: "100%",
            background: "var(--accent, #6aa0ff)",
          }}
        />
      </div>
      <span style={{ color: "var(--text-muted)", fontVariantNumeric: "tabular-nums" }}>
        {packets.toLocaleString()} pkt · {formatBytes(bytes)}
      </span>
    </div>
  );
}

function IpTable({
  rows,
}: {
  rows: { ip: string; packets: number; bytes: number }[];
}) {
  return (
    <table
      style={{
        width: "100%",
        fontSize: 11,
        borderCollapse: "collapse",
        fontVariantNumeric: "tabular-nums",
      }}
    >
      <tbody>
        {rows.map((r, i) => (
          <tr key={`${r.ip}-${i}`}>
            <td
              style={{
                padding: "2px 4px",
                borderBottom: "1px solid var(--border)",
                overflow: "hidden",
                textOverflow: "ellipsis",
                whiteSpace: "nowrap",
                maxWidth: 160,
              }}
              title={r.ip}
            >
              {r.ip}
            </td>
            <td
              style={{
                padding: "2px 4px",
                borderBottom: "1px solid var(--border)",
                textAlign: "right",
                color: "var(--text-muted)",
              }}
            >
              {r.packets.toLocaleString()}
            </td>
            <td
              style={{
                padding: "2px 4px",
                borderBottom: "1px solid var(--border)",
                textAlign: "right",
                color: "var(--text-muted)",
                width: 56,
              }}
            >
              {formatBytes(r.bytes)}
            </td>
          </tr>
        ))}
      </tbody>
    </table>
  );
}

function PortTable({
  rows,
}: {
  rows: {
    port: number;
    protocol: string;
    service?: string;
    packets: number;
  }[];
}) {
  return (
    <table
      style={{
        width: "100%",
        fontSize: 11,
        borderCollapse: "collapse",
        fontVariantNumeric: "tabular-nums",
      }}
    >
      <tbody>
        {rows.map((r, i) => (
          <tr key={`${r.port}-${r.protocol}-${i}`}>
            <td
              style={{
                padding: "2px 4px",
                borderBottom: "1px solid var(--border)",
              }}
            >
              {r.protocol} / {r.port}
              {r.service && (
                <span
                  style={{
                    marginLeft: 6,
                    color: "var(--text-muted)",
                    fontSize: 10,
                  }}
                >
                  {r.service}
                </span>
              )}
            </td>
            <td
              style={{
                padding: "2px 4px",
                borderBottom: "1px solid var(--border)",
                textAlign: "right",
                color: "var(--text-muted)",
              }}
            >
              {r.packets.toLocaleString()} pkt
            </td>
          </tr>
        ))}
      </tbody>
    </table>
  );
}

function formatBytes(n: number): string {
  if (!Number.isFinite(n) || n <= 0) return "0 B";
  const units = ["B", "KB", "MB", "GB", "TB"];
  let v = n;
  let i = 0;
  while (v >= 1024 && i < units.length - 1) {
    v /= 1024;
    i++;
  }
  return `${v.toFixed(v >= 100 || i === 0 ? 0 : 1)} ${units[i]}`;
}

function formatTimeSpan(ts: {
  first_unix_secs: number;
  last_unix_secs: number;
  duration_secs: number;
}): string {
  const first = new Date(ts.first_unix_secs * 1000).toISOString().replace("T", " ").slice(0, 19);
  const last = new Date(ts.last_unix_secs * 1000).toISOString().replace("T", " ").slice(0, 19);
  const dur =
    ts.duration_secs < 60
      ? `${ts.duration_secs}s`
      : ts.duration_secs < 3600
        ? `${Math.round(ts.duration_secs / 60)}m`
        : ts.duration_secs < 86400
          ? `${(ts.duration_secs / 3600).toFixed(1)}h`
          : `${(ts.duration_secs / 86400).toFixed(1)}d`;
  return `${first} → ${last} (${dur})`;
}
