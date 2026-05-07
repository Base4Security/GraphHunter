import { useEffect, useState } from "react";
import { AlertTriangle, ChevronDown, ChevronRight, Download, Edit3, Sparkles, Trash2 } from "lucide-react";
import { invoke, errorMessage } from "../../lib/tauri";
import type { DatasetInfo, GraphStats, LogEntry } from "../../types";
import { now } from "../../lib/time";

type InvariantPredicateResult = {
  predicate: string;
  passed: boolean;
  checked: number;
  violated: number;
  samples: Array<{ reason: string; relation_label?: string; timestamp?: number }>;
  skipped_reason?: string | null;
};

type InvariantReport = {
  entity_count: number;
  relation_count: number;
  results: InvariantPredicateResult[];
  treewidth_estimate?: {
    value: number;
    method: string;
    quotient_node_count: number;
    quotient_edge_count: number;
  } | null;
};

interface DatasetCardProps {
  dataset: DatasetInfo;
  onStatsUpdate: (stats: GraphStats) => void;
  onLog: (entry: LogEntry) => void;
  onDatasetsChange: (datasets: DatasetInfo[]) => void;
  onOpenRename: (datasetId: string, datasetName: string) => void;
}

export default function DatasetCard({
  dataset: d,
  onStatsUpdate,
  onLog,
  onDatasetsChange,
  onOpenRename,
}: DatasetCardProps) {
  const [schemaOpen, setSchemaOpen] = useState(false);
  const [skipsOpen, setSkipsOpen] = useState(false);
  const [health, setHealth] = useState<InvariantReport | null>(null);
  const [healthError, setHealthError] = useState<string | null>(null);
  const [healthOpen, setHealthOpen] = useState(false);
  // True while `cmd_request_llm_proposal` is awaiting Phi-3. Disables
  // the button + swaps the label so the user knows it's working — the
  // banner state itself lives in the parent (DatasetsLeftPanel) where
  // the permanent `ingest-llm-proposal` listener catches the event.
  const [aiProposalRunning, setAiProposalRunning] = useState(false);

  useEffect(() => {
    if (d.relation_count === 0) return;
    let cancelled = false;
    (async () => {
      try {
        const report = await invoke<InvariantReport>("cmd_check_invariants", {
          datasetId: d.id,
        });
        if (!cancelled) {
          setHealth(report);
          setHealthError(null);
        }
      } catch (e) {
        if (!cancelled) setHealthError(errorMessage(e));
      }
    })();
    return () => {
      cancelled = true;
    };
  }, [d.id, d.relation_count, d.entity_count]);

  const healthFailures = health
    ? health.results.filter((r) => !r.passed && !r.skipped_reason)
    : [];
  const healthTotalViolations = healthFailures.reduce(
    (sum, r) => sum + r.violated,
    0
  );

  const stats = d.ingest_stats ?? null;
  const zeroTriples =
    !!stats && stats.rows_seen > 0 && stats.rows_with_triples === 0;
  const statsKnown = !!stats && stats.rows_seen > 0;
  const skipReasons = stats?.skip_reasons ?? {};
  const hasSkipReasons = Object.keys(skipReasons).length > 0;
  const skippedSamples = stats?.skipped_samples ?? [];

  return (
    <li
      style={{
        padding: "6px 8px",
        marginBottom: 6,
        background: "var(--bg-tertiary)",
        borderRadius: 4,
        fontSize: 11,
      }}
    >
      <div style={{ fontWeight: 600, marginBottom: 2 }}>{d.name}</div>
      <div style={{ color: "var(--text-muted)", marginBottom: 6 }}>
        {d.entity_count} entities, {d.relation_count} relations
      </div>
      {statsKnown && (
        <div
          style={{
            display: "flex",
            gap: 4,
            flexWrap: "wrap",
            marginBottom: 6,
          }}
        >
          <Badge
            label={`Parsed ${stats!.rows_seen}`}
            tone="neutral"
          />
          <Badge
            label={`With triples ${stats!.rows_with_triples}`}
            tone={zeroTriples ? "danger" : "success"}
          />
          <Badge
            label={`Skipped ${stats!.rows_skipped}`}
            tone={stats!.rows_skipped > 0 ? "warning" : "neutral"}
            onClick={
              hasSkipReasons ? () => setSkipsOpen((v) => !v) : undefined
            }
            title={
              hasSkipReasons
                ? "Click to see skip reasons"
                : undefined
            }
          />
          {health && (
            <Badge
              label={
                healthFailures.length === 0
                  ? "Health: OK"
                  : `${healthTotalViolations} violation${
                      healthTotalViolations === 1 ? "" : "s"
                    }`
              }
              tone={healthFailures.length === 0 ? "success" : "warning"}
              onClick={() => setHealthOpen((v) => !v)}
              title="Click to see invariant breakdown"
            />
          )}
          {healthError && (
            <Badge
              label="Health: error"
              tone="danger"
              title={healthError}
            />
          )}
        </div>
      )}
      {healthOpen && health && (
        <div
          style={{
            padding: "4px 6px",
            marginBottom: 6,
            background: "rgba(148, 163, 184, 0.08)",
            border: "1px solid rgba(148, 163, 184, 0.25)",
            borderRadius: 4,
            fontSize: 10,
          }}
        >
          <div style={{ color: "var(--text-muted)", marginBottom: 2 }}>
            Invariants
          </div>
          {health.results.map((r) => {
            const status = r.skipped_reason
              ? `skipped — ${r.skipped_reason}`
              : r.passed
              ? "OK"
              : `${r.violated} violated`;
            const color = r.skipped_reason
              ? "var(--text-muted)"
              : r.passed
              ? "#4ade80"
              : "#facc15";
            return (
              <div
                key={r.predicate}
                style={{
                  display: "flex",
                  justifyContent: "space-between",
                  fontFamily:
                    "ui-monospace, SFMono-Regular, Menlo, monospace",
                }}
              >
                <span>{r.predicate}</span>
                <span style={{ color }}>{status}</span>
              </div>
            );
          })}
          {health.treewidth_estimate && (
            <div
              style={{
                marginTop: 4,
                color: "var(--text-muted)",
                fontFamily:
                  "ui-monospace, SFMono-Regular, Menlo, monospace",
              }}
            >
              treewidth ({health.treewidth_estimate.method}):{" "}
              {health.treewidth_estimate.value} over{" "}
              {health.treewidth_estimate.quotient_node_count} types
            </div>
          )}
          {healthFailures.some((r) => r.samples.length > 0) && (
            <div style={{ marginTop: 6 }}>
              <div style={{ color: "var(--text-muted)", marginBottom: 2 }}>
                Sample violations
              </div>
              <div style={{ maxHeight: 160, overflowY: "auto" }}>
                {healthFailures.flatMap((r) =>
                  r.samples.map((s, i) => (
                    <div
                      key={`${r.predicate}-${i}`}
                      style={{
                        padding: "2px 4px",
                        marginBottom: 2,
                        background: "rgba(0,0,0,0.15)",
                        borderRadius: 2,
                        fontFamily:
                          "ui-monospace, SFMono-Regular, Menlo, monospace",
                        fontSize: 9,
                      }}
                      title={s.reason}
                    >
                      <span style={{ color: "#facc15", marginRight: 4 }}>
                        [{r.predicate}]
                      </span>
                      {s.relation_label ?? ""}
                      {s.relation_label ? " — " : ""}
                      {s.reason}
                    </div>
                  ))
                )}
              </div>
            </div>
          )}
        </div>
      )}
      {skipsOpen && hasSkipReasons && (
        <div
          style={{
            padding: "4px 6px",
            marginBottom: 6,
            background: "rgba(234, 179, 8, 0.08)",
            border: "1px solid rgba(234, 179, 8, 0.25)",
            borderRadius: 4,
            fontSize: 10,
          }}
        >
          <div style={{ color: "var(--text-muted)", marginBottom: 2 }}>
            Skip reasons
          </div>
          {Object.entries(skipReasons)
            .sort(([, a], [, b]) => b - a)
            .map(([reason, n]) => (
              <div
                key={reason}
                style={{
                  display: "flex",
                  justifyContent: "space-between",
                  fontFamily:
                    "ui-monospace, SFMono-Regular, Menlo, monospace",
                }}
              >
                <span>{reason}</span>
                <span>{n}</span>
              </div>
            ))}
          {skippedSamples.length > 0 && (
            <div style={{ marginTop: 6 }}>
              <div style={{ color: "var(--text-muted)", marginBottom: 2 }}>
                Sampled skipped rows ({skippedSamples.length})
              </div>
              <div style={{ maxHeight: 160, overflowY: "auto" }}>
                {skippedSamples.map(([raw, reason], i) => (
                  <div
                    key={i}
                    style={{
                      padding: "2px 4px",
                      marginBottom: 2,
                      background: "rgba(0,0,0,0.15)",
                      borderRadius: 2,
                      fontFamily:
                        "ui-monospace, SFMono-Regular, Menlo, monospace",
                      fontSize: 9,
                      whiteSpace: "nowrap",
                      overflow: "hidden",
                      textOverflow: "ellipsis",
                    }}
                    title={`${reason}: ${raw}`}
                  >
                    <span style={{ color: "#facc15", marginRight: 4 }}>
                      [{reason}]
                    </span>
                    {raw.length > 160 ? raw.slice(0, 160) + "…" : raw}
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>
      )}
      {zeroTriples && (
        <div
          style={{
            display: "flex",
            flexDirection: "column",
            gap: 6,
            padding: "6px 8px",
            marginBottom: 6,
            background: "rgba(220, 38, 38, 0.12)",
            border: "1px solid rgba(220, 38, 38, 0.35)",
            borderRadius: 4,
            color: "#f87171",
            fontSize: 10,
          }}
        >
          <div style={{ display: "flex", alignItems: "center", gap: 4 }}>
            <AlertTriangle size={12} />
            <span>
              Parser saw {stats!.rows_seen} rows but produced 0 triples.
              Re-ingest with an adjusted mapping.
            </span>
          </div>
          <button
            type="button"
            disabled={aiProposalRunning}
            onClick={async () => {
              if (aiProposalRunning) return;
              setAiProposalRunning(true);
              onLog({
                time: now(),
                message: `${d.name}: pidiendo mapeo al compilador IA (Phi-3, puede tardar 15-60s)…`,
                level: "info",
              });
              try {
                await invoke("cmd_request_llm_proposal", { datasetId: d.id });
                // Success message is fire-and-forget — the actual outcome
                // lands as either an `ingest-llm-proposal` event (banner
                // appears in DatasetsLeftPanel) or `ingest-llm-diagnostic`
                // (status-log entry from the parent listener). We don't
                // duplicate the log here.
              } catch (e) {
                onLog({
                  time: now(),
                  message: `${d.name}: solicitud al compilador IA falló — ${errorMessage(e)}`,
                  level: "error",
                });
              } finally {
                setAiProposalRunning(false);
              }
            }}
            style={{
              display: "flex",
              alignItems: "center",
              justifyContent: "center",
              gap: 4,
              padding: "4px 8px",
              background: aiProposalRunning
                ? "rgba(251, 191, 36, 0.25)"
                : "rgba(99, 102, 241, 0.25)",
              border: aiProposalRunning
                ? "1px solid #fbbf24"
                : "1px solid rgba(99, 102, 241, 0.55)",
              borderRadius: 3,
              color: aiProposalRunning ? "#fde68a" : "#c7d2fe",
              fontSize: 10,
              fontWeight: 600,
              cursor: aiProposalRunning ? "wait" : "pointer",
            }}
            title={
              aiProposalRunning
                ? "Phi-3 corriendo en background, esperá el banner"
                : "Pedir al compilador IA un mapeo alternativo basado en una muestra del archivo"
            }
          >
            <Sparkles size={11} />
            {aiProposalRunning ? "⏳ Compilador IA pensando…" : "Probar mapeo IA"}
          </button>
        </div>
      )}
      {d.field_config && d.field_config.mappings.length > 0 && (
        <div style={{ marginBottom: 6 }}>
          <button
            type="button"
            onClick={() => setSchemaOpen((v) => !v)}
            style={{
              display: "flex",
              alignItems: "center",
              gap: 2,
              padding: 0,
              background: "none",
              border: "none",
              color: "var(--text-muted)",
              fontSize: 10,
              cursor: "pointer",
            }}
            aria-expanded={schemaOpen}
          >
            {schemaOpen ? (
              <ChevronDown size={11} />
            ) : (
              <ChevronRight size={11} />
            )}
            Schema used ({d.field_config.mappings.length})
          </button>
          {schemaOpen && (
            <table
              style={{
                width: "100%",
                marginTop: 4,
                fontSize: 10,
                borderCollapse: "collapse",
              }}
            >
              <tbody>
                {d.field_config.mappings.map((m) => {
                  const occ = stats?.per_field_occurrence?.[m.raw_name];
                  const seen = stats?.rows_seen ?? 0;
                  const coverage =
                    occ !== undefined && seen > 0
                      ? `${Math.round((occ / seen) * 100)}%`
                      : null;
                  return (
                    <tr key={m.raw_name}>
                      <td
                        style={{
                          padding: "2px 4px",
                          color: "var(--text-muted)",
                          fontFamily:
                            "ui-monospace, SFMono-Regular, Menlo, monospace",
                        }}
                      >
                        {m.raw_name}
                      </td>
                      <td style={{ padding: "2px 4px" }}>
                        {m.role}
                        {m.entity_type ? ` → ${m.entity_type}` : ""}
                        {m.timestamp_format
                          ? ` (${m.timestamp_format}${
                              m.locale ? ` · ${m.locale}` : ""
                            })`
                          : ""}
                      </td>
                      <td
                        style={{
                          padding: "2px 4px",
                          color: "var(--text-muted)",
                          textAlign: "right",
                          fontVariantNumeric: "tabular-nums",
                        }}
                        title={
                          occ !== undefined
                            ? `${occ} / ${seen} rows`
                            : "coverage unknown"
                        }
                      >
                        {coverage ?? "—"}
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          )}
        </div>
      )}
      <div style={{ display: "flex", gap: 6, flexWrap: "wrap" }}>
        <button
          type="button"
          className="btn btn-sm"
          onClick={() => onOpenRename(d.id, d.name)}
          title="Rename entity type in this dataset"
        >
          <Edit3 size={12} />
          Rename types
        </button>
        <button
          type="button"
          className="btn btn-sm"
          onClick={async () => {
            try {
              const ndjson = await invoke<string>("cmd_export_ocsf", {
                format: "ndjson",
                datasetId: d.id,
              });
              const blob = new Blob([ndjson], {
                type: "application/x-ndjson",
              });
              const url = URL.createObjectURL(blob);
              const a = document.createElement("a");
              a.href = url;
              a.download = `${d.name.replace(/[^\w.-]+/g, "_")}.ocsf.ndjson`;
              document.body.appendChild(a);
              a.click();
              document.body.removeChild(a);
              URL.revokeObjectURL(url);
              const lineCount = ndjson
                .split("\n")
                .filter((l) => l.trim().length > 0).length;
              onLog({
                time: now(),
                message: `Exported ${lineCount} OCSF events from ${d.name}`,
                level: "success",
              });
            } catch (e) {
              onLog({
                time: now(),
                message: `Export OCSF failed: ${errorMessage(e)}`,
                level: "error",
              });
            }
          }}
          title="Download this dataset as OCSF v1.4 NDJSON with Provenance Extension"
        >
          <Download size={12} />
          Export OCSF
        </button>
        <button
          type="button"
          className="btn btn-sm"
          onClick={async () => {
            if (
              !confirm(
                `Remove dataset "${d.name}"? This will delete ${d.entity_count} entities and ${d.relation_count} relations.`
              )
            )
              return;
            try {
              await invoke<[number, number]>("cmd_remove_dataset", {
                datasetId: d.id,
              });
              const s = await invoke<GraphStats>("cmd_get_graph_stats");
              onStatsUpdate(s);
              const list = await invoke<DatasetInfo[]>("cmd_list_datasets");
              onDatasetsChange(list);
              onLog({
                time: now(),
                message: `Removed dataset: ${d.name}`,
                level: "success",
              });
            } catch (e) {
              onLog({
                time: now(),
                message: `Remove failed: ${errorMessage(e)}`,
                level: "error",
              });
            }
          }}
          title="Remove this dataset from the graph"
        >
          <Trash2 size={12} />
          Remove
        </button>
      </div>
    </li>
  );
}

interface BadgeProps {
  label: string;
  tone: "neutral" | "success" | "warning" | "danger";
  onClick?: () => void;
  title?: string;
}

function Badge({ label, tone, onClick, title }: BadgeProps) {
  const palette = {
    neutral: { bg: "rgba(148, 163, 184, 0.15)", fg: "var(--text-muted)" },
    success: { bg: "rgba(34, 197, 94, 0.15)", fg: "#4ade80" },
    warning: { bg: "rgba(234, 179, 8, 0.18)", fg: "#facc15" },
    danger: { bg: "rgba(220, 38, 38, 0.18)", fg: "#f87171" },
  }[tone];
  const common = {
    padding: "1px 6px",
    borderRadius: 4,
    fontSize: 10,
    background: palette.bg,
    color: palette.fg,
    whiteSpace: "nowrap" as const,
  };
  if (onClick) {
    return (
      <button
        type="button"
        onClick={onClick}
        title={title}
        style={{
          ...common,
          border: "none",
          cursor: "pointer",
          font: "inherit",
        }}
      >
        {label}
      </button>
    );
  }
  return (
    <span style={common} title={title}>
      {label}
    </span>
  );
}
