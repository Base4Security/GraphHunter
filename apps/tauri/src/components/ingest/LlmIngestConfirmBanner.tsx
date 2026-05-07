import type { IngestLlmProposalEvent, FieldMappingSummary } from "../../types";

/**
 * Confirm-banner UX for the LLM-as-compiler dispatcher.
 *
 * Renders side-by-side the heuristic FieldConfig and the LLM-refined
 * alternative for an ambiguous dataset that the streaming pipeline
 * paused on. The analyst picks one of the two — the parent component
 * is responsible for re-triggering ingest with the chosen config.
 *
 * Visual conventions mirror the existing `zeroTripleWarning` block in
 * `IngestPanel.tsx` (red alert) but use a blue/purple palette so the
 * LLM proposal reads as informational, not as an error.
 */
export interface LlmIngestConfirmBannerProps {
  proposal: IngestLlmProposalEvent;
  loading?: boolean;
  /** Re-ingest with the LLM-refined config. */
  onApplyRefined: () => void;
  /** Re-ingest with the original heuristic config. */
  onApplyHeuristic: () => void;
  /** Dismiss without re-ingesting. The dataset stays absent. */
  onDismiss: () => void;
}

const containerStyle: React.CSSProperties = {
  padding: "10px 12px",
  margin: "0 0 8px 0",
  background: "rgba(99, 102, 241, 0.10)",
  border: "1px solid rgba(99, 102, 241, 0.45)",
  borderRadius: 4,
  color: "#c7d2fe",
  fontSize: 11,
  display: "flex",
  flexDirection: "column",
  gap: 8,
};

const headerStyle: React.CSSProperties = {
  display: "flex",
  alignItems: "flex-start",
  justifyContent: "space-between",
  gap: 6,
};

const titleStyle: React.CSSProperties = {
  fontSize: 12,
  color: "#e0e7ff",
  fontWeight: 600,
};

const subtitleStyle: React.CSSProperties = {
  marginTop: 2,
  color: "#a5b4fc",
};

const tableWrapStyle: React.CSSProperties = {
  display: "grid",
  gridTemplateColumns: "1fr 1fr",
  gap: 12,
  marginTop: 4,
};

const columnStyle: React.CSSProperties = {
  background: "rgba(0, 0, 0, 0.18)",
  borderRadius: 3,
  padding: "6px 8px",
  maxHeight: 220,
  overflowY: "auto",
};

const columnHeaderStyle: React.CSSProperties = {
  fontWeight: 600,
  marginBottom: 4,
  color: "#e0e7ff",
};

const mappingRowStyle: React.CSSProperties = {
  display: "flex",
  justifyContent: "space-between",
  padding: "1px 0",
};

const mutedStyle: React.CSSProperties = { color: "#94a3b8", fontStyle: "italic" };

const buttonRowStyle: React.CSSProperties = {
  display: "flex",
  gap: 6,
  alignItems: "center",
  marginTop: 4,
  flexWrap: "wrap",
};

const baseButton: React.CSSProperties = {
  border: "1px solid rgba(99, 102, 241, 0.5)",
  borderRadius: 3,
  padding: "4px 10px",
  fontSize: 11,
  cursor: "pointer",
  background: "transparent",
  color: "#c7d2fe",
};

const primaryButton: React.CSSProperties = {
  ...baseButton,
  background: "rgba(99, 102, 241, 0.55)",
  color: "#fff",
  border: "1px solid rgba(99, 102, 241, 0.75)",
  fontWeight: 600,
};

const dismissButton: React.CSSProperties = {
  padding: 0,
  background: "none",
  border: "none",
  color: "#a5b4fc",
  cursor: "pointer",
  fontSize: 14,
  lineHeight: 1,
};

function formatMapping(m: FieldMappingSummary): string {
  if (m.role === "Metadata" && !m.entity_type) {
    return "(Metadata)";
  }
  if (m.role === "Ignore") {
    return "(Skip)";
  }
  return `${m.role}${m.entity_type ? ` → ${m.entity_type}` : ""}`;
}

function ConfigColumn({
  title,
  mappings,
}: {
  title: string;
  mappings: FieldMappingSummary[];
}) {
  return (
    <div style={columnStyle}>
      <div style={columnHeaderStyle}>{title}</div>
      {mappings.length === 0 ? (
        <div style={mutedStyle}>(empty)</div>
      ) : (
        mappings.map((m) => (
          <div key={m.raw_name} style={mappingRowStyle}>
            <span>{m.raw_name}</span>
            <span style={mutedStyle}>{formatMapping(m)}</span>
          </div>
        ))
      )}
    </div>
  );
}

export function LlmIngestConfirmBanner({
  proposal,
  loading,
  onApplyRefined,
  onApplyHeuristic,
  onDismiss,
}: LlmIngestConfirmBannerProps) {
  const fileName = proposal.source_path.split(/[/\\]/).pop() || proposal.source_path;
  const heuristicMappings: FieldMappingSummary[] = (proposal.heuristic.mappings || []).map(
    (m) => ({ raw_name: m.raw_name, role: m.role, entity_type: m.entity_type }),
  );
  const refinedMappings: FieldMappingSummary[] = (proposal.refined.mappings || []).map(
    (m) => ({ raw_name: m.raw_name, role: m.role, entity_type: m.entity_type }),
  );

  const confidencePct = Math.round(Math.max(0, Math.min(1, proposal.confidence)) * 100);

  return (
    <div role="alertdialog" aria-label="LLM ingest proposal" style={containerStyle}>
      <div style={headerStyle}>
        <div>
          <div style={titleStyle}>
            Compilador IA propone otro mapeo para <strong>{fileName}</strong>
          </div>
          <div style={subtitleStyle}>
            Formato {proposal.format} · backend{" "}
            <code style={{ color: "#fde68a" }}>{proposal.backend_id}</code> · confianza
            {" "}{confidencePct}% · {proposal.diff.added.length} agregados,
            {" "}{proposal.diff.changed.length} cambios,
            {" "}{proposal.diff.removed.length} retirados,
            {" "}{proposal.diff.unchanged_count} sin cambios.
          </div>
        </div>
        <button
          type="button"
          style={dismissButton}
          aria-label="Dismiss proposal"
          onClick={onDismiss}
        >
          &times;
        </button>
      </div>

      <div style={tableWrapStyle}>
        <ConfigColumn title="Heurística sugiere" mappings={heuristicMappings} />
        <ConfigColumn title="Compilador IA propone" mappings={refinedMappings} />
      </div>

      <div style={buttonRowStyle}>
        <button
          type="button"
          style={primaryButton}
          disabled={loading}
          onClick={onApplyRefined}
        >
          {loading ? "Re-ingestando…" : "Aplicar mapeo IA"}
        </button>
        <button
          type="button"
          style={baseButton}
          disabled={loading}
          onClick={onApplyHeuristic}
        >
          Usar heurística
        </button>
        <span style={{ marginLeft: "auto", ...mutedStyle, fontSize: 10 }}>
          La ingesta se pausó antes de insertar triples — ningún dato fue
          escrito todavía.
        </span>
      </div>
    </div>
  );
}
