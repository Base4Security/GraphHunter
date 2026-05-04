interface IngestProgressBarProps {
  progress: {
    processed: number;
    total: number;
    entities: number;
    relations: number;
    phase?: string;
  };
  /** When true, uses the phase-aware display from IngestPanel (shows scoring phase, MB units) */
  showPhase?: boolean;
}

export default function IngestProgressBar({ progress, showPhase }: IngestProgressBarProps) {
  const pct =
    showPhase && progress.phase === "scoring"
      ? 100
      : progress.total > 0
        ? Math.round((progress.processed / progress.total) * 100)
        : 0;

  let label: string;
  if (showPhase && progress.phase === "scoring") {
    label = `Scoring — ${progress.entities.toLocaleString()} entities, ${progress.relations.toLocaleString()} relations`;
  } else if (showPhase && progress.phase) {
    const sizeLabel =
      progress.total > 1_000_000
        ? `${(progress.processed / 1_048_576).toFixed(0)} / ${(progress.total / 1_048_576).toFixed(0)} MB`
        : `${progress.processed.toLocaleString()} / ${progress.total.toLocaleString()}`;
    label = `${sizeLabel} — ${progress.entities.toLocaleString()} entities, ${progress.relations.toLocaleString()} relations`;
  } else {
    const suffix = progress.total > 1_000_000 ? " bytes" : "";
    label = `${progress.processed.toLocaleString()} / ${progress.total.toLocaleString()}${suffix} — ${progress.entities.toLocaleString()} entities, ${progress.relations.toLocaleString()} relations`;
  }

  return (
    <div style={{ marginTop: 6, width: "100%" }}>
      <div
        style={{
          height: 6,
          background: "var(--bg-secondary)",
          borderRadius: 3,
          overflow: "hidden",
        }}
      >
        <div
          style={{
            height: "100%",
            width: `${pct}%`,
            background: "var(--accent)",
            borderRadius: 3,
            transition: "width 0.2s",
          }}
        />
      </div>
      <div style={{ fontSize: 10, color: "var(--text-muted)", marginTop: 2 }}>
        {label}
      </div>
    </div>
  );
}
